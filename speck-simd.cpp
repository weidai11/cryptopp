// speck-simd.cpp - written and placed in the public domain by Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    SSSE3, ARM NEON and ARMv8a, and Power7 Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"

#include "speck.h"
#include "misc.h"

// Uncomment for benchmarking C++ against SSE or NEON.
// Do so in both speck.cpp and speck-simd.cpp.
// #undef CRYPTOPP_SSSE3_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

// Disable NEON/ASIMD for Cortex-A53 and A57. The shifts are too slow and C/C++ is 3 cpb
// faster than NEON/ASIMD. Also see http://github.com/weidai11/cryptopp/issues/367.
#if (defined(__aarch32__) || defined(__aarch64__)) && defined(CRYPTOPP_SLOW_ARMV8_SHIFT)
# undef CRYPTOPP_ARM_NEON_AVAILABLE
#endif

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_SSSE3_AVAILABLE)
# include <tmmintrin.h>
#endif

// Hack for SunCC, http://github.com/weidai11/cryptopp/issues/224
#if (__SUNPRO_CC >= 0x5130)
# define MAYBE_CONST
# define MAYBE_UNCONST_CAST(T, x) const_cast<MAYBE_CONST T>(x)
#else
# define MAYBE_CONST const
# define MAYBE_UNCONST_CAST(T, x) (x)
#endif

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::BlockTransformation;

// *************************** ARM NEON ************************** //

#if defined(CRYPTOPP_ARM_NEON_AVAILABLE)

#if defined(CRYPTOPP_LITTLE_ENDIAN)
const word32 s_one[] = {0, 0, 0, 1<<24};  // uint32x4_t
#else
const word32 s_one[] = {0, 0, 0, 1};      // uint32x4_t
#endif

template <class W, class T>
inline W UnpackHigh64(const T& a, const T& b)
{
    const uint64x1_t x = vget_high_u64((uint64x2_t)a);
    const uint64x1_t y = vget_high_u64((uint64x2_t)b);
    return (W)vcombine_u64(x, y);
}

template <class W, class T>
inline W UnpackLow64(const T& a, const T& b)
{
    const uint64x1_t x = vget_low_u64((uint64x2_t)a);
    const uint64x1_t y = vget_low_u64((uint64x2_t)b);
    return (W)vcombine_u64(x, y);
}

template <unsigned int R>
inline uint64x2_t RotateLeft64(const uint64x2_t& val)
{
    CRYPTOPP_ASSERT(R < 64);
    const uint64x2_t a(vshlq_n_u64(val, R));
    const uint64x2_t b(vshrq_n_u64(val, 64 - R));
    return vorrq_u64(a, b);
}

template <unsigned int R>
inline uint64x2_t RotateRight64(const uint64x2_t& val)
{
    CRYPTOPP_ASSERT(R < 64);
    const uint64x2_t a(vshlq_n_u64(val, 64 - R));
    const uint64x2_t b(vshrq_n_u64(val, R));
    return vorrq_u64(a, b);
}

inline uint64x2_t Shuffle64(const uint64x2_t& val)
{
    return vreinterpretq_u64_u8(
        vrev64q_u8(vreinterpretq_u8_u64(val)));
}

inline void SPECK128_Enc_Block(uint8x16_t &block0, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SPECK128_Enc_Blocks then SPECK128_AdvancedProcessBlocks_SSSE3.
    // The zero block below is a "don't care". It is present so we can vectorize.
    uint8x16_t block1 = {0};
    uint64x2_t x1 = UnpackLow64<uint64x2_t>(block0, block1);
    uint64x2_t y1 = UnpackHigh64<uint64x2_t>(block0, block1);

    x1 = Shuffle64(x1);
    y1 = Shuffle64(y1);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+i);

        x1 = RotateRight64<8>(x1);
        x1 = vaddq_u64(x1, y1);
        x1 = veorq_u64(x1, rk);
        y1 = RotateLeft64<3>(y1);
        y1 = veorq_u64(y1, x1);
    }

    x1 = Shuffle64(x1);
    y1 = Shuffle64(y1);

    block0 = UnpackLow64<uint8x16_t>(x1, y1);
    // block1 = UnpackHigh64<uint8x16_t>(x1, y1);
}

inline void SPECK128_Enc_6_Blocks(uint8x16_t &block0, uint8x16_t &block1,
            uint8x16_t &block2, uint8x16_t &block3, uint8x16_t &block4,
            uint8x16_t &block5, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SPECK128_Enc_Blocks then SPECK128_AdvancedProcessBlocks_SSSE3.
    uint64x2_t x1 = UnpackLow64<uint64x2_t>(block0, block1);
    uint64x2_t y1 = UnpackHigh64<uint64x2_t>(block0, block1);
    uint64x2_t x2 = UnpackLow64<uint64x2_t>(block2, block3);
    uint64x2_t y2 = UnpackHigh64<uint64x2_t>(block2, block3);
    uint64x2_t x3 = UnpackLow64<uint64x2_t>(block4, block5);
    uint64x2_t y3 = UnpackHigh64<uint64x2_t>(block4, block5);

    x1 = Shuffle64(x1);
    y1 = Shuffle64(y1);
    x2 = Shuffle64(x2);
    y2 = Shuffle64(y2);
    x3 = Shuffle64(x3);
    y3 = Shuffle64(y3);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+i);

        x1 = RotateRight64<8>(x1);
        x2 = RotateRight64<8>(x2);
        x3 = RotateRight64<8>(x3);
        x1 = vaddq_u64(x1, y1);
        x2 = vaddq_u64(x2, y2);
        x3 = vaddq_u64(x3, y3);
        x1 = veorq_u64(x1, rk);
        x2 = veorq_u64(x2, rk);
        x3 = veorq_u64(x3, rk);
        y1 = RotateLeft64<3>(y1);
        y2 = RotateLeft64<3>(y2);
        y3 = RotateLeft64<3>(y3);
        y1 = veorq_u64(y1, x1);
        y2 = veorq_u64(y2, x2);
        y3 = veorq_u64(y3, x3);
    }

    x1 = Shuffle64(x1);
    y1 = Shuffle64(y1);
    x2 = Shuffle64(x2);
    y2 = Shuffle64(y2);
    x3 = Shuffle64(x3);
    y3 = Shuffle64(y3);

    block0 = UnpackLow64<uint8x16_t>(x1, y1);
    block1 = UnpackHigh64<uint8x16_t>(x1, y1);
    block2 = UnpackLow64<uint8x16_t>(x2, y2);
    block3 = UnpackHigh64<uint8x16_t>(x2, y2);
    block4 = UnpackLow64<uint8x16_t>(x3, y3);
    block5 = UnpackHigh64<uint8x16_t>(x3, y3);
}

inline void SPECK128_Dec_Block(uint8x16_t &block0, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SPECK128_Dec_Blocks then SPECK128_AdvancedProcessBlocks_SSSE3.
    // The zero block below is a "don't care". It is present so we can vectorize.
    uint8x16_t block1 = {0};
    uint64x2_t x1 = UnpackLow64<uint64x2_t>(block0, block1);
    uint64x2_t y1 = UnpackHigh64<uint64x2_t>(block0, block1);

    x1 = Shuffle64(x1);
    y1 = Shuffle64(y1);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+i);

        y1 = veorq_u64(y1, x1);
        y1 = RotateRight64<3>(y1);
        x1 = veorq_u64(x1, rk);
        x1 = vsubq_u64(x1, y1);
        x1 = RotateLeft64<8>(x1);
    }

    x1 = Shuffle64(x1);
    y1 = Shuffle64(y1);

    block0 = UnpackLow64<uint8x16_t>(x1, y1);
    // block1 = UnpackHigh64<uint8x16_t>(x1, y1);
}

inline void SPECK128_Dec_6_Blocks(uint8x16_t &block0, uint8x16_t &block1,
            uint8x16_t &block2, uint8x16_t &block3, uint8x16_t &block4,
            uint8x16_t &block5, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SPECK128_Dec_Blocks then SPECK128_AdvancedProcessBlocks_SSSE3.
    uint64x2_t x1 = UnpackLow64<uint64x2_t>(block0, block1);
    uint64x2_t y1 = UnpackHigh64<uint64x2_t>(block0, block1);
    uint64x2_t x2 = UnpackLow64<uint64x2_t>(block2, block3);
    uint64x2_t y2 = UnpackHigh64<uint64x2_t>(block2, block3);
    uint64x2_t x3 = UnpackLow64<uint64x2_t>(block4, block5);
    uint64x2_t y3 = UnpackHigh64<uint64x2_t>(block5, block5);

    x1 = Shuffle64(x1);
    y1 = Shuffle64(y1);
    x2 = Shuffle64(x2);
    y2 = Shuffle64(y2);
    x3 = Shuffle64(x3);
    y3 = Shuffle64(y3);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+i);

        y1 = veorq_u64(y1, x1);
        y2 = veorq_u64(y2, x2);
        y3 = veorq_u64(y3, x3);
        y1 = RotateRight64<3>(y1);
        y2 = RotateRight64<3>(y2);
        y3 = RotateRight64<3>(y3);
        x1 = veorq_u64(x1, rk);
        x2 = veorq_u64(x2, rk);
        x3 = veorq_u64(x3, rk);
        x1 = vsubq_u64(x1, y1);
        x2 = vsubq_u64(x2, y2);
        x3 = vsubq_u64(x3, y3);
        x1 = RotateLeft64<8>(x1);
        x2 = RotateLeft64<8>(x2);
        x3 = RotateLeft64<8>(x3);
    }

    x1 = Shuffle64(x1);
    y1 = Shuffle64(y1);
    x2 = Shuffle64(x2);
    y2 = Shuffle64(y2);
    x3 = Shuffle64(x3);
    y3 = Shuffle64(y3);

    block0 = UnpackLow64<uint8x16_t>(x1, y1);
    block1 = UnpackHigh64<uint8x16_t>(x1, y1);
    block2 = UnpackLow64<uint8x16_t>(x2, y2);
    block3 = UnpackHigh64<uint8x16_t>(x2, y2);
    block4 = UnpackLow64<uint8x16_t>(x3, y3);
    block5 = UnpackHigh64<uint8x16_t>(x3, y3);
}

template <typename F1, typename F6>
size_t SPECK128_AdvancedProcessBlocks_NEON(F1 func1, F6 func6,
            const word64 *subKeys, size_t rounds, const byte *inBlocks,
            const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 16);

    const size_t blockSize = 16;
    size_t inIncrement = (flags & (BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_DontIncrementInOutPointers)) ? 0 : blockSize;
    size_t xorIncrement = xorBlocks ? blockSize : 0;
    size_t outIncrement = (flags & BlockTransformation::BT_DontIncrementInOutPointers) ? 0 : blockSize;

    if (flags & BlockTransformation::BT_ReverseDirection)
    {
        inBlocks += length - blockSize;
        xorBlocks += length - blockSize;
        outBlocks += length - blockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BlockTransformation::BT_AllowParallel)
    {
        while (length >= 6*blockSize)
        {
            uint8x16_t block0, block1, block2, block3, block4, block5, temp;
            block0 = vld1q_u8(inBlocks);

            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                uint32x4_t be = vld1q_u32(s_one);
                block1 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block0), be);
                block2 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block1), be);
                block3 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block2), be);
                block4 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block3), be);
                block5 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block4), be);
                temp   = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block5), be);
                vst1q_u8(const_cast<byte*>(inBlocks), temp);
            }
            else
            {
                const int inc = static_cast<int>(inIncrement);
                block1 = vld1q_u8(inBlocks+1*inc);
                block2 = vld1q_u8(inBlocks+2*inc);
                block3 = vld1q_u8(inBlocks+3*inc);
                block4 = vld1q_u8(inBlocks+4*inc);
                block5 = vld1q_u8(inBlocks+5*inc);
                inBlocks += 6*inc;
            }

            if (flags & BlockTransformation::BT_XorInput)
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u8(block0, vld1q_u8(xorBlocks+0*inc));
                block1 = veorq_u8(block1, vld1q_u8(xorBlocks+1*inc));
                block2 = veorq_u8(block2, vld1q_u8(xorBlocks+2*inc));
                block3 = veorq_u8(block3, vld1q_u8(xorBlocks+3*inc));
                block4 = veorq_u8(block4, vld1q_u8(xorBlocks+4*inc));
                block5 = veorq_u8(block5, vld1q_u8(xorBlocks+5*inc));
                xorBlocks += 6*inc;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, rounds);

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u8(block0, vld1q_u8(xorBlocks+0*inc));
                block1 = veorq_u8(block1, vld1q_u8(xorBlocks+1*inc));
                block2 = veorq_u8(block2, vld1q_u8(xorBlocks+2*inc));
                block3 = veorq_u8(block3, vld1q_u8(xorBlocks+3*inc));
                block4 = veorq_u8(block4, vld1q_u8(xorBlocks+4*inc));
                block5 = veorq_u8(block5, vld1q_u8(xorBlocks+5*inc));
                xorBlocks += 6*inc;
            }

            const int inc = static_cast<int>(outIncrement);
            vst1q_u8(outBlocks+0*inc, block0);
            vst1q_u8(outBlocks+1*inc, block1);
            vst1q_u8(outBlocks+2*inc, block2);
            vst1q_u8(outBlocks+3*inc, block3);
            vst1q_u8(outBlocks+4*inc, block4);
            vst1q_u8(outBlocks+5*inc, block5);

            outBlocks += 6*inc;
            length -= 6*blockSize;
        }
    }

    while (length >= blockSize)
    {
        uint8x16_t block = vld1q_u8(inBlocks);

        if (flags & BlockTransformation::BT_XorInput)
            block = veorq_u8(block, vld1q_u8(xorBlocks));

        if (flags & BlockTransformation::BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func1(block, subKeys, rounds);

        if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            block = veorq_u8(block, vld1q_u8(xorBlocks));

        vst1q_u8(outBlocks, block);

        inBlocks += inIncrement;
        outBlocks += outIncrement;
        xorBlocks += xorIncrement;
        length -= blockSize;
    }

    return length;
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// ***************************** IA-32 ***************************** //

#if defined(CRYPTOPP_SSSE3_AVAILABLE)

CRYPTOPP_ALIGN_DATA(16)
const word32 s_one[] = {0, 0, 0, 1<<24};

template <unsigned int R>
inline __m128i RotateLeft64(const __m128i& val)
{
    CRYPTOPP_ASSERT(R < 64);
    const __m128i a(_mm_slli_epi64(val, R));
    const __m128i b(_mm_srli_epi64(val, 64-R));
    return _mm_or_si128(a, b);
}

template <unsigned int R>
inline __m128i RotateRight64(const __m128i& val)
{
    CRYPTOPP_ASSERT(R < 64);
    const __m128i a(_mm_slli_epi64(val, 64-R));
    const __m128i b(_mm_srli_epi64(val, R));
    return _mm_or_si128(a, b);
}

inline void SPECK128_Enc_Block(__m128i &block0, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SPECK128_Enc_Blocks then SPECK128_AdvancedProcessBlocks_SSSE3.
    // The zero block below is a "don't care". It is present so we can vectorize.
    __m128i block1 = _mm_setzero_si128();
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i)));

        x1 = RotateRight64<8>(x1);
        x1 = _mm_add_epi64(x1, y1);
        x1 = _mm_xor_si128(x1, rk);
        y1 = RotateLeft64<3>(y1);
        y1 = _mm_xor_si128(y1, x1);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    block0 = _mm_unpacklo_epi64(x1, y1);
    // block1 = _mm_unpackhi_epi64(x1, y1);
}

inline void SPECK128_Enc_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SPECK128_Enc_Blocks then SPECK128_AdvancedProcessBlocks_SSSE3.
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);
    __m128i x2 = _mm_unpacklo_epi64(block2, block3);
    __m128i y2 = _mm_unpackhi_epi64(block2, block3);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i)));

        x1 = RotateRight64<8>(x1);
        x2 = RotateRight64<8>(x2);
        x1 = _mm_add_epi64(x1, y1);
        x2 = _mm_add_epi64(x2, y2);
        x1 = _mm_xor_si128(x1, rk);
        x2 = _mm_xor_si128(x2, rk);
        y1 = RotateLeft64<3>(y1);
        y2 = RotateLeft64<3>(y2);
        y1 = _mm_xor_si128(y1, x1);
        y2 = _mm_xor_si128(y2, x2);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);

    block0 = _mm_unpacklo_epi64(x1, y1);
    block1 = _mm_unpackhi_epi64(x1, y1);
    block2 = _mm_unpacklo_epi64(x2, y2);
    block3 = _mm_unpackhi_epi64(x2, y2);
}

inline void SPECK128_Dec_Block(__m128i &block0, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SPECK128_Dec_Blocks then SPECK128_AdvancedProcessBlocks_SSSE3.
    // The zero block below is a "don't care". It is present so we can vectorize.
    __m128i block1 = _mm_setzero_si128();
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i)));

        y1 = _mm_xor_si128(y1, x1);
        y1 = RotateRight64<3>(y1);
        x1 = _mm_xor_si128(x1, rk);
        x1 = _mm_sub_epi64(x1, y1);
        x1 = RotateLeft64<8>(x1);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    block0 = _mm_unpacklo_epi64(x1, y1);
    // block1 = _mm_unpackhi_epi64(x1, y1);
}

inline void SPECK128_Dec_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SPECK128_Dec_Blocks then SPECK128_AdvancedProcessBlocks_SSSE3.
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);
    __m128i x2 = _mm_unpacklo_epi64(block2, block3);
    __m128i y2 = _mm_unpackhi_epi64(block2, block3);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i)));

        y1 = _mm_xor_si128(y1, x1);
        y2 = _mm_xor_si128(y2, x2);
        y1 = RotateRight64<3>(y1);
        y2 = RotateRight64<3>(y2);
        x1 = _mm_xor_si128(x1, rk);
        x2 = _mm_xor_si128(x2, rk);
        x1 = _mm_sub_epi64(x1, y1);
        x2 = _mm_sub_epi64(x2, y2);
        x1 = RotateLeft64<8>(x1);
        x2 = RotateLeft64<8>(x2);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);

    block0 = _mm_unpacklo_epi64(x1, y1);
    block1 = _mm_unpackhi_epi64(x1, y1);
    block2 = _mm_unpacklo_epi64(x2, y2);
    block3 = _mm_unpackhi_epi64(x2, y2);
}

template <typename F1, typename F4>
inline size_t SPECK128_AdvancedProcessBlocks_SSSE3(F1 func1, F4 func4,
        const word64 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 16);

    const size_t blockSize = 16;
    size_t inIncrement = (flags & (BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_DontIncrementInOutPointers)) ? 0 : blockSize;
    size_t xorIncrement = xorBlocks ? blockSize : 0;
    size_t outIncrement = (flags & BlockTransformation::BT_DontIncrementInOutPointers) ? 0 : blockSize;

    if (flags & BlockTransformation::BT_ReverseDirection)
    {
        inBlocks += length - blockSize;
        xorBlocks += length - blockSize;
        outBlocks += length - blockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BlockTransformation::BT_AllowParallel)
    {
        while (length >= 4*blockSize)
        {
            __m128i block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks)), block1, block2, block3;
            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                const __m128i be1 = *CONST_M128_CAST(s_one);
                block1 = _mm_add_epi32(block0, be1);
                block2 = _mm_add_epi32(block1, be1);
                block3 = _mm_add_epi32(block2, be1);
                _mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block3, be1));
            }
            else
            {
                inBlocks += inIncrement;
                block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block2 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block3 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
            }

            if (flags & BlockTransformation::BT_XorInput)
            {
                // Coverity finding, appears to be false positive. Assert the condition.
                CRYPTOPP_ASSERT(xorBlocks);
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func4(block0, block1, block2, block3, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            _mm_storeu_si128(M128_CAST(outBlocks), block0);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block1);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block2);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block3);
            outBlocks += outIncrement;

            length -= 4*blockSize;
        }
    }

    while (length >= blockSize)
    {
        __m128i block = _mm_loadu_si128(CONST_M128_CAST(inBlocks));

        if (flags & BlockTransformation::BT_XorInput)
            block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

        if (flags & BlockTransformation::BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func1(block, subKeys, static_cast<unsigned int>(rounds));

        if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

        _mm_storeu_si128(M128_CAST(outBlocks), block);

        inBlocks += inIncrement;
        outBlocks += outIncrement;
        xorBlocks += xorIncrement;
        length -= blockSize;
    }

    return length;
}

#endif  // CRYPTOPP_SSSE3_AVAILABLE

ANONYMOUS_NAMESPACE_END

///////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

// *************************** ARM NEON **************************** //

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
size_t SPECK128_Enc_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK128_AdvancedProcessBlocks_NEON(SPECK128_Enc_Block, SPECK128_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK128_Dec_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK128_AdvancedProcessBlocks_NEON(SPECK128_Dec_Block, SPECK128_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// ***************************** IA-32 ***************************** //

#if defined(CRYPTOPP_SSSE3_AVAILABLE)
size_t SPECK128_Enc_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK128_AdvancedProcessBlocks_SSSE3(SPECK128_Enc_Block, SPECK128_Enc_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK128_Dec_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK128_AdvancedProcessBlocks_SSSE3(SPECK128_Dec_Block, SPECK128_Dec_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_SSSE3_AVAILABLE

NAMESPACE_END
