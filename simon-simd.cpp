// simon-simd.cpp - written and placed in the public domain by Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    SSSE3, ARM NEON and ARMv8a, and Power7 Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"

#include "simon.h"
#include "misc.h"

// Uncomment for benchmarking C++ against SSE or NEON.
// Do so in both simon.cpp and simon-simd.cpp.
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

#if defined(__AVX512F__) && defined(__AVX512VL__)
# define CRYPTOPP_AVX512_ROTATE 1
# include <immintrin.h>
#endif

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlFixed;
using CryptoPP::rotrFixed;
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

#if defined(__aarch32__) || defined(__aarch64__)
// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline uint64x2_t RotateLeft64<8>(const uint64x2_t& val)
{
    const uint8_t maskb[16] = { 14,13,12,11, 10,9,8,15, 6,5,4,3, 2,1,0,7 };
    const uint8x16_t mask = vld1q_u8(maskb);
    return vreinterpretq_u64_u8(
        vqtbl1q_u8(vreinterpretq_u8_u64(val), mask));
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline uint64x2_t RotateRight64<8>(const uint64x2_t& val)
{
    const uint8_t maskb[16] = { 8,15,14,13, 12,11,10,9, 0,7,6,5, 4,3,2,1 };
    const uint8x16_t mask = vld1q_u8(maskb);
    return vreinterpretq_u64_u8(
        vqtbl1q_u8(vreinterpretq_u8_u64(val), mask));
}
#endif

inline uint64x2_t Shuffle64(const uint64x2_t& val)
{
#if defined(CRYPTOPP_LITTLE_ENDIAN)
    return vreinterpretq_u64_u8(
        vrev64q_u8(vreinterpretq_u8_u64(val)));
#else
    return val;
#endif
}

inline uint64x2_t SIMON128_f(const uint64x2_t& val)
{
    return veorq_u64(RotateLeft64<2>(val),
        vandq_u64(RotateLeft64<1>(val), RotateLeft64<8>(val)));
}

inline void SIMON128_Enc_Block(uint8x16_t &block0, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SIMON128_Enc_Blocks then SIMON128_AdvancedProcessBlocks_NEON.
    // The zero block below is a "don't care". It is present so we can vectorize.
    uint8x16_t block1 = {0};
    uint64x2_t x1 = UnpackLow64<uint64x2_t>(block0, block1);
    uint64x2_t y1 = UnpackHigh64<uint64x2_t>(block0, block1);

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);

    for (size_t i = 0; static_cast<int>(i) < (rounds & ~1)-1; i += 2)
    {
        const uint64x2_t rk1 = vld1q_dup_u64(subkeys+i);
        y1 = veorq_u64(veorq_u64(y1, SIMON128_f(x1)), rk1);

        const uint64x2_t rk2 = vld1q_dup_u64(subkeys+i+1);
        x1 = veorq_u64(veorq_u64(x1, SIMON128_f(y1)), rk2);
    }

    if (rounds & 1)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+rounds-1);

        y1 = veorq_u64(veorq_u64(y1, SIMON128_f(x1)), rk);
        std::swap(x1, y1);
    }

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);

    block0 = UnpackLow64<uint8x16_t>(x1, y1);
    // block1 = UnpackHigh64<uint8x16_t>(x1, y1);
}

inline void SIMON128_Enc_6_Blocks(uint8x16_t &block0, uint8x16_t &block1,
            uint8x16_t &block2, uint8x16_t &block3, uint8x16_t &block4,
            uint8x16_t &block5, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SIMON128_Enc_Blocks then SIMON128_AdvancedProcessBlocks_NEON.
    uint64x2_t x1 = UnpackLow64<uint64x2_t>(block0, block1);
    uint64x2_t y1 = UnpackHigh64<uint64x2_t>(block0, block1);
    uint64x2_t x2 = UnpackLow64<uint64x2_t>(block2, block3);
    uint64x2_t y2 = UnpackHigh64<uint64x2_t>(block2, block3);
    uint64x2_t x3 = UnpackLow64<uint64x2_t>(block4, block5);
    uint64x2_t y3 = UnpackHigh64<uint64x2_t>(block4, block5);

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);
    x2 = Shuffle64(x2); y2 = Shuffle64(y2);
    x3 = Shuffle64(x3); y3 = Shuffle64(y3);

    for (size_t i = 0; static_cast<int>(i) < (rounds & ~1) - 1; i += 2)
    {
        const uint64x2_t rk1 = vld1q_dup_u64(subkeys+i);
        y1 = veorq_u64(veorq_u64(y1, SIMON128_f(x1)), rk1);
        y2 = veorq_u64(veorq_u64(y2, SIMON128_f(x2)), rk1);
        y3 = veorq_u64(veorq_u64(y3, SIMON128_f(x3)), rk1);

        const uint64x2_t rk2 = vld1q_dup_u64(subkeys+i+1);
        x1 = veorq_u64(veorq_u64(x1, SIMON128_f(y1)), rk2);
        x2 = veorq_u64(veorq_u64(x2, SIMON128_f(y2)), rk2);
        x3 = veorq_u64(veorq_u64(x3, SIMON128_f(y3)), rk2);
    }

    if (rounds & 1)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys + rounds - 1);

        y1 = veorq_u64(veorq_u64(y1, SIMON128_f(x1)), rk);
        y2 = veorq_u64(veorq_u64(y2, SIMON128_f(x2)), rk);
        y3 = veorq_u64(veorq_u64(y3, SIMON128_f(x3)), rk);
        std::swap(x1, y1); std::swap(x2, y2); std::swap(x3, y3);
    }

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);
    x2 = Shuffle64(x2); y2 = Shuffle64(y2);
    x3 = Shuffle64(x3); y3 = Shuffle64(y3);

    block0 = UnpackLow64<uint8x16_t>(x1, y1);
    block1 = UnpackHigh64<uint8x16_t>(x1, y1);
    block2 = UnpackLow64<uint8x16_t>(x2, y2);
    block3 = UnpackHigh64<uint8x16_t>(x2, y2);
    block4 = UnpackLow64<uint8x16_t>(x3, y3);
    block5 = UnpackHigh64<uint8x16_t>(x3, y3);
}

inline void SIMON128_Dec_Block(uint8x16_t &block0, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SIMON128_Dec_Blocks then SIMON128_AdvancedProcessBlocks_NEON.
    // The zero block below is a "don't care". It is present so we can vectorize.
    uint8x16_t block1 = {0};
    uint64x2_t x1 = UnpackLow64<uint64x2_t>(block0, block1);
    uint64x2_t y1 = UnpackHigh64<uint64x2_t>(block0, block1);

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);

    if (rounds & 1)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys + rounds - 1);
        std::swap(x1, y1);
        y1 = veorq_u64(veorq_u64(y1, rk), SIMON128_f(x1));
        rounds--;
    }

    for (size_t i = rounds-2; static_cast<int>(i) >= 0; i -= 2)
    {
        const uint64x2_t rk1 = vld1q_dup_u64(subkeys+i+1);
        x1 = veorq_u64(veorq_u64(x1, SIMON128_f(y1)), rk1);

        const uint64x2_t rk2 = vld1q_dup_u64(subkeys+i);
        y1 = veorq_u64(veorq_u64(y1, SIMON128_f(x1)), rk2);
    }

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);

    block0 = UnpackLow64<uint8x16_t>(x1, y1);
    // block1 = UnpackHigh64<uint8x16_t>(x1, y1);
}

inline void SIMON128_Dec_6_Blocks(uint8x16_t &block0, uint8x16_t &block1,
            uint8x16_t &block2, uint8x16_t &block3, uint8x16_t &block4,
            uint8x16_t &block5, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SIMON128_Dec_Blocks then SIMON128_AdvancedProcessBlocks_NEON.
    uint64x2_t x1 = UnpackLow64<uint64x2_t>(block0, block1);
    uint64x2_t y1 = UnpackHigh64<uint64x2_t>(block0, block1);
    uint64x2_t x2 = UnpackLow64<uint64x2_t>(block2, block3);
    uint64x2_t y2 = UnpackHigh64<uint64x2_t>(block2, block3);
    uint64x2_t x3 = UnpackLow64<uint64x2_t>(block4, block5);
    uint64x2_t y3 = UnpackHigh64<uint64x2_t>(block5, block5);

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);
    x2 = Shuffle64(x2); y2 = Shuffle64(y2);
    x3 = Shuffle64(x3); y3 = Shuffle64(y3);

    if (rounds & 1)
    {
        std::swap(x1, y1); std::swap(x2, y2); std::swap(x3, y3);
        const uint64x2_t rk = vld1q_dup_u64(subkeys + rounds - 1);

        y1 = veorq_u64(veorq_u64(y1, rk), SIMON128_f(x1));
        y2 = veorq_u64(veorq_u64(y2, rk), SIMON128_f(x2));
        rounds--;
    }

    for (size_t i = rounds - 2; static_cast<int>(i) >= 0; i -= 2)
    {
        const uint64x2_t rk1 = vld1q_dup_u64(subkeys + i + 1);
        x1 = veorq_u64(veorq_u64(x1, SIMON128_f(y1)), rk1);
        x2 = veorq_u64(veorq_u64(x2, SIMON128_f(y2)), rk1);
        x3 = veorq_u64(veorq_u64(x3, SIMON128_f(y3)), rk1);

        const uint64x2_t rk2 = vld1q_dup_u64(subkeys + i);
        y1 = veorq_u64(veorq_u64(y1, SIMON128_f(x1)), rk2);
        y2 = veorq_u64(veorq_u64(y2, SIMON128_f(x2)), rk2);
        y3 = veorq_u64(veorq_u64(y3, SIMON128_f(x3)), rk2);
    }

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);
    x2 = Shuffle64(x2); y2 = Shuffle64(y2);
    x3 = Shuffle64(x3); y3 = Shuffle64(y3);

    block0 = UnpackLow64<uint8x16_t>(x1, y1);
    block1 = UnpackHigh64<uint8x16_t>(x1, y1);
    block2 = UnpackLow64<uint8x16_t>(x2, y2);
    block3 = UnpackHigh64<uint8x16_t>(x2, y2);
    block4 = UnpackLow64<uint8x16_t>(x3, y3);
    block5 = UnpackHigh64<uint8x16_t>(x3, y3);
}

template <typename F1, typename F6>
size_t SIMON128_AdvancedProcessBlocks_NEON(F1 func1, F6 func6,
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

inline void Swap128(__m128i& a,__m128i& b)
{
#if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x5120)
    // __m128i is an unsigned long long[2], and support for swapping it was not added until C++11.
    // SunCC 12.1 - 12.3 fail to consume the swap; while SunCC 12.4 consumes it without -std=c++11.
    vec_swap(a, b);
#else
    std::swap(a, b);
#endif
}

#if defined(CRYPTOPP_AVX512_ROTATE)
template <unsigned int R>
inline __m128i RotateLeft64(const __m128i& val)
{
    return _mm_rol_epi64(val, R);
}

template <unsigned int R>
inline __m128i RotateRight64(const __m128i& val)
{
    return _mm_ror_epi64(val, R);
}
#else
template <unsigned int R>
inline __m128i RotateLeft64(const __m128i& val)
{
    return _mm_or_si128(
        _mm_slli_epi64(val, R), _mm_srli_epi64(val, 64-R));
}

template <unsigned int R>
inline __m128i RotateRight64(const __m128i& val)
{
    return _mm_or_si128(
        _mm_slli_epi64(val, 64-R), _mm_srli_epi64(val, R));
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline __m128i RotateLeft64<8>(const __m128i& val)
{
    const __m128i mask = _mm_set_epi8(14,13,12,11, 10,9,8,15, 6,5,4,3, 2,1,0,7);
    return _mm_shuffle_epi8(val, mask);
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline __m128i RotateRight64<8>(const __m128i& val)
{
    const __m128i mask = _mm_set_epi8(8,15,14,13, 12,11,10,9, 0,7,6,5, 4,3,2,1);
    return _mm_shuffle_epi8(val, mask);
}
#endif  // CRYPTOPP_AVX512_ROTATE

inline __m128i SIMON128_f(const __m128i& v)
{
    return _mm_xor_si128(RotateLeft64<2>(v),
        _mm_and_si128(RotateLeft64<1>(v), RotateLeft64<8>(v)));
}

inline void SIMON128_Enc_Block(__m128i &block0, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SIMON128_Enc_Blocks then SIMON128_AdvancedProcessBlocks_SSSE3.
    // The zero block below is a "don't care". It is present so we can vectorize.
    __m128i block1 = _mm_setzero_si128();
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    for (size_t i = 0; static_cast<int>(i) < (rounds & ~1)-1; i += 2)
    {
        const __m128i rk1 = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i)));
        y1 = _mm_xor_si128(_mm_xor_si128(y1, SIMON128_f(x1)), rk1);

        const __m128i rk2 = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i+1)));
        x1 = _mm_xor_si128(_mm_xor_si128(x1, SIMON128_f(y1)), rk2);
    }

    if (rounds & 1)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+rounds-1)));

        y1 = _mm_xor_si128(_mm_xor_si128(y1, SIMON128_f(x1)), rk);
        Swap128(x1, y1);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    block0 = _mm_unpacklo_epi64(x1, y1);
    // block1 = _mm_unpackhi_epi64(x1, y1);
}

inline void SIMON128_Enc_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SIMON128_Enc_Blocks then SIMON128_AdvancedProcessBlocks_SSSE3.
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);
    __m128i x2 = _mm_unpacklo_epi64(block2, block3);
    __m128i y2 = _mm_unpackhi_epi64(block2, block3);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);

    for (size_t i = 0; static_cast<int>(i) < (rounds & ~1) - 1; i += 2)
    {
        const __m128i rk1 = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys + i)));
        y1 = _mm_xor_si128(_mm_xor_si128(y1, SIMON128_f(x1)), rk1);
        y2 = _mm_xor_si128(_mm_xor_si128(y2, SIMON128_f(x2)), rk1);

        const __m128i rk2 = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys + i + 1)));
        x1 = _mm_xor_si128(_mm_xor_si128(x1, SIMON128_f(y1)), rk2);
        x2 = _mm_xor_si128(_mm_xor_si128(x2, SIMON128_f(y2)), rk2);
    }

    if (rounds & 1)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys + rounds - 1)));
        y1 = _mm_xor_si128(_mm_xor_si128(y1, SIMON128_f(x1)), rk);
        y2 = _mm_xor_si128(_mm_xor_si128(y2, SIMON128_f(x2)), rk);
        Swap128(x1, y1); Swap128(x2, y2);
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

inline void SIMON128_Dec_Block(__m128i &block0, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SIMON128_Dec_Blocks then SIMON128_AdvancedProcessBlocks_SSSE3.
    // The zero block below is a "don't care". It is present so we can vectorize.
    __m128i block1 = _mm_setzero_si128();
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    if (rounds & 1)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys + rounds - 1)));

        Swap128(x1, y1);
        y1 = _mm_xor_si128(_mm_xor_si128(y1, rk), SIMON128_f(x1));
        rounds--;
    }

    for (size_t i = rounds-2; static_cast<int>(i) >= 0; i -= 2)
    {
        const __m128i rk1 = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i+1)));
        x1 = _mm_xor_si128(_mm_xor_si128(x1, SIMON128_f(y1)), rk1);

        const __m128i rk2 = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i)));
        y1 = _mm_xor_si128(_mm_xor_si128(y1, SIMON128_f(x1)), rk2);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    block0 = _mm_unpacklo_epi64(x1, y1);
    // block1 = _mm_unpackhi_epi64(x1, y1);
}

inline void SIMON128_Dec_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word64 *subkeys, unsigned int rounds)
{
    // Hack ahead... Rearrange the data for vectorization. It is easier to permute
    // the data in SIMON128_Dec_Blocks then SIMON128_AdvancedProcessBlocks_SSSE3.
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);
    __m128i x2 = _mm_unpacklo_epi64(block2, block3);
    __m128i y2 = _mm_unpackhi_epi64(block2, block3);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);

    if (rounds & 1)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys + rounds - 1)));

        Swap128(x1, y1); Swap128(x2, y2);
        y1 = _mm_xor_si128(_mm_xor_si128(y1, rk), SIMON128_f(x1));
        y2 = _mm_xor_si128(_mm_xor_si128(y2, rk), SIMON128_f(x2));
        rounds--;
    }

    for (size_t i = rounds - 2; static_cast<int>(i) >= 0; i -= 2)
    {
        const __m128i rk1 = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys + i + 1)));
        x1 = _mm_xor_si128(_mm_xor_si128(x1, SIMON128_f(y1)), rk1);
        x2 = _mm_xor_si128(_mm_xor_si128(x2, SIMON128_f(y2)), rk1);

        const __m128i rk2 = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys + i)));
        y1 = _mm_xor_si128(_mm_xor_si128(y1, SIMON128_f(x1)), rk2);
        y2 = _mm_xor_si128(_mm_xor_si128(y2, SIMON128_f(x2)), rk2);
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
inline size_t SIMON128_AdvancedProcessBlocks_SSSE3(F1 func1, F4 func4,
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
size_t SIMON128_Enc_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SIMON128_AdvancedProcessBlocks_NEON(SIMON128_Enc_Block, SIMON128_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SIMON128_Dec_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SIMON128_AdvancedProcessBlocks_NEON(SIMON128_Dec_Block, SIMON128_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// ***************************** IA-32 ***************************** //

#if defined(CRYPTOPP_SSSE3_AVAILABLE)
size_t SIMON128_Enc_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SIMON128_AdvancedProcessBlocks_SSSE3(SIMON128_Enc_Block, SIMON128_Enc_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SIMON128_Dec_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SIMON128_AdvancedProcessBlocks_SSSE3(SIMON128_Dec_Block, SIMON128_Dec_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_SSSE3_AVAILABLE

NAMESPACE_END
