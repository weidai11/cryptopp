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
// #undef CRYPTOPP_SSE41_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_SSSE3_AVAILABLE)
# include <tmmintrin.h>
#endif

#if (CRYPTOPP_SSE41_AVAILABLE)
# include <smmintrin.h>
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
using CryptoPP::BlockTransformation;

// *************************** ARM NEON ************************** //

#if defined(CRYPTOPP_ARM_NEON_AVAILABLE)

#if defined(CRYPTOPP_LITTLE_ENDIAN)
const word32 s_one64[] = {0, 1<<24, 0, 1<<24};
#else
const word32 s_one64[] = {0, 1, 0, 1};
#endif

template <unsigned int R>
inline uint32x4_t RotateLeft32(const uint32x4_t& val)
{
    CRYPTOPP_ASSERT(R < 32);
    const uint32x4_t a(vshlq_n_u32(val, R));
    const uint32x4_t b(vshrq_n_u32(val, 32 - R));
    return vorrq_u32(a, b);
}

template <unsigned int R>
inline uint32x4_t RotateRight32(const uint32x4_t& val)
{
    CRYPTOPP_ASSERT(R < 32);
    const uint32x4_t a(vshlq_n_u32(val, 32 - R));
    const uint32x4_t b(vshrq_n_u32(val, R));
    return vorrq_u32(a, b);
}

#if defined(__aarch32__) || defined(__aarch64__)
// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline uint32x4_t RotateLeft32<8>(const uint32x4_t& val)
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    const uint8_t maskb[16] = { 14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3 };
    const uint8x16_t mask = vld1q_u8(maskb);
#else
    const uint8_t maskb[16] = { 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 };
    const uint8x16_t mask = vld1q_u8(maskb);
#endif

    return vreinterpretq_u32_u8(
        vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline uint32x4_t RotateRight32<8>(const uint32x4_t& val)
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    const uint8_t maskb[16] = { 12,15,14,13, 8,11,10,9, 4,7,6,5, 0,3,2,1 };
    const uint8x16_t mask = vld1q_u8(maskb);
#else
    const uint8_t maskb[16] = { 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,14,12 };
    const uint8x16_t mask = vld1q_u8(maskb);
#endif

    return vreinterpretq_u32_u8(
        vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
}
#endif

inline uint32x4_t Shuffle32(const uint32x4_t& val)
{
#if defined(CRYPTOPP_LITTLE_ENDIAN)
    return vreinterpretq_u32_u8(
        vrev32q_u8(vreinterpretq_u8_u32(val)));
#else
    return val;
#endif
}

template <typename T>
inline word32* Ptr32(T* ptr)
{
    return reinterpret_cast<word32*>(ptr);
}

template <typename T>
inline const word32* Ptr32(const T* ptr)
{
    return reinterpret_cast<const word32*>(ptr);
}

template <typename T>
inline word64* Ptr64(T* ptr)
{
    return reinterpret_cast<word64*>(ptr);
}

template <typename T>
inline const word64* Ptr64(const T* ptr)
{
    return reinterpret_cast<const word64*>(ptr);
}

inline void SPECK64_Enc_Block(uint32x4_t &block0, uint32x4_t &block1,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const uint32x4x2_t t0 = vuzpq_u32(block0, block1);
    uint32x4_t x1 = t0.val[0];
    uint32x4_t y1 = t0.val[1];

    x1 = Shuffle32(x1); y1 = Shuffle32(y1);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const uint32x4_t rk = vdupq_n_u32(subkeys[i]);

        x1 = RotateRight32<8>(x1);
        x1 = vaddq_u32(x1, y1);
        x1 = veorq_u32(x1, rk);
        y1 = RotateLeft32<3>(y1);
        y1 = veorq_u32(y1, x1);
    }

    x1 = Shuffle32(x1); y1 = Shuffle32(y1);

    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    const uint32x4x2_t t1 = vzipq_u32(x1, y1);
    block0 = t1.val[0];
    block1 = t1.val[1];
}

inline void SPECK64_Dec_Block(uint32x4_t &block0, uint32x4_t &block1,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const uint32x4x2_t t0 = vuzpq_u32(block0, block1);
    uint32x4_t x1 = t0.val[0];
    uint32x4_t y1 = t0.val[1];

    x1 = Shuffle32(x1); y1 = Shuffle32(y1);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const uint32x4_t rk = vdupq_n_u32(subkeys[i]);

        y1 = veorq_u32(y1, x1);
        y1 = RotateRight32<3>(y1);
        x1 = veorq_u32(x1, rk);
        x1 = vsubq_u32(x1, y1);
        x1 = RotateLeft32<8>(x1);
    }

    x1 = Shuffle32(x1); y1 = Shuffle32(y1);

    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    const uint32x4x2_t t1 = vzipq_u32(x1, y1);
    block0 = t1.val[0];
    block1 = t1.val[1];
}

inline void SPECK64_Enc_6_Blocks(uint32x4_t &block0, uint32x4_t &block1,
    uint32x4_t &block2, uint32x4_t &block3, uint32x4_t &block4, uint32x4_t &block5,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following. If only a single block is available then
    // a Zero block is provided to promote vectorizations.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const uint32x4x2_t t0 = vuzpq_u32(block0, block1);
    uint32x4_t x1 = t0.val[0];
    uint32x4_t y1 = t0.val[1];

    const uint32x4x2_t t1 = vuzpq_u32(block2, block3);
    uint32x4_t x2 = t1.val[0];
    uint32x4_t y2 = t1.val[1];

    const uint32x4x2_t t2 = vuzpq_u32(block4, block5);
    uint32x4_t x3 = t2.val[0];
    uint32x4_t y3 = t2.val[1];

    x1 = Shuffle32(x1); y1 = Shuffle32(y1);
    x2 = Shuffle32(x2); y2 = Shuffle32(y2);
    x3 = Shuffle32(x3); y3 = Shuffle32(y3);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const uint32x4_t rk = vdupq_n_u32(subkeys[i]);

        x1 = RotateRight32<8>(x1);
        x2 = RotateRight32<8>(x2);
        x3 = RotateRight32<8>(x3);
        x1 = vaddq_u32(x1, y1);
        x2 = vaddq_u32(x2, y2);
        x3 = vaddq_u32(x3, y3);
        x1 = veorq_u32(x1, rk);
        x2 = veorq_u32(x2, rk);
        x3 = veorq_u32(x3, rk);
        y1 = RotateLeft32<3>(y1);
        y2 = RotateLeft32<3>(y2);
        y3 = RotateLeft32<3>(y3);
        y1 = veorq_u32(y1, x1);
        y2 = veorq_u32(y2, x2);
        y3 = veorq_u32(y3, x3);
    }

    x1 = Shuffle32(x1); y1 = Shuffle32(y1);
    x2 = Shuffle32(x2); y2 = Shuffle32(y2);
    x3 = Shuffle32(x3); y3 = Shuffle32(y3);

    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    const uint32x4x2_t t3 = vzipq_u32(x1, y1);
    block0 = t3.val[0];
    block1 = t3.val[1];

    const uint32x4x2_t t4 = vzipq_u32(x2, y2);
    block2 = t4.val[0];
    block3 = t4.val[1];

    const uint32x4x2_t t5 = vzipq_u32(x3, y3);
    block4 = t5.val[0];
    block5 = t5.val[1];
}

inline void SPECK64_Dec_6_Blocks(uint32x4_t &block0, uint32x4_t &block1,
    uint32x4_t &block2, uint32x4_t &block3, uint32x4_t &block4, uint32x4_t &block5,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following. If only a single block is available then
    // a Zero block is provided to promote vectorizations.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const uint32x4x2_t t0 = vuzpq_u32(block0, block1);
    uint32x4_t x1 = t0.val[0];
    uint32x4_t y1 = t0.val[1];

    const uint32x4x2_t t1 = vuzpq_u32(block2, block3);
    uint32x4_t x2 = t1.val[0];
    uint32x4_t y2 = t1.val[1];

    const uint32x4x2_t t2 = vuzpq_u32(block4, block5);
    uint32x4_t x3 = t2.val[0];
    uint32x4_t y3 = t2.val[1];

    x1 = Shuffle32(x1); y1 = Shuffle32(y1);
    x2 = Shuffle32(x2); y2 = Shuffle32(y2);
    x3 = Shuffle32(x3); y3 = Shuffle32(y3);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const uint32x4_t rk = vdupq_n_u32(subkeys[i]);

        y1 = veorq_u32(y1, x1);
        y2 = veorq_u32(y2, x2);
        y3 = veorq_u32(y3, x3);
        y1 = RotateRight32<3>(y1);
        y2 = RotateRight32<3>(y2);
        y3 = RotateRight32<3>(y3);
        x1 = veorq_u32(x1, rk);
        x2 = veorq_u32(x2, rk);
        x3 = veorq_u32(x3, rk);
        x1 = vsubq_u32(x1, y1);
        x2 = vsubq_u32(x2, y2);
        x3 = vsubq_u32(x3, y3);
        x1 = RotateLeft32<8>(x1);
        x2 = RotateLeft32<8>(x2);
        x3 = RotateLeft32<8>(x3);
    }

    x1 = Shuffle32(x1); y1 = Shuffle32(y1);
    x2 = Shuffle32(x2); y2 = Shuffle32(y2);
    x3 = Shuffle32(x3); y3 = Shuffle32(y3);

    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    const uint32x4x2_t t3 = vzipq_u32(x1, y1);
    block0 = t3.val[0];
    block1 = t3.val[1];

    const uint32x4x2_t t4 = vzipq_u32(x2, y2);
    block2 = t4.val[0];
    block3 = t4.val[1];

    const uint32x4x2_t t5 = vzipq_u32(x3, y3);
    block4 = t5.val[0];
    block5 = t5.val[1];
}

template <typename F2, typename F6>
inline size_t SPECK64_AdvancedProcessBlocks_NEON(F2 func2, F6 func6,
        const word32 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 8);

    const size_t neonBlockSize = 16;
    size_t inIncrement = (flags & (BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_DontIncrementInOutPointers)) ? 0 : neonBlockSize;
    size_t xorIncrement = xorBlocks ? neonBlockSize : 0;
    size_t outIncrement = (flags & BlockTransformation::BT_DontIncrementInOutPointers) ? 0 : neonBlockSize;

    if (flags & BlockTransformation::BT_ReverseDirection)
    {
        inBlocks += length - neonBlockSize;
        xorBlocks += length - neonBlockSize;
        outBlocks += length - neonBlockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BlockTransformation::BT_AllowParallel)
    {
        while (length >= 6*neonBlockSize)
        {
            uint32x4_t block0, block1, block2, block3, block4, block5;
            block0 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));

            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                const uint32x4_t be1 = vld1q_u32(s_one64);
                block1 = vaddq_u32(block0, be1);
                block2 = vaddq_u32(block1, be1);
                block3 = vaddq_u32(block2, be1);
                block4 = vaddq_u32(block3, be1);
                block5 = vaddq_u32(block4, be1);
                vst1q_u8(const_cast<byte*>(inBlocks),
                    vreinterpretq_u8_u32(vaddq_u32(block5, be1)));
            }
            else
            {
                const int inc = static_cast<int>(inIncrement);
                block1 = vreinterpretq_u32_u8(vld1q_u8(inBlocks+1*inc));
                block2 = vreinterpretq_u32_u8(vld1q_u8(inBlocks+2*inc));
                block3 = vreinterpretq_u32_u8(vld1q_u8(inBlocks+3*inc));
                block4 = vreinterpretq_u32_u8(vld1q_u8(inBlocks+4*inc));
                block5 = vreinterpretq_u32_u8(vld1q_u8(inBlocks+5*inc));
                inBlocks += 6*inc;
            }

            if (flags & BlockTransformation::BT_XorInput)
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u32(block0, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+0*inc)));
                block1 = veorq_u32(block1, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+1*inc)));
                block2 = veorq_u32(block2, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+2*inc)));
                block3 = veorq_u32(block3, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+3*inc)));
                block4 = veorq_u32(block4, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+4*inc)));
                block5 = veorq_u32(block5, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+5*inc)));
                xorBlocks += 6*inc;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u32(block0, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+0*inc)));
                block1 = veorq_u32(block1, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+1*inc)));
                block2 = veorq_u32(block2, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+2*inc)));
                block3 = veorq_u32(block3, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+3*inc)));
                block4 = veorq_u32(block4, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+4*inc)));
                block5 = veorq_u32(block5, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+5*inc)));
                xorBlocks += 6*inc;
            }

            const int inc = static_cast<int>(outIncrement);
            vst1q_u8(outBlocks+0*inc, vreinterpretq_u8_u32(block0));
            vst1q_u8(outBlocks+1*inc, vreinterpretq_u8_u32(block1));
            vst1q_u8(outBlocks+2*inc, vreinterpretq_u8_u32(block2));
            vst1q_u8(outBlocks+3*inc, vreinterpretq_u8_u32(block3));
            vst1q_u8(outBlocks+4*inc, vreinterpretq_u8_u32(block4));
            vst1q_u8(outBlocks+5*inc, vreinterpretq_u8_u32(block5));

            outBlocks += 6*inc;
            length -= 6*neonBlockSize;
        }

        while (length >= 2*neonBlockSize)
        {
            uint32x4_t block0, block1;
            block0 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));

            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                const uint32x4_t be1 = vld1q_u32(s_one64);
                block1 = vaddq_u32(block0, be1);
                vst1q_u8(const_cast<byte*>(inBlocks),
                    vreinterpretq_u8_u32(vaddq_u32(block1, be1)));
            }
            else
            {
                const int inc = static_cast<int>(inIncrement);
                block1 = vreinterpretq_u32_u8(vld1q_u8(inBlocks+1*inc));
                inBlocks += 2*inc;
            }

            if (flags & BlockTransformation::BT_XorInput)
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u32(block0, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+0*inc)));
                block1 = veorq_u32(block1, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+1*inc)));
                xorBlocks += 2*inc;
            }

            func2(block0, block1, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u32(block0, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+0*inc)));
                block1 = veorq_u32(block1, vreinterpretq_u32_u8(vld1q_u8(xorBlocks+1*inc)));
                xorBlocks += 2*inc;
            }

            const int inc = static_cast<int>(outIncrement);
            vst1q_u8(outBlocks+0*inc, vreinterpretq_u8_u32(block0));
            vst1q_u8(outBlocks+1*inc, vreinterpretq_u8_u32(block1));

            outBlocks += 2*inc;
            length -= 2*neonBlockSize;
        }
    }

    if (length)
    {
        // Adjust to real block size
        const size_t blockSize = 8;
        if (flags & BlockTransformation::BT_ReverseDirection)
        {
            inIncrement += inIncrement ? blockSize : 0;
            xorIncrement += xorIncrement ? blockSize : 0;
            outIncrement += outIncrement ? blockSize : 0;
            inBlocks -= inIncrement;
            xorBlocks -= xorIncrement;
            outBlocks -= outIncrement;
        }
        else
        {
            inIncrement -= inIncrement ? blockSize : 0;
            xorIncrement -= xorIncrement ? blockSize : 0;
            outIncrement -= outIncrement ? blockSize : 0;
        }

        while (length >= blockSize)
        {
            uint32x4_t block, zero = {0,0,0,0};
            block = vsetq_lane_u32(Ptr32(inBlocks)[0], block, 0);
            block = vsetq_lane_u32(Ptr32(inBlocks)[1], block, 1);

            if (flags & BlockTransformation::BT_XorInput)
            {
                uint32x4_t x;
                x = vsetq_lane_u32(Ptr32(xorBlocks)[0], x, 0);
                x = vsetq_lane_u32(Ptr32(xorBlocks)[1], x, 1);
                block = veorq_u32(block, x);
            }

            if (flags & BlockTransformation::BT_InBlockIsCounter)
                const_cast<byte *>(inBlocks)[7]++;

            func2(block, zero, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                uint32x4_t x;
                x = vsetq_lane_u32(Ptr32(xorBlocks)[0], x, 0);
                x = vsetq_lane_u32(Ptr32(xorBlocks)[1], x, 1);
                block = veorq_u32(block, x);
            }

            word32 t[2];
            t[0] = vgetq_lane_u32(block, 0);
            t[1] = vgetq_lane_u32(block, 1);
            std::memcpy(outBlocks, t, sizeof(t));

            inBlocks += inIncrement;
            outBlocks += outIncrement;
            xorBlocks += xorIncrement;
            length -= blockSize;
        }
    }

    return length;
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

#if defined(CRYPTOPP_ARM_NEON_AVAILABLE)

#if defined(CRYPTOPP_LITTLE_ENDIAN)
const word32 s_one128[] = {0, 0, 0, 1<<24};
#else
const word32 s_one128[] = {0, 0, 0, 1};
#endif

template <class T>
inline T UnpackHigh64(const T& a, const T& b)
{
    const uint64x1_t x(vget_high_u64((uint64x2_t)a));
    const uint64x1_t y(vget_high_u64((uint64x2_t)b));
    return (T)vcombine_u64(x, y);
}

template <class T>
inline T UnpackLow64(const T& a, const T& b)
{
    const uint64x1_t x(vget_low_u64((uint64x2_t)a));
    const uint64x1_t y(vget_low_u64((uint64x2_t)b));
    return (T)vcombine_u64(x, y);
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
#if defined(CRYPTOPP_BIG_ENDIAN)
    const uint8_t maskb[16] = { 14,13,12,11, 10,9,8,15, 6,5,4,3, 2,1,0,7 };
    const uint8x16_t mask = vld1q_u8(maskb);
#else
    const uint8_t maskb[16] = { 7,0,1,2, 3,4,5,6, 15,8,9,10, 11,12,13,14 };
    const uint8x16_t mask = vld1q_u8(maskb);
#endif

    return vreinterpretq_u64_u8(
        vqtbl1q_u8(vreinterpretq_u8_u64(val), mask));
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline uint64x2_t RotateRight64<8>(const uint64x2_t& val)
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    const uint8_t maskb[16] = { 8,15,14,13, 12,11,10,9, 0,7,6,5, 4,3,2,1 };
    const uint8x16_t mask = vld1q_u8(maskb);
#else
    const uint8_t maskb[16] = { 1,2,3,4, 5,6,7,0, 9,10,11,12, 13,14,15,8 };
    const uint8x16_t mask = vld1q_u8(maskb);
#endif

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

inline void SPECK128_Enc_Block(uint64x2_t &block0, uint64x2_t &block1,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    uint64x2_t x1 = UnpackLow64(block0, block1);
    uint64x2_t y1 = UnpackHigh64(block0, block1);

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+i);

        x1 = RotateRight64<8>(x1);
        x1 = vaddq_u64(x1, y1);
        x1 = veorq_u64(x1, rk);
        y1 = RotateLeft64<3>(y1);
        y1 = veorq_u64(y1, x1);
    }

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = UnpackLow64(x1, y1);
    block1 = UnpackHigh64(x1, y1);
}

inline void SPECK128_Enc_6_Blocks(uint64x2_t &block0, uint64x2_t &block1,
    uint64x2_t &block2, uint64x2_t &block3, uint64x2_t &block4, uint64x2_t &block5,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    uint64x2_t x1 = UnpackLow64(block0, block1);
    uint64x2_t y1 = UnpackHigh64(block0, block1);
    uint64x2_t x2 = UnpackLow64(block2, block3);
    uint64x2_t y2 = UnpackHigh64(block2, block3);
    uint64x2_t x3 = UnpackLow64(block4, block5);
    uint64x2_t y3 = UnpackHigh64(block4, block5);

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);
    x2 = Shuffle64(x2); y2 = Shuffle64(y2);
    x3 = Shuffle64(x3); y3 = Shuffle64(y3);

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

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);
    x2 = Shuffle64(x2); y2 = Shuffle64(y2);
    x3 = Shuffle64(x3); y3 = Shuffle64(y3);

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = UnpackLow64(x1, y1);
    block1 = UnpackHigh64(x1, y1);
    block2 = UnpackLow64(x2, y2);
    block3 = UnpackHigh64(x2, y2);
    block4 = UnpackLow64(x3, y3);
    block5 = UnpackHigh64(x3, y3);
}

inline void SPECK128_Dec_Block(uint64x2_t &block0, uint64x2_t &block1,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    uint64x2_t x1 = UnpackLow64(block0, block1);
    uint64x2_t y1 = UnpackHigh64(block0, block1);

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+i);

        y1 = veorq_u64(y1, x1);
        y1 = RotateRight64<3>(y1);
        x1 = veorq_u64(x1, rk);
        x1 = vsubq_u64(x1, y1);
        x1 = RotateLeft64<8>(x1);
    }

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = UnpackLow64(x1, y1);
    block1 = UnpackHigh64(x1, y1);
}

inline void SPECK128_Dec_6_Blocks(uint64x2_t &block0, uint64x2_t &block1,
    uint64x2_t &block2, uint64x2_t &block3, uint64x2_t &block4, uint64x2_t &block5,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    uint64x2_t x1 = UnpackLow64(block0, block1);
    uint64x2_t y1 = UnpackHigh64(block0, block1);
    uint64x2_t x2 = UnpackLow64(block2, block3);
    uint64x2_t y2 = UnpackHigh64(block2, block3);
    uint64x2_t x3 = UnpackLow64(block4, block5);
    uint64x2_t y3 = UnpackHigh64(block4, block5);

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);
    x2 = Shuffle64(x2); y2 = Shuffle64(y2);
    x3 = Shuffle64(x3); y3 = Shuffle64(y3);

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

    x1 = Shuffle64(x1); y1 = Shuffle64(y1);
    x2 = Shuffle64(x2); y2 = Shuffle64(y2);
    x3 = Shuffle64(x3); y3 = Shuffle64(y3);

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = UnpackLow64(x1, y1);
    block1 = UnpackHigh64(x1, y1);
    block2 = UnpackLow64(x2, y2);
    block3 = UnpackHigh64(x2, y2);
    block4 = UnpackLow64(x3, y3);
    block5 = UnpackHigh64(x3, y3);
}

template <typename F2, typename F6>
size_t SPECK128_AdvancedProcessBlocks_NEON(F2 func2, F6 func6,
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
            uint64x2_t block0, block1, block2, block3, block4, block5;
            block0 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));

            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                uint64x2_t be = vreinterpretq_u64_u32(vld1q_u32(s_one128));
                block1 = vaddq_u64(block0, be);
                block2 = vaddq_u64(block1, be);
                block3 = vaddq_u64(block2, be);
                block4 = vaddq_u64(block3, be);
                block5 = vaddq_u64(block4, be);
                vst1q_u8(const_cast<byte*>(inBlocks),
                    vreinterpretq_u8_u64(vaddq_u64(block5, be)));
            }
            else
            {
                const int inc = static_cast<int>(inIncrement);
                block1 = vreinterpretq_u64_u8(vld1q_u8(inBlocks+1*inc));
                block2 = vreinterpretq_u64_u8(vld1q_u8(inBlocks+2*inc));
                block3 = vreinterpretq_u64_u8(vld1q_u8(inBlocks+3*inc));
                block4 = vreinterpretq_u64_u8(vld1q_u8(inBlocks+4*inc));
                block5 = vreinterpretq_u64_u8(vld1q_u8(inBlocks+5*inc));
                inBlocks += 6*inc;
            }

            if (flags & BlockTransformation::BT_XorInput)
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+0*inc)));
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+1*inc)));
                block2 = veorq_u64(block2, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+2*inc)));
                block3 = veorq_u64(block3, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+3*inc)));
                block4 = veorq_u64(block4, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+4*inc)));
                block5 = veorq_u64(block5, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+5*inc)));
                xorBlocks += 6*inc;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+0*inc)));
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+1*inc)));
                block2 = veorq_u64(block2, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+2*inc)));
                block3 = veorq_u64(block3, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+3*inc)));
                block4 = veorq_u64(block4, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+4*inc)));
                block5 = veorq_u64(block5, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+5*inc)));
                xorBlocks += 6*inc;
            }

            const int inc = static_cast<int>(outIncrement);
            vst1q_u8(outBlocks+0*inc, vreinterpretq_u8_u64(block0));
            vst1q_u8(outBlocks+1*inc, vreinterpretq_u8_u64(block1));
            vst1q_u8(outBlocks+2*inc, vreinterpretq_u8_u64(block2));
            vst1q_u8(outBlocks+3*inc, vreinterpretq_u8_u64(block3));
            vst1q_u8(outBlocks+4*inc, vreinterpretq_u8_u64(block4));
            vst1q_u8(outBlocks+5*inc, vreinterpretq_u8_u64(block5));

            outBlocks += 6*inc;
            length -= 6*blockSize;
        }

        while (length >= 2*blockSize)
        {
            uint64x2_t block0, block1;
            block0 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));

            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                uint64x2_t be = vreinterpretq_u64_u32(vld1q_u32(s_one128));
                block1 = vaddq_u64(block0, be);
                vst1q_u8(const_cast<byte*>(inBlocks),
                    vreinterpretq_u8_u64(vaddq_u64(block1, be)));
            }
            else
            {
                const int inc = static_cast<int>(inIncrement);
                block1 = vreinterpretq_u64_u8(vld1q_u8(inBlocks+1*inc));
                inBlocks += 2*inc;
            }

            if (flags & BlockTransformation::BT_XorInput)
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+0*inc)));
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+1*inc)));
                xorBlocks += 2*inc;
            }

            func2(block0, block1, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+0*inc)));
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks+1*inc)));
                xorBlocks += 2*inc;
            }

            const int inc = static_cast<int>(outIncrement);
            vst1q_u8(outBlocks+0*inc, vreinterpretq_u8_u64(block0));
            vst1q_u8(outBlocks+1*inc, vreinterpretq_u8_u64(block1));

            outBlocks += 2*inc;
            length -= 2*blockSize;
        }
    }

    while (length >= blockSize)
    {
        uint64x2_t block, zero = {0,0};
        block = vreinterpretq_u64_u8(vld1q_u8(inBlocks));

        if (flags & BlockTransformation::BT_XorInput)
            block = veorq_u64(block, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));

        if (flags & BlockTransformation::BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func2(block, zero, subKeys, static_cast<unsigned int>(rounds));

        if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            block = veorq_u64(block, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));

        vst1q_u8(outBlocks, vreinterpretq_u8_u64(block));

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
const word32 s_one64[] = {0, 1<<24, 0, 1<<24};

CRYPTOPP_ALIGN_DATA(16)
const word32 s_one128[] = {0, 0, 0, 1<<24};

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

inline void SPECK128_Enc_Block(__m128i &block0, __m128i &block1,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
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

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = _mm_unpacklo_epi64(x1, y1);
    block1 = _mm_unpackhi_epi64(x1, y1);
}

inline void SPECK128_Enc_6_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, __m128i &block4, __m128i &block5,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);
    __m128i x2 = _mm_unpacklo_epi64(block2, block3);
    __m128i y2 = _mm_unpackhi_epi64(block2, block3);
    __m128i x3 = _mm_unpacklo_epi64(block4, block5);
    __m128i y3 = _mm_unpackhi_epi64(block4, block5);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);
    x3 = _mm_shuffle_epi8(x3, mask);
    y3 = _mm_shuffle_epi8(y3, mask);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i)));

        x1 = RotateRight64<8>(x1);
        x2 = RotateRight64<8>(x2);
        x3 = RotateRight64<8>(x3);
        x1 = _mm_add_epi64(x1, y1);
        x2 = _mm_add_epi64(x2, y2);
        x3 = _mm_add_epi64(x3, y3);
        x1 = _mm_xor_si128(x1, rk);
        x2 = _mm_xor_si128(x2, rk);
        x3 = _mm_xor_si128(x3, rk);
        y1 = RotateLeft64<3>(y1);
        y2 = RotateLeft64<3>(y2);
        y3 = RotateLeft64<3>(y3);
        y1 = _mm_xor_si128(y1, x1);
        y2 = _mm_xor_si128(y2, x2);
        y3 = _mm_xor_si128(y3, x3);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);
    x3 = _mm_shuffle_epi8(x3, mask);
    y3 = _mm_shuffle_epi8(y3, mask);

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = _mm_unpacklo_epi64(x1, y1);
    block1 = _mm_unpackhi_epi64(x1, y1);
    block2 = _mm_unpacklo_epi64(x2, y2);
    block3 = _mm_unpackhi_epi64(x2, y2);
    block4 = _mm_unpacklo_epi64(x3, y3);
    block5 = _mm_unpackhi_epi64(x3, y3);
}

inline void SPECK128_Dec_Block(__m128i &block0, __m128i &block1,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
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

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = _mm_unpacklo_epi64(x1, y1);
    block1 = _mm_unpackhi_epi64(x1, y1);
}

inline void SPECK128_Dec_6_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, __m128i &block4, __m128i &block5,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    __m128i x1 = _mm_unpacklo_epi64(block0, block1);
    __m128i y1 = _mm_unpackhi_epi64(block0, block1);
    __m128i x2 = _mm_unpacklo_epi64(block2, block3);
    __m128i y2 = _mm_unpackhi_epi64(block2, block3);
    __m128i x3 = _mm_unpacklo_epi64(block4, block5);
    __m128i y3 = _mm_unpackhi_epi64(block4, block5);

    const __m128i mask = _mm_set_epi8(8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);
    x3 = _mm_shuffle_epi8(x3, mask);
    y3 = _mm_shuffle_epi8(y3, mask);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(reinterpret_cast<const double*>(subkeys+i)));

        y1 = _mm_xor_si128(y1, x1);
        y2 = _mm_xor_si128(y2, x2);
        y3 = _mm_xor_si128(y3, x3);
        y1 = RotateRight64<3>(y1);
        y2 = RotateRight64<3>(y2);
        y3 = RotateRight64<3>(y3);
        x1 = _mm_xor_si128(x1, rk);
        x2 = _mm_xor_si128(x2, rk);
        x3 = _mm_xor_si128(x3, rk);
        x1 = _mm_sub_epi64(x1, y1);
        x2 = _mm_sub_epi64(x2, y2);
        x3 = _mm_sub_epi64(x3, y3);
        x1 = RotateLeft64<8>(x1);
        x2 = RotateLeft64<8>(x2);
        x3 = RotateLeft64<8>(x3);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);
    x3 = _mm_shuffle_epi8(x3, mask);
    y3 = _mm_shuffle_epi8(y3, mask);

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = _mm_unpacklo_epi64(x1, y1);
    block1 = _mm_unpackhi_epi64(x1, y1);
    block2 = _mm_unpacklo_epi64(x2, y2);
    block3 = _mm_unpackhi_epi64(x2, y2);
    block4 = _mm_unpacklo_epi64(x3, y3);
    block5 = _mm_unpackhi_epi64(x3, y3);
}

template <typename F2, typename F6>
inline size_t SPECK128_AdvancedProcessBlocks_SSSE3(F2 func2, F6 func6,
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
            __m128i block0, block1, block2, block3, block4, block5;
            block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                const __m128i be1 = *CONST_M128_CAST(s_one128);
                block1 = _mm_add_epi32(block0, be1);
                block2 = _mm_add_epi32(block1, be1);
                block3 = _mm_add_epi32(block2, be1);
                block4 = _mm_add_epi32(block3, be1);
                block5 = _mm_add_epi32(block4, be1);
                _mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block5, be1));
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
                block4 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block5 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
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
                block4 = _mm_xor_si128(block4, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = _mm_xor_si128(block5, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

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
                block4 = _mm_xor_si128(block4, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = _mm_xor_si128(block5, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
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
            _mm_storeu_si128(M128_CAST(outBlocks), block4);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block5);
            outBlocks += outIncrement;

            length -= 6*blockSize;
        }

        while (length >= 2*blockSize)
        {
            __m128i block0, block1;
            block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                const __m128i be1 = *CONST_M128_CAST(s_one128);
                block1 = _mm_add_epi32(block0, be1);
                _mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block1, be1));
            }
            else
            {
                inBlocks += inIncrement;
                block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
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
            }

            func2(block0, block1, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            _mm_storeu_si128(M128_CAST(outBlocks), block0);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block1);
            outBlocks += outIncrement;

            length -= 2*blockSize;
        }
    }

    while (length >= blockSize)
    {
        __m128i block, zero = _mm_setzero_si128();
        block = _mm_loadu_si128(CONST_M128_CAST(inBlocks));

        if (flags & BlockTransformation::BT_XorInput)
            block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

        if (flags & BlockTransformation::BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func2(block, zero, subKeys, static_cast<unsigned int>(rounds));

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

#if defined(CRYPTOPP_SSE41_AVAILABLE)

template <unsigned int R>
inline __m128i RotateLeft32(const __m128i& val)
{
    return _mm_or_si128(
        _mm_slli_epi32(val, R), _mm_srli_epi32(val, 32-R));
}

template <unsigned int R>
inline __m128i RotateRight32(const __m128i& val)
{
    return _mm_or_si128(
        _mm_slli_epi32(val, 32-R), _mm_srli_epi32(val, R));
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline __m128i RotateLeft32<8>(const __m128i& val)
{
    const __m128i mask = _mm_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
    return _mm_shuffle_epi8(val, mask);
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline __m128i RotateRight32<8>(const __m128i& val)
{
    const __m128i mask = _mm_set_epi8(12,15,14,13, 8,11,10,9, 4,7,6,5, 0,3,2,1);
    return _mm_shuffle_epi8(val, mask);
}

inline void SPECK64_Enc_Block(__m128i &block0, __m128i &block1,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following. Thanks to Peter Cordes for help with the
    // SSE permutes below.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const __m128 t0 = _mm_castsi128_ps(block0);
    const __m128 t1 = _mm_castsi128_ps(block1);
    __m128i x1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(2,0,2,0)));
    __m128i y1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(3,1,3,1)));

    const __m128i mask = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const __m128i rk = _mm_set1_epi32(subkeys[i]);

        x1 = RotateRight32<8>(x1);
        x1 = _mm_add_epi32(x1, y1);
        x1 = _mm_xor_si128(x1, rk);
        y1 = RotateLeft32<3>(y1);
        y1 = _mm_xor_si128(y1, x1);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    // The is roughly the SSE equivalent to ARM vzp32
    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = _mm_unpacklo_epi32(x1, y1);
    block1 = _mm_unpackhi_epi32(x1, y1);
}

inline void SPECK64_Dec_Block(__m128i &block0, __m128i &block1,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following. Thanks to Peter Cordes for help with the
    // SSE permutes below.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const __m128 t0 = _mm_castsi128_ps(block0);
    const __m128 t1 = _mm_castsi128_ps(block1);
    __m128i x1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(2,0,2,0)));
    __m128i y1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(3,1,3,1)));

    const __m128i mask = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const __m128i rk = _mm_set1_epi32(subkeys[i]);

        y1 = _mm_xor_si128(y1, x1);
        y1 = RotateRight32<3>(y1);
        x1 = _mm_xor_si128(x1, rk);
        x1 = _mm_sub_epi32(x1, y1);
        x1 = RotateLeft32<8>(x1);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);

    // The is roughly the SSE equivalent to ARM vzp32
    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = _mm_unpacklo_epi32(x1, y1);
    block1 = _mm_unpackhi_epi32(x1, y1);
}

inline void SPECK64_Enc_6_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, __m128i &block4, __m128i &block5,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following. Thanks to Peter Cordes for help with the
    // SSE permutes below.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const __m128 t0 = _mm_castsi128_ps(block0);
    const __m128 t1 = _mm_castsi128_ps(block1);
    __m128i x1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(2,0,2,0)));
    __m128i y1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(3,1,3,1)));

    const __m128 t2 = _mm_castsi128_ps(block2);
    const __m128 t3 = _mm_castsi128_ps(block3);
    __m128i x2 = _mm_castps_si128(_mm_shuffle_ps(t2, t3, _MM_SHUFFLE(2,0,2,0)));
    __m128i y2 = _mm_castps_si128(_mm_shuffle_ps(t2, t3, _MM_SHUFFLE(3,1,3,1)));

    const __m128 t4 = _mm_castsi128_ps(block4);
    const __m128 t5 = _mm_castsi128_ps(block5);
    __m128i x3 = _mm_castps_si128(_mm_shuffle_ps(t4, t5, _MM_SHUFFLE(2,0,2,0)));
    __m128i y3 = _mm_castps_si128(_mm_shuffle_ps(t4, t5, _MM_SHUFFLE(3,1,3,1)));

    const __m128i mask = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);
    x3 = _mm_shuffle_epi8(x3, mask);
    y3 = _mm_shuffle_epi8(y3, mask);

    for (size_t i=0; static_cast<int>(i)<rounds; ++i)
    {
        const __m128i rk = _mm_set1_epi32(subkeys[i]);

        x1 = RotateRight32<8>(x1);
        x2 = RotateRight32<8>(x2);
        x3 = RotateRight32<8>(x3);
        x1 = _mm_add_epi32(x1, y1);
        x2 = _mm_add_epi32(x2, y2);
        x3 = _mm_add_epi32(x3, y3);
        x1 = _mm_xor_si128(x1, rk);
        x2 = _mm_xor_si128(x2, rk);
        x3 = _mm_xor_si128(x3, rk);
        y1 = RotateLeft32<3>(y1);
        y2 = RotateLeft32<3>(y2);
        y3 = RotateLeft32<3>(y3);
        y1 = _mm_xor_si128(y1, x1);
        y2 = _mm_xor_si128(y2, x2);
        y3 = _mm_xor_si128(y3, x3);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);
    x3 = _mm_shuffle_epi8(x3, mask);
    y3 = _mm_shuffle_epi8(y3, mask);

    // The is roughly the SSE equivalent to ARM vzp32
    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = _mm_unpacklo_epi32(x1, y1);
    block1 = _mm_unpackhi_epi32(x1, y1);
    block2 = _mm_unpacklo_epi32(x2, y2);
    block3 = _mm_unpackhi_epi32(x2, y2);
    block4 = _mm_unpacklo_epi32(x3, y3);
    block5 = _mm_unpackhi_epi32(x3, y3);
}

inline void SPECK64_Dec_6_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, __m128i &block4, __m128i &block5,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read from
    // a big-endian byte array. Depending on the number of blocks it needs to
    // be permuted to the following. Thanks to Peter Cordes for help with the
    // SSE permutes below.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const __m128 t0 = _mm_castsi128_ps(block0);
    const __m128 t1 = _mm_castsi128_ps(block1);
    __m128i x1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(2,0,2,0)));
    __m128i y1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(3,1,3,1)));

    const __m128 t2 = _mm_castsi128_ps(block2);
    const __m128 t3 = _mm_castsi128_ps(block3);
    __m128i x2 = _mm_castps_si128(_mm_shuffle_ps(t2, t3, _MM_SHUFFLE(2,0,2,0)));
    __m128i y2 = _mm_castps_si128(_mm_shuffle_ps(t2, t3, _MM_SHUFFLE(3,1,3,1)));

    const __m128 t4 = _mm_castsi128_ps(block4);
    const __m128 t5 = _mm_castsi128_ps(block5);
    __m128i x3 = _mm_castps_si128(_mm_shuffle_ps(t4, t5, _MM_SHUFFLE(2,0,2,0)));
    __m128i y3 = _mm_castps_si128(_mm_shuffle_ps(t4, t5, _MM_SHUFFLE(3,1,3,1)));

    const __m128i mask = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);
    x3 = _mm_shuffle_epi8(x3, mask);
    y3 = _mm_shuffle_epi8(y3, mask);

    for (size_t i=rounds-1; static_cast<int>(i)>=0; --i)
    {
        const __m128i rk = _mm_set1_epi32(subkeys[i]);

        y1 = _mm_xor_si128(y1, x1);
        y2 = _mm_xor_si128(y2, x2);
        y3 = _mm_xor_si128(y3, x3);
        y1 = RotateRight32<3>(y1);
        y2 = RotateRight32<3>(y2);
        y3 = RotateRight32<3>(y3);
        x1 = _mm_xor_si128(x1, rk);
        x2 = _mm_xor_si128(x2, rk);
        x3 = _mm_xor_si128(x3, rk);
        x1 = _mm_sub_epi32(x1, y1);
        x2 = _mm_sub_epi32(x2, y2);
        x3 = _mm_sub_epi32(x3, y3);
        x1 = RotateLeft32<8>(x1);
        x2 = RotateLeft32<8>(x2);
        x3 = RotateLeft32<8>(x3);
    }

    x1 = _mm_shuffle_epi8(x1, mask);
    y1 = _mm_shuffle_epi8(y1, mask);
    x2 = _mm_shuffle_epi8(x2, mask);
    y2 = _mm_shuffle_epi8(y2, mask);
    x3 = _mm_shuffle_epi8(x3, mask);
    y3 = _mm_shuffle_epi8(y3, mask);

    // The is roughly the SSE equivalent to ARM vzp32
    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = _mm_unpacklo_epi32(x1, y1);
    block1 = _mm_unpackhi_epi32(x1, y1);
    block2 = _mm_unpacklo_epi32(x2, y2);
    block3 = _mm_unpackhi_epi32(x2, y2);
    block4 = _mm_unpacklo_epi32(x3, y3);
    block5 = _mm_unpackhi_epi32(x3, y3);
}

template <typename F2, typename F6>
inline size_t SPECK64_AdvancedProcessBlocks_SSE41(F2 func2, F6 func6,
        const word32 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 8);

    // Fake block size to match XMM word
    const size_t xmmBlockSize = 16;
    size_t inIncrement = (flags & (BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_DontIncrementInOutPointers)) ? 0 : xmmBlockSize;
    size_t xorIncrement = xorBlocks ? xmmBlockSize : 0;
    size_t outIncrement = (flags & BlockTransformation::BT_DontIncrementInOutPointers) ? 0 : xmmBlockSize;

    if (flags & BlockTransformation::BT_ReverseDirection)
    {
        inBlocks += length - xmmBlockSize;
        xorBlocks += length - xmmBlockSize;
        outBlocks += length - xmmBlockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BlockTransformation::BT_AllowParallel)
    {
        while (length >= 6*xmmBlockSize)
        {
            __m128i block0, block1, block2, block3, block4, block5;
            block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                const __m128i be1 = *CONST_M128_CAST(s_one64);
                block1 = _mm_add_epi32(block0, be1);
                block2 = _mm_add_epi32(block1, be1);
                block3 = _mm_add_epi32(block2, be1);
                block4 = _mm_add_epi32(block3, be1);
                block5 = _mm_add_epi32(block4, be1);
                _mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block5, be1));
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
                block4 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block5 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
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
                block4 = _mm_xor_si128(block4, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = _mm_xor_si128(block5, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

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
                block4 = _mm_xor_si128(block4, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = _mm_xor_si128(block5, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
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
            _mm_storeu_si128(M128_CAST(outBlocks), block4);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block5);
            outBlocks += outIncrement;

            length -= 6*xmmBlockSize;
        }

        while (length >= 2*xmmBlockSize)
        {
            __m128i block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks)), block1;
            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                const __m128i be1 = *CONST_M128_CAST(s_one64);
                block1 = _mm_add_epi32(block0, be1);
                _mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block1, be1));
            }
            else
            {
                inBlocks += inIncrement;
                block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
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
            }

            func2(block0, block1, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            _mm_storeu_si128(M128_CAST(outBlocks), block0);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block1);
            outBlocks += outIncrement;

            length -= 2*xmmBlockSize;
        }
    }

    if (length)
    {
        // Adjust to real block size
        const size_t blockSize = 8;
        if (flags & BlockTransformation::BT_ReverseDirection)
        {
            inIncrement += inIncrement ? blockSize : 0;
            xorIncrement += xorIncrement ? blockSize : 0;
            outIncrement += outIncrement ? blockSize : 0;
            inBlocks -= inIncrement;
            xorBlocks -= xorIncrement;
            outBlocks -= outIncrement;
        }
        else
        {
            inIncrement -= inIncrement ? blockSize : 0;
            xorIncrement -= xorIncrement ? blockSize : 0;
            outIncrement -= outIncrement ? blockSize : 0;
        }

        while (length >= blockSize)
        {
            __m128i block, zero = _mm_setzero_si128();
            block = _mm_castpd_si128(
                _mm_load_sd(reinterpret_cast<const double*>(inBlocks)));

            if (flags & BlockTransformation::BT_XorInput)
            {
                block = _mm_xor_si128(block, _mm_castpd_si128(
                    _mm_load_sd(reinterpret_cast<const double*>(xorBlocks))));
            }

            if (flags & BlockTransformation::BT_InBlockIsCounter)
                const_cast<byte *>(inBlocks)[7]++;

            func2(block, zero, subKeys, static_cast<unsigned int>(rounds));

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                block = _mm_xor_si128(block, _mm_castpd_si128(
                    _mm_load_sd(reinterpret_cast<const double*>(xorBlocks))));
            }

            _mm_store_sd(reinterpret_cast<double*>(outBlocks), _mm_castsi128_pd(block));

            inBlocks += inIncrement;
            outBlocks += outIncrement;
            xorBlocks += xorIncrement;
            length -= blockSize;
        }
    }

    return length;
}

#endif  // CRYPTOPP_SSE41_AVAILABLE

ANONYMOUS_NAMESPACE_END

///////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

// *************************** ARM NEON **************************** //

#if defined(CRYPTOPP_ARM_NEON_AVAILABLE)
size_t SPECK64_Enc_AdvancedProcessBlocks_NEON(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK64_AdvancedProcessBlocks_NEON(SPECK64_Enc_Block, SPECK64_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK64_Dec_AdvancedProcessBlocks_NEON(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK64_AdvancedProcessBlocks_NEON(SPECK64_Dec_Block, SPECK64_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif

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

#if defined(CRYPTOPP_SSE41_AVAILABLE)
size_t SPECK64_Enc_AdvancedProcessBlocks_SSE41(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK64_AdvancedProcessBlocks_SSE41(SPECK64_Enc_Block, SPECK64_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK64_Dec_AdvancedProcessBlocks_SSE41(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK64_AdvancedProcessBlocks_SSE41(SPECK64_Dec_Block, SPECK64_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif

#if defined(CRYPTOPP_SSSE3_AVAILABLE)
size_t SPECK128_Enc_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK128_AdvancedProcessBlocks_SSSE3(SPECK128_Enc_Block, SPECK128_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK128_Dec_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return SPECK128_AdvancedProcessBlocks_SSSE3(SPECK128_Dec_Block, SPECK128_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_SSSE3_AVAILABLE

NAMESPACE_END
