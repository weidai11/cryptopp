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
#include "adv-simd.h"

// Uncomment for benchmarking C++ against SSE or NEON.
// Do so in both speck.cpp and speck-simd.cpp.
// #undef CRYPTOPP_SSSE3_AVAILABLE
// #undef CRYPTOPP_SSE41_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_SSSE3_AVAILABLE)
# include <pmmintrin.h>
# include <tmmintrin.h>
#endif

#if (CRYPTOPP_SSE41_AVAILABLE)
# include <smmintrin.h>
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__)
# define CRYPTOPP_AVX512_ROTATE 1
# include <immintrin.h>
#endif

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
# include <arm_neon.h>
#endif

// Can't use CRYPTOPP_ARM_XXX_AVAILABLE because too many
// compilers don't follow ACLE conventions for the include.
#if defined(CRYPTOPP_ARM_ACLE_AVAILABLE)
# include <stdint.h>
# include <arm_acle.h>
#endif

// https://www.spinics.net/lists/gcchelp/msg47735.html and
// https://www.spinics.net/lists/gcchelp/msg47749.html
#if (CRYPTOPP_GCC_VERSION >= 40900)
# define GCC_NO_UBSAN __attribute__ ((no_sanitize_undefined))
#else
# define GCC_NO_UBSAN
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;

// *************************** ARM NEON ************************** //

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

template <class T>
inline T UnpackHigh32(const T& a, const T& b)
{
    const uint32x2_t x(vget_high_u32((uint32x4_t)a));
    const uint32x2_t y(vget_high_u32((uint32x4_t)b));
    const uint32x2x2_t r = vzip_u32(x, y);
    return (T)vcombine_u32(r.val[0], r.val[1]);
}

template <class T>
inline T UnpackLow32(const T& a, const T& b)
{
    const uint32x2_t x(vget_low_u32((uint32x4_t)a));
    const uint32x2_t y(vget_low_u32((uint32x4_t)b));
    const uint32x2x2_t r = vzip_u32(x, y);
    return (T)vcombine_u32(r.val[0], r.val[1]);
}

template <unsigned int R>
inline uint32x4_t RotateLeft32(const uint32x4_t& val)
{
    const uint32x4_t a(vshlq_n_u32(val, R));
    const uint32x4_t b(vshrq_n_u32(val, 32 - R));
    return vorrq_u32(a, b);
}

template <unsigned int R>
inline uint32x4_t RotateRight32(const uint32x4_t& val)
{
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
    const uint8_t maskb[16] = { 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12 };
    const uint8x16_t mask = vld1q_u8(maskb);
#endif

    return vreinterpretq_u32_u8(
        vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
}
#endif  // Aarch32 or Aarch64

inline void SPECK64_Enc_Block(uint32x4_t &block0, uint32x4_t &block1,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    uint32x4_t x1 = vuzpq_u32(block0, block1).val[1];
    uint32x4_t y1 = vuzpq_u32(block0, block1).val[0];

    for (int i=0; i < static_cast<int>(rounds); ++i)
    {
        const uint32x4_t rk = vdupq_n_u32(subkeys[i]);

        x1 = RotateRight32<8>(x1);
        x1 = vaddq_u32(x1, y1);
        x1 = veorq_u32(x1, rk);
        y1 = RotateLeft32<3>(y1);
        y1 = veorq_u32(y1, x1);
    }

    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = UnpackLow32(y1, x1);
    block1 = UnpackHigh32(y1, x1);
}

inline void SPECK64_Dec_Block(uint32x4_t &block0, uint32x4_t &block1,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    uint32x4_t x1 = vuzpq_u32(block0, block1).val[1];
    uint32x4_t y1 = vuzpq_u32(block0, block1).val[0];

    for (int i = static_cast<int>(rounds-1); i >= 0; --i)
    {
        const uint32x4_t rk = vdupq_n_u32(subkeys[i]);

        y1 = veorq_u32(y1, x1);
        y1 = RotateRight32<3>(y1);
        x1 = veorq_u32(x1, rk);
        x1 = vsubq_u32(x1, y1);
        x1 = RotateLeft32<8>(x1);
    }

    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = UnpackLow32(y1, x1);
    block1 = UnpackHigh32(y1, x1);
}

inline void SPECK64_Enc_6_Blocks(uint32x4_t &block0, uint32x4_t &block1,
    uint32x4_t &block2, uint32x4_t &block3, uint32x4_t &block4, uint32x4_t &block5,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following. If only a single block is available then
    // a Zero block is provided to promote vectorizations.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    uint32x4_t x1 = vuzpq_u32(block0, block1).val[1];
    uint32x4_t y1 = vuzpq_u32(block0, block1).val[0];
    uint32x4_t x2 = vuzpq_u32(block2, block3).val[1];
    uint32x4_t y2 = vuzpq_u32(block2, block3).val[0];
    uint32x4_t x3 = vuzpq_u32(block4, block5).val[1];
    uint32x4_t y3 = vuzpq_u32(block4, block5).val[0];

    for (int i=0; i < static_cast<int>(rounds); ++i)
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

    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = UnpackLow32(y1, x1);
    block1 = UnpackHigh32(y1, x1);
    block2 = UnpackLow32(y2, x2);
    block3 = UnpackHigh32(y2, x2);
    block4 = UnpackLow32(y3, x3);
    block5 = UnpackHigh32(y3, x3);
}

inline void SPECK64_Dec_6_Blocks(uint32x4_t &block0, uint32x4_t &block1,
    uint32x4_t &block2, uint32x4_t &block3, uint32x4_t &block4, uint32x4_t &block5,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following. If only a single block is available then
    // a Zero block is provided to promote vectorizations.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    uint32x4_t x1 = vuzpq_u32(block0, block1).val[1];
    uint32x4_t y1 = vuzpq_u32(block0, block1).val[0];
    uint32x4_t x2 = vuzpq_u32(block2, block3).val[1];
    uint32x4_t y2 = vuzpq_u32(block2, block3).val[0];
    uint32x4_t x3 = vuzpq_u32(block4, block5).val[1];
    uint32x4_t y3 = vuzpq_u32(block4, block5).val[0];

    for (int i = static_cast<int>(rounds-1); i >= 0; --i)
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

    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = UnpackLow32(y1, x1);
    block1 = UnpackHigh32(y1, x1);
    block2 = UnpackLow32(y2, x2);
    block3 = UnpackHigh32(y2, x2);
    block4 = UnpackLow32(y3, x3);
    block5 = UnpackHigh32(y3, x3);
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

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
    const uint64x2_t a(vshlq_n_u64(val, R));
    const uint64x2_t b(vshrq_n_u64(val, 64 - R));
    return vorrq_u64(a, b);
}

template <unsigned int R>
inline uint64x2_t RotateRight64(const uint64x2_t& val)
{
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

inline void SPECK128_Enc_Block(uint64x2_t &block0, uint64x2_t &block1,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    uint64x2_t x1 = UnpackHigh64(block0, block1);
    uint64x2_t y1 = UnpackLow64(block0, block1);

    for (int i=0; i < static_cast<int>(rounds); ++i)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+i);

        x1 = RotateRight64<8>(x1);
        x1 = vaddq_u64(x1, y1);
        x1 = veorq_u64(x1, rk);
        y1 = RotateLeft64<3>(y1);
        y1 = veorq_u64(y1, x1);
    }

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = UnpackLow64(y1, x1);
    block1 = UnpackHigh64(y1, x1);
}

inline void SPECK128_Enc_6_Blocks(uint64x2_t &block0, uint64x2_t &block1,
    uint64x2_t &block2, uint64x2_t &block3, uint64x2_t &block4, uint64x2_t &block5,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    uint64x2_t x1 = UnpackHigh64(block0, block1);
    uint64x2_t y1 = UnpackLow64(block0, block1);
    uint64x2_t x2 = UnpackHigh64(block2, block3);
    uint64x2_t y2 = UnpackLow64(block2, block3);
    uint64x2_t x3 = UnpackHigh64(block4, block5);
    uint64x2_t y3 = UnpackLow64(block4, block5);

    for (int i=0; i < static_cast<int>(rounds); ++i)
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

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = UnpackLow64(y1, x1);
    block1 = UnpackHigh64(y1, x1);
    block2 = UnpackLow64(y2, x2);
    block3 = UnpackHigh64(y2, x2);
    block4 = UnpackLow64(y3, x3);
    block5 = UnpackHigh64(y3, x3);
}

inline void SPECK128_Dec_Block(uint64x2_t &block0, uint64x2_t &block1,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    uint64x2_t x1 = UnpackHigh64(block0, block1);
    uint64x2_t y1 = UnpackLow64(block0, block1);

    for (int i = static_cast<int>(rounds-1); i >= 0; --i)
    {
        const uint64x2_t rk = vld1q_dup_u64(subkeys+i);

        y1 = veorq_u64(y1, x1);
        y1 = RotateRight64<3>(y1);
        x1 = veorq_u64(x1, rk);
        x1 = vsubq_u64(x1, y1);
        x1 = RotateLeft64<8>(x1);
    }

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = UnpackLow64(y1, x1);
    block1 = UnpackHigh64(y1, x1);
}

inline void SPECK128_Dec_6_Blocks(uint64x2_t &block0, uint64x2_t &block1,
    uint64x2_t &block2, uint64x2_t &block3, uint64x2_t &block4, uint64x2_t &block5,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    uint64x2_t x1 = UnpackHigh64(block0, block1);
    uint64x2_t y1 = UnpackLow64(block0, block1);
    uint64x2_t x2 = UnpackHigh64(block2, block3);
    uint64x2_t y2 = UnpackLow64(block2, block3);
    uint64x2_t x3 = UnpackHigh64(block4, block5);
    uint64x2_t y3 = UnpackLow64(block4, block5);

    for (int i = static_cast<int>(rounds-1); i >= 0; --i)
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

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = UnpackLow64(y1, x1);
    block1 = UnpackHigh64(y1, x1);
    block2 = UnpackLow64(y2, x2);
    block3 = UnpackHigh64(y2, x2);
    block4 = UnpackLow64(y3, x3);
    block5 = UnpackHigh64(y3, x3);
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// ***************************** IA-32 ***************************** //

#if defined(CRYPTOPP_SSSE3_AVAILABLE)

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#ifndef M128_CAST
# define M128_CAST(x) ((__m128i *)(void *)(x))
#endif
#ifndef CONST_M128_CAST
# define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))
#endif

// GCC double casts, https://www.spinics.net/lists/gcchelp/msg47735.html
#ifndef DOUBLE_CAST
# define DOUBLE_CAST(x) ((double *)(void *)(x))
#endif
#ifndef CONST_DOUBLE_CAST
# define CONST_DOUBLE_CAST(x) ((const double *)(const void *)(x))
#endif

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

inline void GCC_NO_UBSAN SPECK128_Enc_Block(__m128i &block0, __m128i &block1,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    __m128i x1 = _mm_unpackhi_epi64(block0, block1);
    __m128i y1 = _mm_unpacklo_epi64(block0, block1);

    for (int i=0; i < static_cast<int>(rounds); ++i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(CONST_DOUBLE_CAST(subkeys+i)));

        x1 = RotateRight64<8>(x1);
        x1 = _mm_add_epi64(x1, y1);
        x1 = _mm_xor_si128(x1, rk);
        y1 = RotateLeft64<3>(y1);
        y1 = _mm_xor_si128(y1, x1);
    }

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = _mm_unpacklo_epi64(y1, x1);
    block1 = _mm_unpackhi_epi64(y1, x1);
}

inline void GCC_NO_UBSAN SPECK128_Enc_6_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, __m128i &block4, __m128i &block5,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    __m128i x1 = _mm_unpackhi_epi64(block0, block1);
    __m128i y1 = _mm_unpacklo_epi64(block0, block1);
    __m128i x2 = _mm_unpackhi_epi64(block2, block3);
    __m128i y2 = _mm_unpacklo_epi64(block2, block3);
    __m128i x3 = _mm_unpackhi_epi64(block4, block5);
    __m128i y3 = _mm_unpacklo_epi64(block4, block5);

    for (int i=0; i < static_cast<int>(rounds); ++i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(CONST_DOUBLE_CAST(subkeys+i)));

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

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = _mm_unpacklo_epi64(y1, x1);
    block1 = _mm_unpackhi_epi64(y1, x1);
    block2 = _mm_unpacklo_epi64(y2, x2);
    block3 = _mm_unpackhi_epi64(y2, x2);
    block4 = _mm_unpacklo_epi64(y3, x3);
    block5 = _mm_unpackhi_epi64(y3, x3);
}

inline void GCC_NO_UBSAN SPECK128_Dec_Block(__m128i &block0, __m128i &block1,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    __m128i x1 = _mm_unpackhi_epi64(block0, block1);
    __m128i y1 = _mm_unpacklo_epi64(block0, block1);

    for (int i = static_cast<int>(rounds-1); i >= 0; --i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(CONST_DOUBLE_CAST(subkeys+i)));

        y1 = _mm_xor_si128(y1, x1);
        y1 = RotateRight64<3>(y1);
        x1 = _mm_xor_si128(x1, rk);
        x1 = _mm_sub_epi64(x1, y1);
        x1 = RotateLeft64<8>(x1);
    }

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = _mm_unpacklo_epi64(y1, x1);
    block1 = _mm_unpackhi_epi64(y1, x1);
}

inline void GCC_NO_UBSAN SPECK128_Dec_6_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, __m128i &block4, __m128i &block5,
    const word64 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following.
    // [A1 A2][B1 B2] ... => [A1 B1][A2 B2] ...
    __m128i x1 = _mm_unpackhi_epi64(block0, block1);
    __m128i y1 = _mm_unpacklo_epi64(block0, block1);
    __m128i x2 = _mm_unpackhi_epi64(block2, block3);
    __m128i y2 = _mm_unpacklo_epi64(block2, block3);
    __m128i x3 = _mm_unpackhi_epi64(block4, block5);
    __m128i y3 = _mm_unpacklo_epi64(block4, block5);

    for (int i = static_cast<int>(rounds-1); i >= 0; --i)
    {
        const __m128i rk = _mm_castpd_si128(
            _mm_loaddup_pd(CONST_DOUBLE_CAST(subkeys+i)));

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

    // [A1 B1][A2 B2] ... => [A1 A2][B1 B2] ...
    block0 = _mm_unpacklo_epi64(y1, x1);
    block1 = _mm_unpackhi_epi64(y1, x1);
    block2 = _mm_unpacklo_epi64(y2, x2);
    block3 = _mm_unpackhi_epi64(y2, x2);
    block4 = _mm_unpacklo_epi64(y3, x3);
    block5 = _mm_unpackhi_epi64(y3, x3);
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

inline void GCC_NO_UBSAN SPECK64_Enc_Block(__m128i &block0, __m128i &block1,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following. Thanks to Peter Cordes for help with the
    // SSE permutes below.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const __m128 t0 = _mm_castsi128_ps(block0);
    const __m128 t1 = _mm_castsi128_ps(block1);
    __m128i x1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(3,1,3,1)));
    __m128i y1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(2,0,2,0)));

    for (int i=0; i < static_cast<int>(rounds); ++i)
    {
        const __m128i rk = _mm_set1_epi32(subkeys[i]);

        x1 = RotateRight32<8>(x1);
        x1 = _mm_add_epi32(x1, y1);
        x1 = _mm_xor_si128(x1, rk);
        y1 = RotateLeft32<3>(y1);
        y1 = _mm_xor_si128(y1, x1);
    }

    // The is roughly the SSE equivalent to ARM vzp32
    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = _mm_unpacklo_epi32(y1, x1);
    block1 = _mm_unpackhi_epi32(y1, x1);
}

inline void GCC_NO_UBSAN SPECK64_Dec_Block(__m128i &block0, __m128i &block1,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following. Thanks to Peter Cordes for help with the
    // SSE permutes below.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const __m128 t0 = _mm_castsi128_ps(block0);
    const __m128 t1 = _mm_castsi128_ps(block1);
    __m128i x1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(3,1,3,1)));
    __m128i y1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(2,0,2,0)));

    for (int i = static_cast<int>(rounds-1); i >= 0; --i)
    {
        const __m128i rk = _mm_set1_epi32(subkeys[i]);

        y1 = _mm_xor_si128(y1, x1);
        y1 = RotateRight32<3>(y1);
        x1 = _mm_xor_si128(x1, rk);
        x1 = _mm_sub_epi32(x1, y1);
        x1 = RotateLeft32<8>(x1);
    }

    // The is roughly the SSE equivalent to ARM vzp32
    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = _mm_unpacklo_epi32(y1, x1);
    block1 = _mm_unpackhi_epi32(y1, x1);
}

inline void GCC_NO_UBSAN SPECK64_Enc_6_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, __m128i &block4, __m128i &block5,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following. Thanks to Peter Cordes for help with the
    // SSE permutes below.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const __m128 t0 = _mm_castsi128_ps(block0);
    const __m128 t1 = _mm_castsi128_ps(block1);
    __m128i x1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(3,1,3,1)));
    __m128i y1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(2,0,2,0)));

    const __m128 t2 = _mm_castsi128_ps(block2);
    const __m128 t3 = _mm_castsi128_ps(block3);
    __m128i x2 = _mm_castps_si128(_mm_shuffle_ps(t2, t3, _MM_SHUFFLE(3,1,3,1)));
    __m128i y2 = _mm_castps_si128(_mm_shuffle_ps(t2, t3, _MM_SHUFFLE(2,0,2,0)));

    const __m128 t4 = _mm_castsi128_ps(block4);
    const __m128 t5 = _mm_castsi128_ps(block5);
    __m128i x3 = _mm_castps_si128(_mm_shuffle_ps(t4, t5, _MM_SHUFFLE(3,1,3,1)));
    __m128i y3 = _mm_castps_si128(_mm_shuffle_ps(t4, t5, _MM_SHUFFLE(2,0,2,0)));

    for (int i=0; i < static_cast<int>(rounds); ++i)
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

    // The is roughly the SSE equivalent to ARM vzp32
    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = _mm_unpacklo_epi32(y1, x1);
    block1 = _mm_unpackhi_epi32(y1, x1);
    block2 = _mm_unpacklo_epi32(y2, x2);
    block3 = _mm_unpackhi_epi32(y2, x2);
    block4 = _mm_unpacklo_epi32(y3, x3);
    block5 = _mm_unpackhi_epi32(y3, x3);
}

inline void GCC_NO_UBSAN SPECK64_Dec_6_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, __m128i &block4, __m128i &block5,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. The incoming data was read into
    // a little-endian word array. Depending on the number of blocks it needs to
    // be permuted to the following. Thanks to Peter Cordes for help with the
    // SSE permutes below.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 A3 B1 B3][A2 A4 B2 B4] ...
    const __m128 t0 = _mm_castsi128_ps(block0);
    const __m128 t1 = _mm_castsi128_ps(block1);
    __m128i x1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(3,1,3,1)));
    __m128i y1 = _mm_castps_si128(_mm_shuffle_ps(t0, t1, _MM_SHUFFLE(2,0,2,0)));

    const __m128 t2 = _mm_castsi128_ps(block2);
    const __m128 t3 = _mm_castsi128_ps(block3);
    __m128i x2 = _mm_castps_si128(_mm_shuffle_ps(t2, t3, _MM_SHUFFLE(3,1,3,1)));
    __m128i y2 = _mm_castps_si128(_mm_shuffle_ps(t2, t3, _MM_SHUFFLE(2,0,2,0)));

    const __m128 t4 = _mm_castsi128_ps(block4);
    const __m128 t5 = _mm_castsi128_ps(block5);
    __m128i x3 = _mm_castps_si128(_mm_shuffle_ps(t4, t5, _MM_SHUFFLE(3,1,3,1)));
    __m128i y3 = _mm_castps_si128(_mm_shuffle_ps(t4, t5, _MM_SHUFFLE(2,0,2,0)));

    for (int i = static_cast<int>(rounds-1); i >= 0; --i)
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

    // The is roughly the SSE equivalent to ARM vzp32
    // [A1 A3 B1 B3][A2 A4 B2 B4] => [A1 A2 A3 A4][B1 B2 B3 B4]
    block0 = _mm_unpacklo_epi32(y1, x1);
    block1 = _mm_unpackhi_epi32(y1, x1);
    block2 = _mm_unpacklo_epi32(y2, x2);
    block3 = _mm_unpackhi_epi32(y2, x2);
    block4 = _mm_unpacklo_epi32(y3, x3);
    block5 = _mm_unpackhi_epi32(y3, x3);
}

#endif  // CRYPTOPP_SSE41_AVAILABLE

ANONYMOUS_NAMESPACE_END

///////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

// *************************** ARM NEON **************************** //

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
size_t SPECK64_Enc_AdvancedProcessBlocks_NEON(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks64_6x2_NEON(SPECK64_Enc_Block, SPECK64_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK64_Dec_AdvancedProcessBlocks_NEON(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks64_6x2_NEON(SPECK64_Dec_Block, SPECK64_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
size_t SPECK128_Enc_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_6x2_NEON(SPECK128_Enc_Block, SPECK128_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK128_Dec_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_6x2_NEON(SPECK128_Dec_Block, SPECK128_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// ***************************** IA-32 ***************************** //

#if defined(CRYPTOPP_SSE41_AVAILABLE)
size_t SPECK64_Enc_AdvancedProcessBlocks_SSE41(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks64_6x2_SSE(SPECK64_Enc_Block, SPECK64_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK64_Dec_AdvancedProcessBlocks_SSE41(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks64_6x2_SSE(SPECK64_Dec_Block, SPECK64_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif

#if defined(CRYPTOPP_SSSE3_AVAILABLE)
size_t SPECK128_Enc_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_6x2_SSE(SPECK128_Enc_Block, SPECK128_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK128_Dec_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_6x2_SSE(SPECK128_Dec_Block, SPECK128_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_SSSE3_AVAILABLE

NAMESPACE_END
