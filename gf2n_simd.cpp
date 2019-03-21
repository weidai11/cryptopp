// gf2n_simd.cpp - written and placed in the public domain by Jeffrey Walton
//                 Also based on PCLMULQDQ code by Jankowski, Laurent and
//                 O'Mahony from Intel (see reference below).
//
//    This source file uses intrinsics and built-ins to gain access to
//    CLMUL, ARMv8a, and Power8 instructions. A separate source file is
//    needed because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.
//
//    Several speedups were taken from Intel Polynomial Multiplication
//    Instruction and its Usage for Elliptic Curve Cryptography, by
//    Krzysztof Jankowski, Pierre Laurent and Aidan O'Mahony,
//    https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/polynomial-multiplication-instructions-paper.pdf
//    There may be more speedups available, see https://eprint.iacr.org/2011/589.pdf.
//    The IACR paper performs some optimizations that the compiler is
//    expected to perform, like Common Subexpression Elimination to save
//    on variables (among others). Note that the compiler may miss the
//    optimization so the IACR paper is useful. However, the code is GPL3
//    and toxic for some users of the library...

#include "pch.h"
#include "config.h"

#ifndef CRYPTOPP_IMPORTS

#include "gf2n.h"

#if (CRYPTOPP_CLMUL_AVAILABLE)
# include <emmintrin.h>
# include <wmmintrin.h>
#endif

#if (CRYPTOPP_ARM_PMULL_AVAILABLE)
# include "arm_simd.h"
#endif

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include "ppc_simd.h"
#endif

ANONYMOUS_NAMESPACE_BEGIN

// ************************** ARMv8 ************************** //

using CryptoPP::word;

#if (CRYPTOPP_ARM_PMULL_AVAILABLE)

// c1c0 = a * b
inline void
F2N_Multiply_128x128_ARMv8(uint64x2_t& c1, uint64x2_t& c0, const uint64x2_t& a, const uint64x2_t& b)
{
    uint64x2_t t1, t2, z0={0};

    c0 = PMULL_00(a, b);
    c1 = PMULL_11(a, b);
    t1 = vmovq_n_u64(vgetq_lane_u64(a, 1));
    t1 = veorq_u64(a, t1);
    t2 = vmovq_n_u64(vgetq_lane_u64(b, 1));
    t2 = veorq_u64(b, t2);
    t1 = PMULL_00(t1, t2);
    t1 = veorq_u64(c0, t1);
    t1 = veorq_u64(c1, t1);
    t2 = t1;
    t1 = vextq_u64(z0, t1, 1);
    t2 = vextq_u64(t2, z0, 1);
    c0 = veorq_u64(c0, t1);
    c1 = veorq_u64(c1, t2);
}

// c3c2c1c0 = a1a0 * b1b0
inline void
F2N_Multiply_256x256_ARMv8(uint64x2_t& c3, uint64x2_t& c2, uint64x2_t& c1, uint64x2_t& c0,
    const uint64x2_t& b1, const uint64x2_t& b0, const uint64x2_t& a1, const uint64x2_t& a0)
{
    uint64x2_t c4, c5;
    uint64x2_t x0=a0, x1=a1, y0=b0, y1=b1;

    F2N_Multiply_128x128_ARMv8(c1, c0, x0, y0);
    F2N_Multiply_128x128_ARMv8(c3, c2, x1, y1);

    x0 = veorq_u64(x0, x1);
    y0 = veorq_u64(y0, y1);

    F2N_Multiply_128x128_ARMv8(c5, c4, x0, y0);

    c4 = veorq_u64(c4, c0);
    c4 = veorq_u64(c4, c2);
    c5 = veorq_u64(c5, c1);
    c5 = veorq_u64(c5, c3);
    c1 = veorq_u64(c1, c4);
    c2 = veorq_u64(c2, c5);
}

// c3c2c1c0 = a1a0 * a1a0
inline void
F2N_Square_256_ARMv8(uint64x2_t& c3, uint64x2_t& c2, uint64x2_t& c1,
    uint64x2_t& c0, const uint64x2_t& a1, const uint64x2_t& a0)
{
    c0 = PMULL_00(a0, a0);
    c1 = PMULL_11(a0, a0);
    c2 = PMULL_00(a1, a1);
    c3 = PMULL_11(a1, a1);
}

// x = (x << n), z = 0
template <unsigned int N>
inline uint64x2_t ShiftLeft128_ARMv8(uint64x2_t x)
{
    uint64x2_t u=x, v, z={0};
    x = vshlq_n_u64(x, N);
    u = vshrq_n_u64(u, (64-N));
    v = vcombine_u64(vget_low_u64(z), vget_low_u64(u));
    x = vorrq_u64(x, v);
    return x;
}

// c1c0 = c3c2c1c0 MOD p. This is a Barrett reduction. Reading at
// Intel paper or https://github.com/antonblanchard/crc32-vpmsum.
inline void
GF2NT_233_Reduce_ARMv8(uint64x2_t& c3, uint64x2_t& c2, uint64x2_t& c1, uint64x2_t& c0)
{
    const unsigned int mask[4] = {
        0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff,
    };

    uint64x2_t b3, b2, b1, /*b0,*/ a1, a0, m0, z0={0};
    m0 = vreinterpretq_u64_u32(vld1q_u32(mask));
    b1 = c1; a1 = c1;
    a0 = vcombine_u64(vget_low_u64(c1), vget_low_u64(z0));
    a1 = vshlq_n_u64(a1, 23);
    a1 = vshrq_n_u64(a1, 23);
    c1 = vorrq_u64(a1, a0);
    b2 = vshrq_n_u64(c2, (64-23));
    c3 = ShiftLeft128_ARMv8<23>(c3);
    a0 = vcombine_u64(vget_high_u64(b2), vget_high_u64(z0));
    c3 = vorrq_u64(c3, a0);
    b1 = vshrq_n_u64(b1, (64-23));
    c2 = ShiftLeft128_ARMv8<23>(c2);
    a0 = vcombine_u64(vget_high_u64(b1), vget_high_u64(z0));
    c2 = vorrq_u64(c2, a0);
    b3 = c3;
    b2 = vshrq_n_u64(c2, (64-10));
    b3 = ShiftLeft128_ARMv8<10>(b3);
    a0 = vcombine_u64(vget_high_u64(b2), vget_high_u64(z0));
    b3 = vorrq_u64(b3, a0);
    a0 = vcombine_u64(vget_high_u64(c3), vget_high_u64(z0));
    b3 = veorq_u64(b3, a0);
    b1 = vshrq_n_u64(b3, (64-23));
    b3 = ShiftLeft128_ARMv8<23>(b3);
    b3 = vcombine_u64(vget_high_u64(b3), vget_high_u64(z0));
    b3 = vorrq_u64(b3, b1);
    c2 = veorq_u64(c2, b3);
    b3 = c3;
    b2 = vshrq_n_u64(c2, (64-10));
    b3 = ShiftLeft128_ARMv8<10>(b3);
    b2 = vcombine_u64(vget_high_u64(b2), vget_high_u64(z0));
    b3 = vorrq_u64(b3, b2);
    b2 = c2;
    b2 = ShiftLeft128_ARMv8<10>(b2);
    a0 = vcombine_u64(vget_low_u64(z0), vget_low_u64(b2));
    c2 = veorq_u64(c2, a0);
    a0 = vcombine_u64(vget_low_u64(z0), vget_low_u64(b3));
    a1 = vcombine_u64(vget_high_u64(b2), vget_high_u64(z0));
    a0 = vorrq_u64(a0, a1);
    c3 = veorq_u64(c3, a0);
    c0 = veorq_u64(c0, c2);
    c1 = veorq_u64(c1, c3);
    c1 = vandq_u64(c1, m0);
}

#endif

// ************************** SSE ************************** //

#if (CRYPTOPP_CLMUL_AVAILABLE)

using CryptoPP::word;

// c1c0 = a * b
inline void
F2N_Multiply_128x128_CLMUL(__m128i& c1, __m128i& c0, const __m128i& a, const __m128i& b)
{
    __m128i t1, t2;

    c0 = _mm_clmulepi64_si128(a, b, 0x00);
    c1 = _mm_clmulepi64_si128(a, b, 0x11);
    t1 = _mm_shuffle_epi32(a, 0xEE);
    t1 = _mm_xor_si128(a, t1);
    t2 = _mm_shuffle_epi32(b, 0xEE);
    t2 = _mm_xor_si128(b, t2);
    t1 = _mm_clmulepi64_si128(t1, t2, 0x00);
    t1 = _mm_xor_si128(c0, t1);
    t1 = _mm_xor_si128(c1, t1);
    t2 = t1;
    t1 = _mm_slli_si128(t1, 8);
    t2 = _mm_srli_si128(t2, 8);
    c0 = _mm_xor_si128(c0, t1);
    c1 = _mm_xor_si128(c1, t2);
}

// c3c2c1c0 = a1a0 * b1b0
inline void
F2N_Multiply_256x256_CLMUL(__m128i& c3, __m128i& c2, __m128i& c1, __m128i& c0,
    const __m128i& b1, const __m128i& b0, const __m128i& a1, const __m128i& a0)
{
    __m128i c4, c5;
    __m128i x0=a0, x1=a1, y0=b0, y1=b1;

    F2N_Multiply_128x128_CLMUL(c1, c0, x0, y0);
    F2N_Multiply_128x128_CLMUL(c3, c2, x1, y1);

    x0 = _mm_xor_si128(x0, x1);
    y0 = _mm_xor_si128(y0, y1);

    F2N_Multiply_128x128_CLMUL(c5, c4, x0, y0);

    c4 = _mm_xor_si128(c4, c0);
    c4 = _mm_xor_si128(c4, c2);
    c5 = _mm_xor_si128(c5, c1);
    c5 = _mm_xor_si128(c5, c3);
    c1 = _mm_xor_si128(c1, c4);
    c2 = _mm_xor_si128(c2, c5);
}

// c3c2c1c0 = a1a0 * a1a0
inline void
F2N_Square_256_CLMUL(__m128i& c3, __m128i& c2, __m128i& c1,
    __m128i& c0, const __m128i& a1, const __m128i& a0)
{
    c0 = _mm_clmulepi64_si128(a0, a0, 0x00);
    c1 = _mm_clmulepi64_si128(a0, a0, 0x11);
    c2 = _mm_clmulepi64_si128(a1, a1, 0x00);
    c3 = _mm_clmulepi64_si128(a1, a1, 0x11);
}

// x = (x << n), z = 0
template <unsigned int N>
inline __m128i ShiftLeft128_SSE(__m128i x, const __m128i& z)
{
    __m128i u=x, v;
    x = _mm_slli_epi64(x, N);
    u = _mm_srli_epi64(u, (64-N));
    v = _mm_unpacklo_epi64(z, u);
    x = _mm_or_si128(x, v);
    return x;
}

// c1c0 = c3c2c1c0 MOD p. This is a Barrett reduction. Reading at
// Intel paper or https://github.com/antonblanchard/crc32-vpmsum.
inline void
GF2NT_233_Reduce_CLMUL(__m128i& c3, __m128i& c2, __m128i& c1, __m128i& c0)
{
    const unsigned int m[4] = {
        0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff
    };

    __m128i b3, b2, b1, /*b0,*/ a1, a0, m0, z0;
    m0 = _mm_set_epi32(m[3], m[2], m[1], m[0]);
    z0 = _mm_setzero_si128();
    b1 = c1; a1 = c1;
    a0 = _mm_move_epi64(c1);
    a1 = _mm_slli_epi64(a1, 23);
    a1 = _mm_srli_epi64(a1, 23);
    c1 = _mm_or_si128(a1, a0);
    b2 = _mm_srli_epi64(c2, (64-23));
    c3 = ShiftLeft128_SSE<23>(c3, z0);
    a0 = _mm_unpackhi_epi64(b2, z0);
    c3 = _mm_or_si128(c3, a0);
    b1 = _mm_srli_epi64(b1, (64-23));
    c2 = ShiftLeft128_SSE<23>(c2, z0);
    a0 = _mm_unpackhi_epi64(b1, z0);
    c2 = _mm_or_si128(c2, a0);
    b3 = c3;
    b2 = _mm_srli_epi64(c2, (64-10));
    b3 = ShiftLeft128_SSE<10>(b3, z0);
    a0 = _mm_unpackhi_epi64(b2, z0);
    b3 = _mm_or_si128(b3, a0);
    a0 = _mm_unpackhi_epi64(c3, z0);
    b3 = _mm_xor_si128(b3, a0);
    b1 = _mm_srli_epi64(b3, (64-23));
    b3 = ShiftLeft128_SSE<23>(b3, z0);
    b3 = _mm_unpackhi_epi64(b3, z0);
    b3 = _mm_or_si128(b3, b1);
    c2 = _mm_xor_si128(c2, b3);
    b3 = c3;
    b2 = _mm_srli_epi64(c2, (64-10));
    b3 = ShiftLeft128_SSE<10>(b3, z0);
    b2 = _mm_unpackhi_epi64(b2, z0);
    b3 = _mm_or_si128(b3, b2);
    b2 = c2;
    b2 = ShiftLeft128_SSE<10>(b2, z0);
    a0 = _mm_unpacklo_epi64(z0, b2);
    c2 = _mm_xor_si128(c2, a0);
    a0 = _mm_unpacklo_epi64(z0, b3);
    a1 = _mm_unpackhi_epi64(b2, z0);
    a0 = _mm_or_si128(a0, a1);
    c3 = _mm_xor_si128(c3, a0);
    c0 = _mm_xor_si128(c0, c2);
    c1 = _mm_xor_si128(c1, c3);
    c1 = _mm_and_si128(c1, m0);
}

#endif

// ************************* Power8 ************************* //

#if (CRYPTOPP_POWER8_VMULL_AVAILABLE)

using CryptoPP::byte;
using CryptoPP::word;
using CryptoPP::uint8x16_p;
using CryptoPP::uint64x2_p;

using CryptoPP::VecLoad;
using CryptoPP::VecStore;

using CryptoPP::VecOr;
using CryptoPP::VecXor;
using CryptoPP::VecAnd;

using CryptoPP::VecPermute;
using CryptoPP::VecMergeLow;
using CryptoPP::VecMergeHigh;
using CryptoPP::VecShiftLeft;
using CryptoPP::VecShiftRight;

using CryptoPP::VecPolyMultiply00LE;
using CryptoPP::VecPolyMultiply11LE;

// c1c0 = a * b
inline void
F2N_Multiply_128x128_POWER8(uint64x2_p& c1, uint64x2_p& c0, const uint64x2_p& a, const uint64x2_p& b)
{
    uint64x2_p t1, t2;
    const uint64x2_p z0={0};

    c0 = VecPolyMultiply00LE(a, b);
    c1 = VecPolyMultiply11LE(a, b);
    t1 = VecMergeLow(a, a);
    t1 = VecXor(a, t1);
    t2 = VecMergeLow(b, b);
    t2 = VecXor(b, t2);
    t1 = VecPolyMultiply00LE(t1, t2);
    t1 = VecXor(c0, t1);
    t1 = VecXor(c1, t1);
    t2 = t1;
    t1 = VecMergeHigh(z0, t1);
    t2 = VecMergeLow(t2, z0);
    c0 = VecXor(c0, t1);
    c1 = VecXor(c1, t2);
}

// c3c2c1c0 = a1a0 * b1b0
inline void
F2N_Multiply_256x256_POWER8(uint64x2_p& c3, uint64x2_p& c2, uint64x2_p& c1, uint64x2_p& c0,
    const uint64x2_p& b1, const uint64x2_p& b0, const uint64x2_p& a1, const uint64x2_p& a0)
{
    uint64x2_p c4, c5;
    uint64x2_p x0=a0, x1=a1, y0=b0, y1=b1;

    F2N_Multiply_128x128_POWER8(c1, c0, x0, y0);
    F2N_Multiply_128x128_POWER8(c3, c2, x1, y1);

    x0 = VecXor(x0, x1);
    y0 = VecXor(y0, y1);

    F2N_Multiply_128x128_POWER8(c5, c4, x0, y0);

    c4 = VecXor(c4, c0);
    c4 = VecXor(c4, c2);
    c5 = VecXor(c5, c1);
    c5 = VecXor(c5, c3);
    c1 = VecXor(c1, c4);
    c2 = VecXor(c2, c5);
}

// c3c2c1c0 = a1a0 * a1a0
inline void
F2N_Square_256_POWER8(uint64x2_p& c3, uint64x2_p& c2, uint64x2_p& c1,
    uint64x2_p& c0, const uint64x2_p& a1, const uint64x2_p& a0)
{
    c0 = VecPolyMultiply00LE(a0, a0);
    c1 = VecPolyMultiply11LE(a0, a0);
    c2 = VecPolyMultiply00LE(a1, a1);
    c3 = VecPolyMultiply11LE(a1, a1);
}

// x = (x << n), z = 0
template <unsigned int N>
inline uint64x2_p ShiftLeft128_POWER8(uint64x2_p x)
{
    uint64x2_p u=x, v;
    const uint64x2_p z={0};

    x = VecShiftLeft<N>(x);
    u = VecShiftRight<64-N>(u);
    v = VecMergeHigh(z, u);
    x = VecOr(x, v);
    return x;
}

// c1c0 = c3c2c1c0 MOD p. This is a Barrett reduction. Reading at
// Intel paper or https://github.com/antonblanchard/crc32-vpmsum.
inline void
GF2NT_233_Reduce_POWER8(uint64x2_p& c3, uint64x2_p& c2, uint64x2_p& c1, uint64x2_p& c0)
{
    const uint64_t mod[] = {W64LIT(0xffffffffffffffff), W64LIT(0x01ffffffffff)};
    const uint64x2_p m0 = (uint64x2_p)VecLoad(mod);

    uint64x2_p b3, b2, b1, /*b0,*/ a1, a0;
    const uint64x2_p z0={0};

    b1 = c1; a1 = c1;
    a0 = VecMergeHigh(c1, z0);
    a1 = VecShiftLeft<23>(a1);
    a1 = VecShiftRight<23>(a1);
    c1 = VecOr(a1, a0);
    b2 = VecShiftRight<64-23>(c2);
    c3 = ShiftLeft128_POWER8<23>(c3);
    a0 = VecMergeLow(b2, z0);
    c3 = VecOr(c3, a0);
    b1 = VecShiftRight<64-23>(b1);
    c2 = ShiftLeft128_POWER8<23>(c2);
    a0 = VecMergeLow(b1, z0);
    c2 = VecOr(c2, a0);
    b3 = c3;
    b2 = VecShiftRight<64-10>(c2);
    b3 = ShiftLeft128_POWER8<10>(b3);
    a0 = VecMergeLow(b2, z0);
    b3 = VecOr(b3, a0);
    a0 = VecMergeLow(c3, z0);
    b3 = VecXor(b3, a0);
    b1 = VecShiftRight<64-23>(b3);
    b3 = ShiftLeft128_POWER8<23>(b3);
    b3 = VecMergeLow(b3, z0);
    b3 = VecOr(b3, b1);
    c2 = VecXor(c2, b3);
    b3 = c3;
    b2 = VecShiftRight<64-10>(c2);
    b3 = ShiftLeft128_POWER8<10>(b3);
    b2 = VecMergeLow(b2, z0);
    b3 = VecOr(b3, b2);
    b2 = c2;
    b2 = ShiftLeft128_POWER8<10>(b2);
    a0 = VecMergeHigh(z0, b2);
    c2 = VecXor(c2, a0);
    a0 = VecMergeHigh(z0, b3);
    a1 = VecMergeLow(b2, z0);
    a0 = VecOr(a0, a1);
    c3 = VecXor(c3, a0);
    c0 = VecXor(c0, c2);
    c1 = VecXor(c1, c3);
    c1 = VecAnd(c1, m0);
}

#endif

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_CLMUL_AVAILABLE)

void
GF2NT_233_Multiply_Reduce_CLMUL(const word* pA, const word* pB, word* pC)
{
    const __m128i* pAA = reinterpret_cast<const __m128i*>(pA);
    const __m128i* pBB = reinterpret_cast<const __m128i*>(pB);
    __m128i a0 = _mm_loadu_si128(pAA+0);
    __m128i a1 = _mm_loadu_si128(pAA+1);
    __m128i b0 = _mm_loadu_si128(pBB+0);
    __m128i b1 = _mm_loadu_si128(pBB+1);

    __m128i c0, c1, c2, c3;
    F2N_Multiply_256x256_CLMUL(c3, c2, c1, c0, a1, a0, b1, b0);
    GF2NT_233_Reduce_CLMUL(c3, c2, c1, c0);

    __m128i* pCC = reinterpret_cast<__m128i*>(pC);
    _mm_storeu_si128(pCC+0, c0);
    _mm_storeu_si128(pCC+1, c1);
}

void
GF2NT_233_Square_Reduce_CLMUL(const word* pA, word* pC)
{
    const __m128i* pAA = reinterpret_cast<const __m128i*>(pA);
    __m128i a0 = _mm_loadu_si128(pAA+0);
    __m128i a1 = _mm_loadu_si128(pAA+1);

    __m128i c0, c1, c2, c3;
    F2N_Square_256_CLMUL(c3, c2, c1, c0, a1, a0);
    GF2NT_233_Reduce_CLMUL(c3, c2, c1, c0);

    __m128i* pCC = reinterpret_cast<__m128i*>(pC);
    _mm_storeu_si128(pCC+0, c0);
    _mm_storeu_si128(pCC+1, c1);
}

#elif (CRYPTOPP_ARM_PMULL_AVAILABLE)

void
GF2NT_233_Multiply_Reduce_ARMv8(const word* pA, const word* pB, word* pC)
{
    // word is either 32-bit or 64-bit, depending on the platform.
    // Load using a 32-bit pointer to avoid possible alignment issues.
    const uint32_t* pAA = reinterpret_cast<const uint32_t*>(pA);
    const uint32_t* pBB = reinterpret_cast<const uint32_t*>(pB);

    uint64x2_t a0 = vreinterpretq_u64_u32(vld1q_u32(pAA+0));
    uint64x2_t a1 = vreinterpretq_u64_u32(vld1q_u32(pAA+4));
    uint64x2_t b0 = vreinterpretq_u64_u32(vld1q_u32(pBB+0));
    uint64x2_t b1 = vreinterpretq_u64_u32(vld1q_u32(pBB+4));

    uint64x2_t c0, c1, c2, c3;
    F2N_Multiply_256x256_ARMv8(c3, c2, c1, c0, a1, a0, b1, b0);
    GF2NT_233_Reduce_ARMv8(c3, c2, c1, c0);

    uint32_t* pCC = reinterpret_cast<uint32_t*>(pC);
    vst1q_u32(pCC+0, vreinterpretq_u32_u64(c0));
    vst1q_u32(pCC+4, vreinterpretq_u32_u64(c1));
}

void
GF2NT_233_Square_Reduce_ARMv8(const word* pA, word* pC)
{
    // word is either 32-bit or 64-bit, depending on the platform.
    // Load using a 32-bit pointer to avoid possible alignment issues.
    const uint32_t* pAA = reinterpret_cast<const uint32_t*>(pA);
    uint64x2_t a0 = vreinterpretq_u64_u32(vld1q_u32(pAA+0));
    uint64x2_t a1 = vreinterpretq_u64_u32(vld1q_u32(pAA+4));

    uint64x2_t c0, c1, c2, c3;
    F2N_Square_256_ARMv8(c3, c2, c1, c0, a1, a0);
    GF2NT_233_Reduce_ARMv8(c3, c2, c1, c0);

    uint32_t* pCC = reinterpret_cast<uint32_t*>(pC);
    vst1q_u32(pCC+0, vreinterpretq_u32_u64(c0));
    vst1q_u32(pCC+4, vreinterpretq_u32_u64(c1));
}

#elif (CRYPTOPP_POWER8_VMULL_AVAILABLE)

void
GF2NT_233_Multiply_Reduce_POWER8(const word* pA, const word* pB, word* pC)
{
    // word is either 32-bit or 64-bit, depending on the platform.
    // Load using a byte pointer to avoid possible alignment issues.
    const byte* pAA = reinterpret_cast<const byte*>(pA);
    const byte* pBB = reinterpret_cast<const byte*>(pB);

    uint64x2_p a0 = (uint64x2_p)VecLoad(pAA+0);
    uint64x2_p a1 = (uint64x2_p)VecLoad(pAA+16);
    uint64x2_p b0 = (uint64x2_p)VecLoad(pBB+0);
    uint64x2_p b1 = (uint64x2_p)VecLoad(pBB+16);

#if (CRYPTOPP_BIG_ENDIAN)
    const uint8_t mb[] = {4,5,6,7, 0,1,2,3, 12,13,14,15, 8,9,10,11};
    const uint8x16_p m = (uint8x16_p)VecLoad(mb);
    a0 = VecPermute(a0, m);
    a1 = VecPermute(a1, m);
    b0 = VecPermute(b0, m);
    b1 = VecPermute(b1, m);
#endif

    uint64x2_p c0, c1, c2, c3;
    F2N_Multiply_256x256_POWER8(c3, c2, c1, c0, a1, a0, b1, b0);
    GF2NT_233_Reduce_POWER8(c3, c2, c1, c0);

#if (CRYPTOPP_BIG_ENDIAN)
    c0 = VecPermute(c0, m);
    c1 = VecPermute(c1, m);
#endif

    byte* pCC = reinterpret_cast<byte*>(pC);
    VecStore(c0, pCC+0);
    VecStore(c1, pCC+16);
}

void
GF2NT_233_Square_Reduce_POWER8(const word* pA, word* pC)
{
    // word is either 32-bit or 64-bit, depending on the platform.
    // Load using a byte pointer to avoid possible alignment issues.
    const byte* pAA = reinterpret_cast<const byte*>(pA);
    uint64x2_p a0 = (uint64x2_p)VecLoad(pAA+0);
    uint64x2_p a1 = (uint64x2_p)VecLoad(pAA+16);

#if (CRYPTOPP_BIG_ENDIAN)
    const uint8_t mb[] = {4,5,6,7, 0,1,2,3, 12,13,14,15, 8,9,10,11};
    const uint8x16_p m = (uint8x16_p)VecLoad(mb);
    a0 = VecPermute(a0, m);
    a1 = VecPermute(a1, m);
#endif

    uint64x2_p c0, c1, c2, c3;
    F2N_Square_256_POWER8(c3, c2, c1, c0, a1, a0);
    GF2NT_233_Reduce_POWER8(c3, c2, c1, c0);

#if (CRYPTOPP_BIG_ENDIAN)
    c0 = VecPermute(c0, m);
    c1 = VecPermute(c1, m);
#endif

    byte* pCC = reinterpret_cast<byte*>(pC);
    VecStore(c0, pCC+0);
    VecStore(c1, pCC+16);
}

#endif

NAMESPACE_END

#endif  // CRYPTOPP_IMPORTS