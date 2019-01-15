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

#include "gf2n.h"

#if (CRYPTOPP_CLMUL_AVAILABLE)
# include <emmintrin.h>
# include <wmmintrin.h>
#endif

#if (CRYPTOPP_ARM_PMULL_AVAILABLE)
# include "arm_simd.h"
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word;

// ************************** ARMv8 ************************** //

#if (CRYPTOPP_ARM_PMULL_AVAILABLE)

// c1c0 = a * b
inline void
F2N_Multiply_128x128_ARMv8(uint64x2_t& c1, uint64x2_t& c0, const uint64x2_t& a, const uint64x2_t& b)
{
    uint64x2_t t1, t2, z0 = {0};

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

    uint64x2_t b3, b2, b1, /*b0,*/ a1, a0, m0, z0 = {0};
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

inline void
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

    uint64x2_t c0, c1, c2, c3, c4, c5;
    F2N_Multiply_128x128_ARMv8(c1, c0, a0, b0);
    F2N_Multiply_128x128_ARMv8(c3, c2, a1, b1);

    a0 = veorq_u64(a0, a1);
    b0 = veorq_u64(b0, b1);

    F2N_Multiply_128x128_ARMv8(c5, c4, a0, b0);

    c4 = veorq_u64(c4, c0);
    c4 = veorq_u64(c4, c2);
    c5 = veorq_u64(c5, c1);
    c5 = veorq_u64(c5, c3);
    c1 = veorq_u64(c1, c4);
    c2 = veorq_u64(c2, c5);

    GF2NT_233_Reduce_ARMv8(c3, c2, c1, c0);

    uint32_t* pCC = reinterpret_cast<uint32_t*>(pC);
    vst1q_u32(pCC+0, vreinterpretq_u32_u64(c0));
    vst1q_u32(pCC+4, vreinterpretq_u32_u64(c1));
}

#endif

// ************************** x86 ************************** //

#if defined(CRYPTOPP_CLMUL_AVAILABLE)

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

inline void
GF2NT_233_Multiply_Reduce_CLMUL(const word* pA, const word* pB, word* pC)
{
    const __m128i* pAA = reinterpret_cast<const __m128i*>(pA);
    const __m128i* pBB = reinterpret_cast<const __m128i*>(pB);
    __m128i a0 = _mm_loadu_si128(pAA+0);
    __m128i a1 = _mm_loadu_si128(pAA+1);
    __m128i b0 = _mm_loadu_si128(pBB+0);
    __m128i b1 = _mm_loadu_si128(pBB+1);

    __m128i c0, c1, c2, c3, c4, c5;
    F2N_Multiply_128x128_CLMUL(c1, c0, a0, b0);
    F2N_Multiply_128x128_CLMUL(c3, c2, a1, b1);

    a0 = _mm_xor_si128(a0, a1);
    b0 = _mm_xor_si128(b0, b1);

    F2N_Multiply_128x128_CLMUL(c5, c4, a0, b0);

    c4 = _mm_xor_si128(c4, c0);
    c4 = _mm_xor_si128(c4, c2);
    c5 = _mm_xor_si128(c5, c1);
    c5 = _mm_xor_si128(c5, c3);
    c1 = _mm_xor_si128(c1, c4);
    c2 = _mm_xor_si128(c2, c5);

    GF2NT_233_Reduce_CLMUL(c3, c2, c1, c0);

    __m128i* pCC = reinterpret_cast<__m128i*>(pC);
    _mm_storeu_si128(pCC+0, c0);
    _mm_storeu_si128(pCC+1, c1);
}

#endif

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void GF2NT_233_Multiply_Reduce(const word* pA, const word* pB, word* pC)
{
#if defined(CRYPTOPP_CLMUL_AVAILABLE)
    return GF2NT_233_Multiply_Reduce_CLMUL(pA, pB, pC);
#elif (CRYPTOPP_ARM_PMULL_AVAILABLE)
    return GF2NT_233_Multiply_Reduce_ARMv8(pA, pB, pC);
#else
    CRYPTOPP_ASSERT(0);
#endif
}

NAMESPACE_END
