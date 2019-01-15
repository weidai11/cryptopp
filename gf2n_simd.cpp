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

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word;

#if defined(CRYPTOPP_CLMUL_AVAILABLE)

// c1c0 = a * b
inline void
F2N_Multiply_128x128_CLMUL(__m128i& c1, __m128i& c0, const __m128i& a, const __m128i& b)
{
    __m128i t1, t2;

    c0 = _mm_clmulepi64_si128(a, b, 0x00);
    c1 = _mm_clmulepi64_si128(a, b, 0x11);
    t1  = _mm_shuffle_epi32(a, 0xEE);
    t1  = _mm_xor_si128(a, t1);
    t2  = _mm_shuffle_epi32(b, 0xEE);
    t2  = _mm_xor_si128(b, t2);
    t1  = _mm_clmulepi64_si128(t1, t2, 0x00);
    t1  = _mm_xor_si128(c0, t1);
    t1  = _mm_xor_si128(c1, t1);
    t2  = t1;
    t1  = _mm_slli_si128(t1, 8);
    t2  = _mm_srli_si128(t2, 8);
    c0 = _mm_xor_si128(c0, t1);
    c1 = _mm_xor_si128(c1, t2);
}

// x = (x << n), z = 0
template <unsigned int N>
inline __m128i XMM_SHL_N(__m128i x, const __m128i& z)
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
inline void GF2NT_233_Reduce(__m128i& c3, __m128i& c2, __m128i& c1, __m128i& c0)
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
    c3 = XMM_SHL_N<23>(c3, z0);
    a0 = _mm_unpackhi_epi64(b2, z0);
    c3 = _mm_or_si128(c3, a0);
    b1 = _mm_srli_epi64(b1, (64-23));
    c2 = XMM_SHL_N<23>(c2, z0);
    a0 = _mm_unpackhi_epi64(b1, z0);
    c2 = _mm_or_si128(c2, a0);
    b3 = c3;
    b2 = _mm_srli_epi64(c2, (64-10));
    b3 = XMM_SHL_N<10>(b3, z0);
    a0 = _mm_unpackhi_epi64(b2, z0);
    b3 = _mm_or_si128(b3, a0);
    a0 = _mm_unpackhi_epi64(c3, z0);
    b3 = _mm_xor_si128(b3, a0);
    b1 = _mm_srli_epi64(b3, (64-23));
    b3 = XMM_SHL_N<23>(b3, z0);
    b3 = _mm_unpackhi_epi64(b3, z0);
    b3 = _mm_or_si128(b3, b1);
    c2 = _mm_xor_si128(c2, b3);
    b3 = c3;
    b2 = _mm_srli_epi64(c2, (64-10));
    b3 = XMM_SHL_N<10>(b3, z0);
    b2 = _mm_unpackhi_epi64(b2, z0);
    b3 = _mm_or_si128(b3, b2);
    b2 = c2;
    b2 = XMM_SHL_N<10>(b2, z0);
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

    GF2NT_233_Reduce(c3, c2, c1, c0);

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
#else
    CRYPTOPP_ASSERT(0);
#endif
}

NAMESPACE_END
