// cham_simd.cpp - written and placed in the public domain by Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    SSSE3, ARM NEON and ARMv8a, and Power7 Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"

#include "cham.h"
#include "misc.h"

// Uncomment for benchmarking C++ against SSE or NEON.
// Do so in both simon.cpp and simon-simd.cpp.
// #undef CRYPTOPP_SSSE3_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_SSSE3_AVAILABLE)
#include "adv_simd.h"
# include <pmmintrin.h>
# include <tmmintrin.h>
#endif

#if defined(__XOP__)
# include <ammintrin.h>
#endif

#if defined(__AVX512F__)
# define CRYPTOPP_AVX512_ROTATE 1
# include <immintrin.h>
#endif

// Squash MS LNK4221 and libtool warnings
extern const char CHAM_SIMD_FNAME[] = __FILE__;

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word16;
using CryptoPP::word32;

#if (CRYPTOPP_SSSE3_AVAILABLE)

//////////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(W16)  // CHAM64, 16-bit word size

template <unsigned int R>
inline __m128i RotateLeft16(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi16(val, R);
#else
    return _mm_or_si128(
        _mm_slli_epi16(val, R), _mm_srli_epi16(val, 16-R));
#endif
}

template <unsigned int R>
inline __m128i RotateRight16(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi16(val, 16-R);
#else
    return _mm_or_si128(
        _mm_slli_epi16(val, 16-R), _mm_srli_epi16(val, R));
#endif
}

template <>
inline __m128i RotateLeft16<8>(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi16(val, 8);
#else
    const __m128i mask = _mm_set_epi8(14,15, 12,13, 10,11, 8,9, 6,7, 4,5, 2,3, 0,1);
    return _mm_shuffle_epi8(val, mask);
#endif
}

template <>
inline __m128i RotateRight16<8>(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi16(val, 16-8);
#else
    const __m128i mask = _mm_set_epi8(14,15, 12,13, 10,11, 8,9, 6,7, 4,5, 2,3, 0,1);
    return _mm_shuffle_epi8(val, mask);
#endif
}

template <unsigned int IDX>
inline __m128i UnpackXMM(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                         const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // Should not be instantiated
    CRYPTOPP_UNUSED(a); CRYPTOPP_UNUSED(b);
    CRYPTOPP_UNUSED(c); CRYPTOPP_UNUSED(d);
    CRYPTOPP_UNUSED(e); CRYPTOPP_UNUSED(f);
    CRYPTOPP_UNUSED(g); CRYPTOPP_UNUSED(h);
    CRYPTOPP_ASSERT(0);
    return _mm_setzero_si128();
}

template <>
inline __m128i UnpackXMM<0>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                            const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpacklo_epi16(a, b);
    const __m128i r2 = _mm_unpacklo_epi16(c, d);
    const __m128i r3 = _mm_unpacklo_epi16(e, f);
    const __m128i r4 = _mm_unpacklo_epi16(g, h);

    const __m128i r5 = _mm_unpacklo_epi32(r1, r2);
    const __m128i r6 = _mm_unpacklo_epi32(r3, r4);
    return _mm_shuffle_epi8(_mm_unpacklo_epi64(r5, r6),
        _mm_set_epi8(14,15,12,13, 10,11,8,9, 6,7,4,5, 2,3,0,1));
}

template <>
inline __m128i UnpackXMM<1>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                            const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpacklo_epi16(a, b);
    const __m128i r2 = _mm_unpacklo_epi16(c, d);
    const __m128i r3 = _mm_unpacklo_epi16(e, f);
    const __m128i r4 = _mm_unpacklo_epi16(g, h);

    const __m128i r5 = _mm_unpacklo_epi32(r1, r2);
    const __m128i r6 = _mm_unpacklo_epi32(r3, r4);
    return _mm_shuffle_epi8(_mm_unpackhi_epi64(r5, r6),
        _mm_set_epi8(14,15,12,13, 10,11,8,9, 6,7,4,5, 2,3,0,1));
}

template <>
inline __m128i UnpackXMM<2>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                            const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpacklo_epi16(a, b);
    const __m128i r2 = _mm_unpacklo_epi16(c, d);
    const __m128i r3 = _mm_unpacklo_epi16(e, f);
    const __m128i r4 = _mm_unpacklo_epi16(g, h);

    const __m128i r5 = _mm_unpackhi_epi32(r1, r2);
    const __m128i r6 = _mm_unpackhi_epi32(r3, r4);
    return _mm_shuffle_epi8(_mm_unpacklo_epi64(r5, r6),
        _mm_set_epi8(14,15,12,13, 10,11,8,9, 6,7,4,5, 2,3,0,1));
}

template <>
inline __m128i UnpackXMM<3>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                            const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpacklo_epi16(a, b);
    const __m128i r2 = _mm_unpacklo_epi16(c, d);
    const __m128i r3 = _mm_unpacklo_epi16(e, f);
    const __m128i r4 = _mm_unpacklo_epi16(g, h);

    const __m128i r5 = _mm_unpackhi_epi32(r1, r2);
    const __m128i r6 = _mm_unpackhi_epi32(r3, r4);
    return _mm_shuffle_epi8(_mm_unpackhi_epi64(r5, r6),
        _mm_set_epi8(14,15,12,13, 10,11,8,9, 6,7,4,5, 2,3,0,1));
}

template <>
inline __m128i UnpackXMM<4>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                            const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpackhi_epi16(a, b);
    const __m128i r2 = _mm_unpackhi_epi16(c, d);
    const __m128i r3 = _mm_unpackhi_epi16(e, f);
    const __m128i r4 = _mm_unpackhi_epi16(g, h);

    const __m128i r5 = _mm_unpacklo_epi32(r1, r2);
    const __m128i r6 = _mm_unpacklo_epi32(r3, r4);
    return _mm_shuffle_epi8(_mm_unpacklo_epi64(r5, r6),
        _mm_set_epi8(14,15,12,13, 10,11,8,9, 6,7,4,5, 2,3,0,1));
}

template <>
inline __m128i UnpackXMM<5>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                            const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpackhi_epi16(a, b);
    const __m128i r2 = _mm_unpackhi_epi16(c, d);
    const __m128i r3 = _mm_unpackhi_epi16(e, f);
    const __m128i r4 = _mm_unpackhi_epi16(g, h);

    const __m128i r5 = _mm_unpacklo_epi32(r1, r2);
    const __m128i r6 = _mm_unpacklo_epi32(r3, r4);
    return _mm_shuffle_epi8(_mm_unpackhi_epi64(r5, r6),
        _mm_set_epi8(14,15,12,13, 10,11,8,9, 6,7,4,5, 2,3,0,1));
}

template <>
inline __m128i UnpackXMM<6>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                            const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpackhi_epi16(a, b);
    const __m128i r2 = _mm_unpackhi_epi16(c, d);
    const __m128i r3 = _mm_unpackhi_epi16(e, f);
    const __m128i r4 = _mm_unpackhi_epi16(g, h);

    const __m128i r5 = _mm_unpackhi_epi32(r1, r2);
    const __m128i r6 = _mm_unpackhi_epi32(r3, r4);
    return _mm_shuffle_epi8(_mm_unpacklo_epi64(r5, r6),
        _mm_set_epi8(14,15,12,13, 10,11,8,9, 6,7,4,5, 2,3,0,1));
}

template <>
inline __m128i UnpackXMM<7>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                            const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpackhi_epi16(a, b);
    const __m128i r2 = _mm_unpackhi_epi16(c, d);
    const __m128i r3 = _mm_unpackhi_epi16(e, f);
    const __m128i r4 = _mm_unpackhi_epi16(g, h);

    const __m128i r5 = _mm_unpackhi_epi32(r1, r2);
    const __m128i r6 = _mm_unpackhi_epi32(r3, r4);
    return _mm_shuffle_epi8(_mm_unpackhi_epi64(r5, r6),
        _mm_set_epi8(14,15,12,13, 10,11,8,9, 6,7,4,5, 2,3,0,1));
}

template <unsigned int IDX>
inline __m128i UnpackXMM(const __m128i& v)
{
    // Should not be instantiated
    CRYPTOPP_UNUSED(v); CRYPTOPP_ASSERT(0);

    return _mm_setzero_si128();
}

template <>
inline __m128i UnpackXMM<0>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(0,1, 0,1, 0,1, 0,1, 0,1, 0,1, 0,1, 0,1));
}

template <>
inline __m128i UnpackXMM<1>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(2,3, 2,3, 2,3, 2,3, 2,3, 2,3, 2,3, 2,3));
}

template <>
inline __m128i UnpackXMM<2>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(4,5, 4,5, 4,5, 4,5, 4,5, 4,5, 4,5, 4,5));
}

template <>
inline __m128i UnpackXMM<3>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(6,7, 6,7, 6,7, 6,7, 6,7, 6,7, 6,7, 6,7));
}

template <>
inline __m128i UnpackXMM<4>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(8,9, 8,9, 8,9, 8,9, 8,9, 8,9, 8,9, 8,9));
}

template <>
inline __m128i UnpackXMM<5>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(10,11, 10,11, 10,11, 10,11, 10,11, 10,11, 10,11, 10,11));
}

template <>
inline __m128i UnpackXMM<6>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(12,13, 12,13, 12,13, 12,13, 12,13, 12,13, 12,13, 12,13));
}

template <>
inline __m128i UnpackXMM<7>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(14,15, 14,15, 14,15, 14,15, 14,15, 14,15, 14,15, 14,15));
}

template <unsigned int IDX>
inline __m128i UnpackXMM(const __m128i& a, const __m128i& b)
{
    const __m128i& z = _mm_setzero_si128();
    return UnpackXMM<IDX>(a, b, z, z, z, z, z, z);
}

template <unsigned int IDX>
inline __m128i RepackXMM(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d,
                         const __m128i& e, const __m128i& f, const __m128i& g, const __m128i& h)
{
    return UnpackXMM<IDX>(a, b, c, d, e, f, g, h);
}

template <unsigned int IDX>
inline __m128i RepackXMM(const __m128i& v)
{
    return UnpackXMM<IDX>(v);
}

inline void CHAM64_Enc_Block(__m128i &block0,
    const word16 *subkeys, unsigned int /*rounds*/)
{
    // Rearrange the data for vectorization. UnpackXMM includes a
    // little-endian swap for SSE. Thanks to Peter Cordes for help
    // with packing and unpacking.
    // [A1 A2 .. A6 A7][B1 B2 .. B6 B7] ... => [A1 B1 .. G1 H1][A2 B2 .. G2 H2] ...
    __m128i a = UnpackXMM<0>(block0);
    __m128i b = UnpackXMM<1>(block0);
    __m128i c = UnpackXMM<2>(block0);
    __m128i d = UnpackXMM<3>(block0);
    __m128i e = UnpackXMM<4>(block0);
    __m128i f = UnpackXMM<5>(block0);
    __m128i g = UnpackXMM<6>(block0);
    __m128i h = UnpackXMM<7>(block0);

    const unsigned int rounds = 80;
    __m128i counter = _mm_set_epi16(0,0,0,0,0,0,0,0);
    __m128i increment = _mm_set_epi16(1,1,1,1,1,1,1,1);

    const unsigned int MASK = 15;
    for (int i=0; i<static_cast<int>(rounds); i+=4)
    {
        __m128i k, kr, t1, t2, t3, t4;
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i+0) & MASK])));

        // Shuffle out key
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(1,0,1,0, 1,0,1,0, 1,0,1,0, 1,0,1,0));

        t1 = _mm_xor_si128(a, counter);
        t3 = _mm_xor_si128(e, counter);
        t2 = _mm_xor_si128(RotateLeft16<1>(b), kr);
        t4 = _mm_xor_si128(RotateLeft16<1>(f), kr);
        a = RotateLeft16<8>(_mm_add_epi16(t1, t2));
        e = RotateLeft16<8>(_mm_add_epi16(t3, t4));

        counter = _mm_add_epi16(counter, increment);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,3,2, 3,2,3,2, 3,2,3,2, 3,2,3,2));

        t1 = _mm_xor_si128(b, counter);
        t3 = _mm_xor_si128(f, counter);
        t2 = _mm_xor_si128(RotateLeft16<8>(c), kr);
        t4 = _mm_xor_si128(RotateLeft16<8>(g), kr);
        b = RotateLeft16<1>(_mm_add_epi16(t1, t2));
        f = RotateLeft16<1>(_mm_add_epi16(t3, t4));

        counter = _mm_add_epi16(counter, increment);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(5,4,5,4, 5,4,5,4, 5,4,5,4, 5,4,5,4));

        t1 = _mm_xor_si128(c, counter);
        t3 = _mm_xor_si128(g, counter);
        t2 = _mm_xor_si128(RotateLeft16<1>(d), kr);
        t4 = _mm_xor_si128(RotateLeft16<1>(h), kr);
        c = RotateLeft16<8>(_mm_add_epi16(t1, t2));
        g = RotateLeft16<8>(_mm_add_epi16(t3, t4));

        counter = _mm_add_epi16(counter, increment);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,7,6, 7,6,7,6, 7,6,7,6, 7,6,7,6));

        t1 = _mm_xor_si128(d, counter);
        t3 = _mm_xor_si128(h, counter);
        t2 = _mm_xor_si128(RotateLeft16<8>(a), kr);
        t4 = _mm_xor_si128(RotateLeft16<8>(e), kr);
        d = RotateLeft16<1>(_mm_add_epi16(t1, t2));
        h = RotateLeft16<1>(_mm_add_epi16(t3, t4));

        counter = _mm_add_epi16(counter, increment);
    }

    // [A1 B1 .. G1 H1][A2 B2 .. G2 H2] ... => [A1 A2 .. A6 A7][B1 B2 .. B6 B7] ...
    block0 = RepackXMM<0>(a,b,c,d,e,f,g,h);
}

inline void CHAM64_Dec_Block(__m128i &block0,
    const word16 *subkeys, unsigned int /*rounds*/)
{
    // Rearrange the data for vectorization. UnpackXMM includes a
    // little-endian swap for SSE. Thanks to Peter Cordes for help
    // with packing and unpacking.
    // [A1 A2 .. A6 A7][B1 B2 .. B6 B7] ... => [A1 B1 .. G1 H1][A2 B2 .. G2 H2] ...
    __m128i a = UnpackXMM<0>(block0);
    __m128i b = UnpackXMM<1>(block0);
    __m128i c = UnpackXMM<2>(block0);
    __m128i d = UnpackXMM<3>(block0);
    __m128i e = UnpackXMM<4>(block0);
    __m128i f = UnpackXMM<5>(block0);
    __m128i g = UnpackXMM<6>(block0);
    __m128i h = UnpackXMM<7>(block0);

    const unsigned int rounds = 80;
    __m128i counter = _mm_set_epi16(rounds-1,rounds-1,rounds-1,rounds-1, rounds-1,rounds-1,rounds-1,rounds-1);
    __m128i decrement = _mm_set_epi16(1,1,1,1,1,1,1,1);

    const unsigned int MASK = 15;
    for (int i = static_cast<int>(rounds)-1; i >= 0; i-=4)
    {
        __m128i k, kr, t1, t2, t3, t4;
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i-3) & MASK])));

        // Shuffle out key
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,7,6, 7,6,7,6, 7,6,7,6, 7,6,7,6));

        // Odd round
        t1 = RotateRight16<1>(d);
        t3 = RotateRight16<1>(h);
        t2 = _mm_xor_si128(RotateLeft16<8>(a), kr);
        t4 = _mm_xor_si128(RotateLeft16<8>(e), kr);
        d = _mm_xor_si128(_mm_sub_epi16(t1, t2), counter);
        h = _mm_xor_si128(_mm_sub_epi16(t3, t4), counter);

        counter = _mm_sub_epi16(counter, decrement);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(5,4,5,4, 5,4,5,4, 5,4,5,4, 5,4,5,4));

        // Even round
        t1 = RotateRight16<8>(c);
        t3 = RotateRight16<8>(g);
        t2 = _mm_xor_si128(RotateLeft16<1>(d), kr);
        t4 = _mm_xor_si128(RotateLeft16<1>(h), kr);
        c = _mm_xor_si128(_mm_sub_epi16(t1, t2), counter);
        g = _mm_xor_si128(_mm_sub_epi16(t3, t4), counter);

        counter = _mm_sub_epi16(counter, decrement);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,3,2, 3,2,3,2, 3,2,3,2, 3,2,3,2));

        // Odd round
        t1 = RotateRight16<1>(b);
        t3 = RotateRight16<1>(f);
        t2 = _mm_xor_si128(RotateLeft16<8>(c), kr);
        t4 = _mm_xor_si128(RotateLeft16<8>(g), kr);
        b = _mm_xor_si128(_mm_sub_epi16(t1, t2), counter);
        f = _mm_xor_si128(_mm_sub_epi16(t3, t4), counter);

        counter = _mm_sub_epi16(counter, decrement);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(1,0,1,0, 1,0,1,0, 1,0,1,0, 1,0,1,0));

        // Even round
        t1 = RotateRight16<8>(a);
        t3 = RotateRight16<8>(e);
        t2 = _mm_xor_si128(RotateLeft16<1>(b), kr);
        t4 = _mm_xor_si128(RotateLeft16<1>(f), kr);
        a = _mm_xor_si128(_mm_sub_epi16(t1, t2), counter);
        e = _mm_xor_si128(_mm_sub_epi16(t3, t4), counter);

        counter = _mm_sub_epi16(counter, decrement);
    }

    // [A1 B1 .. G1 H1][A2 B2 .. G2 H2] ... => [A1 A2 .. A6 A7][B1 B2 .. B6 B7] ...
    block0 = RepackXMM<0>(a,b,c,d,e,f,g,h);
}

inline void CHAM64_Enc_2_Blocks(__m128i &block0,
    __m128i &block1, const word16 *subkeys, unsigned int /*rounds*/)
{
    // Rearrange the data for vectorization. UnpackXMM includes a
    // little-endian swap for SSE. Thanks to Peter Cordes for help
    // with packing and unpacking.
    // [A1 A2 .. A6 A7][B1 B2 .. B6 B7] ... => [A1 B1 .. G1 H1][A2 B2 .. G2 H2] ...
    __m128i a = UnpackXMM<0>(block0, block1);
    __m128i b = UnpackXMM<1>(block0, block1);
    __m128i c = UnpackXMM<2>(block0, block1);
    __m128i d = UnpackXMM<3>(block0, block1);
    __m128i e = UnpackXMM<4>(block0, block1);
    __m128i f = UnpackXMM<5>(block0, block1);
    __m128i g = UnpackXMM<6>(block0, block1);
    __m128i h = UnpackXMM<7>(block0, block1);

    const unsigned int rounds = 80;
    __m128i counter = _mm_set_epi16(0,0,0,0,0,0,0,0);
    __m128i increment = _mm_set_epi16(1,1,1,1,1,1,1,1);

    const unsigned int MASK = 15;
    for (int i=0; i<static_cast<int>(rounds); i+=4)
    {
        __m128i k, kr, t1, t2, t3, t4;
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[i & MASK])));

        // Shuffle out key
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(1,0,1,0, 1,0,1,0, 1,0,1,0, 1,0,1,0));

        t1 = _mm_xor_si128(a, counter);
        t3 = _mm_xor_si128(e, counter);
        t2 = _mm_xor_si128(RotateLeft16<1>(b), kr);
        t4 = _mm_xor_si128(RotateLeft16<1>(f), kr);
        a = RotateLeft16<8>(_mm_add_epi16(t1, t2));
        e = RotateLeft16<8>(_mm_add_epi16(t3, t4));

        counter = _mm_add_epi16(counter, increment);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,3,2, 3,2,3,2, 3,2,3,2, 3,2,3,2));

        t1 = _mm_xor_si128(b, counter);
        t3 = _mm_xor_si128(f, counter);
        t2 = _mm_xor_si128(RotateLeft16<8>(c), kr);
        t4 = _mm_xor_si128(RotateLeft16<8>(g), kr);
        b = RotateLeft16<1>(_mm_add_epi16(t1, t2));
        f = RotateLeft16<1>(_mm_add_epi16(t3, t4));

        counter = _mm_add_epi16(counter, increment);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(5,4,5,4, 5,4,5,4, 5,4,5,4, 5,4,5,4));

        t1 = _mm_xor_si128(c, counter);
        t3 = _mm_xor_si128(g, counter);
        t2 = _mm_xor_si128(RotateLeft16<1>(d), kr);
        t4 = _mm_xor_si128(RotateLeft16<1>(h), kr);
        c = RotateLeft16<8>(_mm_add_epi16(t1, t2));
        g = RotateLeft16<8>(_mm_add_epi16(t3, t4));

        counter = _mm_add_epi16(counter, increment);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,7,6, 7,6,7,6, 7,6,7,6, 7,6,7,6));

        t1 = _mm_xor_si128(d, counter);
        t3 = _mm_xor_si128(h, counter);
        t2 = _mm_xor_si128(RotateLeft16<8>(a), kr);
        t4 = _mm_xor_si128(RotateLeft16<8>(e), kr);
        d = RotateLeft16<1>(_mm_add_epi16(t1, t2));
        h = RotateLeft16<1>(_mm_add_epi16(t3, t4));

        counter = _mm_add_epi16(counter, increment);
    }

    // [A1 B1 .. G1 H1][A2 B2 .. G2 H2] ... => [A1 A2 .. A6 A7][B1 B2 .. B6 B7] ...
    block0 = RepackXMM<0>(a,b,c,d,e,f,g,h);
    block1 = RepackXMM<1>(a,b,c,d,e,f,g,h);
}

inline void CHAM64_Dec_2_Blocks(__m128i &block0,
    __m128i &block1, const word16 *subkeys, unsigned int /*rounds*/)
{
    // Rearrange the data for vectorization. UnpackXMM includes a
    // little-endian swap for SSE. Thanks to Peter Cordes for help
    // with packing and unpacking.
    // [A1 A2 .. A6 A7][B1 B2 .. B6 B7] ... => [A1 B1 .. G1 H1][A2 B2 .. G2 H2] ...
    __m128i a = UnpackXMM<0>(block0, block1);
    __m128i b = UnpackXMM<1>(block0, block1);
    __m128i c = UnpackXMM<2>(block0, block1);
    __m128i d = UnpackXMM<3>(block0, block1);
    __m128i e = UnpackXMM<4>(block0, block1);
    __m128i f = UnpackXMM<5>(block0, block1);
    __m128i g = UnpackXMM<6>(block0, block1);
    __m128i h = UnpackXMM<7>(block0, block1);

    const unsigned int rounds = 80;
    __m128i counter = _mm_set_epi16(rounds-1,rounds-1,rounds-1,rounds-1, rounds-1,rounds-1,rounds-1,rounds-1);
    __m128i decrement = _mm_set_epi16(1,1,1,1,1,1,1,1);

    const unsigned int MASK = 15;
    for (int i = static_cast<int>(rounds)-1; i >= 0; i-=4)
    {
        __m128i k, kr, t1, t2, t3, t4;
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i-3) & MASK])));

        // Shuffle out key
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,7,6, 7,6,7,6, 7,6,7,6, 7,6,7,6));

        // Odd round
        t1 = RotateRight16<1>(d);
        t3 = RotateRight16<1>(h);
        t2 = _mm_xor_si128(RotateLeft16<8>(a), kr);
        t4 = _mm_xor_si128(RotateLeft16<8>(e), kr);
        d = _mm_xor_si128(_mm_sub_epi16(t1, t2), counter);
        h = _mm_xor_si128(_mm_sub_epi16(t3, t4), counter);

        counter = _mm_sub_epi16(counter, decrement);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(5,4,5,4, 5,4,5,4, 5,4,5,4, 5,4,5,4));

        // Even round
        t1 = RotateRight16<8>(c);
        t3 = RotateRight16<8>(g);
        t2 = _mm_xor_si128(RotateLeft16<1>(d), kr);
        t4 = _mm_xor_si128(RotateLeft16<1>(h), kr);
        c = _mm_xor_si128(_mm_sub_epi16(t1, t2), counter);
        g = _mm_xor_si128(_mm_sub_epi16(t3, t4), counter);

        counter = _mm_sub_epi16(counter, decrement);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,3,2, 3,2,3,2, 3,2,3,2, 3,2,3,2));

        // Odd round
        t1 = RotateRight16<1>(b);
        t3 = RotateRight16<1>(f);
        t2 = _mm_xor_si128(RotateLeft16<8>(c), kr);
        t4 = _mm_xor_si128(RotateLeft16<8>(g), kr);
        b = _mm_xor_si128(_mm_sub_epi16(t1, t2), counter);
        f = _mm_xor_si128(_mm_sub_epi16(t3, t4), counter);

        counter = _mm_sub_epi16(counter, decrement);
        kr = _mm_shuffle_epi8(k, _mm_set_epi8(1,0,1,0, 1,0,1,0, 1,0,1,0, 1,0,1,0));

        // Even round
        t1 = RotateRight16<8>(a);
        t3 = RotateRight16<8>(e);
        t2 = _mm_xor_si128(RotateLeft16<1>(b), kr);
        t4 = _mm_xor_si128(RotateLeft16<1>(f), kr);
        a = _mm_xor_si128(_mm_sub_epi16(t1, t2), counter);
        e = _mm_xor_si128(_mm_sub_epi16(t3, t4), counter);

        counter = _mm_sub_epi16(counter, decrement);
    }

    // [A1 B1 .. G1 H1][A2 B2 .. G2 H2] ... => [A1 A2 .. A6 A7][B1 B2 .. B6 B7] ...
    block0 = RepackXMM<0>(a,b,c,d,e,f,g,h);
    block1 = RepackXMM<1>(a,b,c,d,e,f,g,h);
}

NAMESPACE_END  // W16

//////////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(W32)  // CHAM128, 32-bit word size

template <unsigned int R>
inline __m128i RotateLeft32(const __m128i& val)
{
#if defined(CRYPTOPP_AVX512_ROTATE)
    return _mm_rol_epi32(val, R);
#elif defined(__XOP__)
    return _mm_roti_epi32(val, R);
#else
    return _mm_or_si128(
        _mm_slli_epi32(val, R), _mm_srli_epi32(val, 32-R));
#endif
}

template <unsigned int R>
inline __m128i RotateRight32(const __m128i& val)
{
#if defined(CRYPTOPP_AVX512_ROTATE)
    return _mm_ror_epi32(val, R);
#elif defined(__XOP__)
    return _mm_roti_epi32(val, 32-R);
#else
    return _mm_or_si128(
        _mm_slli_epi32(val, 32-R), _mm_srli_epi32(val, R));
#endif
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline __m128i RotateLeft32<8>(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi32(val, 8);
#else
    const __m128i mask = _mm_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
    return _mm_shuffle_epi8(val, mask);
#endif
}

// Faster than two Shifts and an Or. Thanks to Louis Wingers and Bryan Weeks.
template <>
inline __m128i RotateRight32<8>(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi32(val, 32-8);
#else
    const __m128i mask = _mm_set_epi8(12,15,14,13, 8,11,10,9, 4,7,6,5, 0,3,2,1);
    return _mm_shuffle_epi8(val, mask);
#endif
}

template <unsigned int IDX>
inline __m128i UnpackXMM(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    // Should not be instantiated
    CRYPTOPP_UNUSED(a); CRYPTOPP_UNUSED(b);
    CRYPTOPP_UNUSED(c); CRYPTOPP_UNUSED(d);
    CRYPTOPP_ASSERT(0);
    return _mm_setzero_si128();
}

template <>
inline __m128i UnpackXMM<0>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpacklo_epi32(a, b);
    const __m128i r2 = _mm_unpacklo_epi32(c, d);
    return _mm_shuffle_epi8(_mm_unpacklo_epi64(r1, r2),
        _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
}

template <>
inline __m128i UnpackXMM<1>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpacklo_epi32(a, b);
    const __m128i r2 = _mm_unpacklo_epi32(c, d);
    return _mm_shuffle_epi8(_mm_unpackhi_epi64(r1, r2),
        _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
}

template <>
inline __m128i UnpackXMM<2>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpackhi_epi32(a, b);
    const __m128i r2 = _mm_unpackhi_epi32(c, d);
    return _mm_shuffle_epi8(_mm_unpacklo_epi64(r1, r2),
        _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
}

template <>
inline __m128i UnpackXMM<3>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    // The shuffle converts to and from little-endian for SSE. A specialized
    // CHAM implementation can avoid the shuffle by framing the data for
    // encryption, decryption and benchmarks. The library cannot take the
    // speed-up because of the byte oriented API.
    const __m128i r1 = _mm_unpackhi_epi32(a, b);
    const __m128i r2 = _mm_unpackhi_epi32(c, d);
    return _mm_shuffle_epi8(_mm_unpackhi_epi64(r1, r2),
        _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
}

template <unsigned int IDX>
inline __m128i UnpackXMM(const __m128i& v)
{
    // Should not be instantiated
    CRYPTOPP_UNUSED(v); CRYPTOPP_ASSERT(0);
    return _mm_setzero_si128();
}

template <>
inline __m128i UnpackXMM<0>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(0,1,2,3, 0,1,2,3, 0,1,2,3, 0,1,2,3));
}

template <>
inline __m128i UnpackXMM<1>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(4,5,6,7, 4,5,6,7, 4,5,6,7, 4,5,6,7));
}

template <>
inline __m128i UnpackXMM<2>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(8,9,10,11, 8,9,10,11, 8,9,10,11, 8,9,10,11));
}

template <>
inline __m128i UnpackXMM<3>(const __m128i& v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(12,13,14,15, 12,13,14,15, 12,13,14,15, 12,13,14,15));
}

template <unsigned int IDX>
inline __m128i RepackXMM(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    return UnpackXMM<IDX>(a, b, c, d);
}

template <unsigned int IDX>
inline __m128i RepackXMM(const __m128i& v)
{
    return UnpackXMM<IDX>(v);
}

inline void CHAM128_Enc_Block(__m128i &block0,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. UnpackXMM includes a
    // little-endian swap for SSE. Thanks to Peter Cordes for help
    // with packing and unpacking.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 B1 C1 D1][A2 B2 C2 D2] ...
    __m128i a = UnpackXMM<0>(block0);
    __m128i b = UnpackXMM<1>(block0);
    __m128i c = UnpackXMM<2>(block0);
    __m128i d = UnpackXMM<3>(block0);

    __m128i counter = _mm_set_epi32(0,0,0,0);
    __m128i increment = _mm_set_epi32(1,1,1,1);

    const unsigned int MASK = (rounds == 80 ? 7 : 15);
    for (int i=0; i<static_cast<int>(rounds); i+=4)
    {
        __m128i k, k1, k2, t1, t2;
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i+0) & MASK])));

        // Shuffle out two subkeys
        k1 = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));
        k2 = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));

        t1 = _mm_xor_si128(a, counter);
        t2 = _mm_xor_si128(RotateLeft32<1>(b), k1);
        a = RotateLeft32<8>(_mm_add_epi32(t1, t2));

        counter = _mm_add_epi32(counter, increment);

        t1 = _mm_xor_si128(b, counter);
        t2 = _mm_xor_si128(RotateLeft32<8>(c), k2);
        b = RotateLeft32<1>(_mm_add_epi32(t1, t2));

        counter = _mm_add_epi32(counter, increment);

        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i+2) & MASK])));

        // Shuffle out two subkeys
        k1 = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));
        k2 = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));

        t1 = _mm_xor_si128(c, counter);
        t2 = _mm_xor_si128(RotateLeft32<1>(d), k1);
        c = RotateLeft32<8>(_mm_add_epi32(t1, t2));

        counter = _mm_add_epi32(counter, increment);

        t1 = _mm_xor_si128(d, counter);
        t2 = _mm_xor_si128(RotateLeft32<8>(a), k2);
        d = RotateLeft32<1>(_mm_add_epi32(t1, t2));

        counter = _mm_add_epi32(counter, increment);
    }

    // [A1 B1 C1 D1][A2 B2 C2 D2] ... => [A1 A2 A3 A4][B1 B2 B3 B4] ...
    block0 = RepackXMM<0>(a,b,c,d);
}

inline void CHAM128_Dec_Block(__m128i &block0,
    const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. UnpackXMM includes a
    // little-endian swap for SSE. Thanks to Peter Cordes for help
    // with packing and unpacking.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 B1 C1 D1][A2 B2 C2 D2] ...
    __m128i a = UnpackXMM<0>(block0);
    __m128i b = UnpackXMM<1>(block0);
    __m128i c = UnpackXMM<2>(block0);
    __m128i d = UnpackXMM<3>(block0);

    __m128i counter = _mm_set_epi32(rounds-1,rounds-1,rounds-1,rounds-1);
    __m128i decrement = _mm_set_epi32(1,1,1,1);

    const unsigned int MASK = (rounds == 80 ? 7 : 15);
    for (int i = static_cast<int>(rounds)-1; i >= 0; i-=4)
    {
        __m128i k, k1, k2, t1, t2;
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i-1) & MASK])));

        // Shuffle out two subkeys
        k1 = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));
        k2 = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));

        // Odd round
        t1 = RotateRight32<1>(d);
        t2 = _mm_xor_si128(RotateLeft32<8>(a), k1);
        d = _mm_xor_si128(_mm_sub_epi32(t1, t2), counter);

        counter = _mm_sub_epi32(counter, decrement);

        // Even round
        t1 = RotateRight32<8>(c);
        t2 = _mm_xor_si128(RotateLeft32<1>(d), k2);
        c = _mm_xor_si128(_mm_sub_epi32(t1, t2), counter);

        counter = _mm_sub_epi32(counter, decrement);
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i-3) & MASK])));

        // Shuffle out two subkeys
        k1 = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));
        k2 = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));

        // Odd round
        t1 = RotateRight32<1>(b);
        t2 = _mm_xor_si128(RotateLeft32<8>(c), k1);
        b = _mm_xor_si128(_mm_sub_epi32(t1, t2), counter);

        counter = _mm_sub_epi32(counter, decrement);

        // Even round
        t1 = RotateRight32<8>(a);
        t2 = _mm_xor_si128(RotateLeft32<1>(b), k2);
        a = _mm_xor_si128(_mm_sub_epi32(t1, t2), counter);

        counter = _mm_sub_epi32(counter, decrement);
    }

    // [A1 B1 C1 D1][A2 B2 C2 D2] ... => [A1 A2 A3 A4][B1 B2 B3 B4] ...
    block0 = RepackXMM<0>(a,b,c,d);
}

inline void CHAM128_Enc_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. UnpackXMM includes a
    // little-endian swap for SSE. Thanks to Peter Cordes for help
    // with packing and unpacking.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 B1 C1 D1][A2 B2 C2 D2] ...
    __m128i a = UnpackXMM<0>(block0, block1, block2, block3);
    __m128i b = UnpackXMM<1>(block0, block1, block2, block3);
    __m128i c = UnpackXMM<2>(block0, block1, block2, block3);
    __m128i d = UnpackXMM<3>(block0, block1, block2, block3);

    __m128i counter = _mm_set_epi32(0,0,0,0);
    __m128i increment = _mm_set_epi32(1,1,1,1);

    const unsigned int MASK = (rounds == 80 ? 7 : 15);
    for (int i=0; i<static_cast<int>(rounds); i+=4)
    {
        __m128i k, k1, k2, t1, t2;
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i+0) & MASK])));

        // Shuffle out two subkeys
        k1 = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));
        k2 = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));

        t1 = _mm_xor_si128(a, counter);
        t2 = _mm_xor_si128(RotateLeft32<1>(b), k1);
        a = RotateLeft32<8>(_mm_add_epi32(t1, t2));

        counter = _mm_add_epi32(counter, increment);

        t1 = _mm_xor_si128(b, counter);
        t2 = _mm_xor_si128(RotateLeft32<8>(c), k2);
        b = RotateLeft32<1>(_mm_add_epi32(t1, t2));

        counter = _mm_add_epi32(counter, increment);
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i+2) & MASK])));

        // Shuffle out two subkeys
        k1 = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));
        k2 = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));

        t1 = _mm_xor_si128(c, counter);
        t2 = _mm_xor_si128(RotateLeft32<1>(d), k1);
        c = RotateLeft32<8>(_mm_add_epi32(t1, t2));

        counter = _mm_add_epi32(counter, increment);

        t1 = _mm_xor_si128(d, counter);
        t2 = _mm_xor_si128(RotateLeft32<8>(a), k2);
        d = RotateLeft32<1>(_mm_add_epi32(t1, t2));

        counter = _mm_add_epi32(counter, increment);
    }

    // [A1 B1 C1 D1][A2 B2 C2 D2] ... => [A1 A2 A3 A4][B1 B2 B3 B4] ...
    block0 = RepackXMM<0>(a,b,c,d);
    block1 = RepackXMM<1>(a,b,c,d);
    block2 = RepackXMM<2>(a,b,c,d);
    block3 = RepackXMM<3>(a,b,c,d);
}

inline void CHAM128_Dec_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys, unsigned int rounds)
{
    // Rearrange the data for vectorization. UnpackXMM includes a
    // little-endian swap for SSE. Thanks to Peter Cordes for help
    // with packing and unpacking.
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 B1 C1 D1][A2 B2 C2 D2] ...
    __m128i a = UnpackXMM<0>(block0, block1, block2, block3);
    __m128i b = UnpackXMM<1>(block0, block1, block2, block3);
    __m128i c = UnpackXMM<2>(block0, block1, block2, block3);
    __m128i d = UnpackXMM<3>(block0, block1, block2, block3);

    __m128i counter = _mm_set_epi32(rounds-1,rounds-1,rounds-1,rounds-1);
    __m128i decrement = _mm_set_epi32(1,1,1,1);

    const unsigned int MASK = (rounds == 80 ? 7 : 15);
    for (int i = static_cast<int>(rounds)-1; i >= 0; i-=4)
    {
        __m128i k, k1, k2, t1, t2;
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i-1) & MASK])));

        // Shuffle out two subkeys
        k1 = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));
        k2 = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));

        // Odd round
        t1 = RotateRight32<1>(d);
        t2 = _mm_xor_si128(RotateLeft32<8>(a), k1);
        d = _mm_xor_si128(_mm_sub_epi32(t1, t2), counter);

        counter = _mm_sub_epi32(counter, decrement);

        // Even round
        t1 = RotateRight32<8>(c);
        t2 = _mm_xor_si128(RotateLeft32<1>(d), k2);
        c = _mm_xor_si128(_mm_sub_epi32(t1, t2), counter);

        counter = _mm_sub_epi32(counter, decrement);
        k = _mm_castpd_si128(_mm_load_sd((const double*)(&subkeys[(i-3) & MASK])));

        // Shuffle out two subkeys
        k1 = _mm_shuffle_epi8(k, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));
        k2 = _mm_shuffle_epi8(k, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));

        // Odd round
        t1 = RotateRight32<1>(b);
        t2 = _mm_xor_si128(RotateLeft32<8>(c), k1);
        b = _mm_xor_si128(_mm_sub_epi32(t1, t2), counter);

        counter = _mm_sub_epi32(counter, decrement);

        // Even round
        t1 = RotateRight32<8>(a);
        t2 = _mm_xor_si128(RotateLeft32<1>(b), k2);
        a = _mm_xor_si128(_mm_sub_epi32(t1, t2), counter);

        counter = _mm_sub_epi32(counter, decrement);
    }

    // [A1 B1 C1 D1][A2 B2 C2 D2] ... => [A1 A2 A3 A4][B1 B2 B3 B4] ...
    block0 = RepackXMM<0>(a,b,c,d);
    block1 = RepackXMM<1>(a,b,c,d);
    block2 = RepackXMM<2>(a,b,c,d);
    block3 = RepackXMM<3>(a,b,c,d);
}

//////////////////////////////////////////////////////////////////////////

NAMESPACE_END  // W32

#endif  // CRYPTOPP_SSSE3_AVAILABLE

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_SSSE3_AVAILABLE)
size_t CHAM64_Enc_AdvancedProcessBlocks_SSSE3(const word16* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks64_2x1_SSE(W16::CHAM64_Enc_Block, W16::CHAM64_Enc_2_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t CHAM64_Dec_AdvancedProcessBlocks_SSSE3(const word16* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks64_2x1_SSE(W16::CHAM64_Dec_Block, W16::CHAM64_Dec_2_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t CHAM128_Enc_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_SSE(W32::CHAM128_Enc_Block, W32::CHAM128_Enc_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t CHAM128_Dec_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_SSE(W32::CHAM128_Dec_Block, W32::CHAM128_Dec_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif // CRYPTOPP_SSSE3_AVAILABLE

NAMESPACE_END
