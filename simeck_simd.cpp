// simeck_simd.cpp - written and placed in the public domain by Gangqiang Yang and Jeffrey Walton.
//
//    This source file uses intrinsics and built-ins to gain access to
//    SSSE3, ARM NEON and ARMv8a, and Power7 Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"

#include "simeck.h"
#include "misc.h"

// Uncomment for benchmarking C++ against SSE or NEON.
// Do so in both simon.cpp and simon-simd.cpp.
// #undef CRYPTOPP_SSSE3_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_SSSE3_AVAILABLE)
# include "adv_simd.h"
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
extern const char SIMECK_SIMD_FNAME[] = __FILE__;

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word16;
using CryptoPP::word32;

#if (CRYPTOPP_SSSE3_AVAILABLE)

//////////////////////////////////////////////////////////////////////////

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

/// \brief Unpack XMM words
/// \tparam IDX the element from each XMM word
/// \param a the first XMM word
/// \param b the second XMM word
/// \param c the third XMM word
/// \param d the fourth XMM word
/// \details UnpackXMM selects the IDX element from a, b, c, d and returns a concatenation
///   equivalent to <tt>a[IDX] || b[IDX] || c[IDX] || d[IDX]</tt>.
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
    const __m128i r1 = _mm_unpacklo_epi32(a, b);
    const __m128i r2 = _mm_unpacklo_epi32(c, d);
    return _mm_shuffle_epi8(_mm_unpacklo_epi64(r1, r2),
        _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
}

template <>
inline __m128i UnpackXMM<1>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    const __m128i r1 = _mm_unpacklo_epi32(a, b);
    const __m128i r2 = _mm_unpacklo_epi32(c, d);
    return _mm_shuffle_epi8(_mm_unpackhi_epi64(r1, r2),
        _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
}

template <>
inline __m128i UnpackXMM<2>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    const __m128i r1 = _mm_unpackhi_epi32(a, b);
    const __m128i r2 = _mm_unpackhi_epi32(c, d);
    return _mm_shuffle_epi8(_mm_unpacklo_epi64(r1, r2),
        _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
}

template <>
inline __m128i UnpackXMM<3>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    const __m128i r1 = _mm_unpackhi_epi32(a, b);
    const __m128i r2 = _mm_unpackhi_epi32(c, d);
    return _mm_shuffle_epi8(_mm_unpackhi_epi64(r1, r2),
        _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
}

/// \brief Unpack a XMM word
/// \tparam IDX the element from each XMM word
/// \param v the first XMM word
/// \details UnpackXMM selects the IDX element from v and returns a concatenation
///   equivalent to <tt>v[IDX] || v[IDX] || v[IDX] || v[IDX]</tt>.
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

inline void SIMECK64_Encrypt(__m128i &a, __m128i &b, __m128i &c, __m128i &d, const __m128i key)
{
    // SunStudio 12.3 workaround
    __m128i s, t; s = a; t = c;
    a = _mm_xor_si128(_mm_and_si128(a, RotateLeft32<5>(a)), RotateLeft32<1>(a));
    c = _mm_xor_si128(_mm_and_si128(c, RotateLeft32<5>(c)), RotateLeft32<1>(c));
    a = _mm_xor_si128(a, _mm_xor_si128(b, key));
    c = _mm_xor_si128(c, _mm_xor_si128(d, key));
    b = s; d = t;
}

inline void SIMECK64_Enc_Block(__m128i &block0, const word32 *subkeys, unsigned int /*rounds*/)
{
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 B1 C1 D1][A2 B2 C2 D2] ...
    __m128i a = UnpackXMM<0>(block0);
    __m128i b = UnpackXMM<1>(block0);
    __m128i c = UnpackXMM<2>(block0);
    __m128i d = UnpackXMM<3>(block0);

    const unsigned int rounds = 44;
    for (int i = 0; i < static_cast<int>(rounds); i += 4)
    {
        const __m128i key = _mm_loadu_si128((const __m128i*)(subkeys + i));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(0, 0, 0, 0)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(1, 1, 1, 1)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(2, 2, 2, 2)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(3, 3, 3, 3)));
    }

    // [A1 B1 C1 D1][A2 B2 C2 D2] ... => [A1 A2 A3 A4][B1 B2 B3 B4] ...
    block0 = RepackXMM<0>(a,b,c,d);
}

inline void SIMECK64_Dec_Block(__m128i &block0, const word32 *subkeys, unsigned int /*rounds*/)
{
    // SIMECK requires a word swap for the decryption transform
    __m128i w = _mm_shuffle_epi32(block0, _MM_SHUFFLE(2, 3, 0, 1));

    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 B1 C1 D1][A2 B2 C2 D2] ...
    __m128i a = UnpackXMM<0>(w);
    __m128i b = UnpackXMM<1>(w);
    __m128i c = UnpackXMM<2>(w);
    __m128i d = UnpackXMM<3>(w);

    const unsigned int rounds = 44;
    for (int i = static_cast<int>(rounds)-1; i >= 0; i -= 4)
    {
        const __m128i key = _mm_loadu_si128((const __m128i*)(subkeys + i - 3));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(3, 3, 3, 3)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(2, 2, 2, 2)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(1, 1, 1, 1)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(0, 0, 0, 0)));
    }

    // [A1 B1 C1 D1][A2 B2 C2 D2] ... => [A1 A2 A3 A4][B1 B2 B3 B4] ...
    w = RepackXMM<0>(a,b,c,d);

    block0 = _mm_shuffle_epi32(w, _MM_SHUFFLE(2, 3, 0, 1));
}

inline void SIMECK64_Enc_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys, unsigned int /*rounds*/)
{
    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 B1 C1 D1][A2 B2 C2 D2] ...
    __m128i a = UnpackXMM<0>(block0, block1, block2, block3);
    __m128i b = UnpackXMM<1>(block0, block1, block2, block3);
    __m128i c = UnpackXMM<2>(block0, block1, block2, block3);
    __m128i d = UnpackXMM<3>(block0, block1, block2, block3);

    const unsigned int rounds = 44;
    for (int i = 0; i < static_cast<int>(rounds); i += 4)
    {
        const __m128i key = _mm_loadu_si128((const __m128i*)(subkeys + i));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(0, 0, 0, 0)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(1, 1, 1, 1)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(2, 2, 2, 2)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(3, 3, 3, 3)));
    }

    // [A1 B1 C1 D1][A2 B2 C2 D2] ... => [A1 A2 A3 A4][B1 B2 B3 B4] ...
    block0 = RepackXMM<0>(a, b, c, d);
    block1 = RepackXMM<1>(a, b, c, d);
    block2 = RepackXMM<2>(a, b, c, d);
    block3 = RepackXMM<3>(a, b, c, d);
}

inline void SIMECK64_Dec_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys, unsigned int /*rounds*/)
{
    // SIMECK requires a word swap for the decryption transform
    __m128i w = _mm_shuffle_epi32(block0, _MM_SHUFFLE(2, 3, 0, 1));
    __m128i x = _mm_shuffle_epi32(block1, _MM_SHUFFLE(2, 3, 0, 1));
    __m128i y = _mm_shuffle_epi32(block2, _MM_SHUFFLE(2, 3, 0, 1));
    __m128i z = _mm_shuffle_epi32(block3, _MM_SHUFFLE(2, 3, 0, 1));

    // [A1 A2 A3 A4][B1 B2 B3 B4] ... => [A1 B1 C1 D1][A2 B2 C2 D2] ...
    __m128i a = UnpackXMM<0>(w, x, y, z);
    __m128i b = UnpackXMM<1>(w, x, y, z);
    __m128i c = UnpackXMM<2>(w, x, y, z);
    __m128i d = UnpackXMM<3>(w, x, y, z);

    const unsigned int rounds = 44;
    for (int i = static_cast<int>(rounds)-1; i >= 0; i -= 4)
    {
        const __m128i key = _mm_loadu_si128((const __m128i*)(subkeys + i - 3));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(3, 3, 3, 3)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(2, 2, 2, 2)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(1, 1, 1, 1)));
        SIMECK64_Encrypt(a, b, c, d, _mm_shuffle_epi32(key, _MM_SHUFFLE(0, 0, 0, 0)));
    }

    // [A1 B1 C1 D1][A2 B2 C2 D2] ... => [A1 A2 A3 A4][B1 B2 B3 B4] ...
    w = RepackXMM<0>(a, b, c, d);
    x = RepackXMM<1>(a, b, c, d);
    y = RepackXMM<2>(a, b, c, d);
    z = RepackXMM<3>(a, b, c, d);

    block0 = _mm_shuffle_epi32(w, _MM_SHUFFLE(2, 3, 0, 1));
    block1 = _mm_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
    block2 = _mm_shuffle_epi32(y, _MM_SHUFFLE(2, 3, 0, 1));
    block3 = _mm_shuffle_epi32(z, _MM_SHUFFLE(2, 3, 0, 1));
}

#endif  // CRYPTOPP_SSSE3_AVAILABLE

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_SSSE3_AVAILABLE)
size_t SIMECK64_Enc_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks64_4x1_SSE(SIMECK64_Enc_Block, SIMECK64_Enc_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SIMECK64_Dec_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks64_4x1_SSE(SIMECK64_Dec_Block, SIMECK64_Dec_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif // CRYPTOPP_SSSE3_AVAILABLE

NAMESPACE_END
