// sm4_simd.cpp - written and placed in the public domain by
//                Markku-Juhani O. Saarinen and Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    AESNI, ARM NEON and ARMv8a, and Power7 Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.
//
//    AES-NI based on Markku-Juhani O. Saarinen work at https://github.com/mjosaarinen/sm4ni.
//
//    ARMv8 is upcoming.

#include "pch.h"
#include "config.h"

#include "sm4.h"
#include "misc.h"

// Uncomment for benchmarking C++ against SSE.
// Do so in both simon.cpp and simon_simd.cpp.
// #undef CRYPTOPP_AESNI_AVAILABLE

#if (CRYPTOPP_AESNI_AVAILABLE)
# include "adv_simd.h"
# include <emmintrin.h>
# include <tmmintrin.h>
# include <wmmintrin.h>
#endif

// Squash MS LNK4221 and libtool warnings
extern const char SM4_SIMD_FNAME[] = __FILE__;

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;

#if (CRYPTOPP_AESNI_AVAILABLE)

template <unsigned int R>
inline __m128i ShiftLeft(const __m128i& val)
{
    return _mm_slli_epi32(val, R);
}

template <unsigned int R>
inline __m128i ShiftRight(const __m128i& val)
{
    return _mm_srli_epi32(val, R);
}

template <unsigned int R>
inline __m128i ShiftLeft64(const __m128i& val)
{
    return _mm_slli_epi64(val, R);
}

template <unsigned int R>
inline __m128i ShiftRight64(const __m128i& val)
{
    return _mm_srli_epi64(val, R);
}

template <unsigned int R>
inline __m128i RotateLeft(const __m128i& val)
{
    return _mm_or_si128(
        _mm_slli_epi32(val, R), _mm_srli_epi32(val, 32-R));
}

template <unsigned int R>
inline __m128i RotateRight(const __m128i& val)
{
    return _mm_or_si128(
        _mm_slli_epi32(val, 32-R), _mm_srli_epi32(val, R));
}

template <>
inline __m128i RotateLeft<8>(const __m128i& val)
{
    const __m128i r08 = _mm_set_epi32(0x0E0D0C0F, 0x0A09080B, 0x06050407, 0x02010003);
    return _mm_shuffle_epi8(val, r08);
}

template <>
inline __m128i RotateLeft<16>(const __m128i& val)
{
    const __m128i mask = _mm_set_epi32(0x0D0C0F0E, 0x09080B0A, 0x05040706, 0x01000302);
    return _mm_shuffle_epi8(val, mask);
}

template <>
inline __m128i RotateLeft<24>(const __m128i& val)
{
    const __m128i mask = _mm_set_epi32(0x0C0F0E0D, 0x080B0A09, 0x04070605, 0x00030201);
    return _mm_shuffle_epi8(val, mask);
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
    return _mm_unpacklo_epi64(r1, r2);
}

template <>
inline __m128i UnpackXMM<1>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    const __m128i r1 = _mm_unpacklo_epi32(a, b);
    const __m128i r2 = _mm_unpacklo_epi32(c, d);
    return _mm_unpackhi_epi64(r1, r2);
}

template <>
inline __m128i UnpackXMM<2>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    const __m128i r1 = _mm_unpackhi_epi32(a, b);
    const __m128i r2 = _mm_unpackhi_epi32(c, d);
    return _mm_unpacklo_epi64(r1, r2);
}

template <>
inline __m128i UnpackXMM<3>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    const __m128i r1 = _mm_unpackhi_epi32(a, b);
    const __m128i r2 = _mm_unpackhi_epi32(c, d);
    return _mm_unpackhi_epi64(r1, r2);
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
    // Splat to all lanes
    return _mm_shuffle_epi8(v, _mm_set_epi8(3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0));
}

template <>
inline __m128i UnpackXMM<1>(const __m128i& v)
{
    // Splat to all lanes
    return _mm_shuffle_epi8(v, _mm_set_epi8(7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4));
}

template <>
inline __m128i UnpackXMM<2>(const __m128i& v)
{
    // Splat to all lanes
    return _mm_shuffle_epi8(v, _mm_set_epi8(11,10,9,8, 11,10,9,8, 11,10,9,8, 11,10,9,8));
}

template <>
inline __m128i UnpackXMM<3>(const __m128i& v)
{
    // Splat to all lanes
    return _mm_shuffle_epi8(v, _mm_set_epi8(15,14,13,12, 15,14,13,12, 15,14,13,12, 15,14,13,12));
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

inline void SM4_Encrypt(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys)
{
    // nibble mask
    const __m128i c0f = _mm_set_epi32(0x0F0F0F0F, 0x0F0F0F0F, 0x0F0F0F0F, 0x0F0F0F0F);

    // flip all bytes in all 32-bit words
    const __m128i flp = _mm_set_epi32(0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203);

    // inverse shift rows
    const __m128i shr = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);

    // Affine transform 1 (low and high hibbles)
    const __m128i m1l = _mm_set_epi32(0xC7C1B4B2, 0x22245157, 0x9197E2E4, 0x74720701);
    const __m128i m1h = _mm_set_epi32(0xF052B91B, 0xF95BB012, 0xE240AB09, 0xEB49A200);

    // Affine transform 2 (low and high hibbles)
    const __m128i m2l = _mm_set_epi32(0xEDD14478, 0x172BBE82, 0x5B67F2CE, 0xA19D0834);
    const __m128i m2h = _mm_set_epi32(0x11CDBE62, 0xCC1063BF, 0xAE7201DD, 0x73AFDC00);

    __m128i t0 = UnpackXMM<0>(block0, block1, block2, block3);
    __m128i t1 = UnpackXMM<1>(block0, block1, block2, block3);
    __m128i t2 = UnpackXMM<2>(block0, block1, block2, block3);
    __m128i t3 = UnpackXMM<3>(block0, block1, block2, block3);

    t0 = _mm_shuffle_epi8(t0, flp);
    t1 = _mm_shuffle_epi8(t1, flp);
    t2 = _mm_shuffle_epi8(t2, flp);
    t3 = _mm_shuffle_epi8(t3, flp);

    const unsigned int ROUNDS = 32;
    for (unsigned int i = 0; i < ROUNDS; i++)
    {
        const __m128i k = _mm_shuffle_epi32(_mm_castps_si128(
            _mm_load_ss((const float*)(subkeys+i))), _MM_SHUFFLE(0,0,0,0));

        __m128i x, y;
        x = _mm_xor_si128(t1, _mm_xor_si128(t2,    _mm_xor_si128(t3, k)));

        y = _mm_and_si128(x, c0f);          // inner affine
        y = _mm_shuffle_epi8(m1l, y);
        x = _mm_and_si128(ShiftRight64<4>(x), c0f);
        x = _mm_xor_si128(_mm_shuffle_epi8(m1h, x), y);

        x = _mm_shuffle_epi8(x, shr);       // inverse MixColumns
        x = _mm_aesenclast_si128(x, c0f);   // AESNI instruction

        y = _mm_andnot_si128(x, c0f);       // outer affine
        y = _mm_shuffle_epi8(m2l, y);
        x = _mm_and_si128(ShiftRight64<4>(x), c0f);
        x = _mm_xor_si128(_mm_shuffle_epi8(m2h, x), y);

        // 4 parallel L1 linear transforms
        y = _mm_xor_si128(x, RotateLeft<8>(x));
        y = _mm_xor_si128(y, RotateLeft<16>(x));
        y = _mm_xor_si128(ShiftLeft<2>(y), ShiftRight<30>(y));
        x = _mm_xor_si128(x, _mm_xor_si128(y, RotateLeft<24>(x)));

        // rotate registers
        x = _mm_xor_si128(x, t0);
        t0 = t1; t1 = t2;
        t2 = t3; t3 = x;
    }

    t0 = _mm_shuffle_epi8(t0, flp);
    t1 = _mm_shuffle_epi8(t1, flp);
    t2 = _mm_shuffle_epi8(t2, flp);
    t3 = _mm_shuffle_epi8(t3, flp);

    block0 = RepackXMM<0>(t3,t2,t1,t0);
    block1 = RepackXMM<1>(t3,t2,t1,t0);
    block2 = RepackXMM<2>(t3,t2,t1,t0);
    block3 = RepackXMM<3>(t3,t2,t1,t0);
}

inline void SM4_Enc_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys, unsigned int /*rounds*/)
{
    SM4_Encrypt(block0, block1, block2, block3, subkeys);
}

inline void SM4_Dec_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys, unsigned int /*rounds*/)
{
    SM4_Encrypt(block0, block1, block2, block3, subkeys);
}

inline void SM4_Enc_Block(__m128i &block0,
    const word32 *subkeys, unsigned int /*rounds*/)
{
    __m128i t1 = _mm_setzero_si128();
    __m128i t2 = _mm_setzero_si128();
    __m128i t3 = _mm_setzero_si128();

    SM4_Encrypt(block0, t1, t2, t3, subkeys);
}

inline void SM4_Dec_Block(__m128i &block0,
    const word32 *subkeys, unsigned int /*rounds*/)
{
    __m128i t1 = _mm_setzero_si128();
    __m128i t2 = _mm_setzero_si128();
    __m128i t3 = _mm_setzero_si128();

    SM4_Encrypt(block0, t1, t2, t3, subkeys);
}

#endif  // CRYPTOPP_AESNI_AVAILABLE

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_AESNI_AVAILABLE)
size_t SM4_Enc_AdvancedProcessBlocks_AESNI(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_SSE(SM4_Enc_Block, SM4_Enc_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif // CRYPTOPP_AESNI_AVAILABLE

NAMESPACE_END
