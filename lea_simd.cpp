// lea_simd.cpp - written and placed in the public domain by Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    SSSE3, ARM NEON and ARMv8a, and Power8 Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"

#include "lea.h"
#include "misc.h"

// Uncomment for benchmarking C++ against SSE or NEON.
// Do so in both simon.cpp and simon_simd.cpp.
// #undef CRYPTOPP_SSSE3_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_SSSE3_AVAILABLE)
# include "adv_simd.h"
# include <pmmintrin.h>
# include <tmmintrin.h>
#endif

#if defined(__XOP__)
# if defined(CRYPTOPP_GCC_COMPATIBLE)
#  include <x86intrin.h>
# endif
# include <ammintrin.h>
#endif  // XOP

#if (CRYPTOPP_ARM_NEON_HEADER)
# include "adv_simd.h"
# include <arm_neon.h>
#endif

#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

#if defined(_M_ARM64)
# include "adv_simd.h"
#endif

// Do not port this to POWER architecture. Naively we hoped
// for a 2x to 3x speedup. The result was a 5x slow down.
// The table below shows MiB/s and cpb.
//
// C++:
// <TD>LEA-128(128)/CTR (128-bit key)<TD>C++<TD>207<TD>15.64
// <TD>LEA-128(192)/CTR (192-bit key)<TD>C++<TD>186<TD>17.48
// <TD>LEA-128(256)/CTR (256-bit key)<TD>C++<TD>124<TD>26.2
//
// Power8:
// <TD>LEA-128(128)/CTR (128-bit key)<TD>Power8<TD>37<TD>88.7
// <TD>LEA-128(192)/CTR (192-bit key)<TD>Power8<TD>40<TD>82.1
// <TD>LEA-128(256)/CTR (256-bit key)<TD>Power8<TD>28<TD>116.0

#undef CRYPTOPP_POWER8_AVAILABLE
#if defined(CRYPTOPP_POWER8_AVAILABLE)
# include "adv_simd.h"
# include "ppc_simd.h"
#endif

// Squash MS LNK4221 and libtool warnings
extern const char LEA_SIMD_FNAME[] = __FILE__;

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;

// *************************** ARM NEON ***************************//

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

inline uint32x4_t Xor(const uint32x4_t& a, const uint32x4_t& b)
{
    return veorq_u32(a, b);
}

inline uint32x4_t Add(const uint32x4_t& a, const uint32x4_t& b)
{
    return vaddq_u32(a, b);
}

inline uint32x4_t Sub(const uint32x4_t& a, const uint32x4_t& b)
{
    return vsubq_u32(a, b);
}

template <unsigned int R>
inline uint32x4_t RotateLeft(const uint32x4_t& val)
{
    const uint32x4_t a(vshlq_n_u32(val, R));
    const uint32x4_t b(vshrq_n_u32(val, 32 - R));
    return vorrq_u32(a, b);
}

template <unsigned int R>
inline uint32x4_t RotateRight(const uint32x4_t& val)
{
    const uint32x4_t a(vshlq_n_u32(val, 32 - R));
    const uint32x4_t b(vshrq_n_u32(val, R));
    return vorrq_u32(a, b);
}

#if defined(__aarch32__) || defined(__aarch64__)
template <>
inline uint32x4_t RotateLeft<8>(const uint32x4_t& val)
{
#if (CRYPTOPP_BIG_ENDIAN)
    const uint8_t maskb[16] = { 14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3 };
    const uint8x16_t mask = vld1q_u8(maskb);
#else
    const uint8_t maskb[16] = { 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 };
    const uint8x16_t mask = vld1q_u8(maskb);
#endif

    return vreinterpretq_u32_u8(
        vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
}

template <>
inline uint32x4_t RotateRight<8>(const uint32x4_t& val)
{
#if (CRYPTOPP_BIG_ENDIAN)
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

uint32x4_t UnpackLow32(uint32x4_t a, uint32x4_t b)
{
    uint32x2_t a1 = vget_low_u32(a);
    uint32x2_t b1 = vget_low_u32(b);
    uint32x2x2_t result = vzip_u32(a1, b1);
    return vcombine_u32(result.val[0], result.val[1]);
}

uint32x4_t UnpackHigh32(uint32x4_t a, uint32x4_t b)
{
    uint32x2_t a1 = vget_high_u32(a);
    uint32x2_t b1 = vget_high_u32(b);
    uint32x2x2_t result = vzip_u32(a1, b1);
    return vcombine_u32(result.val[0], result.val[1]);
}

uint32x4_t UnpackLow64(uint32x4_t a, uint32x4_t b)
{
    uint64x1_t a1 = vget_low_u64((uint64x2_t)a);
    uint64x1_t b1 = vget_low_u64((uint64x2_t)b);
    return (uint32x4_t)vcombine_u64(a1, b1);
}

uint32x4_t UnpackHigh64(uint32x4_t a, uint32x4_t b)
{
    uint64x1_t a1 = vget_high_u64((uint64x2_t)a);
    uint64x1_t b1 = vget_high_u64((uint64x2_t)b);
    return (uint32x4_t)vcombine_u64(a1, b1);
}

template <unsigned int IDX>
inline uint32x4_t LoadKey(const word32 rkey[])
{
    return vdupq_n_u32(rkey[IDX]);
}

template <unsigned int IDX>
inline uint32x4_t UnpackNEON(const uint32x4_t& a, const uint32x4_t& b, const uint32x4_t& c, const uint32x4_t& d)
{
    // Should not be instantiated
    CRYPTOPP_ASSERT(0);

    CRYPTOPP_UNUSED(a); CRYPTOPP_UNUSED(b);
    CRYPTOPP_UNUSED(c); CRYPTOPP_UNUSED(d);
    return vmovq_n_u32(0);
}

template <>
inline uint32x4_t UnpackNEON<0>(const uint32x4_t& a, const uint32x4_t& b, const uint32x4_t& c, const uint32x4_t& d)
{
    const uint32x4_t r1 = UnpackLow32(a, b);
    const uint32x4_t r2 = UnpackLow32(c, d);
    return UnpackLow64(r1, r2);
}

template <>
inline uint32x4_t UnpackNEON<1>(const uint32x4_t& a, const uint32x4_t& b, const uint32x4_t& c, const uint32x4_t& d)
{
    const uint32x4_t r1 = UnpackLow32(a, b);
    const uint32x4_t r2 = UnpackLow32(c, d);
    return UnpackHigh64(r1, r2);
}

template <>
inline uint32x4_t UnpackNEON<2>(const uint32x4_t& a, const uint32x4_t& b, const uint32x4_t& c, const uint32x4_t& d)
{
    const uint32x4_t r1 = UnpackHigh32(a, b);
    const uint32x4_t r2 = UnpackHigh32(c, d);
    return UnpackLow64(r1, r2);
}

template <>
inline uint32x4_t UnpackNEON<3>(const uint32x4_t& a, const uint32x4_t& b, const uint32x4_t& c, const uint32x4_t& d)
{
    const uint32x4_t r1 = UnpackHigh32(a, b);
    const uint32x4_t r2 = UnpackHigh32(c, d);
    return UnpackHigh64(r1, r2);
}

template <unsigned int IDX>
inline uint32x4_t UnpackNEON(const uint32x4_t& v)
{
    // Should not be instantiated
    CRYPTOPP_ASSERT(0);

    CRYPTOPP_UNUSED(v);
    return vmovq_n_u32(0);
}

template <>
inline uint32x4_t UnpackNEON<0>(const uint32x4_t& v)
{
    // Splat to all lanes
    return vdupq_n_u32(vgetq_lane_u32(v, 0));
}

template <>
inline uint32x4_t UnpackNEON<1>(const uint32x4_t& v)
{
    // Splat to all lanes
    return vdupq_n_u32(vgetq_lane_u32(v, 1));
}

template <>
inline uint32x4_t UnpackNEON<2>(const uint32x4_t& v)
{
    // Splat to all lanes
    return vdupq_n_u32(vgetq_lane_u32(v, 2));
}

template <>
inline uint32x4_t UnpackNEON<3>(const uint32x4_t& v)
{
    // Splat to all lanes
    return vdupq_n_u32(vgetq_lane_u32(v, 3));
}

template <unsigned int IDX>
inline uint32x4_t RepackNEON(const uint32x4_t& a, const uint32x4_t& b, const uint32x4_t& c, const uint32x4_t& d)
{
    return UnpackNEON<IDX>(a, b, c, d);
}

template <unsigned int IDX>
inline uint32x4_t RepackNEON(const uint32x4_t& v)
{
    return UnpackNEON<IDX>(v);
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// *************************** IA-32 ***************************//

#if (CRYPTOPP_SSSE3_AVAILABLE)

inline __m128i Xor(const __m128i& a, const __m128i& b)
{
    return _mm_xor_si128(a, b);
}

inline __m128i Add(const __m128i& a, const __m128i& b)
{
    return _mm_add_epi32(a, b);
}

inline __m128i Sub(const __m128i& a, const __m128i& b)
{
    return _mm_sub_epi32(a, b);
}

template <unsigned int R>
inline __m128i RotateLeft(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi32(val, R);
#else
    return _mm_or_si128(
        _mm_slli_epi32(val, R), _mm_srli_epi32(val, 32-R));
#endif
}

template <unsigned int R>
inline __m128i RotateRight(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi32(val, 32-R);
#else
    return _mm_or_si128(
        _mm_slli_epi32(val, 32-R), _mm_srli_epi32(val, R));
#endif
}

// Faster than two Shifts and an Or.
template <>
inline __m128i RotateLeft<8>(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi32(val, 8);
#else
    const __m128i mask = _mm_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
    return _mm_shuffle_epi8(val, mask);
#endif
}

// Faster than two Shifts and an Or.
template <>
inline __m128i RotateRight<8>(const __m128i& val)
{
#if defined(__XOP__)
    return _mm_roti_epi32(val, 32-8);
#else
    const __m128i mask = _mm_set_epi8(12,15,14,13, 8,11,10,9, 4,7,6,5, 0,3,2,1);
    return _mm_shuffle_epi8(val, mask);
#endif
}

template <unsigned int IDX>
inline __m128i LoadKey(const word32 rkey[])
{
    float rk; std::memcpy(&rk, rkey+IDX, sizeof(rk));
    return _mm_castps_si128(_mm_load_ps1(&rk));
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
    // LEA is little-endian oriented, so there is no need for a separate shuffle.
    const __m128i r1 = _mm_unpacklo_epi32(a, b);
    const __m128i r2 = _mm_unpacklo_epi32(c, d);
    return _mm_unpacklo_epi64(r1, r2);
}

template <>
inline __m128i UnpackXMM<1>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    // LEA is little-endian oriented, so there is no need for a separate shuffle.
    const __m128i r1 = _mm_unpacklo_epi32(a, b);
    const __m128i r2 = _mm_unpacklo_epi32(c, d);
    return _mm_unpackhi_epi64(r1, r2);
}

template <>
inline __m128i UnpackXMM<2>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    // LEA is little-endian oriented, so there is no need for a separate shuffle.
    const __m128i r1 = _mm_unpackhi_epi32(a, b);
    const __m128i r2 = _mm_unpackhi_epi32(c, d);
    return _mm_unpacklo_epi64(r1, r2);
}

template <>
inline __m128i UnpackXMM<3>(const __m128i& a, const __m128i& b, const __m128i& c, const __m128i& d)
{
    // LEA is little-endian oriented, so there is no need for a separate shuffle.
    const __m128i r1 = _mm_unpackhi_epi32(a, b);
    const __m128i r2 = _mm_unpackhi_epi32(c, d);
    return _mm_unpackhi_epi64(r1, r2);
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

#endif  // CRYPTOPP_SSSE3_AVAILABLE

// *************************** Power8 ***************************//

#if (CRYPTOPP_POWER8_AVAILABLE)

using CryptoPP::uint8x16_p;
using CryptoPP::uint32x4_p;
using CryptoPP::uint64x2_p;

inline uint32x4_p Xor(const uint32x4_p& a, const uint32x4_p& b)
{
    return VecXor(a, b);
}

inline uint32x4_p Add(const uint32x4_p& a, const uint32x4_p& b)
{
    return VecAdd(a, b);
}

inline uint32x4_p Sub(const uint32x4_p& a, const uint32x4_p& b)
{
    return VecSub(a, b);
}

template <unsigned int R>
inline uint32x4_p RotateLeft(const uint32x4_p& val)
{
    const uint32x4_p m = {R, R, R, R};
    return vec_rl(val, m);
}

template <unsigned int R>
inline uint32x4_p RotateRight(const uint32x4_p& val)
{
    const uint32x4_p m = {32-R, 32-R, 32-R, 32-R};
    return vec_rl(val, m);
}

template <unsigned int IDX>
inline uint32x4_p LoadKey(const word32 rkey[])
{
    return vec_splats(rkey[IDX]);
}

template <unsigned int IDX>
inline uint32x4_p UnpackSIMD(const uint32x4_p& a, const uint32x4_p& b, const uint32x4_p& c, const uint32x4_p& d)
{
    // Should not be instantiated
    CRYPTOPP_UNUSED(a); CRYPTOPP_UNUSED(b);
    CRYPTOPP_UNUSED(c); CRYPTOPP_UNUSED(d);
    CRYPTOPP_ASSERT(0);
    return VecXor(a, a);
}

template <>
inline uint32x4_p UnpackSIMD<0>(const uint32x4_p& a, const uint32x4_p& b, const uint32x4_p& c, const uint32x4_p& d)
{
    const uint64x2_p r1 = (uint64x2_p)vec_mergel(a, b);
    const uint64x2_p r2 = (uint64x2_p)vec_mergel(c, d);
    return (uint32x4_p)vec_mergel(r1, r2);
}

template <>
inline uint32x4_p UnpackSIMD<1>(const uint32x4_p& a, const uint32x4_p& b, const uint32x4_p& c, const uint32x4_p& d)
{
    const uint64x2_p r1 = (uint64x2_p)vec_mergel(a, b);
    const uint64x2_p r2 = (uint64x2_p)vec_mergel(c, d);
    return (uint32x4_p)vec_mergeh(r1, r2);
}

template <>
inline uint32x4_p UnpackSIMD<2>(const uint32x4_p& a, const uint32x4_p& b, const uint32x4_p& c, const uint32x4_p& d)
{
    const uint64x2_p r1 = (uint64x2_p)vec_mergeh(a, b);
    const uint64x2_p r2 = (uint64x2_p)vec_mergeh(c, d);
    return (uint32x4_p)vec_mergel(r1, r2);
}

template <>
inline uint32x4_p UnpackSIMD<3>(const uint32x4_p& a, const uint32x4_p& b, const uint32x4_p& c, const uint32x4_p& d)
{
    const uint64x2_p r1 = (uint64x2_p)vec_mergeh(a, b);
    const uint64x2_p r2 = (uint64x2_p)vec_mergeh(c, d);
    return (uint32x4_p)vec_mergeh(r1, r2);
}

template <unsigned int IDX>
inline uint32x4_p UnpackSIMD(const uint32x4_p& v)
{
    // Should not be instantiated
    CRYPTOPP_ASSERT(0);
    return VecXor(v, v);
}

template <>
inline uint32x4_p UnpackSIMD<0>(const uint32x4_p& v)
{
    // Splat to all lanes
    const uint8x16_p m = {3,2,1,0, 3,2,1,0, 3,2,1,0, 3,2,1,0};
    return (uint32x4_p)VecPermute(v, v, m);
}

template <>
inline uint32x4_p UnpackSIMD<1>(const uint32x4_p& v)
{
    // Splat to all lanes
    const uint8x16_p m = {7,6,5,4, 7,6,5,4, 7,6,5,4, 7,6,5,4};
    return (uint32x4_p)VecPermute(v, v, m);
}

template <>
inline uint32x4_p UnpackSIMD<2>(const uint32x4_p& v)
{
    // Splat to all lanes
    const uint8x16_p m = {11,10,9,8, 11,10,9,8, 11,10,9,8, 11,10,9,8};
    return (uint32x4_p)VecPermute(v, v, m);
}

template <>
inline uint32x4_p UnpackSIMD<3>(const uint32x4_p& v)
{
    // Splat to all lanes
    const uint8x16_p m = {15,14,13,12, 15,14,13,12, 15,14,13,12, 15,14,13,12};
    return (uint32x4_p)VecPermute(v, v, m);
}

template <unsigned int IDX>
inline uint32x4_p RepackSIMD(const uint32x4_p& a, const uint32x4_p& b, const uint32x4_p& c, const uint32x4_p& d)
{
    return UnpackSIMD<IDX>(a, b, c, d);
}

template <unsigned int IDX>
inline uint32x4_p RepackSIMD(const uint32x4_p& v)
{
    return UnpackSIMD<IDX>(v);
}

#endif  // CRYPTOPP_POWER8_AVAILABLE

// *************************** LEA Encryption ***************************//

#if (CRYPTOPP_ARM_NEON_AVAILABLE || CRYPTOPP_SSSE3_AVAILABLE)

template <class W>
inline void LEA_Encryption(W temp[4], const word32 *subkeys, unsigned int rounds)
{
    temp[3] = RotateRight<3>(Add(Xor(temp[2], LoadKey<4>(subkeys)), Xor(temp[3], LoadKey<5>(subkeys))));
    temp[2] = RotateRight<5>(Add(Xor(temp[1], LoadKey<2>(subkeys)), Xor(temp[2], LoadKey<3>(subkeys))));
    temp[1] = RotateLeft<9>(Add(Xor(temp[0], LoadKey<0>(subkeys)), Xor(temp[1], LoadKey<1>(subkeys))));
    temp[0] = RotateRight<3>(Add(Xor(temp[3], LoadKey<10>(subkeys)), Xor(temp[0], LoadKey<11>(subkeys))));
    temp[3] = RotateRight<5>(Add(Xor(temp[2], LoadKey<8>(subkeys)), Xor(temp[3], LoadKey<9>(subkeys))));
    temp[2] = RotateLeft<9>(Add(Xor(temp[1], LoadKey<6>(subkeys)), Xor(temp[2], LoadKey<7>(subkeys))));
    temp[1] = RotateRight<3>(Add(Xor(temp[0], LoadKey<16>(subkeys)), Xor(temp[1], LoadKey<17>(subkeys))));
    temp[0] = RotateRight<5>(Add(Xor(temp[3], LoadKey<14>(subkeys)), Xor(temp[0], LoadKey<15>(subkeys))));
    temp[3] = RotateLeft<9>(Add(Xor(temp[2], LoadKey<12>(subkeys)), Xor(temp[3], LoadKey<13>(subkeys))));
    temp[2] = RotateRight<3>(Add(Xor(temp[1], LoadKey<22>(subkeys)), Xor(temp[2], LoadKey<23>(subkeys))));
    temp[1] = RotateRight<5>(Add(Xor(temp[0], LoadKey<20>(subkeys)), Xor(temp[1], LoadKey<21>(subkeys))));
    temp[0] = RotateLeft<9>(Add(Xor(temp[3], LoadKey<18>(subkeys)), Xor(temp[0], LoadKey<19>(subkeys))));

    temp[3] = RotateRight<3>(Add(Xor(temp[2], LoadKey<28>(subkeys)), Xor(temp[3], LoadKey<29>(subkeys))));
    temp[2] = RotateRight<5>(Add(Xor(temp[1], LoadKey<26>(subkeys)), Xor(temp[2], LoadKey<27>(subkeys))));
    temp[1] = RotateLeft<9>(Add(Xor(temp[0], LoadKey<24>(subkeys)), Xor(temp[1], LoadKey<25>(subkeys))));
    temp[0] = RotateRight<3>(Add(Xor(temp[3], LoadKey<34>(subkeys)), Xor(temp[0], LoadKey<35>(subkeys))));
    temp[3] = RotateRight<5>(Add(Xor(temp[2], LoadKey<32>(subkeys)), Xor(temp[3], LoadKey<33>(subkeys))));
    temp[2] = RotateLeft<9>(Add(Xor(temp[1], LoadKey<30>(subkeys)), Xor(temp[2], LoadKey<31>(subkeys))));
    temp[1] = RotateRight<3>(Add(Xor(temp[0], LoadKey<40>(subkeys)), Xor(temp[1], LoadKey<41>(subkeys))));
    temp[0] = RotateRight<5>(Add(Xor(temp[3], LoadKey<38>(subkeys)), Xor(temp[0], LoadKey<39>(subkeys))));
    temp[3] = RotateLeft<9>(Add(Xor(temp[2], LoadKey<36>(subkeys)), Xor(temp[3], LoadKey<37>(subkeys))));
    temp[2] = RotateRight<3>(Add(Xor(temp[1], LoadKey<46>(subkeys)), Xor(temp[2], LoadKey<47>(subkeys))));
    temp[1] = RotateRight<5>(Add(Xor(temp[0], LoadKey<44>(subkeys)), Xor(temp[1], LoadKey<45>(subkeys))));
    temp[0] = RotateLeft<9>(Add(Xor(temp[3], LoadKey<42>(subkeys)), Xor(temp[0], LoadKey<43>(subkeys))));

    temp[3] = RotateRight<3>(Add(Xor(temp[2], LoadKey<52>(subkeys)), Xor(temp[3], LoadKey<53>(subkeys))));
    temp[2] = RotateRight<5>(Add(Xor(temp[1], LoadKey<50>(subkeys)), Xor(temp[2], LoadKey<51>(subkeys))));
    temp[1] = RotateLeft<9>(Add(Xor(temp[0], LoadKey<48>(subkeys)), Xor(temp[1], LoadKey<49>(subkeys))));
    temp[0] = RotateRight<3>(Add(Xor(temp[3], LoadKey<58>(subkeys)), Xor(temp[0], LoadKey<59>(subkeys))));
    temp[3] = RotateRight<5>(Add(Xor(temp[2], LoadKey<56>(subkeys)), Xor(temp[3], LoadKey<57>(subkeys))));
    temp[2] = RotateLeft<9>(Add(Xor(temp[1], LoadKey<54>(subkeys)), Xor(temp[2], LoadKey<55>(subkeys))));
    temp[1] = RotateRight<3>(Add(Xor(temp[0], LoadKey<64>(subkeys)), Xor(temp[1], LoadKey<65>(subkeys))));
    temp[0] = RotateRight<5>(Add(Xor(temp[3], LoadKey<62>(subkeys)), Xor(temp[0], LoadKey<63>(subkeys))));
    temp[3] = RotateLeft<9>(Add(Xor(temp[2], LoadKey<60>(subkeys)), Xor(temp[3], LoadKey<61>(subkeys))));
    temp[2] = RotateRight<3>(Add(Xor(temp[1], LoadKey<70>(subkeys)), Xor(temp[2], LoadKey<71>(subkeys))));
    temp[1] = RotateRight<5>(Add(Xor(temp[0], LoadKey<68>(subkeys)), Xor(temp[1], LoadKey<69>(subkeys))));
    temp[0] = RotateLeft<9>(Add(Xor(temp[3], LoadKey<66>(subkeys)), Xor(temp[0], LoadKey<67>(subkeys))));

    temp[3] = RotateRight<3>(Add(Xor(temp[2], LoadKey<76>(subkeys)), Xor(temp[3], LoadKey<77>(subkeys))));
    temp[2] = RotateRight<5>(Add(Xor(temp[1], LoadKey<74>(subkeys)), Xor(temp[2], LoadKey<75>(subkeys))));
    temp[1] = RotateLeft<9>(Add(Xor(temp[0], LoadKey<72>(subkeys)), Xor(temp[1], LoadKey<73>(subkeys))));
    temp[0] = RotateRight<3>(Add(Xor(temp[3], LoadKey<82>(subkeys)), Xor(temp[0], LoadKey<83>(subkeys))));
    temp[3] = RotateRight<5>(Add(Xor(temp[2], LoadKey<80>(subkeys)), Xor(temp[3], LoadKey<81>(subkeys))));
    temp[2] = RotateLeft<9>(Add(Xor(temp[1], LoadKey<78>(subkeys)), Xor(temp[2], LoadKey<79>(subkeys))));
    temp[1] = RotateRight<3>(Add(Xor(temp[0], LoadKey<88>(subkeys)), Xor(temp[1], LoadKey<89>(subkeys))));
    temp[0] = RotateRight<5>(Add(Xor(temp[3], LoadKey<86>(subkeys)), Xor(temp[0], LoadKey<87>(subkeys))));
    temp[3] = RotateLeft<9>(Add(Xor(temp[2], LoadKey<84>(subkeys)), Xor(temp[3], LoadKey<85>(subkeys))));
    temp[2] = RotateRight<3>(Add(Xor(temp[1], LoadKey<94>(subkeys)), Xor(temp[2], LoadKey<95>(subkeys))));
    temp[1] = RotateRight<5>(Add(Xor(temp[0], LoadKey<92>(subkeys)), Xor(temp[1], LoadKey<93>(subkeys))));
    temp[0] = RotateLeft<9>(Add(Xor(temp[3], LoadKey<90>(subkeys)), Xor(temp[0], LoadKey<91>(subkeys))));

    temp[3] = RotateRight<3>(Add(Xor(temp[2], LoadKey<100>(subkeys)), Xor(temp[3], LoadKey<101>(subkeys))));
    temp[2] = RotateRight<5>(Add(Xor(temp[1], LoadKey<98>(subkeys)), Xor(temp[2], LoadKey<99>(subkeys))));
    temp[1] = RotateLeft<9>(Add(Xor(temp[0], LoadKey<96>(subkeys)), Xor(temp[1], LoadKey<97>(subkeys))));
    temp[0] = RotateRight<3>(Add(Xor(temp[3], LoadKey<106>(subkeys)), Xor(temp[0], LoadKey<107>(subkeys))));
    temp[3] = RotateRight<5>(Add(Xor(temp[2], LoadKey<104>(subkeys)), Xor(temp[3], LoadKey<105>(subkeys))));
    temp[2] = RotateLeft<9>(Add(Xor(temp[1], LoadKey<102>(subkeys)), Xor(temp[2], LoadKey<103>(subkeys))));
    temp[1] = RotateRight<3>(Add(Xor(temp[0], LoadKey<112>(subkeys)), Xor(temp[1], LoadKey<113>(subkeys))));
    temp[0] = RotateRight<5>(Add(Xor(temp[3], LoadKey<110>(subkeys)), Xor(temp[0], LoadKey<111>(subkeys))));
    temp[3] = RotateLeft<9>(Add(Xor(temp[2], LoadKey<108>(subkeys)), Xor(temp[3], LoadKey<109>(subkeys))));
    temp[2] = RotateRight<3>(Add(Xor(temp[1], LoadKey<118>(subkeys)), Xor(temp[2], LoadKey<119>(subkeys))));
    temp[1] = RotateRight<5>(Add(Xor(temp[0], LoadKey<116>(subkeys)), Xor(temp[1], LoadKey<117>(subkeys))));
    temp[0] = RotateLeft<9>(Add(Xor(temp[3], LoadKey<114>(subkeys)), Xor(temp[0], LoadKey<115>(subkeys))));

    temp[3] = RotateRight<3>(Add(Xor(temp[2], LoadKey<124>(subkeys)), Xor(temp[3], LoadKey<125>(subkeys))));
    temp[2] = RotateRight<5>(Add(Xor(temp[1], LoadKey<122>(subkeys)), Xor(temp[2], LoadKey<123>(subkeys))));
    temp[1] = RotateLeft<9>(Add(Xor(temp[0], LoadKey<120>(subkeys)), Xor(temp[1], LoadKey<121>(subkeys))));
    temp[0] = RotateRight<3>(Add(Xor(temp[3], LoadKey<130>(subkeys)), Xor(temp[0], LoadKey<131>(subkeys))));
    temp[3] = RotateRight<5>(Add(Xor(temp[2], LoadKey<128>(subkeys)), Xor(temp[3], LoadKey<129>(subkeys))));
    temp[2] = RotateLeft<9>(Add(Xor(temp[1], LoadKey<126>(subkeys)), Xor(temp[2], LoadKey<127>(subkeys))));
    temp[1] = RotateRight<3>(Add(Xor(temp[0], LoadKey<136>(subkeys)), Xor(temp[1], LoadKey<137>(subkeys))));
    temp[0] = RotateRight<5>(Add(Xor(temp[3], LoadKey<134>(subkeys)), Xor(temp[0], LoadKey<135>(subkeys))));
    temp[3] = RotateLeft<9>(Add(Xor(temp[2], LoadKey<132>(subkeys)), Xor(temp[3], LoadKey<133>(subkeys))));
    temp[2] = RotateRight<3>(Add(Xor(temp[1], LoadKey<142>(subkeys)), Xor(temp[2], LoadKey<143>(subkeys))));
    temp[1] = RotateRight<5>(Add(Xor(temp[0], LoadKey<140>(subkeys)), Xor(temp[1], LoadKey<141>(subkeys))));
    temp[0] = RotateLeft<9>(Add(Xor(temp[3], LoadKey<138>(subkeys)), Xor(temp[0], LoadKey<139>(subkeys))));

    if(rounds > 24)
    {
        temp[3] = RotateRight<3>(Add(Xor(temp[2], LoadKey<148>(subkeys)), Xor(temp[3], LoadKey<149>(subkeys))));
        temp[2] = RotateRight<5>(Add(Xor(temp[1], LoadKey<146>(subkeys)), Xor(temp[2], LoadKey<147>(subkeys))));
        temp[1] = RotateLeft<9>(Add(Xor(temp[0], LoadKey<144>(subkeys)), Xor(temp[1], LoadKey<145>(subkeys))));
        temp[0] = RotateRight<3>(Add(Xor(temp[3], LoadKey<154>(subkeys)), Xor(temp[0], LoadKey<155>(subkeys))));
        temp[3] = RotateRight<5>(Add(Xor(temp[2], LoadKey<152>(subkeys)), Xor(temp[3], LoadKey<153>(subkeys))));
        temp[2] = RotateLeft<9>(Add(Xor(temp[1], LoadKey<150>(subkeys)), Xor(temp[2], LoadKey<151>(subkeys))));
        temp[1] = RotateRight<3>(Add(Xor(temp[0], LoadKey<160>(subkeys)), Xor(temp[1], LoadKey<161>(subkeys))));
        temp[0] = RotateRight<5>(Add(Xor(temp[3], LoadKey<158>(subkeys)), Xor(temp[0], LoadKey<159>(subkeys))));
        temp[3] = RotateLeft<9>(Add(Xor(temp[2], LoadKey<156>(subkeys)), Xor(temp[3], LoadKey<157>(subkeys))));
        temp[2] = RotateRight<3>(Add(Xor(temp[1], LoadKey<166>(subkeys)), Xor(temp[2], LoadKey<167>(subkeys))));
        temp[1] = RotateRight<5>(Add(Xor(temp[0], LoadKey<164>(subkeys)), Xor(temp[1], LoadKey<165>(subkeys))));
        temp[0] = RotateLeft<9>(Add(Xor(temp[3], LoadKey<162>(subkeys)), Xor(temp[0], LoadKey<163>(subkeys))));
    }

    if(rounds > 28)
    {
        temp[3] = RotateRight<3>(Add(Xor(temp[2], LoadKey<172>(subkeys)), Xor(temp[3], LoadKey<173>(subkeys))));
        temp[2] = RotateRight<5>(Add(Xor(temp[1], LoadKey<170>(subkeys)), Xor(temp[2], LoadKey<171>(subkeys))));
        temp[1] = RotateLeft<9>(Add(Xor(temp[0], LoadKey<168>(subkeys)), Xor(temp[1], LoadKey<169>(subkeys))));
        temp[0] = RotateRight<3>(Add(Xor(temp[3], LoadKey<178>(subkeys)), Xor(temp[0], LoadKey<179>(subkeys))));
        temp[3] = RotateRight<5>(Add(Xor(temp[2], LoadKey<176>(subkeys)), Xor(temp[3], LoadKey<177>(subkeys))));
        temp[2] = RotateLeft<9>(Add(Xor(temp[1], LoadKey<174>(subkeys)), Xor(temp[2], LoadKey<175>(subkeys))));
        temp[1] = RotateRight<3>(Add(Xor(temp[0], LoadKey<184>(subkeys)), Xor(temp[1], LoadKey<185>(subkeys))));
        temp[0] = RotateRight<5>(Add(Xor(temp[3], LoadKey<182>(subkeys)), Xor(temp[0], LoadKey<183>(subkeys))));
        temp[3] = RotateLeft<9>(Add(Xor(temp[2], LoadKey<180>(subkeys)), Xor(temp[3], LoadKey<181>(subkeys))));
        temp[2] = RotateRight<3>(Add(Xor(temp[1], LoadKey<190>(subkeys)), Xor(temp[2], LoadKey<191>(subkeys))));
        temp[1] = RotateRight<5>(Add(Xor(temp[0], LoadKey<188>(subkeys)), Xor(temp[1], LoadKey<189>(subkeys))));
        temp[0] = RotateLeft<9>(Add(Xor(temp[3], LoadKey<186>(subkeys)), Xor(temp[0], LoadKey<187>(subkeys))));
    }
}

// *************************** LEA Decryption ***************************//

template <class W>
inline void LEA_Decryption(W temp[4], const word32 *subkeys, unsigned int rounds)
{
    if(rounds > 28)
    {
        temp[0] = Xor(Sub(RotateRight<9>(temp[0]), Xor(temp[3], LoadKey<186>(subkeys))), LoadKey<187>(subkeys));
        temp[1] = Xor(Sub(RotateLeft<5>(temp[1]), Xor(temp[0], LoadKey<188>(subkeys))), LoadKey<189>(subkeys));
        temp[2] = Xor(Sub(RotateLeft<3>(temp[2]), Xor(temp[1], LoadKey<190>(subkeys))), LoadKey<191>(subkeys));
        temp[3] = Xor(Sub(RotateRight<9>(temp[3]), Xor(temp[2], LoadKey<180>(subkeys))), LoadKey<181>(subkeys));
        temp[0] = Xor(Sub(RotateLeft<5>(temp[0]), Xor(temp[3], LoadKey<182>(subkeys))), LoadKey<183>(subkeys));
        temp[1] = Xor(Sub(RotateLeft<3>(temp[1]), Xor(temp[0], LoadKey<184>(subkeys))), LoadKey<185>(subkeys));
        temp[2] = Xor(Sub(RotateRight<9>(temp[2]), Xor(temp[1], LoadKey<174>(subkeys))), LoadKey<175>(subkeys));
        temp[3] = Xor(Sub(RotateLeft<5>(temp[3]), Xor(temp[2], LoadKey<176>(subkeys))), LoadKey<177>(subkeys));
        temp[0] = Xor(Sub(RotateLeft<3>(temp[0]), Xor(temp[3], LoadKey<178>(subkeys))), LoadKey<179>(subkeys));
        temp[1] = Xor(Sub(RotateRight<9>(temp[1]), Xor(temp[0], LoadKey<168>(subkeys))), LoadKey<169>(subkeys));
        temp[2] = Xor(Sub(RotateLeft<5>(temp[2]), Xor(temp[1], LoadKey<170>(subkeys))), LoadKey<171>(subkeys));
        temp[3] = Xor(Sub(RotateLeft<3>(temp[3]), Xor(temp[2], LoadKey<172>(subkeys))), LoadKey<173>(subkeys));
    }

    if(rounds > 24)
    {
        temp[0] = Xor(Sub(RotateRight<9>(temp[0]), Xor(temp[3], LoadKey<162>(subkeys))), LoadKey<163>(subkeys));
        temp[1] = Xor(Sub(RotateLeft<5>(temp[1]), Xor(temp[0], LoadKey<164>(subkeys))), LoadKey<165>(subkeys));
        temp[2] = Xor(Sub(RotateLeft<3>(temp[2]), Xor(temp[1], LoadKey<166>(subkeys))), LoadKey<167>(subkeys));
        temp[3] = Xor(Sub(RotateRight<9>(temp[3]), Xor(temp[2], LoadKey<156>(subkeys))), LoadKey<157>(subkeys));
        temp[0] = Xor(Sub(RotateLeft<5>(temp[0]), Xor(temp[3], LoadKey<158>(subkeys))), LoadKey<159>(subkeys));
        temp[1] = Xor(Sub(RotateLeft<3>(temp[1]), Xor(temp[0], LoadKey<160>(subkeys))), LoadKey<161>(subkeys));
        temp[2] = Xor(Sub(RotateRight<9>(temp[2]), Xor(temp[1], LoadKey<150>(subkeys))), LoadKey<151>(subkeys));
        temp[3] = Xor(Sub(RotateLeft<5>(temp[3]), Xor(temp[2], LoadKey<152>(subkeys))), LoadKey<153>(subkeys));
        temp[0] = Xor(Sub(RotateLeft<3>(temp[0]), Xor(temp[3], LoadKey<154>(subkeys))), LoadKey<155>(subkeys));
        temp[1] = Xor(Sub(RotateRight<9>(temp[1]), Xor(temp[0], LoadKey<144>(subkeys))), LoadKey<145>(subkeys));
        temp[2] = Xor(Sub(RotateLeft<5>(temp[2]), Xor(temp[1], LoadKey<146>(subkeys))), LoadKey<147>(subkeys));
        temp[3] = Xor(Sub(RotateLeft<3>(temp[3]), Xor(temp[2], LoadKey<148>(subkeys))), LoadKey<149>(subkeys));
    }

    temp[0] = Xor(Sub(RotateRight<9>(temp[0]), Xor(temp[3], LoadKey<138>(subkeys))), LoadKey<139>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<5>(temp[1]), Xor(temp[0], LoadKey<140>(subkeys))), LoadKey<141>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<3>(temp[2]), Xor(temp[1], LoadKey<142>(subkeys))), LoadKey<143>(subkeys));
    temp[3] = Xor(Sub(RotateRight<9>(temp[3]), Xor(temp[2], LoadKey<132>(subkeys))), LoadKey<133>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<5>(temp[0]), Xor(temp[3], LoadKey<134>(subkeys))), LoadKey<135>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<3>(temp[1]), Xor(temp[0], LoadKey<136>(subkeys))), LoadKey<137>(subkeys));
    temp[2] = Xor(Sub(RotateRight<9>(temp[2]), Xor(temp[1], LoadKey<126>(subkeys))), LoadKey<127>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<5>(temp[3]), Xor(temp[2], LoadKey<128>(subkeys))), LoadKey<129>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<3>(temp[0]), Xor(temp[3], LoadKey<130>(subkeys))), LoadKey<131>(subkeys));
    temp[1] = Xor(Sub(RotateRight<9>(temp[1]), Xor(temp[0], LoadKey<120>(subkeys))), LoadKey<121>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<5>(temp[2]), Xor(temp[1], LoadKey<122>(subkeys))), LoadKey<123>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<3>(temp[3]), Xor(temp[2], LoadKey<124>(subkeys))), LoadKey<125>(subkeys));

    temp[0] = Xor(Sub(RotateRight<9>(temp[0]), Xor(temp[3], LoadKey<114>(subkeys))), LoadKey<115>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<5>(temp[1]), Xor(temp[0], LoadKey<116>(subkeys))), LoadKey<117>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<3>(temp[2]), Xor(temp[1], LoadKey<118>(subkeys))), LoadKey<119>(subkeys));
    temp[3] = Xor(Sub(RotateRight<9>(temp[3]), Xor(temp[2], LoadKey<108>(subkeys))), LoadKey<109>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<5>(temp[0]), Xor(temp[3], LoadKey<110>(subkeys))), LoadKey<111>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<3>(temp[1]), Xor(temp[0], LoadKey<112>(subkeys))), LoadKey<113>(subkeys));
    temp[2] = Xor(Sub(RotateRight<9>(temp[2]), Xor(temp[1], LoadKey<102>(subkeys))), LoadKey<103>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<5>(temp[3]), Xor(temp[2], LoadKey<104>(subkeys))), LoadKey<105>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<3>(temp[0]), Xor(temp[3], LoadKey<106>(subkeys))), LoadKey<107>(subkeys));
    temp[1] = Xor(Sub(RotateRight<9>(temp[1]), Xor(temp[0], LoadKey<96>(subkeys))), LoadKey<97>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<5>(temp[2]), Xor(temp[1], LoadKey<98>(subkeys))), LoadKey<99>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<3>(temp[3]), Xor(temp[2], LoadKey<100>(subkeys))), LoadKey<101>(subkeys));

    temp[0] = Xor(Sub(RotateRight<9>(temp[0]), Xor(temp[3], LoadKey<90>(subkeys))), LoadKey<91>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<5>(temp[1]), Xor(temp[0], LoadKey<92>(subkeys))), LoadKey<93>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<3>(temp[2]), Xor(temp[1], LoadKey<94>(subkeys))), LoadKey<95>(subkeys));
    temp[3] = Xor(Sub(RotateRight<9>(temp[3]), Xor(temp[2], LoadKey<84>(subkeys))), LoadKey<85>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<5>(temp[0]), Xor(temp[3], LoadKey<86>(subkeys))), LoadKey<87>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<3>(temp[1]), Xor(temp[0], LoadKey<88>(subkeys))), LoadKey<89>(subkeys));
    temp[2] = Xor(Sub(RotateRight<9>(temp[2]), Xor(temp[1], LoadKey<78>(subkeys))), LoadKey<79>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<5>(temp[3]), Xor(temp[2], LoadKey<80>(subkeys))), LoadKey<81>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<3>(temp[0]), Xor(temp[3], LoadKey<82>(subkeys))), LoadKey<83>(subkeys));
    temp[1] = Xor(Sub(RotateRight<9>(temp[1]), Xor(temp[0], LoadKey<72>(subkeys))), LoadKey<73>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<5>(temp[2]), Xor(temp[1], LoadKey<74>(subkeys))), LoadKey<75>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<3>(temp[3]), Xor(temp[2], LoadKey<76>(subkeys))), LoadKey<77>(subkeys));

    temp[0] = Xor(Sub(RotateRight<9>(temp[0]), Xor(temp[3], LoadKey<66>(subkeys))), LoadKey<67>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<5>(temp[1]), Xor(temp[0], LoadKey<68>(subkeys))), LoadKey<69>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<3>(temp[2]), Xor(temp[1], LoadKey<70>(subkeys))), LoadKey<71>(subkeys));
    temp[3] = Xor(Sub(RotateRight<9>(temp[3]), Xor(temp[2], LoadKey<60>(subkeys))), LoadKey<61>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<5>(temp[0]), Xor(temp[3], LoadKey<62>(subkeys))), LoadKey<63>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<3>(temp[1]), Xor(temp[0], LoadKey<64>(subkeys))), LoadKey<65>(subkeys));
    temp[2] = Xor(Sub(RotateRight<9>(temp[2]), Xor(temp[1], LoadKey<54>(subkeys))), LoadKey<55>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<5>(temp[3]), Xor(temp[2], LoadKey<56>(subkeys))), LoadKey<57>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<3>(temp[0]), Xor(temp[3], LoadKey<58>(subkeys))), LoadKey<59>(subkeys));
    temp[1] = Xor(Sub(RotateRight<9>(temp[1]), Xor(temp[0], LoadKey<48>(subkeys))), LoadKey<49>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<5>(temp[2]), Xor(temp[1], LoadKey<50>(subkeys))), LoadKey<51>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<3>(temp[3]), Xor(temp[2], LoadKey<52>(subkeys))), LoadKey<53>(subkeys));

    temp[0] = Xor(Sub(RotateRight<9>(temp[0]), Xor(temp[3], LoadKey<42>(subkeys))), LoadKey<43>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<5>(temp[1]), Xor(temp[0], LoadKey<44>(subkeys))), LoadKey<45>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<3>(temp[2]), Xor(temp[1], LoadKey<46>(subkeys))), LoadKey<47>(subkeys));
    temp[3] = Xor(Sub(RotateRight<9>(temp[3]), Xor(temp[2], LoadKey<36>(subkeys))), LoadKey<37>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<5>(temp[0]), Xor(temp[3], LoadKey<38>(subkeys))), LoadKey<39>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<3>(temp[1]), Xor(temp[0], LoadKey<40>(subkeys))), LoadKey<41>(subkeys));
    temp[2] = Xor(Sub(RotateRight<9>(temp[2]), Xor(temp[1], LoadKey<30>(subkeys))), LoadKey<31>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<5>(temp[3]), Xor(temp[2], LoadKey<32>(subkeys))), LoadKey<33>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<3>(temp[0]), Xor(temp[3], LoadKey<34>(subkeys))), LoadKey<35>(subkeys));
    temp[1] = Xor(Sub(RotateRight<9>(temp[1]), Xor(temp[0], LoadKey<24>(subkeys))), LoadKey<25>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<5>(temp[2]), Xor(temp[1], LoadKey<26>(subkeys))), LoadKey<27>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<3>(temp[3]), Xor(temp[2], LoadKey<28>(subkeys))), LoadKey<29>(subkeys));

    temp[0] = Xor(Sub(RotateRight<9>(temp[0]), Xor(temp[3], LoadKey<18>(subkeys))), LoadKey<19>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<5>(temp[1]), Xor(temp[0], LoadKey<20>(subkeys))), LoadKey<21>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<3>(temp[2]), Xor(temp[1], LoadKey<22>(subkeys))), LoadKey<23>(subkeys));
    temp[3] = Xor(Sub(RotateRight<9>(temp[3]), Xor(temp[2], LoadKey<12>(subkeys))), LoadKey<13>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<5>(temp[0]), Xor(temp[3], LoadKey<14>(subkeys))), LoadKey<15>(subkeys));
    temp[1] = Xor(Sub(RotateLeft<3>(temp[1]), Xor(temp[0], LoadKey<16>(subkeys))), LoadKey<17>(subkeys));
    temp[2] = Xor(Sub(RotateRight<9>(temp[2]), Xor(temp[1], LoadKey<6>(subkeys))), LoadKey<7>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<5>(temp[3]), Xor(temp[2], LoadKey<8>(subkeys))), LoadKey<9>(subkeys));
    temp[0] = Xor(Sub(RotateLeft<3>(temp[0]), Xor(temp[3], LoadKey<10>(subkeys))), LoadKey<11>(subkeys));
    temp[1] = Xor(Sub(RotateRight<9>(temp[1]), Xor(temp[0], LoadKey<0>(subkeys))), LoadKey<1>(subkeys));
    temp[2] = Xor(Sub(RotateLeft<5>(temp[2]), Xor(temp[1], LoadKey<2>(subkeys))), LoadKey<3>(subkeys));
    temp[3] = Xor(Sub(RotateLeft<3>(temp[3]), Xor(temp[2], LoadKey<4>(subkeys))), LoadKey<5>(subkeys));
}

#endif  // LEA Encryption and Decryption

// *************************** ARM NEON ***************************//

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

inline void LEA_Enc_Block(uint32x4_t &block0,
    const word32 *subkeys, unsigned int rounds)
{
    uint32x4_t temp[4];
    temp[0] = UnpackNEON<0>(block0);
    temp[1] = UnpackNEON<1>(block0);
    temp[2] = UnpackNEON<2>(block0);
    temp[3] = UnpackNEON<3>(block0);

    LEA_Encryption(temp, subkeys, rounds);

    block0 = RepackNEON<0>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Dec_Block(uint32x4_t &block0,
    const word32 *subkeys, unsigned int rounds)
{
    uint32x4_t temp[4];
    temp[0] = UnpackNEON<0>(block0);
    temp[1] = UnpackNEON<1>(block0);
    temp[2] = UnpackNEON<2>(block0);
    temp[3] = UnpackNEON<3>(block0);

    LEA_Decryption(temp, subkeys, rounds);

    block0 = RepackNEON<0>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Enc_4_Blocks(uint32x4_t &block0, uint32x4_t &block1,
    uint32x4_t &block2, uint32x4_t &block3, const word32 *subkeys, unsigned int rounds)
{
    uint32x4_t temp[4];
    temp[0] = UnpackNEON<0>(block0, block1, block2, block3);
    temp[1] = UnpackNEON<1>(block0, block1, block2, block3);
    temp[2] = UnpackNEON<2>(block0, block1, block2, block3);
    temp[3] = UnpackNEON<3>(block0, block1, block2, block3);

    LEA_Encryption(temp, subkeys, rounds);

    block0 = RepackNEON<0>(temp[0], temp[1], temp[2], temp[3]);
    block1 = RepackNEON<1>(temp[0], temp[1], temp[2], temp[3]);
    block2 = RepackNEON<2>(temp[0], temp[1], temp[2], temp[3]);
    block3 = RepackNEON<3>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Dec_4_Blocks(uint32x4_t &block0, uint32x4_t &block1,
    uint32x4_t &block2, uint32x4_t &block3, const word32 *subkeys, unsigned int rounds)
{
    uint32x4_t temp[4];
    temp[0] = UnpackNEON<0>(block0, block1, block2, block3);
    temp[1] = UnpackNEON<1>(block0, block1, block2, block3);
    temp[2] = UnpackNEON<2>(block0, block1, block2, block3);
    temp[3] = UnpackNEON<3>(block0, block1, block2, block3);

    LEA_Decryption(temp, subkeys, rounds);

    block0 = RepackNEON<0>(temp[0], temp[1], temp[2], temp[3]);
    block1 = RepackNEON<1>(temp[0], temp[1], temp[2], temp[3]);
    block2 = RepackNEON<2>(temp[0], temp[1], temp[2], temp[3]);
    block3 = RepackNEON<3>(temp[0], temp[1], temp[2], temp[3]);
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// *************************** IA-32 ***************************//

#if (CRYPTOPP_SSSE3_AVAILABLE)

inline void LEA_Enc_Block(__m128i &block0,
    const word32 *subkeys, unsigned int rounds)
{
    __m128i temp[4];
    temp[0] = UnpackXMM<0>(block0);
    temp[1] = UnpackXMM<1>(block0);
    temp[2] = UnpackXMM<2>(block0);
    temp[3] = UnpackXMM<3>(block0);

    LEA_Encryption(temp, subkeys, rounds);

    block0 = RepackXMM<0>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Dec_Block(__m128i &block0,
    const word32 *subkeys, unsigned int rounds)
{
    __m128i temp[4];
    temp[0] = UnpackXMM<0>(block0);
    temp[1] = UnpackXMM<1>(block0);
    temp[2] = UnpackXMM<2>(block0);
    temp[3] = UnpackXMM<3>(block0);

    LEA_Decryption(temp, subkeys, rounds);

    block0 = RepackXMM<0>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Enc_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys, unsigned int rounds)
{
    __m128i temp[4];
    temp[0] = UnpackXMM<0>(block0, block1, block2, block3);
    temp[1] = UnpackXMM<1>(block0, block1, block2, block3);
    temp[2] = UnpackXMM<2>(block0, block1, block2, block3);
    temp[3] = UnpackXMM<3>(block0, block1, block2, block3);

    LEA_Encryption(temp, subkeys, rounds);

    block0 = RepackXMM<0>(temp[0], temp[1], temp[2], temp[3]);
    block1 = RepackXMM<1>(temp[0], temp[1], temp[2], temp[3]);
    block2 = RepackXMM<2>(temp[0], temp[1], temp[2], temp[3]);
    block3 = RepackXMM<3>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Dec_4_Blocks(__m128i &block0, __m128i &block1,
    __m128i &block2, __m128i &block3, const word32 *subkeys, unsigned int rounds)
{
    __m128i temp[4];
    temp[0] = UnpackXMM<0>(block0, block1, block2, block3);
    temp[1] = UnpackXMM<1>(block0, block1, block2, block3);
    temp[2] = UnpackXMM<2>(block0, block1, block2, block3);
    temp[3] = UnpackXMM<3>(block0, block1, block2, block3);

    LEA_Decryption(temp, subkeys, rounds);

    block0 = RepackXMM<0>(temp[0], temp[1], temp[2], temp[3]);
    block1 = RepackXMM<1>(temp[0], temp[1], temp[2], temp[3]);
    block2 = RepackXMM<2>(temp[0], temp[1], temp[2], temp[3]);
    block3 = RepackXMM<3>(temp[0], temp[1], temp[2], temp[3]);
}

#endif  // CRYPTOPP_SSSE3_AVAILABLE

// *************************** Power8 ***************************//

#if (CRYPTOPP_POWER8_AVAILABLE)

inline void LEA_Enc_Block(uint32x4_p &block0,
    const word32 *subkeys, unsigned int rounds)
{
    uint32x4_p temp[4];
    temp[0] = UnpackSIMD<0>(block0);
    temp[1] = UnpackSIMD<1>(block0);
    temp[2] = UnpackSIMD<2>(block0);
    temp[3] = UnpackSIMD<3>(block0);

    LEA_Encryption(temp, subkeys, rounds);

    block0 = RepackSIMD<0>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Dec_Block(uint32x4_p &block0,
    const word32 *subkeys, unsigned int rounds)
{
    uint32x4_p temp[4];
    temp[0] = UnpackSIMD<0>(block0);
    temp[1] = UnpackSIMD<1>(block0);
    temp[2] = UnpackSIMD<2>(block0);
    temp[3] = UnpackSIMD<3>(block0);

    LEA_Decryption(temp, subkeys, rounds);

    block0 = RepackSIMD<0>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Enc_4_Blocks(uint32x4_p &block0, uint32x4_p &block1,
    uint32x4_p &block2, uint32x4_p &block3, const word32 *subkeys, unsigned int rounds)
{
    uint32x4_p temp[4];
    temp[0] = UnpackSIMD<0>(block0, block1, block2, block3);
    temp[1] = UnpackSIMD<1>(block0, block1, block2, block3);
    temp[2] = UnpackSIMD<2>(block0, block1, block2, block3);
    temp[3] = UnpackSIMD<3>(block0, block1, block2, block3);

    LEA_Encryption(temp, subkeys, rounds);

    block0 = RepackSIMD<0>(temp[0], temp[1], temp[2], temp[3]);
    block1 = RepackSIMD<1>(temp[0], temp[1], temp[2], temp[3]);
    block2 = RepackSIMD<2>(temp[0], temp[1], temp[2], temp[3]);
    block3 = RepackSIMD<3>(temp[0], temp[1], temp[2], temp[3]);
}

inline void LEA_Dec_4_Blocks(uint32x4_p &block0, uint32x4_p &block1,
    uint32x4_p &block2, uint32x4_p &block3, const word32 *subkeys, unsigned int rounds)
{
    uint32x4_p temp[4];
    temp[0] = UnpackSIMD<0>(block0, block1, block2, block3);
    temp[1] = UnpackSIMD<1>(block0, block1, block2, block3);
    temp[2] = UnpackSIMD<2>(block0, block1, block2, block3);
    temp[3] = UnpackSIMD<3>(block0, block1, block2, block3);

    LEA_Decryption(temp, subkeys, rounds);

    block0 = RepackSIMD<0>(temp[0], temp[1], temp[2], temp[3]);
    block1 = RepackSIMD<1>(temp[0], temp[1], temp[2], temp[3]);
    block2 = RepackSIMD<2>(temp[0], temp[1], temp[2], temp[3]);
    block3 = RepackSIMD<3>(temp[0], temp[1], temp[2], temp[3]);
}

#endif  // CRYPTOPP_POWER8_AVAILABLE

ANONYMOUS_NAMESPACE_END

// *************************** SIMD Templates ***************************//

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_SSSE3_AVAILABLE)
size_t LEA_Enc_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_SSE(LEA_Enc_Block, LEA_Enc_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t LEA_Dec_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_SSE(LEA_Dec_Block, LEA_Dec_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif // CRYPTOPP_SSSE3_AVAILABLE

#if defined(CRYPTOPP_ARM_NEON_AVAILABLE)
size_t LEA_Enc_AdvancedProcessBlocks_NEON(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_NEON(LEA_Enc_Block, LEA_Enc_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t LEA_Dec_AdvancedProcessBlocks_NEON(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_NEON(LEA_Dec_Block, LEA_Dec_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif // CRYPTOPP_ARM_NEON_AVAILABLE

#if defined(CRYPTOPP_POWER8_AVAILABLE)
size_t LEA_Enc_AdvancedProcessBlocks_POWER8(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_ALTIVEC(LEA_Enc_Block, LEA_Enc_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t LEA_Dec_AdvancedProcessBlocks_POWER8(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_4x1_ALTIVEC(LEA_Dec_Block, LEA_Dec_4_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif // CRYPTOPP_POWER8_AVAILABLE

NAMESPACE_END
