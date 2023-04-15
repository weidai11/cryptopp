// blake2_simd.cpp - written and placed in the public domain by
//                   Samuel Neves, Jeffrey Walton, Uri Blumenthal
//                   and Marcel Raad.
//
//    This source file uses intrinsics to gain access to ARMv7a/ARMv8a
//    NEON, Power8 and SSE4.1 instructions. A separate source file is
//    needed because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"
#include "blake2.h"

// Uncomment for benchmarking C++ against SSE2 or NEON.
// Do so in both blake2.cpp and blake2_simd.cpp.
// #undef CRYPTOPP_SSE41_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE
// #undef CRYPTOPP_ALTIVEC_AVAILABLE

// Disable NEON/ASIMD for Cortex-A53 and A57. The shifts are too slow and C/C++ is about
// 3 cpb faster than NEON/ASIMD. Also see http://github.com/weidai11/cryptopp/issues/367.
#if (defined(__aarch32__) || defined(__aarch64__)) && defined(CRYPTOPP_SLOW_ARMV8_SHIFT)
# undef CRYPTOPP_ARM_NEON_AVAILABLE
#endif

// BLAKE2s bug on AIX 7.1 (POWER7) with XLC 12.01
// https://github.com/weidai11/cryptopp/issues/743
#if defined(__xlC__) && (__xlC__ < 0x0d01)
# define CRYPTOPP_DISABLE_ALTIVEC 1
# undef CRYPTOPP_POWER8_AVAILABLE
# undef CRYPTOPP_ALTIVEC_AVAILABLE
#endif

#if defined(__XOP__)
# if defined(CRYPTOPP_GCC_COMPATIBLE)
#  include <x86intrin.h>
# endif
# include <ammintrin.h>
#endif  // XOP

#if (CRYPTOPP_SSE41_AVAILABLE)
# include <emmintrin.h>
# include <tmmintrin.h>
# include <smmintrin.h>
#endif

#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

#if (CRYPTOPP_POWER8_AVAILABLE)
# include "ppc_simd.h"
#endif

#if defined(CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE)
/* Ignore "warning: vec_lvsl is deprecated..." */
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

// Squash MS LNK4221 and libtool warnings
extern const char BLAKE2B_SIMD_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

// Exported by blake2.cpp
extern const word32 BLAKE2S_IV[8];
extern const word64 BLAKE2B_IV[8];

#if CRYPTOPP_SSE41_AVAILABLE

#define LOADU(p)  _mm_loadu_si128((const __m128i *)(const void*)(p))
#define STOREU(p,r) _mm_storeu_si128((__m128i *)(void*)(p), r)
#define TOF(reg) _mm_castsi128_ps((reg))
#define TOI(reg) _mm_castps_si128((reg))

void BLAKE2_Compress64_SSE4(const byte* input, BLAKE2b_State& state)
{
    #define BLAKE2B_LOAD_MSG_0_1(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m0, m1); \
    b1 = _mm_unpacklo_epi64(m2, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_0_2(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m0, m1); \
    b1 = _mm_unpackhi_epi64(m2, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_0_3(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m4, m5); \
    b1 = _mm_unpacklo_epi64(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_0_4(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m4, m5); \
    b1 = _mm_unpackhi_epi64(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_1_1(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m7, m2); \
    b1 = _mm_unpackhi_epi64(m4, m6); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_1_2(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m5, m4); \
    b1 = _mm_alignr_epi8(m3, m7, 8); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_1_3(b0, b1) \
    do { \
    b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1,0,3,2)); \
    b1 = _mm_unpackhi_epi64(m5, m2); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_1_4(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m6, m1); \
    b1 = _mm_unpackhi_epi64(m3, m1); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_2_1(b0, b1) \
    do { \
    b0 = _mm_alignr_epi8(m6, m5, 8); \
    b1 = _mm_unpackhi_epi64(m2, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_2_2(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m4, m0); \
    b1 = _mm_blend_epi16(m1, m6, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_2_3(b0, b1) \
    do { \
    b0 = _mm_blend_epi16(m5, m1, 0xF0); \
    b1 = _mm_unpackhi_epi64(m3, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_2_4(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m7, m3); \
    b1 = _mm_alignr_epi8(m2, m0, 8); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_3_1(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m3, m1); \
    b1 = _mm_unpackhi_epi64(m6, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_3_2(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m4, m0); \
    b1 = _mm_unpacklo_epi64(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_3_3(b0, b1) \
    do { \
    b0 = _mm_blend_epi16(m1, m2, 0xF0); \
    b1 = _mm_blend_epi16(m2, m7, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_3_4(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m3, m5); \
    b1 = _mm_unpacklo_epi64(m0, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_4_1(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m4, m2); \
    b1 = _mm_unpacklo_epi64(m1, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_4_2(b0, b1) \
    do { \
    b0 = _mm_blend_epi16(m0, m3, 0xF0); \
    b1 = _mm_blend_epi16(m2, m7, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_4_3(b0, b1) \
    do { \
    b0 = _mm_blend_epi16(m7, m5, 0xF0); \
    b1 = _mm_blend_epi16(m3, m1, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_4_4(b0, b1) \
    do { \
    b0 = _mm_alignr_epi8(m6, m0, 8); \
    b1 = _mm_blend_epi16(m4, m6, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_5_1(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m1, m3); \
    b1 = _mm_unpacklo_epi64(m0, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_5_2(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m6, m5); \
    b1 = _mm_unpackhi_epi64(m5, m1); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_5_3(b0, b1) \
    do { \
    b0 = _mm_blend_epi16(m2, m3, 0xF0); \
    b1 = _mm_unpackhi_epi64(m7, m0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_5_4(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m6, m2); \
    b1 = _mm_blend_epi16(m7, m4, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_6_1(b0, b1) \
    do { \
    b0 = _mm_blend_epi16(m6, m0, 0xF0); \
    b1 = _mm_unpacklo_epi64(m7, m2); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_6_2(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m2, m7); \
    b1 = _mm_alignr_epi8(m5, m6, 8); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_6_3(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m0, m3); \
    b1 = _mm_shuffle_epi32(m4, _MM_SHUFFLE(1,0,3,2)); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_6_4(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m3, m1); \
    b1 = _mm_blend_epi16(m1, m5, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_7_1(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m6, m3); \
    b1 = _mm_blend_epi16(m6, m1, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_7_2(b0, b1) \
    do { \
    b0 = _mm_alignr_epi8(m7, m5, 8); \
    b1 = _mm_unpackhi_epi64(m0, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_7_3(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m2, m7); \
    b1 = _mm_unpacklo_epi64(m4, m1); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_7_4(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m0, m2); \
    b1 = _mm_unpacklo_epi64(m3, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_8_1(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m3, m7); \
    b1 = _mm_alignr_epi8(m0, m5, 8); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_8_2(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m7, m4); \
    b1 = _mm_alignr_epi8(m4, m1, 8); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_8_3(b0, b1) \
    do { \
    b0 = m6; \
    b1 = _mm_alignr_epi8(m5, m0, 8); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_8_4(b0, b1) \
    do { \
    b0 = _mm_blend_epi16(m1, m3, 0xF0); \
    b1 = m2; \
    } while(0)

    #define BLAKE2B_LOAD_MSG_9_1(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m5, m4); \
    b1 = _mm_unpackhi_epi64(m3, m0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_9_2(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m1, m2); \
    b1 = _mm_blend_epi16(m3, m2, 0xF0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_9_3(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m7, m4); \
    b1 = _mm_unpackhi_epi64(m1, m6); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_9_4(b0, b1) \
    do { \
    b0 = _mm_alignr_epi8(m7, m5, 8); \
    b1 = _mm_unpacklo_epi64(m6, m0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_10_1(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m0, m1); \
    b1 = _mm_unpacklo_epi64(m2, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_10_2(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m0, m1); \
    b1 = _mm_unpackhi_epi64(m2, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_10_3(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m4, m5); \
    b1 = _mm_unpacklo_epi64(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_10_4(b0, b1) \
    do { \
    b0 = _mm_unpackhi_epi64(m4, m5); \
    b1 = _mm_unpackhi_epi64(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_11_1(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m7, m2); \
    b1 = _mm_unpackhi_epi64(m4, m6); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_11_2(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m5, m4); \
    b1 = _mm_alignr_epi8(m3, m7, 8); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_11_3(b0, b1) \
    do { \
    b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1,0,3,2)); \
    b1 = _mm_unpackhi_epi64(m5, m2); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_11_4(b0, b1) \
    do { \
    b0 = _mm_unpacklo_epi64(m6, m1); \
    b1 = _mm_unpackhi_epi64(m3, m1); \
    } while(0)

#ifdef __XOP__
# define MM_ROTI_EPI64(r, c) \
    _mm_roti_epi64(r, c)
#else
# define MM_ROTI_EPI64(x, c) \
      (-(c) == 32) ? _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))  \
    : (-(c) == 24) ? _mm_shuffle_epi8((x), r24) \
    : (-(c) == 16) ? _mm_shuffle_epi8((x), r16) \
    : (-(c) == 63) ? _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_add_epi64((x), (x)))  \
    : _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_slli_epi64((x), 64-(-(c))))
#endif

#define BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
    row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l); \
    row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h); \
    \
    row4l = _mm_xor_si128(row4l, row1l); \
    row4h = _mm_xor_si128(row4h, row1h); \
    \
    row4l = MM_ROTI_EPI64(row4l, -32); \
    row4h = MM_ROTI_EPI64(row4h, -32); \
    \
    row3l = _mm_add_epi64(row3l, row4l); \
    row3h = _mm_add_epi64(row3h, row4h); \
    \
    row2l = _mm_xor_si128(row2l, row3l); \
    row2h = _mm_xor_si128(row2h, row3h); \
    \
    row2l = MM_ROTI_EPI64(row2l, -24); \
    row2h = MM_ROTI_EPI64(row2h, -24);

#define BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
    row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l); \
    row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h); \
    \
    row4l = _mm_xor_si128(row4l, row1l); \
    row4h = _mm_xor_si128(row4h, row1h); \
    \
    row4l = MM_ROTI_EPI64(row4l, -16); \
    row4h = MM_ROTI_EPI64(row4h, -16); \
    \
    row3l = _mm_add_epi64(row3l, row4l); \
    row3h = _mm_add_epi64(row3h, row4h); \
    \
    row2l = _mm_xor_si128(row2l, row3l); \
    row2h = _mm_xor_si128(row2h, row3h); \
    \
    row2l = MM_ROTI_EPI64(row2l, -63); \
    row2h = MM_ROTI_EPI64(row2h, -63); \

#define BLAKE2B_DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
    t0 = row4l;\
    t1 = row2l;\
    row4l = row3l;\
    row3l = row3h;\
    row3h = row4l;\
    row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0)); \
    row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h)); \
    row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h)); \
    row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1))

#define BLAKE2B_UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
    t0 = row3l;\
    row3l = row3h;\
    row3h = t0;\
    t0 = row2l;\
    t1 = row4l;\
    row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l)); \
    row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h)); \
    row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h)); \
    row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1))

#define BLAKE2B_ROUND(r) \
    BLAKE2B_LOAD_MSG_ ##r ##_1(b0, b1); \
    BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    BLAKE2B_LOAD_MSG_ ##r ##_2(b0, b1); \
    BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    BLAKE2B_DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
    BLAKE2B_LOAD_MSG_ ##r ##_3(b0, b1); \
    BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    BLAKE2B_LOAD_MSG_ ##r ##_4(b0, b1); \
    BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    BLAKE2B_UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

    __m128i row1l, row1h;
    __m128i row2l, row2h;
    __m128i row3l, row3h;
    __m128i row4l, row4h;
    __m128i b0, b1;
    __m128i t0, t1;

    const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
    const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);

    const __m128i m0 = LOADU(input + 00);
    const __m128i m1 = LOADU(input + 16);
    const __m128i m2 = LOADU(input + 32);
    const __m128i m3 = LOADU(input + 48);
    const __m128i m4 = LOADU(input + 64);
    const __m128i m5 = LOADU(input + 80);
    const __m128i m6 = LOADU(input + 96);
    const __m128i m7 = LOADU(input + 112);

    row1l = LOADU(state.h()+0);
    row1h = LOADU(state.h()+2);
    row2l = LOADU(state.h()+4);
    row2h = LOADU(state.h()+6);
    row3l = LOADU(BLAKE2B_IV+0);
    row3h = LOADU(BLAKE2B_IV+2);
    row4l = _mm_xor_si128(LOADU(BLAKE2B_IV+4), LOADU(state.t()+0));
    row4h = _mm_xor_si128(LOADU(BLAKE2B_IV+6), LOADU(state.f()+0));

    BLAKE2B_ROUND(0);
    BLAKE2B_ROUND(1);
    BLAKE2B_ROUND(2);
    BLAKE2B_ROUND(3);
    BLAKE2B_ROUND(4);
    BLAKE2B_ROUND(5);
    BLAKE2B_ROUND(6);
    BLAKE2B_ROUND(7);
    BLAKE2B_ROUND(8);
    BLAKE2B_ROUND(9);
    BLAKE2B_ROUND(10);
    BLAKE2B_ROUND(11);

    row1l = _mm_xor_si128(row3l, row1l);
    row1h = _mm_xor_si128(row3h, row1h);
    STOREU(state.h()+0, _mm_xor_si128(LOADU(state.h()+0), row1l));
    STOREU(state.h()+2, _mm_xor_si128(LOADU(state.h()+2), row1h));
    row2l = _mm_xor_si128(row4l, row2l);
    row2h = _mm_xor_si128(row4h, row2h);
    STOREU(state.h()+4, _mm_xor_si128(LOADU(state.h()+4), row2l));
    STOREU(state.h()+6, _mm_xor_si128(LOADU(state.h()+6), row2h));
}
#endif  // CRYPTOPP_SSE41_AVAILABLE

#if CRYPTOPP_ARM_NEON_AVAILABLE
void BLAKE2_Compress64_NEON(const byte* input, BLAKE2b_State& state)
{
    #define BLAKE2B_LOAD_MSG_0_1(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m1)); b1 = vcombine_u64(vget_low_u64(m2), vget_low_u64(m3)); } while(0)

    #define BLAKE2B_LOAD_MSG_0_2(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m3)); } while(0)

    #define BLAKE2B_LOAD_MSG_0_3(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)

    #define BLAKE2B_LOAD_MSG_0_4(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m5)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m7)); } while(0)

    #define BLAKE2B_LOAD_MSG_1_1(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); b1 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m6)); } while(0)

    #define BLAKE2B_LOAD_MSG_1_2(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vextq_u64(m7, m3, 1); } while(0)

    #define BLAKE2B_LOAD_MSG_1_3(b0, b1) \
    do { b0 = vextq_u64(m0, m0, 1); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m2)); } while(0)

    #define BLAKE2B_LOAD_MSG_1_4(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); } while(0)

    #define BLAKE2B_LOAD_MSG_2_1(b0, b1) \
    do { b0 = vextq_u64(m5, m6, 1); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); } while(0)

    #define BLAKE2B_LOAD_MSG_2_2(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m0)); b1 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m6)); } while(0)

    #define BLAKE2B_LOAD_MSG_2_3(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m5), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m4)); } while(0)

    #define BLAKE2B_LOAD_MSG_2_4(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m3)); b1 = vextq_u64(m0, m2, 1); } while(0)

    #define BLAKE2B_LOAD_MSG_3_1(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m5)); } while(0)

    #define BLAKE2B_LOAD_MSG_3_2(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m0)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)

    #define BLAKE2B_LOAD_MSG_3_3(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m7)); } while(0)

    #define BLAKE2B_LOAD_MSG_3_4(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m4)); } while(0)

    #define BLAKE2B_LOAD_MSG_4_1(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m5)); } while(0)

    #define BLAKE2B_LOAD_MSG_4_2(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m0), vget_high_u64(m3)); b1 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m7)); } while(0)

    #define BLAKE2B_LOAD_MSG_4_3(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m7), vget_high_u64(m5)); b1 = vcombine_u64(vget_low_u64(m3), vget_high_u64(m1)); } while(0)

    #define BLAKE2B_LOAD_MSG_4_4(b0, b1) \
    do { b0 = vextq_u64(m0, m6, 1); b1 = vcombine_u64(vget_low_u64(m4), vget_high_u64(m6)); } while(0)

    #define BLAKE2B_LOAD_MSG_5_1(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m3)); b1 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m4)); } while(0)

    #define BLAKE2B_LOAD_MSG_5_2(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m5)); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m1)); } while(0)

    #define BLAKE2B_LOAD_MSG_5_3(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m3)); b1 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m0)); } while(0)

    #define BLAKE2B_LOAD_MSG_5_4(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m7), vget_high_u64(m4)); } while(0)

    #define BLAKE2B_LOAD_MSG_6_1(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m6), vget_high_u64(m0)); b1 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); } while(0)

    #define BLAKE2B_LOAD_MSG_6_2(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); b1 = vextq_u64(m6, m5, 1); } while(0)

    #define BLAKE2B_LOAD_MSG_6_3(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m3)); b1 = vextq_u64(m4, m4, 1); } while(0)

    #define BLAKE2B_LOAD_MSG_6_4(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); b1 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m5)); } while(0)

    #define BLAKE2B_LOAD_MSG_7_1(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m3)); b1 = vcombine_u64(vget_low_u64(m6), vget_high_u64(m1)); } while(0)

    #define BLAKE2B_LOAD_MSG_7_2(b0, b1) \
    do { b0 = vextq_u64(m5, m7, 1); b1 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m4)); } while(0)

    #define BLAKE2B_LOAD_MSG_7_3(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); b1 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m1)); } while(0)

    #define BLAKE2B_LOAD_MSG_7_4(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m2)); b1 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)); } while(0)

    #define BLAKE2B_LOAD_MSG_8_1(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m7)); b1 = vextq_u64(m5, m0, 1); } while(0)

    #define BLAKE2B_LOAD_MSG_8_2(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)); b1 = vextq_u64(m1, m4, 1); } while(0)

    #define BLAKE2B_LOAD_MSG_8_3(b0, b1) \
    do { b0 = m6; b1 = vextq_u64(m0, m5, 1); } while(0)

    #define BLAKE2B_LOAD_MSG_8_4(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m3)); b1 = m2; } while(0)

    #define BLAKE2B_LOAD_MSG_9_1(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m0)); } while(0)

    #define BLAKE2B_LOAD_MSG_9_2(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m2)); b1 = vcombine_u64(vget_low_u64(m3), vget_high_u64(m2)); } while(0)

    #define BLAKE2B_LOAD_MSG_9_3(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)); b1 = vcombine_u64(vget_high_u64(m1), vget_high_u64(m6)); } while(0)

    #define BLAKE2B_LOAD_MSG_9_4(b0, b1) \
    do { b0 = vextq_u64(m5, m7, 1); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m0)); } while(0)

    #define BLAKE2B_LOAD_MSG_10_1(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m1)); b1 = vcombine_u64(vget_low_u64(m2), vget_low_u64(m3)); } while(0)

    #define BLAKE2B_LOAD_MSG_10_2(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m3)); } while(0)

    #define BLAKE2B_LOAD_MSG_10_3(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)

    #define BLAKE2B_LOAD_MSG_10_4(b0, b1) \
    do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m5)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m7)); } while(0)

    #define BLAKE2B_LOAD_MSG_11_1(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); b1 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m6)); } while(0)

    #define BLAKE2B_LOAD_MSG_11_2(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vextq_u64(m7, m3, 1); } while(0)

    #define BLAKE2B_LOAD_MSG_11_3(b0, b1) \
    do { b0 = vextq_u64(m0, m0, 1); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m2)); } while(0)

    #define BLAKE2B_LOAD_MSG_11_4(b0, b1) \
    do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); } while(0)

    #define vrorq_n_u64_32(x) vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64((x))))

    #define vrorq_n_u64_24(x) vcombine_u64( \
        vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 3)), \
        vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 3)))

    #define vrorq_n_u64_16(x) vcombine_u64( \
        vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 2)), \
        vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 2)))

    #define vrorq_n_u64_63(x) veorq_u64(vaddq_u64(x, x), vshrq_n_u64(x, 63))

    #define BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
    do { \
      row1l = vaddq_u64(vaddq_u64(row1l, b0), row2l); \
      row1h = vaddq_u64(vaddq_u64(row1h, b1), row2h); \
      row4l = veorq_u64(row4l, row1l); row4h = veorq_u64(row4h, row1h); \
      row4l = vrorq_n_u64_32(row4l); row4h = vrorq_n_u64_32(row4h); \
      row3l = vaddq_u64(row3l, row4l); row3h = vaddq_u64(row3h, row4h); \
      row2l = veorq_u64(row2l, row3l); row2h = veorq_u64(row2h, row3h); \
      row2l = vrorq_n_u64_24(row2l); row2h = vrorq_n_u64_24(row2h); \
    } while(0)

    #define BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
    do { \
      row1l = vaddq_u64(vaddq_u64(row1l, b0), row2l); \
      row1h = vaddq_u64(vaddq_u64(row1h, b1), row2h); \
      row4l = veorq_u64(row4l, row1l); row4h = veorq_u64(row4h, row1h); \
      row4l = vrorq_n_u64_16(row4l); row4h = vrorq_n_u64_16(row4h); \
      row3l = vaddq_u64(row3l, row4l); row3h = vaddq_u64(row3h, row4h); \
      row2l = veorq_u64(row2l, row3l); row2h = veorq_u64(row2h, row3h); \
      row2l = vrorq_n_u64_63(row2l); row2h = vrorq_n_u64_63(row2h); \
    } while(0)

    #define BLAKE2B_DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
    do { \
      uint64x2_t t0 = vextq_u64(row2l, row2h, 1); \
      uint64x2_t t1 = vextq_u64(row2h, row2l, 1); \
      row2l = t0; row2h = t1; t0 = row3l;  row3l = row3h; row3h = t0; \
      t0 = vextq_u64(row4h, row4l, 1); t1 = vextq_u64(row4l, row4h, 1); \
      row4l = t0; row4h = t1; \
    } while(0)

    #define BLAKE2B_UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
    do { \
      uint64x2_t t0 = vextq_u64(row2h, row2l, 1); \
      uint64x2_t t1 = vextq_u64(row2l, row2h, 1); \
      row2l = t0; row2h = t1; t0 = row3l; row3l = row3h; row3h = t0; \
      t0 = vextq_u64(row4l, row4h, 1); t1 = vextq_u64(row4h, row4l, 1); \
      row4l = t0; row4h = t1; \
    } while(0)

    #define BLAKE2B_ROUND(r) \
    do { \
      uint64x2_t b0, b1; \
      BLAKE2B_LOAD_MSG_ ##r ##_1(b0, b1); \
      BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
      BLAKE2B_LOAD_MSG_ ##r ##_2(b0, b1); \
      BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
      BLAKE2B_DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
      BLAKE2B_LOAD_MSG_ ##r ##_3(b0, b1); \
      BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
      BLAKE2B_LOAD_MSG_ ##r ##_4(b0, b1); \
      BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
      BLAKE2B_UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
    } while(0)

    const uint64x2_t m0 = vreinterpretq_u64_u8(vld1q_u8(input +  00));
    const uint64x2_t m1 = vreinterpretq_u64_u8(vld1q_u8(input +  16));
    const uint64x2_t m2 = vreinterpretq_u64_u8(vld1q_u8(input +  32));
    const uint64x2_t m3 = vreinterpretq_u64_u8(vld1q_u8(input +  48));
    const uint64x2_t m4 = vreinterpretq_u64_u8(vld1q_u8(input +  64));
    const uint64x2_t m5 = vreinterpretq_u64_u8(vld1q_u8(input +  80));
    const uint64x2_t m6 = vreinterpretq_u64_u8(vld1q_u8(input +  96));
    const uint64x2_t m7 = vreinterpretq_u64_u8(vld1q_u8(input + 112));

    uint64x2_t row1l, row1h, row2l, row2h;
    uint64x2_t row3l, row3h, row4l, row4h;

    const uint64x2_t h0 = row1l = vld1q_u64(state.h()+0);
    const uint64x2_t h1 = row1h = vld1q_u64(state.h()+2);
    const uint64x2_t h2 = row2l = vld1q_u64(state.h()+4);
    const uint64x2_t h3 = row2h = vld1q_u64(state.h()+6);

    row3l = vld1q_u64(BLAKE2B_IV+0);
    row3h = vld1q_u64(BLAKE2B_IV+2);
    row4l = veorq_u64(vld1q_u64(BLAKE2B_IV+4), vld1q_u64(state.t()+0));
    row4h = veorq_u64(vld1q_u64(BLAKE2B_IV+6), vld1q_u64(state.f()+0));

    BLAKE2B_ROUND(0);
    BLAKE2B_ROUND(1);
    BLAKE2B_ROUND(2);
    BLAKE2B_ROUND(3);
    BLAKE2B_ROUND(4);
    BLAKE2B_ROUND(5);
    BLAKE2B_ROUND(6);
    BLAKE2B_ROUND(7);
    BLAKE2B_ROUND(8);
    BLAKE2B_ROUND(9);
    BLAKE2B_ROUND(10);
    BLAKE2B_ROUND(11);

    vst1q_u64(state.h()+0, veorq_u64(h0, veorq_u64(row1l, row3l)));
    vst1q_u64(state.h()+2, veorq_u64(h1, veorq_u64(row1h, row3h)));
    vst1q_u64(state.h()+4, veorq_u64(h2, veorq_u64(row2l, row4l)));
    vst1q_u64(state.h()+6, veorq_u64(h3, veorq_u64(row2h, row4h)));
}
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_POWER8_AVAILABLE)

inline uint64x2_p VecLoad64(const void* p)
{
    return (uint64x2_p)vec_xl(0, CONST_V32_CAST(p));
}

inline uint64x2_p VecLoad64LE(const void* p, const uint8x16_p le_mask)
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    const uint32x4_p v = vec_xl(0, CONST_V32_CAST(p));
    return (uint64x2_p)VecPermute(v, v, le_mask);
#else
    CRYPTOPP_UNUSED(le_mask);
    return (uint64x2_p)vec_xl(0, CONST_V32_CAST(p));
#endif
}

inline void VecStore64(void* p, const uint64x2_p x)
{
    vec_xst((uint32x4_p)x, 0, NCONST_V32_CAST(p));
}

inline void VecStore64LE(void* p, const uint64x2_p x, const uint8x16_p le_mask)
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    const uint64x2_p v = VecPermute(x, x, le_mask);
    vec_xst((uint32x4_p)v, 0, NCONST_V32_CAST(p));
#else
    CRYPTOPP_UNUSED(le_mask);
    vec_xst((uint32x4_p)x, 0, NCONST_V32_CAST(p));
#endif
}

#if defined(CRYPTOPP_BIG_ENDIAN)
#define vec_shl_8(a,b) (uint64x2_p)vec_sld((uint8x16_p)a,(uint8x16_p)b,8)
#else
#define vec_shl_8(a,b) (uint64x2_p)vec_sld((uint8x16_p)b,(uint8x16_p)a,8)
#endif

#define vec_merge_hi(a, b) vec_mergeh(a,b)
#define vec_merge_hi_lo(a, b) vec_mergeh(a,(uint64x2_p)vec_sld((uint8x16_p)b,(uint8x16_p)b,8))
#define vec_merge_lo(a, b) vec_mergel(a,b)

void BLAKE2_Compress64_POWER8(const byte* input, BLAKE2b_State& state)
{
    #define BLAKE2B_LOAD_MSG_0_1(b0, b1) \
    do { \
         b0 = vec_merge_hi(m0, m1); \
         b1 = vec_merge_hi(m2, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_0_2(b0, b1) \
    do { \
         b0 = vec_merge_lo(m0, m1); \
         b1 = vec_merge_lo(m2, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_0_3(b0, b1) \
    do { \
         b0 = vec_merge_hi(m4, m5); \
         b1 = vec_merge_hi(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_0_4(b0, b1) \
    do { \
         b0 = vec_merge_lo(m4, m5); \
         b1 = vec_merge_lo(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_1_1(b0, b1) \
    do { \
         b0 = vec_merge_hi(m7, m2); \
         b1 = vec_merge_lo(m4, m6); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_1_2(b0, b1) \
    do { \
         b0 = vec_merge_hi(m5, m4); \
         b1 = vec_shl_8(m7, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_1_3(b0, b1) \
    do { \
         b0 = vec_shl_8(m0, m0); \
         b1 = vec_merge_lo(m5, m2); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_1_4(b0, b1) \
    do { \
         b0 = vec_merge_hi(m6, m1); \
         b1 = vec_merge_lo(m3, m1); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_2_1(b0, b1) \
    do { \
         b0 = vec_shl_8(m5, m6); \
         b1 = vec_merge_lo(m2, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_2_2(b0, b1) \
    do { \
         b0 = vec_merge_hi(m4, m0); \
         b1 = vec_merge_hi_lo(m1, m6); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_2_3(b0, b1) \
       do { \
         b0 = vec_merge_hi_lo(m5, m1); \
         b1 = vec_merge_lo(m3, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_2_4(b0, b1) \
       do { \
         b0 = vec_merge_hi(m7, m3); \
         b1 = vec_shl_8(m0, m2); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_3_1(b0, b1) \
       do { \
         b0 = vec_merge_lo(m3, m1); \
         b1 = vec_merge_lo(m6, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_3_2(b0, b1) \
       do { \
         b0 = vec_merge_lo(m4, m0); \
         b1 = vec_merge_hi(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_3_3(b0, b1) \
       do { \
         b0 = vec_merge_hi_lo(m1, m2); \
         b1 = vec_merge_hi_lo(m2, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_3_4(b0, b1) \
       do { \
         b0 = vec_merge_hi(m3, m5); \
         b1 = vec_merge_hi(m0, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_4_1(b0, b1) \
       do { \
         b0 = vec_merge_lo(m4, m2); \
         b1 = vec_merge_hi(m1, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_4_2(b0, b1) \
       do { \
         b0 = vec_merge_hi_lo(m0, m3); \
         b1 = vec_merge_hi_lo(m2, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_4_3(b0, b1) \
       do { \
         b0 = vec_merge_hi_lo(m7, m5); \
         b1 = vec_merge_hi_lo(m3, m1); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_4_4(b0, b1) \
       do { \
         b0 = vec_shl_8(m0, m6); \
         b1 = vec_merge_hi_lo(m4, m6); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_5_1(b0, b1) \
       do { \
         b0 = vec_merge_hi(m1, m3); \
         b1 = vec_merge_hi(m0, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_5_2(b0, b1) \
       do { \
         b0 = vec_merge_hi(m6, m5); \
         b1 = vec_merge_lo(m5, m1); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_5_3(b0, b1) \
       do { \
         b0 = vec_merge_hi_lo(m2, m3); \
         b1 = vec_merge_lo(m7, m0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_5_4(b0, b1) \
       do { \
         b0 = vec_merge_lo(m6, m2); \
         b1 = vec_merge_hi_lo(m7, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_6_1(b0, b1) \
       do { \
         b0 = vec_merge_hi_lo(m6, m0); \
         b1 = vec_merge_hi(m7, m2); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_6_2(b0, b1) \
       do { \
         b0 = vec_merge_lo(m2, m7); \
         b1 = vec_shl_8(m6, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_6_3(b0, b1) \
       do { \
         b0 = vec_merge_hi(m0, m3); \
         b1 = vec_shl_8(m4, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_6_4(b0, b1) \
       do { \
         b0 = vec_merge_lo(m3, m1); \
         b1 = vec_merge_hi_lo(m1, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_7_1(b0, b1) \
       do { \
         b0 = vec_merge_lo(m6, m3); \
         b1 = vec_merge_hi_lo(m6, m1); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_7_2(b0, b1) \
       do { \
         b0 = vec_shl_8(m5, m7); \
         b1 = vec_merge_lo(m0, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_7_3(b0, b1) \
       do { \
         b0 = vec_merge_lo(m2, m7); \
         b1 = vec_merge_hi(m4, m1); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_7_4(b0, b1) \
       do { \
         b0 = vec_merge_hi(m0, m2); \
         b1 = vec_merge_hi(m3, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_8_1(b0, b1) \
       do { \
         b0 = vec_merge_hi(m3, m7); \
         b1 = vec_shl_8(m5, m0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_8_2(b0, b1) \
       do { \
         b0 = vec_merge_lo(m7, m4); \
         b1 = vec_shl_8(m1, m4); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_8_3(b0, b1) \
       do { \
         b0 = m6; \
         b1 = vec_shl_8(m0, m5); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_8_4(b0, b1) \
       do { \
         b0 = vec_merge_hi_lo(m1, m3); \
         b1 = m2; \
    } while(0)

    #define BLAKE2B_LOAD_MSG_9_1(b0, b1) \
       do { \
         b0 = vec_merge_hi(m5, m4); \
         b1 = vec_merge_lo(m3, m0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_9_2(b0, b1) \
       do { \
         b0 = vec_merge_hi(m1, m2); \
         b1 = vec_merge_hi_lo(m3, m2); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_9_3(b0, b1) \
       do { \
         b0 = vec_merge_lo(m7, m4); \
         b1 = vec_merge_lo(m1, m6); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_9_4(b0, b1) \
       do { \
         b0 = vec_shl_8(m5, m7); \
         b1 = vec_merge_hi(m6, m0); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_10_1(b0, b1) \
       do { \
         b0 = vec_merge_hi(m0, m1); \
         b1 = vec_merge_hi(m2, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_10_2(b0, b1) \
       do { \
         b0 = vec_merge_lo(m0, m1); \
         b1 = vec_merge_lo(m2, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_10_3(b0, b1) \
       do { \
         b0 = vec_merge_hi(m4, m5); \
         b1 = vec_merge_hi(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_10_4(b0, b1) \
       do { \
         b0 = vec_merge_lo(m4, m5); \
         b1 = vec_merge_lo(m6, m7); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_11_1(b0, b1) \
       do { \
         b0 = vec_merge_hi(m7, m2); \
         b1 = vec_merge_lo(m4, m6); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_11_2(b0, b1) \
       do { \
         b0 = vec_merge_hi(m5, m4); \
         b1 = vec_shl_8(m7, m3); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_11_3(b0, b1) \
       do { \
         b0 = vec_shl_8(m0, m0); \
         b1 = vec_merge_lo(m5, m2); \
    } while(0)

    #define BLAKE2B_LOAD_MSG_11_4(b0, b1) \
       do { \
         b0 = vec_merge_hi(m6, m1); \
         b1 = vec_merge_lo(m3, m1); \
    } while(0)

    // Power8 has packed 64-bit rotate, but in terms of left rotate
    const uint64x2_p ROR16_MASK = { 64-16, 64-16 };
    const uint64x2_p ROR24_MASK = { 64-24, 64-24 };
    const uint64x2_p ROR32_MASK = { 64-32, 64-32 };
    const uint64x2_p ROR63_MASK = { 64-63, 64-63 };

    #define vec_ror_32(x) vec_rl(x, ROR32_MASK)
    #define vec_ror_24(x) vec_rl(x, ROR24_MASK)
    #define vec_ror_16(x) vec_rl(x, ROR16_MASK)
    #define vec_ror_63(x) vec_rl(x, ROR63_MASK)

    #define BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
    do { \
      row1l = VecAdd(VecAdd(row1l, b0), row2l); \
      row1h = VecAdd(VecAdd(row1h, b1), row2h); \
      row4l = VecXor(row4l, row1l); row4h = VecXor(row4h, row1h); \
      row4l = vec_ror_32(row4l); row4h = vec_ror_32(row4h); \
      row3l = VecAdd(row3l, row4l); row3h = VecAdd(row3h, row4h); \
      row2l = VecXor(row2l, row3l); row2h = VecXor(row2h, row3h); \
      row2l = vec_ror_24(row2l); row2h = vec_ror_24(row2h); \
    } while(0)

    #define BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
    do { \
      row1l = VecAdd(VecAdd(row1l, b0), row2l); \
      row1h = VecAdd(VecAdd(row1h, b1), row2h); \
      row4l = VecXor(row4l, row1l); row4h = VecXor(row4h, row1h); \
      row4l = vec_ror_16(row4l); row4h = vec_ror_16(row4h); \
      row3l = VecAdd(row3l, row4l); row3h = VecAdd(row3h, row4h); \
      row2l = VecXor(row2l, row3l); row2h = VecXor(row2h, row3h); \
      row2l = vec_ror_63(row2l); row2h = vec_ror_63(row2h); \
    } while(0)

    #define BLAKE2B_DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
    do { \
      uint64x2_p t0 = vec_shl_8(row2l, row2h); \
      uint64x2_p t1 = vec_shl_8(row2h, row2l); \
      row2l = t0; row2h = t1; t0 = row3l;  row3l = row3h; row3h = t0; \
      t0 = vec_shl_8(row4h, row4l); t1 = vec_shl_8(row4l, row4h); \
      row4l = t0; row4h = t1; \
    } while(0)

    #define BLAKE2B_UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
    do { \
      uint64x2_p t0 = vec_shl_8(row2h, row2l); \
      uint64x2_p t1 = vec_shl_8(row2l, row2h); \
      row2l = t0; row2h = t1; t0 = row3l; row3l = row3h; row3h = t0; \
      t0 = vec_shl_8(row4l, row4h); t1 = vec_shl_8(row4h, row4l); \
      row4l = t0; row4h = t1; \
    } while(0)

    #define BLAKE2B_ROUND(r) \
    do { \
      uint64x2_p b0, b1; \
      BLAKE2B_LOAD_MSG_ ##r ##_1(b0, b1); \
      BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
      BLAKE2B_LOAD_MSG_ ##r ##_2(b0, b1); \
      BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
      BLAKE2B_DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
      BLAKE2B_LOAD_MSG_ ##r ##_3(b0, b1); \
      BLAKE2B_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
      BLAKE2B_LOAD_MSG_ ##r ##_4(b0, b1); \
      BLAKE2B_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
      BLAKE2B_UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
    } while(0)

    // Possibly unaligned user messages
    uint64x2_p m0, m1, m2, m3, m4, m5, m6, m7;
    // Endian conversion mask
    const uint8x16_p le_mask = {7,6,5,4, 3,2,1,0, 15,14,13,12, 11,10,9,8};

#if defined(_ARCH_PWR9)
    // POWER9 provides loads for char's and short's
    m0 = (uint64x2_p) vec_xl(  0, CONST_V8_CAST( input ));
    m1 = (uint64x2_p) vec_xl( 16, CONST_V8_CAST( input ));
    m2 = (uint64x2_p) vec_xl( 32, CONST_V8_CAST( input ));
    m3 = (uint64x2_p) vec_xl( 48, CONST_V8_CAST( input ));
    m4 = (uint64x2_p) vec_xl( 64, CONST_V8_CAST( input ));
    m5 = (uint64x2_p) vec_xl( 80, CONST_V8_CAST( input ));
    m6 = (uint64x2_p) vec_xl( 96, CONST_V8_CAST( input ));
    m7 = (uint64x2_p) vec_xl(112, CONST_V8_CAST( input ));

# if defined(CRYPTOPP_BIG_ENDIAN)
    m0 = vec_perm(m0, m0, le_mask);
    m1 = vec_perm(m1, m1, le_mask);
    m2 = vec_perm(m2, m2, le_mask);
    m3 = vec_perm(m3, m3, le_mask);
    m4 = vec_perm(m4, m4, le_mask);
    m5 = vec_perm(m5, m5, le_mask);
    m6 = vec_perm(m6, m6, le_mask);
    m7 = vec_perm(m7, m7, le_mask);
# endif
#else
    // Altivec only provides 16-byte aligned loads
    // http://www.nxp.com/docs/en/reference-manual/ALTIVECPEM.pdf
    m0 = (uint64x2_p) vec_ld(  0, CONST_V8_CAST( input ));
    m1 = (uint64x2_p) vec_ld( 16, CONST_V8_CAST( input ));
    m2 = (uint64x2_p) vec_ld( 32, CONST_V8_CAST( input ));
    m3 = (uint64x2_p) vec_ld( 48, CONST_V8_CAST( input ));
    m4 = (uint64x2_p) vec_ld( 64, CONST_V8_CAST( input ));
    m5 = (uint64x2_p) vec_ld( 80, CONST_V8_CAST( input ));
    m6 = (uint64x2_p) vec_ld( 96, CONST_V8_CAST( input ));
    m7 = (uint64x2_p) vec_ld(112, CONST_V8_CAST( input ));

    // Alignment check for load of the message buffer
    const uintptr_t addr = (uintptr_t)input;
    if (addr%16 == 0)
    {
        // Already aligned. Perform a little-endian swap as required
# if defined(CRYPTOPP_BIG_ENDIAN)
        m0 = vec_perm(m0, m0, le_mask);
        m1 = vec_perm(m1, m1, le_mask);
        m2 = vec_perm(m2, m2, le_mask);
        m3 = vec_perm(m3, m3, le_mask);
        m4 = vec_perm(m4, m4, le_mask);
        m5 = vec_perm(m5, m5, le_mask);
        m6 = vec_perm(m6, m6, le_mask);
        m7 = vec_perm(m7, m7, le_mask);
# endif
    }
    else
    {
        // Not aligned. Fix vectors and perform a little-endian swap as required
        // http://mirror.informatimago.com/next/developer.apple.com/
        //        hardwaredrivers/ve/code_optimization.html
        uint64x2_p ex; uint8x16_p perm;
        ex = (uint64x2_p) vec_ld(112+15, CONST_V8_CAST( input ));
        perm = vec_lvsl(0, CONST_V8_CAST( addr ));

# if defined(CRYPTOPP_BIG_ENDIAN)
        // Combine the vector permute with the little-endian swap
        perm = vec_perm(perm, perm, le_mask);
# endif

        m0 = vec_perm(m0, m1, perm);
        m1 = vec_perm(m1, m2, perm);
        m2 = vec_perm(m2, m3, perm);
        m3 = vec_perm(m3, m4, perm);
        m4 = vec_perm(m4, m5, perm);
        m5 = vec_perm(m5, m6, perm);
        m6 = vec_perm(m6, m7, perm);
        m7 = vec_perm(m7, ex, perm);
    }
#endif

    uint64x2_p row1l, row1h, row2l, row2h;
    uint64x2_p row3l, row3h, row4l, row4h;

    const uint64x2_p h0 = row1l = VecLoad64LE(state.h()+0, le_mask);
    const uint64x2_p h1 = row1h = VecLoad64LE(state.h()+2, le_mask);
    const uint64x2_p h2 = row2l = VecLoad64LE(state.h()+4, le_mask);
    const uint64x2_p h3 = row2h = VecLoad64LE(state.h()+6, le_mask);

    row3l = VecLoad64(BLAKE2B_IV+0);
    row3h = VecLoad64(BLAKE2B_IV+2);
    row4l = VecXor(VecLoad64(BLAKE2B_IV+4), VecLoad64(state.t()+0));
    row4h = VecXor(VecLoad64(BLAKE2B_IV+6), VecLoad64(state.f()+0));

    BLAKE2B_ROUND(0);
    BLAKE2B_ROUND(1);
    BLAKE2B_ROUND(2);
    BLAKE2B_ROUND(3);
    BLAKE2B_ROUND(4);
    BLAKE2B_ROUND(5);
    BLAKE2B_ROUND(6);
    BLAKE2B_ROUND(7);
    BLAKE2B_ROUND(8);
    BLAKE2B_ROUND(9);
    BLAKE2B_ROUND(10);
    BLAKE2B_ROUND(11);

    VecStore64LE(state.h()+0, VecXor(h0, VecXor(row1l, row3l)), le_mask);
    VecStore64LE(state.h()+2, VecXor(h1, VecXor(row1h, row3h)), le_mask);
    VecStore64LE(state.h()+4, VecXor(h2, VecXor(row2l, row4l)), le_mask);
    VecStore64LE(state.h()+6, VecXor(h3, VecXor(row2h, row4h)), le_mask);
}
#endif  // CRYPTOPP_POWER8_AVAILABLE

NAMESPACE_END
