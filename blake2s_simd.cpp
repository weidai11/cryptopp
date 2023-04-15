// blake2_simd.cpp - written and placed in the public domain by
//                   Samuel Neves, Jeffrey Walton, Uri Blumenthal
//                   and Marcel Raad.
//
//    This source file uses intrinsics to gain access to ARMv7a/ARMv8a
//    NEON, Power7 and SSE4.1 instructions. A separate source file is
//    needed because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

// The BLAKE2b and BLAKE2s numbers are consistent with the BLAKE2 team's
// numbers. However, we have an Altivec implementation of BLAKE2s,
// and a POWER8 implementation of BLAKE2b (BLAKE2 team is missing them).
// Altivec code is about 2x faster than C++ when using GCC 5.0 or
// above. The POWER8 code is about 2.5x faster than C++ when using GCC 5.0
// or above. If you use GCC 4.0 (PowerMac) or GCC 4.8 (GCC Compile Farm)
// then the PowerPC code will be slower than C++. Be sure to use GCC 5.0
// or above for PowerPC builds or disable Altivec for BLAKE2b and BLAKE2s
// if using the old compilers.

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
# undef CRYPTOPP_POWER7_AVAILABLE
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

#if (CRYPTOPP_ALTIVEC_AVAILABLE)
# include "ppc_simd.h"
#endif

#if defined(CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE)
/* Ignore "warning: vec_lvsl is deprecated..." */
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

// Squash MS LNK4221 and libtool warnings
extern const char BLAKE2S_SIMD_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

// Exported by blake2.cpp
extern const word32 BLAKE2S_IV[8];
extern const word64 BLAKE2B_IV[8];

#if CRYPTOPP_SSE41_AVAILABLE

#define LOADU(p)  _mm_loadu_si128((const __m128i *)(const void*)(p))
#define STOREU(p,r) _mm_storeu_si128((__m128i *)(void*)(p), r)
#define TOF(reg) _mm_castsi128_ps((reg))
#define TOI(reg) _mm_castps_si128((reg))

void BLAKE2_Compress32_SSE4(const byte* input, BLAKE2s_State& state)
{
    #define BLAKE2S_LOAD_MSG_0_1(buf) \
    buf = TOI(_mm_shuffle_ps(TOF(m0), TOF(m1), _MM_SHUFFLE(2,0,2,0)));

    #define BLAKE2S_LOAD_MSG_0_2(buf) \
    buf = TOI(_mm_shuffle_ps(TOF(m0), TOF(m1), _MM_SHUFFLE(3,1,3,1)));

    #define BLAKE2S_LOAD_MSG_0_3(buf) \
    t0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE(3,2,0,1)); \
    t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(0,1,3,2)); \
    buf = _mm_blend_epi16(t0, t1, 0xC3);

    #define BLAKE2S_LOAD_MSG_0_4(buf) \
    t0 = _mm_blend_epi16(t0, t1, 0x3C); \
    buf = _mm_shuffle_epi32(t0, _MM_SHUFFLE(2,3,0,1));

    #define BLAKE2S_LOAD_MSG_1_1(buf) \
    t0 = _mm_blend_epi16(m1, m2, 0x0C); \
    t1 = _mm_slli_si128(m3, 4); \
    t2 = _mm_blend_epi16(t0, t1, 0xF0); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));

    #define BLAKE2S_LOAD_MSG_1_2(buf) \
    t0 = _mm_shuffle_epi32(m2,_MM_SHUFFLE(0,0,2,0)); \
    t1 = _mm_blend_epi16(m1,m3,0xC0); \
    t2 = _mm_blend_epi16(t0, t1, 0xF0); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));

    #define BLAKE2S_LOAD_MSG_1_3(buf) \
    t0 = _mm_slli_si128(m1, 4); \
    t1 = _mm_blend_epi16(m2, t0, 0x30); \
    t2 = _mm_blend_epi16(m0, t1, 0xF0); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,0,1,2));

    #define BLAKE2S_LOAD_MSG_1_4(buf) \
    t0 = _mm_unpackhi_epi32(m0,m1); \
    t1 = _mm_slli_si128(m3, 4); \
    t2 = _mm_blend_epi16(t0, t1, 0x0C); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,0,1,2));

    #define BLAKE2S_LOAD_MSG_2_1(buf) \
    t0 = _mm_unpackhi_epi32(m2,m3); \
    t1 = _mm_blend_epi16(m3,m1,0x0C); \
    t2 = _mm_blend_epi16(t0, t1, 0x0F); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));

    #define BLAKE2S_LOAD_MSG_2_2(buf) \
    t0 = _mm_unpacklo_epi32(m2,m0); \
    t1 = _mm_blend_epi16(t0, m0, 0xF0); \
    t2 = _mm_slli_si128(m3, 8); \
    buf = _mm_blend_epi16(t1, t2, 0xC0);

    #define BLAKE2S_LOAD_MSG_2_3(buf) \
    t0 = _mm_blend_epi16(m0, m2, 0x3C); \
    t1 = _mm_srli_si128(m1, 12); \
    t2 = _mm_blend_epi16(t0,t1,0x03); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(0,3,2,1));

    #define BLAKE2S_LOAD_MSG_2_4(buf) \
    t0 = _mm_slli_si128(m3, 4); \
    t1 = _mm_blend_epi16(m0, m1, 0x33); \
    t2 = _mm_blend_epi16(t1, t0, 0xC0); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,2,3,0));

    #define BLAKE2S_LOAD_MSG_3_1(buf) \
    t0 = _mm_unpackhi_epi32(m0,m1); \
    t1 = _mm_unpackhi_epi32(t0, m2); \
    t2 = _mm_blend_epi16(t1, m3, 0x0C); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));

    #define BLAKE2S_LOAD_MSG_3_2(buf) \
    t0 = _mm_slli_si128(m2, 8); \
    t1 = _mm_blend_epi16(m3,m0,0x0C); \
    t2 = _mm_blend_epi16(t1, t0, 0xC0); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,1,3));

    #define BLAKE2S_LOAD_MSG_3_3(buf) \
    t0 = _mm_blend_epi16(m0,m1,0x0F); \
    t1 = _mm_blend_epi16(t0, m3, 0xC0); \
    buf = _mm_shuffle_epi32(t1, _MM_SHUFFLE(0,1,2,3));

    #define BLAKE2S_LOAD_MSG_3_4(buf) \
    t0 = _mm_alignr_epi8(m0, m1, 4); \
    buf = _mm_blend_epi16(t0, m2, 0x33);

    #define BLAKE2S_LOAD_MSG_4_1(buf) \
    t0 = _mm_unpacklo_epi64(m1,m2); \
    t1 = _mm_unpackhi_epi64(m0,m2); \
    t2 = _mm_blend_epi16(t0,t1,0x33); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,1,3));

    #define BLAKE2S_LOAD_MSG_4_2(buf) \
    t0 = _mm_unpackhi_epi64(m1,m3); \
    t1 = _mm_unpacklo_epi64(m0,m1); \
    buf = _mm_blend_epi16(t0,t1,0x33);

    #define BLAKE2S_LOAD_MSG_4_3(buf) \
    t0 = _mm_unpackhi_epi64(m3,m1); \
    t1 = _mm_unpackhi_epi64(m2,m0); \
    t2 = _mm_blend_epi16(t1,t0,0x33); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));

    #define BLAKE2S_LOAD_MSG_4_4(buf) \
    t0 = _mm_blend_epi16(m0,m2,0x03); \
    t1 = _mm_slli_si128(t0, 8); \
    t2 = _mm_blend_epi16(t1,m3,0x0F); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,3,1));

    #define BLAKE2S_LOAD_MSG_5_1(buf) \
    t0 = _mm_unpackhi_epi32(m0,m1); \
    t1 = _mm_unpacklo_epi32(m0,m2); \
    buf = _mm_unpacklo_epi64(t0,t1);

    #define BLAKE2S_LOAD_MSG_5_2(buf) \
    t0 = _mm_srli_si128(m2, 4); \
    t1 = _mm_blend_epi16(m0,m3,0x03); \
    buf = _mm_blend_epi16(t1,t0,0x3C);

    #define BLAKE2S_LOAD_MSG_5_3(buf) \
    t0 = _mm_blend_epi16(m1,m0,0x0C); \
    t1 = _mm_srli_si128(m3, 4); \
    t2 = _mm_blend_epi16(t0,t1,0x30); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));

    #define BLAKE2S_LOAD_MSG_5_4(buf) \
    t0 = _mm_unpacklo_epi64(m2,m1); \
    t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(2,0,1,0)); \
    t2 = _mm_srli_si128(t0, 4); \
    buf = _mm_blend_epi16(t1,t2,0x33);

    #define BLAKE2S_LOAD_MSG_6_1(buf) \
    t0 = _mm_slli_si128(m1, 12); \
    t1 = _mm_blend_epi16(m0,m3,0x33); \
    buf = _mm_blend_epi16(t1,t0,0xC0);

    #define BLAKE2S_LOAD_MSG_6_2(buf) \
    t0 = _mm_blend_epi16(m3,m2,0x30); \
    t1 = _mm_srli_si128(m1, 4); \
    t2 = _mm_blend_epi16(t0,t1,0x03); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,3,0));

    #define BLAKE2S_LOAD_MSG_6_3(buf) \
    t0 = _mm_unpacklo_epi64(m0,m2); \
    t1 = _mm_srli_si128(m1, 4); \
    t2 = _mm_blend_epi16(t0,t1,0x0C); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));

    #define BLAKE2S_LOAD_MSG_6_4(buf) \
    t0 = _mm_unpackhi_epi32(m1,m2); \
    t1 = _mm_unpackhi_epi64(m0,t0); \
    buf = _mm_shuffle_epi32(t1, _MM_SHUFFLE(0,1,2,3));

    #define BLAKE2S_LOAD_MSG_7_1(buf) \
    t0 = _mm_unpackhi_epi32(m0,m1); \
    t1 = _mm_blend_epi16(t0,m3,0x0F); \
    buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(2,0,3,1));

    #define BLAKE2S_LOAD_MSG_7_2(buf) \
    t0 = _mm_blend_epi16(m2,m3,0x30); \
    t1 = _mm_srli_si128(m0,4); \
    t2 = _mm_blend_epi16(t0,t1,0x03); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,0,2,3));

    #define BLAKE2S_LOAD_MSG_7_3(buf) \
    t0 = _mm_unpackhi_epi64(m0,m3); \
    t1 = _mm_unpacklo_epi64(m1,m2); \
    t2 = _mm_blend_epi16(t0,t1,0x3C); \
    buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(2,3,1,0));

    #define BLAKE2S_LOAD_MSG_7_4(buf) \
    t0 = _mm_unpacklo_epi32(m0,m1); \
    t1 = _mm_unpackhi_epi32(m1,m2); \
    t2 = _mm_unpacklo_epi64(t0,t1); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));

    #define BLAKE2S_LOAD_MSG_8_1(buf) \
    t0 = _mm_unpackhi_epi32(m1,m3); \
    t1 = _mm_unpacklo_epi64(t0,m0); \
    t2 = _mm_blend_epi16(t1,m2,0xC0); \
    buf = _mm_shufflehi_epi16(t2,_MM_SHUFFLE(1,0,3,2));

    #define BLAKE2S_LOAD_MSG_8_2(buf) \
    t0 = _mm_unpackhi_epi32(m0,m3); \
    t1 = _mm_blend_epi16(m2,t0,0xF0); \
    buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(0,2,1,3));

    #define BLAKE2S_LOAD_MSG_8_3(buf) \
    t0 = _mm_unpacklo_epi64(m0,m3); \
    t1 = _mm_srli_si128(m2,8); \
    t2 = _mm_blend_epi16(t0,t1,0x03); \
    buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,3,2,0));

    #define BLAKE2S_LOAD_MSG_8_4(buf) \
    t0 = _mm_blend_epi16(m1,m0,0x30); \
    buf = _mm_shuffle_epi32(t0,_MM_SHUFFLE(0,3,2,1));

    #define BLAKE2S_LOAD_MSG_9_1(buf) \
    t0 = _mm_blend_epi16(m0,m2,0x03); \
    t1 = _mm_blend_epi16(m1,m2,0x30); \
    t2 = _mm_blend_epi16(t1,t0,0x0F); \
    buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(1,3,0,2));

    #define BLAKE2S_LOAD_MSG_9_2(buf) \
    t0 = _mm_slli_si128(m0,4); \
    t1 = _mm_blend_epi16(m1,t0,0xC0); \
    buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(1,2,0,3));

    #define BLAKE2S_LOAD_MSG_9_3(buf) \
    t0 = _mm_unpackhi_epi32(m0,m3); \
    t1 = _mm_unpacklo_epi32(m2,m3); \
    t2 = _mm_unpackhi_epi64(t0,t1); \
    buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(0,2,1,3));

    #define BLAKE2S_LOAD_MSG_9_4(buf) \
    t0 = _mm_blend_epi16(m3,m2,0xC0); \
    t1 = _mm_unpacklo_epi32(m0,m3); \
    t2 = _mm_blend_epi16(t0,t1,0x0F); \
    buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(1,2,3,0));

#ifdef __XOP__
# define MM_ROTI_EPI32(r, c) \
    _mm_roti_epi32(r, c)
#else
# define MM_ROTI_EPI32(r, c) ( \
      (8==-(c)) ? _mm_shuffle_epi8(r,r8) \
    : (16==-(c)) ? _mm_shuffle_epi8(r,r16) \
    : _mm_xor_si128(_mm_srli_epi32((r), -(c)), \
      _mm_slli_epi32((r), 32-(-(c)))))
#endif

#define BLAKE2S_G1(row1,row2,row3,row4,buf) \
    row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
    row4 = _mm_xor_si128( row4, row1 ); \
    row4 = MM_ROTI_EPI32(row4, -16); \
    row3 = _mm_add_epi32( row3, row4 );   \
    row2 = _mm_xor_si128( row2, row3 ); \
    row2 = MM_ROTI_EPI32(row2, -12);

#define BLAKE2S_G2(row1,row2,row3,row4,buf) \
    row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
    row4 = _mm_xor_si128( row4, row1 ); \
    row4 = MM_ROTI_EPI32(row4, -8); \
    row3 = _mm_add_epi32( row3, row4 );   \
    row2 = _mm_xor_si128( row2, row3 ); \
    row2 = MM_ROTI_EPI32(row2, -7);

#define DIAGONALIZE(row1,row2,row3,row4) \
    row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE(2,1,0,3) ); \
    row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(1,0,3,2) ); \
    row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(0,3,2,1) );

#define UNDIAGONALIZE(row1,row2,row3,row4) \
    row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE(0,3,2,1) ); \
    row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(1,0,3,2) ); \
    row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(2,1,0,3) );

#define BLAKE2S_ROUND(r)  \
    BLAKE2S_LOAD_MSG_ ##r ##_1(buf1); \
    BLAKE2S_G1(row1,row2,row3,row4,buf1); \
    BLAKE2S_LOAD_MSG_ ##r ##_2(buf2); \
    BLAKE2S_G2(row1,row2,row3,row4,buf2); \
    DIAGONALIZE(row1,row2,row3,row4); \
    BLAKE2S_LOAD_MSG_ ##r ##_3(buf3); \
    BLAKE2S_G1(row1,row2,row3,row4,buf3); \
    BLAKE2S_LOAD_MSG_ ##r ##_4(buf4); \
    BLAKE2S_G2(row1,row2,row3,row4,buf4); \
    UNDIAGONALIZE(row1,row2,row3,row4);

    __m128i row1, row2, row3, row4;
    __m128i buf1, buf2, buf3, buf4;
    __m128i t0, t1, t2, ff0, ff1;

    const __m128i r8 = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1);
    const __m128i r16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);

    const __m128i m0 = LOADU(input + 00);
    const __m128i m1 = LOADU(input + 16);
    const __m128i m2 = LOADU(input + 32);
    const __m128i m3 = LOADU(input + 48);

    row1 = ff0 = LOADU(state.h()+0);
    row2 = ff1 = LOADU(state.h()+4);
    row3 = LOADU(BLAKE2S_IV+0);
    row4 = _mm_xor_si128(LOADU(BLAKE2S_IV+4), LOADU(state.t()+0));

    BLAKE2S_ROUND(0);
    BLAKE2S_ROUND(1);
    BLAKE2S_ROUND(2);
    BLAKE2S_ROUND(3);
    BLAKE2S_ROUND(4);
    BLAKE2S_ROUND(5);
    BLAKE2S_ROUND(6);
    BLAKE2S_ROUND(7);
    BLAKE2S_ROUND(8);
    BLAKE2S_ROUND(9);

    STOREU(state.h()+0, _mm_xor_si128(ff0, _mm_xor_si128(row1, row3)));
    STOREU(state.h()+4, _mm_xor_si128(ff1, _mm_xor_si128(row2, row4)));
}
#endif  // CRYPTOPP_SSE41_AVAILABLE

#if CRYPTOPP_ARM_NEON_AVAILABLE
void BLAKE2_Compress32_NEON(const byte* input, BLAKE2s_State& state)
{
    #define BLAKE2S_LOAD_MSG_0_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m0), vget_high_u32(m0)).val[0]; \
    t1 = vzip_u32(vget_low_u32(m1), vget_high_u32(m1)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_0_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m0), vget_high_u32(m0)).val[1]; \
    t1 = vzip_u32(vget_low_u32(m1), vget_high_u32(m1)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_0_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m2), vget_high_u32(m2)).val[0]; \
    t1 = vzip_u32(vget_low_u32(m3), vget_high_u32(m3)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_0_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m2), vget_high_u32(m2)).val[1]; \
    t1 = vzip_u32(vget_low_u32(m3), vget_high_u32(m3)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_1_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m3), vget_low_u32(m1)).val[0]; \
    t1 = vzip_u32(vget_low_u32(m2), vget_low_u32(m3)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_1_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m2), vget_low_u32(m2)).val[0]; \
    t1 = vext_u32(vget_high_u32(m3), vget_high_u32(m1), 1); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_1_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vext_u32(vget_low_u32(m0), vget_low_u32(m0), 1); \
    t1 = vzip_u32(vget_high_u32(m2), vget_low_u32(m1)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_1_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m3), vget_high_u32(m0)).val[0]; \
    t1 = vzip_u32(vget_high_u32(m1), vget_high_u32(m0)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_2_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vext_u32(vget_high_u32(m2), vget_low_u32(m3), 1); \
    t1 = vzip_u32(vget_low_u32(m1), vget_high_u32(m3)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_2_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m2), vget_low_u32(m0)).val[0]; \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m0), vget_low_u32(m3)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_2_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m2), vget_high_u32(m0)); \
    t1 = vzip_u32(vget_high_u32(m1), vget_low_u32(m2)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_2_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m3), vget_high_u32(m1)).val[0]; \
    t1 = vext_u32(vget_low_u32(m0), vget_low_u32(m1), 1); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_3_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m1), vget_high_u32(m0)).val[1]; \
    t1 = vzip_u32(vget_low_u32(m3), vget_high_u32(m2)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_3_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m2), vget_low_u32(m0)).val[1]; \
    t1 = vzip_u32(vget_low_u32(m3), vget_high_u32(m3)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_3_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m0), vget_low_u32(m1)); \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m1), vget_high_u32(m3)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_3_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m1), vget_high_u32(m2)).val[0]; \
    t1 = vzip_u32(vget_low_u32(m0), vget_low_u32(m2)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_4_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m2), vget_low_u32(m1)).val[1]; \
    t1 = vzip_u32((vget_high_u32(m0)), vget_high_u32(m2)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_4_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m0), vget_high_u32(m1)); \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m1), vget_high_u32(m3)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_4_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m3), vget_high_u32(m2)); \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m1), vget_high_u32(m0)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_4_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vext_u32(vget_low_u32(m0), vget_low_u32(m3), 1); \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m2), vget_low_u32(m3)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_5_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32((vget_high_u32(m0)), vget_high_u32(m1)).val[0]; \
    t1 = vzip_u32(vget_low_u32(m0), vget_low_u32(m2)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_5_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m3), vget_high_u32(m2)).val[0]; \
    t1 = vzip_u32(vget_high_u32(m2), vget_high_u32(m0)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_5_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m1), vget_high_u32(m1)); \
    t1 = vzip_u32(vget_high_u32(m3), vget_low_u32(m0)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_5_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m3), vget_low_u32(m1)).val[1]; \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m3), vget_low_u32(m2)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_6_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m3), vget_low_u32(m0)); \
    t1 = vzip_u32(vget_high_u32(m3), vget_low_u32(m1)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_6_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m1), vget_high_u32(m3)).val[1]; \
    t1 = vext_u32(vget_low_u32(m3), vget_high_u32(m2), 1); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_6_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m0), vget_high_u32(m1)).val[0]; \
    t1 = vext_u32(vget_low_u32(m2), vget_low_u32(m2), 1); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_6_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m1), vget_high_u32(m0)).val[1]; \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m0), vget_high_u32(m2)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_7_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m3), vget_high_u32(m1)).val[1]; \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m3), vget_high_u32(m0)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_7_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vext_u32(vget_high_u32(m2), vget_high_u32(m3), 1); \
    t1 = vzip_u32(vget_low_u32(m0), vget_low_u32(m2)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_7_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m1), vget_high_u32(m3)).val[1]; \
    t1 = vzip_u32(vget_low_u32(m2), vget_high_u32(m0)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_7_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_low_u32(m0), vget_low_u32(m1)).val[0]; \
    t1 = vzip_u32(vget_high_u32(m1), vget_high_u32(m2)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_8_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m1), vget_high_u32(m3)).val[0]; \
    t1 = vext_u32(vget_high_u32(m2), vget_low_u32(m0), 1); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_8_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m3), vget_low_u32(m2)).val[1]; \
    t1 = vext_u32(vget_high_u32(m0), vget_low_u32(m2), 1); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_8_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m3), vget_low_u32(m3)); \
    t1 = vext_u32(vget_low_u32(m0), vget_high_u32(m2), 1); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_8_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m0), vget_high_u32(m1)); \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_low_u32(m1), vget_low_u32(m1)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_9_1(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m2), vget_low_u32(m2)).val[0]; \
    t1 = vzip_u32(vget_high_u32(m1), vget_low_u32(m0)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_9_2(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32((vget_high_u32(m0)), vget_low_u32(m1)).val[0]; \
    t1 = vbsl_u32(vcreate_u32(0xFFFFFFFF), vget_high_u32(m1), vget_low_u32(m1)); \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_9_3(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vzip_u32(vget_high_u32(m3), vget_low_u32(m2)).val[1]; \
    t1 = vzip_u32((vget_high_u32(m0)), vget_low_u32(m3)).val[1]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define BLAKE2S_LOAD_MSG_9_4(buf) \
    do { uint32x2_t t0, t1; \
    t0 = vext_u32(vget_high_u32(m2), vget_high_u32(m3), 1); \
    t1 = vzip_u32(vget_low_u32(m3), vget_low_u32(m0)).val[0]; \
    buf = vcombine_u32(t0, t1); } while(0)

    #define vrorq_n_u32_16(x) vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))

    #define vrorq_n_u32_8(x) vsriq_n_u32(vshlq_n_u32((x), 24), (x), 8)

    #define vrorq_n_u32(x, c) vsriq_n_u32(vshlq_n_u32((x), 32-(c)), (x), (c))

    #define BLAKE2S_G1(row1,row2,row3,row4,buf) \
    do { \
      row1 = vaddq_u32(vaddq_u32(row1, buf), row2); row4 = veorq_u32(row4, row1); \
      row4 = vrorq_n_u32_16(row4); row3 = vaddq_u32(row3, row4); \
      row2 = veorq_u32(row2, row3); row2 = vrorq_n_u32(row2, 12); \
    } while(0)

    #define BLAKE2S_G2(row1,row2,row3,row4,buf) \
    do { \
      row1 = vaddq_u32(vaddq_u32(row1, buf), row2); row4 = veorq_u32(row4, row1); \
      row4 = vrorq_n_u32_8(row4); row3 = vaddq_u32(row3, row4); \
      row2 = veorq_u32(row2, row3); row2 = vrorq_n_u32(row2, 7); \
    } while(0)

    #define BLAKE2S_DIAGONALIZE(row1,row2,row3,row4) \
    do { \
      row4 = vextq_u32(row4, row4, 3); row3 = vextq_u32(row3, row3, 2); row2 = vextq_u32(row2, row2, 1); \
    } while(0)

    #define BLAKE2S_UNDIAGONALIZE(row1,row2,row3,row4) \
    do { \
      row4 = vextq_u32(row4, row4, 1); \
      row3 = vextq_u32(row3, row3, 2); \
      row2 = vextq_u32(row2, row2, 3); \
    } while(0)

    #define BLAKE2S_ROUND(r)  \
    do { \
      uint32x4_t buf1, buf2, buf3, buf4; \
      BLAKE2S_LOAD_MSG_ ##r ##_1(buf1); \
      BLAKE2S_G1(row1,row2,row3,row4,buf1); \
      BLAKE2S_LOAD_MSG_ ##r ##_2(buf2); \
      BLAKE2S_G2(row1,row2,row3,row4,buf2); \
      BLAKE2S_DIAGONALIZE(row1,row2,row3,row4); \
      BLAKE2S_LOAD_MSG_ ##r ##_3(buf3); \
      BLAKE2S_G1(row1,row2,row3,row4,buf3); \
      BLAKE2S_LOAD_MSG_ ##r ##_4(buf4); \
      BLAKE2S_G2(row1,row2,row3,row4,buf4); \
      BLAKE2S_UNDIAGONALIZE(row1,row2,row3,row4); \
    } while(0)

    const uint32x4_t m0 = vreinterpretq_u32_u8(vld1q_u8(input + 00));
    const uint32x4_t m1 = vreinterpretq_u32_u8(vld1q_u8(input + 16));
    const uint32x4_t m2 = vreinterpretq_u32_u8(vld1q_u8(input + 32));
    const uint32x4_t m3 = vreinterpretq_u32_u8(vld1q_u8(input + 48));

    uint32x4_t row1, row2, row3, row4;

    const uint32x4_t f0 = row1 = vld1q_u32(state.h()+0);
    const uint32x4_t f1 = row2 = vld1q_u32(state.h()+4);
    row3 = vld1q_u32(BLAKE2S_IV+0);
    row4 = veorq_u32(vld1q_u32(BLAKE2S_IV+4), vld1q_u32(state.t()+0));

    BLAKE2S_ROUND(0);
    BLAKE2S_ROUND(1);
    BLAKE2S_ROUND(2);
    BLAKE2S_ROUND(3);
    BLAKE2S_ROUND(4);
    BLAKE2S_ROUND(5);
    BLAKE2S_ROUND(6);
    BLAKE2S_ROUND(7);
    BLAKE2S_ROUND(8);
    BLAKE2S_ROUND(9);

    vst1q_u32(state.h()+0, veorq_u32(f0, veorq_u32(row1, row3)));
    vst1q_u32(state.h()+4, veorq_u32(f1, veorq_u32(row2, row4)));
}
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_ALTIVEC_AVAILABLE)

template <class T>
inline uint32x4_p VecLoad32(const T* p)
{
    return VecLoad(p);
}

template <class T>
inline uint32x4_p VecLoad32LE(const T* p, const uint8x16_p le_mask)
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    const uint32x4_p v = VecLoad(p);
    return VecPermute(v, v, le_mask);
#else
    CRYPTOPP_UNUSED(le_mask);
    return VecLoad(p);
#endif
}

template <class T>
inline void VecStore32(T* p, const uint32x4_p x)
{
    VecStore(x, p);
}

template <class T>
inline void VecStore32LE(T* p, const uint32x4_p x, const uint8x16_p le_mask)
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    const uint32x4_p v = VecPermute(x, x, le_mask);
    VecStore(v, p);
#else
    CRYPTOPP_UNUSED(le_mask);
    VecStore(x, p);
#endif
}

template <unsigned int E1, unsigned int E2>
inline uint32x4_p VectorSet32(const uint32x4_p a, const uint32x4_p b)
{
    // Re-index. I'd like to use something like Z=Y*4 and then
    // VecShiftLeftOctet<Z>(b) but it crashes early Red Hat
    // GCC compilers.
    enum {X=E1&3, Y=E2&3};

    // Don't care element
    const unsigned int DC = 31;

    // Element 0 combinations
    if (X == 0 && Y == 0)
    {
        const uint8x16_p mask = {0,1,2,3, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, b, mask);
    }
    else if (X == 0 && Y == 1)
    {
        const uint8x16_p mask = {0,1,2,3, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<4>(b), mask);
    }
    else if (X == 0 && Y == 2)
    {
        const uint8x16_p mask = {0,1,2,3, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<8>(b), mask);
    }
    else if (X == 0 && Y == 3)
    {
        const uint8x16_p mask = {0,1,2,3, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<12>(b), mask);
    }

    // Element 1 combinations
    else if (X == 1 && Y == 0)
    {
        const uint8x16_p mask = {4,5,6,7, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, b, mask);
    }
    else if (X == 1 && Y == 1)
    {
        const uint8x16_p mask = {4,5,6,7, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<4>(b), mask);
    }
    else if (X == 1 && Y == 2)
    {
        const uint8x16_p mask = {4,5,6,7, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<8>(b), mask);
    }
    else if (X == 1 && Y == 3)
    {
        const uint8x16_p mask = {4,5,6,7, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<12>(b), mask);
    }

    // Element 2 combinations
    else if (X == 2 && Y == 0)
    {
        const uint8x16_p mask = {8,9,10,11, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, b, mask);
    }
    else if (X == 2 && Y == 1)
    {
        const uint8x16_p mask = {8,9,10,11, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<4>(b), mask);
    }
    else if (X == 2 && Y == 2)
    {
        const uint8x16_p mask = {8,9,10,11, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<8>(b), mask);
    }
    else if (X == 2 && Y == 3)
    {
        const uint8x16_p mask = {8,9,10,11, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<12>(b), mask);
    }

    // Element 3 combinations
    else if (X == 3 && Y == 0)
    {
        const uint8x16_p mask = {12,13,14,15, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, b, mask);
    }
    else if (X == 3 && Y == 1)
    {
        const uint8x16_p mask = {12,13,14,15, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<4>(b), mask);
    }
    else if (X == 3 && Y == 2)
    {
        const uint8x16_p mask = {12,13,14,15, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<8>(b), mask);
    }
    else if (X == 3 && Y == 3)
    {
        const uint8x16_p mask = {12,13,14,15, 16,17,18,19, DC,DC,DC,DC, DC,DC,DC,DC};
        return VecPermute(a, VecShiftLeftOctet<12>(b), mask);
    }

    // Quiet IBM XLC warning
    return VecXor(a, a);
}

template <unsigned int E1, unsigned int E2, unsigned int E3, unsigned int E4>
inline uint32x4_p VectorSet32(const uint32x4_p a, const uint32x4_p b,
                              const uint32x4_p c, const uint32x4_p d)
{
    // Re-index
    enum {W=E1&3, X=E2&3, Y=E3&3, Z=E4&3};

    const uint32x4_p t0 = VectorSet32<W,X>(a, b);
    const uint32x4_p t1 = VectorSet32<Y,Z>(c, d);

    // PowerPC follows SSE2's implementation, and this is _mm_set_epi32.
    const uint8x16_p mask = {20,21,22,23, 16,17,18,19, 4,5,6,7, 0,1,2,3};
    return VecPermute(t0, t1, mask);
}

template<>
uint32x4_p VectorSet32<2,0,2,0>(const uint32x4_p a, const uint32x4_p b,
                                const uint32x4_p c, const uint32x4_p d)
{
    // a=b, c=d, mask is {2,0, 2,0}
    CRYPTOPP_UNUSED(b); CRYPTOPP_UNUSED(d);
    const uint8x16_p mask = {16,17,18,19, 24,25,26,27, 0,1,2,3, 8,9,10,11};
    return VecPermute(a, c, mask);
}

template<>
uint32x4_p VectorSet32<3,1,3,1>(const uint32x4_p a, const uint32x4_p b,
                                const uint32x4_p c, const uint32x4_p d)
{
    // a=b, c=d, mask is {3,1, 3,1}
    CRYPTOPP_UNUSED(b); CRYPTOPP_UNUSED(d);
    const uint8x16_p mask = {20,21,22,23, 28,29,30,31, 4,5,6,7, 12,13,14,15};
    return VecPermute(a, c, mask);
}

void BLAKE2_Compress32_ALTIVEC(const byte* input, BLAKE2s_State& state)
{
    # define m1 m0
    # define m2 m0
    # define m3 m0

    # define m5 m4
    # define m6 m4
    # define m7 m4

    # define m9 m8
    # define m10 m8
    # define m11 m8

    # define m13 m12
    # define m14 m12
    # define m15 m12

    // #define BLAKE2S_LOAD_MSG_0_1(buf) buf = VectorSet32<6,4,2,0>(m6,m4,m2,m0);
    #define BLAKE2S_LOAD_MSG_0_1(buf) buf = VectorSet32<2,0,2,0>(m6,m4,m2,m0);
    // #define BLAKE2S_LOAD_MSG_0_2(buf) buf = VectorSet32<7,5,3,1>(m7,m5,m3,m1);
    #define BLAKE2S_LOAD_MSG_0_2(buf) buf = VectorSet32<3,1,3,1>(m7,m5,m3,m1);
    // #define BLAKE2S_LOAD_MSG_0_3(buf) buf = VectorSet32<14,12,10,8>(m14,m12,m10,m8);
    #define BLAKE2S_LOAD_MSG_0_3(buf) buf = VectorSet32<2,0,2,0>(m14,m12,m10,m8);
    // #define BLAKE2S_LOAD_MSG_0_4(buf) buf = VectorSet32<15,13,11,9>(m15,m13,m11,m9);
    #define BLAKE2S_LOAD_MSG_0_4(buf) buf = VectorSet32<3,1,3,1>(m15,m13,m11,m9);

    #define BLAKE2S_LOAD_MSG_1_1(buf) buf = VectorSet32<13,9,4,14>(m13,m9,m4,m14);
    #define BLAKE2S_LOAD_MSG_1_2(buf) buf = VectorSet32<6,15,8,10>(m6,m15,m8,m10)
    #define BLAKE2S_LOAD_MSG_1_3(buf) buf = VectorSet32<5,11,0,1>(m5,m11,m0,m1)
    #define BLAKE2S_LOAD_MSG_1_4(buf) buf = VectorSet32<3,7,2,12>(m3,m7,m2,m12)

    #define BLAKE2S_LOAD_MSG_2_1(buf) buf = VectorSet32<15,5,12,11>(m15,m5,m12,m11)
    #define BLAKE2S_LOAD_MSG_2_2(buf) buf = VectorSet32<13,2,0,8>(m13,m2,m0,m8)
    #define BLAKE2S_LOAD_MSG_2_3(buf) buf = VectorSet32<9,7,3,10>(m9,m7,m3,m10)
    #define BLAKE2S_LOAD_MSG_2_4(buf) buf = VectorSet32<4,1,6,14>(m4,m1,m6,m14)

    #define BLAKE2S_LOAD_MSG_3_1(buf) buf = VectorSet32<11,13,3,7>(m11,m13,m3,m7)
    #define BLAKE2S_LOAD_MSG_3_2(buf) buf = VectorSet32<14,12,1,9>(m14,m12,m1,m9)
    #define BLAKE2S_LOAD_MSG_3_3(buf) buf = VectorSet32<15,4,5,2>(m15,m4,m5,m2)
    #define BLAKE2S_LOAD_MSG_3_4(buf) buf = VectorSet32<8,0,10,6>(m8,m0,m10,m6)

    #define BLAKE2S_LOAD_MSG_4_1(buf) buf = VectorSet32<10,2,5,9>(m10,m2,m5,m9)
    #define BLAKE2S_LOAD_MSG_4_2(buf) buf = VectorSet32<15,4,7,0>(m15,m4,m7,m0)
    #define BLAKE2S_LOAD_MSG_4_3(buf) buf = VectorSet32<3,6,11,14>(m3,m6,m11,m14)
    #define BLAKE2S_LOAD_MSG_4_4(buf) buf = VectorSet32<13,8,12,1>(m13,m8,m12,m1)

    #define BLAKE2S_LOAD_MSG_5_1(buf) buf = VectorSet32<8,0,6,2>(m8,m0,m6,m2)
    #define BLAKE2S_LOAD_MSG_5_2(buf) buf = VectorSet32<3,11,10,12>(m3,m11,m10,m12)
    #define BLAKE2S_LOAD_MSG_5_3(buf) buf = VectorSet32<1,15,7,4>(m1,m15,m7,m4)
    #define BLAKE2S_LOAD_MSG_5_4(buf) buf = VectorSet32<9,14,5,13>(m9,m14,m5,m13)

    #define BLAKE2S_LOAD_MSG_6_1(buf) buf = VectorSet32<4,14,1,12>(m4,m14,m1,m12)
    #define BLAKE2S_LOAD_MSG_6_2(buf) buf = VectorSet32<10,13,15,5>(m10,m13,m15,m5)
    #define BLAKE2S_LOAD_MSG_6_3(buf) buf = VectorSet32<8,9,6,0>(m8,m9,m6,m0)
    #define BLAKE2S_LOAD_MSG_6_4(buf) buf = VectorSet32<11,2,3,7>(m11,m2,m3,m7)

    #define BLAKE2S_LOAD_MSG_7_1(buf) buf = VectorSet32<3,12,7,13>(m3,m12,m7,m13)
    #define BLAKE2S_LOAD_MSG_7_2(buf) buf = VectorSet32<9,1,14,11>(m9,m1,m14,m11)
    #define BLAKE2S_LOAD_MSG_7_3(buf) buf = VectorSet32<2,8,15,5>(m2,m8,m15,m5)
    #define BLAKE2S_LOAD_MSG_7_4(buf) buf = VectorSet32<10,6,4,0>(m10,m6,m4,m0)

    #define BLAKE2S_LOAD_MSG_8_1(buf) buf = VectorSet32<0,11,14,6>(m0,m11,m14,m6)
    #define BLAKE2S_LOAD_MSG_8_2(buf) buf = VectorSet32<8,3,9,15>(m8,m3,m9,m15)
    #define BLAKE2S_LOAD_MSG_8_3(buf) buf = VectorSet32<10,1,13,12>(m10,m1,m13,m12)
    #define BLAKE2S_LOAD_MSG_8_4(buf) buf = VectorSet32<5,4,7,2>(m5,m4,m7,m2)

    #define BLAKE2S_LOAD_MSG_9_1(buf) buf = VectorSet32<1,7,8,10>(m1,m7,m8,m10)
    #define BLAKE2S_LOAD_MSG_9_2(buf) buf = VectorSet32<5,6,4,2>(m5,m6,m4,m2)
    #define BLAKE2S_LOAD_MSG_9_3(buf) buf = VectorSet32<13,3,9,15>(m13,m3,m9,m15)
    #define BLAKE2S_LOAD_MSG_9_4(buf) buf = VectorSet32<0,12,14,11>(m0,m12,m14,m11)

    #define vec_ror_16(x) VecRotateRight<16>(x)
    #define vec_ror_12(x) VecRotateRight<12>(x)
    #define vec_ror_8(x)  VecRotateRight<8>(x)
    #define vec_ror_7(x)  VecRotateRight<7>(x)

    #define BLAKE2S_G1(row1,row2,row3,row4,buf) \
      row1 = VecAdd(VecAdd(row1, buf), row2); \
      row4 = VecXor(row4, row1); \
      row4 = vec_ror_16(row4); \
      row3 = VecAdd(row3, row4);   \
      row2 = VecXor(row2, row3); \
      row2 = vec_ror_12(row2);

    #define BLAKE2S_G2(row1,row2,row3,row4,buf) \
      row1 = VecAdd(VecAdd(row1, buf), row2); \
      row4 = VecXor(row4, row1); \
      row4 = vec_ror_8(row4); \
      row3 = VecAdd(row3, row4);   \
      row2 = VecXor(row2, row3); \
      row2 = vec_ror_7(row2);

    const uint8x16_p D2103_MASK = {12,13,14,15, 0,1,2,3, 4,5,6,7, 8,9,10,11};
    const uint8x16_p D1032_MASK = {8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7};
    const uint8x16_p D0321_MASK = {4,5,6,7, 8,9,10,11, 12,13,14,15, 0,1,2,3};

    #define BLAKE2S_DIAGONALIZE(row1,row2,row3,row4) \
      row4 = VecPermute(row4, row4, D2103_MASK); \
      row3 = VecPermute(row3, row3, D1032_MASK); \
      row2 = VecPermute(row2, row2, D0321_MASK);

    #define BLAKE2S_UNDIAGONALIZE(row1,row2,row3,row4) \
      row4 = VecPermute(row4, row4, D0321_MASK); \
      row3 = VecPermute(row3, row3, D1032_MASK); \
      row2 = VecPermute(row2, row2, D2103_MASK);

    #define BLAKE2S_ROUND(r)  \
      BLAKE2S_LOAD_MSG_ ##r ##_1(buf1); \
      BLAKE2S_G1(row1,row2,row3,row4,buf1); \
      BLAKE2S_LOAD_MSG_ ##r ##_2(buf2); \
      BLAKE2S_G2(row1,row2,row3,row4,buf2); \
      BLAKE2S_DIAGONALIZE(row1,row2,row3,row4); \
      BLAKE2S_LOAD_MSG_ ##r ##_3(buf3); \
      BLAKE2S_G1(row1,row2,row3,row4,buf3); \
      BLAKE2S_LOAD_MSG_ ##r ##_4(buf4); \
      BLAKE2S_G2(row1,row2,row3,row4,buf4); \
      BLAKE2S_UNDIAGONALIZE(row1,row2,row3,row4);

    // Possibly unaligned user messages
    uint32x4_p m0, m4, m8, m12;
    // Endian conversion mask
    const uint8x16_p le_mask = {3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12};

#if defined(_ARCH_PWR9)
    // POWER9 provides loads for char's and short's
    m0 = (uint32x4_p) vec_xl(  0, CONST_V8_CAST( input ));
    m4 = (uint32x4_p) vec_xl( 16, CONST_V8_CAST( input ));
    m8 = (uint32x4_p) vec_xl( 32, CONST_V8_CAST( input ));
    m12 = (uint32x4_p) vec_xl( 48, CONST_V8_CAST( input ));

# if defined(CRYPTOPP_BIG_ENDIAN)
    m0 = vec_perm(m0, m0, le_mask);
    m4 = vec_perm(m4, m4, le_mask);
    m8 = vec_perm(m8, m8, le_mask);
    m12 = vec_perm(m12, m12, le_mask);
# endif
#else
    // Altivec only provides 16-byte aligned loads
    // http://www.nxp.com/docs/en/reference-manual/ALTIVECPEM.pdf
    m0 = (uint32x4_p) vec_ld(  0, CONST_V8_CAST( input ));
    m4 = (uint32x4_p) vec_ld( 16, CONST_V8_CAST( input ));
    m8 = (uint32x4_p) vec_ld( 32, CONST_V8_CAST( input ));
    m12 = (uint32x4_p) vec_ld( 48, CONST_V8_CAST( input ));

    // Alignment check for load of the message buffer
    const uintptr_t addr = (uintptr_t)input;
    if (addr%16 == 0)
    {
        // Already aligned. Perform a little-endian swap as required
# if defined(CRYPTOPP_BIG_ENDIAN)
        m0 = vec_perm(m0, m0, le_mask);
        m4 = vec_perm(m4, m4, le_mask);
        m8 = vec_perm(m8, m8, le_mask);
        m12 = vec_perm(m12, m12, le_mask);
# endif
    }
    else
    {
        // Not aligned. Fix vectors and perform a little-endian swap as required
        // http://mirror.informatimago.com/next/developer.apple.com/
        //        hardwaredrivers/ve/code_optimization.html
        uint32x4_p ex; uint8x16_p perm;
        ex = (uint32x4_p) vec_ld(48+15, CONST_V8_CAST( input ));
        perm = vec_lvsl(0, CONST_V8_CAST( addr ));

# if defined(CRYPTOPP_BIG_ENDIAN)
        // Combine the vector permute with the little-endian swap
        perm = vec_perm(perm, perm, le_mask);
# endif

        m0 = vec_perm(m0, m4, perm);
        m4 = vec_perm(m4, m8, perm);
        m8 = vec_perm(m8, m12, perm);
        m12 = vec_perm(m12, ex, perm);
    }
#endif

    uint32x4_p row1, row2, row3, row4;
    uint32x4_p buf1, buf2, buf3, buf4;
    uint32x4_p  ff0,  ff1;

    row1 = ff0 = VecLoad32LE(state.h()+0, le_mask);
    row2 = ff1 = VecLoad32LE(state.h()+4, le_mask);
    row3 = VecLoad32(BLAKE2S_IV+0);
    row4 = VecXor(VecLoad32(BLAKE2S_IV+4), VecLoad32(state.t()+0));

    BLAKE2S_ROUND(0);
    BLAKE2S_ROUND(1);
    BLAKE2S_ROUND(2);
    BLAKE2S_ROUND(3);
    BLAKE2S_ROUND(4);
    BLAKE2S_ROUND(5);
    BLAKE2S_ROUND(6);
    BLAKE2S_ROUND(7);
    BLAKE2S_ROUND(8);
    BLAKE2S_ROUND(9);

    VecStore32LE(state.h()+0, VecXor(ff0, VecXor(row1, row3)), le_mask);
    VecStore32LE(state.h()+4, VecXor(ff1, VecXor(row2, row4)), le_mask);
}
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE

NAMESPACE_END
