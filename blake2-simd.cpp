// blake2-simd.cpp - written and placed in the public domain by
//                   Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to ARMv7a/ARMv8a
//    NEON and SSE4.2 instructions. A separate source file is needed
//    because additional CXXFLAGS are required to enable the appropriate
//    instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"
#include "blake2.h"

// Uncomment for benchmarking C++ against SSE2 or NEON.
// Do so in both blake2.cpp and blake2-simd.cpp.
// #undef CRYPTOPP_SSE41_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

// Disable NEON/ASIMD for Cortex-A53 and A57. The shifts are too slow and C/C++ is about
// 3 cpb faster than NEON/ASIMD. Also see http://github.com/weidai11/cryptopp/issues/367.
#if (defined(__aarch32__) || defined(__aarch64__)) && defined(CRYPTOPP_SLOW_ARMV8_SHIFT)
# undef CRYPTOPP_ARM_NEON_AVAILABLE
#endif

#if (CRYPTOPP_SSE41_AVAILABLE)
# include <emmintrin.h>
# include <tmmintrin.h>
# include <smmintrin.h>
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

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

NAMESPACE_BEGIN(CryptoPP)

// Sun Studio 12.3 and earlier lack SSE2's _mm_set_epi64x. Win32 lacks _mm_set_epi64x,
// Win64 supplies it except for VS2008. See http://stackoverflow.com/a/38547909/608639
#if CRYPTOPP_SSE2_INTRIN_AVAILABLE && ((__SUNPRO_CC >= 0x5100 && __SUNPRO_CC < 0x5130) || \
	(defined(_MSC_VER) && _MSC_VER < 1600) || (defined(_M_IX86) && _MSC_VER >= 1600))
inline __m128i MM_SET_EPI64X(const word64 a, const word64 b)
{
    const word64 t[2] = {b,a}; __m128i r;
    std::memcpy(&r, t, sizeof(t));
    return r;
}
#else
# define MM_SET_EPI64X(a, b) _mm_set_epi64x(a, b)
#endif

ANONYMOUS_NAMESPACE_BEGIN

CRYPTOPP_ALIGN_DATA(16)
const word32 BLAKE2S_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

CRYPTOPP_ALIGN_DATA(16)
const word64 BLAKE2B_IV[8] = {
    W64LIT(0x6a09e667f3bcc908), W64LIT(0xbb67ae8584caa73b),
    W64LIT(0x3c6ef372fe94f82b), W64LIT(0xa54ff53a5f1d36f1),
    W64LIT(0x510e527fade682d1), W64LIT(0x9b05688c2b3e6c1f),
    W64LIT(0x1f83d9abfb41bd6b), W64LIT(0x5be0cd19137e2179)
};

ANONYMOUS_NAMESPACE_END

#if CRYPTOPP_SSE41_AVAILABLE
void BLAKE2_Compress32_SSE4(const byte* input, BLAKE2_State<word32, false>& state)
{
  __m128i row1, row2, row3, row4;
  __m128i buf1, buf2, buf3, buf4;

  __m128i t0, t1, t2;
  __m128i ff0, ff1;

  const __m128i r8 = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1);
  const __m128i r16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);

  const __m128i m0 = _mm_loadu_si128(CONST_M128_CAST(input + 00));
  const __m128i m1 = _mm_loadu_si128(CONST_M128_CAST(input + 16));
  const __m128i m2 = _mm_loadu_si128(CONST_M128_CAST(input + 32));
  const __m128i m3 = _mm_loadu_si128(CONST_M128_CAST(input + 48));

  row1 = ff0 = _mm_loadu_si128(CONST_M128_CAST(&state.h[0]));
  row2 = ff1 = _mm_loadu_si128(CONST_M128_CAST(&state.h[4]));
  row3 = _mm_setr_epi32(BLAKE2S_IV[0], BLAKE2S_IV[1], BLAKE2S_IV[2], BLAKE2S_IV[3]);
  row4 = _mm_xor_si128(_mm_setr_epi32(BLAKE2S_IV[4], BLAKE2S_IV[5], BLAKE2S_IV[6], BLAKE2S_IV[7]), _mm_loadu_si128(CONST_M128_CAST(&state.t[0])));
  buf1 = _mm_castps_si128((_mm_shuffle_ps(_mm_castsi128_ps((m0)), _mm_castsi128_ps((m1)), _MM_SHUFFLE(2,0,2,0))));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  buf2 = _mm_castps_si128((_mm_shuffle_ps(_mm_castsi128_ps((m0)), _mm_castsi128_ps((m1)), _MM_SHUFFLE(3,1,3,1))));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_castps_si128((_mm_shuffle_ps(_mm_castsi128_ps((m2)), _mm_castsi128_ps((m3)), _MM_SHUFFLE(2,0,2,0))));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  buf4 = _mm_castps_si128((_mm_shuffle_ps(_mm_castsi128_ps((m2)), _mm_castsi128_ps((m3)), _MM_SHUFFLE(3,1,3,1))));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_blend_epi16(m1, m2, 0x0C);
  t1 = _mm_slli_si128(m3, 4);
  t2 = _mm_blend_epi16(t0, t1, 0xF0);
  buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_shuffle_epi32(m2,_MM_SHUFFLE(0,0,2,0));
  t1 = _mm_blend_epi16(m1,m3,0xC0);
  t2 = _mm_blend_epi16(t0, t1, 0xF0);
  buf2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_slli_si128(m1, 4);
  t1 = _mm_blend_epi16(m2, t0, 0x30);
  t2 = _mm_blend_epi16(m0, t1, 0xF0);
  buf3 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_unpackhi_epi32(m0,m1);
  t1 = _mm_slli_si128(m3, 4);
  t2 = _mm_blend_epi16(t0, t1, 0x0C);
  buf4 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_unpackhi_epi32(m2,m3);
  t1 = _mm_blend_epi16(m3,m1,0x0C);
  t2 = _mm_blend_epi16(t0, t1, 0x0F);
  buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_unpacklo_epi32(m2,m0);
  t1 = _mm_blend_epi16(t0, m0, 0xF0);
  t2 = _mm_slli_si128(m3, 8);
  buf2 = _mm_blend_epi16(t1, t2, 0xC0);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_blend_epi16(m0, m2, 0x3C);
  t1 = _mm_srli_si128(m1, 12);
  t2 = _mm_blend_epi16(t0,t1,0x03);
  buf3 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,0,3,2));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_slli_si128(m3, 4);
  t1 = _mm_blend_epi16(m0, m1, 0x33);
  t2 = _mm_blend_epi16(t1, t0, 0xC0);
  buf4 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(0,1,2,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_unpackhi_epi32(m0,m1);
  t1 = _mm_unpackhi_epi32(t0, m2);
  t2 = _mm_blend_epi16(t1, m3, 0x0C);
  buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_slli_si128(m2, 8);
  t1 = _mm_blend_epi16(m3,m0,0x0C);
  t2 = _mm_blend_epi16(t1, t0, 0xC0);
  buf2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,1,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_blend_epi16(m0,m1,0x0F);
  t1 = _mm_blend_epi16(t0, m3, 0xC0);
  buf3 = _mm_shuffle_epi32(t1, _MM_SHUFFLE(3,0,1,2));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_unpacklo_epi32(m0,m2);
  t1 = _mm_unpackhi_epi32(m1,m2);
  buf4 = _mm_unpacklo_epi64(t1,t0);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_unpacklo_epi64(m1,m2);
  t1 = _mm_unpackhi_epi64(m0,m2);
  t2 = _mm_blend_epi16(t0,t1,0x33);
  buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,1,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_unpackhi_epi64(m1,m3);
  t1 = _mm_unpacklo_epi64(m0,m1);
  buf2 = _mm_blend_epi16(t0,t1,0x33);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_unpackhi_epi64(m3,m1);
  t1 = _mm_unpackhi_epi64(m2,m0);
  buf3 = _mm_blend_epi16(t1,t0,0x33);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_blend_epi16(m0,m2,0x03);
  t1 = _mm_slli_si128(t0, 8);
  t2 = _mm_blend_epi16(t1,m3,0x0F);
  buf4 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,2,0,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_unpackhi_epi32(m0,m1);
  t1 = _mm_unpacklo_epi32(m0,m2);
  buf1 = _mm_unpacklo_epi64(t0,t1);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_srli_si128(m2, 4);
  t1 = _mm_blend_epi16(m0,m3,0x03);
  buf2 = _mm_blend_epi16(t1,t0,0x3C);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_blend_epi16(m1,m0,0x0C);
  t1 = _mm_srli_si128(m3, 4);
  t2 = _mm_blend_epi16(t0,t1,0x30);
  buf3 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,2,3,0));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_unpacklo_epi64(m1,m2);
  t1= _mm_shuffle_epi32(m3, _MM_SHUFFLE(0,2,0,1));
  buf4 = _mm_blend_epi16(t0,t1,0x33);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_slli_si128(m1, 12);
  t1 = _mm_blend_epi16(m0,m3,0x33);
  buf1 = _mm_blend_epi16(t1,t0,0xC0);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_blend_epi16(m3,m2,0x30);
  t1 = _mm_srli_si128(m1, 4);
  t2 = _mm_blend_epi16(t0,t1,0x03);
  buf2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,3,0));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_unpacklo_epi64(m0,m2);
  t1 = _mm_srli_si128(m1, 4);
  buf3 = _mm_shuffle_epi32(_mm_blend_epi16(t0,t1,0x0C), _MM_SHUFFLE(2,3,1,0));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_unpackhi_epi32(m1,m2);
  t1 = _mm_unpackhi_epi64(m0,t0);
  buf4 = _mm_shuffle_epi32(t1, _MM_SHUFFLE(3,0,1,2));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_unpackhi_epi32(m0,m1);
  t1 = _mm_blend_epi16(t0,m3,0x0F);
  buf1 = _mm_shuffle_epi32(t1,_MM_SHUFFLE(2,0,3,1));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_blend_epi16(m2,m3,0x30);
  t1 = _mm_srli_si128(m0,4);
  t2 = _mm_blend_epi16(t0,t1,0x03);
  buf2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,0,2,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_unpackhi_epi64(m0,m3);
  t1 = _mm_unpacklo_epi64(m1,m2);
  t2 = _mm_blend_epi16(t0,t1,0x3C);
  buf3 = _mm_shuffle_epi32(t2,_MM_SHUFFLE(0,2,3,1));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_unpacklo_epi32(m0,m1);
  t1 = _mm_unpackhi_epi32(m1,m2);
  buf4 = _mm_unpacklo_epi64(t0,t1);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_unpackhi_epi32(m1,m3);
  t1 = _mm_unpacklo_epi64(t0,m0);
  t2 = _mm_blend_epi16(t1,m2,0xC0);
  buf1 = _mm_shufflehi_epi16(t2,_MM_SHUFFLE(1,0,3,2));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_unpackhi_epi32(m0,m3);
  t1 = _mm_blend_epi16(m2,t0,0xF0);
  buf2 = _mm_shuffle_epi32(t1,_MM_SHUFFLE(0,2,1,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_blend_epi16(m2,m0,0x0C);
  t1 = _mm_slli_si128(t0,4);
  buf3 = _mm_blend_epi16(t1,m3,0x0F);

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_blend_epi16(m1,m0,0x30);
  buf4 = _mm_shuffle_epi32(t0,_MM_SHUFFLE(1,0,3,2));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  t0 = _mm_blend_epi16(m0,m2,0x03);
  t1 = _mm_blend_epi16(m1,m2,0x30);
  t2 = _mm_blend_epi16(t1,t0,0x0F);
  buf1 = _mm_shuffle_epi32(t2,_MM_SHUFFLE(1,3,0,2));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_slli_si128(m0,4);
  t1 = _mm_blend_epi16(m1,t0,0xC0);
  buf2 = _mm_shuffle_epi32(t1,_MM_SHUFFLE(1,2,0,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0,3,2,1));

  t0 = _mm_unpackhi_epi32(m0,m3);
  t1 = _mm_unpacklo_epi32(m2,m3);
  t2 = _mm_unpackhi_epi64(t0,t1);
  buf3 = _mm_shuffle_epi32(t2,_MM_SHUFFLE(3,0,2,1));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r16);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 12),_mm_slli_epi32(row2, 20));

  t0 = _mm_blend_epi16(m3,m2,0xC0);
  t1 = _mm_unpacklo_epi32(m0,m3);
  t2 = _mm_blend_epi16(t0,t1,0x0F);
  buf4 = _mm_shuffle_epi32(t2,_MM_SHUFFLE(0,1,2,3));

  row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
  row4 = _mm_xor_si128(row4, row1);
  row4 = _mm_shuffle_epi8(row4,r8);
  row3 = _mm_add_epi32(row3, row4);
  row2 = _mm_xor_si128(row2, row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2, 7),_mm_slli_epi32(row2, 25));

  row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2,1,0,3));

  _mm_storeu_si128(M128_CAST(&state.h[0]), _mm_xor_si128(ff0, _mm_xor_si128(row1, row3)));
  _mm_storeu_si128(M128_CAST(&state.h[4]), _mm_xor_si128(ff1, _mm_xor_si128(row2, row4)));
}

void BLAKE2_Compress64_SSE4(const byte* input, BLAKE2_State<word64, true>& state)
{
  __m128i row1l, row1h;
  __m128i row2l, row2h;
  __m128i row3l, row3h;
  __m128i row4l, row4h;
  __m128i b0, b1, t0, t1;

  const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
  const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);

  const __m128i m0 = _mm_loadu_si128(CONST_M128_CAST(input + 00));
  const __m128i m1 = _mm_loadu_si128(CONST_M128_CAST(input + 16));
  const __m128i m2 = _mm_loadu_si128(CONST_M128_CAST(input + 32));
  const __m128i m3 = _mm_loadu_si128(CONST_M128_CAST(input + 48));
  const __m128i m4 = _mm_loadu_si128(CONST_M128_CAST(input + 64));
  const __m128i m5 = _mm_loadu_si128(CONST_M128_CAST(input + 80));
  const __m128i m6 = _mm_loadu_si128(CONST_M128_CAST(input + 96));
  const __m128i m7 = _mm_loadu_si128(CONST_M128_CAST(input + 112));

  row1l = _mm_loadu_si128(CONST_M128_CAST(&state.h[0]));
  row1h = _mm_loadu_si128(CONST_M128_CAST(&state.h[2]));
  row2l = _mm_loadu_si128(CONST_M128_CAST(&state.h[4]));
  row2h = _mm_loadu_si128(CONST_M128_CAST(&state.h[6]));
  row3l = _mm_loadu_si128(CONST_M128_CAST(&BLAKE2B_IV[0]));
  row3h = _mm_loadu_si128(CONST_M128_CAST(&BLAKE2B_IV[2]));
  row4l = _mm_xor_si128(_mm_loadu_si128(CONST_M128_CAST(&BLAKE2B_IV[4])), _mm_loadu_si128(CONST_M128_CAST(&state.t[0])));
  row4h = _mm_xor_si128(_mm_loadu_si128(CONST_M128_CAST(&BLAKE2B_IV[6])), _mm_loadu_si128(CONST_M128_CAST(&state.f[0])));

  b0 = _mm_unpacklo_epi64(m0, m1);
  b1 = _mm_unpacklo_epi64(m2, m3);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m0, m1);
  b1 = _mm_unpackhi_epi64(m2, m3);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m4, m5);
  b1 = _mm_unpacklo_epi64(m6, m7);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m4, m5);
  b1 = _mm_unpackhi_epi64(m6, m7);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m7, m2);
  b1 = _mm_unpackhi_epi64(m4, m6);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m5, m4);
  b1 = _mm_alignr_epi8(m3, m7, 8);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1,0,3,2));
  b1 = _mm_unpackhi_epi64(m5, m2);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m6, m1);
  b1 = _mm_unpackhi_epi64(m3, m1);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_alignr_epi8(m6, m5, 8);
  b1 = _mm_unpackhi_epi64(m2, m7);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m4, m0);
  b1 = _mm_blend_epi16(m1, m6, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_blend_epi16(m5, m1, 0xF0);
  b1 = _mm_unpackhi_epi64(m3, m4);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m7, m3);
  b1 = _mm_alignr_epi8(m2, m0, 8);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpackhi_epi64(m3, m1);
  b1 = _mm_unpackhi_epi64(m6, m5);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m4, m0);
  b1 = _mm_unpacklo_epi64(m6, m7);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_blend_epi16(m1, m2, 0xF0);
  b1 = _mm_blend_epi16(m2, m7, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m3, m5);
  b1 = _mm_unpacklo_epi64(m0, m4);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpackhi_epi64(m4, m2);
  b1 = _mm_unpacklo_epi64(m1, m5);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_blend_epi16(m0, m3, 0xF0);
  b1 = _mm_blend_epi16(m2, m7, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_blend_epi16(m7, m5, 0xF0);
  b1 = _mm_blend_epi16(m3, m1, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_alignr_epi8(m6, m0, 8);
  b1 = _mm_blend_epi16(m4, m6, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m1, m3);
  b1 = _mm_unpacklo_epi64(m0, m4);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m6, m5);
  b1 = _mm_unpackhi_epi64(m5, m1);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_blend_epi16(m2, m3, 0xF0);
  b1 = _mm_unpackhi_epi64(m7, m0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m6, m2);
  b1 = _mm_blend_epi16(m7, m4, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_blend_epi16(m6, m0, 0xF0);
  b1 = _mm_unpacklo_epi64(m7, m2);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m2, m7);
  b1 = _mm_alignr_epi8(m5, m6, 8);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m0, m3);
  b1 = _mm_shuffle_epi32(m4, _MM_SHUFFLE(1,0,3,2));

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m3, m1);
  b1 = _mm_blend_epi16(m1, m5, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpackhi_epi64(m6, m3);
  b1 = _mm_blend_epi16(m6, m1, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_alignr_epi8(m7, m5, 8);
  b1 = _mm_unpackhi_epi64(m0, m4);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpackhi_epi64(m2, m7);
  b1 = _mm_unpacklo_epi64(m4, m1);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m0, m2);
  b1 = _mm_unpacklo_epi64(m3, m5);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m3, m7);
  b1 = _mm_alignr_epi8(m0, m5, 8);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m7, m4);
  b1 = _mm_alignr_epi8(m4, m1, 8);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = m6;
  b1 = _mm_alignr_epi8(m5, m0, 8);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_blend_epi16(m1, m3, 0xF0);
  b1 = m2;

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m5, m4);
  b1 = _mm_unpackhi_epi64(m3, m0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m1, m2);
  b1 = _mm_blend_epi16(m3, m2, 0xF0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpackhi_epi64(m7, m4);
  b1 = _mm_unpackhi_epi64(m1, m6);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_alignr_epi8(m7, m5, 8);
  b1 = _mm_unpacklo_epi64(m6, m0);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m0, m1);
  b1 = _mm_unpacklo_epi64(m2, m3);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m0, m1);
  b1 = _mm_unpackhi_epi64(m2, m3);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m4, m5);
  b1 = _mm_unpacklo_epi64(m6, m7);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpackhi_epi64(m4, m5);
  b1 = _mm_unpackhi_epi64(m6, m7);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_unpacklo_epi64(m7, m2);
  b1 = _mm_unpackhi_epi64(m4, m6);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m5, m4);
  b1 = _mm_alignr_epi8(m3, m7, 8);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2h, row2l, 8);
  t1 = _mm_alignr_epi8(row2l, row2h, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4h, row4l, 8);
  t1 = _mm_alignr_epi8(row4l, row4h, 8);
  row4l = t1, row4h = t0;

  b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1,0,3,2));
  b1 = _mm_unpackhi_epi64(m5, m2);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi32(row4l, _MM_SHUFFLE(2,3,0,1));
  row4h = _mm_shuffle_epi32(row4h, _MM_SHUFFLE(2,3,0,1));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_shuffle_epi8(row2l, r24);
  row2h = _mm_shuffle_epi8(row2h, r24);

  b0 = _mm_unpacklo_epi64(m6, m1);
  b1 = _mm_unpackhi_epi64(m3, m1);

  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_shuffle_epi8(row4l, r16);
  row4h = _mm_shuffle_epi8(row4h, r16);
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l, 63), _mm_add_epi64(row2l, row2l));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h, 63), _mm_add_epi64(row2h, row2h));

  t0 = _mm_alignr_epi8(row2l, row2h, 8);
  t1 = _mm_alignr_epi8(row2h, row2l, 8);
  row2l = t0, row2h = t1, t0 = row3l, row3l = row3h, row3h = t0;
  t0 = _mm_alignr_epi8(row4l, row4h, 8);
  t1 = _mm_alignr_epi8(row4h, row4l, 8);
  row4l = t1, row4h = t0;

  row1l = _mm_xor_si128(row3l, row1l);
  row1h = _mm_xor_si128(row3h, row1h);
  _mm_storeu_si128(M128_CAST(&state.h[0]), _mm_xor_si128(_mm_loadu_si128(CONST_M128_CAST(&state.h[0])), row1l));
  _mm_storeu_si128(M128_CAST(&state.h[2]), _mm_xor_si128(_mm_loadu_si128(CONST_M128_CAST(&state.h[2])), row1h));

  row2l = _mm_xor_si128(row4l, row2l);
  row2h = _mm_xor_si128(row4h, row2h);
  _mm_storeu_si128(M128_CAST(&state.h[4]), _mm_xor_si128(_mm_loadu_si128(CONST_M128_CAST(&state.h[4])), row2l));
  _mm_storeu_si128(M128_CAST(&state.h[6]), _mm_xor_si128(_mm_loadu_si128(CONST_M128_CAST(&state.h[6])), row2h));
}
#endif  // CRYPTOPP_SSE41_AVAILABLE

#if CRYPTOPP_ARM_NEON_AVAILABLE
void BLAKE2_Compress32_NEON(const byte* input, BLAKE2_State<word32, false>& state)
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

    CRYPTOPP_ASSERT(IsAlignedOn(&state.h[0],GetAlignmentOf<uint32x4_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(&state.t[0],GetAlignmentOf<uint32x4_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(&state.f[0],GetAlignmentOf<uint32x4_t>()));

    const uint32x4_t m0 = vreinterpretq_u32_u8(vld1q_u8((input + 00)));
    const uint32x4_t m1 = vreinterpretq_u32_u8(vld1q_u8((input + 16)));
    const uint32x4_t m2 = vreinterpretq_u32_u8(vld1q_u8((input + 32)));
    const uint32x4_t m3 = vreinterpretq_u32_u8(vld1q_u8((input + 48)));

    uint32x4_t row1, row2, row3, row4;

    const uint32x4_t f0 = row1 = vld1q_u32(&state.h[0]);
    const uint32x4_t f1 = row2 = vld1q_u32(&state.h[4]);
    row3 = vld1q_u32(&BLAKE2S_IV[0]);
    row4 = veorq_u32(vld1q_u32(&BLAKE2S_IV[4]), vld1q_u32(&state.t[0]));

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

    vst1q_u32(&state.h[0], veorq_u32(f0, veorq_u32(row1, row3)));
    vst1q_u32(&state.h[4], veorq_u32(f1, veorq_u32(row2, row4)));
}

void BLAKE2_Compress64_NEON(const byte* input, BLAKE2_State<word64, true>& state)
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

    #define vrorq_n_u64_24(x) vcombine_u64(\
        vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 3)), \
        vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 3)))

    #define vrorq_n_u64_16(x) vcombine_u64(\
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

    CRYPTOPP_ASSERT(IsAlignedOn(&state.h[0],GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(&state.t[0],GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(&state.f[0],GetAlignmentOf<uint64x2_t>()));

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

    const uint64x2_t h0 = row1l = vld1q_u64(&state.h[0]);
    const uint64x2_t h1 = row1h = vld1q_u64(&state.h[2]);
    const uint64x2_t h2 = row2l = vld1q_u64(&state.h[4]);
    const uint64x2_t h3 = row2h = vld1q_u64(&state.h[6]);

    row3l = vld1q_u64(&BLAKE2B_IV[0]);
    row3h = vld1q_u64(&BLAKE2B_IV[2]);
    row4l = veorq_u64(vld1q_u64(&BLAKE2B_IV[4]), vld1q_u64(&state.t[0]));
    row4h = veorq_u64(vld1q_u64(&BLAKE2B_IV[6]), vld1q_u64(&state.f[0]));

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

    vst1q_u64(&state.h[0], veorq_u64(h0, veorq_u64(row1l, row3l)));
    vst1q_u64(&state.h[2], veorq_u64(h1, veorq_u64(row1h, row3h)));
    vst1q_u64(&state.h[4], veorq_u64(h2, veorq_u64(row2l, row4l)));
    vst1q_u64(&state.h[6], veorq_u64(h3, veorq_u64(row2h, row4h)));
}
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

NAMESPACE_END
