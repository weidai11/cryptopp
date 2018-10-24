// chacha-simd.cpp - written and placed in the public domain by
//                   Jack Lloyd and Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    SSE2, ARM NEON and ARMv8a, and Power7 Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.
//
//    SSE2 implementation based on Botan's chacha_sse2.cpp. Many thanks
//    to Jack Lloyd and the Botan team for allowing us to use it.
//
//    NEON and Power7 is upcoming.

#include "pch.h"
#include "config.h"

#include "chacha.h"
#include "misc.h"

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)
# include <xmmintrin.h>
# include <emmintrin.h>
#endif

#if (CRYPTOPP_SSSE3_INTRIN_AVAILABLE || CRYPTOPP_SSSE3_ASM_AVAILABLE)
# include <tmmintrin.h>
#endif

#ifdef __XOP__
# include <ammintrin.h>
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

// Squash MS LNK4221 and libtool warnings
extern const char CHACHA_SIMD_FNAME[] = __FILE__;

ANONYMOUS_NAMESPACE_BEGIN

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)

template <unsigned int R>
inline __m128i RotateLeft(const __m128i val)
{
#ifdef __XOP__
	return _mm_roti_epi32(val, R);
#else
	return _mm_or_si128(_mm_slli_epi32(val, R), _mm_srli_epi32(val, 32-R));
#endif
}

#if defined(__SSSE3__)
template <>
inline __m128i RotateLeft<8>(const __m128i val)
{
#ifdef __XOP__
	return _mm_roti_epi32(val, 8);
#else
	const __m128i mask = _mm_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
	return _mm_shuffle_epi8(val, mask);
#endif
}

template <>
inline __m128i RotateLeft<16>(const __m128i val)
{
#ifdef __XOP__
	return _mm_roti_epi32(val, 16);
#else
	const __m128i mask = _mm_set_epi8(13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2);
	return _mm_shuffle_epi8(val, mask);
#endif
}
#endif  // SSE3

#endif  // CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)

void ChaCha_OperateKeystream_SSE2(const word32 *state, const byte* input, byte *output, unsigned int rounds, bool xorInput)
{
	const __m128i* state_mm = reinterpret_cast<const __m128i*>(state);
	const __m128i* input_mm = reinterpret_cast<const __m128i*>(input);
	__m128i* output_mm = reinterpret_cast<__m128i*>(output);

	const __m128i state0 = _mm_load_si128(state_mm + 0);
	const __m128i state1 = _mm_load_si128(state_mm + 1);
	const __m128i state2 = _mm_load_si128(state_mm + 2);
	const __m128i state3 = _mm_load_si128(state_mm + 3);

	__m128i r0_0 = state0;
	__m128i r0_1 = state1;
	__m128i r0_2 = state2;
	__m128i r0_3 = state3;

	__m128i r1_0 = state0;
	__m128i r1_1 = state1;
	__m128i r1_2 = state2;
	__m128i r1_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 1));

	__m128i r2_0 = state0;
	__m128i r2_1 = state1;
	__m128i r2_2 = state2;
	__m128i r2_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 2));

	__m128i r3_0 = state0;
	__m128i r3_1 = state1;
	__m128i r3_2 = state2;
	__m128i r3_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 3));

	for (int i = static_cast<int>(rounds); i > 0; i -= 2)
	{
		r0_0 = _mm_add_epi32(r0_0, r0_1);
		r1_0 = _mm_add_epi32(r1_0, r1_1);
		r2_0 = _mm_add_epi32(r2_0, r2_1);
		r3_0 = _mm_add_epi32(r3_0, r3_1);

		r0_3 = _mm_xor_si128(r0_3, r0_0);
		r1_3 = _mm_xor_si128(r1_3, r1_0);
		r2_3 = _mm_xor_si128(r2_3, r2_0);
		r3_3 = _mm_xor_si128(r3_3, r3_0);

		r0_3 = RotateLeft<16>(r0_3);
		r1_3 = RotateLeft<16>(r1_3);
		r2_3 = RotateLeft<16>(r2_3);
		r3_3 = RotateLeft<16>(r3_3);

		r0_2 = _mm_add_epi32(r0_2, r0_3);
		r1_2 = _mm_add_epi32(r1_2, r1_3);
		r2_2 = _mm_add_epi32(r2_2, r2_3);
		r3_2 = _mm_add_epi32(r3_2, r3_3);

		r0_1 = _mm_xor_si128(r0_1, r0_2);
		r1_1 = _mm_xor_si128(r1_1, r1_2);
		r2_1 = _mm_xor_si128(r2_1, r2_2);
		r3_1 = _mm_xor_si128(r3_1, r3_2);

		r0_1 = RotateLeft<12>(r0_1);
		r1_1 = RotateLeft<12>(r1_1);
		r2_1 = RotateLeft<12>(r2_1);
		r3_1 = RotateLeft<12>(r3_1);

		r0_0 = _mm_add_epi32(r0_0, r0_1);
		r1_0 = _mm_add_epi32(r1_0, r1_1);
		r2_0 = _mm_add_epi32(r2_0, r2_1);
		r3_0 = _mm_add_epi32(r3_0, r3_1);

		r0_3 = _mm_xor_si128(r0_3, r0_0);
		r1_3 = _mm_xor_si128(r1_3, r1_0);
		r2_3 = _mm_xor_si128(r2_3, r2_0);
		r3_3 = _mm_xor_si128(r3_3, r3_0);

		r0_3 = RotateLeft<8>(r0_3);
		r1_3 = RotateLeft<8>(r1_3);
		r2_3 = RotateLeft<8>(r2_3);
		r3_3 = RotateLeft<8>(r3_3);

		r0_2 = _mm_add_epi32(r0_2, r0_3);
		r1_2 = _mm_add_epi32(r1_2, r1_3);
		r2_2 = _mm_add_epi32(r2_2, r2_3);
		r3_2 = _mm_add_epi32(r3_2, r3_3);

		r0_1 = _mm_xor_si128(r0_1, r0_2);
		r1_1 = _mm_xor_si128(r1_1, r1_2);
		r2_1 = _mm_xor_si128(r2_1, r2_2);
		r3_1 = _mm_xor_si128(r3_1, r3_2);

		r0_1 = RotateLeft<7>(r0_1);
		r1_1 = RotateLeft<7>(r1_1);
		r2_1 = RotateLeft<7>(r2_1);
		r3_1 = RotateLeft<7>(r3_1);

		r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(0, 3, 2, 1));
		r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
		r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(2, 1, 0, 3));

		r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(0, 3, 2, 1));
		r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
		r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(2, 1, 0, 3));

		r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(0, 3, 2, 1));
		r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
		r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(2, 1, 0, 3));

		r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(0, 3, 2, 1));
		r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
		r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(2, 1, 0, 3));

		r0_0 = _mm_add_epi32(r0_0, r0_1);
		r1_0 = _mm_add_epi32(r1_0, r1_1);
		r2_0 = _mm_add_epi32(r2_0, r2_1);
		r3_0 = _mm_add_epi32(r3_0, r3_1);

		r0_3 = _mm_xor_si128(r0_3, r0_0);
		r1_3 = _mm_xor_si128(r1_3, r1_0);
		r2_3 = _mm_xor_si128(r2_3, r2_0);
		r3_3 = _mm_xor_si128(r3_3, r3_0);

		r0_3 = RotateLeft<16>(r0_3);
		r1_3 = RotateLeft<16>(r1_3);
		r2_3 = RotateLeft<16>(r2_3);
		r3_3 = RotateLeft<16>(r3_3);

		r0_2 = _mm_add_epi32(r0_2, r0_3);
		r1_2 = _mm_add_epi32(r1_2, r1_3);
		r2_2 = _mm_add_epi32(r2_2, r2_3);
		r3_2 = _mm_add_epi32(r3_2, r3_3);

		r0_1 = _mm_xor_si128(r0_1, r0_2);
		r1_1 = _mm_xor_si128(r1_1, r1_2);
		r2_1 = _mm_xor_si128(r2_1, r2_2);
		r3_1 = _mm_xor_si128(r3_1, r3_2);

		r0_1 = RotateLeft<12>(r0_1);
		r1_1 = RotateLeft<12>(r1_1);
		r2_1 = RotateLeft<12>(r2_1);
		r3_1 = RotateLeft<12>(r3_1);

		r0_0 = _mm_add_epi32(r0_0, r0_1);
		r1_0 = _mm_add_epi32(r1_0, r1_1);
		r2_0 = _mm_add_epi32(r2_0, r2_1);
		r3_0 = _mm_add_epi32(r3_0, r3_1);

		r0_3 = _mm_xor_si128(r0_3, r0_0);
		r1_3 = _mm_xor_si128(r1_3, r1_0);
		r2_3 = _mm_xor_si128(r2_3, r2_0);
		r3_3 = _mm_xor_si128(r3_3, r3_0);

		r0_3 = RotateLeft<8>(r0_3);
		r1_3 = RotateLeft<8>(r1_3);
		r2_3 = RotateLeft<8>(r2_3);
		r3_3 = RotateLeft<8>(r3_3);

		r0_2 = _mm_add_epi32(r0_2, r0_3);
		r1_2 = _mm_add_epi32(r1_2, r1_3);
		r2_2 = _mm_add_epi32(r2_2, r2_3);
		r3_2 = _mm_add_epi32(r3_2, r3_3);

		r0_1 = _mm_xor_si128(r0_1, r0_2);
		r1_1 = _mm_xor_si128(r1_1, r1_2);
		r2_1 = _mm_xor_si128(r2_1, r2_2);
		r3_1 = _mm_xor_si128(r3_1, r3_2);

		r0_1 = RotateLeft<7>(r0_1);
		r1_1 = RotateLeft<7>(r1_1);
		r2_1 = RotateLeft<7>(r2_1);
		r3_1 = RotateLeft<7>(r3_1);

		r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(2, 1, 0, 3));
		r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
		r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(0, 3, 2, 1));

		r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(2, 1, 0, 3));
		r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
		r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(0, 3, 2, 1));

		r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(2, 1, 0, 3));
		r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
		r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(0, 3, 2, 1));

		r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(2, 1, 0, 3));
		r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
		r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(0, 3, 2, 1));
	}

	r0_0 = _mm_add_epi32(r0_0, state0);
	r0_1 = _mm_add_epi32(r0_1, state1);
	r0_2 = _mm_add_epi32(r0_2, state2);
	r0_3 = _mm_add_epi32(r0_3, state3);

	r1_0 = _mm_add_epi32(r1_0, state0);
	r1_1 = _mm_add_epi32(r1_1, state1);
	r1_2 = _mm_add_epi32(r1_2, state2);
	r1_3 = _mm_add_epi32(r1_3, state3);
	r1_3 = _mm_add_epi64(r1_3, _mm_set_epi32(0, 0, 0, 1));

	r2_0 = _mm_add_epi32(r2_0, state0);
	r2_1 = _mm_add_epi32(r2_1, state1);
	r2_2 = _mm_add_epi32(r2_2, state2);
	r2_3 = _mm_add_epi32(r2_3, state3);
	r2_3 = _mm_add_epi64(r2_3, _mm_set_epi32(0, 0, 0, 2));

	r3_0 = _mm_add_epi32(r3_0, state0);
	r3_1 = _mm_add_epi32(r3_1, state1);
	r3_2 = _mm_add_epi32(r3_2, state2);
	r3_3 = _mm_add_epi32(r3_3, state3);
	r3_3 = _mm_add_epi64(r3_3, _mm_set_epi32(0, 0, 0, 3));

	if (xorInput)
	{
		r0_0 = _mm_xor_si128(_mm_loadu_si128(input_mm + 0), r0_0);
		r0_1 = _mm_xor_si128(_mm_loadu_si128(input_mm + 1), r0_1);
		r0_2 = _mm_xor_si128(_mm_loadu_si128(input_mm + 2), r0_2);
		r0_3 = _mm_xor_si128(_mm_loadu_si128(input_mm + 3), r0_3);
	}

	_mm_storeu_si128(output_mm + 0, r0_0);
	_mm_storeu_si128(output_mm + 1, r0_1);
	_mm_storeu_si128(output_mm + 2, r0_2);
	_mm_storeu_si128(output_mm + 3, r0_3);

	if (xorInput)
	{
		r1_0 = _mm_xor_si128(_mm_loadu_si128(input_mm + 4), r1_0);
		r1_1 = _mm_xor_si128(_mm_loadu_si128(input_mm + 5), r1_1);
		r1_2 = _mm_xor_si128(_mm_loadu_si128(input_mm + 6), r1_2);
		r1_3 = _mm_xor_si128(_mm_loadu_si128(input_mm + 7), r1_3);
	}

	_mm_storeu_si128(output_mm + 4, r1_0);
	_mm_storeu_si128(output_mm + 5, r1_1);
	_mm_storeu_si128(output_mm + 6, r1_2);
	_mm_storeu_si128(output_mm + 7, r1_3);

	if (xorInput)
	{
		r2_0 = _mm_xor_si128(_mm_loadu_si128(input_mm + 8), r2_0);
		r2_1 = _mm_xor_si128(_mm_loadu_si128(input_mm + 9), r2_1);
		r2_2 = _mm_xor_si128(_mm_loadu_si128(input_mm + 10), r2_2);
		r2_3 = _mm_xor_si128(_mm_loadu_si128(input_mm + 11), r2_3);
	}

	_mm_storeu_si128(output_mm + 8, r2_0);
	_mm_storeu_si128(output_mm + 9, r2_1);
	_mm_storeu_si128(output_mm + 10, r2_2);
	_mm_storeu_si128(output_mm + 11, r2_3);

	if (xorInput)
	{
		r3_0 = _mm_xor_si128(_mm_loadu_si128(input_mm + 12), r3_0);
		r3_1 = _mm_xor_si128(_mm_loadu_si128(input_mm + 13), r3_1);
		r3_2 = _mm_xor_si128(_mm_loadu_si128(input_mm + 14), r3_2);
		r3_3 = _mm_xor_si128(_mm_loadu_si128(input_mm + 15), r3_3);
	}

	_mm_storeu_si128(output_mm + 12, r3_0);
	_mm_storeu_si128(output_mm + 13, r3_1);
	_mm_storeu_si128(output_mm + 14, r3_2);
	_mm_storeu_si128(output_mm + 15, r3_3);
}

#endif  // CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE

NAMESPACE_END
