// shacla2-simd.cpp - written and placed in the public domain by
//                    Jeffrey Walton and Jack Lloyd
//
//    Jack Lloyd and the Botan team allowed Crypto++ to use parts of
//    Botan's implementation under the same license as Crypto++
//    is released. The code for SHACAL2_Enc_ProcessAndXorBlock_SHANI
//    below is Botan's x86_encrypt_blocks with minor tweaks. Many thanks
//    to the Botan team. Also see http://github.com/randombit/botan/.
//
//    This source file uses intrinsics to gain access to SHA-NI and
//    ARMv8a SHA instructions. A separate source file is needed because
//    additional CXXFLAGS are required to enable the appropriate instruction
//    sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "sha.h"
#include "misc.h"

#if (CRYPTOPP_SHANI_AVAILABLE)
# include <nmmintrin.h>
# include <immintrin.h>
#endif

// Clang intrinsic casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

// Squash MS LNK4221 and libtool warnings
extern const char SHACAL2_SIMD_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

#if CRYPTOPP_SHANI_AVAILABLE
void SHACAL2_Enc_ProcessAndXorBlock_SHANI(const word32* subKeys, const byte *inBlock, const byte *xorBlock, byte *outBlock)
{
	CRYPTOPP_ASSERT(subKeys);
	CRYPTOPP_ASSERT(inBlock);
	CRYPTOPP_ASSERT(outBlock);

	const __m128i MASK1 = _mm_set_epi8(8,9,10,11,  12,13,14,15,  0,1,2,3,  4,5,6,7);
	const __m128i MASK2 = _mm_set_epi8(0,1,2,3,  4,5,6,7,  8,9,10,11,  12,13,14,15);

	__m128i B0 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(inBlock + 0)), MASK1);
	__m128i B1 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(inBlock + 16)), MASK2);

	__m128i TMP = _mm_alignr_epi8(B0, B1, 8);
	B1 = _mm_blend_epi16(B1, B0, 0xF0);
	B0 = TMP;

#if 0
	// SSE2 + SSSE3, but 0.2 cpb slower on a Celeraon J3455
	const __m128i MASK1 = _mm_set_epi8(8,9,10,11,  12,13,14,15,  0,1,2,3,  4,5,6,7);
	const __m128i MASK2 = _mm_set_epi8(0,1,2,3,  4,5,6,7,  8,9,10,11,  12,13,14,15);

	__m128i B0 = _mm_loadu_si128(CONST_M128_CAST(inBlock + 0));
	__m128i B1 = _mm_loadu_si128(CONST_M128_CAST(inBlock + 16));

	__m128i TMP = _mm_shuffle_epi8(_mm_unpacklo_epi64(B0, B1), MASK2);
	B1 = _mm_shuffle_epi8(_mm_unpackhi_epi64(B0, B1), MASK2);
	B0 = TMP;
#endif

	const byte* keys = reinterpret_cast<const byte*>(subKeys);
	for (size_t i = 0; i != 8; ++i)
	{
		const __m128i RK0 = _mm_load_si128(CONST_M128_CAST(keys + 32*i));
		const __m128i RK2 = _mm_load_si128(CONST_M128_CAST(keys + 32*i+16));
		const __m128i RK1 = _mm_srli_si128(RK0, 8);
		const __m128i RK3 = _mm_srli_si128(RK2, 8);

		B1 = _mm_sha256rnds2_epu32(B1, B0, RK0);
		B0 = _mm_sha256rnds2_epu32(B0, B1, RK1);
		B1 = _mm_sha256rnds2_epu32(B1, B0, RK2);
		B0 = _mm_sha256rnds2_epu32(B0, B1, RK3);
	}

	TMP = _mm_shuffle_epi8(_mm_unpackhi_epi64(B0, B1), MASK1);
	B1 = _mm_shuffle_epi8(_mm_unpacklo_epi64(B0, B1), MASK1);
	B0 = TMP;

	if (xorBlock)
	{
		_mm_storeu_si128(M128_CAST(outBlock + 0),
			_mm_xor_si128(B0, _mm_loadu_si128(CONST_M128_CAST(xorBlock + 0))));

		_mm_storeu_si128(M128_CAST(outBlock + 16),
			_mm_xor_si128(B1, _mm_loadu_si128(CONST_M128_CAST(xorBlock + 16))));
	}
	else
	{
		_mm_storeu_si128(M128_CAST(outBlock + 0), B0);
		_mm_storeu_si128(M128_CAST(outBlock + 16), B1);
	}
}
#endif

NAMESPACE_END
