// shacla2-simd.cpp - written and placed in the public domain by
//                    Jeffrey Walton and Jack Lloyd
//
//    Jack Lloyd is the author of Botan and allowed Crypto++ to use parts of
//    Botan's implementation under the same license as Crypto++ is released.
//    The code for SHACAL2_Enc_ProcessAndXorBlock_SHANI below is Botan's
//    x86_encrypt_blocks with minor tweaks. Many thanks to the Botan team.
//    Also see https://github.com/randombit/botan/pull/1151/files.
//
//    This source file uses intrinsics to gain access to SHA-NI and
//    ARMv8a SHA instructions. A separate source file is needed because
//    additional CXXFLAGS are required to enable the appropriate instructions
//    sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "sha.h"
#include "misc.h"

// Clang and GCC hoops...
#if !(defined(__ARM_FEATURE_CRYPTO) || defined(_MSC_VER))
# undef CRYPTOPP_ARM_SHA_AVAILABLE
#endif

#if (CRYPTOPP_SHANI_AVAILABLE)
# include "nmmintrin.h"
# include "immintrin.h"
#endif

#if (CRYPTOPP_ARM_SHA_AVAILABLE)
# include "arm_neon.h"
#endif

// Don't include <arm_acle.h> when using Apple Clang. Early Apple compilers
//  fail to compile with <arm_acle.h> included. Later Apple compilers compile
//  intrinsics without <arm_acle.h> included.
#if (CRYPTOPP_ARM_SHA_AVAILABLE) && !defined(CRYPTOPP_APPLE_CLANG_VERSION)
# include "arm_acle.h"
#endif

// Clang __m128i casts
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

NAMESPACE_BEGIN(CryptoPP)

#if CRYPTOPP_SHANI_AVAILABLE
void SHACAL2_Enc_ProcessAndXorBlock_SHANI(const word32* subKeys, const byte *inBlock, const byte *xorBlock, byte *outBlock)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlock);
    CRYPTOPP_ASSERT(outBlock);

	__m128i B0 = _mm_loadu_si128(CONST_M128_CAST(inBlock + 0));
	__m128i B1 = _mm_loadu_si128(CONST_M128_CAST(inBlock + 16));
	__m128i MASK = _mm_set_epi64x(0x0C0D0E0F08090A0B, 0x0405060700010203);

	B0 = _mm_shuffle_epi8(B0, MASK);
	B1 = _mm_shuffle_epi8(B1, MASK);

	B0 = _mm_shuffle_epi32(B0, 0xB1);  // CDAB
	B1 = _mm_shuffle_epi32(B1, 0x1B);  // EFGH

	__m128i TMP  = _mm_alignr_epi8(B0, B1, 8);  // ABEF
	B1 = _mm_blend_epi16(B1, B0, 0xF0);         // CDGH
	B0 = TMP;

	for (size_t i = 0; i != 8; ++i)
	{
		B1 = _mm_sha256rnds2_epu32(B1, B0, _mm_set_epi32(0,0,subKeys[8*i+1],subKeys[8*i+0]));
		B0 = _mm_sha256rnds2_epu32(B0, B1, _mm_set_epi32(0,0,subKeys[8*i+3],subKeys[8*i+2]));
		B1 = _mm_sha256rnds2_epu32(B1, B0, _mm_set_epi32(0,0,subKeys[8*i+5],subKeys[8*i+4]));
		B0 = _mm_sha256rnds2_epu32(B0, B1, _mm_set_epi32(0,0,subKeys[8*i+7],subKeys[8*i+6]));
	}

	TMP = _mm_shuffle_epi32(B0, 0x1B);    // FEBA
	B1 = _mm_shuffle_epi32(B1, 0xB1);     // DCHG
	B0 = _mm_blend_epi16(TMP, B1, 0xF0);  // DCBA
	B1 = _mm_alignr_epi8(B1, TMP, 8);     // ABEF

	B0 = _mm_shuffle_epi8(B0, MASK);
	B1 = _mm_shuffle_epi8(B1, MASK);

	// Save state
	//_mm_storeu_si128(M128_CAST(outBlock + 0), B0);
	//_mm_storeu_si128(M128_CAST(outBlock + 16), B1);

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
