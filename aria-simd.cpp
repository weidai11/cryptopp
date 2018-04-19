// aria-simd.cpp - written and placed in the public domain by
//                 Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to ARMv7a and
//    ARMv8a NEON instructions. A separate source file is needed
//    because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"

#if (CRYPTOPP_SSSE3_AVAILABLE)
# include <tmmintrin.h>
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

// GCC cast warning
#define UINT32_CAST(x) ((uint32_t *)(void *)(x))
#define CONST_UINT32_CAST(x) ((const uint32_t *)(const void *)(x))

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(ARIATab)

extern const word32 S1[256];
extern const word32 S2[256];
extern const word32 X1[256];
extern const word32 X2[256];
extern const word32 KRK[3][4];

NAMESPACE_END
NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

using CryptoPP::ARIATab::S1;
using CryptoPP::ARIATab::S2;
using CryptoPP::ARIATab::X1;
using CryptoPP::ARIATab::X2;
using CryptoPP::ARIATab::KRK;

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

template <unsigned int N>
inline void ARIA_GSRK_NEON(const uint32x4_t X, const uint32x4_t Y, byte RK[16])
{
	static const unsigned int Q1 = (4-(N/32)) % 4;
	static const unsigned int Q2 = (3-(N/32)) % 4;
	static const unsigned int R = N % 32;

	vst1q_u32(UINT32_CAST(RK),
		veorq_u32(X, veorq_u32(
			vshrq_n_u32(vextq_u32(Y, Y, Q1), R),
			vshlq_n_u32(vextq_u32(Y, Y, Q2), 32-R))));
}

void ARIA_UncheckedSetKey_Schedule_NEON(byte* rk, word32* ws, unsigned int keylen)
{
	const uint32x4_t w0 = vld1q_u32(CONST_UINT32_CAST(ws+ 0));
	const uint32x4_t w1 = vld1q_u32(CONST_UINT32_CAST(ws+ 8));
	const uint32x4_t w2 = vld1q_u32(CONST_UINT32_CAST(ws+12));
	const uint32x4_t w3 = vld1q_u32(CONST_UINT32_CAST(ws+16));

	ARIA_GSRK_NEON<19>(w0, w1, rk +   0);
	ARIA_GSRK_NEON<19>(w1, w2, rk +  16);
	ARIA_GSRK_NEON<19>(w2, w3, rk +  32);
	ARIA_GSRK_NEON<19>(w3, w0, rk +  48);
	ARIA_GSRK_NEON<31>(w0, w1, rk +  64);
	ARIA_GSRK_NEON<31>(w1, w2, rk +  80);
	ARIA_GSRK_NEON<31>(w2, w3, rk +  96);
	ARIA_GSRK_NEON<31>(w3, w0, rk + 112);
	ARIA_GSRK_NEON<67>(w0, w1, rk + 128);
	ARIA_GSRK_NEON<67>(w1, w2, rk + 144);
	ARIA_GSRK_NEON<67>(w2, w3, rk + 160);
	ARIA_GSRK_NEON<67>(w3, w0, rk + 176);
	ARIA_GSRK_NEON<97>(w0, w1, rk + 192);

	if (keylen > 16)
	{
		ARIA_GSRK_NEON<97>(w1, w2, rk + 208);
		ARIA_GSRK_NEON<97>(w2, w3, rk + 224);

		if (keylen > 24)
		{
			ARIA_GSRK_NEON< 97>(w3, w0, rk + 240);
			ARIA_GSRK_NEON<109>(w0, w1, rk + 256);
		}
	}
}

void ARIA_ProcessAndXorBlock_Xor_NEON(const byte* xorBlock, byte* outBlock)
{
	vst1q_u32(UINT32_CAST(outBlock), veorq_u32(
		vld1q_u32(CONST_UINT32_CAST(outBlock)),
		vld1q_u32(CONST_UINT32_CAST(xorBlock))));
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_SSSE3_AVAILABLE)

inline byte ARIA_BRF(const word32 x, const int y) {
	return GETBYTE(x, y);
}

void ARIA_ProcessAndXorBlock_Xor_SSSE3(const byte* xorBlock, byte* outBlock, const byte *rk, word32 *t)
{
	const __m128i MASK = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);

	outBlock[ 0] = (byte)(X1[ARIA_BRF(t[0],3)]   );
	outBlock[ 1] = (byte)(X2[ARIA_BRF(t[0],2)]>>8);
	outBlock[ 2] = (byte)(S1[ARIA_BRF(t[0],1)]   );
	outBlock[ 3] = (byte)(S2[ARIA_BRF(t[0],0)]   );
	outBlock[ 4] = (byte)(X1[ARIA_BRF(t[1],3)]   );
	outBlock[ 5] = (byte)(X2[ARIA_BRF(t[1],2)]>>8);
	outBlock[ 6] = (byte)(S1[ARIA_BRF(t[1],1)]   );
	outBlock[ 7] = (byte)(S2[ARIA_BRF(t[1],0)]   );
	outBlock[ 8] = (byte)(X1[ARIA_BRF(t[2],3)]   );
	outBlock[ 9] = (byte)(X2[ARIA_BRF(t[2],2)]>>8);
	outBlock[10] = (byte)(S1[ARIA_BRF(t[2],1)]   );
	outBlock[11] = (byte)(S2[ARIA_BRF(t[2],0)]   );
	outBlock[12] = (byte)(X1[ARIA_BRF(t[3],3)]   );
	outBlock[13] = (byte)(X2[ARIA_BRF(t[3],2)]>>8);
	outBlock[14] = (byte)(S1[ARIA_BRF(t[3],1)]   );
	outBlock[15] = (byte)(S2[ARIA_BRF(t[3],0)]   );

	// 'outBlock' may be unaligned.
	_mm_storeu_si128(M128_CAST(outBlock),
		_mm_xor_si128(_mm_loadu_si128(CONST_M128_CAST(outBlock)),
			_mm_shuffle_epi8(_mm_load_si128(CONST_M128_CAST(rk)), MASK)));

	// 'outBlock' and 'xorBlock' may be unaligned.
	if (xorBlock != NULLPTR)
	{
		_mm_storeu_si128(M128_CAST(outBlock),
			_mm_xor_si128(
				_mm_loadu_si128(CONST_M128_CAST(outBlock)),
				_mm_loadu_si128(CONST_M128_CAST(xorBlock))));
	}
}

#endif  // CRYPTOPP_SSSE3_AVAILABLE

NAMESPACE_END
