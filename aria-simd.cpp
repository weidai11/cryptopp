// crc-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to ARMv7a and
//    ARMv8a NEON instructions. A separate source file is needed
//    because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"

#if (CRYPTOPP_ARM_NEON_AVAILABLE) && defined(__GNUC__)
# include "arm_neon.h"
#endif

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
template <unsigned int N>
inline void ARIA_GSRK_NEON(const uint32x4_t X, const uint32x4_t Y, byte RK[16])
{
	static const unsigned int Q1 = (4-(N/32)) % 4;
	static const unsigned int Q2 = (3-(N/32)) % 4;
	static const unsigned int R = N % 32;

	vst1q_u32(reinterpret_cast<uint32_t*>(RK),
		veorq_u32(X, veorq_u32(
			vshrq_n_u32(vextq_u32(Y, Y, Q1), R),
			vshlq_n_u32(vextq_u32(Y, Y, Q2), 32-R))));
}

void ARIA_UncheckedSetKey_Schedule_NEON(byte* rk, word32* ws, unsigned int keylen)
{
	const uint32x4_t w0 = vld1q_u32((const uint32_t*)(ws+ 0));
	const uint32x4_t w1 = vld1q_u32((const uint32_t*)(ws+ 8));
	const uint32x4_t w2 = vld1q_u32((const uint32_t*)(ws+12));
	const uint32x4_t w3 = vld1q_u32((const uint32_t*)(ws+16));

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
	vst1q_u32(reinterpret_cast<uint32_t*>(outBlock), veorq_u32(
		vld1q_u32(reinterpret_cast<const uint32_t*>(outBlock)),
		vld1q_u32(reinterpret_cast<const uint32_t*>(xorBlock))));
}
#endif

NAMESPACE_END
