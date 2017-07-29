// crc-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to SSE4.2 and
//    ARMv8a CRC-32 and CRC-32C instructions. A separate source file
//    is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"

#if (CRYPTOPP_SSE42_AVAILABLE)
# include "nmmintrin.h"
#endif

#if (CRYPTOPP_ARMV8A_CRC32_AVAILABLE) && defined(__GNUC__)
# include "arm_neon.h"
# include "arm_acle.h"
#endif

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_ARMV8A_CRC32_AVAILABLE)
void CRC32_Update_ARMV8(const byte *s, size_t n, word32& c)
{
	for(; !IsAligned<word32>(s) && n > 0; s++, n--)
		c = __crc32b(c, *s);

	for(; n > 4; s+=4, n-=4)
		c = __crc32w(c, *(const word32 *)(void*)s);

	for(; n > 0; s++, n--)
		c = __crc32b(c, *s);
}

void CRC32C_Update_ARMV8(const byte *s, size_t n, word32& c)
{
	for(; !IsAligned<word32>(s) && n > 0; s++, n--)
		c = __crc32cb(c, *s);

	for(; n > 4; s+=4, n-=4)
		c = __crc32cw(c, *(const word32 *)(void*)s);

	for(; n > 0; s++, n--)
		c = __crc32cb(c, *s);
}
#endif

#if (CRYPTOPP_SSE42_AVAILABLE)
void CRC32C_Update_SSE42(const byte *s, size_t n, word32& c)
{
	for(; !IsAligned<word32>(s) && n > 0; s++, n--)
		c = _mm_crc32_u8(c, *s);

	for(; n > 4; s+=4, n-=4)
		c = _mm_crc32_u32(c, *(const word32 *)(void*)s);

	for(; n > 0; s++, n--)
		c = _mm_crc32_u8(c, *s);
}
#endif

NAMESPACE_END