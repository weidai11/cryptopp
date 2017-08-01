// rijndael-simd.cpp - written and placed in the public domain by
//                     Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to AES-NI and
//    ARMv8a AES instructions. A separate source file is needed
//    because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"

// Clang and GCC hoops...
#if !(defined(__ARM_FEATURE_CRYPTO) || defined(_MSC_VER))
# undef CRYPTOPP_ARM_AES_AVAILABLE
#endif

#if (CRYPTOPP_SSE42_AVAILABLE)
# include "nmmintrin.h"
#endif

#if (CRYPTOPP_AESNI_AVAILABLE)
# include "wmmintrin.h"
#endif

#if (CRYPTOPP_ARM_AES_AVAILABLE)
# include "arm_neon.h"
# include "arm_acle.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
extern "C" {
    typedef void (*SigHandler)(int);

	static jmp_buf s_jmpSIGILL;
	static void SigIllHandler(int)
	{
		longjmp(s_jmpSIGILL, 1);
	}
};
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64)
bool CPU_TryAES_ARMV8()
{
#if (CRYPTOPP_ARM_AES_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
	volatile bool result = true;
	__try
	{
		// AES encrypt and decrypt
		uint8x16_t data = vdupq_n_u8(0), key = vdupq_n_u8(0);
		uint8x16_t r1 = vaeseq_u8(data, key);
		uint8x16_t r2 = vaesdq_u8(data, key);

		result = !!(vgetq_lane_u8(r1,0) | vgetq_lane_u8(r2,7));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return result;
# else
	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile bool result = true;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandlerAES);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpNoAES))
		result = false;
	else
	{
		uint8x16_t data = vdupq_n_u8(0), key = vdupq_n_u8(0);
		uint8x16_t r1 = vaeseq_u8(data, key);
		uint8x16_t r2 = vaesdq_u8(data, key);

		// Hack... GCC optimizes away the code and returns true
		result = !!(vgetq_lane_u8(r1,0) | vgetq_lane_u8(r2,7));
	}

	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_ARM_AES_AVAILABLE
}
#endif  // ARM32 or ARM64

#if (CRYPTOPP_ARM_AES_AVAILABLE)
#endif  // CRYPTOPP_ARM_AES_AVAILABLE

#if (CRYPTOPP_AESNI_AVAILABLE)
void Rijndael_UncheckedSetKey_SSE4_AESNI(const byte *userKey, size_t keyLen, word32 *rk)
{
	const unsigned rounds = keyLen/4 + 6;
	static const word32 rcLE[] = {
		0x01, 0x02, 0x04, 0x08,
		0x10, 0x20, 0x40, 0x80,
		0x1B, 0x36, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
	};

	const word32 *ro = rcLE, *rc = rcLE;
	CRYPTOPP_UNUSED(ro);

	__m128i temp = _mm_loadu_si128((__m128i *)(void *)(userKey+keyLen-16));
	std::memcpy(rk, userKey, keyLen);

	// keySize: m_key allocates 4*(rounds+1 word32's.
	const size_t keySize = 4*(rounds+1);
	const word32* end = rk + keySize;
	while (true)
	{
		CRYPTOPP_ASSERT(rc < ro + COUNTOF(rcLE));
		rk[keyLen/4] = rk[0] ^ _mm_extract_epi32(_mm_aeskeygenassist_si128(temp, 0), 3) ^ *(rc++);
		rk[keyLen/4+1] = rk[1] ^ rk[keyLen/4];
		rk[keyLen/4+2] = rk[2] ^ rk[keyLen/4+1];
		rk[keyLen/4+3] = rk[3] ^ rk[keyLen/4+2];

		if (rk + keyLen/4 + 4 == end)
			break;

		if (keyLen == 24)
		{
			rk[10] = rk[ 4] ^ rk[ 9];
			rk[11] = rk[ 5] ^ rk[10];

			CRYPTOPP_ASSERT(keySize >= 12);
			temp = _mm_insert_epi32(temp, rk[11], 3);
		}
		else if (keyLen == 32)
		{
			CRYPTOPP_ASSERT(keySize >= 12);
			temp = _mm_insert_epi32(temp, rk[11], 3);
			rk[12] = rk[ 4] ^ _mm_extract_epi32(_mm_aeskeygenassist_si128(temp, 0), 2);
			rk[13] = rk[ 5] ^ rk[12];
			rk[14] = rk[ 6] ^ rk[13];
			rk[15] = rk[ 7] ^ rk[14];

			CRYPTOPP_ASSERT(keySize >= 16);
			temp = _mm_insert_epi32(temp, rk[15], 3);
		}
		else
		{
			CRYPTOPP_ASSERT(keySize >= 8);
			temp = _mm_insert_epi32(temp, rk[7], 3);
		}

		rk += keyLen/4;
	}
}

void Rijndael_UncheckedSetKeyRev_SSE4_AESNI(word32 *key, unsigned int rounds)
{
	unsigned int i, j;
	__m128i temp;

#if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x5120)
	// __m128i is an unsigned long long[2], and support for swapping it was not added until C++11.
	// SunCC 12.1 - 12.3 fail to consume the swap; while SunCC 12.4 consumes it without -std=c++11.
	vec_swap(*(__m128i *)(key), *(__m128i *)(key+4*rounds));
#else
	std::swap(*(__m128i *)(void *)(key), *(__m128i *)(void *)(key+4*rounds));
#endif
	for (i = 4, j = 4*rounds-4; i < j; i += 4, j -= 4)
	{
		temp = _mm_aesimc_si128(*(__m128i *)(void *)(key+i));
		*(__m128i *)(void *)(key+i) = _mm_aesimc_si128(*(__m128i *)(void *)(key+j));
		*(__m128i *)(void *)(key+j) = temp;
	}

	*(__m128i *)(void *)(key+i) = _mm_aesimc_si128(*(__m128i *)(void *)(key+i));	
}
#endif  // CRYPTOPP_AESNI_AVAILABLE

NAMESPACE_END
