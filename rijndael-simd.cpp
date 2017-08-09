// rijndael-simd.cpp - written and placed in the public domain by
//                     Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to AES-NI and
//    ARMv8a AES instructions. A separate source file is needed
//    because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.
//
//    ARMv8a AES code based on CriticalBlue code from Johannes Schneiders,
//    Skip Hovsmith and Barry O'Rourke for the mbedTLS project. Stepping
//    mbedTLS under a debugger was helped for us to determine problems
//    with our subkey generation and scheduling.

#include "pch.h"
#include "config.h"
#include "misc.h"

// Clang and GCC hoops...
#if !(defined(__ARM_FEATURE_CRYPTO) || defined(_MSC_VER))
# undef CRYPTOPP_ARM_AES_AVAILABLE
#endif

#if defined(__linux__)
# include <sys/auxv.h>
# ifndef HWCAP_AES
# define HWCAP_AES (1 << 3)
# endif
# ifndef HWCAP2_AES
# define HWCAP2_AES (1 << 0)
# endif
#endif

#if (CRYPTOPP_SSE41_AVAILABLE)
// Hack... GCC 4.8, LLVM Clang 3.5 and Apple Clang 6.0 conflates SSE4.1
//   and SSE4.2. Without __SSE4_2__, early compilers fail with "SSE4.2
//   instruction set not enabled" when "nmmintrin.h" is included.
# if defined(__clang__) || defined(__GNUC__)
#  define __SSE4_2__ 1
# endif
# include "nmmintrin.h"
#endif  // CRYPTOPP_SSE41_AVAILABLE

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

// Hack for SunCC, http://github.com/weidai11/cryptopp/issues/224
#if (__SUNPRO_CC >= 0x5130)
# define MAYBE_CONST
#else
# define MAYBE_CONST const
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
		r1 = vaesmcq_u8(r1);
		r2 = vaesimcq_u8(r2);

		result = !!(vgetq_lane_u8(r1,0) | vgetq_lane_u8(r2,7));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return result;
# else
#   if defined(__ANDROID__) && (defined(__aarch64__) || defined(__aarch32__))
    if (android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_AES)
		return true;
    // https://sourceware.org/ml/libc-help/2017-08/msg00012.html
#   elif defined(__linux__) && defined(__aarch64__)
	if (getauxval(AT_HWCAP) & HWCAP_AES)
		return true;
#   elif defined(__linux__) && defined(__aarch32__)
	if (getauxval(AT_HWCAP2) & HWCAP2_AES)
		return true;
#   endif

	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile bool result = true;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpSIGILL))
		result = false;
	else
	{
		uint8x16_t data = vdupq_n_u8(0), key = vdupq_n_u8(0);
		uint8x16_t r1 = vaeseq_u8(data, key);
		uint8x16_t r2 = vaesdq_u8(data, key);
		r1 = vaesmcq_u8(r1);
		r2 = vaesimcq_u8(r2);

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

void Rijndael_Enc_ProcessAndXorBlock_ARMV8(const byte *inBlock, const byte *xorBlock, byte *outBlock,
                                           const word32 *subKeys, unsigned int rounds)
{
	uint8x16_t data = vld1q_u8(inBlock);
	const byte *keys = reinterpret_cast<const byte*>(subKeys);

	// Unroll the loop, profit 0.3 to 0.5 cpb.
	data = vaeseq_u8(data, vld1q_u8(keys+0));
	data = vaesmcq_u8(data);
	data = vaeseq_u8(data, vld1q_u8(keys+16));
	data = vaesmcq_u8(data);
	data = vaeseq_u8(data, vld1q_u8(keys+32));
	data = vaesmcq_u8(data);
	data = vaeseq_u8(data, vld1q_u8(keys+48));
	data = vaesmcq_u8(data);
	data = vaeseq_u8(data, vld1q_u8(keys+64));
	data = vaesmcq_u8(data);
	data = vaeseq_u8(data, vld1q_u8(keys+80));
	data = vaesmcq_u8(data);
	data = vaeseq_u8(data, vld1q_u8(keys+96));
	data = vaesmcq_u8(data);
	data = vaeseq_u8(data, vld1q_u8(keys+112));
	data = vaesmcq_u8(data);
	data = vaeseq_u8(data, vld1q_u8(keys+128));
	data = vaesmcq_u8(data);

	unsigned int i=9;
	for ( ; i<rounds-1; ++i)
	{
		// AES single round encryption
		data = vaeseq_u8(data, vld1q_u8(keys+i*16));
		// AES mix columns
		data = vaesmcq_u8(data);
	}

	// AES single round encryption
	data = vaeseq_u8(data, vld1q_u8(keys+i*16));

	// Final Add (bitwise Xor)
	data = veorq_u8(data, vld1q_u8(keys+(i+1)*16));

	if (xorBlock)
		vst1q_u8(outBlock, veorq_u8(data, vld1q_u8(xorBlock)));
	else
		vst1q_u8(outBlock, data);
}

void Rijndael_Dec_ProcessAndXorBlock_ARMV8(const byte *inBlock, const byte *xorBlock, byte *outBlock,
                                           const word32 *subKeys, unsigned int rounds)
{
	uint8x16_t data = vld1q_u8(inBlock);
	const byte *keys = reinterpret_cast<const byte*>(subKeys);

	// Unroll the loop, profit 0.3 to 0.5 cpb.
	data = vaesdq_u8(data, vld1q_u8(keys+0));
	data = vaesimcq_u8(data);
	data = vaesdq_u8(data, vld1q_u8(keys+16));
	data = vaesimcq_u8(data);
	data = vaesdq_u8(data, vld1q_u8(keys+32));
	data = vaesimcq_u8(data);
	data = vaesdq_u8(data, vld1q_u8(keys+48));
	data = vaesimcq_u8(data);
	data = vaesdq_u8(data, vld1q_u8(keys+64));
	data = vaesimcq_u8(data);
	data = vaesdq_u8(data, vld1q_u8(keys+80));
	data = vaesimcq_u8(data);
	data = vaesdq_u8(data, vld1q_u8(keys+96));
	data = vaesimcq_u8(data);
	data = vaesdq_u8(data, vld1q_u8(keys+112));
	data = vaesimcq_u8(data);
	data = vaesdq_u8(data, vld1q_u8(keys+128));
	data = vaesimcq_u8(data);

	unsigned int i=9;
	for ( ; i<rounds-1; ++i)
	{
		// AES single round decryption
		data = vaesdq_u8(data, vld1q_u8(keys+i*16));
		// AES inverse mix columns
		data = vaesimcq_u8(data);
	}

	// AES single round decryption
	data = vaesdq_u8(data, vld1q_u8(keys+i*16));

	// Final Add (bitwise Xor)
	data = veorq_u8(data, vld1q_u8(keys+(i+1)*16));

	if (xorBlock)
		vst1q_u8(outBlock, veorq_u8(data, vld1q_u8(xorBlock)));
	else
		vst1q_u8(outBlock, data);
}
#endif  // CRYPTOPP_ARM_AES_AVAILABLE

#if (CRYPTOPP_AESNI_AVAILABLE)
void AESNI_Enc_Block(__m128i &block, MAYBE_CONST __m128i *subkeys, unsigned int rounds)
{
	block = _mm_xor_si128(block, subkeys[0]);
	for (unsigned int i=1; i<rounds-1; i+=2)
	{
		block = _mm_aesenc_si128(block, subkeys[i]);
		block = _mm_aesenc_si128(block, subkeys[i+1]);
	}
	block = _mm_aesenc_si128(block, subkeys[rounds-1]);
	block = _mm_aesenclast_si128(block, subkeys[rounds]);
}

inline void AESNI_Enc_4_Blocks(__m128i &block0, __m128i &block1, __m128i &block2, __m128i &block3,
                               MAYBE_CONST __m128i *subkeys, unsigned int rounds)
{
	__m128i rk = subkeys[0];
	block0 = _mm_xor_si128(block0, rk);
	block1 = _mm_xor_si128(block1, rk);
	block2 = _mm_xor_si128(block2, rk);
	block3 = _mm_xor_si128(block3, rk);
	for (unsigned int i=1; i<rounds; i++)
	{
		rk = subkeys[i];
		block0 = _mm_aesenc_si128(block0, rk);
		block1 = _mm_aesenc_si128(block1, rk);
		block2 = _mm_aesenc_si128(block2, rk);
		block3 = _mm_aesenc_si128(block3, rk);
	}
	rk = subkeys[rounds];
	block0 = _mm_aesenclast_si128(block0, rk);
	block1 = _mm_aesenclast_si128(block1, rk);
	block2 = _mm_aesenclast_si128(block2, rk);
	block3 = _mm_aesenclast_si128(block3, rk);
}

void AESNI_Dec_Block(__m128i &block, MAYBE_CONST __m128i *subkeys, unsigned int rounds)
{
	block = _mm_xor_si128(block, subkeys[0]);
	for (unsigned int i=1; i<rounds-1; i+=2)
	{
		block = _mm_aesdec_si128(block, subkeys[i]);
		block = _mm_aesdec_si128(block, subkeys[i+1]);
	}
	block = _mm_aesdec_si128(block, subkeys[rounds-1]);
	block = _mm_aesdeclast_si128(block, subkeys[rounds]);
}

void AESNI_Dec_4_Blocks(__m128i &block0, __m128i &block1, __m128i &block2, __m128i &block3,
                        MAYBE_CONST __m128i *subkeys, unsigned int rounds)
{
	__m128i rk = subkeys[0];
	block0 = _mm_xor_si128(block0, rk);
	block1 = _mm_xor_si128(block1, rk);
	block2 = _mm_xor_si128(block2, rk);
	block3 = _mm_xor_si128(block3, rk);
	for (unsigned int i=1; i<rounds; i++)
	{
		rk = subkeys[i];
		block0 = _mm_aesdec_si128(block0, rk);
		block1 = _mm_aesdec_si128(block1, rk);
		block2 = _mm_aesdec_si128(block2, rk);
		block3 = _mm_aesdec_si128(block3, rk);
	}
	rk = subkeys[rounds];
	block0 = _mm_aesdeclast_si128(block0, rk);
	block1 = _mm_aesdeclast_si128(block1, rk);
	block2 = _mm_aesdeclast_si128(block2, rk);
	block3 = _mm_aesdeclast_si128(block3, rk);
}

CRYPTOPP_ALIGN_DATA(16)
static const word32 s_one[] = {0, 0, 0, 1<<24};

template <typename F1, typename F4>
inline size_t Rijndael_AdvancedProcessBlocks_AESNI(F1 func1, F4 func4,
        MAYBE_CONST word32 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	size_t blockSize = 16;
	size_t inIncrement = (flags & (BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_DontIncrementInOutPointers)) ? 0 : blockSize;
	size_t xorIncrement = xorBlocks ? blockSize : 0;
	size_t outIncrement = (flags & BlockTransformation::BT_DontIncrementInOutPointers) ? 0 : blockSize;
	MAYBE_CONST __m128i *subkeys = reinterpret_cast<MAYBE_CONST __m128i*>(subKeys);

	if (flags & BlockTransformation::BT_ReverseDirection)
	{
		CRYPTOPP_ASSERT(length % blockSize == 0);
		inBlocks += length - blockSize;
		xorBlocks += length - blockSize;
		outBlocks += length - blockSize;
		inIncrement = 0-inIncrement;
		xorIncrement = 0-xorIncrement;
		outIncrement = 0-outIncrement;
	}

	if (flags & BlockTransformation::BT_AllowParallel)
	{
		while (length >= 4*blockSize)
		{
			__m128i block0 = _mm_loadu_si128((const __m128i *)(const void *)inBlocks), block1, block2, block3;
			if (flags & BlockTransformation::BT_InBlockIsCounter)
			{
				const __m128i be1 = *(const __m128i *)(const void *)s_one;
				block1 = _mm_add_epi32(block0, be1);
				block2 = _mm_add_epi32(block1, be1);
				block3 = _mm_add_epi32(block2, be1);
				_mm_storeu_si128((__m128i *)(void *)inBlocks, _mm_add_epi32(block3, be1));
			}
			else
			{
				inBlocks += inIncrement;
				block1 = _mm_loadu_si128((const __m128i *)(const void *)inBlocks);
				inBlocks += inIncrement;
				block2 = _mm_loadu_si128((const __m128i *)(const void *)inBlocks);
				inBlocks += inIncrement;
				block3 = _mm_loadu_si128((const __m128i *)(const void *)inBlocks);
				inBlocks += inIncrement;
			}

			if (flags & BlockTransformation::BT_XorInput)
			{
				// Coverity finding, appears to be false positive. Assert the condition.
				CRYPTOPP_ASSERT(xorBlocks);
				block0 = _mm_xor_si128(block0, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));
				xorBlocks += xorIncrement;
				block1 = _mm_xor_si128(block1, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));
				xorBlocks += xorIncrement;
				block2 = _mm_xor_si128(block2, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));
				xorBlocks += xorIncrement;
				block3 = _mm_xor_si128(block3, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));
				xorBlocks += xorIncrement;
			}

			func4(block0, block1, block2, block3, subkeys, static_cast<unsigned int>(rounds));

			if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			{
				block0 = _mm_xor_si128(block0, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));
				xorBlocks += xorIncrement;
				block1 = _mm_xor_si128(block1, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));
				xorBlocks += xorIncrement;
				block2 = _mm_xor_si128(block2, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));
				xorBlocks += xorIncrement;
				block3 = _mm_xor_si128(block3, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));
				xorBlocks += xorIncrement;
			}

			_mm_storeu_si128((__m128i *)(void *)outBlocks, block0);
			outBlocks += outIncrement;
			_mm_storeu_si128((__m128i *)(void *)outBlocks, block1);
			outBlocks += outIncrement;
			_mm_storeu_si128((__m128i *)(void *)outBlocks, block2);
			outBlocks += outIncrement;
			_mm_storeu_si128((__m128i *)(void *)outBlocks, block3);
			outBlocks += outIncrement;

			length -= 4*blockSize;
		}
	}

	while (length >= blockSize)
	{
		__m128i block = _mm_loadu_si128((const __m128i *)(const void *)inBlocks);

		if (flags & BlockTransformation::BT_XorInput)
			block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));

		if (flags & BlockTransformation::BT_InBlockIsCounter)
			const_cast<byte *>(inBlocks)[15]++;

		func1(block, subkeys, static_cast<unsigned int>(rounds));

		if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)(const void *)xorBlocks));

		_mm_storeu_si128((__m128i *)(void *)outBlocks, block);

		inBlocks += inIncrement;
		outBlocks += outIncrement;
		xorBlocks += xorIncrement;
		length -= blockSize;
	}

	return length;
}

size_t Rijndael_Enc_AdvancedProcessBlocks_AESNI(MAYBE_CONST word32 *subkeys, size_t rounds,
        const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	MAYBE_CONST __m128i* keys = reinterpret_cast<MAYBE_CONST __m128i*>(subkeys);
	return Rijndael_AdvancedProcessBlocks_AESNI(AESNI_Enc_Block, AESNI_Enc_4_Blocks,
                subkeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_AESNI(MAYBE_CONST word32 *subkeys, size_t rounds,
        const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	MAYBE_CONST __m128i* keys = reinterpret_cast<MAYBE_CONST __m128i*>(subkeys);
	return Rijndael_AdvancedProcessBlocks_AESNI(AESNI_Dec_Block, AESNI_Dec_4_Blocks,
                subkeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

void Rijndael_UncheckedSetKey_SSE4_AESNI(const byte *userKey, size_t keyLen, word32 *rk)
{
	const unsigned rounds = static_cast<unsigned int>(keyLen/4 + 6);
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
