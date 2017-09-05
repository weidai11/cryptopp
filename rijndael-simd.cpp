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

#if (CRYPTOPP_AESNI_AVAILABLE)
// Hack... We are supposed to use <nmmintrin.h>. GCC 4.8, LLVM Clang 3.5
//   and Apple Clang 6.0 conflates SSE4.1 and SSE4.2. If we use <nmmintrin.h>
//   then compile fails with "SSE4.2 instruction set not enabled". Also see
//   https://gcc.gnu.org/ml/gcc-help/2017-08/msg00015.html.
# include "smmintrin.h"
# include "wmmintrin.h"
#endif

#if (CRYPTOPP_ARM_AES_AVAILABLE)
# include "arm_neon.h"
#endif

// Don't include <arm_acle.h> when using Apple Clang. Early Apple compilers
//  fail to compile with <arm_acle.h> included. Later Apple compilers compile
//  intrinsics without <arm_acle.h> included.
#if (CRYPTOPP_ARM_AES_AVAILABLE) && !defined(CRYPTOPP_APPLE_CLANG_VERSION)
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
# define MAYBE_UNCONST_CAST(T, x) const_cast<MAYBE_CONST T>(x)
#else
# define MAYBE_CONST const
# define MAYBE_UNCONST_CAST(T, x) (x)
#endif

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

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
bool CPU_ProbeAES()
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

# if defined(__APPLE__)
    // No SIGILL probes on Apple platforms.
    return false;
# endif

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
inline void ARMV8_Enc_Block(uint8x16_t &block, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	CRYPTOPP_ASSERT(rounds >= 9);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	// Unroll the loop, profit 0.3 to 0.5 cpb.
	block = vaeseq_u8(block, vld1q_u8(keys+0));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(keys+16));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(keys+32));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(keys+48));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(keys+64));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(keys+80));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(keys+96));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(keys+112));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(keys+128));
	block = vaesmcq_u8(block);

	unsigned int i=9;
	for ( ; i<rounds-1; ++i)
	{
		// AES single round encryption
		block = vaeseq_u8(block, vld1q_u8(keys+i*16));
		// AES mix columns
		block = vaesmcq_u8(block);
	}

	// AES single round encryption
	block = vaeseq_u8(block, vld1q_u8(keys+i*16));
	// Final Add (bitwise Xor)
	block = veorq_u8(block, vld1q_u8(keys+(i+1)*16));
}

inline void ARMV8_Enc_4_Blocks(uint8x16_t &block0, uint8x16_t &block1, uint8x16_t &block2,
            uint8x16_t &block3, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	unsigned int i=0;
	for ( ; i<rounds-1; ++i)
	{
		// AES single round encryption
		block0 = vaeseq_u8(block0, vld1q_u8(keys+i*16));
		// AES mix columns
		block0 = vaesmcq_u8(block0);
		// AES single round encryption
		block1 = vaeseq_u8(block1, vld1q_u8(keys+i*16));
		// AES mix columns
		block1 = vaesmcq_u8(block1);
		// AES single round encryption
		block2 = vaeseq_u8(block2, vld1q_u8(keys+i*16));
		// AES mix columns
		block2 = vaesmcq_u8(block2);
		// AES single round encryption
		block3 = vaeseq_u8(block3, vld1q_u8(keys+i*16));
		// AES mix columns
		block3 = vaesmcq_u8(block3);
	}

	// AES single round encryption
	block0 = vaeseq_u8(block0, vld1q_u8(keys+i*16));
	block1 = vaeseq_u8(block1, vld1q_u8(keys+i*16));
	block2 = vaeseq_u8(block2, vld1q_u8(keys+i*16));
	block3 = vaeseq_u8(block3, vld1q_u8(keys+i*16));

	// Final Add (bitwise Xor)
	block0 = veorq_u8(block0, vld1q_u8(keys+(i+1)*16));
	block1 = veorq_u8(block1, vld1q_u8(keys+(i+1)*16));
	block2 = veorq_u8(block2, vld1q_u8(keys+(i+1)*16));
	block3 = veorq_u8(block3, vld1q_u8(keys+(i+1)*16));
}

inline void ARMV8_Dec_Block(uint8x16_t &block, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	CRYPTOPP_ASSERT(rounds >= 9);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	// Unroll the loop, profit 0.3 to 0.5 cpb.
	block = vaesdq_u8(block, vld1q_u8(keys+0));
	block = vaesimcq_u8(block);
	block = vaesdq_u8(block, vld1q_u8(keys+16));
	block = vaesimcq_u8(block);
	block = vaesdq_u8(block, vld1q_u8(keys+32));
	block = vaesimcq_u8(block);
	block = vaesdq_u8(block, vld1q_u8(keys+48));
	block = vaesimcq_u8(block);
	block = vaesdq_u8(block, vld1q_u8(keys+64));
	block = vaesimcq_u8(block);
	block = vaesdq_u8(block, vld1q_u8(keys+80));
	block = vaesimcq_u8(block);
	block = vaesdq_u8(block, vld1q_u8(keys+96));
	block = vaesimcq_u8(block);
	block = vaesdq_u8(block, vld1q_u8(keys+112));
	block = vaesimcq_u8(block);
	block = vaesdq_u8(block, vld1q_u8(keys+128));
	block = vaesimcq_u8(block);

	unsigned int i=9;
	for ( ; i<rounds-1; ++i)
	{
		// AES single round decryption
		block = vaesdq_u8(block, vld1q_u8(keys+i*16));
		// AES inverse mix columns
		block = vaesimcq_u8(block);
	}

	// AES single round decryption
	block = vaesdq_u8(block, vld1q_u8(keys+i*16));
	// Final Add (bitwise Xor)
	block = veorq_u8(block, vld1q_u8(keys+(i+1)*16));
}

inline void ARMV8_Dec_4_Blocks(uint8x16_t &block0, uint8x16_t &block1, uint8x16_t &block2,
            uint8x16_t &block3, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	unsigned int i=0;
	for ( ; i<rounds-1; ++i)
	{
		// AES single round decryption
		block0 = vaesdq_u8(block0, vld1q_u8(keys+i*16));
		// AES inverse mix columns
		block0 = vaesimcq_u8(block0);
		// AES single round decryption
		block1 = vaesdq_u8(block1, vld1q_u8(keys+i*16));
		// AES inverse mix columns
		block1 = vaesimcq_u8(block1);
		// AES single round decryption
		block2 = vaesdq_u8(block2, vld1q_u8(keys+i*16));
		// AES inverse mix columns
		block2 = vaesimcq_u8(block2);
		// AES single round decryption
		block3 = vaesdq_u8(block3, vld1q_u8(keys+i*16));
		// AES inverse mix columns
		block3 = vaesimcq_u8(block3);
	}

	// AES single round decryption
	block0 = vaesdq_u8(block0, vld1q_u8(keys+i*16));
	block1 = vaesdq_u8(block1, vld1q_u8(keys+i*16));
	block2 = vaesdq_u8(block2, vld1q_u8(keys+i*16));
	block3 = vaesdq_u8(block3, vld1q_u8(keys+i*16));

	// Final Add (bitwise Xor)
	block0 = veorq_u8(block0, vld1q_u8(keys+(i+1)*16));
	block1 = veorq_u8(block1, vld1q_u8(keys+(i+1)*16));
	block2 = veorq_u8(block2, vld1q_u8(keys+(i+1)*16));
	block3 = veorq_u8(block3, vld1q_u8(keys+(i+1)*16));
}

const word32 s_one[] = {0, 0, 0, 1<<24};

template <typename F1, typename F4>
size_t Rijndael_AdvancedProcessBlocks_ARMV8(F1 func1, F4 func4, const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	CRYPTOPP_ASSERT(subKeys);
	CRYPTOPP_ASSERT(inBlocks);
	CRYPTOPP_ASSERT(outBlocks);
	CRYPTOPP_ASSERT(length >= 16);

	const size_t blockSize = 16;
	size_t inIncrement = (flags & (BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_DontIncrementInOutPointers)) ? 0 : blockSize;
	size_t xorIncrement = xorBlocks ? blockSize : 0;
	size_t outIncrement = (flags & BlockTransformation::BT_DontIncrementInOutPointers) ? 0 : blockSize;

	if (flags & BlockTransformation::BT_ReverseDirection)
	{
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
			uint8x16_t block0, block1, block2, block3, temp;
			block0 = vld1q_u8(inBlocks);

			if (flags & BlockTransformation::BT_InBlockIsCounter)
			{
				uint32x4_t be = vld1q_u32(s_one);
				block1 = vaddq_u8(block0, vreinterpretq_u8_u32(be));
				block2 = vaddq_u8(block1, vreinterpretq_u8_u32(be));
				block3 = vaddq_u8(block2, vreinterpretq_u8_u32(be));
				temp   = vaddq_u8(block3, vreinterpretq_u8_u32(be));
				vst1q_u8(const_cast<byte*>(inBlocks), temp);
			}
			else
			{
				inBlocks += inIncrement;
				block1 = vld1q_u8(inBlocks);
				inBlocks += inIncrement;
				block2 = vld1q_u8(inBlocks);
				inBlocks += inIncrement;
				block3 = vld1q_u8(inBlocks);
				inBlocks += inIncrement;
			}

			if (flags & BlockTransformation::BT_XorInput)
			{
				block0 = veorq_u8(block0, vld1q_u8(xorBlocks));
				xorBlocks += xorIncrement;
				block1 = veorq_u8(block1, vld1q_u8(xorBlocks));
				xorBlocks += xorIncrement;
				block2 = veorq_u8(block2, vld1q_u8(xorBlocks));
				xorBlocks += xorIncrement;
				block3 = veorq_u8(block3, vld1q_u8(xorBlocks));
				xorBlocks += xorIncrement;
			}

			func4(block0, block1, block2, block3, subKeys, rounds);

			if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			{
				block0 = veorq_u8(block0, vld1q_u8(xorBlocks));
				xorBlocks += xorIncrement;
				block1 = veorq_u8(block1, vld1q_u8(xorBlocks));
				xorBlocks += xorIncrement;
				block2 = veorq_u8(block2, vld1q_u8(xorBlocks));
				xorBlocks += xorIncrement;
				block3 = veorq_u8(block3, vld1q_u8(xorBlocks));
				xorBlocks += xorIncrement;
			}

			vst1q_u8(outBlocks, block0);
			outBlocks += outIncrement;
			vst1q_u8(outBlocks, block1);
			outBlocks += outIncrement;
			vst1q_u8(outBlocks, block2);
			outBlocks += outIncrement;
			vst1q_u8(outBlocks, block3);
			outBlocks += outIncrement;

			length -= 4*blockSize;
		}
	}

	while (length >= blockSize)
	{
		uint8x16_t block = vld1q_u8(inBlocks);

		if (flags & BlockTransformation::BT_XorInput)
			block = veorq_u8(block, vld1q_u8(xorBlocks));

		if (flags & BlockTransformation::BT_InBlockIsCounter)
			const_cast<byte *>(inBlocks)[15]++;

		func1(block, subKeys, rounds);

		if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			block = veorq_u8(block, vld1q_u8(xorBlocks));

		vst1q_u8(outBlocks, block);

		inBlocks += inIncrement;
		outBlocks += outIncrement;
		xorBlocks += xorIncrement;
		length -= blockSize;
	}

	return length;
}

size_t Rijndael_Enc_AdvancedProcessBlocks_ARMV8(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	return Rijndael_AdvancedProcessBlocks_ARMV8(ARMV8_Enc_Block, ARMV8_Enc_4_Blocks,
            subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_ARMV8(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	return Rijndael_AdvancedProcessBlocks_ARMV8(ARMV8_Dec_Block, ARMV8_Dec_4_Blocks,
            subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

#endif  // CRYPTOPP_ARM_AES_AVAILABLE

#if (CRYPTOPP_AESNI_AVAILABLE)
inline void AESNI_Enc_Block(__m128i &block, MAYBE_CONST __m128i *subkeys, unsigned int rounds)
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

inline void AESNI_Dec_Block(__m128i &block, MAYBE_CONST __m128i *subkeys, unsigned int rounds)
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

inline void AESNI_Dec_4_Blocks(__m128i &block0, __m128i &block1, __m128i &block2, __m128i &block3,
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
	CRYPTOPP_ASSERT(subKeys);
	CRYPTOPP_ASSERT(inBlocks);
	CRYPTOPP_ASSERT(outBlocks);
	CRYPTOPP_ASSERT(length >= 16);

	const size_t blockSize = 16;
	size_t inIncrement = (flags & (BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_DontIncrementInOutPointers)) ? 0 : blockSize;
	size_t xorIncrement = xorBlocks ? blockSize : 0;
	size_t outIncrement = (flags & BlockTransformation::BT_DontIncrementInOutPointers) ? 0 : blockSize;
	MAYBE_CONST __m128i *subkeys = reinterpret_cast<MAYBE_CONST __m128i*>(subKeys);

	if (flags & BlockTransformation::BT_ReverseDirection)
	{
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
			__m128i block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks)), block1, block2, block3;
			if (flags & BlockTransformation::BT_InBlockIsCounter)
			{
				const __m128i be1 = *CONST_M128_CAST(s_one);
				block1 = _mm_add_epi32(block0, be1);
				block2 = _mm_add_epi32(block1, be1);
				block3 = _mm_add_epi32(block2, be1);
				_mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block3, be1));
			}
			else
			{
				inBlocks += inIncrement;
				block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
				inBlocks += inIncrement;
				block2 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
				inBlocks += inIncrement;
				block3 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
				inBlocks += inIncrement;
			}

			if (flags & BlockTransformation::BT_XorInput)
			{
				// Coverity finding, appears to be false positive. Assert the condition.
				CRYPTOPP_ASSERT(xorBlocks);
				block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
				xorBlocks += xorIncrement;
				block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
				xorBlocks += xorIncrement;
				block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
				xorBlocks += xorIncrement;
				block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
				xorBlocks += xorIncrement;
			}

			func4(block0, block1, block2, block3, subkeys, static_cast<unsigned int>(rounds));

			if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			{
				block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
				xorBlocks += xorIncrement;
				block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
				xorBlocks += xorIncrement;
				block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
				xorBlocks += xorIncrement;
				block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
				xorBlocks += xorIncrement;
			}

			_mm_storeu_si128(M128_CAST(outBlocks), block0);
			outBlocks += outIncrement;
			_mm_storeu_si128(M128_CAST(outBlocks), block1);
			outBlocks += outIncrement;
			_mm_storeu_si128(M128_CAST(outBlocks), block2);
			outBlocks += outIncrement;
			_mm_storeu_si128(M128_CAST(outBlocks), block3);
			outBlocks += outIncrement;

			length -= 4*blockSize;
		}
	}

	while (length >= blockSize)
	{
		__m128i block = _mm_loadu_si128(CONST_M128_CAST(inBlocks));

		if (flags & BlockTransformation::BT_XorInput)
			block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

		if (flags & BlockTransformation::BT_InBlockIsCounter)
			const_cast<byte *>(inBlocks)[15]++;

		func1(block, subkeys, static_cast<unsigned int>(rounds));

		if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

		_mm_storeu_si128(M128_CAST(outBlocks), block);

		inBlocks += inIncrement;
		outBlocks += outIncrement;
		xorBlocks += xorIncrement;
		length -= blockSize;
	}

	return length;
}

size_t Rijndael_Enc_AdvancedProcessBlocks_AESNI(const word32 *subKeys, size_t rounds,
        const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	// SunCC workaround
	MAYBE_CONST word32* sk = MAYBE_UNCONST_CAST(word32*, subKeys);
	MAYBE_CONST byte* ib = MAYBE_UNCONST_CAST(byte*, inBlocks);
	MAYBE_CONST byte* xb = MAYBE_UNCONST_CAST(byte*, xorBlocks);

	return Rijndael_AdvancedProcessBlocks_AESNI(AESNI_Enc_Block, AESNI_Enc_4_Blocks,
                sk, rounds, ib, xb, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_AESNI(const word32 *subKeys, size_t rounds,
        const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	MAYBE_CONST word32* sk = MAYBE_UNCONST_CAST(word32*, subKeys);
	MAYBE_CONST byte* ib = MAYBE_UNCONST_CAST(byte*, inBlocks);
	MAYBE_CONST byte* xb = MAYBE_UNCONST_CAST(byte*, xorBlocks);

	return Rijndael_AdvancedProcessBlocks_AESNI(AESNI_Dec_Block, AESNI_Dec_4_Blocks,
                sk, rounds, ib, xb, outBlocks, length, flags);
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

	__m128i temp = _mm_loadu_si128(M128_CAST(userKey+keyLen-16));
	std::memcpy(rk, userKey, keyLen);

	// keySize: m_key allocates 4*(rounds+1) word32's.
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

void Rijndael_UncheckedSetKeyRev_AESNI(word32 *key, unsigned int rounds)
{
	unsigned int i, j;
	__m128i temp;

#if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x5120)
	// __m128i is an unsigned long long[2], and support for swapping it was not added until C++11.
	// SunCC 12.1 - 12.3 fail to consume the swap; while SunCC 12.4 consumes it without -std=c++11.
	vec_swap(*(__m128i *)(key), *(__m128i *)(key+4*rounds));
#else
	std::swap(*M128_CAST(key), *M128_CAST(key+4*rounds));
#endif
	for (i = 4, j = 4*rounds-4; i < j; i += 4, j -= 4)
	{
		temp = _mm_aesimc_si128(*M128_CAST(key+i));
		*M128_CAST(key+i) = _mm_aesimc_si128(*M128_CAST(key+j));
		*M128_CAST(key+j) = temp;
	}

	*M128_CAST(key+i) = _mm_aesimc_si128(*M128_CAST(key+i));
}
#endif  // CRYPTOPP_AESNI_AVAILABLE

NAMESPACE_END
