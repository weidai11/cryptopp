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
//
//    AltiVec and Power8 code based on http://github.com/noloader/AES-Power8
//

#include "pch.h"
#include "config.h"
#include "misc.h"

// We set CRYPTOPP_ARM_AES_AVAILABLE based on compiler version.
// If the crypto is not available, then we have to disable it here.
#if !(defined(__ARM_FEATURE_CRYPTO) || defined(_MSC_VER))
# undef CRYPTOPP_ARM_AES_AVAILABLE
#endif

// We set CRYPTOPP_POWER8_CRYPTO_AVAILABLE based on compiler version.
// If the crypto is not available, then we have to disable it here.
#if !(defined(__CRYPTO) || defined(_ARCH_PWR8) || defined(_ARCH_PWR9))
# undef CRYPTOPP_POWER8_CRYPTO_AVAILABLE
#endif

#if (CRYPTOPP_AESNI_AVAILABLE)
// Hack... We are supposed to use <nmmintrin.h>. GCC 4.8, LLVM Clang 3.5
//   and Apple Clang 6.0 conflates SSE4.1 and SSE4.2. If we use <nmmintrin.h>
//   then compile fails with "SSE4.2 instruction set not enabled". Also see
//   http://gcc.gnu.org/ml/gcc-help/2017-08/msg00015.html.
# include <smmintrin.h>
# include <wmmintrin.h>
#endif

#if (CRYPTOPP_ARM_AES_AVAILABLE)
# include <arm_neon.h>
# if defined(CRYPTOPP_ARM_ACLE_AVAILABLE)
#  include <arm_acle.h>
# endif
#endif

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include <altivec.h>
# undef vector
# undef pixel
# undef bool
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

// ***************************** ARMv8 ***************************** //

#if (CRYPTOPP_ARM_AES_AVAILABLE)

#if defined(IS_LITTLE_ENDIAN)
const word32 s_one[] = {0, 0, 0, 1<<24};  // uint32x4_t
#else
const word32 s_one[] = {0, 0, 0, 1};      // uint32x4_t
#endif

inline void ARMV8_Enc_Block(uint8x16_t &block, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	// AES single round encryption
	block = vaeseq_u8(block, vld1q_u8(keys+0*16));
	// AES mix columns
	block = vaesmcq_u8(block);

	for (unsigned int i=1; i<rounds-1; i+=2)
	{
		// AES single round encryption
		block = vaeseq_u8(block, vld1q_u8(keys+i*16));
		// AES mix columns
		block = vaesmcq_u8(block);
		// AES single round encryption
		block = vaeseq_u8(block, vld1q_u8(keys+(i+1)*16));
		// AES mix columns
		block = vaesmcq_u8(block);
	}

	// AES single round encryption
	block = vaeseq_u8(block, vld1q_u8(keys+(rounds-1)*16));
	// Final Add (bitwise Xor)
	block = veorq_u8(block, vld1q_u8(keys+rounds*16));
}

inline void ARMV8_Enc_6_Blocks(uint8x16_t &block0, uint8x16_t &block1, uint8x16_t &block2,
            uint8x16_t &block3, uint8x16_t &block4, uint8x16_t &block5,
            const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);
	uint8x16_t key;

	for (unsigned int i=0; i<rounds-1; ++i)
	{
		uint8x16_t key = vld1q_u8(keys+i*16);
		// AES single round encryption
		block0 = vaeseq_u8(block0, key);
		// AES mix columns
		block0 = vaesmcq_u8(block0);
		// AES single round encryption
		block1 = vaeseq_u8(block1, key);
		// AES mix columns
		block1 = vaesmcq_u8(block1);
		// AES single round encryption
		block2 = vaeseq_u8(block2, key);
		// AES mix columns
		block2 = vaesmcq_u8(block2);
		// AES single round encryption
		block3 = vaeseq_u8(block3, key);
		// AES mix columns
		block3 = vaesmcq_u8(block3);
		// AES single round encryption
		block4 = vaeseq_u8(block4, key);
		// AES mix columns
		block4 = vaesmcq_u8(block4);
		// AES single round encryption
		block5 = vaeseq_u8(block5, key);
		// AES mix columns
		block5 = vaesmcq_u8(block5);
	}

	// AES single round encryption
	key = vld1q_u8(keys+(rounds-1)*16);
	block0 = vaeseq_u8(block0, key);
	block1 = vaeseq_u8(block1, key);
	block2 = vaeseq_u8(block2, key);
	block3 = vaeseq_u8(block3, key);
	block4 = vaeseq_u8(block4, key);
	block5 = vaeseq_u8(block5, key);

	// Final Add (bitwise Xor)
	key = vld1q_u8(keys+rounds*16);
	block0 = veorq_u8(block0, key);
	block1 = veorq_u8(block1, key);
	block2 = veorq_u8(block2, key);
	block3 = veorq_u8(block3, key);
	block4 = veorq_u8(block4, key);
	block5 = veorq_u8(block5, key);
}

inline void ARMV8_Dec_Block(uint8x16_t &block, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	// AES single round decryption
	block = vaesdq_u8(block, vld1q_u8(keys+0*16));
	// AES inverse mix columns
	block = vaesimcq_u8(block);

	for (unsigned int i=1; i<rounds-1; i+=2)
	{
		// AES single round decryption
		block = vaesdq_u8(block, vld1q_u8(keys+i*16));
		// AES inverse mix columns
		block = vaesimcq_u8(block);
		// AES single round decryption
		block = vaesdq_u8(block, vld1q_u8(keys+(i+1)*16));
		// AES inverse mix columns
		block = vaesimcq_u8(block);
	}

	// AES single round decryption
	block = vaesdq_u8(block, vld1q_u8(keys+(rounds-1)*16));
	// Final Add (bitwise Xor)
	block = veorq_u8(block, vld1q_u8(keys+rounds*16));
}

inline void ARMV8_Dec_6_Blocks(uint8x16_t &block0, uint8x16_t &block1, uint8x16_t &block2,
            uint8x16_t &block3, uint8x16_t &block4, uint8x16_t &block5,
            const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	uint8x16_t key;
	for (unsigned int i=0; i<rounds-1; ++i)
	{
		key = vld1q_u8(keys+i*16);
		// AES single round decryption
		block0 = vaesdq_u8(block0, key);
		// AES inverse mix columns
		block0 = vaesimcq_u8(block0);
		// AES single round decryption
		block1 = vaesdq_u8(block1, key);
		// AES inverse mix columns
		block1 = vaesimcq_u8(block1);
		// AES single round decryption
		block2 = vaesdq_u8(block2, key);
		// AES inverse mix columns
		block2 = vaesimcq_u8(block2);
		// AES single round decryption
		block3 = vaesdq_u8(block3, key);
		// AES inverse mix columns
		block3 = vaesimcq_u8(block3);
		// AES single round decryption
		block4 = vaesdq_u8(block4, key);
		// AES inverse mix columns
		block4 = vaesimcq_u8(block4);
		// AES single round decryption
		block5 = vaesdq_u8(block5, key);
		// AES inverse mix columns
		block5 = vaesimcq_u8(block5);
	}

	// AES single round decryption
	key = vld1q_u8(keys+(rounds-1)*16);
	block0 = vaesdq_u8(block0, key);
	block1 = vaesdq_u8(block1, key);
	block2 = vaesdq_u8(block2, key);
	block3 = vaesdq_u8(block3, key);
	block4 = vaesdq_u8(block4, key);
	block5 = vaesdq_u8(block5, key);

	// Final Add (bitwise Xor)
	key = vld1q_u8(keys+rounds*16);
	block0 = veorq_u8(block0, key);
	block1 = veorq_u8(block1, key);
	block2 = veorq_u8(block2, key);
	block3 = veorq_u8(block3, key);
	block4 = veorq_u8(block4, key);
	block5 = veorq_u8(block5, key);
}

template <typename F1, typename F6>
size_t Rijndael_AdvancedProcessBlocks_ARMV8(F1 func1, F6 func6, const word32 *subKeys, size_t rounds,
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
		while (length >= 6*blockSize)
		{
			uint8x16_t block0, block1, block2, block3, block4, block5, temp;
			block0 = vld1q_u8(inBlocks);

			if (flags & BlockTransformation::BT_InBlockIsCounter)
			{
				uint32x4_t be = vld1q_u32(s_one);
				block1 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block0), be);
				block2 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block1), be);
				block3 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block2), be);
				block4 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block3), be);
				block5 = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block4), be);
				temp   = (uint8x16_t)vaddq_u32(vreinterpretq_u32_u8(block5), be);
				vst1q_u8(const_cast<byte*>(inBlocks), temp);
			}
			else
			{
				const int inc = static_cast<int>(inIncrement);
				block1 = vld1q_u8(inBlocks+1*inc);
				block2 = vld1q_u8(inBlocks+2*inc);
				block3 = vld1q_u8(inBlocks+3*inc);
				block4 = vld1q_u8(inBlocks+4*inc);
				block5 = vld1q_u8(inBlocks+5*inc);
				inBlocks += 6*inc;
			}

			if (flags & BlockTransformation::BT_XorInput)
			{
				const int inc = static_cast<int>(xorIncrement);
				block0 = veorq_u8(block0, vld1q_u8(xorBlocks+0*inc));
				block1 = veorq_u8(block1, vld1q_u8(xorBlocks+1*inc));
				block2 = veorq_u8(block2, vld1q_u8(xorBlocks+2*inc));
				block3 = veorq_u8(block3, vld1q_u8(xorBlocks+3*inc));
				block4 = veorq_u8(block4, vld1q_u8(xorBlocks+4*inc));
				block5 = veorq_u8(block5, vld1q_u8(xorBlocks+5*inc));
				xorBlocks += 6*inc;
			}

			func6(block0, block1, block2, block3, block4, block5, subKeys, rounds);

			if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			{
				const int inc = static_cast<int>(xorIncrement);
				block0 = veorq_u8(block0, vld1q_u8(xorBlocks+0*inc));
				block1 = veorq_u8(block1, vld1q_u8(xorBlocks+1*inc));
				block2 = veorq_u8(block2, vld1q_u8(xorBlocks+2*inc));
				block3 = veorq_u8(block3, vld1q_u8(xorBlocks+3*inc));
				block4 = veorq_u8(block4, vld1q_u8(xorBlocks+4*inc));
				block5 = veorq_u8(block5, vld1q_u8(xorBlocks+5*inc));
				xorBlocks += 6*inc;
			}

			const int inc = static_cast<int>(outIncrement);
			vst1q_u8(outBlocks+0*inc, block0);
			vst1q_u8(outBlocks+1*inc, block1);
			vst1q_u8(outBlocks+2*inc, block2);
			vst1q_u8(outBlocks+3*inc, block3);
			vst1q_u8(outBlocks+4*inc, block4);
			vst1q_u8(outBlocks+5*inc, block5);

			outBlocks += 6*inc;
			length -= 6*blockSize;
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
	return Rijndael_AdvancedProcessBlocks_ARMV8(ARMV8_Enc_Block, ARMV8_Enc_6_Blocks,
            subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_ARMV8(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	return Rijndael_AdvancedProcessBlocks_ARMV8(ARMV8_Dec_Block, ARMV8_Dec_6_Blocks,
            subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

#endif  // CRYPTOPP_ARM_AES_AVAILABLE

// ***************************** AES-NI ***************************** //

#if (CRYPTOPP_AESNI_AVAILABLE)

CRYPTOPP_ALIGN_DATA(16)
const word32 s_one[] = {0, 0, 0, 1<<24};

/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
CRYPTOPP_ALIGN_DATA(16)
const word32 s_rconLE[] = {
	0x01, 0x02, 0x04, 0x08,	0x10, 0x20, 0x40, 0x80,	0x1B, 0x36
};

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
	MAYBE_CONST   byte* ib = MAYBE_UNCONST_CAST(byte*,  inBlocks);
	MAYBE_CONST   byte* xb = MAYBE_UNCONST_CAST(byte*, xorBlocks);

	return Rijndael_AdvancedProcessBlocks_AESNI(AESNI_Enc_Block, AESNI_Enc_4_Blocks,
                sk, rounds, ib, xb, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_AESNI(const word32 *subKeys, size_t rounds,
        const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	MAYBE_CONST word32* sk = MAYBE_UNCONST_CAST(word32*, subKeys);
	MAYBE_CONST   byte* ib = MAYBE_UNCONST_CAST(byte*,  inBlocks);
	MAYBE_CONST   byte* xb = MAYBE_UNCONST_CAST(byte*, xorBlocks);

	return Rijndael_AdvancedProcessBlocks_AESNI(AESNI_Dec_Block, AESNI_Dec_4_Blocks,
                sk, rounds, ib, xb, outBlocks, length, flags);
}

void Rijndael_UncheckedSetKey_SSE4_AESNI(const byte *userKey, size_t keyLen, word32 *rk, unsigned int rounds)
{
	const word32 *ro = s_rconLE, *rc = s_rconLE;
	CRYPTOPP_UNUSED(ro);

	__m128i temp = _mm_loadu_si128(M128_CAST(userKey+keyLen-16));
	std::memcpy(rk, userKey, keyLen);

	// keySize: m_key allocates 4*(rounds+1) word32's.
	const size_t keySize = 4*(rounds+1);
	const word32* end = rk + keySize;

	while (true)
	{
		CRYPTOPP_ASSERT(rc < ro + COUNTOF(s_rconLE));
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

// ***************************** Power 8 ***************************** //

#if (CRYPTOPP_POWER8_AES_AVAILABLE)

typedef __vector unsigned char      uint8x16_p8;
typedef __vector unsigned long long uint64x2_p8;

void ReverseByteArrayLE(byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION) && defined(IS_LITTLE_ENDIAN)
	vec_st(vec_reve(vec_ld(0, src)), 0, src);
#elif defined(IS_LITTLE_ENDIAN)
	const uint8x16_p8 mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
	const uint8x16_p8 zero = {0};
	vec_vsx_st(vec_perm(vec_vsx_ld(0, src), zero, mask), 0, src);
#endif
}

static inline uint8x16_p8 Reverse8x16(const uint8x16_p8& src)
{
	const uint8x16_p8 mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
	const uint8x16_p8 zero = {0};
	return vec_perm(src, zero, mask);
}

static inline uint64x2_p8 Reverse64x2(const uint64x2_p8& src)
{
	const uint8x16_p8 mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
	const uint8x16_p8 zero = {0};
	return (uint64x2_p8)vec_perm((uint8x16_p8)src, zero, mask);
}

static inline uint8x16_p8 Load8x16(const uint8_t src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return vec_xl_be(0, (uint8_t*)src);
#else
# if defined(IS_LITTLE_ENDIAN)
	return Reverse8x16(vec_vsx_ld(0, src));
# else
	return vec_vsx_ld(0, src);
# endif
#endif
}

static inline uint8x16_p8 Load8x16(int off, const uint8_t src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return vec_xl_be(off, (uint8_t*)src);
#else
# if defined(IS_LITTLE_ENDIAN)
	return Reverse8x16(vec_vsx_ld(off, src));
# else
	return vec_vsx_ld(off, src);
# endif
#endif
}

static inline void Store8x16(const uint8x16_p8& src, uint8_t dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	vec_xst_be(src, 0, (uint8_t*)dest);
#else
# if defined(IS_LITTLE_ENDIAN)
	vec_vsx_st(Reverse8x16(src), 0, dest);
# else
	vec_vsx_st(src, 0, dest);
# endif
#endif
}

static inline uint64x2_p8 Load64x2(const uint8_t src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (uint64x2_p8)vec_xl_be(0, (uint8_t*)src);
#else
# if defined(IS_LITTLE_ENDIAN)
	return Reverse64x2((uint64x2_p8)vec_vsx_ld(0, src));
# else
	return (uint64x2_p8)vec_vsx_ld(0, src);
# endif
#endif
}

static inline uint64x2_p8 Load64x2(int off, const uint8_t src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (uint64x2_p8)vec_xl_be(off, (uint8_t*)src);
#else
# if defined(IS_LITTLE_ENDIAN)
	return (uint64x2_p8)Reverse8x16(vec_vsx_ld(off, src));
# else
	return (uint64x2_p8)vec_vsx_ld(off, src);
# endif
#endif
}

static inline void Store64x2(const uint64x2_p8& src, uint8_t dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	vec_xst_be((uint8x16_p8)src, 0, (uint8_t*)dest);
#else
# if defined(IS_LITTLE_ENDIAN)
	vec_vsx_st((uint8x16_p8)Reverse64x2(src), 0, dest);
# else
	vec_vsx_st((uint8x16_p8)src, 0, dest);
# endif
#endif
}

//////////////////////////////////////////////////////////////////

#if defined(CRYPTOPP_XLC_VERSION)
	typedef uint8x16_p8 VectorType;
#elif defined(CRYPTOPP_GCC_VERSION)
	typedef uint64x2_p8 VectorType;
#else
	CRYPTOPP_ASSERT(0);
#endif

// Loads a mis-aligned byte array, performs an endian conversion.
inline VectorType VectorLoad(const byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return Load8x16(src);
#elif defined(CRYPTOPP_GCC_VERSION)
	return Load64x2(src);
#endif
}

// Loads a mis-aligned byte array, performs an endian conversion.
inline VectorType VectorLoad(int off, const byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return Load8x16(off, src);
#elif defined(CRYPTOPP_GCC_VERSION)
	return Load64x2(off, src);
#endif
}

// Loads an aligned byte array, does not perform an endian conversion.
//  This function presumes the subkey table is correct endianess.
inline VectorType VectorLoadKey(const byte src[16])
{
	CRYPTOPP_ASSERT(IsAlignedOn(src, 16));
	return (VectorType)vec_ld(0, src);
}

// Loads an aligned byte array, does not perform an endian conversion.
//  This function presumes the subkey table is correct endianess.
inline VectorType VectorLoadKey(int off, const byte src[16])
{
	CRYPTOPP_ASSERT(IsAlignedOn(src, 16));
	return (VectorType)vec_ld(off, src);
}

// Stores to a mis-aligned byte array, performs an endian conversion.
inline void VectorStore(const VectorType& src, byte dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return Store8x16(src, dest);
#elif defined(CRYPTOPP_GCC_VERSION)
	return Store64x2(src, dest);
#endif
}

template <class T1, class T2>
inline T1 VectorXor(const T1& vec1, const T2& vec2)
{
	return (T1)vec_xor(vec1, (T1)vec2);
}

template <class T1, class T2>
inline T1 VectorAdd(const T1& vec1, const T2& vec2)
{
	return (T1)vec_add(vec1, (T1)vec2);
}

template <class T1, class T2>
inline T1 VectorEncrypt(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (T1)__vcipher(state, (T1)key);
#elif defined(CRYPTOPP_GCC_VERSION)
	return (T1)__builtin_crypto_vcipher(state, (T1)key);
#else
	CRYPTOPP_ASSERT(0);
#endif
}

template <class T1, class T2>
inline T1 VectorEncryptLast(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (T1)__vcipherlast(state, (T1)key);
#elif defined(CRYPTOPP_GCC_VERSION)
	return (T1)__builtin_crypto_vcipherlast(state, (T1)key);
#else
	CRYPTOPP_ASSERT(0);
#endif
}

template <class T1, class T2>
inline T1 VectorDecrypt(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (T1)__vncipher(state, (T1)key);
#elif defined(CRYPTOPP_GCC_VERSION)
	return (T1)__builtin_crypto_vncipher(state, (T1)key);
#else
	CRYPTOPP_ASSERT(0);
#endif
}

template <class T1, class T2>
inline T1 VectorDecryptLast(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (T1)__vncipherlast(state, (T1)key);
#elif defined(CRYPTOPP_GCC_VERSION)
	return (T1)__builtin_crypto_vncipherlast(state, (T1)key);
#else
	CRYPTOPP_ASSERT(0);
#endif
}

//////////////////////////////////////////////////////////////////

void Rijndael_UncheckedSetKey_POWER8(word32* rk, size_t keyLen, const word32* rc,
                                     const byte* Se, unsigned int rounds)
{
	word32 *rk_saved = rk, temp;

	// keySize: m_key allocates 4*(rounds+1) word32's.
	const size_t keySize = 4*(rounds+1);
	const word32* end = rk + keySize;

	while (true)
	{
		temp  = rk[keyLen/4-1];
		word32 x = (word32(Se[GETBYTE(temp, 2)]) << 24) ^ (word32(Se[GETBYTE(temp, 1)]) << 16) ^
					(word32(Se[GETBYTE(temp, 0)]) << 8) ^ Se[GETBYTE(temp, 3)];
		rk[keyLen/4] = rk[0] ^ x ^ *(rc++);
		rk[keyLen/4+1] = rk[1] ^ rk[keyLen/4];
		rk[keyLen/4+2] = rk[2] ^ rk[keyLen/4+1];
		rk[keyLen/4+3] = rk[3] ^ rk[keyLen/4+2];

		if (rk + keyLen/4 + 4 == end)
			break;

		if (keyLen == 24)
		{
			rk[10] = rk[ 4] ^ rk[ 9];
			rk[11] = rk[ 5] ^ rk[10];
		}
		else if (keyLen == 32)
		{
    		temp = rk[11];
    		rk[12] = rk[ 4] ^ (word32(Se[GETBYTE(temp, 3)]) << 24) ^ (word32(Se[GETBYTE(temp, 2)]) << 16) ^ (word32(Se[GETBYTE(temp, 1)]) << 8) ^ Se[GETBYTE(temp, 0)];
    		rk[13] = rk[ 5] ^ rk[12];
    		rk[14] = rk[ 6] ^ rk[13];
    		rk[15] = rk[ 7] ^ rk[14];
		}
		rk += keyLen/4;
	}

	rk = rk_saved;
	ConditionalByteReverse(BIG_ENDIAN_ORDER, rk, rk, 16);
	ConditionalByteReverse(BIG_ENDIAN_ORDER, rk + rounds*4, rk + rounds*4, 16);
	ConditionalByteReverse(BIG_ENDIAN_ORDER, rk+4, rk+4, (rounds-1)*16);

#if defined(IS_LITTLE_ENDIAN)
	// VSX registers are big-endian. The entire subkey table must be byte
	// reversed on little-endian systems to ensure it loads properly.
	byte * ptr = reinterpret_cast<byte*>(rk);
	for (unsigned int i=0; i<=rounds; i++)
		ReverseByteArrayLE(ptr+i*16);
#endif  // IS_LITTLE_ENDIAN
}

inline void POWER8_Enc_Block(VectorType &block, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	VectorType k = VectorLoadKey(keys);
	block = VectorXor(block, k);

	for (size_t i=1; i<rounds-1; i+=2)
	{
		block = VectorEncrypt(block, VectorLoadKey(  i*16,   keys));
		block = VectorEncrypt(block, VectorLoadKey((i+1)*16, keys));
	}

	block = VectorEncrypt(block, VectorLoadKey((rounds-1)*16, keys));
	block = VectorEncryptLast(block, VectorLoadKey(rounds*16, keys));
}

inline void POWER8_Enc_6_Blocks(VectorType &block0, VectorType &block1,
            VectorType &block2, VectorType &block3, VectorType &block4,
            VectorType &block5, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	VectorType k = VectorLoadKey(keys);
	block0 = VectorXor(block0, k);
	block1 = VectorXor(block1, k);
	block2 = VectorXor(block2, k);
	block3 = VectorXor(block3, k);
	block4 = VectorXor(block4, k);
	block5 = VectorXor(block5, k);

	for (size_t i=1; i<rounds; ++i)
	{
		k = VectorLoadKey(i*16, keys);
		block0 = VectorEncrypt(block0, k);
		block1 = VectorEncrypt(block1, k);
		block2 = VectorEncrypt(block2, k);
		block3 = VectorEncrypt(block3, k);
		block4 = VectorEncrypt(block4, k);
		block5 = VectorEncrypt(block5, k);
	}

	k = VectorLoadKey(rounds*16, keys);
	block0 = VectorEncryptLast(block0, k);
	block1 = VectorEncryptLast(block1, k);
	block2 = VectorEncryptLast(block2, k);
	block3 = VectorEncryptLast(block3, k);
	block4 = VectorEncryptLast(block4, k);
	block5 = VectorEncryptLast(block5, k);
}

inline void POWER8_Dec_Block(VectorType &block, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	VectorType k = VectorLoadKey(rounds*16, keys);
	block = VectorXor(block, k);

	for (size_t i=rounds-1; i>1; i-=2)
	{
		block = VectorDecrypt(block, VectorLoadKey(  i*16,   keys));
		block = VectorDecrypt(block, VectorLoadKey((i-1)*16, keys));
	}

	block = VectorDecrypt(block, VectorLoadKey(16, keys));
	block = VectorDecryptLast(block, VectorLoadKey(0, keys));
}

inline void POWER8_Dec_6_Blocks(VectorType &block0, VectorType &block1,
            VectorType &block2, VectorType &block3, VectorType &block4,
            VectorType &block5, const word32 *subkeys, unsigned int rounds)
{
	CRYPTOPP_ASSERT(subkeys);
	const byte *keys = reinterpret_cast<const byte*>(subkeys);

	VectorType k = VectorLoadKey(rounds*16, keys);
	block0 = VectorXor(block0, k);
	block1 = VectorXor(block1, k);
	block2 = VectorXor(block2, k);
	block3 = VectorXor(block3, k);
	block4 = VectorXor(block4, k);
	block5 = VectorXor(block5, k);

	for (size_t i=rounds-1; i>0; --i)
	{
		k = VectorLoadKey(i*16, keys);
		block0 = VectorDecrypt(block0, k);
		block1 = VectorDecrypt(block1, k);
		block2 = VectorDecrypt(block2, k);
		block3 = VectorDecrypt(block3, k);
		block4 = VectorDecrypt(block4, k);
		block5 = VectorDecrypt(block5, k);
	}

	k = VectorLoadKey(0, keys);
	block0 = VectorDecryptLast(block0, k);
	block1 = VectorDecryptLast(block1, k);
	block2 = VectorDecryptLast(block2, k);
	block3 = VectorDecryptLast(block3, k);
	block4 = VectorDecryptLast(block4, k);
	block5 = VectorDecryptLast(block5, k);
}

template <typename F1, typename F6>
size_t Rijndael_AdvancedProcessBlocks_POWER8(F1 func1, F6 func6, const word32 *subKeys, size_t rounds,
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
		while (length >= 6*blockSize)
		{
#if defined(IS_LITTLE_ENDIAN)
			const VectorType one = (VectorType)((uint64x2_p8){1,0});
#else
			const VectorType one = (VectorType)((uint64x2_p8){0,1});
#endif

			VectorType block0, block1, block2, block3, block4, block5, temp;
			block0 = VectorLoad(inBlocks);

			if (flags & BlockTransformation::BT_InBlockIsCounter)
			{
				block1 = VectorAdd(block0, one);
				block2 = VectorAdd(block1, one);
				block3 = VectorAdd(block2, one);
				block4 = VectorAdd(block3, one);
				block5 = VectorAdd(block4, one);
				temp   = VectorAdd(block5, one);
				VectorStore(temp, const_cast<byte*>(inBlocks));
			}
			else
			{
				const int inc = static_cast<int>(inIncrement);
				block1 = VectorLoad(1*inc, inBlocks);
				block2 = VectorLoad(2*inc, inBlocks);
				block3 = VectorLoad(3*inc, inBlocks);
				block4 = VectorLoad(4*inc, inBlocks);
				block5 = VectorLoad(5*inc, inBlocks);
				inBlocks += 6*inc;
			}

			if (flags & BlockTransformation::BT_XorInput)
			{
				const int inc = static_cast<int>(xorIncrement);
				block0 = VectorXor(block0, VectorLoad(0*inc, xorBlocks));
				block1 = VectorXor(block1, VectorLoad(1*inc, xorBlocks));
				block2 = VectorXor(block2, VectorLoad(2*inc, xorBlocks));
				block3 = VectorXor(block3, VectorLoad(3*inc, xorBlocks));
				block4 = VectorXor(block4, VectorLoad(4*inc, xorBlocks));
				block5 = VectorXor(block5, VectorLoad(5*inc, xorBlocks));
				xorBlocks += 6*inc;
			}

			func6(block0, block1, block2, block3, block4, block5, subKeys, rounds);

			if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			{
				const int inc = static_cast<int>(xorIncrement);
				block0 = VectorXor(block0, VectorLoad(0*inc, xorBlocks));
				block1 = VectorXor(block1, VectorLoad(1*inc, xorBlocks));
				block2 = VectorXor(block2, VectorLoad(2*inc, xorBlocks));
				block3 = VectorXor(block3, VectorLoad(3*inc, xorBlocks));
				block4 = VectorXor(block4, VectorLoad(4*inc, xorBlocks));
				block5 = VectorXor(block5, VectorLoad(5*inc, xorBlocks));
				xorBlocks += 6*inc;
			}

			const int inc = static_cast<int>(outIncrement);
			VectorStore(block0, outBlocks+0*inc);
			VectorStore(block1, outBlocks+1*inc);
			VectorStore(block2, outBlocks+2*inc);
			VectorStore(block3, outBlocks+3*inc);
			VectorStore(block4, outBlocks+4*inc);
			VectorStore(block5, outBlocks+5*inc);

			outBlocks += 6*inc;
			length -= 6*blockSize;
		}
	}

	while (length >= blockSize)
	{
		VectorType block = VectorLoad(inBlocks);

		if (flags & BlockTransformation::BT_XorInput)
			block = VectorXor(block, VectorLoad(xorBlocks));

		if (flags & BlockTransformation::BT_InBlockIsCounter)
			const_cast<byte *>(inBlocks)[15]++;

		func1(block, subKeys, rounds);

		if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
			block = VectorXor(block, VectorLoad(xorBlocks));

		VectorStore(block, outBlocks);

		inBlocks += inIncrement;
		outBlocks += outIncrement;
		xorBlocks += xorIncrement;
		length -= blockSize;
	}

	return length;
}

size_t Rijndael_Enc_AdvancedProcessBlocks_POWER8(const word32 *subKeys, size_t rounds,
			const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	return Rijndael_AdvancedProcessBlocks_POWER8(POWER8_Enc_Block, POWER8_Enc_6_Blocks,
		subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_POWER8(const word32 *subKeys, size_t rounds,
			const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
	return Rijndael_AdvancedProcessBlocks_POWER8(POWER8_Dec_Block, POWER8_Dec_6_Blocks,
		subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

#endif  // CRYPTOPP_POWER8_AES_AVAILABLE
NAMESPACE_END
