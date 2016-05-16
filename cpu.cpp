// cpu.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "config.h"

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

#ifndef CRYPTOPP_IMPORTS

#include "cpu.h"
#include "misc.h"
#include <algorithm>

#ifndef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY
#include <signal.h>
#include <setjmp.h>
#endif

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
#include <emmintrin.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifndef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

// MacPorts/GCC does not provide constructor(priority). Apple/GCC and Fink/GCC do provide it.
#define HAVE_GCC_CONSTRUCTOR1 (__GNUC__ && (CRYPTOPP_INIT_PRIORITY > 0) && ((CRYPTOPP_GCC_VERSION >= 40300) || (CRYPTOPP_CLANG_VERSION >= 20900) || (_INTEL_COMPILER >= 300)) && !(MACPORTS_GCC_COMPILER > 0))
#define HAVE_GCC_CONSTRUCTOR0 (__GNUC__ && (CRYPTOPP_INIT_PRIORITY > 0) && !(MACPORTS_GCC_COMPILER > 0))

extern "C" {
    typedef void (*SigHandler)(int);
};
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#ifdef CRYPTOPP_CPUID_AVAILABLE

#if _MSC_VER >= 1400 && CRYPTOPP_BOOL_X64

bool CpuId(word32 input, word32 output[4])
{
	__cpuid((int *)output, input);
	return true;
}

#else

#ifndef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY
extern "C" {

static jmp_buf s_jmpNoCPUID;
static void SigIllHandlerCPUID(int)
{
	longjmp(s_jmpNoCPUID, 1);
}

static jmp_buf s_jmpNoSSE2;
static void SigIllHandlerSSE2(int)
{
	longjmp(s_jmpNoSSE2, 1);
}
}
#endif

bool CpuId(word32 input, word32 output[4])
{
#if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    __try
	{
		__asm
		{
			mov eax, input
			mov ecx, 0
			cpuid
			mov edi, output
			mov [edi], eax
			mov [edi+4], ebx
			mov [edi+8], ecx
			mov [edi+12], edx
		}
	}
	// GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	// function 0 returns the highest basic function understood in EAX
	if(input == 0)
		return !!output[0];

	return true;
#else
	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24
	// http://stackoverflow.com/q/7721854
	volatile bool result = true;

	SigHandler oldHandler = signal(SIGILL, SigIllHandlerCPUID);
	if (oldHandler == SIG_ERR)
		result = false;

	if (setjmp(s_jmpNoCPUID))
		result = false;
	else
	{
		asm volatile
		(
			// save ebx in case -fPIC is being used
			// TODO: this might need an early clobber on EDI.
# if CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
			"pushq %%rbx; cpuid; mov %%ebx, %%edi; popq %%rbx"
# else
			"push %%ebx; cpuid; mov %%ebx, %%edi; pop %%ebx"
# endif
			: "=a" (output[0]), "=D" (output[1]), "=c" (output[2]), "=d" (output[3])
			: "a" (input), "c" (0)
		);
	}

	signal(SIGILL, oldHandler);
	return result;
#endif
}

#endif

static bool TrySSE2()
{
#if CRYPTOPP_BOOL_X64
	return true;
#elif defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    __try
	{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
		AS2(por xmm0, xmm0)        // executing SSE2 instruction
#elif CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		__m128i x = _mm_setzero_si128();
		return _mm_cvtsi128_si32(x) == 0;
#endif
	}
	// GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return true;
#else
	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24
	// http://stackoverflow.com/q/7721854
	volatile bool result = true;

	SigHandler oldHandler = signal(SIGILL, SigIllHandlerSSE2);
	if (oldHandler == SIG_ERR)
		return false;

	if (setjmp(s_jmpNoSSE2))
		result = true;
	else
	{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
		__asm __volatile ("por %xmm0, %xmm0");
#elif CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		__m128i x = _mm_setzero_si128();
		result = _mm_cvtsi128_si32(x) == 0;
#endif
	}

	signal(SIGILL, oldHandler);
	return result;
#endif
}

bool g_x86DetectionDone = false;
bool g_hasMMX = false, g_hasISSE = false, g_hasSSE2 = false, g_hasSSSE3 = false, g_hasSSE4 = false, g_hasAESNI = false, g_hasCLMUL = false, g_isP4 = false, g_hasRDRAND = false, g_hasRDSEED = false;
word32 g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

static inline bool IsIntel(const word32 output[4])
{
	// This is the "GenuineIntel" string
	return (output[1] /*EBX*/ == 0x756e6547) &&
		(output[2] /*ECX*/ == 0x6c65746e) &&
		(output[3] /*EDX*/ == 0x49656e69);
}

static inline bool IsAMD(const word32 output[4])
{
	// This is the "AuthenticAMD" string
	return (output[1] /*EBX*/ == 0x68747541) &&
		(output[2] /*ECX*/ == 0x69746E65) &&
		(output[3] /*EDX*/ == 0x444D4163);
}

#if HAVE_GCC_CONSTRUCTOR1
void __attribute__ ((constructor (CRYPTOPP_INIT_PRIORITY + 50))) DetectX86Features()
#elif HAVE_GCC_CONSTRUCTOR0
void __attribute__ ((constructor)) DetectX86Features()
#else
void DetectX86Features()
#endif
{
	word32 cpuid[4], cpuid1[4];
	if (!CpuId(0, cpuid))
		return;
	if (!CpuId(1, cpuid1))
		return;

	g_hasMMX = (cpuid1[3] & (1 << 23)) != 0;
	if ((cpuid1[3] & (1 << 26)) != 0)
		g_hasSSE2 = TrySSE2();
	g_hasSSSE3 = g_hasSSE2 && (cpuid1[2] & (1<<9));
	g_hasSSE4 = g_hasSSE2 && ((cpuid1[2] & (1<<19)) && (cpuid1[2] & (1<<20)));
	g_hasAESNI = g_hasSSE2 && (cpuid1[2] & (1<<25));
	g_hasCLMUL = g_hasSSE2 && (cpuid1[2] & (1<<1));

	if ((cpuid1[3] & (1 << 25)) != 0)
		g_hasISSE = true;
	else
	{
		word32 cpuid2[4];
		CpuId(0x080000000, cpuid2);
		if (cpuid2[0] >= 0x080000001)
		{
			CpuId(0x080000001, cpuid2);
			g_hasISSE = (cpuid2[3] & (1 << 22)) != 0;
		}
	}

	static const unsigned int RDRAND_FLAG = (1 << 30);
	static const unsigned int RDSEED_FLAG = (1 << 18);
	if (IsIntel(cpuid))
	{
		g_isP4 = ((cpuid1[0] >> 8) & 0xf) == 0xf;
		g_cacheLineSize = 8 * GETBYTE(cpuid1[1], 1);
		g_hasRDRAND = !!(cpuid1[2] /*ECX*/ & RDRAND_FLAG);

		if (cpuid[0] /*EAX*/ >= 7)
		{
			word32 cpuid3[4];
			if (CpuId(7, cpuid3))
				g_hasRDSEED = !!(cpuid3[1] /*EBX*/ & RDSEED_FLAG);
		}
	}
	else if (IsAMD(cpuid))
	{
		CpuId(0x80000005, cpuid);
		g_cacheLineSize = GETBYTE(cpuid[2], 0);
		g_hasRDRAND = !!(cpuid[2] /*ECX*/ & RDRAND_FLAG);
	}

	if (!g_cacheLineSize)
		g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

	*((volatile bool*)&g_x86DetectionDone) = true;
}

// http://community.arm.com/groups/android-community/blog/2014/10/10/runtime-detection-of-cpu-features-on-an-armv8-a-cpu
// http://stackoverflow.com/questions/26701262/how-to-check-the-existence-of-neon-on-arm
#elif (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64)

bool g_ArmDetectionDone = false;
bool g_hasNEON = false, g_hasCRC32 = false, g_hasCrypto = false;

word32 g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

// The ARM equivalent of CPUID is reading a MSR. For example, fetch crypto capabilities with:
//   #if defined(__arm64__) || defined(__aarch64__)
//	   word64 caps = 0;  // Read ID_AA64ISAR0_EL1
//	   __asm __volatile("mrs %0, " "id_aa64isar0_el1" : "=r" (caps));
//   #elif defined(__arm__) || defined(__aarch32__)
//	   word32 caps = 0;  // Read ID_ISAR5_EL1
//	   __asm __volatile("mrs %0, " "id_isar5_el1" : "=r" (caps));
//   #endif
// The code requires Exception Level 1 (EL1) and above, but user space runs at EL0.
//   Attempting to run the code results in a SIGILL and termination.

#ifndef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY
extern "C" {

	static jmp_buf s_jmpNoNEON;
	static void SigIllHandlerNEON(int)
	{
		longjmp(s_jmpNoNEON, 1);
	}

	static jmp_buf s_jmpNoCRC32;
	static void SigIllHandlerCRC32(int)
	{
		longjmp(s_jmpNoCRC32, 1);
	}

	static jmp_buf s_jmpNoCrypto;
	static void SigIllHandlerCrypto(int)
	{
		longjmp(s_jmpNoCrypto, 1);
	}
};
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

static bool TryNEON()
{
#if (CRYPTOPP_BOOL_NEON_INTRINSICS_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
	__try
	{
		static const uint32_t v1[4] = {1,1,1,1};
		uint32x4_t x1 = vld1q_u32(v1);
		static const uint64_t v2[2] = {1,1};
		uint64x2_t x2 = vld1q_u64(v2);

		uint32x4_t x3 = vdupq_n_u32(0);
		x3 = vsetq_lane_u32(vgetq_lane_u32(x1,0),x3,0);
		x3 = vsetq_lane_u32(vgetq_lane_u32(x1,3),x3,3);
		uint64x2_t x4 = vdupq_n_u64(0);
		x4 = vsetq_lane_u64(vgetq_lane_u64(x2,0),x4,0);
		x4 = vsetq_lane_u64(vgetq_lane_u64(x2,1),x4,1);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return true;
# else
	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24
	// http://stackoverflow.com/q/7721854
	volatile bool result = true;

	SigHandler oldHandler = signal(SIGILL, SigIllHandlerNEON);
	if (oldHandler == SIG_ERR)
		result = false;

	if (setjmp(s_jmpNoNEON))
		result = false;
	else
	{
		static const uint32_t v1[4] = {1,1,1,1};
		uint32x4_t x1 = vld1q_u32(v1);
		static const uint64_t v2[2] = {1,1};
		uint64x2_t x2 = vld1q_u64(v2);

		uint32x4_t x3 = vdupq_n_u32(0);
		x3 = vsetq_lane_u32(vgetq_lane_u32(x1,0),x3,0);
		x3 = vsetq_lane_u32(vgetq_lane_u32(x1,3),x3,3);
		uint64x2_t x4 = vdupq_n_u64(0);
		x4 = vsetq_lane_u64(vgetq_lane_u64(x2,0),x4,0);
		x4 = vsetq_lane_u64(vgetq_lane_u64(x2,1),x4,1);
	}

	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_BOOL_NEON_INTRINSICS_AVAILABLE
}

static bool TryCRC32()
{
#if (CRYPTOPP_BOOL_ARM_CRC32_INTRINSICS_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
	__try
	{
		word32 w=0, x=0; word16 y=0; byte z=0;
		w = __crc32cw(w,x);
		w = __crc32ch(w,y);
		w = __crc32cb(w,z);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return true;
# else
	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24
	// http://stackoverflow.com/q/7721854
	volatile bool result = true;

	SigHandler oldHandler = signal(SIGILL, SigIllHandlerCRC32);
	if (oldHandler == SIG_ERR)
		result = false;

	if (setjmp(s_jmpNoCRC32))
		result = false;
	else
	{
		word32 w=0, x=0; word16 y=0; byte z=0;
		w = __crc32cw(w,x);
		w = __crc32ch(w,y);
		w = __crc32cb(w,z);
	}

	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_BOOL_ARM_CRC32_INTRINSICS_AVAILABLE
}

static bool TryCrypto()
{
#if (CRYPTOPP_BOOL_ARM_CRYPTO_INTRINSICS_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
	__try
	{
		// AES encrypt and decrypt
		static const uint8x16_t data = vdupq_n_u8(0), key = vdupq_n_u8(0); 
		uint8x16_t r1 = vaeseq_u8(data, key);
		uint8x16_t r2 = vaesdq_u8(data, key);

		// 
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return true;
# else
	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24
	// http://stackoverflow.com/q/7721854
	volatile bool result = true;

	SigHandler oldHandler = signal(SIGILL, SigIllHandlerCrypto);
	if (oldHandler == SIG_ERR)
		result = false;

	if (setjmp(s_jmpNoCrypto))
		result = false;
	else
	{
		static const uint8x16_t data = vdupq_n_u8(0), key = vdupq_n_u8(0); 
		uint8x16_t r1 = vaeseq_u8(data, key);
		uint8x16_t r2 = vaesdq_u8(data, key);
	}

	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_BOOL_ARM_CRYPTO_INTRINSICS_AVAILABLE
}

#if HAVE_GCC_CONSTRUCTOR1
void __attribute__ ((constructor (CRYPTOPP_INIT_PRIORITY + 50))) DetectArmFeatures()
#elif HAVE_GCC_CONSTRUCTOR0
void __attribute__ ((constructor)) DetectArmFeatures()
#else
void DetectArmFeatures()
#endif
{
	g_hasNEON = TryNEON();
	g_hasCRC32 = TryCRC32();
	g_hasCrypto = TryCrypto();

	*((volatile bool*)&g_ArmDetectionDone) = true;
}

#endif

NAMESPACE_END

#endif
