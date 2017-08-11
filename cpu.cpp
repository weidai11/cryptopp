// cpu.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "config.h"

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

#ifndef CRYPTOPP_IMPORTS

#include "cpu.h"
#include "misc.h"
#include "stdcpp.h"

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
#include <signal.h>
#include <setjmp.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifndef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY
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
extern "C"
{
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
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile bool result = true;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandlerCPUID);
	if (oldHandler == SIG_ERR)
		return false;

# ifndef __MINGW32__
	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;
# endif

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
			: "cc"
		);
	}

# ifndef __MINGW32__
	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
# endif

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
#elif CRYPTOPP_SSE2_AVAILABLE
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
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile bool result = true;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandlerSSE2);
	if (oldHandler == SIG_ERR)
		return false;

# ifndef __MINGW32__
	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;
# endif

	if (setjmp(s_jmpNoSSE2))
		result = false;
	else
	{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
		__asm __volatile ("por %xmm0, %xmm0");
#elif CRYPTOPP_SSE2_AVAILABLE
		__m128i x = _mm_setzero_si128();
		result = _mm_cvtsi128_si32(x) == 0;
#endif
	}

# ifndef __MINGW32__
	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
# endif

	signal(SIGILL, oldHandler);
	return result;
#endif
}

bool CRYPTOPP_SECTION_INIT g_x86DetectionDone = false;
bool CRYPTOPP_SECTION_INIT CRYPTOPP_SECTION_INIT g_hasSSE2 = false, CRYPTOPP_SECTION_INIT g_hasSSSE3 = false;
bool CRYPTOPP_SECTION_INIT g_hasSSE41 = false, CRYPTOPP_SECTION_INIT g_hasSSE42 = false;
bool CRYPTOPP_SECTION_INIT g_hasAESNI = false, CRYPTOPP_SECTION_INIT g_hasCLMUL = false, CRYPTOPP_SECTION_INIT g_hasSHA = false;
bool CRYPTOPP_SECTION_INIT g_hasRDRAND = false, CRYPTOPP_SECTION_INIT g_hasRDSEED = false, CRYPTOPP_SECTION_INIT g_isP4 = false;
bool CRYPTOPP_SECTION_INIT g_hasPadlockRNG = false, CRYPTOPP_SECTION_INIT g_hasPadlockACE = false, CRYPTOPP_SECTION_INIT g_hasPadlockACE2 = false;
bool CRYPTOPP_SECTION_INIT g_hasPadlockPHE = false, CRYPTOPP_SECTION_INIT g_hasPadlockPMM = false;
word32 CRYPTOPP_SECTION_INIT g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

static inline bool IsIntel(const word32 output[4])
{
	// This is the "GenuineIntel" string
	return (output[1] /*EBX*/ == 0x756e6547) &&
		(output[2] /*ECX*/ == 0x6c65746e) &&
		(output[3] /*EDX*/ == 0x49656e69);
}

static inline bool IsAMD(const word32 output[4])
{
	// This is the "AuthenticAMD" string. Some early K5's can return "AMDisbetter!"
	return (output[1] /*EBX*/ == 0x68747541) &&
		(output[2] /*ECX*/ == 0x444D4163) &&
		(output[3] /*EDX*/ == 0x69746E65);
}

static inline bool IsVIA(const word32 output[4])
{
	// This is the "CentaurHauls" string. Some non-PadLock's can return "VIA VIA VIA "
	return (output[1] /*EBX*/ == 0x746e6543) &&
		(output[2] /*ECX*/ == 0x736c7561) &&
		(output[3] /*EDX*/ == 0x48727561);
}

void DetectX86Features()
{
	// Coverity finding CID 171239...
	word32 cpuid0[4]={0}, cpuid1[4]={0}, cpuid2[4]={0};
	if (!CpuId(0, cpuid0))
		return;
	if (!CpuId(1, cpuid1))
		return;

	if ((cpuid1[3] & (1 << 26)) != 0)
		g_hasSSE2 = TrySSE2();
	g_hasSSSE3 = g_hasSSE2 && (cpuid1[2] & (1<<9));
	g_hasSSE41 = g_hasSSE2 && (cpuid1[2] & (1<<19));
	g_hasSSE42 = g_hasSSE2 && (cpuid1[2] & (1<<20));
	g_hasAESNI = g_hasSSE2 && (cpuid1[2] & (1<<25));
	g_hasCLMUL = g_hasSSE2 && (cpuid1[2] & (1<<1));

	if (IsIntel(cpuid0))
	{
		enum { RDRAND_FLAG = (1 << 30) };
		enum { RDSEED_FLAG = (1 << 18) };
		enum {    SHA_FLAG = (1 << 29) };

		g_isP4 = ((cpuid1[0] >> 8) & 0xf) == 0xf;
		g_cacheLineSize = 8 * GETBYTE(cpuid1[1], 1);
		g_hasRDRAND = !!(cpuid1[2] /*ECX*/ & RDRAND_FLAG);

		if (cpuid0[0] /*EAX*/ >= 7)
		{
			if (CpuId(7, cpuid2))
			{
				g_hasRDSEED = !!(cpuid2[1] /*EBX*/ & RDSEED_FLAG);
				g_hasSHA = !!(cpuid2[1] /*EBX*/ & SHA_FLAG);
			}
		}
	}
	else if (IsAMD(cpuid0))
	{
		enum { RDRAND_FLAG = (1 << 30) };
		enum { RDSEED_FLAG = (1 << 18) };
		enum {    SHA_FLAG = (1 << 29) };

		CpuId(0x80000005, cpuid2);
		g_cacheLineSize = GETBYTE(cpuid2[2], 0);
		g_hasRDRAND = !!(cpuid1[2] /*ECX*/ & RDRAND_FLAG);

		if (cpuid1[0] /*EAX*/ >= 7)
		{
			if (CpuId(7, cpuid2))
			{
				g_hasRDSEED = !!(cpuid2[1] /*EBX*/ & RDSEED_FLAG);
				g_hasSHA = !!(cpuid2[1] /*EBX*/ & SHA_FLAG);
			}
		}
	}
	else if (IsVIA(cpuid0))
	{
		enum {  RNG_FLAGS = (0x3 << 2) };
		enum {  ACE_FLAGS = (0x3 << 6) };
		enum { ACE2_FLAGS = (0x3 << 8) };
		enum {  PHE_FLAGS = (0x3 << 10) };
		enum {  PMM_FLAGS = (0x3 << 12) };

		CpuId(0xC0000000, cpuid0);
		if (cpuid0[0] >= 0xC0000001)
		{
			// Extended features available
			CpuId(0xC0000001, cpuid0);
			g_hasPadlockRNG  = !!(cpuid0[3] /*EDX*/ & RNG_FLAGS);
			g_hasPadlockACE  = !!(cpuid0[3] /*EDX*/ & ACE_FLAGS);
			g_hasPadlockACE2 = !!(cpuid0[3] /*EDX*/ & ACE2_FLAGS);
			g_hasPadlockPHE  = !!(cpuid0[3] /*EDX*/ & PHE_FLAGS);
			g_hasPadlockPMM  = !!(cpuid0[3] /*EDX*/ & PMM_FLAGS);
		}
	}

	if (!g_cacheLineSize)
		g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

	g_x86DetectionDone = true;
}

#elif (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64)

// The ARM equivalent of CPUID probing is reading a MSR. The code requires Exception Level 1 (EL1)
//   and above, but user space runs at EL0. Attempting to run the code results in a SIGILL and termination.
//
//     #if defined(__arm64__) || defined(__aarch64__)
//	     word64 caps = 0;  // Read ID_AA64ISAR0_EL1
//	     __asm __volatile("mrs %0, " "id_aa64isar0_el1" : "=r" (caps));
//     #elif defined(__arm__) || defined(__aarch32__)
//	     word32 caps = 0;  // Read ID_ISAR5_EL1
//	     __asm __volatile("mrs %0, " "id_isar5_el1" : "=r" (caps));
//     #endif
//
// The following does not work well either. Its appears to be missing constants, and it does not detect
//   Aarch32 execution environments on Aarch64
//   http://community.arm.com/groups/android-community/blog/2014/10/10/runtime-detection-of-cpu-features-on-an-armv8-a-cpu
//
bool CRYPTOPP_SECTION_INIT g_ArmDetectionDone = false;
bool CRYPTOPP_SECTION_INIT g_hasNEON = false, CRYPTOPP_SECTION_INIT g_hasPMULL = false, CRYPTOPP_SECTION_INIT g_hasCRC32 = false;
bool CRYPTOPP_SECTION_INIT g_hasAES = false, CRYPTOPP_SECTION_INIT g_hasSHA1 = false, CRYPTOPP_SECTION_INIT g_hasSHA2 = false;
word32 CRYPTOPP_SECTION_INIT g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

extern bool CPU_TryNEON_ARM();
extern bool CPU_TryAES_ARMV8();
extern bool CPU_TrySHA1_ARMV8();
extern bool CPU_TrySHA2_ARMV8();
extern bool CPU_TryCRC32_ARMV8();
extern bool CPU_TryPMULL_ARMV8();

void DetectArmFeatures()
{
	g_hasNEON = CPU_TryNEON_ARM();
	g_hasPMULL = CPU_TryPMULL_ARMV8();
	g_hasCRC32 = CPU_TryCRC32_ARMV8();
	g_hasAES = CPU_TryAES_ARMV8();
	g_hasSHA1 = CPU_TrySHA1_ARMV8();
	g_hasSHA2 = CPU_TrySHA2_ARMV8();

	g_ArmDetectionDone = true;
}

#endif
NAMESPACE_END

// ***************** C++ Static Initialization ********************

ANONYMOUS_NAMESPACE_BEGIN
struct InitializeCpu
{
	InitializeCpu()
	{
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
		CryptoPP::DetectX86Features();
#elif CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64
		CryptoPP::DetectArmFeatures();
#endif
	}
};

#if HAVE_GCC_INIT_PRIORITY
const InitializeCpu s_init __attribute__ ((init_priority (CRYPTOPP_INIT_PRIORITY + 20))) = InitializeCpu();
#elif HAVE_MSC_INIT_PRIORITY
#pragma warning(disable: 4075)
#pragma init_seg(".CRT$XCU-020")
const InitializeCpu s_init;
#pragma warning(default: 4075)
#else
const InitializeCpu& s_init = CryptoPP::Singleton<InitializeCpu>().Ref();
#endif
ANONYMOUS_NAMESPACE_END

#endif  // CRYPTOPP_IMPORTS
