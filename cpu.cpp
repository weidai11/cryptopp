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

#ifdef _AIX
# include <sys/systemcfg.h>
#endif

#ifdef __linux__
# include <unistd.h>
#endif

// Capability queries, requires Glibc 2.16, http://lwn.net/Articles/519085/
// CRYPTOPP_GLIBC_VERSION not used because config.h is missing <feature.h>
#if (((__GLIBC__ * 100) + __GLIBC_MINOR__) >= 216)
# define CRYPTOPP_GETAUXV_AVAILABLE 1
#endif

#if CRYPTOPP_GETAUXV_AVAILABLE
# include <sys/auxv.h>
#else
#ifndef AT_HWCAP
# define AT_HWCAP 16
#endif
#ifndef AT_HWCAP2
# define AT_HWCAP2 26
#endif
unsigned long int getauxval(unsigned long int) { return 0; }
#endif

#if defined(__APPLE__) && (defined(__aarch64__) || defined(__POWERPC__))
# include <sys/utsname.h>
#endif

// The cpu-features header and source file are located in $ANDROID_NDK_ROOT/sources/android/cpufeatures
// setenv-android.sh will copy the header and source file into PWD and the makefile will build it in place.
#if defined(__ANDROID__)
# include "cpu-features.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifndef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY
extern "C" {
    typedef void (*SigHandler)(int);
}

extern "C"
{
	static jmp_buf s_jmpNoCPUID;
	static void SigIllHandlerCPUID(int unused)
	{
		CRYPTOPP_UNUSED(unused);
		longjmp(s_jmpNoCPUID, 1);
	}
}
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

// *************************** IA-32 CPUs ***************************

#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)

extern bool CPU_ProbeSSE2();

#if _MSC_VER >= 1600

inline bool CpuId(word32 func, word32 subfunc, word32 output[4])
{
	__cpuidex((int *)output, func, subfunc);
	return true;
}

#elif _MSC_VER >= 1400 && CRYPTOPP_BOOL_X64

inline bool CpuId(word32 func, word32 subfunc, word32 output[4])
{
	if (subfunc != 0)
		return false;

	__cpuid((int *)output, func);
	return true;
}

#else

// Borland/Embarcadero and Issue 498
// cpu.cpp (131): E2211 Inline assembly not allowed in inline and template functions
bool CpuId(word32 func, word32 subfunc, word32 output[4])
{
#if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY) || defined(__BORLANDC__)
    __try
	{
		// Borland/Embarcadero and Issue 500
		// Local variables for cpuid output
		word32 a, b, c, d;
		__asm
		{
			mov eax, func
			mov ecx, subfunc
			cpuid
			mov [a], eax
			mov [b], ebx
			mov [c], ecx
			mov [d], edx
		}
		output[0] = a;
		output[1] = b;
		output[2] = c;
		output[3] = d;
	}
	// GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	// func = 0 returns the highest basic function understood in EAX. If the CPU does
	// not return non-0, then it is mostly useless. The code below converts basic
	// function value to a true/false return value.
	if(func == 0)
		return output[0] != 0;

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
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask) != 0)
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
			: "a" (func), "c" (subfunc)
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

bool CRYPTOPP_SECTION_INIT g_x86DetectionDone = false;
bool CRYPTOPP_SECTION_INIT g_hasSSE2 = false;
bool CRYPTOPP_SECTION_INIT g_hasSSSE3 = false;
bool CRYPTOPP_SECTION_INIT g_hasSSE41 = false;
bool CRYPTOPP_SECTION_INIT g_hasSSE42 = false;
bool CRYPTOPP_SECTION_INIT g_hasAESNI = false;
bool CRYPTOPP_SECTION_INIT g_hasCLMUL = false;
bool CRYPTOPP_SECTION_INIT g_hasADX = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA = false;
bool CRYPTOPP_SECTION_INIT g_hasRDRAND = false;
bool CRYPTOPP_SECTION_INIT g_hasRDSEED = false;
bool CRYPTOPP_SECTION_INIT g_isP4 = false;
bool CRYPTOPP_SECTION_INIT g_hasPadlockRNG = false;
bool CRYPTOPP_SECTION_INIT g_hasPadlockACE = false;
bool CRYPTOPP_SECTION_INIT g_hasPadlockACE2 = false;
bool CRYPTOPP_SECTION_INIT g_hasPadlockPHE = false;
bool CRYPTOPP_SECTION_INIT g_hasPadlockPMM = false;
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
	if (!CpuId(0, 0, cpuid0))
		return;
	if (!CpuId(1, 0, cpuid1))
		return;

	// cpuid1[2] & (1 << 27) is XSAVE/XRESTORE and signals OS support for SSE; use it to avoid probes.
	// See http://github.com/weidai11/cryptopp/issues/511 and http://stackoverflow.com/a/22521619/608639
	if ((cpuid1[3] & (1 << 26)) != 0)
		g_hasSSE2 = ((cpuid1[2] & (1 << 27)) != 0) || CPU_ProbeSSE2();

	g_hasSSSE3 = g_hasSSE2 && ((cpuid1[2] & (1<< 9)) != 0);
	g_hasSSE41 = g_hasSSE2 && ((cpuid1[2] & (1<<19)) != 0);
	g_hasSSE42 = g_hasSSE2 && ((cpuid1[2] & (1<<20)) != 0);
	g_hasAESNI = g_hasSSE2 && ((cpuid1[2] & (1<<25)) != 0);
	g_hasCLMUL = g_hasSSE2 && ((cpuid1[2] & (1<< 1)) != 0);

	if (IsIntel(cpuid0))
	{
		CRYPTOPP_CONSTANT(RDRAND_FLAG = (1 << 30))
		CRYPTOPP_CONSTANT(RDSEED_FLAG = (1 << 18))
		CRYPTOPP_CONSTANT(   ADX_FLAG = (1 << 19))
		CRYPTOPP_CONSTANT(   SHA_FLAG = (1 << 29))

		g_isP4 = ((cpuid1[0] >> 8) & 0xf) == 0xf;
		g_cacheLineSize = 8 * GETBYTE(cpuid1[1], 1);
		g_hasRDRAND = (cpuid1[2] /*ECX*/ & RDRAND_FLAG) != 0;

		if (cpuid0[0] /*EAX*/ >= 7)
		{
			if (CpuId(7, 0, cpuid2))
			{
				g_hasRDSEED = (cpuid2[1] /*EBX*/ & RDSEED_FLAG) != 0;
				g_hasADX = (cpuid2[1] /*EBX*/ & ADX_FLAG) != 0;
				g_hasSHA = (cpuid2[1] /*EBX*/ & SHA_FLAG) != 0;
			}
		}
	}
	else if (IsAMD(cpuid0))
	{
		CRYPTOPP_CONSTANT(RDRAND_FLAG = (1 << 30))
		CRYPTOPP_CONSTANT(RDSEED_FLAG = (1 << 18))
		CRYPTOPP_CONSTANT(   ADX_FLAG = (1 << 19))
		CRYPTOPP_CONSTANT(   SHA_FLAG = (1 << 29))

		CpuId(0x80000005, 0, cpuid2);
		g_cacheLineSize = GETBYTE(cpuid2[2], 0);
		g_hasRDRAND = (cpuid1[2] /*ECX*/ & RDRAND_FLAG) != 0;

		if (cpuid0[0] /*EAX*/ >= 7)
		{
			if (CpuId(7, 0, cpuid2))
			{
				g_hasRDSEED = (cpuid2[1] /*EBX*/ & RDSEED_FLAG) != 0;
				g_hasADX = (cpuid2[1] /*EBX*/ & ADX_FLAG) != 0;
				g_hasSHA = (cpuid2[1] /*EBX*/ & SHA_FLAG) != 0;
			}
		}
	}
	else if (IsVIA(cpuid0))
	{
		CRYPTOPP_CONSTANT( RNG_FLAGS = (0x3 << 2))
		CRYPTOPP_CONSTANT( ACE_FLAGS = (0x3 << 6))
		CRYPTOPP_CONSTANT(ACE2_FLAGS = (0x3 << 8))
		CRYPTOPP_CONSTANT( PHE_FLAGS = (0x3 << 10))
		CRYPTOPP_CONSTANT( PMM_FLAGS = (0x3 << 12))

		CpuId(0xC0000000, 0, cpuid2);
		if (cpuid2[0] >= 0xC0000001)
		{
			// Extended features available
			CpuId(0xC0000001, 0, cpuid2);
			g_hasPadlockRNG  = (cpuid2[3] /*EDX*/ & RNG_FLAGS) != 0;
			g_hasPadlockACE  = (cpuid2[3] /*EDX*/ & ACE_FLAGS) != 0;
			g_hasPadlockACE2 = (cpuid2[3] /*EDX*/ & ACE2_FLAGS) != 0;
			g_hasPadlockPHE  = (cpuid2[3] /*EDX*/ & PHE_FLAGS) != 0;
			g_hasPadlockPMM  = (cpuid2[3] /*EDX*/ & PMM_FLAGS) != 0;
		}
	}

	if (g_cacheLineSize == 0)
		g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

	*const_cast<volatile bool*>(&g_x86DetectionDone) = true;
}

// *************************** ARM-32, Aarch32 and Aarch64 ***************************

#elif (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64)

bool CRYPTOPP_SECTION_INIT g_ArmDetectionDone = false;
bool CRYPTOPP_SECTION_INIT g_hasNEON = false;
bool CRYPTOPP_SECTION_INIT g_hasPMULL = false;
bool CRYPTOPP_SECTION_INIT g_hasCRC32 = false;
bool CRYPTOPP_SECTION_INIT g_hasAES = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA1 = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA2 = false;
word32 CRYPTOPP_SECTION_INIT g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

// ARM does not have an unprivliged equivalent to CPUID on IA-32. We have to jump through some
//   hoops to detect features on a wide array of platforms. Our strategy is two part. First,
//   attempt to *Query* the OS for a feature, like using getauxval on Linux. If that fails,
//   then *Probe* the cpu executing an instruction and an observe a SIGILL if unsupported.
// The probes are in source files where compilation options like -march=armv8-a+crc make
//   intrinsics available. They are expensive when compared to a standard OS feature query.
//   Always perform the feature quesry first. For Linux see
//   http://sourceware.org/ml/libc-help/2017-08/msg00012.html
// Avoid probes on Apple platforms because Apple's signal handling for SIGILLs appears broken.
//   We are trying to figure out a way to feature test without probes. Also see
//   http://stackoverflow.com/a/11197770/608639 and
//   http://gist.github.com/erkanyildiz/390a480f27e86f8cd6ba

extern bool CPU_ProbeNEON();
extern bool CPU_ProbeCRC32();
extern bool CPU_ProbeAES();
extern bool CPU_ProbeSHA1();
extern bool CPU_ProbeSHA2();
extern bool CPU_ProbePMULL();

#ifndef HWCAP_ASIMD
# define HWCAP_ASIMD (1 << 1)
#endif
#ifndef HWCAP_ARM_NEON
# define HWCAP_ARM_NEON 4096
#endif
#ifndef HWCAP_CRC32
# define HWCAP_CRC32 (1 << 7)
#endif
#ifndef HWCAP2_CRC32
# define HWCAP2_CRC32 (1 << 4)
#endif
#ifndef HWCAP_PMULL
# define HWCAP_PMULL (1 << 4)
#endif
#ifndef HWCAP2_PMULL
# define HWCAP2_PMULL (1 << 1)
#endif
#ifndef HWCAP_AES
# define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP2_AES
# define HWCAP2_AES (1 << 0)
#endif
#ifndef HWCAP_SHA1
# define HWCAP_SHA1 (1 << 5)
#endif
#ifndef HWCAP_SHA2
# define HWCAP_SHA2 (1 << 6)
#endif
#ifndef HWCAP2_SHA1
# define HWCAP2_SHA1 (1 << 2)
#endif
#ifndef HWCAP2_SHA2
# define HWCAP2_SHA2 (1 << 3)
#endif

inline bool CPU_QueryNEON()
{
#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_ASIMD) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM)  != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_ASIMD) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_ASIMD) != 0)
		return true;
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_ARM_NEON) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__)
	// Core feature set for Aarch32 and Aarch64.
	return true;
#endif
	return false;
}

inline bool CPU_QueryCRC32()
{
#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_CRC32) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM)  != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_CRC32) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_CRC32) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_CRC32) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__)
	// No compiler support. CRC intrinsics result in a failed compiled.
	return false;
#endif
	return false;
}

inline bool CPU_QueryPMULL()
{
#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64)  != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_PMULL) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_PMULL) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_PMULL) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_PMULL) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__)
	// No compiler support. PMULL intrinsics result in a failed compiled.
	return false;
#endif
	return false;
}

inline bool CPU_QueryAES()
{
#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64)  != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_AES) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM)  != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_AES) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_AES) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__)
	// http://stackoverflow.com/questions/45637888/how-to-determine-armv8-features-at-runtime-on-ios
	struct utsname systemInfo;
	systemInfo.machine[0] = '\0';
	uname(&systemInfo);

	// The machine strings below are known ARM8 devices
	std::string machine(systemInfo.machine);
	if (machine.substr(0, 7) == "iPhone6" || machine.substr(0, 7) == "iPhone7" ||
		machine.substr(0, 7) == "iPhone8" || machine.substr(0, 7) == "iPhone9" ||
		machine.substr(0, 5) == "iPad4" || machine.substr(0, 5) == "iPad5" ||
		machine.substr(0, 5) == "iPad6" || machine.substr(0, 5) == "iPad7")
	{
		return true;
	}
#endif
	return false;
}

inline bool CPU_QuerySHA1()
{
#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA1) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA1) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA1) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA1) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__)
	// http://stackoverflow.com/questions/45637888/how-to-determine-armv8-features-at-runtime-on-ios
	struct utsname systemInfo;
	systemInfo.machine[0] = '\0';
	uname(&systemInfo);

	// The machine strings below are known ARM8 devices
	std::string machine(systemInfo.machine);
	if (machine.substr(0, 7) == "iPhone6" || machine.substr(0, 7) == "iPhone7" ||
		machine.substr(0, 7) == "iPhone8" || machine.substr(0, 7) == "iPhone9" ||
		machine.substr(0, 5) == "iPad4" || machine.substr(0, 5) == "iPad5" ||
		machine.substr(0, 5) == "iPad6" || machine.substr(0, 5) == "iPad7")
	{
		return true;
	}
#endif
	return false;
}

inline bool CPU_QuerySHA2()
{
#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64)  != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA2) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA2) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA2) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA2) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__)
	// http://stackoverflow.com/questions/45637888/how-to-determine-armv8-features-at-runtime-on-ios
	struct utsname systemInfo;
	systemInfo.machine[0] = '\0';
	uname(&systemInfo);

	// The machine strings below are known ARM8 devices
	std::string machine(systemInfo.machine);
	if (machine.substr(0, 7) == "iPhone6" || machine.substr(0, 7) == "iPhone7" ||
		machine.substr(0, 7) == "iPhone8" || machine.substr(0, 7) == "iPhone9" ||
		machine.substr(0, 5) == "iPad4" || machine.substr(0, 5) == "iPad5" ||
		machine.substr(0, 5) == "iPad6" || machine.substr(0, 5) == "iPad7")
	{
		return true;
	}
#endif
	return false;
}

void DetectArmFeatures()
{
	// The CPU_ProbeXXX's return false for OSes which
	//   can't tolerate SIGILL-based probes
	g_hasNEON  = CPU_QueryNEON() || CPU_ProbeNEON();
	g_hasCRC32 = CPU_QueryCRC32() || CPU_ProbeCRC32();
	g_hasPMULL = CPU_QueryPMULL() || CPU_ProbePMULL();
	g_hasAES  = CPU_QueryAES() || CPU_ProbeAES();
	g_hasSHA1 = CPU_QuerySHA1() || CPU_ProbeSHA1();
	g_hasSHA2 = CPU_QuerySHA2() || CPU_ProbeSHA2();

#if defined(__linux__) && defined(_SC_LEVEL1_DCACHE_LINESIZE)
	// Glibc does not implement on some platforms. The runtime returns 0 instead of error.
	// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/posix/sysconf.c
	int cacheLineSize = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	if (cacheLineSize > 0)
		g_cacheLineSize = cacheLineSize;
#endif

	*const_cast<volatile bool*>(&g_ArmDetectionDone) = true;
}

// *************************** PowerPC and PowerPC64 ***************************

#elif (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)

bool CRYPTOPP_SECTION_INIT g_PowerpcDetectionDone = false;
bool CRYPTOPP_SECTION_INIT g_hasAltivec = false;
bool CRYPTOPP_SECTION_INIT g_hasPower7 = false;
bool CRYPTOPP_SECTION_INIT g_hasPower8 = false;
bool CRYPTOPP_SECTION_INIT g_hasAES = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA256 = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA512 = false;
word32 CRYPTOPP_SECTION_INIT g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

extern bool CPU_ProbeAltivec();
extern bool CPU_ProbePower7();
extern bool CPU_ProbePower8();
extern bool CPU_ProbeAES();
extern bool CPU_ProbeSHA256();
extern bool CPU_ProbeSHA512();

#ifndef PPC_FEATURE_HAS_ALTIVEC
# define PPC_FEATURE_HAS_ALTIVEC  0x10000000
#endif
#ifndef PPC_FEATURE_ARCH_2_06
# define PPC_FEATURE_ARCH_2_06    0x00000100
#endif
#ifndef PPC_FEATURE2_ARCH_2_07
# define PPC_FEATURE2_ARCH_2_07   0x80000000
#endif
#ifndef PPC_FEATURE2_VEC_CRYPTO
# define PPC_FEATURE2_VEC_CRYPTO  0x02000000
#endif

inline bool CPU_QueryAltivec()
{
#if defined(__linux__)
	if ((getauxval(AT_HWCAP) & PPC_FEATURE_HAS_ALTIVEC) != 0)
		return true;
#elif defined(_AIX)
	if (__power_vmx() != 0)
		return true;
#elif defined(__APPLE__) && defined(__POWERPC__)
	// http://stackoverflow.com/questions/45637888/how-to-determine-armv8-features-at-runtime-on-ios
	struct utsname systemInfo;
	systemInfo.machine[0] = '\0';
	uname(&systemInfo);

	// The machine strings below are known PPC machines
	std::string machine(systemInfo.machine);
	if (machine.substr(0, 15) == "Power Macintosh")
	{
		return true;
	}
#endif
	return false;
}

inline bool CPU_QueryPower7()
{
	// Power7 and ISA 2.06
#if defined(__linux__)
	if ((getauxval(AT_HWCAP) & PPC_FEATURE_ARCH_2_06) != 0)
		return true;
#elif defined(_AIX)
	if (__power_7_andup() != 0)
		return true;
#endif
	return false;
}

inline bool CPU_QueryPower8()
{
	// Power8 and ISA 2.07 provide in-core crypto.
#if defined(__linux__)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_ARCH_2_07) != 0)
		return true;
#elif defined(_AIX)
	if (__power_8_andup() != 0)
		return true;
#endif
	return false;
}

inline bool CPU_QueryAES()
{
	// Power8 and ISA 2.07 provide in-core crypto. Glibc
	// 2.24 or higher is required for PPC_FEATURE2_VEC_CRYPTO.
#if defined(__linux__)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_VEC_CRYPTO) != 0)
		return true;
#elif defined(_AIX)
	if (__power_8_andup() != 0)
		return true;
#endif
	return false;
}

inline bool CPU_QuerySHA256()
{
	// Power8 and ISA 2.07 provide in-core crypto. Glibc
	// 2.24 or higher is required for PPC_FEATURE2_VEC_CRYPTO.
#if defined(__linux__)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_VEC_CRYPTO) != 0)
		return true;
#elif defined(_AIX)
	if (__power_8_andup() != 0)
		return true;
#endif
	return false;
}
inline bool CPU_QuerySHA512()
{
	// Power8 and ISA 2.07 provide in-core crypto. Glibc
	// 2.24 or higher is required for PPC_FEATURE2_VEC_CRYPTO.
#if defined(__linux__)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_VEC_CRYPTO) != 0)
		return true;
#elif defined(_AIX)
	if (__power_8_andup() != 0)
		return true;
#endif
	return false;
}

void DetectPowerpcFeatures()
{
	// The CPU_ProbeXXX's return false for OSes which
	//   can't tolerate SIGILL-based probes, like Apple
	g_hasAltivec  = CPU_QueryAltivec() || CPU_ProbeAltivec();
	g_hasPower7 = CPU_QueryPower7() || CPU_ProbePower7();
	g_hasPower8 = CPU_QueryPower8() || CPU_ProbePower8();
	//g_hasPMULL = CPU_QueryPMULL() || CPU_ProbePMULL();
	g_hasAES  = CPU_QueryAES() || CPU_ProbeAES();
	g_hasSHA256 = CPU_QuerySHA256() || CPU_ProbeSHA256();
	g_hasSHA512 = CPU_QuerySHA512() || CPU_ProbeSHA512();

#if defined(_AIX) && defined(SC_L1C_DLS)
	// /usr/include/sys/systemcfg.h
	int cacheLineSize = getsystemcfg(SC_L1C_DLS);
	if (cacheLineSize > 0)
		g_cacheLineSize = cacheLineSize;
#elif defined(__linux__) && defined(_SC_LEVEL1_DCACHE_LINESIZE)
	// Glibc does not implement on some platforms. The runtime returns 0 instead of error.
	// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/posix/sysconf.c
	int cacheLineSize = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	if (cacheLineSize > 0)
		g_cacheLineSize = cacheLineSize;
#endif

	*const_cast<volatile bool*>(&g_PowerpcDetectionDone) = true;
}

#endif
NAMESPACE_END

// *************************** C++ Static Initialization ***************************

ANONYMOUS_NAMESPACE_BEGIN

class InitCpu
{
public:
	InitCpu()
	{
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
		CryptoPP::DetectX86Features();
#elif CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64
		CryptoPP::DetectArmFeatures();
#elif CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64
		CryptoPP::DetectPowerpcFeatures();
#endif
	}
};

// This is not really needed because HasSSE() and friends can dynamically initialize.
// Everything depends on CPU features so we initialize it once at load time.
// Dynamic initialization will be used if init priorities are not available.

#if HAVE_GCC_INIT_PRIORITY
	const InitCpu s_init __attribute__ ((init_priority (CRYPTOPP_INIT_PRIORITY + 10))) = InitCpu();
#elif HAVE_MSC_INIT_PRIORITY
	#pragma warning(disable: 4075)
	#pragma init_seg(".CRT$XCU")
	const InitCpu s_init;
	#pragma warning(default: 4075)
#else
	const InitCpu s_init;
#endif

ANONYMOUS_NAMESPACE_END

#endif  // CRYPTOPP_IMPORTS
