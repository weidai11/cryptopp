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

#if defined(__APPLE__)
# include <sys/utsname.h>
#endif

// The cpu-features header and source file are located in
// "$ANDROID_NDK_ROOT/sources/android/cpufeatures".
// setenv-android.sh will copy the header and source file
// into PWD and the makefile will build it in place.
#if defined(__ANDROID__)
# include "cpu-features.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

// Visual Studio 2008 and below is missing _xgetbv. See x64dll.asm for the body.
#if defined(_MSC_VER) && _MSC_VER <= 1500 && defined(_M_X64)
extern "C" unsigned long long __fastcall XGETBV64(unsigned int);
#endif

ANONYMOUS_NAMESPACE_BEGIN

#if defined(__APPLE__)
enum {PowerMac=1, Mac, iPhone, iPod, iPad, AppleTV, AppleWatch};
void GetAppleMachineInfo(unsigned int& device, unsigned int& version)
{
	device = version = 0;

	struct utsname systemInfo;
	systemInfo.machine[0] = '\0';
	uname(&systemInfo);

	std::string machine(systemInfo.machine);
	if (machine.find("PowerMac") != std::string::npos ||
	    machine.find("Power Macintosh") != std::string::npos)
		device = PowerMac;
	else if (machine.find("Mac") != std::string::npos ||
	         machine.find("Macintosh") != std::string::npos)
		device = Mac;
	else if (machine.find("iPhone") != std::string::npos)
		device = iPhone;
	else if (machine.find("iPod") != std::string::npos)
		device = iPod;
	else if (machine.find("iPad") != std::string::npos)
		device = iPad;
	else if (machine.find("AppleTV") != std::string::npos)
		device = AppleTV;
	else if (machine.find("AppleWatch") != std::string::npos)
		device = AppleWatch;

	std::string::size_type pos = machine.find_first_of("0123456789");
	if (pos != std::string::npos)
		version = std::atoi(machine.substr(pos).c_str());
}

// http://stackoverflow.com/questions/45637888/how-to-determine-armv8-features-at-runtime-on-ios
bool IsAppleMachineARMv8(unsigned int device, unsigned int version)
{
	if ((device == iPhone && version >= 6) ||
	    (device == iPad && version >= 4))
	{
		return true;
	}
	return false;
}

bool IsAppleMachineARMv84(unsigned int device, unsigned int version)
{
    CRYPTOPP_UNUSED(device);
    CRYPTOPP_UNUSED(version);
	return false;
}
#endif  // __APPLE__

ANONYMOUS_NAMESPACE_END

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
bool CRYPTOPP_SECTION_INIT g_hasAVX = false;
bool CRYPTOPP_SECTION_INIT g_hasAVX2 = false;
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
	// This is the "AuthenticAMD" string.
	return ((output[1] /*EBX*/ == 0x68747541) &&
		(output[2] /*ECX*/ == 0x444D4163) &&
		(output[3] /*EDX*/ == 0x69746E65)) ||
		// Some early K5's can return "AMDisbetter!"
		((output[1] /*EBX*/ == 0x69444d41) &&
		(output[2] /*ECX*/ == 0x74656273) &&
		(output[3] /*EDX*/ == 0x21726574));
}

static inline bool IsHygon(const word32 output[4])
{
	// This is the "HygonGenuine" string.
	return (output[1] /*EBX*/ == 0x6f677948) &&
		(output[2] /*ECX*/ == 0x656e6975) &&
		(output[3] /*EDX*/ == 0x6e65476e);
}

static inline bool IsVIA(const word32 output[4])
{
	// This is the "CentaurHauls" string.
	return ((output[1] /*EBX*/ == 0x746e6543) &&
		(output[2] /*ECX*/ == 0x736c7561) &&
		(output[3] /*EDX*/ == 0x48727561)) ||
		// Some non-PadLock's return "VIA VIA VIA "
		((output[1] /*EBX*/ == 0x32414956) &&
		(output[2] /*ECX*/ == 0x32414956) &&
		(output[3] /*EDX*/ == 0x32414956));
}

void DetectX86Features()
{
	// Coverity finding CID 171239. Initialize arrays.
	word32 cpuid0[4]={0}, cpuid1[4]={0}, cpuid2[4]={0};

#if defined(CRYPTOPP_DISABLE_ASM)
	// Not available
	goto done;
#else
	if (!CpuId(0, 0, cpuid0))
		goto done;
	if (!CpuId(1, 0, cpuid1))
		goto done;
#endif

	// cpuid1[2] & (1 << 27) is XSAVE/XRESTORE and signals OS support for SSE;
	// use it to avoid probes. See http://stackoverflow.com/a/22521619/608639
	// and http://github.com/weidai11/cryptopp/issues/511.
	if ((cpuid1[3] & (1 << 26)) != 0)
		g_hasSSE2 = ((cpuid1[2] & (1 << 27)) != 0) || CPU_ProbeSSE2();

	if (g_hasSSE2 == false)
		goto done;

	g_hasSSSE3 = (cpuid1[2] & (1<< 9)) != 0;
	g_hasSSE41 = (cpuid1[2] & (1<<19)) != 0;
	g_hasSSE42 = (cpuid1[2] & (1<<20)) != 0;
	g_hasAESNI = (cpuid1[2] & (1<<25)) != 0;
	g_hasCLMUL = (cpuid1[2] & (1<< 1)) != 0;

	// AVX is similar to SSE, but check both bits 27 (SSE) and 28 (AVX).
	// https://software.intel.com/en-us/blogs/2011/04/14/is-avx-enabled
	CRYPTOPP_CONSTANT(YMM_FLAG = (3 <<  1));
	CRYPTOPP_CONSTANT(AVX_FLAG = (3 << 27));
	if ((cpuid1[2] & AVX_FLAG) == AVX_FLAG)
	{

// GCC 4.1/Binutils 2.17 cannot consume xgetbv
#if defined(__GNUC__) || (__SUNPRO_CC >= 0x5100) || defined(__BORLANDC__)
		// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=71659 and
		// http://www.agner.org/optimize/vectorclass/read.php?i=65
		word32 a=0, d=0;
		__asm __volatile
		(
			// "xgetbv" : "=a"(a), "=d"(d) : "c"(0) :
			".byte 0x0f, 0x01, 0xd0"   "\n\t"
			: "=a"(a), "=d"(d) : "c"(0) : "cc"
		);
		word64 xcr0 = a | static_cast<word64>(d) << 32;
		g_hasAVX = (xcr0 & YMM_FLAG) == YMM_FLAG;

// Visual Studio 2010 and below lack xgetbv
#elif defined(_MSC_VER) && _MSC_VER <= 1600 && defined(_M_IX86)
		word32 a=0, d=0;
		__asm {
			push eax
			push edx
			push ecx
			mov ecx, 0
			_emit 0x0f
			_emit 0x01
			_emit 0xd0
			mov a, eax
			mov d, edx
			pop ecx
			pop edx
			pop eax
		}
		word64 xcr0 = a | static_cast<word64>(d) << 32;
		g_hasAVX = (xcr0 & YMM_FLAG) == YMM_FLAG;

// Visual Studio 2008 and below lack xgetbv
#elif defined(_MSC_VER) && _MSC_VER <= 1500 && defined(_M_X64)
		word64 xcr0 = XGETBV64(0);
		g_hasAVX = (xcr0 & YMM_FLAG) == YMM_FLAG;

// Downlevel SunCC
#elif defined(__SUNPRO_CC)
		g_hasAVX = false;

// _xgetbv is available
#else
		word64 xcr0 = _xgetbv(0);
		g_hasAVX = (xcr0 & YMM_FLAG) == YMM_FLAG;
#endif
	}

	if (IsIntel(cpuid0))
	{
		CRYPTOPP_CONSTANT(RDRAND_FLAG = (1 << 30));
		CRYPTOPP_CONSTANT(RDSEED_FLAG = (1 << 18));
		CRYPTOPP_CONSTANT(   ADX_FLAG = (1 << 19));
		CRYPTOPP_CONSTANT(   SHA_FLAG = (1 << 29));
		CRYPTOPP_CONSTANT(  AVX2_FLAG = (1 <<  5));

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
				g_hasAVX2 = (cpuid2[1] /*EBX*/ & AVX2_FLAG) != 0;
			}
		}
	}
	else if (IsAMD(cpuid0) || IsHygon(cpuid0))
	{
		CRYPTOPP_CONSTANT(RDRAND_FLAG = (1 << 30));
		CRYPTOPP_CONSTANT(RDSEED_FLAG = (1 << 18));
		CRYPTOPP_CONSTANT(   ADX_FLAG = (1 << 19));
		CRYPTOPP_CONSTANT(   SHA_FLAG = (1 << 29));
		CRYPTOPP_CONSTANT(  AVX2_FLAG = (1 <<  5));

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
				g_hasAVX2 = (cpuid2[1] /*EBX*/ & AVX2_FLAG) != 0;
			}
		}

		// Unconditionally disable RDRAND and RDSEED on AMD cpu's with family 15h or 16h.
		// See Crypto++ Issue 924, https://github.com/weidai11/cryptopp/issues/924,
		// Clear RDRAND CPUID bit on AMD family 15h/16h, https://lore.kernel.org/patchwork/patch/1115413/,
		// and AMD CPUID Specification, https://www.amd.com/system/files/TechDocs/25481.pdf
		{
			CRYPTOPP_CONSTANT(FAMILY_BASE_FLAG = (0x0f << 8));
			CRYPTOPP_CONSTANT(FAMILY_EXT_FLAG = (0xff << 20));

			word32 family = (cpuid1[0] & FAMILY_BASE_FLAG) >> 8;
			if (family == 0xf)
				family += (cpuid1[0] & FAMILY_EXT_FLAG) >> 20;
			if (family == 0x15 || family == 0x16)
			{
				g_hasRDRAND = false;
				g_hasRDSEED = false;
			}
		}
	}
	else if (IsVIA(cpuid0))
	{
		// Two bits: available and enabled
		CRYPTOPP_CONSTANT( RNG_FLAGS = (0x3 << 2));
		CRYPTOPP_CONSTANT( ACE_FLAGS = (0x3 << 6));
		CRYPTOPP_CONSTANT(ACE2_FLAGS = (0x3 << 8));
		CRYPTOPP_CONSTANT( PHE_FLAGS = (0x3 << 10));
		CRYPTOPP_CONSTANT( PMM_FLAGS = (0x3 << 12));

		CpuId(0xC0000000, 0, cpuid2);
		word32 extendedFeatures = cpuid2[0];

		if (extendedFeatures >= 0xC0000001)
		{
			CpuId(0xC0000001, 0, cpuid2);
			g_hasPadlockRNG  = (cpuid2[3] /*EDX*/ & RNG_FLAGS) == RNG_FLAGS;
			g_hasPadlockACE  = (cpuid2[3] /*EDX*/ & ACE_FLAGS) == ACE_FLAGS;
			g_hasPadlockACE2 = (cpuid2[3] /*EDX*/ & ACE2_FLAGS) == ACE2_FLAGS;
			g_hasPadlockPHE  = (cpuid2[3] /*EDX*/ & PHE_FLAGS) == PHE_FLAGS;
			g_hasPadlockPMM  = (cpuid2[3] /*EDX*/ & PMM_FLAGS) == PMM_FLAGS;
		}

		if (extendedFeatures >= 0xC0000005)
		{
			CpuId(0xC0000005, 0, cpuid2);
			g_cacheLineSize = GETBYTE(cpuid2[2] /*ECX*/, 0);
		}
	}

done:

#if defined(_SC_LEVEL1_DCACHE_LINESIZE)
	// Glibc does not implement on some platforms. The runtime returns 0 instead of error.
	// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/posix/sysconf.c
	int cacheLineSize = (int)sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	if (g_cacheLineSize == 0 && cacheLineSize > 0)
		g_cacheLineSize = cacheLineSize;
#endif

	if (g_cacheLineSize == 0)
		g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

	*const_cast<volatile bool*>(&g_x86DetectionDone) = true;
}

// *************************** ARM-32, Aarch32 and Aarch64 ***************************

#elif (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARMV8)

bool CRYPTOPP_SECTION_INIT g_ArmDetectionDone = false;
bool CRYPTOPP_SECTION_INIT g_hasARMv7 = false;
bool CRYPTOPP_SECTION_INIT g_hasNEON = false;
bool CRYPTOPP_SECTION_INIT g_hasPMULL = false;
bool CRYPTOPP_SECTION_INIT g_hasCRC32 = false;
bool CRYPTOPP_SECTION_INIT g_hasAES = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA1 = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA2 = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA512 = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA3 = false;
bool CRYPTOPP_SECTION_INIT g_hasSM3 = false;
bool CRYPTOPP_SECTION_INIT g_hasSM4 = false;
word32 CRYPTOPP_SECTION_INIT g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

// ARM does not have an unprivliged equivalent to CPUID on IA-32. We have to jump through some
//   hoops to detect features on a wide array of platforms. Our strategy is two part. First,
//   attempt to *Query* the OS for a feature, like using getauxval on Linux. If that fails,
//   then *Probe* the cpu executing an instruction and an observe a SIGILL if unsupported.
// The probes are in source files where compilation options like -march=armv8-a+crc make
//   intrinsics available. They are expensive when compared to a standard OS feature query.
//   Always perform the feature query first. For Linux see
//   http://sourceware.org/ml/libc-help/2017-08/msg00012.html
// Avoid probes on Apple platforms because Apple's signal handling for SIGILLs appears broken.
//   We are trying to figure out a way to feature test without probes. Also see
//   http://stackoverflow.com/a/11197770/608639 and
//   http://gist.github.com/erkanyildiz/390a480f27e86f8cd6ba

extern bool CPU_ProbeARMv7();
extern bool CPU_ProbeNEON();
extern bool CPU_ProbeCRC32();
extern bool CPU_ProbeAES();
extern bool CPU_ProbeSHA1();
extern bool CPU_ProbeSHA256();
extern bool CPU_ProbeSHA512();
extern bool CPU_ProbeSHA3();
extern bool CPU_ProbeSM3();
extern bool CPU_ProbeSM4();
extern bool CPU_ProbePMULL();

// https://github.com/torvalds/linux/blob/master/arch/arm/include/uapi/asm/hwcap.h
// https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/hwcap.h
#ifndef HWCAP_ARMv7
# define HWCAP_ARMv7 (1 << 29)
#endif
#ifndef HWCAP_ASIMD
# define HWCAP_ASIMD (1 << 1)
#endif
#ifndef HWCAP_NEON
# define HWCAP_NEON (1 << 12)
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
#ifndef HWCAP_SHA3
# define HWCAP_SHA3 (1 << 17)
#endif
#ifndef HWCAP_SM3
# define HWCAP_SM3 (1 << 18)
#endif
#ifndef HWCAP_SM4
# define HWCAP_SM4 (1 << 19)
#endif
#ifndef HWCAP_SHA512
# define HWCAP_SHA512 (1 << 21)
#endif

inline bool CPU_QueryARMv7()
{
#if defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_ARMv7) != 0))
		return true;
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_ARMv7) != 0 ||
	    (getauxval(AT_HWCAP) & HWCAP_NEON) != 0)
		return true;
#elif defined(__APPLE__) && defined(__arm__)
	// Apple hardware is ARMv7 or above.
	return true;
#endif
	return false;
}

inline bool CPU_QueryNEON()
{
#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_ASIMD) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_ASIMD) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_ASIMD) != 0)
		return true;
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_NEON) != 0)
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
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
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
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
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
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_AES) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_AES) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_AES) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__)
	unsigned int device, version;
	GetAppleMachineInfo(device, version);
	return IsAppleMachineARMv8(device, version);
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
	unsigned int device, version;
	GetAppleMachineInfo(device, version);
	return IsAppleMachineARMv8(device, version);
#endif
	return false;
}

inline bool CPU_QuerySHA256()
{
#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
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
	unsigned int device, version;
	GetAppleMachineInfo(device, version);
	return IsAppleMachineARMv8(device, version);
#endif
	return false;
}

inline bool CPU_QuerySHA512()
{
// Some ARMv8.4 features are disabled at the moment
#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA512) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA512) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA512) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA512) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__) && 0
	unsigned int device, version;
	GetAppleMachineInfo(device, version);
	return IsAppleMachineARMv84(device, version);
#endif
	return false;
}

inline bool CPU_QuerySHA3()
{
// Some ARMv8.4 features are disabled at the moment
#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA3) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA3) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA3) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA3) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__) && 0
	unsigned int device, version;
	GetAppleMachineInfo(device, version);
	return IsAppleMachineARMv84(device, version);
#endif
	return false;
}

inline bool CPU_QuerySM3()
{
// Some ARMv8.4 features are disabled at the moment
#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SM3) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SM3) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SM3) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SM3) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__) && 0
	unsigned int device, version;
	GetAppleMachineInfo(device, version);
	return IsAppleMachineARMv84(device, version);
#endif
	return false;
}

inline bool CPU_QuerySM4()
{
// Some ARMv8.4 features are disabled at the moment
#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SM4) != 0))
		return true;
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SM4) != 0))
		return true;
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SM4) != 0)
		return true;
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SM4) != 0)
		return true;
#elif defined(__APPLE__) && defined(__aarch64__) && 0
	unsigned int device, version;
	GetAppleMachineInfo(device, version);
	return IsAppleMachineARMv84(device, version);
#endif
	return false;
}

void DetectArmFeatures()
{
	// The CPU_ProbeXXX's return false for OSes which
	//   can't tolerate SIGILL-based probes
	g_hasARMv7 = CPU_QueryARMv7() || CPU_ProbeARMv7();
	g_hasNEON = CPU_QueryNEON() || CPU_ProbeNEON();
	g_hasCRC32 = CPU_QueryCRC32() || CPU_ProbeCRC32();
	g_hasPMULL = CPU_QueryPMULL() || CPU_ProbePMULL();
	g_hasAES  = CPU_QueryAES() || CPU_ProbeAES();
	g_hasSHA1 = CPU_QuerySHA1() || CPU_ProbeSHA1();
	g_hasSHA2 = CPU_QuerySHA256() || CPU_ProbeSHA256();
	g_hasSHA512 = CPU_QuerySHA512(); // || CPU_ProbeSHA512();
	g_hasSHA3 = CPU_QuerySHA3(); // || CPU_ProbeSHA3();
	g_hasSM3 = CPU_QuerySM3(); // || CPU_ProbeSM3();
	g_hasSM4 = CPU_QuerySM4(); // || CPU_ProbeSM4();

#if defined(_SC_LEVEL1_DCACHE_LINESIZE)
	// Glibc does not implement on some platforms. The runtime returns 0 instead of error.
	// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/posix/sysconf.c
	int cacheLineSize = (int)sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	if (cacheLineSize > 0)
		g_cacheLineSize = cacheLineSize;
#endif

	if (g_cacheLineSize == 0)
		g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

	*const_cast<volatile bool*>(&g_ArmDetectionDone) = true;
}

// *************************** PowerPC and PowerPC64 ***************************

#elif (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)

bool CRYPTOPP_SECTION_INIT g_PowerpcDetectionDone = false;
bool CRYPTOPP_SECTION_INIT g_hasAltivec = false;
bool CRYPTOPP_SECTION_INIT g_hasPower7 = false;
bool CRYPTOPP_SECTION_INIT g_hasPower8 = false;
bool CRYPTOPP_SECTION_INIT g_hasPower9 = false;
bool CRYPTOPP_SECTION_INIT g_hasAES = false;
bool CRYPTOPP_SECTION_INIT g_hasPMULL = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA256 = false;
bool CRYPTOPP_SECTION_INIT g_hasSHA512 = false;
bool CRYPTOPP_SECTION_INIT g_hasDARN = false;
word32 CRYPTOPP_SECTION_INIT g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

extern bool CPU_ProbeAltivec();
extern bool CPU_ProbePower7();
extern bool CPU_ProbePower8();
extern bool CPU_ProbePower9();
extern bool CPU_ProbeAES();
extern bool CPU_ProbePMULL();
extern bool CPU_ProbeSHA256();
extern bool CPU_ProbeSHA512();
extern bool CPU_ProbeDARN();

// AIX defines. We used to just call __power_7_andup()
// and friends but at Power9, too many compilers were
// missing __power_9_andup(). Instead we switched to
// a pattern similar to OpenSSL caps testing.
#ifndef __power_6_andup
# define __power_6_andup() __power_set(0xffffffffU<<14)
#endif
#ifndef __power_7_andup
# define __power_7_andup() __power_set(0xffffffffU<<15)
#endif
#ifndef __power_8_andup
# define __power_8_andup() __power_set(0xffffffffU<<16)
#endif
#ifndef __power_9_andup
# define __power_9_andup() __power_set(0xffffffffU<<17)
#endif

// AIX first supported Altivec at Power6, though it
// was available much earlier for other vendors.
inline bool CPU_QueryAltivec()
{
#if defined(__linux__) && defined(PPC_FEATURE_HAS_ALTIVEC)
	if ((getauxval(AT_HWCAP) & PPC_FEATURE_HAS_ALTIVEC) != 0)
		return true;
#elif defined(_AIX)
	if (__power_6_andup() != 0)
		return true;
#elif defined(__APPLE__) && defined(__POWERPC__)
	unsigned int device, version;
	GetAppleMachineInfo(device, version);
	return device == PowerMac;
#endif
	return false;
}

inline bool CPU_QueryPower7()
{
	// Power7 and ISA 2.06
#if defined(__linux__) && defined(PPC_FEATURE_ARCH_2_06)
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
#if defined(__linux__) && defined(PPC_FEATURE2_ARCH_2_07)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_ARCH_2_07) != 0)
		return true;
#elif defined(_AIX)
	if (__power_8_andup() != 0)
		return true;
#endif
	return false;
}

inline bool CPU_QueryPower9()
{
	// Power9 and ISA 3.0.
#if defined(__linux__) && defined(PPC_FEATURE2_ARCH_3_00)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_ARCH_3_00) != 0)
		return true;
#elif defined(_AIX)
	if (__power_9_andup() != 0)
		return true;
#endif
	return false;
}

inline bool CPU_QueryAES()
{
	// Power8 and ISA 2.07 provide in-core crypto. Glibc
	// 2.24 or higher is required for PPC_FEATURE2_VEC_CRYPTO.
#if defined(__linux__) && defined(PPC_FEATURE2_VEC_CRYPTO)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_VEC_CRYPTO) != 0)
		return true;
#elif defined(_AIX)
	if (__power_8_andup() != 0)
		return true;
#endif
	return false;
}

inline bool CPU_QueryPMULL()
{
	// Power8 and ISA 2.07 provide in-core crypto. Glibc
	// 2.24 or higher is required for PPC_FEATURE2_VEC_CRYPTO.
#if defined(__linux__) && defined(PPC_FEATURE2_VEC_CRYPTO)
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
#if defined(__linux__) && defined(PPC_FEATURE2_VEC_CRYPTO)
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
#if defined(__linux__) && defined(PPC_FEATURE2_VEC_CRYPTO)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_VEC_CRYPTO) != 0)
		return true;
#elif defined(_AIX)
	if (__power_8_andup() != 0)
		return true;
#endif
	return false;
}

// Power9 random number generator
inline bool CPU_QueryDARN()
{
	// Power9 and ISA 3.0 provide DARN.
#if defined(__linux__) && defined(PPC_FEATURE2_ARCH_3_00)
	if ((getauxval(AT_HWCAP2) & PPC_FEATURE2_ARCH_3_00) != 0)
		return true;
#elif defined(_AIX)
	if (__power_9_andup() != 0)
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
	g_hasPower9 = CPU_QueryPower9() || CPU_ProbePower9();
	g_hasPMULL = CPU_QueryPMULL() || CPU_ProbePMULL();
	g_hasAES  = CPU_QueryAES() || CPU_ProbeAES();
	g_hasSHA256 = CPU_QuerySHA256() || CPU_ProbeSHA256();
	g_hasSHA512 = CPU_QuerySHA512() || CPU_ProbeSHA512();
	g_hasDARN = CPU_QueryDARN() || CPU_ProbeDARN();

#if defined(_AIX) && defined(SC_L1C_DLS)
	// /usr/include/sys/systemcfg.h
	int cacheLineSize = getsystemcfg(SC_L1C_DLS);
	if (cacheLineSize > 0)
		g_cacheLineSize = cacheLineSize;
#elif defined(_SC_LEVEL1_DCACHE_LINESIZE)
	// Glibc does not implement on some platforms. The runtime returns 0 instead of error.
	// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/posix/sysconf.c
	int cacheLineSize = (int)sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	if (cacheLineSize > 0)
		g_cacheLineSize = cacheLineSize;
#endif

	if (g_cacheLineSize == 0)
		g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

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
#elif CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARMV8
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
#elif HAVE_XLC_INIT_PRIORITY
	// XLC needs constant, not a define
	#pragma priority(270)
	const InitCpu s_init;
#else
	const InitCpu s_init;
#endif

ANONYMOUS_NAMESPACE_END

#endif  // CRYPTOPP_IMPORTS
