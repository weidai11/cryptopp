// rdrand.cpp - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
//              Copyright assigned to Crypto++ project.

#include "pch.h"
#include "config.h"
#include "cryptlib.h"
#include "secblock.h"
#include "rdrand.h"
#include "cpu.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4100)
#endif

// This file (and friends) provides both RDRAND and RDSEED, but its somewhat
//   experimental. They were added at Crypto++ 5.6.3. At compile time, it
//   indirectly uses CRYPTOPP_BOOL_{X86|X32|X64} (via CRYPTOPP_CPUID_AVAILABLE)
//   to select an implementation or "throw NotImplemented". At runtime, the
//   class uses the result of CPUID to determine if RDRAND or RDSEED are
//   available. A lazy throw strategy is used in case the CPU does not support
//   the instruction. I.e., the throw is deferred until GenerateBlock is called.

// For GCC/ICC/Clang on Unix/Linux/Apple, you can use `-mrdrnd` to force the
//   option. If you use `-mrdrnd`, then __RDRND__ is defined and intrinsics
//   are used. If you omit the otion, then assembly language routines are
//   used if the compiler supports RDRAND. The same applies to -mrdseed and
//   __RDSEED__ (but they did not skimp on the extra vowel). Also see
//   http://gcc.gnu.org/onlinedocs/gcc/x86-Built-in-Functions.html#x86-Built-in-Functions

// Here's the naming convention for the functions....
//   MSC = Microsoft Compiler (and compatibles)
//   GCC = GNU Compiler (and compatibles)
//   RRA = RDRAND, Assembly
//   RSA = RDSEED, Assembly
//   RRI = RDRAND, Intrinsic
//   RSA = RDSEED, Intrinsic

// Helper macros. IA32_ASM captuers the architecture. MSC_RDRAND_COMPILER means
//   MSC_RDSEED_COMPILER; GCC_RDRAND_COMPILER means GCC_RDSEED_COMPILER.
#define IA32_ASM (!defined(CRYPTOPP_DISABLE_ASM) && (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64))
#define MSC_RDRAND_COMPILER ((CRYPTOPP_MSC_VERSION >= 1700) || (CRYPTOPP_CLANG_VERSION >= 30200) || (_INTEL_COMPILER >= 1210))
#define GCC_RDRAND_COMPILER ((CRYPTOPP_GCC_VERSION >= 40600) || (CRYPTOPP_CLANG_VERSION >= 30200) || (_INTEL_COMPILER >= 1210))
#define MSC_RDSEED_COMPILER MSC_RDRAND_COMPILER
#define GCC_RDSEED_COMPILER GCC_RDRAND_COMPILER

// GCC cannot compile programs with __builtin_ia32_rdseed{16|32|64}_step
#if __GNUC__
# define GCC_RDSEED_INTRINSIC_AVAILABLE 0
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

// Microsoft uses Intel's intrinsics, and it excludes AMD's CPUs. You should
//  "#define MSC_RDRAND_INTRINSIC_AVAILABLE 0" and
//  "#define MSC_RDSEED_INTRINSIC_AVAILABLE 0", if possible. The downside is
//  you must assemble the object files rdrand-x86.obj and rdrand-x86.obj and
//  then build the rdrand-x86.lib and rdrand-x86.lib libraries. To build the
//  libraries run "make-rdrand.cmd" from a developer prompt.

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

// MSC Compatible on Windows. Set MSC_RDRAND_ASM_AVAILABLE if it (and Intrinsics)
//   are not set. The requirement is rdrand.asm assembled with MASM/MAS64. We use
//   CRYTPOPP_MSC_VERSION as a proxy for MASM/MAS64 availability.
#if defined(CRYPTOPP_WIN32_AVAILABLE) && IA32_ASM && defined(CRYTPOPP_MSC_VERSION)
# if !defined(MSC_RDRAND_ASM_AVAILABLE) && !(MSC_RDRAND_INTRINSIC_AVAILABLE > 0)
#  define MSC_RDRAND_ASM_AVAILABLE 1
#  define MSC_RDRAND_INTRINSIC_AVAILABLE  0
# endif
#endif

// Fallback to MSC_RDRAND_INTRINSIC_AVAILABLE on Windows. The compiler must support it.
#if defined(CRYPTOPP_WIN32_AVAILABLE) && MSC_RDRAND_COMPILER
# if !defined(MSC_RDRAND_INTRINSIC_AVAILABLE) && !(MSC_RDRAND_ASM_AVAILABLE > 0)
#  define MSC_RDRAND_INTRINSIC_AVAILABLE 1
#  define MSC_RDRAND_ASM_AVAILABLE 0
# endif
#endif

// GCC Compatible on Unix/Linux/Apple. Set GCC_RDRAND_INTRINSIC_AVAILABLE if
//   it (and ASM) are not set. The requirements are __RDRND__ preprocessor.
#if defined(CRYPTOPP_UNIX_AVAILABLE) && GCC_RDRAND_COMPILER && (__RDRND__ >= 1)
# if !defined(GCC_RDRAND_INTRINSIC_AVAILABLE) && !(defined(GCC_RDRAND_ASM_AVAILABLE) && (GCC_RDRAND_ASM_AVAILABLE > 0))
#  define GCC_RDRAND_INTRINSIC_AVAILABLE  1
#  define GCC_RDRAND_ASM_AVAILABLE 0
# endif
#endif

// Fallback to MSC_ASM_INTRINSIC_AVAILABLE on Unix/Linux/Apple
#if defined(CRYPTOPP_UNIX_AVAILABLE) && IA32_ASM && GCC_RDRAND_COMPILER
# if !defined(GCC_RDRAND_INTRINSIC_AVAILABLE) && !(defined(GCCC_RDRAND_ASM_AVAILABLE) && (GCCC_RDRAND_ASM_AVAILABLE > 0))
#  define GCC_RDRAND_ASM_AVAILABLE 1
#  define GCC_RDRAND_INTRINSIC_AVAILABLE 0
# endif
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

// MSC Compatible on Windows. Set MSC_RDRAND_ASM_AVAILABLE if it (and Intrinsics)
//   are not set. The requirement is rdrand.asm assembled with MASM/MAS64. We use
//   CRYTPOPP_MSC_VERSION as a proxy for MASM/MAS64 availability.
#if defined(CRYPTOPP_WIN32_AVAILABLE) && IA32_ASM && defined(CRYTPOPP_MSC_VERSION)
# if !defined(MSC_RDSEED_ASM_AVAILABLE) && !(MSC_RDSEED_INTRINSIC_AVAILABLE > 0)
#  define MSC_RDSEED_ASM_AVAILABLE 1
#  define MSC_RDSEED_INTRINSIC_AVAILABLE  0
# endif
#endif

// Fallback to MSC_RDSEED_INTRINSIC_AVAILABLE on Windows. The compiler must support it.
#if defined(CRYPTOPP_WIN32_AVAILABLE) && MSC_RDSEED_COMPILER
# if !defined(MSC_RDSEED_INTRINSIC_AVAILABLE) && !(MSC_RDSEED_ASM_AVAILABLE > 0)
#  define MSC_RDSEED_INTRINSIC_AVAILABLE 1
#  define MSC_RDSEED_ASM_AVAILABLE 0
# endif
#endif

// GCC Compatible on Unix/Linux/Apple. Set GCC_RDSEED_INTRINSIC_AVAILABLE if
//   it (and ASM) are not set. The requirements are __RDSEED__ preprocessor.
#if defined(CRYPTOPP_UNIX_AVAILABLE) && GCC_RDSEED_COMPILER && (__RDSEED__ >= 1)
# if !defined(GCC_RDSEED_INTRINSIC_AVAILABLE) && !(defined(GCC_RDSEED_ASM_AVAILABLE) && (GCC_RDSEED_ASM_AVAILABLE > 0))
#  define GCC_RDSEED_INTRINSIC_AVAILABLE  1
#  define GCC_RDSEED_ASM_AVAILABLE 0
# endif
#endif

// Fallback to MSC_ASM_INTRINSIC_AVAILABLE on Unix/Linux/Apple
#if defined(CRYPTOPP_UNIX_AVAILABLE) && IA32_ASM && GCC_RDSEED_COMPILER
# if !defined(GCC_RDSEED_INTRINSIC_AVAILABLE) && !(defined(GCCC_RDSEED_ASM_AVAILABLE) && (GCCC_RDSEED_ASM_AVAILABLE > 0))
#  define GCC_RDSEED_ASM_AVAILABLE 1
#  define GCC_RDSEED_INTRINSIC_AVAILABLE 0
# endif
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

#if MSC_RDRAND_ASM_AVAILABLE
# ifdef _M_X64
extern "C" int CRYPTOPP_FASTCALL MSC_RRA_GenerateBlock(byte*, size_t, unsigned int);
// #  pragma comment(lib, "rdrand-x64.lib")
# else
extern "C" int MSC_RRA_GenerateBlock(byte*, size_t, unsigned int);
// #  pragma comment(lib, "rdrand-x86.lib")
# endif
#endif

#if MSC_RDSEED_ASM_AVAILABLE
# ifdef _M_X64
extern "C" int CRYPTOPP_FASTCALL MSC_RSA_GenerateBlock(byte*, size_t, unsigned int);
// #  pragma comment(lib, "rdrand-x64.lib")
# else
extern "C" int MSC_RSA_GenerateBlock(byte*, size_t, unsigned int);
// #  pragma comment(lib, "rdrand-x86.lib")
# endif
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

#if MSC_RDRAND_INTRINSIC_AVAILABLE || MSC_RDSEED_INTRINSIC_AVAILABLE
# include <immintrin.h>
#elif GCC_RDRAND_INTRINSIC_AVAILABLE || GCC_RDSEED_INTRINSIC_AVAILABLE
# include <emmintrin.h>
#endif

// Define ERROR_DEV_NOT_EXIST for this TU if not already defined
#ifndef ERROR_DEV_NOT_EXIST
# define ERROR_DEV_NOT_EXIST 0x37
#endif

#if defined(CRYPTOPP_UNIX_AVAILABLE)
# include <errno.h>
#endif

NAMESPACE_BEGIN(CryptoPP)
	
/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

#if defined(CRYPTOPP_CPUID_AVAILABLE)
extern CRYPTOPP_DLL bool CpuId(word32 input, word32 *output);
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

// Intel and AMD provide RDRAND, only Intel provides RDSEED. To call these
//   functions, use the word32 array returned from CpuId(0, output[]).

static bool IsIntel(const word32 output[4])
{
	// This is the "GenuineIntel" string
	return (output[1] /*EBX*/ == 0x756e6547) &&
		(output[2] /*ECX*/ == 0x6c65746e) &&
		(output[3] /*EDX*/ == 0x49656e69);
}

static bool IsAMD(const word32 output[4])
{
	// This is the "AuthenticAMD" string
	return (output[1] /*EBX*/ == 0x68747541) &&
		(output[2] /*ECX*/ == 0x69746E65) &&
		(output[3] /*EDX*/ == 0x444D4163);
}

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

static bool RDRAND_Runtime_Helper()
{
#if defined(CRYPTOPP_CPUID_AVAILABLE)
	bool rdrand = false; word32 output[4];
	if (CpuId(0, output))
	{
		if (IsIntel(output) || IsAMD(output))
		{
			if (output[0] /*EAX*/ >= 1 && CpuId(1, output))
			{
				static const unsigned int RDRAND_FLAG = (1 << 30);
				rdrand = !!(output[2] /*ECX*/ & RDRAND_FLAG);
			}
		}
	}
	return rdrand;
#else
	return false;
#endif
}

// This will be moved to CPU.h/CPU.cpp eventually
static bool hasRDRAND = RDRAND_Runtime_Helper();

#if defined(CRYPTOPP_CPUID_AVAILABLE)
	
#if MSC_RDRAND_INTRINSIC_AVAILABLE
static int MSC_RRI_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
#if CRYPTOPP_BOOL_X64
	word64 val;
#else
	word32 val;
#endif

	while (size >= sizeof(val))
	{
#if CRYPTOPP_BOOL_X64
		if (_rdrand64_step((word64*)output))
#else
		if (_rdrand32_step((word32*)output))
#endif
        {
			output += sizeof(val);
			size -= sizeof(val);
        }
        else
        {
			if (!safety--)
				return 0;
        }
	}

	if (size)
	{
#if CRYPTOPP_BOOL_X64
		if (_rdrand64_step(&val))
#else
		if (_rdrand32_step(&val))
#endif
		{
			memcpy(output, &val, size);
			size = 0;
		}
		else
		{
			if (!safety--)
				return 0;
		}
    }
		
#if CRYPTOPP_BOOL_X64
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}
	
#endif // MSC_RDRAND_INTRINSIC_AVAILABLE

#if GCC_RDRAND_INTRINSIC_AVAILABLE
static int GCC_RRI_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	word64 val;
#else // CRYPTOPP_BOOL_X86
	word32 val;
#endif

	while (size >= sizeof(val))
	{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
		if (__builtin_ia32_rdrand64_step((word64*)output))
#else
		if (__builtin_ia32_rdrand32_step((word32*)output))
#endif
        {
			output += sizeof(val);
			size -= sizeof(val);
        }
        else
        {
			if (!safety--)
				return 0;
        }
	}

	if (size)
	{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
		if (__builtin_ia32_rdrand64_step(&val))
#else
		if (__builtin_ia32_rdrand32_step(&val))
#endif
		{
			memcpy(output, &val, size);
			size = 0;
		}
		else
		{
			if (!safety--)
				return 0;
		}
    }
	
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}

#endif // GCC_RDRAND_INTRINSIC_AVAILABLE

#if GCC_RDRAND_ASM_AVAILABLE
static int GCC_RRA_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	word64 val;
#else
	word32 val;
#endif
	char rc;
	while (size)
	{
        __asm__ volatile(
			"rdrand %0; "
			"setc %1; "
			: "=r" (val), "=qm" (rc)
			:
			: "cc"
        );

		if (rc)
        {
			if (size >= sizeof(val))
			{
#if defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32)
				*((word64*)output) = val;
#elif defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && (CRYPTOPP_BOOL_X86)
				*((word32*)output) = val;
#else
				memcpy(output, &val, sizeof(val));
#endif
				output += sizeof(val);
				size -= sizeof(val);
			}
			else
			{
				memcpy(output, &val, size);
				size = 0;
			}
        }
        else
        {
			if (!safety--)
				break;
        }
	}

#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}

#endif // GCC_RDRAND_ASM_AVAILABLE

#endif  // CRYPTOPP_CPUID_AVAILABLE (CRYPTOPP_BOOL_{X86|X32|X64})

//! generate random array of bytes
void RDRAND::GenerateBlock(byte *output, size_t size)
{
	assert((output == NULL && size == 0) || (output != NULL && size != 0));
	assert(Available());

	// We could (should?) test Ready, but Available conveys more useful information.
	if(!Available())
		throw NotImplemented("RDRAND: rdrand is not available on this platform");

#if defined(CRYPTOPP_CPUID_AVAILABLE)
	int rc; CRYPTOPP_UNUSED(rc);
#if MSC_RDRAND_ASM_AVAILABLE
	rc = MSC_RRA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("MSC_RRA_GenerateBlock"); }
#elif GCC_RDRAND_ASM_AVAILABLE
	rc = GCC_RRA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("GCC_RRA_GenerateBlock"); }
#elif MSC_RDRAND_INTRINSIC_AVAILABLE
	rc = MSC_RRI_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("MSC_RRI_GenerateBlock"); }
#elif GCC_RDRAND_INTRINSIC_AVAILABLE
	rc = GCC_RRI_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("GCC_RRI_GenerateBlock"); }
#elif (__RDRND__ >= 1)
	// RDRAND detected at compile time, GCC Compatible compiler, but no suitable implementations
#   error "Please report on the Crypto++ user group"
#else
	// RDRAND not detected at compile time, and no suitable compiler found
	throw NotImplemented("RDRAND: failed to find a suitable implementation???");
#endif
	
#endif  // CRYPTOPP_CPUID_AVAILABLE (CRYPTOPP_BOOL_{X86|X32|X64})
}

//! returns true if RDRAND is present or available according to CPUID, false otherwise
bool RDRAND::Available() const
{
	word64 unused;
    return Available(unused);
}

//! returns true if RDRAND is present or available according to CPUID, false otherwise. There is no exended information available.
bool RDRAND::Available(word64& extendedInfo) const
{
	if (hasRDRAND)
	{
		extendedInfo = 0;
		return true;
	}
	
#if defined(CRYPTOPP_WIN32_AVAILABLE)
	extendedInfo = ERROR_DEV_NOT_EXIST; // 0x00000037
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
	extendedInfo = ENODEV; // 19
#else
	extendedInfo = word64(-1);
#endif

	return false;
}

//! returns true if RDRAND is online/ready to produce random numbers, false otherwise
bool RDRAND::Ready() const
{
	word64 unused;
    return Ready(unused);
}

//! returns true if RDRAND is online/ready to produce random numbers, false otherwise. There is no exended information available.
bool RDRAND::Ready(word64& extendedInfo) const
{
	if (hasRDRAND)
	{
		extendedInfo = 0;
		return true;
	}
	
#if defined(CRYPTOPP_WIN32_AVAILABLE)
	extendedInfo = ERROR_DEV_NOT_EXIST; // 0x00000037
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
	extendedInfo = ENODEV; // 19
#else
	extendedInfo = word64(-1);
#endif

	return false;
}

//! generate and discard n bytes.
void RDRAND::DiscardBytes(size_t n)
{		
	// RoundUpToMultipleOf is used because a full word is read, and its cheaper
	//   to discard full words. There's no sense in dealing with tail bytes.
	assert(Ready());
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	FixedSizeSecBlock<word64, 16> discard;
	n = RoundUpToMultipleOf(n, sizeof(word64));
#else
	FixedSizeSecBlock<word32, 16> discard;
	n = RoundUpToMultipleOf(n, sizeof(word32));
#endif

	size_t count = STDMIN(n, discard.SizeInBytes());
	while (count)
	{
		GenerateBlock(discard.BytePtr(), count);
		n -= count;
		count = STDMIN(n, discard.SizeInBytes());
	}
}

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

static bool RDSEED_Runtime_Helper()
{
#if defined(CRYPTOPP_CPUID_AVAILABLE)
	bool rdseed = false; word32 output[4];
	if (CpuId(0, output))
	{
		// Only Intel supports RDSEED at the moment.
		if (IsIntel(output))
		{
			if (output[0] /*EAX*/ >= 7 && CpuId(7, output))
			{
				static const unsigned int RDSEED_FLAG = (1 << 18);
				rdseed = !!(output[1] /*EBX*/ & RDSEED_FLAG);
			}
		}
	}
	return rdseed;
#else
	return false;
#endif
}

// This will be moved to CPU.h/CPU.cpp eventually
static bool hasRDSEED = RDSEED_Runtime_Helper();

#if defined(CRYPTOPP_CPUID_AVAILABLE)

#if MSC_RDSEED_INTRINSIC_AVAILABLE
static int MSC_RSI_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
#if CRYPTOPP_BOOL_X64
	word64 val;
#else
	word32 val;
#endif

	while (size >= sizeof(val))
	{
#if CRYPTOPP_BOOL_X64
		if (_rdseed64_step((word64*)output))
#else
		if (_rdseed32_step((word32*)output))
#endif
        {
			output += sizeof(val);
			size -= sizeof(val);
        }
        else
        {
			if (!safety--)
				return 0;
        }
	}

	if (size)
	{
#if CRYPTOPP_BOOL_X64
		if (_rdseed64_step(&val))
#else
		if (_rdseed32_step(&val))
#endif
		{
			memcpy(output, &val, size);
			size = 0;
		}
		else
		{
			if (!safety--)
				return 0;
		}
    }
		
#if CRYPTOPP_BOOL_X64
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}
	
#endif // MSC_RDSEED_INTRINSIC_AVAILABLE

#if GCC_RDSEED_INTRINSIC_AVAILABLE
static int GCC_RSI_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	word64 val;
#else // CRYPTOPP_BOOL_X86
	word32 val;
#endif

	while (size >= sizeof(val))
	{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
		if (__builtin_ia32_rdseed64_step((word64*)output))
#else
		if (__builtin_ia32_rdseed32_step((word32*)output))
#endif
        {
			output += sizeof(val);
			size -= sizeof(val);
        }
        else
        {
			if (!safety--)
				return 0;
        }
	}

	if (size)
	{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
		if (__builtin_ia32_rdseed64_step(&val))
#else
		if (__builtin_ia32_rdseed32_step(&val))
#endif
		{
			memcpy(output, &val, size);
			size = 0;
		}
		else
		{
			if (!safety--)
				return 0;
		}
    }
	
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}

#endif // GCC_RDSEED_INTRINSIC_AVAILABLE

#if GCC_RDSEED_ASM_AVAILABLE
static int GCC_RSA_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	word64 val;
#else
	word32 val;
#endif
	char rc;
	while (size)
	{
        __asm__ volatile(
			"rdseed %0; "
			"setc %1; "
			: "=r" (val), "=qm" (rc)
			:
			: "cc"
        );

		if (rc)
        {
			if (size >= sizeof(val))
			{
#if defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32)
				*((word64*)output) = val;
#elif defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && (CRYPTOPP_BOOL_X86)
				*((word32*)output) = val;
#else
				memcpy(output, &val, sizeof(val));
#endif
				output += sizeof(val);
				size -= sizeof(val);
			}
			else
			{
				memcpy(output, &val, size);
				size = 0;
			}
        }
        else
        {
			if (!safety--)
				break;
        }
	}

#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}

#endif // GCC_RDSEED_ASM_AVAILABLE

#endif  // CRYPTOPP_CPUID_AVAILABLE (CRYPTOPP_BOOL_{X86|X32|X64})

//! generate random array of bytes
void RDSEED::GenerateBlock(byte *output, size_t size)
{
	CRYPTOPP_UNUSED(output), CRYPTOPP_UNUSED(size);
	assert((output == NULL && size == 0) || (output != NULL && size != 0));
	assert(Available());

	// We could (should?) test Ready, but Available conveys more useful information.
	if(!Available())
		throw NotImplemented("RDSEED: rdseed is not available on this platform");

#if defined(CRYPTOPP_CPUID_AVAILABLE)
	int rc; CRYPTOPP_UNUSED(rc);
#if MSC_RDSEED_ASM_AVAILABLE
	rc = MSC_RSA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDSEED_Err("MSC_RSA_GenerateBlock"); }
#elif GCC_RDSEED_ASM_AVAILABLE
	rc = GCC_RSA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDSEED_Err("GCC_RSA_GenerateBlock"); }
#elif MSC_RDSEED_INTRINSIC_AVAILABLE
	rc = MSC_RSI_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDSEED_Err("MSC_RSI_GenerateBlock"); }
#elif GCC_RDSEED_INTRINSIC_AVAILABLE
	rc = GCC_RSI_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDSEED_Err("GCC_RSI_GenerateBlock"); }
#elif (__RDSEED__ >= 1)
	// RDSEED detected at compile time, GCC Compatible compiler, but no suitable implementations
#   error "Please report on the Crypto++ user group"
#else
	// RDSEED not detected at compile time, and no suitable compiler found
	throw NotImplemented("RDSEED: failed to find a suitable implementation???");
#endif
	
#endif  // CRYPTOPP_CPUID_AVAILABLE (CRYPTOPP_BOOL_{X86|X32|X64})
}

//! returns true if RDSEED is present or available according to CPUID, false otherwise
bool RDSEED::Available() const
{
	word64 unused;
    return Available(unused);
}

//! returns true if RDSEED is present or available according to CPUID, false otherwise. There is no exended information available.
bool RDSEED::Available(word64& extendedInfo) const
{
	if (hasRDSEED)
	{
		extendedInfo = 0;
		return true;
	}
	
#if defined(CRYPTOPP_WIN32_AVAILABLE)
	extendedInfo = ERROR_DEV_NOT_EXIST; // 0x00000037
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
	extendedInfo = ENODEV; // 19
#else
	extendedInfo = word64(-1);
#endif

	return false;
}

//! returns true if RDSEED is online/ready to produce random numbers, false otherwise
bool RDSEED::Ready() const
{
	word64 unused;
    return Ready(unused);
}

//! returns true if RDSEED is online/ready to produce random numbers, false otherwise. There is no exended information available.
bool RDSEED::Ready(word64& extendedInfo) const
{
	if (hasRDSEED)
	{
		extendedInfo = 0;
		return true;
	}
	
#if defined(CRYPTOPP_WIN32_AVAILABLE)
	extendedInfo = ERROR_DEV_NOT_EXIST; // 0x00000037
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
	extendedInfo = ENODEV; // 19
#else
	extendedInfo = word64(-1);
#endif

	return false;
}

//! generate and discard n bytes.
void RDSEED::DiscardBytes(size_t n)
{		
	// RoundUpToMultipleOf is used because a full word is read, and its cheaper
	//   to discard full words. There's no sense in dealing with tail bytes.
	assert(Ready());
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	FixedSizeSecBlock<word64, 16> discard;
	n = RoundUpToMultipleOf(n, sizeof(word64));
#else
	FixedSizeSecBlock<word32, 16> discard;
	n = RoundUpToMultipleOf(n, sizeof(word32));
#endif

	size_t count = STDMIN(n, discard.SizeInBytes());
	while (count)
	{
		GenerateBlock(discard.BytePtr(), count);
		n -= count;
		count = STDMIN(n, discard.SizeInBytes());
	}
}

NAMESPACE_END
