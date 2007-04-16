// cpu.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "cpu.h"

#include "misc.h"
#include <algorithm>

#ifdef __GNUC__
#include <signal.h>
#include <setjmp.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifdef CRYPTOPP_X86_ASM_AVAILABLE

typedef void (*SigHandler)(int);

static jmp_buf s_jmpNoCPUID;
static void SigIllHandlerCPUID(int)
{
	longjmp(s_jmpNoCPUID, 1);
}

bool CpuId(word32 input, word32 *output)
{
#ifdef _MSC_VER
    __try
	{
		__asm
		{
			mov eax, input
			cpuid
			mov edi, output
			mov [edi], eax
			mov [edi+4], ebx
			mov [edi+8], ecx
			mov [edi+12], edx
		}
	}
    __except (1)
	{
		return false;
    }
	return true;
#else
	SigHandler oldHandler = signal(SIGILL, SigIllHandlerCPUID);
	if (oldHandler == SIG_ERR)
		return false;

	bool result = true;
	if (setjmp(s_jmpNoCPUID))
		result = false;
	else
	{
		__asm__
		(
			// save ebx in case -fPIC is being used
			"push %%ebx; cpuid; mov %%ebx, %%edi; pop %%ebx"
			: "=a" (output[0]), "=D" (output[1]), "=c" (output[2]), "=d" (output[3])
			: "a" (input)
		);
	}

	signal(SIGILL, oldHandler);
	return result;
#endif
}

#ifndef _MSC_VER
static jmp_buf s_jmpNoSSE2;
static void SigIllHandlerSSE2(int)
{
	longjmp(s_jmpNoSSE2, 1);
}
#endif

#elif _MSC_VER >= 1400

bool CpuId(word32 input, word32 *output)
{
	__cpuid((int *)output, input);
	return true;
}

inline bool TrySSE2()
{
	return true;
}

#endif

#ifdef CRYPTOPP_CPUID_AVAILABLE

static bool TrySSE2()
{
#ifdef _MSC_VER
    __try
	{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
        __asm por xmm0, xmm0        // executing SSE2 instruction
#elif CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		__mm128i x = _mm_setzero_si128();
		return _mm_cvtsi128_si32(x) == 0;
#endif
	}
    __except (1)
	{
		return false;
    }
	return true;
#elif defined(__GNUC__)
	SigHandler oldHandler = signal(SIGILL, SigIllHandlerSSE2);
	if (oldHandler == SIG_ERR)
		return false;

	bool result = true;
	if (setjmp(s_jmpNoSSE2))
		result = false;
	else
	{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
		__asm __volatile ("por %xmm0, %xmm0");
#elif CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		__mm128i x = _mm_setzero_si128();
		result = _mm_cvtsi128_si32(x) == 0;
#endif
	}

	signal(SIGILL, oldHandler);
	return result;
#else
	return false;
#endif
}

bool g_x86DetectionDone = false;
bool g_hasSSE2 = false, g_hasSSSE3 = false, g_hasMMX = false, g_isP4 = false;
int g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

void DetectX86Features()
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

	std::swap(cpuid[2], cpuid[3]);
	if (memcmp(cpuid+1, "GenuineIntel", 12) == 0)
	{
		g_isP4 = ((cpuid1[0] >> 8) & 0xf) == 0xf;
		g_cacheLineSize = 8 * GETBYTE(cpuid1[1], 1);
	}
	else if (memcmp(cpuid+1, "AuthenticAMD", 12) == 0)
	{
		CpuId(0x80000005, cpuid);
		g_cacheLineSize = GETBYTE(cpuid[2], 0);
	}

	g_x86DetectionDone = true;
}

#endif

NAMESPACE_END
