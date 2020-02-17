// sse_simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to SSE for CPU
//    feature testing. A separate source file is needed because additional
//    CXXFLAGS are required to enable the appropriate instructions set in
//    some build configurations.

#include "pch.h"
#include "config.h"
#include "cpu.h"

// Needed by MIPS for definition of NULL
#include "stdcpp.h"

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

// Needed by SunCC and MSVC
#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
# if !defined(CRYPTOPP_NO_CPU_FEATURE_PROBES) && !CRYPTOPP_SSE2_ASM_AVAILABLE && CRYPTOPP_SSE2_INTRIN_AVAILABLE
#  include <emmintrin.h>
# endif
#endif

// Squash MS LNK4221 and libtool warnings
extern const char SSE_SIMD_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
extern "C" {
    typedef void (*SigHandler)(int);
}

extern "C"
{
    static jmp_buf s_jmpNoSSE2;
    static void SigIllHandler(int)
    {
        longjmp(s_jmpNoSSE2, 1);
    }
}
#endif  // CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY

bool CPU_ProbeSSE2()
{
    // Apple switched to Intel desktops in 2005/2006 using
    //   Core2 Duo's, which provides SSE2 and above.
#if CRYPTOPP_BOOL_X64 || defined(__APPLE__)
    return true;
#elif defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    __try
    {
# if CRYPTOPP_SSE2_ASM_AVAILABLE
        AS2(por xmm0, xmm0)        // executing SSE2 instruction
# elif CRYPTOPP_SSE2_INTRIN_AVAILABLE
        __m128i x = _mm_setzero_si128();
        return _mm_cvtsi128_si32(x) == 0;
# endif
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

    volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
    if (oldHandler == SIG_ERR)
        return false;

# ifndef __MINGW32__
    volatile sigset_t oldMask;
    if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
    {
        signal(SIGILL, oldHandler);
        return false;
    }
# endif

    if (setjmp(s_jmpNoSSE2))
        result = false;
    else
    {
# if CRYPTOPP_SSE2_ASM_AVAILABLE
        __asm __volatile ("por %xmm0, %xmm0");
# elif CRYPTOPP_SSE2_INTRIN_AVAILABLE
        __m128i x = _mm_setzero_si128();
        result = _mm_cvtsi128_si32(x) == 0;
# endif
    }

# ifndef __MINGW32__
    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
# endif

    signal(SIGILL, oldHandler);
    return result;
#endif
}

NAMESPACE_END
