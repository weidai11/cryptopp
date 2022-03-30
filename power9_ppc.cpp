// ppc_power9.cpp - written and placed in the public domain by
//                  Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics and built-ins to gain access to
//    Power9 instructions. A separate source file is needed because
//    additional CXXFLAGS are required to enable the appropriate
//    instructions sets in some build configurations.

#include "pch.h"
#include "config.h"

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#if defined(_ARCH_PWR9)
# include "ppc_simd.h"
#endif

// Squash MS LNK4221 and libtool warnings
extern const char PPC_POWER9_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

// ************************* Feature Probes ************************* //

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
extern "C" {
    typedef void (*SigHandler)(int);

    static jmp_buf s_jmpSIGILL;
    static void SigIllHandler(int)
    {
        longjmp(s_jmpSIGILL, 1);
    }
}
#endif  // CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)

bool CPU_ProbePower9()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif defined(CRYPTOPP_POWER9_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721954
    volatile int result = true;

    volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
    if (oldHandler == SIG_ERR)
        return false;

    volatile sigset_t oldMask;
    if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
    {
        signal(SIGILL, oldHandler);
        return false;
    }

    if (setjmp(s_jmpSIGILL))
        result = false;
    else
    {
        // This is "darn r3, 0" from POWER9. We cannot use __builtin_darn
        // and friends because Clang and IBM XL C/C++ does not offer them.
#if CRYPTOPP_BIG_ENDIAN
        __asm__ __volatile__ (".byte 0x7c, 0x60, 0x05, 0xe6  \n" : : : "r3");
#else
        __asm__ __volatile__ (".byte 0xe6, 0x05, 0x60, 0x7c  \n" : : : "r3");
#endif
        result = true;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // _ARCH_PWR9
}

// The DARN probe is not guarded with a preprocessor macro at the moment. We
// don't use CRYPTOPP_POWER9_AVAILABLE because old compilers, like GCC 4.8 on
// CentOS 7, will report NO even though we can produce the random numbers.
// Other Power9 implementations which use builtins will use the preprocessor
// macro guard. This strategy also gets into a situation where Power9 is not
// available but DARN is.
bool CPU_ProbeDARN()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#else
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721954
    volatile int result = true;

    volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
    if (oldHandler == SIG_ERR)
        return false;

    volatile sigset_t oldMask;
    if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
    {
        signal(SIGILL, oldHandler);
        return false;
    }

    if (setjmp(s_jmpSIGILL))
        result = false;
    else
    {
        // This is "darn r3, 0" from POWER9. We cannot use __builtin_darn
        // and friends because Clang and IBM XL C/C++ does not offer them.
#if CRYPTOPP_BIG_ENDIAN
        __asm__ __volatile__ (".byte 0x7c, 0x60, 0x05, 0xe6  \n" : : : "r3");
#else
        __asm__ __volatile__ (".byte 0xe6, 0x05, 0x60, 0x7c  \n" : : : "r3");
#endif
        result = true;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#endif  // DARN
}

#endif  // PPC32 or PPC64

NAMESPACE_END
