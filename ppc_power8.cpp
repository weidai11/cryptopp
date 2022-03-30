// ppc_power8.cpp - written and placed in the public domain by
//                  Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics and built-ins to gain access to
//    Power8 instructions. A separate source file is needed because
//    additional CXXFLAGS are required to enable the appropriate
//    instructions sets in some build configurations.

#include "pch.h"
#include "config.h"

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#if defined(_ARCH_PWR8) || defined(__CRYPTO__)
# include "ppc_simd.h"
#endif

// Squash MS LNK4221 and libtool warnings
extern const char PPC_POWER8_FNAME[] = __FILE__;

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

bool CPU_ProbePower8()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif defined(CRYPTOPP_POWER8_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = false;

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
        // This is 64-bit add "vaddudm v0, v1, v0" from POWER8. We cannot use
        // vec_add because GCC uses POWER8 instructions outside this SIGILL block.
        // https://github.com/weidai11/cryptopp/issues/1112 and
        // https://github.com/weidai11/cryptopp/issues/1115.
#if CRYPTOPP_BIG_ENDIAN
        __asm__ __volatile__ (".byte 0x10, 0x01, 0x00, 0xc0  \n\t" : : : "v0");
#else
        __asm__ __volatile__ (".byte 0xc0, 0x00, 0x01, 0x10  \n\t" : : : "v0");
#endif
        result = true;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // _ARCH_PWR8
}

///////////
bool CPU_ProbePMULL()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_POWER8_VMULL_AVAILABLE)
    // longjmp and clobber warnings. Volatile is required.
    volatile bool result = false;

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
        // This is VMULL 'vpmsumd v0,v0,v1'
#if CRYPTOPP_BIG_ENDIAN
        __asm__ __volatile__ (".byte 0x10, 0x00, 0x0c, 0xc8  \n\t" : : : "v0");
#else
        __asm__ __volatile__ (".byte 0xc8, 0x0c, 0x00, 0x10  \n\t" : : : "v0");
#endif
        result = true;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
#else
    return false;
#endif  // CRYPTOPP_POWER8_VMULL_AVAILABLE
}
///////////

bool CPU_ProbeAES()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif defined(CRYPTOPP_POWER8_AES_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = false;

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
        // This is AES 'vcipher v0,v0,v1' followed by 'vcipherlast v0,v0,v1'
#if CRYPTOPP_BIG_ENDIAN
        __asm__ __volatile__ (".byte 0x10, 0x00, 0x0d, 0x08  \n\t"
                              ".byte 0x10, 0x00, 0x0d, 0x09  \n\t" : : : "v0");
#else
        __asm__ __volatile__ (".byte 0x08, 0x0d, 0x00, 0x10  \n\t"
                              ".byte 0x09, 0x0d, 0x00, 0x10  \n\t" : : : "v0");
#endif
        result = true;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // __CRYPTO__
}

bool CPU_ProbeSHA256()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif defined(CRYPTOPP_POWER8_SHA_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = false;

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
        // This is SHA-256 'vshasigmaw v0,v0,1,15'.
#if CRYPTOPP_BIG_ENDIAN
        __asm__ __volatile__ (".byte 0x10, 0x00, 0xfe, 0x82  \n\t" : : : "v0");
#else
        __asm__ __volatile__ (".byte 0x82, 0xfe, 0x00, 0x10  \n\t" : : : "v0");
#endif
        result = true;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE
}

bool CPU_ProbeSHA512()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif defined(CRYPTOPP_POWER8_SHA_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = false;

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
        // This is SHA-512 'vshasigmad v0,v0,1,15'.
#if CRYPTOPP_BIG_ENDIAN
        __asm__ __volatile__ (".byte 0x10, 0x00, 0xfe, 0xc2  \n\t" : : : "v0");
#else
        __asm__ __volatile__ (".byte 0xc2, 0xfe, 0x00, 0x10  \n\t" : : : "v0");
#endif
        result = true;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_POWER8_AVAILABLE
}

#endif  // PPC32 or PPC64

NAMESPACE_END
