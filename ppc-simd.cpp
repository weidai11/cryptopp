// ppc-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to AltiVec,
//    Power8 and in-core crypto instructions. A separate source file
//    is needed because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

// TODO: we still need to implement Power8 SHA. Once we have Power8 SHA,
//    we should be able to use CRYPTOPP_POWER8_AES_AVAILABLE and
//    CRYPTOPP_POWER8_SHA_AVAILABLE instead of the broader
//    CRYPTOPP_POWER8_AVAILABLE. The change will need to be coordinated
//    with the defines in config.h.

// TODO: Bob Wilkinson reported we are misdetecting CRYPTOPP_POWER8_AVAILABLE.
//    The problem is, the updated compiler supports them but the down-level
//    assembler and linker do not. We will probably need to fix it through
//    the makefile, similar to the way x86 AES and SHA are handled. For the time
//    being CRYPTOPP_DISABLE_POWER8 will have to be applied manually. Another
//    twist is, we don't have access to a test machine and it must be fixed
//    for two compilers (IBM XL C/C++ and GCC). Ugh...

#include "pch.h"
#include "config.h"
#include "stdcpp.h"

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include "ppc-simd.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
extern "C" {
    typedef void (*SigHandler)(int);

    static jmp_buf s_jmpSIGILL;
    static void SigIllHandler(int)
    {
        longjmp(s_jmpSIGILL, 1);
    }
}
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)
bool CPU_ProbeAltivec()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_ALTIVEC_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = true;

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
        const byte b1[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        const byte b2[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
        byte b3[16];

        const uint8x16_p v1 = (uint8x16_p)VectorLoad(0, b1);
        const uint8x16_p v2 = (uint8x16_p)VectorLoad(0, b2);
        const uint8x16_p v3 = (uint8x16_p)VectorXor(v1, v2);
        VectorStore(v3, b3);

        result = (0 == std::memcmp(b2, b3, 16));
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE
}

bool CPU_ProbePower7()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_POWER7_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = false;

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
        byte b1[19] = {255, 255, 255, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, b2[17];
        const uint8x16_p v1 = (uint8x16_p)VectorLoad(0, b1+3);
        VectorStore(v1, b2+1);

        result = (0 == std::memcmp(b1+3, b2+1, 16));
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_POWER7_AVAILABLE
}

bool CPU_ProbePower8()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_POWER8_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = true;

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
        byte b1[19] = {255, 255, 255, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, b2[17];
        const uint8x16_p v1 = (uint8x16_p)VectorLoad(0, b1+3);
        VectorStore(v1, b2+1);

        result = (0 == std::memcmp(b1+3, b2+1, 16));
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_POWER8_AVAILABLE
}

bool CPU_ProbeAES()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_POWER8_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = true;

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
        byte key[16] = {0xA0, 0xFA, 0xFE, 0x17, 0x88, 0x54, 0x2c, 0xb1,
                        0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05};
        byte state[16] = {0x19, 0x3d, 0xe3, 0xb3, 0xa0, 0xf4, 0xe2, 0x2b,
                          0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08};
        byte r[16] = {255}, z[16] = {};

        uint8x16_p k = (uint8x16_p)VectorLoad(0, key);
        uint8x16_p s = (uint8x16_p)VectorLoad(0, state);
        s = VectorEncrypt(s, k);
        s = VectorEncryptLast(s, k);
        s = VectorDecrypt(s, k);
        s = VectorDecryptLast(s, k);
        VectorStore(s, r);

        result = (0 != std::memcmp(r, z, 16));
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE
}

bool CPU_ProbeSHA256()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_POWER8_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = false;

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
        byte r[16], z[16] = {0};
        uint8x16_p x = ((uint8x16_p){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});

        x = VectorSHA256<0,0>(x);
        x = VectorSHA256<0,1>(x);
        x = VectorSHA256<1,0>(x);
        x = VectorSHA256<1,1>(x);
        VectorStore(x, r);

        result = (0 == std::memcmp(r, z, 16));
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
#elif (CRYPTOPP_POWER8_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile int result = false;

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
        byte r[16], z[16] = {0};
        uint8x16_p x = ((uint8x16_p){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});

        x = VectorSHA512<0,0>(x);
        x = VectorSHA512<0,1>(x);
        x = VectorSHA512<1,0>(x);
        x = VectorSHA512<1,1>(x);
        VectorStore(x, r);

        result = (0 == std::memcmp(r, z, 16));
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_POWER8_AVAILABLE
}
# endif  // CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64
NAMESPACE_END
