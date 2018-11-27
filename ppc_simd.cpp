// ppc_simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to AltiVec,
//    Power8 and in-core crypto instructions. A separate source file
//    is needed because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "stdcpp.h"

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include "ppc_simd.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

// Squash MS LNK4221 and libtool warnings
extern const char PPC_SIMD_FNAME[] = __FILE__;

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
#elif (_ARCH_PWR3) && (CRYPTOPP_ALTIVEC_AVAILABLE)
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
        CRYPTOPP_ALIGN_DATA(16)
        const byte b1[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        CRYPTOPP_ALIGN_DATA(16)
        const byte b2[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
        CRYPTOPP_ALIGN_DATA(16) byte b3[16];

        // Specifically call the Altivec loads and stores
        const uint8x16_p v1 = (uint8x16_p)vec_ld(0, (byte*)b1);
        const uint8x16_p v2 = (uint8x16_p)vec_ld(0, (byte*)b2);
        const uint8x16_p v3 = (uint8x16_p)VecXor(v1, v2);
        vec_st(v3, 0, b3);

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

# endif  // CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64

NAMESPACE_END
