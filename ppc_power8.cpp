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
#elif (_ARCH_PWR8) && defined(CRYPTOPP_POWER8_AVAILABLE)
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
        // POWER8 added 64-bit SIMD operations
        const word64 x = W64LIT(0xffffffffffffffff);
        word64 w1[2] = {x, x}, w2[2] = {4, 6}, w3[2];

        // Specifically call the VSX loads and stores with 64-bit types
        #if defined(__ibmxl__) || (defined(_AIX) && defined(__xlC__))
        const uint64x2_p v1 = vec_xl(0, (unsigned long long*)w1);
        const uint64x2_p v2 = vec_xl(0, (unsigned long long*)w2);
        const uint64x2_p v3 = vec_add(v1, v2);  // 64-bit add
        vec_xst(v3, 0, (unsigned long long*)w3);
        #else
        const uint64x2_p v1 = (uint64x2_p)vec_vsx_ld(0, (const byte*)w1);
        const uint64x2_p v2 = (uint64x2_p)vec_vsx_ld(0, (const byte*)w2);
        const uint64x2_p v3 = vec_add(v1, v2);  // 64-bit add
        vec_vsx_st((uint8x16_p)v3, 0, (byte*)w3);
        #endif

        // Relies on integer wrap
        result = (w3[0] == 3 && w3[1] == 5);
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // _ARCH_PWR8
}

bool CPU_ProbeAES()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (__CRYPTO__) && defined(CRYPTOPP_POWER8_AES_AVAILABLE)
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

        uint8x16_p k = (uint8x16_p)VecLoad(0, key);
        uint8x16_p s = (uint8x16_p)VecLoad(0, state);
        s = VecEncrypt(s, k);
        s = VecEncryptLast(s, k);
        s = VecDecrypt(s, k);
        s = VecDecryptLast(s, k);
        VecStore(s, r);

        result = (0 != std::memcmp(r, z, 16));
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
#elif (__CRYPTO__) && defined(CRYPTOPP_POWER8_SHA_AVAILABLE)
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
        uint8x16_p x = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

        x = VecSHA256<0,0>(x);
        x = VecSHA256<0,0xf>(x);
        x = VecSHA256<1,0>(x);
        x = VecSHA256<1,0xf>(x);
        VecStore(x, r);

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
#elif (__CRYPTO__) && defined(CRYPTOPP_POWER8_SHA_AVAILABLE)
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
        uint8x16_p x = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

        x = VecSHA512<0,0>(x);
        x = VecSHA512<0,0xf>(x);
        x = VecSHA512<1,0>(x);
        x = VecSHA512<1,0xf>(x);
        VecStore(x, r);

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

#endif  // PPC32 or PPC64

NAMESPACE_END
