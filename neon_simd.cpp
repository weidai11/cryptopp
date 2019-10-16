
// crc_simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to ARMv7a and
//    ARMv8a NEON instructions. A separate source file is needed
//    because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.
//    For Linux and Unix additional flags are not required.

#include "pch.h"
#include "config.h"
#include "stdcpp.h"

#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

// Squash MS LNK4221 and libtool warnings
extern const char NEON_SIMD_FNAME[] = __FILE__;

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

bool CPU_ProbeARMv7()
{
#if defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
    return false;
#elif defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif CRYPTOPP_ARM_NEON_AVAILABLE
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    volatile bool result = true;
    __try
    {
        // Modern MS hardware is ARMv7
        result = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return result;
# else
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile bool result = true;

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

#if 0
        // ARMv7 added movt and movw
        int a;
        asm volatile("movw %0,%1 \n"
                     "movt %0,%1 \n"
                     : "=r"(a) : "i"(0x1234));

00000010 <_Z5test2v>:  // ARM
  10:   e3010234        movw    r0, #4660       ; 0x1234
  14:   e3410234        movt    r0, #4660       ; 0x1234
  18:   e12fff1e        bx      lr

0000001c <_Z5test3v>:  // Thumb
  1c:   f241 2034       movw    r0, #4660       ; 0x1234
  20:   f2c1 2034       movt    r0, #4660       ; 0x1234
  24:   e12fff1e        bx      lr
#endif

        unsigned int a;
        asm volatile (
#if defined(__thumb__)
            ".inst.n 0xf241, 0x2034  \n\t"   // movw r0, 0x1234
            ".inst.n 0xf2c1, 0x2034  \n\t"   // movt r0, 0x1234
            "mov %0, r0              \n\t"   // mov [a], r0
#else
            ".inst 0xe3010234  \n\t"   // movw r0, 0x1234
            ".inst 0xe3410234  \n\t"   // movt r0, 0x1234
            "mov %0, r0        \n\t"   // mov [a], r0
#endif
            : "=r" (a) : : "r0");

        result = (a == 0x12341234);
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE
}

bool CPU_ProbeNEON()
{
#if defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
    return true;
#elif defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif CRYPTOPP_ARM_NEON_AVAILABLE
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    volatile bool result = true;
    __try
    {
        uint32x4_t x = vdupq_n_u32(1);
        uint32x4_t y = vshlq_n_u32(x, 4);

        word32 z[4]; vst1q_u32(z, y);
        return (z[0] & z[1] & z[2] & z[3]) == 16;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return result;
# else
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile bool result = true;

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
        // This is risky... When we hand encode the instructions
        // for vmov.u32 and vshl.u32 we get a SIGILL. Apparently
        // we need more than just the instructions. Using
        // intrinsics introduces the risk because the whole
        // file gets built with ISA options, and the higher ISA
        // may escape the try block with the SIGILL guard.
        uint32x4_t x = vdupq_n_u32(1);
        uint32x4_t y = vshlq_n_u32(x, 4);

        word32 z[4]; vst1q_u32(z, y);
        return (z[0] & z[1] & z[2] & z[3]) == 16;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE
}

NAMESPACE_END
