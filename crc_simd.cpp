// crc_simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to SSE4.2 and
//    ARMv8a CRC-32 and CRC-32C instructions. A separate source file
//    is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"

#if (CRYPTOPP_SSE42_AVAILABLE)
# include <nmmintrin.h>
#endif

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
extern const char CRC_SIMD_FNAME[] = __FILE__;

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

#if (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARMV8)

bool CPU_ProbeCRC32()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
	return false;
#elif (CRYPTOPP_ARM_CRC32_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    volatile bool result = true;
    __try
    {
        word32 w=0, x=1; word16 y=2; byte z=3;
        w = __crc32w(w,x);
        w = __crc32h(w,y);
        w = __crc32b(w,z);
        w = __crc32cw(w,x);
        w = __crc32ch(w,y);
        w = __crc32cb(w,z);

        result = !!w;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return result;
#else

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
        word32 w=0, x=1; word16 y=2; byte z=3;
        w = __crc32w(w,x);
        w = __crc32h(w,y);
        w = __crc32b(w,z);
        w = __crc32cw(w,x);
        w = __crc32ch(w,y);
        w = __crc32cb(w,z);

        // Hack... GCC optimizes away the code and returns true
        result = !!w;
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ARM_CRC32_AVAILABLE
}
#endif  // ARM32 or ARM64

#if (CRYPTOPP_ARM_CRC32_AVAILABLE)
void CRC32_Update_ARMV8(const byte *s, size_t n, word32& c)
{
    for(; !IsAligned<word32>(s) && n > 0; s++, n--)
        c = __crc32b(c, *s);

    for(; n > 4; s+=4, n-=4)
        c = __crc32w(c, *(const word32 *)(void*)s);

    for(; n > 0; s++, n--)
        c = __crc32b(c, *s);
}

void CRC32C_Update_ARMV8(const byte *s, size_t n, word32& c)
{
    for(; !IsAligned<word32>(s) && n > 0; s++, n--)
        c = __crc32cb(c, *s);

    for(; n > 4; s+=4, n-=4)
        c = __crc32cw(c, *(const word32 *)(void*)s);

    for(; n > 0; s++, n--)
        c = __crc32cb(c, *s);
}
#endif

#if (CRYPTOPP_SSE42_AVAILABLE)
void CRC32C_Update_SSE42(const byte *s, size_t n, word32& c)
{
    for(; !IsAligned<word32>(s) && n > 0; s++, n--)
        c = _mm_crc32_u8(c, *s);

    for(; n > 4; s+=4, n-=4)
        c = _mm_crc32_u32(c, *(const word32 *)(void*)s);

    for(; n > 0; s++, n--)
        c = _mm_crc32_u8(c, *s);
}
#endif

NAMESPACE_END
