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

#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

#if (CRYPTOPP_ARM_CRC32_AVAILABLE)
# include "arm_simd.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4244)
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

#define CONST_WORD32_CAST(x) ((const word32 *)(void*)(x))
#define CONST_WORD64_CAST(x) ((const word64 *)(void*)(x))

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
        word32 w=0, x=1; byte z=3;
        w = CRC32W(w,x);
        w = CRC32B(w,z);
        w = CRC32CW(w,x);
        w = CRC32CB(w,z);

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
    {
        signal(SIGILL, oldHandler);
        return false;
    }

    if (setjmp(s_jmpSIGILL))
        result = false;
    else
    {
        word32 w=0, x=1; byte z=3;
        w = CRC32W(w,x);
        w = CRC32B(w,z);
        w = CRC32CW(w,x);
        w = CRC32CB(w,z);

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
        c = CRC32B(c, *s);

    for(; n >= 16; s+=16, n-=16)
        c = CRC32Wx4(c, CONST_WORD32_CAST(s));

    for(; n >= 4; s+=4, n-=4)
        c = CRC32W(c, *CONST_WORD32_CAST(s));

    for(; n > 0; s++, n--)
        c = CRC32B(c, *s);
}

void CRC32C_Update_ARMV8(const byte *s, size_t n, word32& c)
{
    for(; !IsAligned<word32>(s) && n > 0; s++, n--)
        c = CRC32CB(c, *s);

    for(; n >= 16; s+=16, n-=16)
        c = CRC32CWx4(c, CONST_WORD32_CAST(s));

    for(; n >= 4; s+=4, n-=4)
        c = CRC32CW(c, *CONST_WORD32_CAST(s));

    for(; n > 0; s++, n--)
        c = CRC32CB(c, *s);
}
#endif

#if (CRYPTOPP_SSE42_AVAILABLE)
void CRC32C_Update_SSE42(const byte *s, size_t n, word32& c)
{
    // Temporary due to https://github.com/weidai11/cryptopp/issues/1202
    word32 v = c;

    // 64-bit code path due to https://github.com/weidai11/cryptopp/issues/1202
#if CRYPTOPP_BOOL_X64
    for(; !IsAligned<word64>(s) && n > 0; s++, n--)
        v = _mm_crc32_u8(v, *s);
#else
    for(; !IsAligned<word32>(s) && n > 0; s++, n--)
        v = _mm_crc32_u8(v, *s);
#endif

#if CRYPTOPP_BOOL_X64
    for(; n >= 32; s+=32, n-=32)
    {
        v = _mm_crc32_u64(_mm_crc32_u64(_mm_crc32_u64(_mm_crc32_u64(v,
            *CONST_WORD64_CAST(s+ 0)), *CONST_WORD64_CAST(s+ 8)),
            *CONST_WORD64_CAST(s+16)), *CONST_WORD64_CAST(s+24));
    }
#endif

    for(; n >= 16; s+=16, n-=16)
    {
        v = _mm_crc32_u32(_mm_crc32_u32(_mm_crc32_u32(_mm_crc32_u32(v,
            *CONST_WORD32_CAST(s+ 0)), *CONST_WORD32_CAST(s+ 4)),
            *CONST_WORD32_CAST(s+ 8)), *CONST_WORD32_CAST(s+12));
    }

    for(; n >= 4; s+=4, n-=4)
        v = _mm_crc32_u32(v, *CONST_WORD32_CAST(s));

    for(; n > 0; s++, n--)
        v = _mm_crc32_u8(v, *s);

    c = static_cast<word32>(v);
}
#endif

NAMESPACE_END
