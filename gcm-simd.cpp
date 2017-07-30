// crc-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to SSE4.2 and
//    ARMv8a CRC-32 and CRC-32C instructions. A separate source file
//    is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"

#if (CRYPTOPP_AESNI_AVAILABLE)
# include "wmmintrin.h"
#endif

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
# include "arm_neon.h"
#if (CRYPTOPP_ARMV8A_PMULL_AVAILABLE)
# include "arm_acle.h"
#endif
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
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
};
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_ARMV8A_PMULL_AVAILABLE)
bool CPU_TryPMULL_ARMV8()
{
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
	volatile bool result = true;
	__try
	{
		const poly64_t   a1={0x9090909090909090}, b1={0xb0b0b0b0b0b0b0b0};
		const poly8x16_t a2={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},
		                 b2={0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0};

		const poly128_t r1 = vmull_p64(a1, b1);
		const poly128_t r2 = vmull_high_p64((poly64x2_t)(a2), (poly64x2_t)(b2));

		// Linaro is missing vreinterpretq_u64_p128. Also see http://github.com/weidai11/cryptopp/issues/233.
		const uint64x2_t& t1 = (uint64x2_t)(r1);  // {bignum,bignum}
		const uint64x2_t& t2 = (uint64x2_t)(r2);  // {bignum,bignum}

		result = !!(vgetq_lane_u64(t1,0) == 0x5300530053005300 && vgetq_lane_u64(t1,1) == 0x5300530053005300 &&
		            vgetq_lane_u64(t2,0) == 0x6c006c006c006c00 && vgetq_lane_u64(t2,1) == 0x6c006c006c006c00);
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

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandlerPMULL);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpNoPMULL))
		result = false;
	else
	{
		const poly64_t   a1={0x9090909090909090}, b1={0xb0b0b0b0b0b0b0b0};
		const poly8x16_t a2={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},
		                 b2={0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0};

		const poly128_t r1 = vmull_p64(a1, b1);
		const poly128_t r2 = vmull_high_p64((poly64x2_t)(a2), (poly64x2_t)(b2));

		// Linaro is missing vreinterpretq_u64_p128. Also see http://github.com/weidai11/cryptopp/issues/233.
		const uint64x2_t& t1 = (uint64x2_t)(r1);  // {bignum,bignum}
		const uint64x2_t& t2 = (uint64x2_t)(r2);  // {bignum,bignum}

		result = !!(vgetq_lane_u64(t1,0) == 0x5300530053005300 && vgetq_lane_u64(t1,1) == 0x5300530053005300 &&
		            vgetq_lane_u64(t2,0) == 0x6c006c006c006c00 && vgetq_lane_u64(t2,1) == 0x6c006c006c006c00);
	}

	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
	signal(SIGILL, oldHandler);
	return result;
# endif
}
#endif  // CRYPTOPP_ARMV8A_PMULL_AVAILABLE

#if CRYPTOPP_ARM_NEON_AVAILABLE
void GCM_Xor16_NEON(byte *a, const byte *b, const byte *c)
{
    CRYPTOPP_ASSERT(IsAlignedOn(a,GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(b,GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(c,GetAlignmentOf<uint64x2_t>()));
    *(uint64x2_t*)a = veorq_u64(*(uint64x2_t*)b, *(uint64x2_t*)c);
}
#endif

NAMESPACE_END