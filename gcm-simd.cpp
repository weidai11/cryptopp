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
#if (CRYPTOPP_ARMV_PMULL_AVAILABLE)
# include "arm_acle.h"
#endif
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

ANONYMOUS_NAMESPACE_BEGIN

// GCC 4.8 and 4.9 are missing PMULL gear
#if (CRYPTOPP_ARMV_PMULL_AVAILABLE)
# if (CRYPTOPP_GCC_VERSION >= 40800) && (CRYPTOPP_GCC_VERSION < 50000)
inline poly128_t VMULL_P64(poly64_t a, poly64_t b)
{
    return __builtin_aarch64_crypto_pmulldi_ppp (a, b);
}

inline poly128_t VMULL_HIGH_P64(poly64x2_t a, poly64x2_t b)
{
    return __builtin_aarch64_crypto_pmullv2di_ppp (a, b);
}
# endif
#endif

#if (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64) && CRYPTOPP_ARMV_PMULL_AVAILABLE
#if defined(__GNUC__)
// Schneiders, Hovsmith and O'Rourke used this trick.
// It results in much better code generation in production code
// by avoiding D-register spills when using vgetq_lane_u64. The
// problem does not surface under minimal test cases.
inline uint64x2_t PMULL_00(const uint64x2_t a, const uint64x2_t b)
{
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
        :"=w" (r) : "w" (a), "w" (b) );
    return r;
}

inline uint64x2_t PMULL_01(const uint64x2_t a, const uint64x2_t b)
{
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
        :"=w" (r) : "w" (a), "w" (vget_high_u64(b)) );
    return r;
}

inline uint64x2_t PMULL_10(const uint64x2_t a, const uint64x2_t b)
{
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
        :"=w" (r) : "w" (vget_high_u64(a)), "w" (b) );
    return r;
}

inline uint64x2_t PMULL_11(const uint64x2_t a, const uint64x2_t b)
{
    uint64x2_t r;
    __asm __volatile("pmull2   %0.1q, %1.2d, %2.2d \n\t"
        :"=w" (r) : "w" (a), "w" (b) );
    return r;
}

inline uint64x2_t VEXT_U8(uint64x2_t a, uint64x2_t b, unsigned int c)
{
    uint64x2_t r;
    __asm __volatile("ext   %0.16b, %1.16b, %2.16b, %3 \n\t"
        :"=w" (r) : "w" (a), "w" (b), "I" (c) );
    return r;
}

// https://github.com/weidai11/cryptopp/issues/366
template <unsigned int C>
inline uint64x2_t VEXT_U8(uint64x2_t a, uint64x2_t b)
{
    uint64x2_t r;
    __asm __volatile("ext   %0.16b, %1.16b, %2.16b, %3 \n\t"
        :"=w" (r) : "w" (a), "w" (b), "I" (C) );
    return r;
}
#endif // GCC and compatibles

#if defined(_MSC_VER)
inline uint64x2_t PMULL_00(const uint64x2_t a, const uint64x2_t b)
{
    return (uint64x2_t)(vmull_p64(vgetq_lane_u64(vreinterpretq_u64_u8(a),0),
                                  vgetq_lane_u64(vreinterpretq_u64_u8(b),0)));
}

inline uint64x2_t PMULL_01(const uint64x2_t a, const uint64x2_t b)
{
    return (uint64x2_t)(vmull_p64(vgetq_lane_u64(vreinterpretq_u64_u8(a),0),
                                  vgetq_lane_u64(vreinterpretq_u64_u8(b),1)));
}

inline uint64x2_t PMULL_10(const uint64x2_t a, const uint64x2_t b)
{
    return (uint64x2_t)(vmull_p64(vgetq_lane_u64(vreinterpretq_u64_u8(a),1),
                                  vgetq_lane_u64(vreinterpretq_u64_u8(b),0)));
}

inline uint64x2_t PMULL_11(const uint64x2_t a, const uint64x2_t b)
{
    return (uint64x2_t)(vmull_p64(vgetq_lane_u64(vreinterpretq_u64_u8(a),1),
                                  vgetq_lane_u64(vreinterpretq_u64_u8(b),1)));
}

inline uint64x2_t VEXT_U8(uint64x2_t a, uint64x2_t b, unsigned int c)
{
    return (uint64x2_t)vextq_u8(vreinterpretq_u8_u64(a), vreinterpretq_u8_u64(b), c);
}

// https://github.com/weidai11/cryptopp/issues/366
template <unsigned int C>
inline uint64x2_t VEXT_U8(uint64x2_t a, uint64x2_t b)
{
    return (uint64x2_t)vextq_u8(vreinterpretq_u8_u64(a), vreinterpretq_u8_u64(b), C);
}
#endif // Microsoft and compatibles
#endif // CRYPTOPP_ARMV_PMULL_AVAILABLE

ANONYMOUS_NAMESPACE_END

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

#if (CRYPTOPP_ARMV_PMULL_AVAILABLE)
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
		const poly64_t   a1={0x9090909090909090}, b1={0xb0b0b0b0b0b0b0b0};
		const poly8x16_t a2={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},
		                 b2={0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0};

		const poly128_t r1 = VMULL_P64(a1, b1);
		const poly128_t r2 = VMULL_HIGH_P64((poly64x2_t)(a2), (poly64x2_t)(b2));

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
#endif  // CRYPTOPP_ARMV_PMULL_AVAILABLE

#if CRYPTOPP_ARM_NEON_AVAILABLE
void GCM_Xor16_NEON(byte *a, const byte *b, const byte *c)
{
    CRYPTOPP_ASSERT(IsAlignedOn(a,GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(b,GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(c,GetAlignmentOf<uint64x2_t>()));
    *(uint64x2_t*)a = veorq_u64(*(uint64x2_t*)b, *(uint64x2_t*)c);
}
#endif

#if CRYPTOPP_ARMV_PMULL_AVAILABLE

ANONYMOUS_NAMESPACE_BEGIN

CRYPTOPP_ALIGN_DATA(16)
const word64 s_clmulConstants64[] = {
    W64LIT(0xe100000000000000), W64LIT(0xc200000000000000),  // Used for ARM and x86; polynomial coefficients
    W64LIT(0x08090a0b0c0d0e0f), W64LIT(0x0001020304050607),  // Unused for ARM; used for x86 _mm_shuffle_epi8
    W64LIT(0x0001020304050607), W64LIT(0x08090a0b0c0d0e0f)   // Unused for ARM; used for x86 _mm_shuffle_epi8
};

const uint64x2_t *s_clmulConstants = (const uint64x2_t *)s_clmulConstants64;
const unsigned int s_clmulTableSizeInBlocks = 8;

ANONYMOUS_NAMESPACE_END

uint64x2_t GCM_Reduce_ARMV8A(uint64x2_t c0, uint64x2_t c1, uint64x2_t c2, const uint64x2_t &r)
{
    c1 = veorq_u64(c1, VEXT_U8<8>(vdupq_n_u64(0), c0));
    c1 = veorq_u64(c1, PMULL_01(c0, r));
    c0 = VEXT_U8<8>(c0, vdupq_n_u64(0));
    c0 = vshlq_n_u64(veorq_u64(c0, c1), 1);
    c0 = PMULL_00(c0, r);
    c2 = veorq_u64(c2, c0);
    c2 = veorq_u64(c2, VEXT_U8<8>(c1, vdupq_n_u64(0)));
    c1 = vshrq_n_u64(vcombine_u64(vget_low_u64(c1), vget_low_u64(c2)), 63);
    c2 = vshlq_n_u64(c2, 1);

    return veorq_u64(c2, c1);
}

uint64x2_t GCM_Multiply_ARMV8A(const uint64x2_t &x, const uint64x2_t &h, const uint64x2_t &r)
{
    const uint64x2_t c0 = PMULL_00(x, h);
    const uint64x2_t c1 = veorq_u64(PMULL_10(x, h), PMULL_01(x, h));
    const uint64x2_t c2 = PMULL_11(x, h);

    return GCM_Reduce_ARMV8A(c0, c1, c2, r);
}

size_t GCM_AuthenticateBlocks_ARMV8(const byte *data, size_t len, const byte *mtable, byte *hbuffer)
{
	const uint64x2_t* table = reinterpret_cast<const uint64x2_t*>(mtable);
	uint64x2_t x = vreinterpretq_u64_u8(vld1q_u8(hbuffer));
	const uint64x2_t r = s_clmulConstants[0];

	const size_t BLOCKSIZE = 16;
	while (len >= BLOCKSIZE)
	{
		size_t s = UnsignedMin(len/BLOCKSIZE, s_clmulTableSizeInBlocks), i=0;
		uint64x2_t d1, d2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data+(s-1)*BLOCKSIZE)));
		uint64x2_t c0 = vdupq_n_u64(0);
		uint64x2_t c1 = vdupq_n_u64(0);
		uint64x2_t c2 = vdupq_n_u64(0);

		while (true)
		{
			const uint64x2_t h0 = vld1q_u64((const uint64_t*)(table+i));
			const uint64x2_t h1 = vld1q_u64((const uint64_t*)(table+i+1));
			const uint64x2_t h2 = veorq_u64(h0, h1);

			if (++i == s)
			{
				const uint64x2_t t1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data)));
				d1 = veorq_u64(vextq_u64(t1, t1, 1), x);
				c0 = veorq_u64(c0, PMULL_00(d1, h0));
				c2 = veorq_u64(c2, PMULL_10(d1, h1));
				d1 = veorq_u64(d1, (uint64x2_t)vcombine_u32(vget_high_u32(vreinterpretq_u32_u64(d1)),
															vget_low_u32(vreinterpretq_u32_u64(d1))));
				c1 = veorq_u64(c1, PMULL_00(d1, h2));

				break;
			}

			d1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data+(s-i)*16-8)));
			c0 = veorq_u64(c0, PMULL_10(d2, h0));
			c2 = veorq_u64(c2, PMULL_10(d1, h1));
			d2 = veorq_u64(d2, d1);
			c1 = veorq_u64(c1, PMULL_10(d2, h2));

			if (++i == s)
			{
				const uint64x2_t t2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data)));
				d1 = veorq_u64(vextq_u64(t2, t2, 1), x);
				c0 = veorq_u64(c0, PMULL_01(d1, h0));
				c2 = veorq_u64(c2, PMULL_11(d1, h1));
				d1 = veorq_u64(d1, (uint64x2_t)vcombine_u32(vget_high_u32(vreinterpretq_u32_u64(d1)),
															vget_low_u32(vreinterpretq_u32_u64(d1))));
				c1 = veorq_u64(c1, PMULL_01(d1, h2));

				break;
			}

			const uint64x2_t t3 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data+(s-i)*16-8)));
			d2 = vextq_u64(t3, t3, 1);
			c0 = veorq_u64(c0, PMULL_01(d1, h0));
			c2 = veorq_u64(c2, PMULL_01(d2, h1));
			d1 = veorq_u64(d1, d2);
			c1 = veorq_u64(c1, PMULL_01(d1, h2));
		}
		data += s*16;
		len -= s*16;

		c1 = veorq_u64(veorq_u64(c1, c0), c2);
		x = GCM_Reduce_ARMV8A(c0, c1, c2, r);
	}

	vst1q_u64(reinterpret_cast<uint64_t *>(hbuffer), x);
	return len;
}
#endif

NAMESPACE_END