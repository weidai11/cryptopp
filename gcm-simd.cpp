// gcm-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to SSE4.2 and
//    ARMv8a CRC-32 and CRC-32C instructions. A separate source file
//    is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"

// Clang 3.3 integrated assembler crash on Linux. Other versions produce incorrect results.
//   Clang has never handled Intel ASM very well. I wish LLVM would fix it.
#if defined(__clang__)
# undef CRYPTOPP_X86_ASM_AVAILABLE
# undef CRYPTOPP_X32_ASM_AVAILABLE
# undef CRYPTOPP_X64_ASM_AVAILABLE
# undef CRYPTOPP_SSE2_ASM_AVAILABLE
#endif

// SunCC 12.3 - 12.5 crash in GCM_Reduce_CLMUL
//   http://github.com/weidai11/cryptopp/issues/226
#if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x5140)
# undef CRYPTOPP_CLMUL_AVAILABLE
#endif

// Clang and GCC hoops...
#if !(defined(__ARM_FEATURE_CRYPTO) || defined(_MSC_VER))
# undef CRYPTOPP_ARM_PMULL_AVAILABLE
#endif

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
# include <emmintrin.h>
#endif

#if (CRYPTOPP_CLMUL_AVAILABLE)
# include <tmmintrin.h>
# include <wmmintrin.h>
#endif

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
# include <arm_neon.h>
#endif

// Can't use CRYPTOPP_ARM_XXX_AVAILABLE because too many
// compilers don't follow ACLE conventions for the include.
#if defined(CRYPTOPP_ARM_ACLE_AVAILABLE)
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

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

// GCC cast warning
#define UINT64X2_CAST(x) ((uint64x2_t *)(void *)(x))
#define CONST_UINT64X2_CAST(x) ((const uint64x2_t *)(const void *)(x))

ANONYMOUS_NAMESPACE_BEGIN

// GCC 4.8 is missing PMULL gear
#if (CRYPTOPP_ARM_PMULL_AVAILABLE)
# if (CRYPTOPP_GCC_VERSION >= 40800) && (CRYPTOPP_GCC_VERSION < 49000)
inline poly128_t VMULL_P64(poly64_t a, poly64_t b)
{
    return __builtin_aarch64_crypto_pmulldi_ppp (a, b);
}

inline poly128_t VMULL_HIGH_P64(poly64x2_t a, poly64x2_t b)
{
    return __builtin_aarch64_crypto_pmullv2di_ppp (a, b);
}
# else
inline poly128_t VMULL_P64(poly64_t a, poly64_t b)
{
    return vmull_p64(a, b);
}

inline poly128_t VMULL_HIGH_P64(poly64x2_t a, poly64x2_t b)
{
    return vmull_high_p64(a, b);
}
# endif
#endif

#if CRYPTOPP_ARM_PMULL_AVAILABLE
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
#endif // CRYPTOPP_ARM_PMULL_AVAILABLE

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
}
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64)
bool CPU_ProbePMULL()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
	return false;
#elif (CRYPTOPP_ARM_PMULL_AVAILABLE)
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

# if defined(__APPLE__)
    // No SIGILL probes on Apple platforms. Plus, Apple Clang does not have PMULL intrinsics.
    return false;
# endif

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
#else
    return false;
#endif  // CRYPTOPP_ARM_SHA_AVAILABLE
}
#endif  // ARM32 or ARM64

#if CRYPTOPP_ARM_NEON_AVAILABLE
void GCM_Xor16_NEON(byte *a, const byte *b, const byte *c)
{
    CRYPTOPP_ASSERT(IsAlignedOn(a,GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(b,GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(c,GetAlignmentOf<uint64x2_t>()));
    *UINT64X2_CAST(a) = veorq_u64(*CONST_UINT64X2_CAST(b), *CONST_UINT64X2_CAST(c));
}
#endif

#if CRYPTOPP_ARM_PMULL_AVAILABLE

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

uint64x2_t GCM_Reduce_PMULL(uint64x2_t c0, uint64x2_t c1, uint64x2_t c2, const uint64x2_t &r)
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

uint64x2_t GCM_Multiply_PMULL(const uint64x2_t &x, const uint64x2_t &h, const uint64x2_t &r)
{
    const uint64x2_t c0 = PMULL_00(x, h);
    const uint64x2_t c1 = veorq_u64(PMULL_10(x, h), PMULL_01(x, h));
    const uint64x2_t c2 = PMULL_11(x, h);

    return GCM_Reduce_PMULL(c0, c1, c2, r);
}

void GCM_SetKeyWithoutResync_PMULL(const byte *hashKey, byte *mulTable, unsigned int tableSize)
{
    const uint64x2_t r = s_clmulConstants[0];
    const uint64x2_t t = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(hashKey)));
    const uint64x2_t h0 = vextq_u64(t, t, 1);

    uint64x2_t h = h0;
    unsigned int i;
    for (i=0; i<tableSize-32; i+=32)
    {
        const uint64x2_t h1 = GCM_Multiply_PMULL(h, h0, r);
        vst1_u64((uint64_t *)(mulTable+i), vget_low_u64(h));
        vst1q_u64((uint64_t *)(mulTable+i+16), h1);
        vst1q_u64((uint64_t *)(mulTable+i+8), h);
        vst1_u64((uint64_t *)(mulTable+i+8), vget_low_u64(h1));
        h = GCM_Multiply_PMULL(h1, h0, r);
    }

    const uint64x2_t h1 = GCM_Multiply_PMULL(h, h0, r);
    vst1_u64((uint64_t *)(mulTable+i), vget_low_u64(h));
    vst1q_u64((uint64_t *)(mulTable+i+16), h1);
    vst1q_u64((uint64_t *)(mulTable+i+8), h);
    vst1_u64((uint64_t *)(mulTable+i+8), vget_low_u64(h1));
}

size_t GCM_AuthenticateBlocks_PMULL(const byte *data, size_t len, const byte *mtable, byte *hbuffer)
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
        x = GCM_Reduce_PMULL(c0, c1, c2, r);
    }

    vst1q_u64(reinterpret_cast<uint64_t *>(hbuffer), x);
    return len;
}

void GCM_ReverseHashBufferIfNeeded_PMULL(byte *hashBuffer)
{
    if (GetNativeByteOrder() != BIG_ENDIAN_ORDER)
    {
        const uint8x16_t x = vrev64q_u8(vld1q_u8(hashBuffer));
        vst1q_u8(hashBuffer, vextq_u8(x, x, 8));
    }
}
#endif

#if CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE
// SunCC 5.10-5.11 compiler crash. Move GCM_Xor16_SSE2 out-of-line, and place in
// a source file with a SSE architecture switch. Also see GH #226 and GH #284.
void GCM_Xor16_SSE2(byte *a, const byte *b, const byte *c)
{
# if CRYPTOPP_SSE2_ASM_AVAILABLE && defined(__GNUC__)
    asm ("movdqa %1, %%xmm0; pxor %2, %%xmm0; movdqa %%xmm0, %0;"
         : "=m" (a[0]) : "m"(b[0]), "m"(c[0]));
# else  // CRYPTOPP_SSE2_INTRIN_AVAILABLE
    _mm_store_si128(M128_CAST(a), _mm_xor_si128(
        _mm_load_si128(CONST_M128_CAST(b)),
        _mm_load_si128(CONST_M128_CAST(c))));
# endif
}
#endif

#if CRYPTOPP_CLMUL_AVAILABLE

ANONYMOUS_NAMESPACE_BEGIN

CRYPTOPP_ALIGN_DATA(16)
const word64 s_clmulConstants64[] = {
    W64LIT(0xe100000000000000), W64LIT(0xc200000000000000),
    W64LIT(0x08090a0b0c0d0e0f), W64LIT(0x0001020304050607),
    W64LIT(0x0001020304050607), W64LIT(0x08090a0b0c0d0e0f)};

const __m128i *s_clmulConstants = CONST_M128_CAST(s_clmulConstants64);
const unsigned int s_cltableSizeInBlocks = 8;

ANONYMOUS_NAMESPACE_END

#if 0
// preserved for testing
void gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
    word64 Z0=0, Z1=0, V0, V1;

    typedef BlockGetAndPut<word64, BigEndian> Block;
    Block::Get(a)(V0)(V1);

    for (int i=0; i<16; i++)
    {
        for (int j=0x80; j!=0; j>>=1)
        {
            int x = b[i] & j;
            Z0 ^= x ? V0 : 0;
            Z1 ^= x ? V1 : 0;
            x = (int)V1 & 1;
            V1 = (V1>>1) | (V0<<63);
            V0 = (V0>>1) ^ (x ? W64LIT(0xe1) << 56 : 0);
        }
    }
    Block::Put(NULLPTR, c)(Z0)(Z1);
}

__m128i _mm_clmulepi64_si128(const __m128i &a, const __m128i &b, int i)
{
    word64 A[1] = {ByteReverse(((word64*)&a)[i&1])};
    word64 B[1] = {ByteReverse(((word64*)&b)[i>>4])};

    PolynomialMod2 pa((byte *)A, 8);
    PolynomialMod2 pb((byte *)B, 8);
    PolynomialMod2 c = pa*pb;

    __m128i output;
    for (int i=0; i<16; i++)
        ((byte *)&output)[i] = c.GetByte(i);
    return output;
}
#endif  // Testing

__m128i GCM_Reduce_CLMUL(__m128i c0, __m128i c1, __m128i c2, const __m128i &r)
{
    /*
    The polynomial to be reduced is c0 * x^128 + c1 * x^64 + c2. c0t below refers to the most
    significant half of c0 as a polynomial, which, due to GCM's bit reflection, are in the
    rightmost bit positions, and the lowest byte addresses.

    c1 ^= c0t * 0xc200000000000000
    c2t ^= c0t
    t = shift (c1t ^ c0b) left 1 bit
    c2 ^= t * 0xe100000000000000
    c2t ^= c1b
    shift c2 left 1 bit and xor in lowest bit of c1t
    */
    c1 = _mm_xor_si128(c1, _mm_slli_si128(c0, 8));
    c1 = _mm_xor_si128(c1, _mm_clmulepi64_si128(c0, r, 0x10));
    c0 = _mm_srli_si128(c0, 8);
    c0 = _mm_xor_si128(c0, c1);
    c0 = _mm_slli_epi64(c0, 1);
    c0 = _mm_clmulepi64_si128(c0, r, 0);
    c2 = _mm_xor_si128(c2, c0);
    c2 = _mm_xor_si128(c2, _mm_srli_si128(c1, 8));
    c1 = _mm_unpacklo_epi64(c1, c2);
    c1 = _mm_srli_epi64(c1, 63);
    c2 = _mm_slli_epi64(c2, 1);
    return _mm_xor_si128(c2, c1);
}

__m128i GCM_Multiply_CLMUL(const __m128i &x, const __m128i &h, const __m128i &r)
{
    const __m128i c0 = _mm_clmulepi64_si128(x,h,0);
    const __m128i c1 = _mm_xor_si128(_mm_clmulepi64_si128(x,h,1), _mm_clmulepi64_si128(x,h,0x10));
    const __m128i c2 = _mm_clmulepi64_si128(x,h,0x11);

    return GCM_Reduce_CLMUL(c0, c1, c2, r);
}

void GCM_SetKeyWithoutResync_CLMUL(const byte *hashKey, byte *mulTable, unsigned int tableSize)
{
    const __m128i r = s_clmulConstants[0];
    const __m128i h0 = _mm_shuffle_epi8(_mm_load_si128(CONST_M128_CAST(hashKey)), s_clmulConstants[1]);

    __m128i h = h0;
    unsigned int i;
    for (i=0; i<tableSize-32; i+=32)
    {
        const __m128i h1 = GCM_Multiply_CLMUL(h, h0, r);
        _mm_storel_epi64(M128_CAST(mulTable+i), h);
        _mm_storeu_si128(M128_CAST(mulTable+i+16), h1);
        _mm_storeu_si128(M128_CAST(mulTable+i+8), h);
        _mm_storel_epi64(M128_CAST(mulTable+i+8), h1);
        h = GCM_Multiply_CLMUL(h1, h0, r);
    }

    const __m128i h1 = GCM_Multiply_CLMUL(h, h0, r);
    _mm_storel_epi64(M128_CAST(mulTable+i), h);
    _mm_storeu_si128(M128_CAST(mulTable+i+16), h1);
    _mm_storeu_si128(M128_CAST(mulTable+i+8), h);
    _mm_storel_epi64(M128_CAST(mulTable+i+8), h1);
}

size_t GCM_AuthenticateBlocks_CLMUL(const byte *data, size_t len, const byte *mtable, byte *hbuffer)
{
    const __m128i *table = CONST_M128_CAST(mtable);
    __m128i x = _mm_load_si128(M128_CAST(hbuffer));
    const __m128i r = s_clmulConstants[0], mask1 = s_clmulConstants[1], mask2 = s_clmulConstants[2];

    while (len >= 16)
    {
        size_t s = UnsignedMin(len/16, s_cltableSizeInBlocks), i=0;
        __m128i d1, d2 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data+(s-1)*16)), mask2);
        __m128i c0 = _mm_setzero_si128();
        __m128i c1 = _mm_setzero_si128();
        __m128i c2 = _mm_setzero_si128();

        while (true)
        {
            const __m128i h0 = _mm_load_si128(table+i);
            const __m128i h1 = _mm_load_si128(table+i+1);
            const __m128i h2 = _mm_xor_si128(h0, h1);

            if (++i == s)
            {
                d1 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data)), mask1);
                d1 = _mm_xor_si128(d1, x);
                c0 = _mm_xor_si128(c0, _mm_clmulepi64_si128(d1, h0, 0));
                c2 = _mm_xor_si128(c2, _mm_clmulepi64_si128(d1, h1, 1));
                d1 = _mm_xor_si128(d1, _mm_shuffle_epi32(d1, _MM_SHUFFLE(1, 0, 3, 2)));
                c1 = _mm_xor_si128(c1, _mm_clmulepi64_si128(d1, h2, 0));
                break;
            }

            d1 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data+(s-i)*16-8)), mask2);
            c0 = _mm_xor_si128(c0, _mm_clmulepi64_si128(d2, h0, 1));
            c2 = _mm_xor_si128(c2, _mm_clmulepi64_si128(d1, h1, 1));
            d2 = _mm_xor_si128(d2, d1);
            c1 = _mm_xor_si128(c1, _mm_clmulepi64_si128(d2, h2, 1));

            if (++i == s)
            {
                d1 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data)), mask1);
                d1 = _mm_xor_si128(d1, x);
                c0 = _mm_xor_si128(c0, _mm_clmulepi64_si128(d1, h0, 0x10));
                c2 = _mm_xor_si128(c2, _mm_clmulepi64_si128(d1, h1, 0x11));
                d1 = _mm_xor_si128(d1, _mm_shuffle_epi32(d1, _MM_SHUFFLE(1, 0, 3, 2)));
                c1 = _mm_xor_si128(c1, _mm_clmulepi64_si128(d1, h2, 0x10));
                break;
            }

            d2 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data+(s-i)*16-8)), mask1);
            c0 = _mm_xor_si128(c0, _mm_clmulepi64_si128(d1, h0, 0x10));
            c2 = _mm_xor_si128(c2, _mm_clmulepi64_si128(d2, h1, 0x10));
            d1 = _mm_xor_si128(d1, d2);
            c1 = _mm_xor_si128(c1, _mm_clmulepi64_si128(d1, h2, 0x10));
        }
        data += s*16;
        len -= s*16;

        c1 = _mm_xor_si128(_mm_xor_si128(c1, c0), c2);
        x = GCM_Reduce_CLMUL(c0, c1, c2, r);
    }

    _mm_store_si128(M128_CAST(hbuffer), x);
    return len;
}

void GCM_ReverseHashBufferIfNeeded_CLMUL(byte *hashBuffer)
{
	// SSSE3 instruction, but only used with CLMUL
    __m128i &x = *M128_CAST(hashBuffer);
    x = _mm_shuffle_epi8(x, s_clmulConstants[1]);
}
#endif

NAMESPACE_END
