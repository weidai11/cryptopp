// gcm_simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//                Original x86 CLMUL by Wei Dai. ARM and POWER8
//                PMULL and VMULL by JW, UB and MR.
//
//    This source file uses intrinsics to gain access to SSE4.2 and
//    ARMv8a CRC-32 and CRC-32C instructions. A separate source file
//    is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "misc.h"

#if defined(CRYPTOPP_DISABLE_GCM_ASM)
# undef CRYPTOPP_X86_ASM_AVAILABLE
# undef CRYPTOPP_X32_ASM_AVAILABLE
# undef CRYPTOPP_X64_ASM_AVAILABLE
# undef CRYPTOPP_SSE2_ASM_AVAILABLE
#endif

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
# include <emmintrin.h>
# include <xmmintrin.h>
#endif

#if (CRYPTOPP_CLMUL_AVAILABLE)
# include <tmmintrin.h>
# include <wmmintrin.h>
#endif

// C1189: error: This header is specific to ARM targets
#if (CRYPTOPP_ARM_NEON_AVAILABLE) && !defined(_M_ARM64)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_ARM_ACLE_AVAILABLE)
# include <stdint.h>
# include <arm_acle.h>
#endif

#if defined(CRYPTOPP_ARM_PMULL_AVAILABLE)
# include "arm_simd.h"
#endif

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

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

// GCC cast warning
#define UINT64X2_CAST(x) ((uint64x2_t *)(void *)(x))
#define CONST_UINT64X2_CAST(x) ((const uint64x2_t *)(const void *)(x))

// Squash MS LNK4221 and libtool warnings
extern const char GCM_SIMD_FNAME[] = __FILE__;

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
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARMV8)
bool CPU_ProbePMULL()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_ARM_PMULL_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    volatile bool result = true;
    __try
    {
        // Linaro is missing a lot of pmull gear. Also see http://github.com/weidai11/cryptopp/issues/233.
        const uint64_t wa1[]={0,0x9090909090909090}, wb1[]={0,0xb0b0b0b0b0b0b0b0};
        const uint64x2_t a1=vld1q_u64(wa1), b1=vld1q_u64(wb1);

        const uint8_t wa2[]={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,
                             0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},
                      wb2[]={0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,
                             0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0};
        const uint8x16_t a2=vld1q_u8(wa2), b2=vld1q_u8(wb2);

        const uint64x2_t r1 = PMULL_00(a1, b1);
        const uint64x2_t r2 = PMULL_11(vreinterpretq_u64_u8(a2),
                                       vreinterpretq_u64_u8(b2));

        result = !!(vgetq_lane_u64(r1,0) == 0x5300530053005300 &&
                    vgetq_lane_u64(r1,1) == 0x5300530053005300 &&
                    vgetq_lane_u64(r2,0) == 0x6c006c006c006c00 &&
                    vgetq_lane_u64(r2,1) == 0x6c006c006c006c00);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return result;
# else

    // longjmp and clobber warnings. Volatile is required.
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
        // Linaro is missing a lot of pmull gear. Also see http://github.com/weidai11/cryptopp/issues/233.
        const uint64_t wa1[]={0,0x9090909090909090}, wb1[]={0,0xb0b0b0b0b0b0b0b0};
        const uint64x2_t a1=vld1q_u64(wa1), b1=vld1q_u64(wb1);

        const uint8_t wa2[]={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,
                             0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},
                      wb2[]={0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,
                             0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0};
        const uint8x16_t a2=vld1q_u8(wa2), b2=vld1q_u8(wb2);

        const uint64x2_t r1 = PMULL_00(a1, b1);
        const uint64x2_t r2 = PMULL_11(vreinterpretq_u64_u8(a2),
                                       vreinterpretq_u64_u8(b2));

        result = !!(vgetq_lane_u64(r1,0) == 0x5300530053005300 &&
                    vgetq_lane_u64(r1,1) == 0x5300530053005300 &&
                    vgetq_lane_u64(r2,0) == 0x6c006c006c006c00 &&
                    vgetq_lane_u64(r2,1) == 0x6c006c006c006c00);
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ARM_PMULL_AVAILABLE
}
#endif  // ARM32 or ARM64

#if (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)
bool CPU_ProbePMULL()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_POWER8_VMULL_AVAILABLE)
    // longjmp and clobber warnings. Volatile is required.
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
        const uint64_t wa1[]={0,W64LIT(0x9090909090909090)},
                       wb1[]={0,W64LIT(0xb0b0b0b0b0b0b0b0)};
        const uint64x2_p a1=VecLoad(wa1), b1=VecLoad(wb1);

        const uint8_t wa2[]={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,
                             0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},
                      wb2[]={0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,
                             0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0};
        const uint32x4_p a2=VecLoad(wa2), b2=VecLoad(wb2);

        const uint64x2_p r1 = VecPolyMultiply00LE(a1, b1);
        const uint64x2_p r2 = VecPolyMultiply11LE((uint64x2_p)a2, (uint64x2_p)b2);

        const uint64_t wc1[]={W64LIT(0x5300530053005300), W64LIT(0x5300530053005300)},
                       wc2[]={W64LIT(0x6c006c006c006c00), W64LIT(0x6c006c006c006c00)};
        const uint64x2_p c1=VecLoad(wc1), c2=VecLoad(wc2);

        result = !!(VecEqual(r1, c1) && VecEqual(r2, c2));
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
#else
    return false;
#endif  // CRYPTOPP_POWER8_VMULL_AVAILABLE
}
#endif  // PPC32 or PPC64

// *************************** ARM NEON *************************** //

#if CRYPTOPP_ARM_NEON_AVAILABLE
void GCM_Xor16_NEON(byte *a, const byte *b, const byte *c)
{
    CRYPTOPP_ASSERT(IsAlignedOn(a,GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(b,GetAlignmentOf<uint64x2_t>()));
    CRYPTOPP_ASSERT(IsAlignedOn(c,GetAlignmentOf<uint64x2_t>()));
    *UINT64X2_CAST(a) = veorq_u64(*CONST_UINT64X2_CAST(b), *CONST_UINT64X2_CAST(c));
}
#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

#if CRYPTOPP_ARM_PMULL_AVAILABLE

// Swaps high and low 64-bit words
inline uint64x2_t SwapWords(const uint64x2_t& data)
{
    return (uint64x2_t)vcombine_u64(
        vget_high_u64(data), vget_low_u64(data));
}

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
    const uint64x2_t r = {0xe100000000000000ull, 0xc200000000000000ull};
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
    const uint64x2_t r = {0xe100000000000000ull, 0xc200000000000000ull};
    uint64x2_t x = vreinterpretq_u64_u8(vld1q_u8(hbuffer));

    while (len >= 16)
    {
        size_t i=0, s = UnsignedMin(len/16U, 8U);
        uint64x2_t d1, d2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data+(s-1)*16U)));
        uint64x2_t c0 = vdupq_n_u64(0);
        uint64x2_t c1 = vdupq_n_u64(0);
        uint64x2_t c2 = vdupq_n_u64(0);

        while (true)
        {
            const uint64x2_t h0 = vld1q_u64((const uint64_t*)(mtable+(i+0)*16));
            const uint64x2_t h1 = vld1q_u64((const uint64_t*)(mtable+(i+1)*16));
            const uint64x2_t h2 = veorq_u64(h0, h1);

            if (++i == s)
            {
                const uint64x2_t t1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data)));
                d1 = veorq_u64(vextq_u64(t1, t1, 1), x);
                c0 = veorq_u64(c0, PMULL_00(d1, h0));
                c2 = veorq_u64(c2, PMULL_10(d1, h1));
                d1 = veorq_u64(d1, SwapWords(d1));
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
                d1 = veorq_u64(d1, SwapWords(d1));
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
#endif  // CRYPTOPP_ARM_PMULL_AVAILABLE

// ***************************** SSE ***************************** //

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
#endif  // CRYPTOPP_SSE2_ASM_AVAILABLE

#if CRYPTOPP_CLMUL_AVAILABLE

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

// Swaps high and low 64-bit words
inline __m128i SwapWords(const __m128i& val)
{
    return _mm_shuffle_epi32(val, _MM_SHUFFLE(1, 0, 3, 2));
}

// SunCC 5.11-5.15 compiler crash. Make the function inline
// and parameters non-const. Also see GH #188 and GH #224.
inline __m128i GCM_Reduce_CLMUL(__m128i c0, __m128i c1, __m128i c2, const __m128i& r)
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
    c0 = _mm_xor_si128(c1, _mm_srli_si128(c0, 8));
    c0 = _mm_slli_epi64(c0, 1);
    c0 = _mm_clmulepi64_si128(c0, r, 0);
    c2 = _mm_xor_si128(c2, c0);
    c2 = _mm_xor_si128(c2, _mm_srli_si128(c1, 8));
    c1 = _mm_unpacklo_epi64(c1, c2);
    c1 = _mm_srli_epi64(c1, 63);
    c2 = _mm_slli_epi64(c2, 1);
    return _mm_xor_si128(c2, c1);
}

// SunCC 5.13-5.14 compiler crash. Don't make the function inline.
// This is in contrast to GCM_Reduce_CLMUL, which must be inline.
__m128i GCM_Multiply_CLMUL(const __m128i &x, const __m128i &h, const __m128i &r)
{
    const __m128i c0 = _mm_clmulepi64_si128(x,h,0);
    const __m128i c1 = _mm_xor_si128(_mm_clmulepi64_si128(x,h,1), _mm_clmulepi64_si128(x,h,0x10));
    const __m128i c2 = _mm_clmulepi64_si128(x,h,0x11);

    return GCM_Reduce_CLMUL(c0, c1, c2, r);
}

void GCM_SetKeyWithoutResync_CLMUL(const byte *hashKey, byte *mulTable, unsigned int tableSize)
{
    const __m128i r = _mm_set_epi32(0xc2000000, 0x00000000, 0xe1000000, 0x00000000);
    const __m128i m = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
    __m128i h0 = _mm_shuffle_epi8(_mm_load_si128(CONST_M128_CAST(hashKey)), m), h = h0;

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
    const __m128i r = _mm_set_epi32(0xc2000000, 0x00000000, 0xe1000000, 0x00000000);
    const __m128i m1 = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
    const __m128i m2 = _mm_set_epi32(0x08090a0b, 0x0c0d0e0f, 0x00010203, 0x04050607);
    __m128i x = _mm_load_si128(M128_CAST(hbuffer));

    while (len >= 16)
    {
        size_t i=0, s = UnsignedMin(len/16, 8U);
        __m128i d1 = _mm_loadu_si128(CONST_M128_CAST(data+(s-1)*16));
        __m128i d2 = _mm_shuffle_epi8(d1, m2);
        __m128i c0 = _mm_setzero_si128();
        __m128i c1 = _mm_setzero_si128();
        __m128i c2 = _mm_setzero_si128();

        while (true)
        {
            const __m128i h0 = _mm_load_si128(CONST_M128_CAST(mtable+(i+0)*16));
            const __m128i h1 = _mm_load_si128(CONST_M128_CAST(mtable+(i+1)*16));
            const __m128i h2 = _mm_xor_si128(h0, h1);

            if (++i == s)
            {
                d1 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data)), m1);
                d1 = _mm_xor_si128(d1, x);
                c0 = _mm_xor_si128(c0, _mm_clmulepi64_si128(d1, h0, 0));
                c2 = _mm_xor_si128(c2, _mm_clmulepi64_si128(d1, h1, 1));
                d1 = _mm_xor_si128(d1, SwapWords(d1));
                c1 = _mm_xor_si128(c1, _mm_clmulepi64_si128(d1, h2, 0));
                break;
            }

            d1 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data+(s-i)*16-8)), m2);
            c0 = _mm_xor_si128(c0, _mm_clmulepi64_si128(d2, h0, 1));
            c2 = _mm_xor_si128(c2, _mm_clmulepi64_si128(d1, h1, 1));
            d2 = _mm_xor_si128(d2, d1);
            c1 = _mm_xor_si128(c1, _mm_clmulepi64_si128(d2, h2, 1));

            if (++i == s)
            {
                d1 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data)), m1);
                d1 = _mm_xor_si128(d1, x);
                c0 = _mm_xor_si128(c0, _mm_clmulepi64_si128(d1, h0, 0x10));
                c2 = _mm_xor_si128(c2, _mm_clmulepi64_si128(d1, h1, 0x11));
                d1 = _mm_xor_si128(d1, SwapWords(d1));
                c1 = _mm_xor_si128(c1, _mm_clmulepi64_si128(d1, h2, 0x10));
                break;
            }

            d2 = _mm_shuffle_epi8(_mm_loadu_si128(CONST_M128_CAST(data+(s-i)*16-8)), m1);
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
    const __m128i mask = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
    _mm_storeu_si128(M128_CAST(hashBuffer), _mm_shuffle_epi8(
        _mm_loadu_si128(CONST_M128_CAST(hashBuffer)), mask));
}
#endif  // CRYPTOPP_CLMUL_AVAILABLE

// ***************************** POWER8 ***************************** //

#if CRYPTOPP_POWER8_AVAILABLE
void GCM_Xor16_POWER8(byte *a, const byte *b, const byte *c)
{
    VecStore(VecXor(VecLoad(b), VecLoad(c)), a);
}
#endif  // CRYPTOPP_POWER8_AVAILABLE

#if CRYPTOPP_POWER8_VMULL_AVAILABLE

uint64x2_p GCM_Reduce_VMULL(uint64x2_p c0, uint64x2_p c1, uint64x2_p c2, uint64x2_p r)
{
    const uint64x2_p m1 = {1,1}, m63 = {63,63};

    c1 = VecXor(c1, VecShiftRightOctet<8>(c0));
    c1 = VecXor(c1, VecPolyMultiply10LE(c0, r));
    c0 = VecXor(c1, VecShiftLeftOctet<8>(c0));
    c0 = VecPolyMultiply00LE(vec_sl(c0, m1), r);
    c2 = VecXor(c2, c0);
    c2 = VecXor(c2, VecShiftLeftOctet<8>(c1));
    c1 = vec_sr(vec_mergeh(c1, c2), m63);
    c2 = vec_sl(c2, m1);

    return VecXor(c2, c1);
}

inline uint64x2_p GCM_Multiply_VMULL(uint64x2_p x, uint64x2_p h, uint64x2_p r)
{
    const uint64x2_p c0 = VecPolyMultiply00LE(x, h);
    const uint64x2_p c1 = VecXor(VecPolyMultiply01LE(x, h), VecPolyMultiply10LE(x, h));
    const uint64x2_p c2 = VecPolyMultiply11LE(x, h);

    return GCM_Reduce_VMULL(c0, c1, c2, r);
}

inline uint64x2_p LoadHashKey(const byte *hashKey)
{
#if (CRYPTOPP_BIG_ENDIAN)
    const uint64x2_p key = (uint64x2_p)VecLoad(hashKey);
    const uint8x16_p mask = {8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7};
    return VecPermute(key, key, mask);
#else
    const uint64x2_p key = (uint64x2_p)VecLoad(hashKey);
    const uint8x16_p mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
    return VecPermute(key, key, mask);
#endif
}

void GCM_SetKeyWithoutResync_VMULL(const byte *hashKey, byte *mulTable, unsigned int tableSize)
{
    const uint64x2_p r = {0xe100000000000000ull, 0xc200000000000000ull};
    uint64x2_p h = LoadHashKey(hashKey), h0 = h;

    unsigned int i;
    uint64_t temp[2];

    for (i=0; i<tableSize-32; i+=32)
    {
        const uint64x2_p h1 = GCM_Multiply_VMULL(h, h0, r);
        VecStore(h, (byte*)temp);
        std::memcpy(mulTable+i, temp+0, 8);
        VecStore(h1, mulTable+i+16);
        VecStore(h, mulTable+i+8);
        VecStore(h1, (byte*)temp);
        std::memcpy(mulTable+i+8, temp+0, 8);
        h = GCM_Multiply_VMULL(h1, h0, r);
    }

    const uint64x2_p h1 = GCM_Multiply_VMULL(h, h0, r);
    VecStore(h, (byte*)temp);
    std::memcpy(mulTable+i, temp+0, 8);
    VecStore(h1, mulTable+i+16);
    VecStore(h, mulTable+i+8);
    VecStore(h1, (byte*)temp);
    std::memcpy(mulTable+i+8, temp+0, 8);
}

// Swaps high and low 64-bit words
template <class T>
inline T SwapWords(const T& data)
{
    return (T)VecRotateLeftOctet<8>(data);
}

inline uint64x2_p LoadBuffer1(const byte *dataBuffer)
{
#if (CRYPTOPP_BIG_ENDIAN)
    return (uint64x2_p)VecLoad(dataBuffer);
#else
    const uint64x2_p data = (uint64x2_p)VecLoad(dataBuffer);
    const uint8x16_p mask = {7,6,5,4, 3,2,1,0, 15,14,13,12, 11,10,9,8};
    return VecPermute(data, data, mask);
#endif
}

inline uint64x2_p LoadBuffer2(const byte *dataBuffer)
{
#if (CRYPTOPP_BIG_ENDIAN)
    return (uint64x2_p)SwapWords(VecLoadBE(dataBuffer));
#else
    return (uint64x2_p)VecLoadBE(dataBuffer);
#endif
}

size_t GCM_AuthenticateBlocks_VMULL(const byte *data, size_t len, const byte *mtable, byte *hbuffer)
{
    const uint64x2_p r = {0xe100000000000000ull, 0xc200000000000000ull};
    uint64x2_p x = (uint64x2_p)VecLoad(hbuffer);

    while (len >= 16)
    {
        size_t i=0, s = UnsignedMin(len/16, 8U);
        uint64x2_p d1, d2 = LoadBuffer1(data+(s-1)*16);
        uint64x2_p c0 = {0}, c1 = {0}, c2 = {0};

        while (true)
        {
            const uint64x2_p h0 = (uint64x2_p)VecLoad(mtable+(i+0)*16);
            const uint64x2_p h1 = (uint64x2_p)VecLoad(mtable+(i+1)*16);
            const uint64x2_p h2 = (uint64x2_p)VecXor(h0, h1);

            if (++i == s)
            {
                d1 = LoadBuffer2(data);
                d1 = VecXor(d1, x);
                c0 = VecXor(c0, VecPolyMultiply00LE(d1, h0));
                c2 = VecXor(c2, VecPolyMultiply01LE(d1, h1));
                d1 = VecXor(d1, SwapWords(d1));
                c1 = VecXor(c1, VecPolyMultiply00LE(d1, h2));
                break;
            }

            d1 = LoadBuffer1(data+(s-i)*16-8);
            c0 = VecXor(c0, VecPolyMultiply01LE(d2, h0));
            c2 = VecXor(c2, VecPolyMultiply01LE(d1, h1));
            d2 = VecXor(d2, d1);
            c1 = VecXor(c1, VecPolyMultiply01LE(d2, h2));

            if (++i == s)
            {
                d1 = LoadBuffer2(data);
                d1 = VecXor(d1, x);
                c0 = VecXor(c0, VecPolyMultiply10LE(d1, h0));
                c2 = VecXor(c2, VecPolyMultiply11LE(d1, h1));
                d1 = VecXor(d1, SwapWords(d1));
                c1 = VecXor(c1, VecPolyMultiply10LE(d1, h2));
                break;
            }

            d2 = LoadBuffer2(data+(s-i)*16-8);
            c0 = VecXor(c0, VecPolyMultiply10LE(d1, h0));
            c2 = VecXor(c2, VecPolyMultiply10LE(d2, h1));
            d1 = VecXor(d1, d2);
            c1 = VecXor(c1, VecPolyMultiply10LE(d1, h2));
        }
        data += s*16;
        len -= s*16;

        c1 = VecXor(VecXor(c1, c0), c2);
        x = GCM_Reduce_VMULL(c0, c1, c2, r);
    }

    VecStore(x, hbuffer);
    return len;
}

void GCM_ReverseHashBufferIfNeeded_VMULL(byte *hashBuffer)
{
    const uint64x2_p mask = {0x08090a0b0c0d0e0full, 0x0001020304050607ull};
    VecStore(VecPermute(VecLoad(hashBuffer), mask), hashBuffer);
}
#endif  // CRYPTOPP_POWER8_VMULL_AVAILABLE

NAMESPACE_END
