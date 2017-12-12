// sha-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to SHA-NI and
//    ARMv8a SHA instructions. A separate source file is needed
//    because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "sha.h"
#include "misc.h"

// We set CRYPTOPP_ARM_SHA_AVAILABLE based on compiler version.
// If the crypto is not available, then we have to disable it here.
#if !(defined(__ARM_FEATURE_CRYPTO) || defined(_MSC_VER))
# undef CRYPTOPP_ARM_SHA_AVAILABLE
#endif

#if (CRYPTOPP_SHANI_AVAILABLE)
# include <nmmintrin.h>
# include <immintrin.h>
#endif

#if (CRYPTOPP_ARM_SHA_AVAILABLE)
# include <arm_neon.h>
# if defined(CRYPTOPP_ARM_ACLE_AVAILABLE)
#  include <arm_acle.h>
# endif
#endif

#if CRYPTOPP_POWER8_SHA_AVAILABLE
# include "ppc-simd.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

// Clang __m128i casts
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

NAMESPACE_BEGIN(CryptoPP)

// ***************** SIGILL probes ********************

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

#if (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64)
bool CPU_ProbeSHA1()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
	return false;
#elif (CRYPTOPP_ARM_SHA_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    volatile bool result = true;
    __try
    {
        uint32x4_t data1 = {1,2,3,4}, data2 = {5,6,7,8}, data3 = {9,10,11,12};

        uint32x4_t r1 = vsha1cq_u32 (data1, 0, data2);
        uint32x4_t r2 = vsha1mq_u32 (data1, 0, data2);
        uint32x4_t r3 = vsha1pq_u32 (data1, 0, data2);
        uint32x4_t r4 = vsha1su0q_u32 (data1, data2, data3);
        uint32x4_t r5 = vsha1su1q_u32 (data1, data2);

        result = !!(vgetq_lane_u32(r1,0) | vgetq_lane_u32(r2,1) | vgetq_lane_u32(r3,2) | vgetq_lane_u32(r4,3) | vgetq_lane_u32(r5,0));
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
        uint32x4_t data1 = {1,2,3,4}, data2 = {5,6,7,8}, data3 = {9,10,11,12};

        uint32x4_t r1 = vsha1cq_u32 (data1, 0, data2);
        uint32x4_t r2 = vsha1mq_u32 (data1, 0, data2);
        uint32x4_t r3 = vsha1pq_u32 (data1, 0, data2);
        uint32x4_t r4 = vsha1su0q_u32 (data1, data2, data3);
        uint32x4_t r5 = vsha1su1q_u32 (data1, data2);

        result = !!(vgetq_lane_u32(r1,0) | vgetq_lane_u32(r2,1) | vgetq_lane_u32(r3,2) | vgetq_lane_u32(r4,3) | vgetq_lane_u32(r5,0));
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ARM_SHA_AVAILABLE
}

bool CPU_ProbeSHA2()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
	return false;
#elif (CRYPTOPP_ARM_SHA_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    volatile bool result = true;
    __try
    {
        uint32x4_t data1 = {1,2,3,4}, data2 = {5,6,7,8}, data3 = {9,10,11,12};

        uint32x4_t r1 = vsha256hq_u32 (data1, data2, data3);
        uint32x4_t r2 = vsha256h2q_u32 (data1, data2, data3);
        uint32x4_t r3 = vsha256su0q_u32 (data1, data2);
        uint32x4_t r4 = vsha256su1q_u32 (data1, data2, data3);

        result = !!(vgetq_lane_u32(r1,0) | vgetq_lane_u32(r2,1) | vgetq_lane_u32(r3,2) | vgetq_lane_u32(r4,3));
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
        uint32x4_t data1 = {1,2,3,4}, data2 = {5,6,7,8}, data3 = {9,10,11,12};

        uint32x4_t r1 = vsha256hq_u32 (data1, data2, data3);
        uint32x4_t r2 = vsha256h2q_u32 (data1, data2, data3);
        uint32x4_t r3 = vsha256su0q_u32 (data1, data2);
        uint32x4_t r4 = vsha256su1q_u32 (data1, data2, data3);

        result = !!(vgetq_lane_u32(r1,0) | vgetq_lane_u32(r2,1) | vgetq_lane_u32(r3,2) | vgetq_lane_u32(r4,3));
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

// ***************** Intel x86 SHA ********************

// provided by sha.cpp
extern const word32 SHA256_K[64];

///////////////////////////////////
// start of Walton/Gulley's code //
///////////////////////////////////

#if CRYPTOPP_SHANI_AVAILABLE
// Based on http://software.intel.com/en-us/articles/intel-sha-extensions and code by Sean Gulley.
void SHA1_HashMultipleBlocks_SHANI(word32 *state, const word32 *data, size_t length, ByteOrder order)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);
    CRYPTOPP_ASSERT(length >= SHA1::BLOCKSIZE);

    __m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
    __m128i MASK, MSG0, MSG1, MSG2, MSG3;

    // Load initial values
    ABCD = _mm_loadu_si128(CONST_M128_CAST(state));
    E0 = _mm_set_epi32(state[4], 0, 0, 0);
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);

    // IA-32 SHA is little endian, SHA::Transform is big endian,
    // and SHA::HashMultipleBlocks can be either. ByteOrder
    // allows us to avoid extra endian reversals. It saves 1.0 cpb.
    MASK = order == BIG_ENDIAN_ORDER ?  // Data arrangement
           _mm_set_epi8(0,1,2,3, 4,5,6,7, 8,9,10,11, 12,13,14,15) :
           _mm_set_epi8(3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12) ;

    while (length >= SHA1::BLOCKSIZE)
    {
        // Save current hash
        ABCD_SAVE = ABCD;
        E0_SAVE = E0;

        // Rounds 0-3
        MSG0 = _mm_loadu_si128(CONST_M128_CAST(data+0));
        MSG0 = _mm_shuffle_epi8(MSG0, MASK);
        E0 = _mm_add_epi32(E0, MSG0);
        E1 = ABCD;
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

        // Rounds 4-7
        MSG1 = _mm_loadu_si128(CONST_M128_CAST(data+4));
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
        MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

        // Rounds 8-11
        MSG2 = _mm_loadu_si128(CONST_M128_CAST(data+8));
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
        MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
        MSG0 = _mm_xor_si128(MSG0, MSG2);

        // Rounds 12-15
        MSG3 = _mm_loadu_si128(CONST_M128_CAST(data+12));
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
        MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
        MSG1 = _mm_xor_si128(MSG1, MSG3);

        // Rounds 16-19
        E0 = _mm_sha1nexte_epu32(E0, MSG0);
        E1 = ABCD;
        MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
        MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
        MSG2 = _mm_xor_si128(MSG2, MSG0);

        // Rounds 20-23
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
        MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
        MSG3 = _mm_xor_si128(MSG3, MSG1);

        // Rounds 24-27
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
        MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
        MSG0 = _mm_xor_si128(MSG0, MSG2);

        // Rounds 28-31
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
        MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
        MSG1 = _mm_xor_si128(MSG1, MSG3);

        // Rounds 32-35
        E0 = _mm_sha1nexte_epu32(E0, MSG0);
        E1 = ABCD;
        MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
        MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
        MSG2 = _mm_xor_si128(MSG2, MSG0);

        // Rounds 36-39
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
        MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
        MSG3 = _mm_xor_si128(MSG3, MSG1);

        // Rounds 40-43
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
        MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
        MSG0 = _mm_xor_si128(MSG0, MSG2);

        // Rounds 44-47
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
        MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
        MSG1 = _mm_xor_si128(MSG1, MSG3);

        // Rounds 48-51
        E0 = _mm_sha1nexte_epu32(E0, MSG0);
        E1 = ABCD;
        MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
        MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
        MSG2 = _mm_xor_si128(MSG2, MSG0);

        // Rounds 52-55
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
        MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
        MSG3 = _mm_xor_si128(MSG3, MSG1);

        // Rounds 56-59
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
        MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
        MSG0 = _mm_xor_si128(MSG0, MSG2);

        // Rounds 60-63
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
        MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
        MSG1 = _mm_xor_si128(MSG1, MSG3);

        // Rounds 64-67
        E0 = _mm_sha1nexte_epu32(E0, MSG0);
        E1 = ABCD;
        MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
        MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
        MSG2 = _mm_xor_si128(MSG2, MSG0);

        // Rounds 68-71
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
        MSG3 = _mm_xor_si128(MSG3, MSG1);

        // Rounds 72-75
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

        // Rounds 76-79
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

        // Add values back to state
        E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
        ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

        data += SHA1::BLOCKSIZE/sizeof(word32);
        length -= SHA1::BLOCKSIZE;
    }

    // Save state
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
    _mm_storeu_si128(M128_CAST(state), ABCD);
    state[4] = _mm_extract_epi32(E0, 3);
}

// Based on http://software.intel.com/en-us/articles/intel-sha-extensions and code by Sean Gulley.
void SHA256_HashMultipleBlocks_SHANI(word32 *state, const word32 *data, size_t length, ByteOrder order)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);
    CRYPTOPP_ASSERT(length >= SHA256::BLOCKSIZE);

    __m128i STATE0, STATE1;
    __m128i MSG, TMP, MASK;
    __m128i TMSG0, TMSG1, TMSG2, TMSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;

    // Load initial values
    TMP    = _mm_loadu_si128(M128_CAST(&state[0]));
    STATE1 = _mm_loadu_si128(M128_CAST(&state[4]));

    // IA-32 SHA is little endian, SHA::Transform is big endian,
    // and SHA::HashMultipleBlocks can be either. ByteOrder
    // allows us to avoid extra endian reversals. It saves 1.0 cpb.
    MASK = order == BIG_ENDIAN_ORDER ?  // Data arrangement
           _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3) :
           _mm_set_epi8(15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0) ;

    TMP = _mm_shuffle_epi32(TMP, 0xB1);          // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    // EFGH
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); // CDGH

    while (length >= SHA256::BLOCKSIZE)
    {
        // Save current hash
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        // Rounds 0-3
        MSG = _mm_loadu_si128(CONST_M128_CAST(data+0));
        TMSG0 = _mm_shuffle_epi8(MSG, MASK);
        MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(W64LIT(0xE9B5DBA5B5C0FBCF), W64LIT(0x71374491428A2F98)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Rounds 4-7
        TMSG1 = _mm_loadu_si128(CONST_M128_CAST(data+4));
        TMSG1 = _mm_shuffle_epi8(TMSG1, MASK);
        MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(W64LIT(0xAB1C5ED5923F82A4), W64LIT(0x59F111F13956C25B)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

        // Rounds 8-11
        TMSG2 = _mm_loadu_si128(CONST_M128_CAST(data+8));
        TMSG2 = _mm_shuffle_epi8(TMSG2, MASK);
        MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(W64LIT(0x550C7DC3243185BE), W64LIT(0x12835B01D807AA98)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

        // Rounds 12-15
        TMSG3 = _mm_loadu_si128(CONST_M128_CAST(data+12));
        TMSG3 = _mm_shuffle_epi8(TMSG3, MASK);
        MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(W64LIT(0xC19BF1749BDC06A7), W64LIT(0x80DEB1FE72BE5D74)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
        TMSG0 = _mm_add_epi32(TMSG0, TMP);
        TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

        // Rounds 16-19
        MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(W64LIT(0x240CA1CC0FC19DC6), W64LIT(0xEFBE4786E49B69C1)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
        TMSG1 = _mm_add_epi32(TMSG1, TMP);
        TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

        // Rounds 20-23
        MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(W64LIT(0x76F988DA5CB0A9DC), W64LIT(0x4A7484AA2DE92C6F)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
        TMSG2 = _mm_add_epi32(TMSG2, TMP);
        TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

        // Rounds 24-27
        MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(W64LIT(0xBF597FC7B00327C8), W64LIT(0xA831C66D983E5152)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
        TMSG3 = _mm_add_epi32(TMSG3, TMP);
        TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

        // Rounds 28-31
        MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(W64LIT(0x1429296706CA6351), W64LIT(0xD5A79147C6E00BF3)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
        TMSG0 = _mm_add_epi32(TMSG0, TMP);
        TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

        // Rounds 32-35
        MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(W64LIT(0x53380D134D2C6DFC), W64LIT(0x2E1B213827B70A85)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
        TMSG1 = _mm_add_epi32(TMSG1, TMP);
        TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

        // Rounds 36-39
        MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(W64LIT(0x92722C8581C2C92E), W64LIT(0x766A0ABB650A7354)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
        TMSG2 = _mm_add_epi32(TMSG2, TMP);
        TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

        // Rounds 40-43
        MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(W64LIT(0xC76C51A3C24B8B70), W64LIT(0xA81A664BA2BFE8A1)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
        TMSG3 = _mm_add_epi32(TMSG3, TMP);
        TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

        // Rounds 44-47
        MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(W64LIT(0x106AA070F40E3585), W64LIT(0xD6990624D192E819)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
        TMSG0 = _mm_add_epi32(TMSG0, TMP);
        TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

        // Rounds 48-51
        MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(W64LIT(0x34B0BCB52748774C), W64LIT(0x1E376C0819A4C116)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
        TMSG1 = _mm_add_epi32(TMSG1, TMP);
        TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

        // Rounds 52-55
        MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(W64LIT(0x682E6FF35B9CCA4F), W64LIT(0x4ED8AA4A391C0CB3)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
        TMSG2 = _mm_add_epi32(TMSG2, TMP);
        TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Rounds 56-59
        MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(W64LIT(0x8CC7020884C87814), W64LIT(0x78A5636F748F82EE)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
        TMSG3 = _mm_add_epi32(TMSG3, TMP);
        TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Rounds 60-63
        MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(W64LIT(0xC67178F2BEF9A3F7), W64LIT(0xA4506CEB90BEFFFA)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Add values back to state
        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        data += SHA256::BLOCKSIZE/sizeof(word32);
        length -= SHA256::BLOCKSIZE;
    }

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);       // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    // DCHG
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); // DCBA
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    // ABEF

    // Save state
    _mm_storeu_si128(M128_CAST(&state[0]), STATE0);
    _mm_storeu_si128(M128_CAST(&state[4]), STATE1);
}
#endif  // CRYPTOPP_SHANI_AVAILABLE

/////////////////////////////////
// end of Walton/Gulley's code //
/////////////////////////////////

// ***************** ARMV8 SHA ********************

/////////////////////////////////////////////////////////
// start of Walton/Schneiders/O'Rourke/Hovsmith's code //
/////////////////////////////////////////////////////////

#if CRYPTOPP_ARM_SHA_AVAILABLE
void SHA1_HashMultipleBlocks_ARMV8(word32 *state, const word32 *data, size_t length, ByteOrder order)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);
    CRYPTOPP_ASSERT(length >= SHA1::BLOCKSIZE);

    uint32x4_t C0, C1, C2, C3;
    uint32x4_t ABCD, ABCD_SAVED;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1;
    uint32_t   E0, E0_SAVED, E1;

    // Load initial values
    C0 = vdupq_n_u32(0x5A827999);
    C1 = vdupq_n_u32(0x6ED9EBA1);
    C2 = vdupq_n_u32(0x8F1BBCDC);
    C3 = vdupq_n_u32(0xCA62C1D6);

    ABCD = vld1q_u32(&state[0]);
    E0 = state[4];

    while (length >= SHA1::BLOCKSIZE)
    {
        // Save current hash
        ABCD_SAVED = ABCD;
        E0_SAVED = E0;

        MSG0 = vld1q_u32(data +  0);
        MSG1 = vld1q_u32(data +  4);
        MSG2 = vld1q_u32(data +  8);
        MSG3 = vld1q_u32(data + 12);

        if (order == BIG_ENDIAN_ORDER)  // Data arrangement
        {
            MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
            MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
            MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
            MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));
        }

        TMP0 = vaddq_u32(MSG0, C0);
        TMP1 = vaddq_u32(MSG1, C0);

        // Rounds 0-3
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1cq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG2, C0);
        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

        // Rounds 4-7
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1cq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG3, C0);
        MSG0 = vsha1su1q_u32(MSG0, MSG3);
        MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

        // Rounds 8-11
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1cq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG0, C0);
        MSG1 = vsha1su1q_u32(MSG1, MSG0);
        MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

        // Rounds 12-15
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1cq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG1, C1);
        MSG2 = vsha1su1q_u32(MSG2, MSG1);
        MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

        // Rounds 16-19
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1cq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG2, C1);
        MSG3 = vsha1su1q_u32(MSG3, MSG2);
        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

        // Rounds 20-23
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG3, C1);
        MSG0 = vsha1su1q_u32(MSG0, MSG3);
        MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

        // Rounds 24-27
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG0, C1);
        MSG1 = vsha1su1q_u32(MSG1, MSG0);
        MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

        // Rounds 28-31
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG1, C1);
        MSG2 = vsha1su1q_u32(MSG2, MSG1);
        MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

        // Rounds 32-35
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG2, C2);
        MSG3 = vsha1su1q_u32(MSG3, MSG2);
        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

        // Rounds 36-39
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG3, C2);
        MSG0 = vsha1su1q_u32(MSG0, MSG3);
        MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

        // Rounds 40-43
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1mq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG0, C2);
        MSG1 = vsha1su1q_u32(MSG1, MSG0);
        MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

        // Rounds 44-47
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1mq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG1, C2);
        MSG2 = vsha1su1q_u32(MSG2, MSG1);
        MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

        // Rounds 48-51
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1mq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG2, C2);
        MSG3 = vsha1su1q_u32(MSG3, MSG2);
        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

        // Rounds 52-55
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1mq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG3, C3);
        MSG0 = vsha1su1q_u32(MSG0, MSG3);
        MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

        // Rounds 56-59
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1mq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG0, C3);
        MSG1 = vsha1su1q_u32(MSG1, MSG0);
        MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

        // Rounds 60-63
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG1, C3);
        MSG2 = vsha1su1q_u32(MSG2, MSG1);
        MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

        // Rounds 64-67
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E0, TMP0);
        TMP0 = vaddq_u32(MSG2, C3);
        MSG3 = vsha1su1q_u32(MSG3, MSG2);
        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

        // Rounds 68-71
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E1, TMP1);
        TMP1 = vaddq_u32(MSG3, C3);
        MSG0 = vsha1su1q_u32(MSG0, MSG3);

        // Rounds 72-75
        E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E0, TMP0);

        // Rounds 76-79
        E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
        ABCD = vsha1pq_u32(ABCD, E1, TMP1);

        E0 += E0_SAVED;
        ABCD = vaddq_u32(ABCD_SAVED, ABCD);

        data += SHA1::BLOCKSIZE/sizeof(word32);
        length -= SHA1::BLOCKSIZE;
    }

    // Save state
    vst1q_u32(&state[0], ABCD);
    state[4] = E0;
}

void SHA256_HashMultipleBlocks_ARMV8(word32 *state, const word32 *data, size_t length, ByteOrder order)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);
    CRYPTOPP_ASSERT(length >= SHA256::BLOCKSIZE);

    uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1, TMP2;

    // Load initial values
    STATE0 = vld1q_u32(&state[0]);
    STATE1 = vld1q_u32(&state[4]);

    while (length >= SHA256::BLOCKSIZE)
    {
        // Save current hash
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        // Load message
        MSG0 = vld1q_u32(data +  0);
        MSG1 = vld1q_u32(data +  4);
        MSG2 = vld1q_u32(data +  8);
        MSG3 = vld1q_u32(data + 12);

        if (order == BIG_ENDIAN_ORDER)  // Data arrangement
        {
            MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
            MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
            MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
            MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));
        }

        TMP0 = vaddq_u32(MSG0, vld1q_u32(&SHA256_K[0x00]));

        // Rounds 0-3
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG1, vld1q_u32(&SHA256_K[0x04]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);;

        // Rounds 4-7
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&SHA256_K[0x08]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);;

        // Rounds 8-11
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG3, vld1q_u32(&SHA256_K[0x0c]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);;

        // Rounds 12-15
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&SHA256_K[0x10]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);;

        // Rounds 16-19
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG1, vld1q_u32(&SHA256_K[0x14]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);;

        // Rounds 20-23
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&SHA256_K[0x18]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);;

        // Rounds 24-27
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG3, vld1q_u32(&SHA256_K[0x1c]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);;

        // Rounds 28-31
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&SHA256_K[0x20]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);;

        // Rounds 32-35
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG1, vld1q_u32(&SHA256_K[0x24]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);;

        // Rounds 36-39
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&SHA256_K[0x28]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);;

        // Rounds 40-43
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG3, vld1q_u32(&SHA256_K[0x2c]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);;

        // Rounds 44-47
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&SHA256_K[0x30]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);;

        // Rounds 48-51
        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG1, vld1q_u32(&SHA256_K[0x34]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);;

        // Rounds 52-55
        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&SHA256_K[0x38]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);;

        // Rounds 56-59
        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG3, vld1q_u32(&SHA256_K[0x3c]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);;

        // Rounds 60-63
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);;

        // Add back to state
        STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
        STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

        data += SHA256::BLOCKSIZE/sizeof(word32);
        length -= SHA256::BLOCKSIZE;
    }

    // Save state
    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}
#endif  // CRYPTOPP_ARM_SHA_AVAILABLE

///////////////////////////////////////////////////////
// end of Walton/Schneiders/O'Rourke/Hovsmith's code //
///////////////////////////////////////////////////////

// ***************** Power8 SHA ********************

////////////////////////////////////////////////
// Begin Gustavo Serra Scalet and Walton code //
////////////////////////////////////////////////

#if CRYPTOPP_POWER8_SHA_AVAILABLE
void SHA256_HashMultipleBlocks_POWER8(word32 *state, const word32 *data, size_t length, ByteOrder order)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);
    CRYPTOPP_ASSERT(length >= SHA256::BLOCKSIZE);

	CRYPTOPP_ASSERT(0);
}

void SHA512_HashMultipleBlocks_POWER8(word64 *state, const word64 *data, size_t length, ByteOrder order)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);
    CRYPTOPP_ASSERT(length >= SHA512::BLOCKSIZE);

	CRYPTOPP_ASSERT(0);
}

#endif  // CRYPTOPP_POWER8_SHA_AVAILABLE

//////////////////////////////////////////////
// End Gustavo Serra Scalet and Walton code //
//////////////////////////////////////////////

NAMESPACE_END
