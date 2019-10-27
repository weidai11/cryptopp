// chacha_simd.cpp - written and placed in the public domain by
//                   Jack Lloyd and Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    SSE2, ARM NEON and ARMv8a, Power7 and Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.
//
//    SSE2 implementation based on Botan's chacha_sse2.cpp. Many thanks
//    to Jack Lloyd and the Botan team for allowing us to use it.
//
//    The SSE2 implementation is kind of unusual among Crypto++ algorithms.
//    We guard on CRYTPOPP_SSE2_AVAILABLE and use HasSSE2() at runtime. However,
//    if the compiler says a target machine has SSSE3 or XOP available (say, by
//    way of -march=native), then we can pull another 150 to 800 MB/s out of
//    ChaCha. To capture SSSE3 and XOP we use the compiler defines __SSSE3__ and
//    __XOP__ and forgo runtime tests.
//
//    Runtime tests for HasSSSE3() and HasXop() are too expensive to make a
//    sub-case of SSE2. The rotates are on a critical path and the runtime tests
//    crush performance.
//
//    Here are some relative numbers for ChaCha8:
//    * Intel Skylake, 3.0 GHz: SSE2 at 2160 MB/s; SSSE3 at 2310 MB/s.
//    * AMD Bulldozer, 3.3 GHz: SSE2 at 1680 MB/s; XOP at 2510 MB/s.

#include "pch.h"
#include "config.h"

#include "chacha.h"
#include "misc.h"

// Internal compiler error in GCC 3.3 and below
#if defined(__GNUC__) && (__GNUC__ < 4)
# undef CRYPTOPP_SSE2_INTRIN_AVAILABLE
#endif

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
# include <xmmintrin.h>
# include <emmintrin.h>
#endif

#if defined(__SSSE3__)
# include <tmmintrin.h>
#endif

#if defined(__XOP__)
# include <ammintrin.h>
# if defined(__GNUC__)
#  include <x86intrin.h>
# endif
#endif

#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include "ppc_simd.h"
#endif

// Squash MS LNK4221 and libtool warnings
extern const char CHACHA_SIMD_FNAME[] = __FILE__;

ANONYMOUS_NAMESPACE_BEGIN

// ***************************** NEON ***************************** //

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

template <unsigned int R>
inline uint32x4_t RotateLeft(const uint32x4_t& val)
{
    return vorrq_u32(vshlq_n_u32(val, R), vshrq_n_u32(val, 32 - R));
}

template <unsigned int R>
inline uint32x4_t RotateRight(const uint32x4_t& val)
{
    return vorrq_u32(vshlq_n_u32(val, 32 - R), vshrq_n_u32(val, R));
}

template <>
inline uint32x4_t RotateLeft<8>(const uint32x4_t& val)
{
#if defined(__aarch32__) || defined(__aarch64__)
    const uint8_t maskb[16] = { 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 };
    const uint8x16_t mask = vld1q_u8(maskb);

    return vreinterpretq_u32_u8(
        vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
#else
    // fallback to slower C++ rotation.
    return vorrq_u32(vshlq_n_u32(val, 8),
        vshrq_n_u32(val, 32 - 8));
#endif
}

template <>
inline uint32x4_t RotateLeft<16>(const uint32x4_t& val)
{
#if defined(__aarch32__) || defined(__aarch64__)
    return vreinterpretq_u32_u16(
        vrev32q_u16(vreinterpretq_u16_u32(val)));
#else
    // fallback to slower C++ rotation.
    return vorrq_u32(vshlq_n_u32(val, 16),
        vshrq_n_u32(val, 32 - 16));
#endif
}

template <>
inline uint32x4_t RotateRight<8>(const uint32x4_t& val)
{
#if defined(__aarch32__) || defined(__aarch64__)
    const uint8_t maskb[16] = { 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12 };
    const uint8x16_t mask = vld1q_u8(maskb);

    return vreinterpretq_u32_u8(
        vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
#else
    // fallback to slower C++ rotation.
    return vorrq_u32(vshrq_n_u32(val, 8),
        vshlq_n_u32(val, 32 - 8));
#endif
}

template <>
inline uint32x4_t RotateRight<16>(const uint32x4_t& val)
{
#if defined(__aarch32__) || defined(__aarch64__)
    return vreinterpretq_u32_u16(
        vrev32q_u16(vreinterpretq_u16_u32(val)));
#else
    // fallback to slower C++ rotation.
    return vorrq_u32(vshrq_n_u32(val, 16),
        vshlq_n_u32(val, 32 - 16));
#endif
}

// ChaCha's use of x86 shuffle is really a 4, 8, or 12 byte
// rotation on the 128-bit vector word:
//   * [3,2,1,0] => [0,3,2,1] is Extract<1>(x)
//   * [3,2,1,0] => [1,0,3,2] is Extract<2>(x)
//   * [3,2,1,0] => [2,1,0,3] is Extract<3>(x)
template <unsigned int S>
inline uint32x4_t Extract(const uint32x4_t& val)
{
    return vextq_u32(val, val, S);
}

// Helper to perform 64-bit addition across two elements of 32-bit vectors
inline uint32x4_t Add64(const uint32x4_t& a, const uint32x4_t& b)
{
    return vreinterpretq_u32_u64(
        vaddq_u64(
            vreinterpretq_u64_u32(a),
            vreinterpretq_u64_u32(b)));
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// ***************************** SSE2 ***************************** //

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)

template <unsigned int R>
inline __m128i RotateLeft(const __m128i val)
{
#ifdef __XOP__
    return _mm_roti_epi32(val, R);
#else
    return _mm_or_si128(_mm_slli_epi32(val, R), _mm_srli_epi32(val, 32-R));
#endif
}

template <>
inline __m128i RotateLeft<8>(const __m128i val)
{
#if defined(__XOP__)
    return _mm_roti_epi32(val, 8);
#elif defined(__SSSE3__)
    const __m128i mask = _mm_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
    return _mm_shuffle_epi8(val, mask);
#else
    return _mm_or_si128(_mm_slli_epi32(val, 8), _mm_srli_epi32(val, 32-8));
#endif
}

template <>
inline __m128i RotateLeft<16>(const __m128i val)
{
#if defined(__XOP__)
    return _mm_roti_epi32(val, 16);
#elif defined(__SSSE3__)
    const __m128i mask = _mm_set_epi8(13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2);
    return _mm_shuffle_epi8(val, mask);
#else
    return _mm_or_si128(_mm_slli_epi32(val, 16), _mm_srli_epi32(val, 32-16));
#endif
}

#endif  // CRYPTOPP_SSE2_INTRIN_AVAILABLE

// **************************** Altivec **************************** //

#if (CRYPTOPP_ALTIVEC_AVAILABLE)

// ChaCha_OperateKeystream_POWER7 is optimized for POWER7. However, Altivec
// is supported by using vec_ld and vec_st, and using a composite VecAdd
// that supports 64-bit element adds. vec_ld and vec_st add significant
// overhead when memory is not aligned. Despite the drawbacks Altivec
// is profitable. The numbers for ChaCha8 are:
//
//   PowerMac, C++, 2.0 GHz: 205 MB/s, 9.29 cpb
//   PowerMac, Altivec, 2.0 GHz: 471 MB/s, 4.09 cpb

using CryptoPP::uint8x16_p;
using CryptoPP::uint32x4_p;
using CryptoPP::VecLoad;
using CryptoPP::VecStore;
using CryptoPP::VecPermute;

// Permutes bytes in packed 32-bit words to little endian.
// State is already in proper endian order. Input and
// output must be permuted during load and save.
inline uint32x4_p VecLoad32LE(const uint8_t src[16])
{
#if (CRYPTOPP_BIG_ENDIAN)
    const uint8x16_p mask = {3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12};
    const uint32x4_p val = VecLoad(src);
    return VecPermute(val, val, mask);
#else
    return VecLoad(src);
#endif
}

// Permutes bytes in packed 32-bit words to little endian.
// State is already in proper endian order. Input and
// output must be permuted during load and save.
inline void VecStore32LE(uint8_t dest[16], const uint32x4_p& val)
{
#if (CRYPTOPP_BIG_ENDIAN)
    const uint8x16_p mask = {3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12};
    VecStore(VecPermute(val, val, mask), dest);
#else
    return VecStore(val, dest);
#endif
}

// ChaCha's use of x86 shuffle is really a 4, 8, or 12 byte
// rotation on the 128-bit vector word:
//   * [3,2,1,0] => [0,3,2,1] is Shuffle<1>(x)
//   * [3,2,1,0] => [1,0,3,2] is Shuffle<2>(x)
//   * [3,2,1,0] => [2,1,0,3] is Shuffle<3>(x)
template <unsigned int S>
inline uint32x4_p Shuffle(const uint32x4_p& val)
{
    CRYPTOPP_ASSERT(0);
    return val;
}

template <>
inline uint32x4_p Shuffle<1>(const uint32x4_p& val)
{
    const uint8x16_p mask = {4,5,6,7, 8,9,10,11, 12,13,14,15, 0,1,2,3};
    return VecPermute(val, val, mask);
}

template <>
inline uint32x4_p Shuffle<2>(const uint32x4_p& val)
{
    const uint8x16_p mask = {8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7};
    return VecPermute(val, val, mask);
}

template <>
inline uint32x4_p Shuffle<3>(const uint32x4_p& val)
{
    const uint8x16_p mask = {12,13,14,15, 0,1,2,3, 4,5,6,7, 8,9,10,11};
    return VecPermute(val, val, mask);
}

#endif  // CRYPTOPP_ALTIVEC_AVAILABLE

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

// ***************************** NEON ***************************** //

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

void ChaCha_OperateKeystream_NEON(const word32 *state, const byte* input, byte *output, unsigned int rounds)
{
    const uint32x4_t state0 = vld1q_u32(state + 0*4);
    const uint32x4_t state1 = vld1q_u32(state + 1*4);
    const uint32x4_t state2 = vld1q_u32(state + 2*4);
    const uint32x4_t state3 = vld1q_u32(state + 3*4);

    const unsigned int w[] = {1,0,0,0, 2,0,0,0, 3,0,0,0};
    const uint32x4_t CTRS[3] = {
        vld1q_u32(w+0), vld1q_u32(w+4), vld1q_u32(w+8)
    };

    uint32x4_t r0_0 = state0;
    uint32x4_t r0_1 = state1;
    uint32x4_t r0_2 = state2;
    uint32x4_t r0_3 = state3;

    uint32x4_t r1_0 = state0;
    uint32x4_t r1_1 = state1;
    uint32x4_t r1_2 = state2;
    uint32x4_t r1_3 = Add64(r0_3, CTRS[0]);

    uint32x4_t r2_0 = state0;
    uint32x4_t r2_1 = state1;
    uint32x4_t r2_2 = state2;
    uint32x4_t r2_3 = Add64(r0_3, CTRS[1]);

    uint32x4_t r3_0 = state0;
    uint32x4_t r3_1 = state1;
    uint32x4_t r3_2 = state2;
    uint32x4_t r3_3 = Add64(r0_3, CTRS[2]);

    for (int i = static_cast<int>(rounds); i > 0; i -= 2)
    {
        r0_0 = vaddq_u32(r0_0, r0_1);
        r1_0 = vaddq_u32(r1_0, r1_1);
        r2_0 = vaddq_u32(r2_0, r2_1);
        r3_0 = vaddq_u32(r3_0, r3_1);

        r0_3 = veorq_u32(r0_3, r0_0);
        r1_3 = veorq_u32(r1_3, r1_0);
        r2_3 = veorq_u32(r2_3, r2_0);
        r3_3 = veorq_u32(r3_3, r3_0);

        r0_3 = RotateLeft<16>(r0_3);
        r1_3 = RotateLeft<16>(r1_3);
        r2_3 = RotateLeft<16>(r2_3);
        r3_3 = RotateLeft<16>(r3_3);

        r0_2 = vaddq_u32(r0_2, r0_3);
        r1_2 = vaddq_u32(r1_2, r1_3);
        r2_2 = vaddq_u32(r2_2, r2_3);
        r3_2 = vaddq_u32(r3_2, r3_3);

        r0_1 = veorq_u32(r0_1, r0_2);
        r1_1 = veorq_u32(r1_1, r1_2);
        r2_1 = veorq_u32(r2_1, r2_2);
        r3_1 = veorq_u32(r3_1, r3_2);

        r0_1 = RotateLeft<12>(r0_1);
        r1_1 = RotateLeft<12>(r1_1);
        r2_1 = RotateLeft<12>(r2_1);
        r3_1 = RotateLeft<12>(r3_1);

        r0_0 = vaddq_u32(r0_0, r0_1);
        r1_0 = vaddq_u32(r1_0, r1_1);
        r2_0 = vaddq_u32(r2_0, r2_1);
        r3_0 = vaddq_u32(r3_0, r3_1);

        r0_3 = veorq_u32(r0_3, r0_0);
        r1_3 = veorq_u32(r1_3, r1_0);
        r2_3 = veorq_u32(r2_3, r2_0);
        r3_3 = veorq_u32(r3_3, r3_0);

        r0_3 = RotateLeft<8>(r0_3);
        r1_3 = RotateLeft<8>(r1_3);
        r2_3 = RotateLeft<8>(r2_3);
        r3_3 = RotateLeft<8>(r3_3);

        r0_2 = vaddq_u32(r0_2, r0_3);
        r1_2 = vaddq_u32(r1_2, r1_3);
        r2_2 = vaddq_u32(r2_2, r2_3);
        r3_2 = vaddq_u32(r3_2, r3_3);

        r0_1 = veorq_u32(r0_1, r0_2);
        r1_1 = veorq_u32(r1_1, r1_2);
        r2_1 = veorq_u32(r2_1, r2_2);
        r3_1 = veorq_u32(r3_1, r3_2);

        r0_1 = RotateLeft<7>(r0_1);
        r1_1 = RotateLeft<7>(r1_1);
        r2_1 = RotateLeft<7>(r2_1);
        r3_1 = RotateLeft<7>(r3_1);

        r0_1 = Extract<1>(r0_1);
        r0_2 = Extract<2>(r0_2);
        r0_3 = Extract<3>(r0_3);

        r1_1 = Extract<1>(r1_1);
        r1_2 = Extract<2>(r1_2);
        r1_3 = Extract<3>(r1_3);

        r2_1 = Extract<1>(r2_1);
        r2_2 = Extract<2>(r2_2);
        r2_3 = Extract<3>(r2_3);

        r3_1 = Extract<1>(r3_1);
        r3_2 = Extract<2>(r3_2);
        r3_3 = Extract<3>(r3_3);

        r0_0 = vaddq_u32(r0_0, r0_1);
        r1_0 = vaddq_u32(r1_0, r1_1);
        r2_0 = vaddq_u32(r2_0, r2_1);
        r3_0 = vaddq_u32(r3_0, r3_1);

        r0_3 = veorq_u32(r0_3, r0_0);
        r1_3 = veorq_u32(r1_3, r1_0);
        r2_3 = veorq_u32(r2_3, r2_0);
        r3_3 = veorq_u32(r3_3, r3_0);

        r0_3 = RotateLeft<16>(r0_3);
        r1_3 = RotateLeft<16>(r1_3);
        r2_3 = RotateLeft<16>(r2_3);
        r3_3 = RotateLeft<16>(r3_3);

        r0_2 = vaddq_u32(r0_2, r0_3);
        r1_2 = vaddq_u32(r1_2, r1_3);
        r2_2 = vaddq_u32(r2_2, r2_3);
        r3_2 = vaddq_u32(r3_2, r3_3);

        r0_1 = veorq_u32(r0_1, r0_2);
        r1_1 = veorq_u32(r1_1, r1_2);
        r2_1 = veorq_u32(r2_1, r2_2);
        r3_1 = veorq_u32(r3_1, r3_2);

        r0_1 = RotateLeft<12>(r0_1);
        r1_1 = RotateLeft<12>(r1_1);
        r2_1 = RotateLeft<12>(r2_1);
        r3_1 = RotateLeft<12>(r3_1);

        r0_0 = vaddq_u32(r0_0, r0_1);
        r1_0 = vaddq_u32(r1_0, r1_1);
        r2_0 = vaddq_u32(r2_0, r2_1);
        r3_0 = vaddq_u32(r3_0, r3_1);

        r0_3 = veorq_u32(r0_3, r0_0);
        r1_3 = veorq_u32(r1_3, r1_0);
        r2_3 = veorq_u32(r2_3, r2_0);
        r3_3 = veorq_u32(r3_3, r3_0);

        r0_3 = RotateLeft<8>(r0_3);
        r1_3 = RotateLeft<8>(r1_3);
        r2_3 = RotateLeft<8>(r2_3);
        r3_3 = RotateLeft<8>(r3_3);

        r0_2 = vaddq_u32(r0_2, r0_3);
        r1_2 = vaddq_u32(r1_2, r1_3);
        r2_2 = vaddq_u32(r2_2, r2_3);
        r3_2 = vaddq_u32(r3_2, r3_3);

        r0_1 = veorq_u32(r0_1, r0_2);
        r1_1 = veorq_u32(r1_1, r1_2);
        r2_1 = veorq_u32(r2_1, r2_2);
        r3_1 = veorq_u32(r3_1, r3_2);

        r0_1 = RotateLeft<7>(r0_1);
        r1_1 = RotateLeft<7>(r1_1);
        r2_1 = RotateLeft<7>(r2_1);
        r3_1 = RotateLeft<7>(r3_1);

        r0_1 = Extract<3>(r0_1);
        r0_2 = Extract<2>(r0_2);
        r0_3 = Extract<1>(r0_3);

        r1_1 = Extract<3>(r1_1);
        r1_2 = Extract<2>(r1_2);
        r1_3 = Extract<1>(r1_3);

        r2_1 = Extract<3>(r2_1);
        r2_2 = Extract<2>(r2_2);
        r2_3 = Extract<1>(r2_3);

        r3_1 = Extract<3>(r3_1);
        r3_2 = Extract<2>(r3_2);
        r3_3 = Extract<1>(r3_3);
    }

    r0_0 = vaddq_u32(r0_0, state0);
    r0_1 = vaddq_u32(r0_1, state1);
    r0_2 = vaddq_u32(r0_2, state2);
    r0_3 = vaddq_u32(r0_3, state3);

    r1_0 = vaddq_u32(r1_0, state0);
    r1_1 = vaddq_u32(r1_1, state1);
    r1_2 = vaddq_u32(r1_2, state2);
    r1_3 = vaddq_u32(r1_3, state3);
    r1_3 = Add64(r1_3, CTRS[0]);

    r2_0 = vaddq_u32(r2_0, state0);
    r2_1 = vaddq_u32(r2_1, state1);
    r2_2 = vaddq_u32(r2_2, state2);
    r2_3 = vaddq_u32(r2_3, state3);
    r2_3 = Add64(r2_3, CTRS[1]);

    r3_0 = vaddq_u32(r3_0, state0);
    r3_1 = vaddq_u32(r3_1, state1);
    r3_2 = vaddq_u32(r3_2, state2);
    r3_3 = vaddq_u32(r3_3, state3);
    r3_3 = Add64(r3_3, CTRS[2]);

    if (input)
    {
        r0_0 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 0*16)), r0_0);
        r0_1 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 1*16)), r0_1);
        r0_2 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 2*16)), r0_2);
        r0_3 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 3*16)), r0_3);
    }

    vst1q_u8(output + 0*16, vreinterpretq_u8_u32(r0_0));
    vst1q_u8(output + 1*16, vreinterpretq_u8_u32(r0_1));
    vst1q_u8(output + 2*16, vreinterpretq_u8_u32(r0_2));
    vst1q_u8(output + 3*16, vreinterpretq_u8_u32(r0_3));

    if (input)
    {
        r1_0 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 4*16)), r1_0);
        r1_1 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 5*16)), r1_1);
        r1_2 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 6*16)), r1_2);
        r1_3 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 7*16)), r1_3);
    }

    vst1q_u8(output + 4*16, vreinterpretq_u8_u32(r1_0));
    vst1q_u8(output + 5*16, vreinterpretq_u8_u32(r1_1));
    vst1q_u8(output + 6*16, vreinterpretq_u8_u32(r1_2));
    vst1q_u8(output + 7*16, vreinterpretq_u8_u32(r1_3));

    if (input)
    {
        r2_0 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input +  8*16)), r2_0);
        r2_1 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input +  9*16)), r2_1);
        r2_2 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 10*16)), r2_2);
        r2_3 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 11*16)), r2_3);
    }

    vst1q_u8(output +  8*16, vreinterpretq_u8_u32(r2_0));
    vst1q_u8(output +  9*16, vreinterpretq_u8_u32(r2_1));
    vst1q_u8(output + 10*16, vreinterpretq_u8_u32(r2_2));
    vst1q_u8(output + 11*16, vreinterpretq_u8_u32(r2_3));

    if (input)
    {
        r3_0 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 12*16)), r3_0);
        r3_1 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 13*16)), r3_1);
        r3_2 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 14*16)), r3_2);
        r3_3 = veorq_u32(vreinterpretq_u32_u8(vld1q_u8(input + 15*16)), r3_3);
    }

    vst1q_u8(output + 12*16, vreinterpretq_u8_u32(r3_0));
    vst1q_u8(output + 13*16, vreinterpretq_u8_u32(r3_1));
    vst1q_u8(output + 14*16, vreinterpretq_u8_u32(r3_2));
    vst1q_u8(output + 15*16, vreinterpretq_u8_u32(r3_3));
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// ***************************** SSE2 ***************************** //

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)

void ChaCha_OperateKeystream_SSE2(const word32 *state, const byte* input, byte *output, unsigned int rounds)
{
    const __m128i state0 = _mm_load_si128(reinterpret_cast<const __m128i*>(state+0*4));
    const __m128i state1 = _mm_load_si128(reinterpret_cast<const __m128i*>(state+1*4));
    const __m128i state2 = _mm_load_si128(reinterpret_cast<const __m128i*>(state+2*4));
    const __m128i state3 = _mm_load_si128(reinterpret_cast<const __m128i*>(state+3*4));

    __m128i r0_0 = state0;
    __m128i r0_1 = state1;
    __m128i r0_2 = state2;
    __m128i r0_3 = state3;

    __m128i r1_0 = state0;
    __m128i r1_1 = state1;
    __m128i r1_2 = state2;
    __m128i r1_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 1));

    __m128i r2_0 = state0;
    __m128i r2_1 = state1;
    __m128i r2_2 = state2;
    __m128i r2_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 2));

    __m128i r3_0 = state0;
    __m128i r3_1 = state1;
    __m128i r3_2 = state2;
    __m128i r3_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 3));

    for (int i = static_cast<int>(rounds); i > 0; i -= 2)
    {
        r0_0 = _mm_add_epi32(r0_0, r0_1);
        r1_0 = _mm_add_epi32(r1_0, r1_1);
        r2_0 = _mm_add_epi32(r2_0, r2_1);
        r3_0 = _mm_add_epi32(r3_0, r3_1);

        r0_3 = _mm_xor_si128(r0_3, r0_0);
        r1_3 = _mm_xor_si128(r1_3, r1_0);
        r2_3 = _mm_xor_si128(r2_3, r2_0);
        r3_3 = _mm_xor_si128(r3_3, r3_0);

        r0_3 = RotateLeft<16>(r0_3);
        r1_3 = RotateLeft<16>(r1_3);
        r2_3 = RotateLeft<16>(r2_3);
        r3_3 = RotateLeft<16>(r3_3);

        r0_2 = _mm_add_epi32(r0_2, r0_3);
        r1_2 = _mm_add_epi32(r1_2, r1_3);
        r2_2 = _mm_add_epi32(r2_2, r2_3);
        r3_2 = _mm_add_epi32(r3_2, r3_3);

        r0_1 = _mm_xor_si128(r0_1, r0_2);
        r1_1 = _mm_xor_si128(r1_1, r1_2);
        r2_1 = _mm_xor_si128(r2_1, r2_2);
        r3_1 = _mm_xor_si128(r3_1, r3_2);

        r0_1 = RotateLeft<12>(r0_1);
        r1_1 = RotateLeft<12>(r1_1);
        r2_1 = RotateLeft<12>(r2_1);
        r3_1 = RotateLeft<12>(r3_1);

        r0_0 = _mm_add_epi32(r0_0, r0_1);
        r1_0 = _mm_add_epi32(r1_0, r1_1);
        r2_0 = _mm_add_epi32(r2_0, r2_1);
        r3_0 = _mm_add_epi32(r3_0, r3_1);

        r0_3 = _mm_xor_si128(r0_3, r0_0);
        r1_3 = _mm_xor_si128(r1_3, r1_0);
        r2_3 = _mm_xor_si128(r2_3, r2_0);
        r3_3 = _mm_xor_si128(r3_3, r3_0);

        r0_3 = RotateLeft<8>(r0_3);
        r1_3 = RotateLeft<8>(r1_3);
        r2_3 = RotateLeft<8>(r2_3);
        r3_3 = RotateLeft<8>(r3_3);

        r0_2 = _mm_add_epi32(r0_2, r0_3);
        r1_2 = _mm_add_epi32(r1_2, r1_3);
        r2_2 = _mm_add_epi32(r2_2, r2_3);
        r3_2 = _mm_add_epi32(r3_2, r3_3);

        r0_1 = _mm_xor_si128(r0_1, r0_2);
        r1_1 = _mm_xor_si128(r1_1, r1_2);
        r2_1 = _mm_xor_si128(r2_1, r2_2);
        r3_1 = _mm_xor_si128(r3_1, r3_2);

        r0_1 = RotateLeft<7>(r0_1);
        r1_1 = RotateLeft<7>(r1_1);
        r2_1 = RotateLeft<7>(r2_1);
        r3_1 = RotateLeft<7>(r3_1);

        r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(0, 3, 2, 1));
        r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
        r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(2, 1, 0, 3));

        r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(0, 3, 2, 1));
        r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
        r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(2, 1, 0, 3));

        r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(0, 3, 2, 1));
        r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
        r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(2, 1, 0, 3));

        r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(0, 3, 2, 1));
        r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
        r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(2, 1, 0, 3));

        r0_0 = _mm_add_epi32(r0_0, r0_1);
        r1_0 = _mm_add_epi32(r1_0, r1_1);
        r2_0 = _mm_add_epi32(r2_0, r2_1);
        r3_0 = _mm_add_epi32(r3_0, r3_1);

        r0_3 = _mm_xor_si128(r0_3, r0_0);
        r1_3 = _mm_xor_si128(r1_3, r1_0);
        r2_3 = _mm_xor_si128(r2_3, r2_0);
        r3_3 = _mm_xor_si128(r3_3, r3_0);

        r0_3 = RotateLeft<16>(r0_3);
        r1_3 = RotateLeft<16>(r1_3);
        r2_3 = RotateLeft<16>(r2_3);
        r3_3 = RotateLeft<16>(r3_3);

        r0_2 = _mm_add_epi32(r0_2, r0_3);
        r1_2 = _mm_add_epi32(r1_2, r1_3);
        r2_2 = _mm_add_epi32(r2_2, r2_3);
        r3_2 = _mm_add_epi32(r3_2, r3_3);

        r0_1 = _mm_xor_si128(r0_1, r0_2);
        r1_1 = _mm_xor_si128(r1_1, r1_2);
        r2_1 = _mm_xor_si128(r2_1, r2_2);
        r3_1 = _mm_xor_si128(r3_1, r3_2);

        r0_1 = RotateLeft<12>(r0_1);
        r1_1 = RotateLeft<12>(r1_1);
        r2_1 = RotateLeft<12>(r2_1);
        r3_1 = RotateLeft<12>(r3_1);

        r0_0 = _mm_add_epi32(r0_0, r0_1);
        r1_0 = _mm_add_epi32(r1_0, r1_1);
        r2_0 = _mm_add_epi32(r2_0, r2_1);
        r3_0 = _mm_add_epi32(r3_0, r3_1);

        r0_3 = _mm_xor_si128(r0_3, r0_0);
        r1_3 = _mm_xor_si128(r1_3, r1_0);
        r2_3 = _mm_xor_si128(r2_3, r2_0);
        r3_3 = _mm_xor_si128(r3_3, r3_0);

        r0_3 = RotateLeft<8>(r0_3);
        r1_3 = RotateLeft<8>(r1_3);
        r2_3 = RotateLeft<8>(r2_3);
        r3_3 = RotateLeft<8>(r3_3);

        r0_2 = _mm_add_epi32(r0_2, r0_3);
        r1_2 = _mm_add_epi32(r1_2, r1_3);
        r2_2 = _mm_add_epi32(r2_2, r2_3);
        r3_2 = _mm_add_epi32(r3_2, r3_3);

        r0_1 = _mm_xor_si128(r0_1, r0_2);
        r1_1 = _mm_xor_si128(r1_1, r1_2);
        r2_1 = _mm_xor_si128(r2_1, r2_2);
        r3_1 = _mm_xor_si128(r3_1, r3_2);

        r0_1 = RotateLeft<7>(r0_1);
        r1_1 = RotateLeft<7>(r1_1);
        r2_1 = RotateLeft<7>(r2_1);
        r3_1 = RotateLeft<7>(r3_1);

        r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(2, 1, 0, 3));
        r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
        r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(0, 3, 2, 1));

        r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(2, 1, 0, 3));
        r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
        r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(0, 3, 2, 1));

        r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(2, 1, 0, 3));
        r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
        r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(0, 3, 2, 1));

        r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(2, 1, 0, 3));
        r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
        r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(0, 3, 2, 1));
    }

    r0_0 = _mm_add_epi32(r0_0, state0);
    r0_1 = _mm_add_epi32(r0_1, state1);
    r0_2 = _mm_add_epi32(r0_2, state2);
    r0_3 = _mm_add_epi32(r0_3, state3);

    r1_0 = _mm_add_epi32(r1_0, state0);
    r1_1 = _mm_add_epi32(r1_1, state1);
    r1_2 = _mm_add_epi32(r1_2, state2);
    r1_3 = _mm_add_epi32(r1_3, state3);
    r1_3 = _mm_add_epi64(r1_3, _mm_set_epi32(0, 0, 0, 1));

    r2_0 = _mm_add_epi32(r2_0, state0);
    r2_1 = _mm_add_epi32(r2_1, state1);
    r2_2 = _mm_add_epi32(r2_2, state2);
    r2_3 = _mm_add_epi32(r2_3, state3);
    r2_3 = _mm_add_epi64(r2_3, _mm_set_epi32(0, 0, 0, 2));

    r3_0 = _mm_add_epi32(r3_0, state0);
    r3_1 = _mm_add_epi32(r3_1, state1);
    r3_2 = _mm_add_epi32(r3_2, state2);
    r3_3 = _mm_add_epi32(r3_3, state3);
    r3_3 = _mm_add_epi64(r3_3, _mm_set_epi32(0, 0, 0, 3));

    if (input)
    {
        r0_0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+0*16)), r0_0);
        r0_1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+1*16)), r0_1);
        r0_2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+2*16)), r0_2);
        r0_3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+3*16)), r0_3);
    }

    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+0*16), r0_0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+1*16), r0_1);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+2*16), r0_2);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+3*16), r0_3);

    if (input)
    {
        r1_0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+4*16)), r1_0);
        r1_1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+5*16)), r1_1);
        r1_2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+6*16)), r1_2);
        r1_3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+7*16)), r1_3);
    }

    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+4*16), r1_0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+5*16), r1_1);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+6*16), r1_2);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+7*16), r1_3);

    if (input)
    {
        r2_0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+ 8*16)), r2_0);
        r2_1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+ 9*16)), r2_1);
        r2_2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+10*16)), r2_2);
        r2_3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+11*16)), r2_3);
    }

    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+ 8*16), r2_0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+ 9*16), r2_1);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+10*16), r2_2);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+11*16), r2_3);

    if (input)
    {
        r3_0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+12*16)), r3_0);
        r3_1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+13*16)), r3_1);
        r3_2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+14*16)), r3_2);
        r3_3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+15*16)), r3_3);
    }

    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+12*16), r3_0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+13*16), r3_1);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+14*16), r3_2);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output+15*16), r3_3);
}

#endif  // CRYPTOPP_SSE2_INTRIN_AVAILABLE

#if (CRYPTOPP_POWER7_AVAILABLE || CRYPTOPP_ALTIVEC_AVAILABLE)

// ChaCha_OperateKeystream_CORE will use either POWER7 or ALTIVEC,
// depending on the flags used to compile this source file. The
// abstractions are handled in VecLoad, VecStore and friends. In
// the future we may to provide both POWER7 or ALTIVEC at the same
// time to better support distros.
inline void ChaCha_OperateKeystream_CORE(const word32 *state, const byte* input, byte *output, unsigned int rounds)
{
    const uint32x4_p state0 = VecLoad(state + 0*4);
    const uint32x4_p state1 = VecLoad(state + 1*4);
    const uint32x4_p state2 = VecLoad(state + 2*4);
    const uint32x4_p state3 = VecLoad(state + 3*4);

    const uint32x4_p CTRS[3] = {
        {1,0,0,0}, {2,0,0,0}, {3,0,0,0}
    };

    uint32x4_p r0_0 = state0;
    uint32x4_p r0_1 = state1;
    uint32x4_p r0_2 = state2;
    uint32x4_p r0_3 = state3;

    uint32x4_p r1_0 = state0;
    uint32x4_p r1_1 = state1;
    uint32x4_p r1_2 = state2;
    uint32x4_p r1_3 = VecAdd64(r0_3, CTRS[0]);

    uint32x4_p r2_0 = state0;
    uint32x4_p r2_1 = state1;
    uint32x4_p r2_2 = state2;
    uint32x4_p r2_3 = VecAdd64(r0_3, CTRS[1]);

    uint32x4_p r3_0 = state0;
    uint32x4_p r3_1 = state1;
    uint32x4_p r3_2 = state2;
    uint32x4_p r3_3 = VecAdd64(r0_3, CTRS[2]);

    for (int i = static_cast<int>(rounds); i > 0; i -= 2)
    {
        r0_0 = VecAdd(r0_0, r0_1);
        r1_0 = VecAdd(r1_0, r1_1);
        r2_0 = VecAdd(r2_0, r2_1);
        r3_0 = VecAdd(r3_0, r3_1);

        r0_3 = VecXor(r0_3, r0_0);
        r1_3 = VecXor(r1_3, r1_0);
        r2_3 = VecXor(r2_3, r2_0);
        r3_3 = VecXor(r3_3, r3_0);

        r0_3 = VecRotateLeft<16>(r0_3);
        r1_3 = VecRotateLeft<16>(r1_3);
        r2_3 = VecRotateLeft<16>(r2_3);
        r3_3 = VecRotateLeft<16>(r3_3);

        r0_2 = VecAdd(r0_2, r0_3);
        r1_2 = VecAdd(r1_2, r1_3);
        r2_2 = VecAdd(r2_2, r2_3);
        r3_2 = VecAdd(r3_2, r3_3);

        r0_1 = VecXor(r0_1, r0_2);
        r1_1 = VecXor(r1_1, r1_2);
        r2_1 = VecXor(r2_1, r2_2);
        r3_1 = VecXor(r3_1, r3_2);

        r0_1 = VecRotateLeft<12>(r0_1);
        r1_1 = VecRotateLeft<12>(r1_1);
        r2_1 = VecRotateLeft<12>(r2_1);
        r3_1 = VecRotateLeft<12>(r3_1);

        r0_0 = VecAdd(r0_0, r0_1);
        r1_0 = VecAdd(r1_0, r1_1);
        r2_0 = VecAdd(r2_0, r2_1);
        r3_0 = VecAdd(r3_0, r3_1);

        r0_3 = VecXor(r0_3, r0_0);
        r1_3 = VecXor(r1_3, r1_0);
        r2_3 = VecXor(r2_3, r2_0);
        r3_3 = VecXor(r3_3, r3_0);

        r0_3 = VecRotateLeft<8>(r0_3);
        r1_3 = VecRotateLeft<8>(r1_3);
        r2_3 = VecRotateLeft<8>(r2_3);
        r3_3 = VecRotateLeft<8>(r3_3);

        r0_2 = VecAdd(r0_2, r0_3);
        r1_2 = VecAdd(r1_2, r1_3);
        r2_2 = VecAdd(r2_2, r2_3);
        r3_2 = VecAdd(r3_2, r3_3);

        r0_1 = VecXor(r0_1, r0_2);
        r1_1 = VecXor(r1_1, r1_2);
        r2_1 = VecXor(r2_1, r2_2);
        r3_1 = VecXor(r3_1, r3_2);

        r0_1 = VecRotateLeft<7>(r0_1);
        r1_1 = VecRotateLeft<7>(r1_1);
        r2_1 = VecRotateLeft<7>(r2_1);
        r3_1 = VecRotateLeft<7>(r3_1);

        r0_1 = Shuffle<1>(r0_1);
        r0_2 = Shuffle<2>(r0_2);
        r0_3 = Shuffle<3>(r0_3);

        r1_1 = Shuffle<1>(r1_1);
        r1_2 = Shuffle<2>(r1_2);
        r1_3 = Shuffle<3>(r1_3);

        r2_1 = Shuffle<1>(r2_1);
        r2_2 = Shuffle<2>(r2_2);
        r2_3 = Shuffle<3>(r2_3);

        r3_1 = Shuffle<1>(r3_1);
        r3_2 = Shuffle<2>(r3_2);
        r3_3 = Shuffle<3>(r3_3);

        r0_0 = VecAdd(r0_0, r0_1);
        r1_0 = VecAdd(r1_0, r1_1);
        r2_0 = VecAdd(r2_0, r2_1);
        r3_0 = VecAdd(r3_0, r3_1);

        r0_3 = VecXor(r0_3, r0_0);
        r1_3 = VecXor(r1_3, r1_0);
        r2_3 = VecXor(r2_3, r2_0);
        r3_3 = VecXor(r3_3, r3_0);

        r0_3 = VecRotateLeft<16>(r0_3);
        r1_3 = VecRotateLeft<16>(r1_3);
        r2_3 = VecRotateLeft<16>(r2_3);
        r3_3 = VecRotateLeft<16>(r3_3);

        r0_2 = VecAdd(r0_2, r0_3);
        r1_2 = VecAdd(r1_2, r1_3);
        r2_2 = VecAdd(r2_2, r2_3);
        r3_2 = VecAdd(r3_2, r3_3);

        r0_1 = VecXor(r0_1, r0_2);
        r1_1 = VecXor(r1_1, r1_2);
        r2_1 = VecXor(r2_1, r2_2);
        r3_1 = VecXor(r3_1, r3_2);

        r0_1 = VecRotateLeft<12>(r0_1);
        r1_1 = VecRotateLeft<12>(r1_1);
        r2_1 = VecRotateLeft<12>(r2_1);
        r3_1 = VecRotateLeft<12>(r3_1);

        r0_0 = VecAdd(r0_0, r0_1);
        r1_0 = VecAdd(r1_0, r1_1);
        r2_0 = VecAdd(r2_0, r2_1);
        r3_0 = VecAdd(r3_0, r3_1);

        r0_3 = VecXor(r0_3, r0_0);
        r1_3 = VecXor(r1_3, r1_0);
        r2_3 = VecXor(r2_3, r2_0);
        r3_3 = VecXor(r3_3, r3_0);

        r0_3 = VecRotateLeft<8>(r0_3);
        r1_3 = VecRotateLeft<8>(r1_3);
        r2_3 = VecRotateLeft<8>(r2_3);
        r3_3 = VecRotateLeft<8>(r3_3);

        r0_2 = VecAdd(r0_2, r0_3);
        r1_2 = VecAdd(r1_2, r1_3);
        r2_2 = VecAdd(r2_2, r2_3);
        r3_2 = VecAdd(r3_2, r3_3);

        r0_1 = VecXor(r0_1, r0_2);
        r1_1 = VecXor(r1_1, r1_2);
        r2_1 = VecXor(r2_1, r2_2);
        r3_1 = VecXor(r3_1, r3_2);

        r0_1 = VecRotateLeft<7>(r0_1);
        r1_1 = VecRotateLeft<7>(r1_1);
        r2_1 = VecRotateLeft<7>(r2_1);
        r3_1 = VecRotateLeft<7>(r3_1);

        r0_1 = Shuffle<3>(r0_1);
        r0_2 = Shuffle<2>(r0_2);
        r0_3 = Shuffle<1>(r0_3);

        r1_1 = Shuffle<3>(r1_1);
        r1_2 = Shuffle<2>(r1_2);
        r1_3 = Shuffle<1>(r1_3);

        r2_1 = Shuffle<3>(r2_1);
        r2_2 = Shuffle<2>(r2_2);
        r2_3 = Shuffle<1>(r2_3);

        r3_1 = Shuffle<3>(r3_1);
        r3_2 = Shuffle<2>(r3_2);
        r3_3 = Shuffle<1>(r3_3);
    }

    r0_0 = VecAdd(r0_0, state0);
    r0_1 = VecAdd(r0_1, state1);
    r0_2 = VecAdd(r0_2, state2);
    r0_3 = VecAdd(r0_3, state3);

    r1_0 = VecAdd(r1_0, state0);
    r1_1 = VecAdd(r1_1, state1);
    r1_2 = VecAdd(r1_2, state2);
    r1_3 = VecAdd(r1_3, state3);
    r1_3 = VecAdd64(r1_3, CTRS[0]);

    r2_0 = VecAdd(r2_0, state0);
    r2_1 = VecAdd(r2_1, state1);
    r2_2 = VecAdd(r2_2, state2);
    r2_3 = VecAdd(r2_3, state3);
    r2_3 = VecAdd64(r2_3, CTRS[1]);

    r3_0 = VecAdd(r3_0, state0);
    r3_1 = VecAdd(r3_1, state1);
    r3_2 = VecAdd(r3_2, state2);
    r3_3 = VecAdd(r3_3, state3);
    r3_3 = VecAdd64(r3_3, CTRS[2]);

    if (input)
    {
        r0_0 = VecXor(VecLoad32LE(input + 0*16), r0_0);
        r0_1 = VecXor(VecLoad32LE(input + 1*16), r0_1);
        r0_2 = VecXor(VecLoad32LE(input + 2*16), r0_2);
        r0_3 = VecXor(VecLoad32LE(input + 3*16), r0_3);
    }

    VecStore32LE(output + 0*16, r0_0);
    VecStore32LE(output + 1*16, r0_1);
    VecStore32LE(output + 2*16, r0_2);
    VecStore32LE(output + 3*16, r0_3);

    if (input)
    {
        r1_0 = VecXor(VecLoad32LE(input + 4*16), r1_0);
        r1_1 = VecXor(VecLoad32LE(input + 5*16), r1_1);
        r1_2 = VecXor(VecLoad32LE(input + 6*16), r1_2);
        r1_3 = VecXor(VecLoad32LE(input + 7*16), r1_3);
    }

    VecStore32LE(output + 4*16, r1_0);
    VecStore32LE(output + 5*16, r1_1);
    VecStore32LE(output + 6*16, r1_2);
    VecStore32LE(output + 7*16, r1_3);

    if (input)
    {
        r2_0 = VecXor(VecLoad32LE(input +  8*16), r2_0);
        r2_1 = VecXor(VecLoad32LE(input +  9*16), r2_1);
        r2_2 = VecXor(VecLoad32LE(input + 10*16), r2_2);
        r2_3 = VecXor(VecLoad32LE(input + 11*16), r2_3);
    }

    VecStore32LE(output +  8*16, r2_0);
    VecStore32LE(output +  9*16, r2_1);
    VecStore32LE(output + 10*16, r2_2);
    VecStore32LE(output + 11*16, r2_3);

    if (input)
    {
        r3_0 = VecXor(VecLoad32LE(input + 12*16), r3_0);
        r3_1 = VecXor(VecLoad32LE(input + 13*16), r3_1);
        r3_2 = VecXor(VecLoad32LE(input + 14*16), r3_2);
        r3_3 = VecXor(VecLoad32LE(input + 15*16), r3_3);
    }

    VecStore32LE(output + 12*16, r3_0);
    VecStore32LE(output + 13*16, r3_1);
    VecStore32LE(output + 14*16, r3_2);
    VecStore32LE(output + 15*16, r3_3);
}

#endif  // CRYPTOPP_POWER7_AVAILABLE || CRYPTOPP_ALTIVEC_AVAILABLE

#if (CRYPTOPP_POWER7_AVAILABLE)

void ChaCha_OperateKeystream_POWER7(const word32 *state, const byte* input, byte *output, unsigned int rounds)
{
    ChaCha_OperateKeystream_CORE(state, input, output, rounds);
}

#elif (CRYPTOPP_ALTIVEC_AVAILABLE)

void ChaCha_OperateKeystream_ALTIVEC(const word32 *state, const byte* input, byte *output, unsigned int rounds)
{
    ChaCha_OperateKeystream_CORE(state, input, output, rounds);
}

#endif

NAMESPACE_END
