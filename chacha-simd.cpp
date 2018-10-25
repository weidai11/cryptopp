// chacha-simd.cpp - written and placed in the public domain by
//                   Jack Lloyd and Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    SSE2, ARM NEON and ARMv8a, and Power7 Altivec instructions. A separate
//    source file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.
//
//    SSE2 implementation based on Botan's chacha_sse2.cpp. Many thanks
//    to Jack Lloyd and the Botan team for allowing us to use it.
//
//    NEON and Power7 is upcoming.

#include "pch.h"
#include "config.h"

#include "chacha.h"
#include "misc.h"

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)
# include <xmmintrin.h>
# include <emmintrin.h>
#endif

#if (CRYPTOPP_SSSE3_INTRIN_AVAILABLE || CRYPTOPP_SSSE3_ASM_AVAILABLE)
# include <tmmintrin.h>
#endif

#ifdef __XOP__
# include <ammintrin.h>
#endif

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
# include <arm_neon.h>
#endif

// Can't use CRYPTOPP_ARM_XXX_AVAILABLE because too many
// compilers don't follow ACLE conventions for the include.
#if (CRYPTOPP_ARM_ACLE_AVAILABLE)
# include <stdint.h>
# include <arm_acle.h>
#endif

// Squash MS LNK4221 and libtool warnings
extern const char CHACHA_SIMD_FNAME[] = __FILE__;

ANONYMOUS_NAMESPACE_BEGIN

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

template <unsigned int R>
inline uint32x4_t RotateLeft(const uint32x4_t& val)
{
    const uint32x4_t a(vshlq_n_u32(val, R));
    const uint32x4_t b(vshrq_n_u32(val, 32 - R));
    return vorrq_u32(a, b);
}

template <unsigned int R>
inline uint32x4_t RotateRight(const uint32x4_t& val)
{
    const uint32x4_t a(vshlq_n_u32(val, 32 - R));
    const uint32x4_t b(vshrq_n_u32(val, R));
    return vorrq_u32(a, b);
}

#if defined(__aarch32__) || defined(__aarch64__)
template <>
inline uint32x4_t RotateLeft<8>(const uint32x4_t& val)
{
    const uint8_t maskb[16] = { 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 };
    const uint8x16_t mask = vld1q_u8(maskb);

    return vreinterpretq_u32_u8(
        vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
}

template <>
inline uint32x4_t RotateLeft<16>(const uint32x4_t& val)
{
    return vreinterpretq_u32_u16(
        vrev32q_u16(vreinterpretq_u16_u32(val)));
}

template <>
inline uint32x4_t RotateRight<16>(const uint32x4_t& val)
{
    return vreinterpretq_u32_u16(
        vrev32q_u16(vreinterpretq_u16_u32(val)));
}

template <>
inline uint32x4_t RotateRight<8>(const uint32x4_t& val)
{
    const uint8_t maskb[16] = { 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12 };
    const uint8x16_t mask = vld1q_u8(maskb);

    return vreinterpretq_u32_u8(
        vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
}
#endif  // Aarch32 or Aarch64

// ChaCha's use of shuffle is really a 4, 8, or 12 byte rotation:
//   * [3,2,1,0] => [0,3,2,1] is Shuffle<1>(x)
//   * [3,2,1,0] => [1,0,3,2] is Shuffle<2>(x)
//   * [3,2,1,0] => [2,1,0,3] is Shuffle<3>(x)
template <unsigned int S>
inline uint32x4_t Shuffle(const uint32x4_t& val)
{
    return vextq_u32(val, val, S);
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)

template <unsigned int R>
inline __m128i RotateLeft(const __m128i val)
{
#ifdef __XOP__
    return _mm_roti_epi32(val, R);
#else
    return _mm_or_si128(_mm_slli_epi32(val, R), _mm_srli_epi32(val, 32-R));
#endif
}

#if defined(__SSSE3__)
template <>
inline __m128i RotateLeft<8>(const __m128i val)
{
#ifdef __XOP__
    return _mm_roti_epi32(val, 8);
#else
    const __m128i mask = _mm_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
    return _mm_shuffle_epi8(val, mask);
#endif
}

template <>
inline __m128i RotateLeft<16>(const __m128i val)
{
#ifdef __XOP__
    return _mm_roti_epi32(val, 16);
#else
    const __m128i mask = _mm_set_epi8(13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2);
    return _mm_shuffle_epi8(val, mask);
#endif
}
#endif  // SSE3

#endif  // CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

void ChaCha_OperateKeystream_NEON(const word32 *state, const byte* input, byte *output, unsigned int rounds, bool xorInput)
{
    const uint32x4_t state0 = vld1q_u32(state + 0*4);
    const uint32x4_t state1 = vld1q_u32(state + 1*4);
    const uint32x4_t state2 = vld1q_u32(state + 2*4);
    const uint32x4_t state3 = vld1q_u32(state + 3*4);

    const uint64x2_t CTRS[3] = {
        {1, 0}, {2, 0}, {3, 0}
    };

    uint32x4_t r0_0 = state0;
    uint32x4_t r0_1 = state1;
    uint32x4_t r0_2 = state2;
    uint32x4_t r0_3 = state3;

    uint32x4_t r1_0 = state0;
    uint32x4_t r1_1 = state1;
    uint32x4_t r1_2 = state2;
    uint32x4_t r1_3 = vreinterpretq_u32_u64(vaddq_u64(
                        vreinterpretq_u64_u32(r0_3), CTRS[0]));

    uint32x4_t r2_0 = state0;
    uint32x4_t r2_1 = state1;
    uint32x4_t r2_2 = state2;
    uint32x4_t r2_3 = vreinterpretq_u32_u64(vaddq_u64(
                        vreinterpretq_u64_u32(r0_3), CTRS[1]));

    uint32x4_t r3_0 = state0;
    uint32x4_t r3_1 = state1;
    uint32x4_t r3_2 = state2;
    uint32x4_t r3_3 = vreinterpretq_u32_u64(vaddq_u64(
                        vreinterpretq_u64_u32(r0_3), CTRS[2]));

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

    r0_0 = vaddq_u32(r0_0, state0);
    r0_1 = vaddq_u32(r0_1, state1);
    r0_2 = vaddq_u32(r0_2, state2);
    r0_3 = vaddq_u32(r0_3, state3);

    r1_0 = vaddq_u32(r1_0, state0);
    r1_1 = vaddq_u32(r1_1, state1);
    r1_2 = vaddq_u32(r1_2, state2);
    r1_3 = vaddq_u32(r1_3, state3);
    r1_3 = vreinterpretq_u32_u64(vaddq_u64(
             vreinterpretq_u64_u32(r1_3), CTRS[0]));

    r2_0 = vaddq_u32(r2_0, state0);
    r2_1 = vaddq_u32(r2_1, state1);
    r2_2 = vaddq_u32(r2_2, state2);
    r2_3 = vaddq_u32(r2_3, state3);
    r2_3 = vreinterpretq_u32_u64(vaddq_u64(
             vreinterpretq_u64_u32(r2_3), CTRS[1]));

    r3_0 = vaddq_u32(r3_0, state0);
    r3_1 = vaddq_u32(r3_1, state1);
    r3_2 = vaddq_u32(r3_2, state2);
    r3_3 = vaddq_u32(r3_3, state3);
    r3_3 = vreinterpretq_u32_u64(vaddq_u64(
             vreinterpretq_u64_u32(r3_3), CTRS[2]));

    if (xorInput)
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

    if (xorInput)
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

    if (xorInput)
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

    if (xorInput)
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

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)

void ChaCha_OperateKeystream_SSE2(const word32 *state, const byte* input, byte *output, unsigned int rounds, bool xorInput)
{
    const __m128i* state_mm = reinterpret_cast<const __m128i*>(state);
    const __m128i* input_mm = reinterpret_cast<const __m128i*>(input);
    __m128i* output_mm = reinterpret_cast<__m128i*>(output);

    const __m128i state0 = _mm_load_si128(state_mm + 0);
    const __m128i state1 = _mm_load_si128(state_mm + 1);
    const __m128i state2 = _mm_load_si128(state_mm + 2);
    const __m128i state3 = _mm_load_si128(state_mm + 3);

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

    if (xorInput)
    {
        r0_0 = _mm_xor_si128(_mm_loadu_si128(input_mm + 0), r0_0);
        r0_1 = _mm_xor_si128(_mm_loadu_si128(input_mm + 1), r0_1);
        r0_2 = _mm_xor_si128(_mm_loadu_si128(input_mm + 2), r0_2);
        r0_3 = _mm_xor_si128(_mm_loadu_si128(input_mm + 3), r0_3);
    }

    _mm_storeu_si128(output_mm + 0, r0_0);
    _mm_storeu_si128(output_mm + 1, r0_1);
    _mm_storeu_si128(output_mm + 2, r0_2);
    _mm_storeu_si128(output_mm + 3, r0_3);

    if (xorInput)
    {
        r1_0 = _mm_xor_si128(_mm_loadu_si128(input_mm + 4), r1_0);
        r1_1 = _mm_xor_si128(_mm_loadu_si128(input_mm + 5), r1_1);
        r1_2 = _mm_xor_si128(_mm_loadu_si128(input_mm + 6), r1_2);
        r1_3 = _mm_xor_si128(_mm_loadu_si128(input_mm + 7), r1_3);
    }

    _mm_storeu_si128(output_mm + 4, r1_0);
    _mm_storeu_si128(output_mm + 5, r1_1);
    _mm_storeu_si128(output_mm + 6, r1_2);
    _mm_storeu_si128(output_mm + 7, r1_3);

    if (xorInput)
    {
        r2_0 = _mm_xor_si128(_mm_loadu_si128(input_mm + 8), r2_0);
        r2_1 = _mm_xor_si128(_mm_loadu_si128(input_mm + 9), r2_1);
        r2_2 = _mm_xor_si128(_mm_loadu_si128(input_mm + 10), r2_2);
        r2_3 = _mm_xor_si128(_mm_loadu_si128(input_mm + 11), r2_3);
    }

    _mm_storeu_si128(output_mm + 8, r2_0);
    _mm_storeu_si128(output_mm + 9, r2_1);
    _mm_storeu_si128(output_mm + 10, r2_2);
    _mm_storeu_si128(output_mm + 11, r2_3);

    if (xorInput)
    {
        r3_0 = _mm_xor_si128(_mm_loadu_si128(input_mm + 12), r3_0);
        r3_1 = _mm_xor_si128(_mm_loadu_si128(input_mm + 13), r3_1);
        r3_2 = _mm_xor_si128(_mm_loadu_si128(input_mm + 14), r3_2);
        r3_3 = _mm_xor_si128(_mm_loadu_si128(input_mm + 15), r3_3);
    }

    _mm_storeu_si128(output_mm + 12, r3_0);
    _mm_storeu_si128(output_mm + 13, r3_1);
    _mm_storeu_si128(output_mm + 14, r3_2);
    _mm_storeu_si128(output_mm + 15, r3_3);
}

#endif  // CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE

NAMESPACE_END
