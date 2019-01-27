// arm_simd.h - written and placed in public domain by Jeffrey Walton

/// \file arm_simd.h
/// \brief Support functions for ARM and vector operations

#ifndef CRYPTOPP_ARM_SIMD_H
#define CRYPTOPP_ARM_SIMD_H

#include "config.h"

// C1189: error: This header is specific to ARM targets
#if (CRYPTOPP_ARM_NEON_AVAILABLE) && !defined(_M_ARM64)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_ARM_ACLE_AVAILABLE)
# include <stdint.h>
# include <arm_acle.h>
#endif

#if (CRYPTOPP_ARM_PMULL_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)

/// \brief Polynomial multiplication
/// \param a the first term
/// \param b the second term
/// \returns vector product
/// \details PMULL_00() performs polynomial multiplication and presents
///  the result like Intel's <tt>c = _mm_clmulepi64_si128(a, b, 0x00)</tt>.
///  The <tt>0x00</tt> indicates the low 64-bits of <tt>a</tt> and <tt>b</tt>
///  are multiplied.
/// \note An Intel XMM register is composed of 128-bits. The leftmost bit
///  is MSB and numbered 127, while the the rightmost bit is LSB and
///  numbered 0.
/// \since Crypto++ 8.0
inline uint64x2_t PMULL_00(const uint64x2_t a, const uint64x2_t b)
{
#if defined(_MSC_VER)
    const __n64 x = { vgetq_lane_u64(a, 0) };
    const __n64 y = { vgetq_lane_u64(b, 0) };
    return vmull_p64(x, y);
#elif defined(__GNUC__)
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
        :"=w" (r) : "w" (a), "w" (b) );
    return r;
#else
    return (uint64x2_t)(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a),0),
        vgetq_lane_u64(vreinterpretq_u64_u8(b),0)));
#endif
}

/// \brief Polynomial multiplication
/// \param a the first term
/// \param b the second term
/// \returns vector product
/// \details PMULL_01 performs() polynomial multiplication and presents
///  the result like Intel's <tt>c = _mm_clmulepi64_si128(a, b, 0x01)</tt>.
///  The <tt>0x01</tt> indicates the low 64-bits of <tt>a</tt> and high
///  64-bits of <tt>b</tt> are multiplied.
/// \note An Intel XMM register is composed of 128-bits. The leftmost bit
///  is MSB and numbered 127, while the the rightmost bit is LSB and
///  numbered 0.
/// \since Crypto++ 8.0
inline uint64x2_t PMULL_01(const uint64x2_t a, const uint64x2_t b)
{
#if defined(_MSC_VER)
    const __n64 x = { vgetq_lane_u64(a, 0) };
    const __n64 y = { vgetq_lane_u64(b, 1) };
    return vmull_p64(x, y);
#elif defined(__GNUC__)
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
        :"=w" (r) : "w" (a), "w" (vget_high_u64(b)) );
    return r;
#else
    return (uint64x2_t)(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a),0),
        vgetq_lane_u64(vreinterpretq_u64_u8(b),1)));
#endif
}

/// \brief Polynomial multiplication
/// \param a the first term
/// \param b the second term
/// \returns vector product
/// \details PMULL_10() performs polynomial multiplication and presents
///  the result like Intel's <tt>c = _mm_clmulepi64_si128(a, b, 0x10)</tt>.
///  The <tt>0x10</tt> indicates the high 64-bits of <tt>a</tt> and low
///  64-bits of <tt>b</tt> are multiplied.
/// \note An Intel XMM register is composed of 128-bits. The leftmost bit
///  is MSB and numbered 127, while the the rightmost bit is LSB and
///  numbered 0.
/// \since Crypto++ 8.0
inline uint64x2_t PMULL_10(const uint64x2_t a, const uint64x2_t b)
{
#if defined(_MSC_VER)
    const __n64 x = { vgetq_lane_u64(a, 1) };
    const __n64 y = { vgetq_lane_u64(b, 0) };
    return vmull_p64(x, y);
#elif defined(__GNUC__)
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
        :"=w" (r) : "w" (vget_high_u64(a)), "w" (b) );
    return r;
#else
    return (uint64x2_t)(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a),1),
        vgetq_lane_u64(vreinterpretq_u64_u8(b),0)));
#endif
}

/// \brief Polynomial multiplication
/// \param a the first term
/// \param b the second term
/// \returns vector product
/// \details PMULL_11() performs polynomial multiplication and presents
///  the result like Intel's <tt>c = _mm_clmulepi64_si128(a, b, 0x11)</tt>.
///  The <tt>0x11</tt> indicates the high 64-bits of <tt>a</tt> and <tt>b</tt>
///  are multiplied.
/// \note An Intel XMM register is composed of 128-bits. The leftmost bit
///  is MSB and numbered 127, while the the rightmost bit is LSB and
///  numbered 0.
/// \since Crypto++ 8.0
inline uint64x2_t PMULL_11(const uint64x2_t a, const uint64x2_t b)
{
#if defined(_MSC_VER)
    const __n64 x = { vgetq_lane_u64(a, 1) };
    const __n64 y = { vgetq_lane_u64(b, 1) };
    return vmull_p64(x, y);
#elif defined(__GNUC__)
    uint64x2_t r;
    __asm __volatile("pmull2   %0.1q, %1.2d, %2.2d \n\t"
        :"=w" (r) : "w" (a), "w" (b) );
    return r;
#else
    return (uint64x2_t)(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a),1),
        vgetq_lane_u64(vreinterpretq_u64_u8(b),1)));
#endif
}

/// \brief Vector extraction
/// \param a the first term
/// \param b the second term
/// \param c the byte count
/// \returns vector
/// \details VEXT_U8() extracts the first <tt>c</tt> bytes of vector
///  <tt>a</tt> and the remaining bytes in <tt>b</tt>.
/// \since Crypto++ 8.0
inline uint64x2_t VEXT_U8(uint64x2_t a, uint64x2_t b, unsigned int c)
{
#if defined(_MSC_VER)
    return (uint64x2_t)vextq_u8(
        vreinterpretq_u8_u64(a), vreinterpretq_u8_u64(b), c);
#else
    uint64x2_t r;
    __asm __volatile("ext   %0.16b, %1.16b, %2.16b, %3 \n\t"
        :"=w" (r) : "w" (a), "w" (b), "I" (c) );
    return r;
#endif
}

/// \brief Vector extraction
/// \tparam C the byte count
/// \param a the first term
/// \param b the second term
/// \returns vector
/// \details VEXT_U8() extracts the first <tt>C</tt> bytes of vector
///  <tt>a</tt> and the remaining bytes in <tt>b</tt>.
/// \since Crypto++ 8.0
template <unsigned int C>
inline uint64x2_t VEXT_U8(uint64x2_t a, uint64x2_t b)
{
    // https://github.com/weidai11/cryptopp/issues/366
#if defined(_MSC_VER)
    return (uint64x2_t)vextq_u8(
        vreinterpretq_u8_u64(a), vreinterpretq_u8_u64(b), C);
#else
    uint64x2_t r;
    __asm __volatile("ext   %0.16b, %1.16b, %2.16b, %3 \n\t"
        :"=w" (r) : "w" (a), "w" (b), "I" (C) );
    return r;
#endif
}

#endif // CRYPTOPP_ARM_PMULL_AVAILABLE

#endif // CRYPTOPP_ARM_SIMD_H
