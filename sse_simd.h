// sse_simd.h - written and placed in public domain by Jeffrey Walton
//              Helper functions to work with SSE and above. The class file
//              was added after a scan by lgtm.com. We caught some findings
//              that were not problems, but we refactored to squash them.

#ifndef CRYPTOPP_SSE_CRYPTO_H
#define CRYPTOPP_SSE_CRYPTO_H

#include "config.h"

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
# include <emmintrin.h>
#endif

#if (CRYPTOPP_AVX2_AVAILABLE)
# include <immintrin.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)

template <unsigned int N>
inline __m128i load_m128i(const byte* ptr)
{
    enum { SCALE=sizeof(__m128i)/sizeof(byte) };
    return _mm_loadu_si128(
        const_cast<__m128i*>(  // SunCC workaround
        reinterpret_cast<const __m128i*>(ptr+SCALE*N)));
}

template <unsigned int N>
inline __m128i load_m128i(const word16* ptr)
{
    enum { SCALE=sizeof(__m128i)/sizeof(word16) };
    return _mm_loadu_si128(
        const_cast<__m128i*>(  // SunCC workaround
        reinterpret_cast<const __m128i*>(ptr+SCALE*N)));
}

template <unsigned int N>
inline __m128i load_m128i(const word32* ptr)
{
    enum { SCALE=sizeof(__m128i)/sizeof(word32) };
    return _mm_loadu_si128(
        const_cast<__m128i*>(  // SunCC workaround
        reinterpret_cast<const __m128i*>(ptr+SCALE*N)));
}

template <unsigned int N>
inline __m128i load_m128i(const word64* ptr)
{
    enum { SCALE=sizeof(__m128i)/sizeof(word64) };
    return _mm_loadu_si128(
        const_cast<__m128i*>(  // SunCC workaround
        reinterpret_cast<const __m128i*>(ptr+SCALE*N)));
}

// N specifies the nth 128-bit element
template <unsigned int N, class T>
inline void store_m128i(T* ptr, __m128i val)
{
    enum { SCALE=sizeof(__m128i)/sizeof(T) };
    return _mm_storeu_si128(
        reinterpret_cast<__m128i*>(ptr+SCALE*N), val);
}

#endif

#if (CRYPTOPP_AVX2_AVAILABLE)

template <unsigned int N>
inline __m256i load_m256i(const byte* ptr)
{
    enum { SCALE=sizeof(__m256i)/sizeof(byte) };
    return _mm256_loadu_si256(
        const_cast<__m256i*>(  // SunCC workaround
        reinterpret_cast<const __m256i*>(ptr+SCALE*N)));
}

template <unsigned int N>
inline __m256i load_m256i(const word16* ptr)
{
    enum { SCALE=sizeof(__m256i)/sizeof(word16) };
    return _mm256_loadu_si256(
        const_cast<__m256i*>(  // SunCC workaround
        reinterpret_cast<const __m256i*>(ptr+SCALE*N)));
}

template <unsigned int N>
inline __m256i load_m256i(const word32* ptr)
{
    enum { SCALE=sizeof(__m256i)/sizeof(word32) };
    return _mm256_loadu_si256(
        const_cast<__m256i*>(  // SunCC workaround
        reinterpret_cast<const __m256i*>(ptr+SCALE*N)));
}

template <unsigned int N>
inline __m256i load_m256i(const word64* ptr)
{
    enum { SCALE=sizeof(__m256i)/sizeof(word64) };
    return _mm256_loadu_si256(
        const_cast<__m256i*>(  // SunCC workaround
        reinterpret_cast<const __m256i*>(ptr+SCALE*N)));
}

// N specifies the nth 256-bit element
template <unsigned int N, class T>
inline void store_m256i(T* ptr, __m256i val)
{
    enum { SCALE=sizeof(__m256i)/sizeof(T) };
    return _mm256_storeu_si256(
        reinterpret_cast<__m256i*>(ptr+SCALE*N), val);
}

#endif

NAMESPACE_END

#endif  // CRYPTOPP_SSE_CRYPTO_H
