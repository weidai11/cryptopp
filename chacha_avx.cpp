// chacha_avx.cpp - written and placed in the public domain by
//                  Jack Lloyd and Jeffrey Walton
//
//    This source file uses intrinsics and built-ins to gain access to
//    AVX2 instructions. A separate source file is needed because
//    additional CXXFLAGS are required to enable the appropriate
//    instructions sets in some build configurations.
//
//    AVX2 implementation based on Botan's chacha_avx.cpp. Many thanks
//    to Jack Lloyd and the Botan team for allowing us to use it.
//
//    Here are some relative numbers for ChaCha8:
//    * Intel Skylake,   3.0 GHz: AVX2 at 4411 MB/s; 0.57 cpb.
//    * Intel Broadwell, 2.3 GHz: AVX2 at 3828 MB/s; 0.58 cpb.
//    * AMD Bulldozer,   3.3 GHz: AVX2 at 1680 MB/s; 1.47 cpb.

#include "pch.h"
#include "config.h"

#include "chacha.h"
#include "misc.h"

#if defined(CRYPTOPP_AVX2_AVAILABLE)
# include <xmmintrin.h>
# include <emmintrin.h>
# include <immintrin.h>
#endif

// Squash MS LNK4221 and libtool warnings
extern const char CHACHA_AVX_FNAME[] = __FILE__;

// Sun Studio 12.4 OK, 12.5 and 12.6 compile error.
#if (__SUNPRO_CC >= 0x5140) && (__SUNPRO_CC <= 0x5150)
# define MAYBE_CONST
#else
# define MAYBE_CONST const
#endif

// VS2017 and global optimization bug. TODO, figure out when
// we can re-enable full optimizations for VS2017. Also see
// https://github.com/weidai11/cryptopp/issues/649 and
// https://github.com/weidai11/cryptopp/issues/735. The
// 649 issue affects AES but it is the same here. The 735
// issue is ChaCha AVX2 cut-in where it surfaced again.
#if (_MSC_VER >= 1910)
# ifndef CRYPTOPP_DEBUG
#  pragma optimize("", off)
#  pragma optimize("ts", on)
# endif
#endif

// The data is aligned, but Clang issues warning based on type
// and not the actual alignment of the variable and data.
#if CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE
# pragma GCC diagnostic ignored "-Wcast-align"
#endif

ANONYMOUS_NAMESPACE_BEGIN

#if (CRYPTOPP_AVX2_AVAILABLE)

template <unsigned int R>
inline __m256i RotateLeft(const __m256i val)
{
    return _mm256_or_si256(_mm256_slli_epi32(val, R), _mm256_srli_epi32(val, 32-R));
}

template <>
inline __m256i RotateLeft<8>(const __m256i val)
{
    const __m256i mask = _mm256_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3,
                                         14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
    return _mm256_shuffle_epi8(val, mask);
}

template <>
inline __m256i RotateLeft<16>(const __m256i val)
{
    const __m256i mask = _mm256_set_epi8(13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2,
                                         13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2);
    return _mm256_shuffle_epi8(val, mask);
}

#endif  // CRYPTOPP_AVX2_AVAILABLE

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_AVX2_AVAILABLE)

void ChaCha_OperateKeystream_AVX2(const word32 *state, const byte* input, byte *output, unsigned int rounds)
{
    const __m256i state0 = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(state+0*4)));
    const __m256i state1 = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(state+1*4)));
    const __m256i state2 = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(state+2*4)));
    const __m256i state3 = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(state+3*4)));

    const __m256i CTR0 = _mm256_set_epi32(0, 0, 0, 0, 0, 0, 0, 4);
    const __m256i CTR1 = _mm256_set_epi32(0, 0, 0, 1, 0, 0, 0, 5);
    const __m256i CTR2 = _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 6);
    const __m256i CTR3 = _mm256_set_epi32(0, 0, 0, 3, 0, 0, 0, 7);

    __m256i X0_0 = state0;
    __m256i X0_1 = state1;
    __m256i X0_2 = state2;
    __m256i X0_3 = _mm256_add_epi64(state3, CTR0);

    __m256i X1_0 = state0;
    __m256i X1_1 = state1;
    __m256i X1_2 = state2;
    __m256i X1_3 = _mm256_add_epi64(state3, CTR1);

    __m256i X2_0 = state0;
    __m256i X2_1 = state1;
    __m256i X2_2 = state2;
    __m256i X2_3 = _mm256_add_epi64(state3, CTR2);

    __m256i X3_0 = state0;
    __m256i X3_1 = state1;
    __m256i X3_2 = state2;
    __m256i X3_3 = _mm256_add_epi64(state3, CTR3);

    for (int i = static_cast<int>(rounds); i > 0; i -= 2)
    {
        X0_0 = _mm256_add_epi32(X0_0, X0_1);
        X1_0 = _mm256_add_epi32(X1_0, X1_1);
        X2_0 = _mm256_add_epi32(X2_0, X2_1);
        X3_0 = _mm256_add_epi32(X3_0, X3_1);

        X0_3 = _mm256_xor_si256(X0_3, X0_0);
        X1_3 = _mm256_xor_si256(X1_3, X1_0);
        X2_3 = _mm256_xor_si256(X2_3, X2_0);
        X3_3 = _mm256_xor_si256(X3_3, X3_0);

        X0_3 = RotateLeft<16>(X0_3);
        X1_3 = RotateLeft<16>(X1_3);
        X2_3 = RotateLeft<16>(X2_3);
        X3_3 = RotateLeft<16>(X3_3);

        X0_2 = _mm256_add_epi32(X0_2, X0_3);
        X1_2 = _mm256_add_epi32(X1_2, X1_3);
        X2_2 = _mm256_add_epi32(X2_2, X2_3);
        X3_2 = _mm256_add_epi32(X3_2, X3_3);

        X0_1 = _mm256_xor_si256(X0_1, X0_2);
        X1_1 = _mm256_xor_si256(X1_1, X1_2);
        X2_1 = _mm256_xor_si256(X2_1, X2_2);
        X3_1 = _mm256_xor_si256(X3_1, X3_2);

        X0_1 = RotateLeft<12>(X0_1);
        X1_1 = RotateLeft<12>(X1_1);
        X2_1 = RotateLeft<12>(X2_1);
        X3_1 = RotateLeft<12>(X3_1);

        X0_0 = _mm256_add_epi32(X0_0, X0_1);
        X1_0 = _mm256_add_epi32(X1_0, X1_1);
        X2_0 = _mm256_add_epi32(X2_0, X2_1);
        X3_0 = _mm256_add_epi32(X3_0, X3_1);

        X0_3 = _mm256_xor_si256(X0_3, X0_0);
        X1_3 = _mm256_xor_si256(X1_3, X1_0);
        X2_3 = _mm256_xor_si256(X2_3, X2_0);
        X3_3 = _mm256_xor_si256(X3_3, X3_0);

        X0_3 = RotateLeft<8>(X0_3);
        X1_3 = RotateLeft<8>(X1_3);
        X2_3 = RotateLeft<8>(X2_3);
        X3_3 = RotateLeft<8>(X3_3);

        X0_2 = _mm256_add_epi32(X0_2, X0_3);
        X1_2 = _mm256_add_epi32(X1_2, X1_3);
        X2_2 = _mm256_add_epi32(X2_2, X2_3);
        X3_2 = _mm256_add_epi32(X3_2, X3_3);

        X0_1 = _mm256_xor_si256(X0_1, X0_2);
        X1_1 = _mm256_xor_si256(X1_1, X1_2);
        X2_1 = _mm256_xor_si256(X2_1, X2_2);
        X3_1 = _mm256_xor_si256(X3_1, X3_2);

        X0_1 = RotateLeft<7>(X0_1);
        X1_1 = RotateLeft<7>(X1_1);
        X2_1 = RotateLeft<7>(X2_1);
        X3_1 = RotateLeft<7>(X3_1);

        X0_1 = _mm256_shuffle_epi32(X0_1, _MM_SHUFFLE(0, 3, 2, 1));
        X0_2 = _mm256_shuffle_epi32(X0_2, _MM_SHUFFLE(1, 0, 3, 2));
        X0_3 = _mm256_shuffle_epi32(X0_3, _MM_SHUFFLE(2, 1, 0, 3));

        X1_1 = _mm256_shuffle_epi32(X1_1, _MM_SHUFFLE(0, 3, 2, 1));
        X1_2 = _mm256_shuffle_epi32(X1_2, _MM_SHUFFLE(1, 0, 3, 2));
        X1_3 = _mm256_shuffle_epi32(X1_3, _MM_SHUFFLE(2, 1, 0, 3));

        X2_1 = _mm256_shuffle_epi32(X2_1, _MM_SHUFFLE(0, 3, 2, 1));
        X2_2 = _mm256_shuffle_epi32(X2_2, _MM_SHUFFLE(1, 0, 3, 2));
        X2_3 = _mm256_shuffle_epi32(X2_3, _MM_SHUFFLE(2, 1, 0, 3));

        X3_1 = _mm256_shuffle_epi32(X3_1, _MM_SHUFFLE(0, 3, 2, 1));
        X3_2 = _mm256_shuffle_epi32(X3_2, _MM_SHUFFLE(1, 0, 3, 2));
        X3_3 = _mm256_shuffle_epi32(X3_3, _MM_SHUFFLE(2, 1, 0, 3));

        X0_0 = _mm256_add_epi32(X0_0, X0_1);
        X1_0 = _mm256_add_epi32(X1_0, X1_1);
        X2_0 = _mm256_add_epi32(X2_0, X2_1);
        X3_0 = _mm256_add_epi32(X3_0, X3_1);

        X0_3 = _mm256_xor_si256(X0_3, X0_0);
        X1_3 = _mm256_xor_si256(X1_3, X1_0);
        X2_3 = _mm256_xor_si256(X2_3, X2_0);
        X3_3 = _mm256_xor_si256(X3_3, X3_0);

        X0_3 = RotateLeft<16>(X0_3);
        X1_3 = RotateLeft<16>(X1_3);
        X2_3 = RotateLeft<16>(X2_3);
        X3_3 = RotateLeft<16>(X3_3);

        X0_2 = _mm256_add_epi32(X0_2, X0_3);
        X1_2 = _mm256_add_epi32(X1_2, X1_3);
        X2_2 = _mm256_add_epi32(X2_2, X2_3);
        X3_2 = _mm256_add_epi32(X3_2, X3_3);

        X0_1 = _mm256_xor_si256(X0_1, X0_2);
        X1_1 = _mm256_xor_si256(X1_1, X1_2);
        X2_1 = _mm256_xor_si256(X2_1, X2_2);
        X3_1 = _mm256_xor_si256(X3_1, X3_2);

        X0_1 = RotateLeft<12>(X0_1);
        X1_1 = RotateLeft<12>(X1_1);
        X2_1 = RotateLeft<12>(X2_1);
        X3_1 = RotateLeft<12>(X3_1);

        X0_0 = _mm256_add_epi32(X0_0, X0_1);
        X1_0 = _mm256_add_epi32(X1_0, X1_1);
        X2_0 = _mm256_add_epi32(X2_0, X2_1);
        X3_0 = _mm256_add_epi32(X3_0, X3_1);

        X0_3 = _mm256_xor_si256(X0_3, X0_0);
        X1_3 = _mm256_xor_si256(X1_3, X1_0);
        X2_3 = _mm256_xor_si256(X2_3, X2_0);
        X3_3 = _mm256_xor_si256(X3_3, X3_0);

        X0_3 = RotateLeft<8>(X0_3);
        X1_3 = RotateLeft<8>(X1_3);
        X2_3 = RotateLeft<8>(X2_3);
        X3_3 = RotateLeft<8>(X3_3);

        X0_2 = _mm256_add_epi32(X0_2, X0_3);
        X1_2 = _mm256_add_epi32(X1_2, X1_3);
        X2_2 = _mm256_add_epi32(X2_2, X2_3);
        X3_2 = _mm256_add_epi32(X3_2, X3_3);

        X0_1 = _mm256_xor_si256(X0_1, X0_2);
        X1_1 = _mm256_xor_si256(X1_1, X1_2);
        X2_1 = _mm256_xor_si256(X2_1, X2_2);
        X3_1 = _mm256_xor_si256(X3_1, X3_2);

        X0_1 = RotateLeft<7>(X0_1);
        X1_1 = RotateLeft<7>(X1_1);
        X2_1 = RotateLeft<7>(X2_1);
        X3_1 = RotateLeft<7>(X3_1);

        X0_1 = _mm256_shuffle_epi32(X0_1, _MM_SHUFFLE(2, 1, 0, 3));
        X0_2 = _mm256_shuffle_epi32(X0_2, _MM_SHUFFLE(1, 0, 3, 2));
        X0_3 = _mm256_shuffle_epi32(X0_3, _MM_SHUFFLE(0, 3, 2, 1));

        X1_1 = _mm256_shuffle_epi32(X1_1, _MM_SHUFFLE(2, 1, 0, 3));
        X1_2 = _mm256_shuffle_epi32(X1_2, _MM_SHUFFLE(1, 0, 3, 2));
        X1_3 = _mm256_shuffle_epi32(X1_3, _MM_SHUFFLE(0, 3, 2, 1));

        X2_1 = _mm256_shuffle_epi32(X2_1, _MM_SHUFFLE(2, 1, 0, 3));
        X2_2 = _mm256_shuffle_epi32(X2_2, _MM_SHUFFLE(1, 0, 3, 2));
        X2_3 = _mm256_shuffle_epi32(X2_3, _MM_SHUFFLE(0, 3, 2, 1));

        X3_1 = _mm256_shuffle_epi32(X3_1, _MM_SHUFFLE(2, 1, 0, 3));
        X3_2 = _mm256_shuffle_epi32(X3_2, _MM_SHUFFLE(1, 0, 3, 2));
        X3_3 = _mm256_shuffle_epi32(X3_3, _MM_SHUFFLE(0, 3, 2, 1));
    }

    X0_0 = _mm256_add_epi32(X0_0, state0);
    X0_1 = _mm256_add_epi32(X0_1, state1);
    X0_2 = _mm256_add_epi32(X0_2, state2);
    X0_3 = _mm256_add_epi32(X0_3, state3);
    X0_3 = _mm256_add_epi64(X0_3, CTR0);

    X1_0 = _mm256_add_epi32(X1_0, state0);
    X1_1 = _mm256_add_epi32(X1_1, state1);
    X1_2 = _mm256_add_epi32(X1_2, state2);
    X1_3 = _mm256_add_epi32(X1_3, state3);
    X1_3 = _mm256_add_epi64(X1_3, CTR1);

    X2_0 = _mm256_add_epi32(X2_0, state0);
    X2_1 = _mm256_add_epi32(X2_1, state1);
    X2_2 = _mm256_add_epi32(X2_2, state2);
    X2_3 = _mm256_add_epi32(X2_3, state3);
    X2_3 = _mm256_add_epi64(X2_3, CTR2);

    X3_0 = _mm256_add_epi32(X3_0, state0);
    X3_1 = _mm256_add_epi32(X3_1, state1);
    X3_2 = _mm256_add_epi32(X3_2, state2);
    X3_3 = _mm256_add_epi32(X3_3, state3);
    X3_3 = _mm256_add_epi64(X3_3, CTR3);

    if (input)
    {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+0*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X0_0, X0_1, 1 + (3 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+0*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+1*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X0_2, X0_3, 1 + (3 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+1*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+2*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X1_0, X1_1, 1 + (3 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+2*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+3*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X1_2, X1_3, 1 + (3 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+3*32))));
    }
    else
    {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+0*32),
            _mm256_permute2x128_si256(X0_0, X0_1, 1 + (3 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+1*32),
            _mm256_permute2x128_si256(X0_2, X0_3, 1 + (3 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+2*32),
            _mm256_permute2x128_si256(X1_0, X1_1, 1 + (3 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+3*32),
            _mm256_permute2x128_si256(X1_2, X1_3, 1 + (3 << 4)));
    }

    if (input)
    {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+4*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X2_0, X2_1, 1 + (3 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+4*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+5*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X2_2, X2_3, 1 + (3 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+5*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+6*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X3_0, X3_1, 1 + (3 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+6*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+7*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X3_2, X3_3, 1 + (3 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+7*32))));
    }
    else
    {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+4*32),
            _mm256_permute2x128_si256(X2_0, X2_1, 1 + (3 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+5*32),
            _mm256_permute2x128_si256(X2_2, X2_3, 1 + (3 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+6*32),
            _mm256_permute2x128_si256(X3_0, X3_1, 1 + (3 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+7*32),
            _mm256_permute2x128_si256(X3_2, X3_3, 1 + (3 << 4)));
    }

    if (input)
    {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+ 8*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X0_0, X0_1, 0 + (2 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+8*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+ 9*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X0_2, X0_3, 0 + (2 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+9*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+10*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X1_0, X1_1, 0 + (2 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+10*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+11*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X1_2, X1_3, 0 + (2 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+11*32))));
    }
    else
    {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+ 8*32),
            _mm256_permute2x128_si256(X0_0, X0_1, 0 + (2 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+ 9*32),
            _mm256_permute2x128_si256(X0_2, X0_3, 0 + (2 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+10*32),
            _mm256_permute2x128_si256(X1_0, X1_1, 0 + (2 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+11*32),
            _mm256_permute2x128_si256(X1_2, X1_3, 0 + (2 << 4)));
    }

    if (input)
    {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+12*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X2_0, X2_1, 0 + (2 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+12*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+13*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X2_2, X2_3, 0 + (2 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+13*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+14*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X3_0, X3_1, 0 + (2 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+14*32))));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+15*32),
            _mm256_xor_si256(_mm256_permute2x128_si256(X3_2, X3_3, 0 + (2 << 4)),
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input+15*32))));
    }
    else
    {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+12*32),
            _mm256_permute2x128_si256(X2_0, X2_1, 0 + (2 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+13*32),
            _mm256_permute2x128_si256(X2_2, X2_3, 0 + (2 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+14*32),
            _mm256_permute2x128_si256(X3_0, X3_1, 0 + (2 << 4)));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+15*32),
            _mm256_permute2x128_si256(X3_2, X3_3, 0 + (2 << 4)));
    }

    // https://software.intel.com/en-us/articles/avoiding-avx-sse-transition-penalties
    _mm256_zeroupper();
}

#endif  // CRYPTOPP_AVX2_AVAILABLE

NAMESPACE_END
