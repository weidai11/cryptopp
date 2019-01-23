// scrypt.cpp - written and placed in public domain by Jeffrey Walton.
//              Based on reference source code by Colin Percival for
//              Scrypt and Daniel Bernstein for Salsa20 core.

#include "pch.h"

#include "scrypt.h"
#include "algparam.h"
#include "argnames.h"
#include "pwdbased.h"
#include "stdcpp.h"
#include "salsa.h"
#include "misc.h"
#include "sha.h"

#include <sstream>
#include <limits>

#ifdef _OPENMP
# include <omp.h>
#endif

// https://github.com/weidai11/cryptopp/issues/777
#if CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE
# if defined(__clang__)
#  pragma GCC diagnostic ignored "-Wtautological-compare"
# elif defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wtype-limits"
# endif
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::GetWord;
using CryptoPP::PutWord;
using CryptoPP::Salsa20_Core;
using CryptoPP::rotlConstant;
using CryptoPP::LITTLE_ENDIAN_ORDER;
using CryptoPP::AlignedSecByteBlock;

inline void LE32ENC(byte* out, word32 in)
{
    PutWord(false, LITTLE_ENDIAN_ORDER, out, in);
}

inline word32 LE32DEC(const byte* in)
{
    return GetWord<word32>(false, LITTLE_ENDIAN_ORDER, in);
}

inline word64 LE64DEC(const byte* in)
{
    return GetWord<word64>(false, LITTLE_ENDIAN_ORDER, in);
}

inline void BlockCopy(byte* dest, byte* src, size_t len)
{
// OpenMP 4.0 released July 2013.
#if _OPENMP >= 201307
    #pragma omp simd
    for (size_t i = 0; i < len; ++i)
        dest[i] = src[i];
#else
    for (size_t i = 0; i < len; ++i)
        dest[i] = src[i];
#endif
}

inline void BlockXOR(byte* dest, byte* src, size_t len)
{
// OpenMP 4.0 released July 2013.
#if _OPENMP >= 201307
    #pragma omp simd
    for (size_t i = 0; i < len; ++i)
        dest[i] ^= src[i];
#else
    for (size_t i = 0; i < len; ++i)
        dest[i] ^= src[i];
#endif
}

inline void PBKDF2_SHA256(byte* buf, size_t dkLen,
    const byte* passwd, size_t passwdlen,
    const byte* salt, size_t saltlen, byte count)
{
    using CryptoPP::SHA256;
    using CryptoPP::PKCS5_PBKDF2_HMAC;

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(buf, dkLen, 0, passwd, passwdlen, salt, saltlen, count, 0.0f);
}

inline void Salsa20_8(byte B[64])
{
    word32 B32[16];

    for (size_t i = 0; i < 16; ++i)
        B32[i] = LE32DEC(&B[i * 4]);

    Salsa20_Core(B32, 8);

    for (size_t i = 0; i < 16; ++i)
        LE32ENC(&B[4 * i], B32[i]);
}

inline void BlockMix(byte* B, byte* Y, size_t r)
{
    byte X[64];

    // 1: X <-- B_{2r - 1}
    BlockCopy(X, &B[(2 * r - 1) * 64], 64);

    // 2: for i = 0 to 2r - 1 do
    for (size_t i = 0; i < 2 * r; ++i)
    {
        // 3: X <-- H(X \xor B_i)
        BlockXOR(X, &B[i * 64], 64);
        Salsa20_8(X);

        // 4: Y_i <-- X
        BlockCopy(&Y[i * 64], X, 64);
    }

    // 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1})
    for (size_t i = 0; i < r; ++i)
        BlockCopy(&B[i * 64], &Y[(i * 2) * 64], 64);

    for (size_t i = 0; i < r; ++i)
        BlockCopy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

inline word64 Integerify(byte* B, size_t r)
{
    byte* X = &B[(2 * r - 1) * 64];
    return LE64DEC(X);
}

inline void Smix(byte* B, size_t r, word64 N, byte* V, byte* XY)
{
    byte* X = XY;
    byte* Y = XY+128*r;

    // 1: X <-- B
    BlockCopy(X, B, 128 * r);

    // 2: for i = 0 to N - 1 do
    for (word64 i = 0; i < N; ++i)
    {
        // 3: V_i <-- X
        BlockCopy(&V[i * (128 * r)], X, 128 * r);

        // 4: X <-- H(X)
        BlockMix(X, Y, r);
    }

    // 6: for i = 0 to N - 1 do
    for (word64 i = 0; i < N; ++i)
    {
        // 7: j <-- Integerify(X) mod N
        word64 j = Integerify(X, r) & (N - 1);

        // 8: X <-- H(X \xor V_j)
        BlockXOR(X, &V[j * (128 * r)], 128 * r);
        BlockMix(X, Y, r);
    }

    // 10: B' <-- X
    BlockCopy(B, X, 128 * r);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

size_t Scrypt::GetValidDerivedLength(size_t keylength) const
{
    if (keylength > MaxDerivedLength())
        return MaxDerivedLength();
    return keylength;
}

void Scrypt::ValidateParameters(size_t derivedLen, word64 cost, word64 blockSize, word64 parallelization) const
{
    // Optimizer should remove this on 32-bit platforms
    if (std::numeric_limits<size_t>::max() > std::numeric_limits<word32>::max())
    {
        const word64 maxLen = ((static_cast<word64>(1) << 32) - 1) * 32;
        if (derivedLen > maxLen) {
            std::ostringstream oss;
            oss << "derivedLen " << derivedLen << " is larger than " << maxLen;
            throw InvalidArgument("Scrypt: " + oss.str());
        }
    }

    // https://github.com/weidai11/cryptopp/issues/787
    CRYPTOPP_ASSERT(parallelization <= std::numeric_limits<int>::max());
    if (parallelization > static_cast<word64>(std::numeric_limits<int>::max()))
    {
        std::ostringstream oss;
        oss << " parallelization " << parallelization << " is larger than ";
        oss << std::numeric_limits<int>::max();
        throw InvalidArgument("Scrypt: " + oss.str());
    }

    CRYPTOPP_ASSERT(IsPowerOf2(cost));
    if (IsPowerOf2(cost) == false)
        throw InvalidArgument("Scrypt: cost must be a power of 2");

    const word64 prod = static_cast<word64>(blockSize) * parallelization;
    CRYPTOPP_ASSERT(prod < (1U << 30));

    if (prod >= (1U << 30)) {
        std::ostringstream oss;
        oss << "r*p " << prod << " is larger than " << (1U << 30);
        throw InvalidArgument("Scrypt: " + oss.str());
    }

    // Scrypt has several tests that effectively verify allocations like
    // '128 * r * N' and '128 * r * p' do not overflow. They are the tests
    // that set errno to ENOMEM. We can make the logic a little more clear
    // using word128. At first blush the word128 may seem like  overkill.
    // However, this alogirthm is dominated by slow moving parts, so a
    // one-time check is insignificant in the bigger picture.
#if defined(CRYPTOPP_WORD128_AVAILABLE)
    const word128 maxElems = static_cast<word128>(SIZE_MAX);
    bool  bLimit = (maxElems >= static_cast<word128>(cost) * blockSize * 128U);
    bool xyLimit = (maxElems >= static_cast<word128>(parallelization) * blockSize * 128U);
    bool  vLimit = (maxElems >= static_cast<word128>(blockSize) * 256U + 64U);
#else
    const word64 maxElems = static_cast<word64>(SIZE_MAX);
    bool  bLimit = (blockSize < maxElems / 128U / cost);
    bool xyLimit = (blockSize < maxElems / 128U / parallelization);
    bool  vLimit = (blockSize < (maxElems - 64U) / 256U);
#endif

    CRYPTOPP_ASSERT(bLimit); CRYPTOPP_ASSERT(xyLimit); CRYPTOPP_ASSERT(vLimit);
    if (!bLimit || !xyLimit || !vLimit)
        throw std::bad_alloc();
}

size_t Scrypt::DeriveKey(byte*derived, size_t derivedLen,
    const byte*secret, size_t secretLen, const NameValuePairs& params) const
{
    CRYPTOPP_ASSERT(secret /*&& secretLen*/);
    CRYPTOPP_ASSERT(derived && derivedLen);
    CRYPTOPP_ASSERT(derivedLen <= MaxDerivedLength());

    word64 cost=0, blockSize=0, parallelization=0;
    if(params.GetValue("Cost", cost) == false)
        cost = defaultCost;

    if(params.GetValue("BlockSize", blockSize) == false)
        blockSize = defaultBlockSize;

    if(params.GetValue("Parallelization", parallelization) == false)
        parallelization = defaultParallelization;

    ConstByteArrayParameter salt;
    (void)params.GetValue("Salt", salt);

    return DeriveKey(derived, derivedLen, secret, secretLen, salt.begin(), salt.size(), cost, blockSize, parallelization);
}

size_t Scrypt::DeriveKey(byte*derived, size_t derivedLen, const byte*secret, size_t secretLen,
    const byte*salt, size_t saltLen, word64 cost, word64 blockSize, word64 parallel) const
{
    CRYPTOPP_ASSERT(secret /*&& secretLen*/);
    CRYPTOPP_ASSERT(derived && derivedLen);
    CRYPTOPP_ASSERT(derivedLen <= MaxDerivedLength());

    ThrowIfInvalidDerivedLength(derivedLen);
    ValidateParameters(derivedLen, cost, blockSize, parallel);

    AlignedSecByteBlock  B(static_cast<size_t>(blockSize * parallel * 128U));

    // 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen)
    PBKDF2_SHA256(B, B.size(), secret, secretLen, salt, saltLen, 1);

    // Visual Studio and OpenMP 2.0 fixup. We must use int, not size_t.
    int maxParallel=0;
    if (!SafeConvert(parallel, maxParallel))
        maxParallel = std::numeric_limits<int>::max();

    #ifdef _OPENMP
    int threads = STDMIN(omp_get_max_threads(), maxParallel);
    #endif

    // http://stackoverflow.com/q/49604260/608639
    #pragma omp parallel num_threads(threads)
    {
        // Each thread gets its own copy
        AlignedSecByteBlock XY(static_cast<size_t>(blockSize * 256U));
        AlignedSecByteBlock  V(static_cast<size_t>(blockSize * cost * 128U));

        // 2: for i = 0 to p - 1 do
        #pragma omp for
        for (int i = 0; i < maxParallel; ++i)
        {
            // 3: B_i <-- MF(B_i, N)
            const ptrdiff_t offset = static_cast<ptrdiff_t>(blockSize*i*128);
            Smix(B+offset, static_cast<size_t>(blockSize), cost, V, XY);
        }
    }

    // 5: DK <-- PBKDF2(P, B, 1, dkLen)
    PBKDF2_SHA256(derived, derivedLen, secret, secretLen, B, B.size(), 1);

    return 1;
}

NAMESPACE_END
