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
#ifdef _OPENMP
# include <omp.h>
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlConstant;
using CryptoPP::AlignedSecByteBlock;
using CryptoPP::LITTLE_ENDIAN_ORDER;
using CryptoPP::ConditionalByteReverse;

static inline void LE32ENC(byte* out, word32 in)
{
    word32* ptr = reinterpret_cast<word32*>(out);
    ConditionalByteReverse(LITTLE_ENDIAN_ORDER, ptr, &in, 4);
}

static inline word32 LE32DEC(const byte* in)
{
    word32 res;
    const word32* ptr = reinterpret_cast<const word32*>(in);
    ConditionalByteReverse(LITTLE_ENDIAN_ORDER, &res, ptr, 4);
    return res;
}

static inline word64 LE64DEC(const byte* in)
{
    word64 res;
    const word64* ptr = reinterpret_cast<const word64*>(in);
    ConditionalByteReverse(LITTLE_ENDIAN_ORDER, &res, ptr, 8);
    return res;
}

static inline void BlockCopy(byte* dest, byte* src, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        dest[i] = src[i];
}

static inline void BlockXOR(byte* dest, byte* src, size_t len)
{
    #pragma omp simd
    for (size_t i = 0; i < len; ++i)
        dest[i] ^= src[i];
}

static inline void PBKDF2_SHA256(byte* buf, size_t dkLen,
    const byte* passwd, size_t passwdlen,
    const byte* salt, size_t saltlen, byte count)
{
    using CryptoPP::SHA256;
    using CryptoPP::PKCS5_PBKDF2_HMAC;

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(buf, dkLen, 0, passwd, passwdlen, salt, saltlen, count, 0.0f);
}

static inline void Salsa20_8(byte B[64])
{
    word32 B32[16], x[16];

    for (size_t i = 0; i < 16; ++i)
        B32[i] = LE32DEC(&B[i * 4]);

    for (size_t i = 0; i < 16; ++i)
        x[i] = B32[i];

    for (size_t i = 0; i < 8; i += 2)
    {
        x[ 4] ^= rotlConstant< 7>(x[ 0]+x[12]);
        x[ 8] ^= rotlConstant< 9>(x[ 4]+x[ 0]);
        x[12] ^= rotlConstant<13>(x[ 8]+x[ 4]);
        x[ 0] ^= rotlConstant<18>(x[12]+x[ 8]);

        x[ 9] ^= rotlConstant< 7>(x[ 5]+x[ 1]);
        x[13] ^= rotlConstant< 9>(x[ 9]+x[ 5]);
        x[ 1] ^= rotlConstant<13>(x[13]+x[ 9]);
        x[ 5] ^= rotlConstant<18>(x[ 1]+x[13]);

        x[14] ^= rotlConstant< 7>(x[10]+x[ 6]);
        x[ 2] ^= rotlConstant< 9>(x[14]+x[10]);
        x[ 6] ^= rotlConstant<13>(x[ 2]+x[14]);
        x[10] ^= rotlConstant<18>(x[ 6]+x[ 2]);

        x[ 3] ^= rotlConstant< 7>(x[15]+x[11]);
        x[ 7] ^= rotlConstant< 9>(x[ 3]+x[15]);
        x[11] ^= rotlConstant<13>(x[ 7]+x[ 3]);
        x[15] ^= rotlConstant<18>(x[11]+x[ 7]);

        x[ 1] ^= rotlConstant< 7>(x[ 0]+x[ 3]);
        x[ 2] ^= rotlConstant< 9>(x[ 1]+x[ 0]);
        x[ 3] ^= rotlConstant<13>(x[ 2]+x[ 1]);
        x[ 0] ^= rotlConstant<18>(x[ 3]+x[ 2]);

        x[ 6] ^= rotlConstant< 7>(x[ 5]+x[ 4]);
        x[ 7] ^= rotlConstant< 9>(x[ 6]+x[ 5]);
        x[ 4] ^= rotlConstant<13>(x[ 7]+x[ 6]);
        x[ 5] ^= rotlConstant<18>(x[ 4]+x[ 7]);

        x[11] ^= rotlConstant< 7>(x[10]+x[ 9]);
        x[ 8] ^= rotlConstant< 9>(x[11]+x[10]);
        x[ 9] ^= rotlConstant<13>(x[ 8]+x[11]);
        x[10] ^= rotlConstant<18>(x[ 9]+x[ 8]);

        x[12] ^= rotlConstant< 7>(x[15]+x[14]);
        x[13] ^= rotlConstant< 9>(x[12]+x[15]);
        x[14] ^= rotlConstant<13>(x[13]+x[12]);
        x[15] ^= rotlConstant<18>(x[14]+x[13]);
    }

    #pragma omp simd
    for (size_t i = 0; i < 16; ++i)
        B32[i] += x[i];

    for (size_t i = 0; i < 16; ++i)
        LE32ENC(&B[4 * i], B32[i]);
}

static inline void BlockMix(byte* B, byte* Y, size_t r)
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

static inline word64 Integerify(byte* B, size_t r)
{
    byte* X = &B[(2 * r - 1) * 64];
    return LE64DEC(X);
}

static inline void Smix(byte* B, size_t r, word64 N, byte* V, byte* XY)
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

    if (parallel == 1)
    {
        AlignedSecByteBlock XY(static_cast<size_t>(blockSize * 256U));
        AlignedSecByteBlock  V(static_cast<size_t>(blockSize * cost * 128U));

        // 2: for i = 0 to p - 1 do
        // 3: B_i <-- MF(B_i, N)
        Smix(B, static_cast<size_t>(blockSize), cost, V, XY);
        XY.SetMark(256); V.SetMark(128);
    }
    else
    {
        // 2: for i = 0 to p - 1 do
        #pragma omp parallel for
        for (size_t i = 0; i < static_cast<size_t>(parallel); ++i)
        {
            // Can't figure out how to hoist this out of the for-loop
            //   https://stackoverflow.com/q/49604260/608639
            AlignedSecByteBlock XY(static_cast<size_t>(blockSize * 256U));
            AlignedSecByteBlock  V(static_cast<size_t>(blockSize * cost * 128U));

            // 3: B_i <-- MF(B_i, N)
            const ptrdiff_t offset = static_cast<ptrdiff_t>(blockSize*i*128);
            Smix(B+offset, static_cast<size_t>(blockSize), cost, V, XY);
            XY.SetMark(256); V.SetMark(128);
        }
    }

    // 5: DK <-- PBKDF2(P, B, 1, dkLen)
    PBKDF2_SHA256(derived, derivedLen, secret, secretLen, B, B.size(), 1);

    return 1;
}

NAMESPACE_END
