// scrypt.cpp - written and placed in public domain by Jeffrey Walton.
//              Based on reference source code by Colin Percival and Simon Josefsson.

#include "pch.h"

#include "scrypt.h"
#include "argnames.h"
#include "pwdbased.h"
#include "stdcpp.h"
#include "salsa.h"
#include "misc.h"
#include "sha.h"

#ifdef _OPENMP
# include <omp.h>
#endif

#include <stdint.h>
#include <errno.h>
#include <sstream>

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::rotlConstant;
using CryptoPP::AlignedSecByteBlock;
using CryptoPP::LITTLE_ENDIAN_ORDER;
using CryptoPP::ConditionalByteReverse;

static inline void LE32ENC(uint8_t* out, uint32_t in)
{
	uint32_t* ptr = reinterpret_cast<uint32_t*>(out);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER, ptr, &in, 4);
}

static inline uint32_t LE32DEC(const uint8_t* in)
{
	uint32_t res;
	const uint32_t* ptr = reinterpret_cast<const uint32_t*>(in);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER, &res, ptr, 4);
	return res;
}

static inline uint64_t LE64DEC(const uint8_t* in)
{
	uint64_t res;
	const uint64_t* ptr = reinterpret_cast<const uint64_t*>(in);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER, &res, ptr, 8);
	return res;
}

static inline void BlockCopy(uint8_t * dest, uint8_t * src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dest[i] = src[i];
}

static inline void BlockXOR(uint8_t * dest, uint8_t * src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dest[i] ^= src[i];
}

static inline void PBKDF2_SHA256(uint8_t * buf, size_t dkLen,
	const uint8_t * passwd, size_t passwdlen,
	const uint8_t * salt, size_t saltlen, uint8_t count)
{
	using CryptoPP::SHA256;
	using CryptoPP::PKCS5_PBKDF2_HMAC;

	PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
	pbkdf.DeriveKey(buf, dkLen, 0, passwd, passwdlen, salt, saltlen, count, 0.0f);
}

static inline void Salsa20_8(uint8_t B[64])
{
	uint32_t B32[16], x[16];
	size_t i = 0;

	for (i = 0; i < 16; i++)
		B32[i] = LE32DEC(&B[i * 4]);

	for (i = 0; i < 16; i++)
		x[i] = B32[i];

	for (i = 0; i < 8; i += 2)
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

	for (i = 0; i < 16; i++)
		B32[i] += x[i];

	for (i = 0; i < 16; i++)
		LE32ENC(&B[4 * i], B32[i]);
}

static inline void BlockMix(uint8_t * B, uint8_t * Y, size_t r)
{
	uint8_t X[64];
	size_t i;

	// 1: X <-- B_{2r - 1}
	BlockCopy(X, &B[(2 * r - 1) * 64], 64);

	// 2: for i = 0 to 2r - 1 do
	for (i = 0; i < 2 * r; i++)
	{
		// 3: X <-- H(X \xor B_i)
		BlockXOR(X, &B[i * 64], 64);
		Salsa20_8(X);

		// 4: Y_i <-- X
		BlockCopy(&Y[i * 64], X, 64);
	}

	// 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1})
	for (i = 0; i < r; i++)
		BlockCopy(&B[i * 64], &Y[(i * 2) * 64], 64);
	for (i = 0; i < r; i++)
		BlockCopy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

static inline uint64_t Integerify(uint8_t * B, size_t r)
{
	uint8_t * X = &B[(2 * r - 1) * 64];
	return LE64DEC(X);
}

static inline void Smix(uint8_t * B, size_t r, uint32_t N, uint8_t * V, uint8_t * XY)
{
	uint8_t * X = XY;
	uint8_t * Y = XY+128*r;
	uint64_t i, j;

	// 1: X <-- B
	BlockCopy(X, B, 128 * r);

	// 2: for i = 0 to N - 1 do
	for (i = 0; i < N; i++)
	{
		// 3: V_i <-- X
		BlockCopy(&V[i * (128 * r)], X, 128 * r);

		// 4: X <-- H(X)
		BlockMix(X, Y, r);
	}

	// 6: for i = 0 to N - 1 do
	for (i = 0; i < N; i++) {
		// 7: j <-- Integerify(X) mod N
		j = Integerify(X, r) & (N - 1);

		// 8: X <-- H(X \xor V_j)
		BlockXOR(X, &V[j * (128 * r)], 128 * r);
		BlockMix(X, Y, r);
	}

	// 10: B' <-- X
	BlockCopy(B, X, 128 * r);
}

void crypto_scrypt(uint8_t * buf, size_t buflen, const uint8_t * secret, size_t secretLen,
    const uint8_t * salt, size_t saltlen, uint32_t N, uint32_t R, uint32_t P)
{
	size_t r = R, p = P;

	AlignedSecByteBlock B(128 * r * p);
	AlignedSecByteBlock XY(256 * r);
	AlignedSecByteBlock V(128 * r * N);

	// 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen)
	PBKDF2_SHA256(B, B.size(), secret, secretLen, salt, saltlen, 1);

	// 2: for i = 0 to p - 1 do
	for (unsigned int i = 0; i < p; i++)
	{
		// 3: B_i <-- MF(B_i, N)
		Smix(B+i*128*r, r, N, V, XY);
	}

	// 5: DK <-- PBKDF2(P, B, 1, dkLen)
	PBKDF2_SHA256(buf, buflen, secret, secretLen, B, p * 128 * r, 1);
}
ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

size_t Scrypt::GetValidDerivedLength(size_t keylength) const
{
	if (keylength > MaxDerivedLength())
		return MaxDerivedLength();
	return keylength;
}

void Scrypt::ValidateParameters(size_t derivedLen, unsigned int cost, unsigned int blockSize, unsigned int parallelization) const
{
	// Optimizer should remove
	if (std::numeric_limits<size_t>::max() > std::numeric_limits<uint32_t>::max())
	{
		const uint64_t maxLen = ((static_cast<uint64_t>(1) << 32) - 1) * 32;
		if (derivedLen > maxLen) {
			std::ostringstream oss;
			oss << "derivedLen " << derivedLen << " is larger than " << maxLen;
			throw InvalidArgument("Scrypt: " + oss.str());
		}
	}

	if (IsPowerOf2(cost) == false)
		throw InvalidArgument("Scrypt: cost must be a power of 2");

	const uint64_t prod = static_cast<uint64_t>(blockSize) * parallelization;
	if (prod >= (1U << 30)) {
		std::ostringstream oss;
		oss << "r*p " << prod << " is larger than " << (1U << 30);
		throw InvalidArgument("Scrypt: " + oss.str());
	}

	// Scrypt has several tests that effectively verify allocations like
	// '128 * r * N' and '128 * r * p' do not overflow. They are the tests
	// that set errno to ENOMEM. We can make the logic a little more clear
	// using word128 and Integer. At first blush the Integer may seem like
	// overkill. However, this alogirthm is dominated by slow moving parts,
	// so a one-time check is insignificant in the bigger picture.
#if defined(CRYPTOPP_WORD128_AVAILABLE)
	const word128 maxElems = static_cast<word128>(SIZE_MAX);
	const word128 bigSize1 = static_cast<word128>(cost) * blockSize * 128U;
	const word128 bigSize2 = static_cast<word128>(parallelization) * blockSize * 128U;
	if (bigSize1 > maxElems || bigSize2 > maxElems)
		throw std::bad_alloc();
#else
	const Integer maxElems = Integer(Integer::POSITIVE, 0, SIZE_MAX);
	const Integer bigSize1 = Integer(cost) * blockSize * 128U;
	const Integer bigSize2 = Integer(parallelization) * blockSize * 128U;
	if (bigSize1 > maxElems || bigSize2 > maxElems)
		throw std::bad_alloc();
#endif
}

size_t Scrypt::DeriveKey(byte *derived, size_t derivedLen,
    const byte *secret, size_t secretLen, const NameValuePairs& params) const
{
	CRYPTOPP_ASSERT(secret /*&& secretLen*/);
	CRYPTOPP_ASSERT(derived && derivedLen);
	CRYPTOPP_ASSERT(derivedLen <= MaxDerivedLength());

	unsigned int cost = (unsigned int)params.GetIntValueWithDefault("Cost", 2);
	unsigned int blockSize = (unsigned int)params.GetIntValueWithDefault("BlockSize", 8);
	unsigned int parallelization = (unsigned int)params.GetIntValueWithDefault("Parallelization", 1);

	ConstByteArrayParameter salt;
	(void)params.GetValue("Salt", salt);

	return DeriveKey(derived, derivedLen, secret, secretLen, salt.begin(), salt.size(), cost, blockSize, parallelization);
}

size_t Scrypt::DeriveKey(byte *derived, size_t derivedLen, const byte *secret, size_t secretLen,
    const byte *salt, size_t saltLen, unsigned int cost, unsigned int blockSize, unsigned int parallel) const
{
	CRYPTOPP_ASSERT(secret /*&& secretLen*/);
	CRYPTOPP_ASSERT(derived && derivedLen);
	CRYPTOPP_ASSERT(derivedLen <= MaxDerivedLength());
	CRYPTOPP_ASSERT(IsPowerOf2(cost));

	ThrowIfInvalidDerivedLength(derivedLen);
	ValidateParameters(derivedLen, cost, blockSize, parallel);

	crypto_scrypt(derived, derivedLen, secret, secretLen, salt, saltLen, cost, blockSize, parallel);

	return 1;
}

NAMESPACE_END
