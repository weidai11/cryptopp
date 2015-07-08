// hkdf.h - written and placed in public domain by Jeffrey Walton. Copyright assigned to Crypto++ project

#ifndef CRYPTOPP_HASH_KEY_DERIVATION_FUNCTION_H
#define CRYPTOPP_HASH_KEY_DERIVATION_FUNCTION_H

#include "cryptlib.h"
#include "hmac.h"
#include "hrtimer.h"
#include "secblock.h"

#include <cstring>

NAMESPACE_BEGIN(CryptoPP)

//! abstract base class for key derivation function
class KeyDerivationFunction
{
public:
	virtual size_t MaxDerivedKeyLength() const =0;
	virtual bool UsesContext() const =0;
	//! derive key from secret
	virtual unsigned int DeriveKey(byte *derived, size_t derivedLen, const byte *secret, size_t secretLen, const byte *salt, size_t saltLen, const byte* context=NULL, size_t contextLen=0) const =0;
	
	// If salt is missing, then use the NULL vector. The length depends on the Hash function.
	static const byte s_NullVector[64];
};

const byte KeyDerivationFunction::s_NullVector[64] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

//! HKDF from RFC 5869, T should be a HashTransformation class
template <class T>
class CRYPTOPP_DLL HKDF : public KeyDerivationFunction
{
public:
	size_t MaxDerivedKeyLength() const {return static_cast<size_t>(T::DIGESTSIZE) * 255;}
	bool UsesContext() const {return true;}
	unsigned int DeriveKey(byte *derived, size_t derivedLen, const byte *secret, size_t secretLen, const byte *salt, size_t saltLen, const byte* context, size_t contextLen) const;
};

template <class T>
unsigned int HKDF<T>::DeriveKey(byte *derived, size_t derivedLen, const byte *secret, size_t secretLen, const byte *salt, size_t saltLen, const byte* context, size_t contextLen) const
{
	static const size_t DIGEST_SIZE = static_cast<size_t>(T::DIGESTSIZE);
	CRYPTOPP_COMPILE_ASSERT(DIGEST_SIZE <= COUNTOF(s_NullVector));
	const unsigned int req = static_cast<unsigned int>(derivedLen);
	
	assert(secret && secretLen);
	assert(derived && derivedLen);
	assert(derivedLen <= MaxDerivedKeyLength());

	if(derivedLen > MaxDerivedKeyLength())
		throw InvalidArgument("HKDF: derivedLen must be less than or equal to MaxDerivedKeyLength");

	HMAC<T> hmac;
	FixedSizeSecBlock<byte, DIGEST_SIZE> prk, buffer;

	// Extract
	const byte* key = (salt ? salt : s_NullVector);
	const size_t klen = (salt ? saltLen : DIGEST_SIZE);

	hmac.SetKey(key, klen);
	hmac.CalculateDigest(prk, secret, secretLen);

	// Expand
	hmac.SetKey(prk.data(), prk.size());
	byte block = 0;

	while (derivedLen > 0)
	{
		if(block++) {hmac.Update(buffer, buffer.size());}
		if(context && contextLen) {hmac.Update(context, contextLen);}
		hmac.CalculateDigest(buffer, &block, 1);

		size_t segmentLen = STDMIN(derivedLen, DIGEST_SIZE);
		std::memcpy(derived, buffer, segmentLen);

		derived += segmentLen;
		derivedLen -= segmentLen;
	}

	return req;
}

NAMESPACE_END

#endif // CRYPTOPP_HASH_KEY_DERIVATION_FUNCTION_H

