// hmac.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "hmac.h"

NAMESPACE_BEGIN(CryptoPP)

void HMAC_Base::UncheckedSetKey(const byte *userKey, unsigned int keylength)
{
	AssertValidKeyLength(keylength);

	Restart();

	HashTransformation &hash = AccessHash();
	unsigned int blockSize = hash.BlockSize();

	if (!blockSize)
		throw InvalidArgument("HMAC: can only be used with a block-based hash function");

	if (keylength <= blockSize)
		memcpy(AccessIpad(), userKey, keylength);
	else
	{
		AccessHash().CalculateDigest(AccessIpad(), userKey, keylength);
		keylength = hash.DigestSize();
	}

	assert(keylength <= blockSize);
	memset(AccessIpad()+keylength, 0, blockSize-keylength);

	for (unsigned int i=0; i<blockSize; i++)
	{
		AccessOpad()[i] = AccessIpad()[i] ^ OPAD;
		AccessIpad()[i] ^= IPAD;
	}
}

void HMAC_Base::KeyInnerHash()
{
	assert(!m_innerHashKeyed);
	HashTransformation &hash = AccessHash();
	hash.Update(AccessIpad(), hash.BlockSize());
	m_innerHashKeyed = true;
}

void HMAC_Base::Restart()
{
	if (m_innerHashKeyed)
	{
		AccessHash().Restart();
		m_innerHashKeyed = false;
	}
}

void HMAC_Base::Update(const byte *input, unsigned int length)
{
	if (!m_innerHashKeyed)
		KeyInnerHash();
	AccessHash().Update(input, length);
}

void HMAC_Base::TruncatedFinal(byte *mac, unsigned int size)
{
	ThrowIfInvalidTruncatedSize(size);

	HashTransformation &hash = AccessHash();

	if (!m_innerHashKeyed)
		KeyInnerHash();
	hash.Final(AccessInnerHash());

	hash.Update(AccessOpad(), hash.BlockSize());
	hash.Update(AccessInnerHash(), hash.DigestSize());
	hash.TruncatedFinal(mac, size);

	m_innerHashKeyed = false;
}

NAMESPACE_END

#endif
