// hmac.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_HMAC_H
#define CRYPTOPP_HMAC_H

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T>
class CRYPTOPP_NO_VTABLE HMAC_Base : public VariableKeyLength<16, 0, UINT_MAX>, public MessageAuthenticationCode
{
public:
	static std::string StaticAlgorithmName() {return std::string("HMAC(") + T::StaticAlgorithmName() + ")";}

	// put enums here for Metrowerks 4
	enum {DIGESTSIZE=T::DIGESTSIZE, BLOCKSIZE=T::BLOCKSIZE};

	HMAC_Base() : m_innerHashKeyed(false) {}
	void UncheckedSetKey(const byte *userKey, unsigned int keylength);

	void Restart();
	void Update(const byte *input, unsigned int length);
	void TruncatedFinal(byte *mac, unsigned int size);
	unsigned int DigestSize() const {return DIGESTSIZE;}

private:
	void KeyInnerHash();

	enum {IPAD=0x36, OPAD=0x5c};

	FixedSizeSecBlock<byte, BLOCKSIZE> k_ipad, k_opad;
	FixedSizeSecBlock<byte, DIGESTSIZE> m_innerHash;
	T m_hash;
	bool m_innerHashKeyed;
};

//! <a href="http://www.weidai.com/scan-mirror/mac.html#HMAC">HMAC</a>
/*! HMAC(K, text) = H(K XOR opad, H(K XOR ipad, text)) */
template <class T>
class HMAC : public MessageAuthenticationCodeTemplate<HMAC_Base<T> >
{
public:
	HMAC() {}
	HMAC(const byte *key, unsigned int length=HMAC_Base<T>::DEFAULT_KEYLENGTH)
		{SetKey(key, length);}
};

template <class T>
void HMAC_Base<T>::UncheckedSetKey(const byte *userKey, unsigned int keylength)
{
	AssertValidKeyLength(keylength);

	Restart();

	if (keylength <= T::BLOCKSIZE)
		memcpy(k_ipad, userKey, keylength);
	else
	{
		m_hash.CalculateDigest(k_ipad, userKey, keylength);
		keylength = T::DIGESTSIZE;
	}

	assert(keylength <= T::BLOCKSIZE);
	memset(k_ipad+keylength, 0, T::BLOCKSIZE-keylength);

	for (unsigned int i=0; i<T::BLOCKSIZE; i++)
	{
		k_opad[i] = k_ipad[i] ^ OPAD;
		k_ipad[i] ^= IPAD;
	}
}

template <class T>
void HMAC_Base<T>::KeyInnerHash()
{
	assert(!m_innerHashKeyed);
	m_hash.Update(k_ipad, T::BLOCKSIZE);
	m_innerHashKeyed = true;
}

template <class T>
void HMAC_Base<T>::Restart()
{
	if (m_innerHashKeyed)
	{
		m_hash.Restart();
		m_innerHashKeyed = false;
	}
}

template <class T>
void HMAC_Base<T>::Update(const byte *input, unsigned int length)
{
	if (!m_innerHashKeyed)
		KeyInnerHash();
	m_hash.Update(input, length);
}

template <class T>
void HMAC_Base<T>::TruncatedFinal(byte *mac, unsigned int size)
{
	ThrowIfInvalidTruncatedSize(size);

	if (!m_innerHashKeyed)
		KeyInnerHash();
	m_hash.Final(m_innerHash);

	m_hash.Update(k_opad, T::BLOCKSIZE);
	m_hash.Update(m_innerHash, DIGESTSIZE);
	m_hash.TruncatedFinal(mac, size);

	m_innerHashKeyed = false;
}

NAMESPACE_END

#endif
