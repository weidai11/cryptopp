#ifndef CRYPTOPP_CBCMAC_H
#define CRYPTOPP_CBCMAC_H

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T>
class CBC_MAC_Base : public SameKeyLengthAs<T>, public MessageAuthenticationCode
{
public:
	static std::string StaticAlgorithmName() {return std::string("CBC-MAC(") + T::StaticAlgorithmName() + ")";}

	CBC_MAC_Base() {}

	void CheckedSetKey(void *, Empty empty, const byte *key, unsigned int length, const NameValuePairs &params);
	void Update(const byte *input, unsigned int length);
	void TruncatedFinal(byte *mac, unsigned int size);
	unsigned int DigestSize() const {return m_cipher.BlockSize();}

private:
	void ProcessBuf();
	typename T::Encryption m_cipher;
	SecByteBlock m_reg;
	unsigned int m_counter;
};

//! <a href="http://www.weidai.com/scan-mirror/mac.html#CBC-MAC">CBC-MAC</a>
/*! Compatible with FIPS 113. T should be an encryption class.
	Secure only for fixed length messages. For variable length
	messages use DMAC.
*/
template <class T>
class CBC_MAC : public MessageAuthenticationCodeTemplate<CBC_MAC_Base<T> >
{
public:
	CBC_MAC() {}
	CBC_MAC(const byte *key, unsigned int length=CBC_MAC_Base<T>::DEFAULT_KEYLENGTH)
		{SetKey(key, length);}
};

template <class T>
void CBC_MAC_Base<T>::CheckedSetKey(void *, Empty empty, const byte *key, unsigned int length, const NameValuePairs &params)
{
	m_cipher.SetKey(key, length, params);
	m_reg.CleanNew(m_cipher.BlockSize());
	m_counter = 0;
}

template <class T>
void CBC_MAC_Base<T>::Update(const byte *input, unsigned int length)
{
	while (m_counter && length)
	{
		m_reg[m_counter++] ^= *input++;
		if (m_counter == T::BLOCKSIZE)
			ProcessBuf();
		length--;
	}

	while (length >= T::BLOCKSIZE)
	{
		xorbuf(m_reg, input, T::BLOCKSIZE);
		ProcessBuf();
		input += T::BLOCKSIZE;
		length -= T::BLOCKSIZE;
	}

	while (length--)
	{
		m_reg[m_counter++] ^= *input++;
		if (m_counter == T::BLOCKSIZE)
			ProcessBuf();
	}
}

template <class T>
void CBC_MAC_Base<T>::TruncatedFinal(byte *mac, unsigned int size)
{
	ThrowIfInvalidTruncatedSize(size);

	if (m_counter)
		ProcessBuf();

	memcpy(mac, m_reg, size);
	memset(m_reg, 0, T::BLOCKSIZE);
}

template <class T>
void CBC_MAC_Base<T>::ProcessBuf()
{
	m_cipher.ProcessBlock(m_reg);
	m_counter = 0;
}

NAMESPACE_END

#endif
