// hmac.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_HMAC_H
#define CRYPTOPP_HMAC_H

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE HMAC_Base : public VariableKeyLength<16, 0, UINT_MAX>, public MessageAuthenticationCode
{
public:
	HMAC_Base() : m_innerHashKeyed(false) {}
	void UncheckedSetKey(const byte *userKey, unsigned int keylength);

	void Restart();
	void Update(const byte *input, unsigned int length);
	void TruncatedFinal(byte *mac, unsigned int size);
	unsigned int OptimalBlockSize() const {return const_cast<HMAC_Base*>(this)->AccessHash().OptimalBlockSize();}
	unsigned int DigestSize() const {return const_cast<HMAC_Base*>(this)->AccessHash().DigestSize();}

protected:
	virtual HashTransformation & AccessHash() =0;
	virtual byte * AccessIpad() =0;
	virtual byte * AccessOpad() =0;
	virtual byte * AccessInnerHash() =0;

private:
	void KeyInnerHash();

	enum {IPAD=0x36, OPAD=0x5c};

	bool m_innerHashKeyed;
};

//! <a href="http://www.weidai.com/scan-mirror/mac.html#HMAC">HMAC</a>
/*! HMAC(K, text) = H(K XOR opad, H(K XOR ipad, text)) */
template <class T>
class HMAC : public MessageAuthenticationCodeImpl<HMAC_Base, HMAC<T> >
{
public:
	enum {DIGESTSIZE=T::DIGESTSIZE, BLOCKSIZE=T::BLOCKSIZE};

	HMAC() {}
	HMAC(const byte *key, unsigned int length=HMAC_Base::DEFAULT_KEYLENGTH)
		{this->SetKey(key, length);}

	static std::string StaticAlgorithmName() {return std::string("HMAC(") + T::StaticAlgorithmName() + ")";}
	std::string AlgorithmName() const {return std::string("HMAC(") + m_hash.AlgorithmName() + ")";}

private:
	HashTransformation & AccessHash() {return m_hash;}
	byte * AccessIpad() {return m_ipad;}
	byte * AccessOpad() {return m_opad;}
	byte * AccessInnerHash() {return m_innerHash;}

	FixedSizeSecBlock<byte, BLOCKSIZE> m_ipad, m_opad;
	FixedSizeSecBlock<byte, DIGESTSIZE> m_innerHash;
	T m_hash;
};

NAMESPACE_END

#endif
