#ifndef CRYPTOPP_TRUNHASH_H
#define CRYPTOPP_TRUNHASH_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

class NullHash : public HashTransformation
{
public:
	void Update(const byte *input, unsigned int length) {}
	unsigned int DigestSize() const {return 0;}
	void TruncatedFinal(byte *digest, unsigned int digestSize) {}
	bool TruncatedVerify(const byte *digest, unsigned int digestLength) {return true;}
};

//! construct new HashModule with smaller DigestSize() from existing one
template <class T>
class TruncatedHashTemplate : public HashTransformation
{
public:
	TruncatedHashTemplate(T hm, unsigned int digestSize)
		: m_hm(hm), m_digestSize(digestSize) {}
	TruncatedHashTemplate(const byte *key, unsigned int keyLength, unsigned int digestSize)
		: m_hm(key, keyLength), m_digestSize(digestSize) {}
	TruncatedHashTemplate(unsigned int digestSize)
		: m_digestSize(digestSize) {}

	void Update(const byte *input, unsigned int length)
		{m_hm.Update(input, length);}
	unsigned int DigestSize() const {return m_digestSize;}
	void TruncatedFinal(byte *digest, unsigned int digestSize)
		{m_hm.TruncatedFinal(digest, digestSize);}
	bool TruncatedVerify(const byte *digest, unsigned int digestLength)
		{return m_hm.TruncatedVerify(digest, digestLength);}

private:
	T m_hm;
	unsigned int m_digestSize;
};

typedef TruncatedHashTemplate<HashTransformation &> TruncatedHashModule;

NAMESPACE_END

#endif
