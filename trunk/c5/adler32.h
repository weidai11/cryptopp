#ifndef CRYPTOPP_ADLER32_H
#define CRYPTOPP_ADLER32_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

//! ADLER-32 checksum calculations 
class Adler32 : public HashTransformation
{
public:
	enum {DIGESTSIZE = 4};
	Adler32() {Reset();}
	void Update(const byte *input, unsigned int length);
	void TruncatedFinal(byte *hash, unsigned int size);
	unsigned int DigestSize() const {return DIGESTSIZE;}

private:
	void Reset() {m_s1 = 1; m_s2 = 0;}

	word16 m_s1, m_s2;
};

NAMESPACE_END

#endif
