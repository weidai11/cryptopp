#ifndef CRYPTOPP_MD5MAC_H
#define CRYPTOPP_MD5MAC_H

/** \file
*/

#include "seckey.h"
#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

//! .
class MD5MAC_Base : public FixedKeyLength<16>, public IteratedHash<word32, LittleEndian, 64, MessageAuthenticationCode>
{
public:
	static std::string StaticAlgorithmName() {return "MD5-MAC";}
	enum {DIGESTSIZE = 16};

	MD5MAC_Base() : IteratedHash<word32, LittleEndian, 64, MessageAuthenticationCode>(DIGESTSIZE) {}

	void UncheckedSetKey(const byte *userKey, unsigned int keylength);
	void TruncatedFinal(byte *mac, unsigned int size);

protected:
	static void Transform (word32 *buf, const word32 *in, const word32 *key);
	void vTransform(const word32 *data) {Transform(m_digest, data, m_key+4);}
	void Init();

	static const word32 T[12];
	FixedSizeSecBlock<word32, 12> m_key;
};

//! <a href="http://www.weidai.com/scan-mirror/mac.html#MD5-MAC">MD5-MAC</a>
typedef MessageAuthenticationCodeTemplate<MD5MAC_Base> MD5MAC;

NAMESPACE_END

#endif
