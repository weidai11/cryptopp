// ttmac.h - written and placed in the public domain by Kevin Springle

#ifndef CRYPTOPP_TTMAC_H
#define CRYPTOPP_TTMAC_H

#include "seckey.h"
#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)
//! <a href="http://www.eskimo.com/~weidai/scan-mirror/mac.html#Two-Track-MAC">Two-Track-MAC</a>
/*! 160 Bit MAC with 160 Bit Key */

class TTMAC_Base : public FixedKeyLength<20>, public IteratedHash<word32, LittleEndian, 64, MessageAuthenticationCode>
{
public:
	static std::string StaticAlgorithmName() {return std::string("Two-Track-MAC");}
	enum {DIGESTSIZE=20};

	TTMAC_Base() : IteratedHash<word32, LittleEndian, 64, MessageAuthenticationCode>(DIGESTSIZE*2) {}

	unsigned int DigestSize() const {return DIGESTSIZE;};
	void UncheckedSetKey(const byte *userKey, unsigned int keylength);
	void TruncatedFinal(byte *mac, unsigned int size);

protected:
	static void Transform (word32 *digest, const word32 *X, bool last);
	void vTransform(const word32 *data) {Transform(m_digest, data, false);}
	void Init();

	FixedSizeSecBlock<word32, DIGESTSIZE> m_key;
};

//! <a href="http://www.weidai.com/scan-mirror/mac.html#TTMAC">Two-Track-MAC</a>
typedef MessageAuthenticationCodeTemplate<TTMAC_Base> TTMAC;

NAMESPACE_END

#endif
