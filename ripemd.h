#ifndef CRYPTOPP_RIPEMD_H
#define CRYPTOPP_RIPEMD_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

//! <a href="http://www.weidai.com/scan-mirror/md.html#RIPEMD-160">RIPEMD-160</a>
/*! Digest Length = 160 bits */
class RIPEMD160 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD160>
{
public:
	enum {DIGESTSIZE = 20};
	RIPEMD160() : IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD160>(DIGESTSIZE) {Init();}
	static void Transform(word32 *digest, const word32 *data);
	static const char * StaticAlgorithmName() {return "RIPEMD-160";}

protected:
	void Init();
};

NAMESPACE_END

#endif
