#ifndef CRYPTOPP_MD5_H
#define CRYPTOPP_MD5_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

//! <a href="http://www.weidai.com/scan-mirror/md.html#MD5">MD5</a>
/*! 128 Bit Hash */
class MD5 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, MD5>
{
public:
	enum {DIGESTSIZE = 16};
	MD5() : IteratedHashWithStaticTransform<word32, LittleEndian, 64, MD5>(DIGESTSIZE) {Init();}
	static void Transform(word32 *digest, const word32 *data);
	static const char * StaticAlgorithmName() {return "MD5";}

protected:
	void Init();
};

NAMESPACE_END

#endif
