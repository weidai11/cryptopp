#ifndef CRYPTOPP_MD5_H
#define CRYPTOPP_MD5_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

//! <a href="http://www.weidai.com/scan-mirror/md.html#MD5">MD5</a>
/*! \warning MD5 is considered insecure, and should not be used
	unless you absolutely need it for compatibility. */
class MD5 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, 16, MD5>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word32 *digest, const word32 *data);
	static const char * StaticAlgorithmName() {return "MD5";}
};

NAMESPACE_END

#endif
