#ifndef CRYPTOPP_MD4_H
#define CRYPTOPP_MD4_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

//! <a href="http://www.weidai.com/scan-mirror/md.html#MD4">MD4</a>
/*! \warning MD4 is considered insecure, and should not be used
	unless you absolutely need it for compatibility. */
class MD4 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, 16, MD4>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word32 *digest, const word32 *data);
	static const char *StaticAlgorithmName() {return "MD4";}
};

NAMESPACE_END

#endif
