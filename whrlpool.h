#ifndef CRYPTOPP_WHIRLPOOL_H
#define CRYPTOPP_WHIRLPOOL_H

#include "config.h"

#ifdef WORD64_AVAILABLE

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

//! <a href="http://www.weidai.com/scan-mirror/md.html#Whirlpool">Whirlpool</a>
/*! 512 Bit Hash */
class Whirlpool : public IteratedHashWithStaticTransform<word64, BigEndian, 64, 64, Whirlpool>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word64 *digest, const word64 *data);
	void TruncatedFinal(byte *hash, unsigned int size);
	static const char * StaticAlgorithmName() {return "Whirlpool";}
};

NAMESPACE_END

#endif

#endif
