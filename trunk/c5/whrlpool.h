#ifndef CRYPTOPP_WHIRLPOOL_H
#define CRYPTOPP_WHIRLPOOL_H

#include "config.h"

#ifdef WORD64_AVAILABLE

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

//! <a href="http://www.eskimo.com/~weidai/scan-mirror/md.html#Whirlpool">Whirlpool</a>
/*! 512 Bit Hash */
class Whirlpool : public IteratedHashWithStaticTransform<word64, BigEndian, 64, Whirlpool>
{
public:
	enum {DIGESTSIZE = 64};
	Whirlpool() : IteratedHashWithStaticTransform<word64, BigEndian, 64, Whirlpool>(DIGESTSIZE) {Init();}
	static void Transform(word64 *digest, const word64 *data);
	void TruncatedFinal(byte *hash, unsigned int size);
	static const char * StaticAlgorithmName() {return "Whirlpool";}

protected:
	void Init();
};

NAMESPACE_END

#endif

#endif
