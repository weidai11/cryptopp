// whrlpool.h - originally modified by Kevin Springle from Paulo Barreto and Vincent Rijmen's
//              public domain code, whirlpool.c. Updated to Whirlpool version 3.0, optimized
//              and SSE version added by WD. All modifications are placed in the public domain.

#ifndef CRYPTOPP_WHIRLPOOL_H
#define CRYPTOPP_WHIRLPOOL_H

/// \file whrlpool.h
/// \brief Classes for the Whirlpool message digest
/// \details Crypto++ provides version 3.0 of the Whirlpool algorithm.
///   This version of the algorithm was submitted for ISO standardization.

#include "config.h"
#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief Whirlpool message digest
/// \details Crypto++ provides version 3.0 of the Whirlpool algorithm.
///   This version of the algorithm was submitted for ISO standardization.
/// \since Crypto++ 5.2
/// \sa <a href="http://www.cryptopp.com/wiki/Whirlpool">Whirlpool</a>
class Whirlpool : public IteratedHashWithStaticTransform<word64, BigEndian, 64, 64, Whirlpool>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word64 *digest, const word64 *data);
	void TruncatedFinal(byte *hash, size_t size);
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "Whirlpool";}
};

NAMESPACE_END

#endif
