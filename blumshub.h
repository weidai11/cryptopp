#ifndef CRYPTOPP_BLUMSHUB_H
#define CRYPTOPP_BLUMSHUB_H

#include "modarith.h"

NAMESPACE_BEGIN(CryptoPP)

class BlumGoldwasserPublicKey;
class BlumGoldwasserPrivateKey;

//! BlumBlumShub without factorization of the modulus
class PublicBlumBlumShub : public RandomNumberGenerator,
						   public StreamTransformation
{
public:
	PublicBlumBlumShub(const Integer &n, const Integer &seed);

	unsigned int GenerateBit();
	byte GenerateByte();

	void ProcessData(byte *outString, const byte *inString, unsigned int length)
	{
		while (length--)
			*outString++ = *inString ^ GenerateByte();
	}

	bool IsSelfInverting() const {return true;}
	bool IsForwardTransformation() const {return true;}

protected:
	const ModularArithmetic modn;
	const word maxBits;
	Integer current;
	int bitsLeft;

	friend class BlumGoldwasserPublicKey;
	friend class BlumGoldwasserPrivateKey;
};

//! BlumBlumShub with factorization of the modulus
class BlumBlumShub : public PublicBlumBlumShub
{
public:
	// Make sure p and q are both primes congruent to 3 mod 4 and at least 512 bits long,
	// seed is the secret key and should be about as big as p*q
	BlumBlumShub(const Integer &p, const Integer &q, const Integer &seed);
	
	bool IsRandomAccess() const {return true;}
	void Seek(lword index);

protected:
	const Integer p, q;
	const Integer x0;
};

NAMESPACE_END

#endif
