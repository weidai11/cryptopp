#ifndef CRYPTOPP_RANDPOOL_H
#define CRYPTOPP_RANDPOOL_H

#include "cryptlib.h"
#include "filters.h"

NAMESPACE_BEGIN(CryptoPP)

//! Randomness Pool
/*! This class can be used to generate
	pseudorandom bytes after seeding the pool with
	the Put() methods */
class RandomPool : public RandomNumberGenerator,
				   public Bufferless<BufferedTransformation>
{
public:
	//! poolSize must be greater than 16
	RandomPool(unsigned int poolSize=384);

	unsigned int Put2(const byte *begin, unsigned int, int messageEnd, bool blocking);

	bool AnyRetrievable() const {return true;}
	unsigned long MaxRetrievable() const {return ULONG_MAX;}

	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const
	{
		throw NotImplemented("RandomPool: CopyRangeTo2() is not supported by this store");
	}

	byte GenerateByte();
	void GenerateBlock(byte *output, unsigned int size);

	void IsolatedInitialize(const NameValuePairs &parameters) {}

protected:
	void Stir();

private:
	SecByteBlock pool, key;
	unsigned int addPos, getPos;
};

NAMESPACE_END

#endif
