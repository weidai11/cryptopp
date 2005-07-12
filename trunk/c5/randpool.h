#ifndef CRYPTOPP_RANDPOOL_H
#define CRYPTOPP_RANDPOOL_H

#include "cryptlib.h"
#include "filters.h"

NAMESPACE_BEGIN(CryptoPP)

//! Randomness Pool
/*! This class can be used to generate
	pseudorandom bytes after seeding the pool with
	the Put() methods */
class CRYPTOPP_DLL RandomPool : public RandomNumberGenerator,
				   public Bufferless<BufferedTransformation>
{
public:
	//! poolSize must be greater than 16
	RandomPool(unsigned int poolSize=384);

	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking);

	bool AnyRetrievable() const {return true;}
	lword MaxRetrievable() const {return ULONG_MAX;}

	size_t TransferTo2(BufferedTransformation &target, lword &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	size_t CopyRangeTo2(BufferedTransformation &target, lword &begin, lword end=LWORD_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const
	{
		throw NotImplemented("RandomPool: CopyRangeTo2() is not supported by this store");
	}

	byte GenerateByte();
	void GenerateBlock(byte *output, size_t size);

	void IsolatedInitialize(const NameValuePairs &parameters) {}

protected:
	void Stir();

private:
	SecByteBlock pool, key;
	size_t addPos, getPos;
};

NAMESPACE_END

#endif
