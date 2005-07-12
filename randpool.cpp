// randpool.cpp - written and placed in the public domain by Wei Dai
// The algorithm in this module comes from PGP's randpool.c

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "randpool.h"
#include "mdc.h"
#include "sha.h"
#include "modes.h"

NAMESPACE_BEGIN(CryptoPP)

typedef MDC<SHA> RandomPoolCipher;

RandomPool::RandomPool(unsigned int poolSize)
	: pool(poolSize), key(RandomPoolCipher::DEFAULT_KEYLENGTH)
{
	assert(poolSize > key.size());

	addPos=0;
	getPos=poolSize;
	memset(pool, 0, poolSize);
	memset(key, 0, key.size());
}

void RandomPool::Stir()
{
	CFB_Mode<RandomPoolCipher>::Encryption cipher;

	for (int i=0; i<2; i++)
	{
		cipher.SetKeyWithIV(key, key.size(), pool.end()-cipher.IVSize());
		cipher.ProcessString(pool, pool.size());
		memcpy(key, pool, key.size());
	}

	addPos = 0;
	getPos = key.size();
}

size_t RandomPool::Put2(const byte *inString, size_t length, int messageEnd, bool blocking)
{
	size_t t;

	while (length > (t = pool.size() - addPos))
	{
		xorbuf(pool+addPos, inString, t);
		inString += t;
		length -= t;
		Stir();
	}

	if (length)
	{
		xorbuf(pool+addPos, inString, length);
		addPos += length;
		getPos = pool.size(); // Force stir on get
	}

	return 0;
}

size_t RandomPool::TransferTo2(BufferedTransformation &target, lword &transferBytes, const std::string &channel, bool blocking)
{
	if (!blocking)
		throw NotImplemented("RandomPool: nonblocking transfer is not implemented by this object");

	lword size = transferBytes;

	while (size > 0)
	{
		if (getPos == pool.size())
			Stir();
		size_t t = UnsignedMin(pool.size() - getPos, size);
		target.ChannelPut(channel, pool+getPos, t);
		size -= t;
		getPos += t;
	}

	return 0;
}

byte RandomPool::GenerateByte()
{
	if (getPos == pool.size())
		Stir();

	return pool[getPos++];
}

void RandomPool::GenerateBlock(byte *outString, size_t size)
{
	ArraySink sink(outString, size);
	TransferTo(sink, size);
}

NAMESPACE_END

#endif
