// randpool.cpp - written and placed in the public domain by Wei Dai
// The algorithm in this module comes from PGP's randpool.c

#include "pch.h"
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

unsigned int RandomPool::Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
{
	unsigned t;

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

unsigned int RandomPool::TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel, bool blocking)
{
	if (!blocking)
		throw NotImplemented("RandomPool: nonblocking transfer is not implemented by this object");

	unsigned int t;
	unsigned long size = transferBytes;

	while (size > (t = pool.size() - getPos))
	{
		target.ChannelPut(channel, pool+getPos, t);
		size -= t;
		Stir();
	}

	if (size)
	{
		target.ChannelPut(channel, pool+getPos, size);
		getPos += size;
	}

	return 0;
}

byte RandomPool::GenerateByte()
{
	if (getPos == pool.size())
		Stir();

	return pool[getPos++];
}

void RandomPool::GenerateBlock(byte *outString, unsigned int size)
{
	ArraySink sink(outString, size);
	TransferTo(sink, size);
}

NAMESPACE_END
