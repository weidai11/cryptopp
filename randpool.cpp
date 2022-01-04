// randpool.cpp - originally written and placed in the public domain by Wei Dai
// RandomPool used to follow the design of randpool in PGP 2.6.x,
// but as of version 5.5 it has been redesigned to reduce the risk
// of reusing random numbers after state rollback (which may occur
// when running in a virtual machine like VMware).

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "randpool.h"
#include "aes.h"
#include "sha.h"
#include "hrtimer.h"
#include "trap.h"

// OldRandomPool
#include "mdc.h"
#include "modes.h"

#include <time.h>

NAMESPACE_BEGIN(CryptoPP)

RandomPool::RandomPool()
	: m_pCipher(new AES::Encryption), m_keySet(false)
{
	std::memset(m_key, 0, m_key.SizeInBytes());
	std::memset(m_seed, 0, m_seed.SizeInBytes());
}

void RandomPool::IncorporateEntropy(const byte *input, size_t length)
{
	SHA256 hash;
	hash.Update(m_key, 32);
	hash.Update(input, length);
	hash.Final(m_key);
	m_keySet = false;
}

void RandomPool::GenerateIntoBufferedTransformation(BufferedTransformation &target, const std::string &channel, lword size)
{
	if (size > 0)
	{
		if (!m_keySet)
			m_pCipher->SetKey(m_key, 32);

		CRYPTOPP_COMPILE_ASSERT(sizeof(TimerWord) <= 16);
		CRYPTOPP_COMPILE_ASSERT(sizeof(time_t) <= 8);

		Timer timer;
		TimerWord tw = timer.GetCurrentTimerValue();

		*(TimerWord *)(void*)m_seed.data() += tw;
		time_t t = time(NULLPTR);

		// UBsan finding: signed integer overflow: 1876017710 + 1446085457 cannot be represented in type 'long int'
		// *(time_t *)(m_seed.data()+8) += t;
		word64 tt1 = 0, tt2 = (word64)t;
		std::memcpy(&tt1, m_seed.data()+8, 8);
		std::memcpy(m_seed.data()+8, &(tt2 += tt1), 8);

		// Wipe the intermediates
		*((volatile TimerWord*)&tw) = 0;
		*((volatile word64*)&tt1) = 0;
		*((volatile word64*)&tt2) = 0;

		do
		{
			m_pCipher->ProcessBlock(m_seed);
			size_t len = UnsignedMin(16, size);
			target.ChannelPut(channel, m_seed, len);
			size -= len;
		} while (size > 0);
	}
}

// OldRandomPool is provided for backwards compatibility for a migration path
typedef MDC<SHA1> OldRandomPoolCipher;

OldRandomPool::OldRandomPool(unsigned int poolSize)
        : pool(poolSize), key(OldRandomPoolCipher::DEFAULT_KEYLENGTH), addPos(0), getPos(poolSize)
{
	CRYPTOPP_ASSERT(poolSize > key.size());
	std::memset(pool, 0, poolSize);
	std::memset(key, 0, key.size());
}

void OldRandomPool::IncorporateEntropy(const byte *input, size_t length)
{
	size_t t;
	while (length > (t = pool.size() - addPos))
	{
		xorbuf(pool+addPos, input, t);
		input += t;
		length -= t;
		Stir();
	}

	if (length)
	{
		xorbuf(pool+addPos, input, length);
		addPos += length;
		getPos = pool.size(); // Force stir on get
	}
}

// GenerateWord32 is overridden and provides Crypto++ 5.4 behavior.
// Taken from RandomNumberGenerator::GenerateWord32 in cryptlib.cpp.
word32 OldRandomPool::GenerateWord32 (word32 min, word32 max)
{
	const word32 range = max-min;
	const unsigned int maxBytes = BytePrecision(range);
	const unsigned int maxBits = BitPrecision(range);

	word32 value;

	do
	{
		value = 0;
		for (unsigned int i=0; i<maxBytes; i++)
			value = (value << 8) | GenerateByte();

		value = Crop(value, maxBits);
	} while (value > range);

	return value+min;
}

void OldRandomPool::Stir()
{
	CFB_Mode<OldRandomPoolCipher>::Encryption cipher;

	for (int i=0; i<2; i++)
	{
		cipher.SetKeyWithIV(key, key.size(), pool.end()-cipher.IVSize());
		cipher.ProcessString(pool, pool.size());
		std::memcpy(key, pool, key.size());
	}

	addPos = 0;
	getPos = key.size();
}

void OldRandomPool::GenerateIntoBufferedTransformation(BufferedTransformation &target, const std::string &channel, lword size)
{
	while (size > 0)
	{
		if (getPos == pool.size())
				Stir();
		size_t t = UnsignedMin(pool.size() - getPos, size);
		target.ChannelPut(channel, pool+getPos, t);
		size -= t;
		getPos += t;
	}
}

byte OldRandomPool::GenerateByte()
{
	if (getPos == pool.size())
		Stir();

	return pool[getPos++];
}

void OldRandomPool::GenerateBlock(byte *outString, size_t size)
{
	ArraySink sink(outString, size);
	GenerateIntoBufferedTransformation(sink, DEFAULT_CHANNEL, size);
}

NAMESPACE_END

#endif
