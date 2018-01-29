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
	: m_keySet(false)
{
	::memset(m_seed, 0, m_seed.SizeInBytes());
}

RandomPool::RandomPool(result_type seedVal)
	: RandomNumberGenerator(seedVal), m_keySet(false)
	{::memset(m_seed, 0, m_seed.SizeInBytes());}

template <class Sseq> RandomPool::RandomPool(Sseq& q)
	: RandomNumberGenerator(q), m_keySet(false)
	{::memset(m_seed, 0, m_seed.SizeInBytes());}

void RandomPool::IncorporateEntropy(const byte *input, size_t length)
{
	SHA384 hash;
	hash.Update(m_seed, 48);
	hash.Update(input, length);
	hash.Final(m_seed);
	m_keySet = false;
}

void RandomPool::GenerateIntoBufferedTransformation(BufferedTransformation &target, const std::string &channel, lword size)
{
	if (size > 0)
	{
		if (!m_keySet)
		{
			m_cipher.SetKey((byte*)m_seed + 16, 32);
			m_keySet = true;
		}

		CRYPTOPP_COMPILE_ASSERT(sizeof(TimerWord) <= 16);
		CRYPTOPP_COMPILE_ASSERT(sizeof(time_t) <= 8);

		Timer timer;
		TimerWord tw = timer.GetCurrentTimerValue();

		*(TimerWord *)(void*)m_seed.data() += tw;
		time_t t = time(NULLPTR);

		// UBsan finding: signed integer overflow: 1876017710 + 1446085457 cannot be represented in type 'long int'
		// *(time_t *)(m_seed.data()+8) += t;
		word64 tt1 = 0, tt2 = (word64)t;
		::memcpy(&tt1, m_seed.data()+8, 8);
		::memcpy(m_seed.data()+8, &(tt2 += tt1), 8);

		// Wipe the intermediates
		*((volatile TimerWord*)&tw) = 0;
		*((volatile word64*)&tt1) = 0;
		*((volatile word64*)&tt2) = 0;

		size_t len;

		do
		{
			m_cipher.ProcessBlock(m_seed);
			len = UnsignedMin(16, size);
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
	::memset(pool, 0, poolSize);
	::memset(key, 0, key.size());
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

void OldRandomPool::Stir()
{
	CFB_Mode<OldRandomPoolCipher>::Encryption cipher;

	for (int i=0; i<2; i++)
	{
		cipher.SetKeyWithIV(key, key.size(), pool.end()-cipher.IVSize());
		cipher.ProcessString(pool, pool.size());
		::memcpy(key, pool, key.size());
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
	}}

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
