#ifndef CRYPTOPP_OSRNG_H
#define CRYPTOPP_OSRNG_H

#include "config.h"

#ifdef OS_RNG_AVAILABLE

#include "randpool.h"
#include "rng.h"

NAMESPACE_BEGIN(CryptoPP)

//! Exception class for Operating-System Random Number Generator.
class OS_RNG_Err : public Exception
{
public:
	OS_RNG_Err(const std::string &operation);
};

#ifdef NONBLOCKING_RNG_AVAILABLE

#ifdef CRYPTOPP_WIN32_AVAILABLE
class MicrosoftCryptoProvider
{
public:
	MicrosoftCryptoProvider();
	~MicrosoftCryptoProvider();
#if defined(_WIN64)
	typedef unsigned __int64 ProviderHandle;	// type HCRYPTPROV, avoid #include <windows.h>
#else
	typedef unsigned long ProviderHandle;
#endif
	ProviderHandle GetProviderHandle() const {return m_hProvider;}
private:
	ProviderHandle m_hProvider;
};
#endif

//! encapsulate CryptoAPI's CryptGenRandom or /dev/urandom
class NonblockingRng : public RandomNumberGenerator
{
public:
	NonblockingRng();
	~NonblockingRng();
	byte GenerateByte();
	void GenerateBlock(byte *output, unsigned int size);

protected:
#ifdef CRYPTOPP_WIN32_AVAILABLE
#	ifndef WORKAROUND_MS_BUG_Q258000
		MicrosoftCryptoProvider m_Provider;
#	endif
#else
	int m_fd;
#endif
};

#endif

#ifdef BLOCKING_RNG_AVAILABLE

//! encapsulate /dev/random
class BlockingRng : public RandomNumberGenerator
{
public:
	BlockingRng();
	~BlockingRng();
	byte GenerateByte();
	void GenerateBlock(byte *output, unsigned int size);

protected:
	int m_fd;
};

#endif

void OS_GenerateRandomBlock(bool blocking, byte *output, unsigned int size);

//! Automaticly Seeded Randomness Pool
/*! This class seeds itself using an operating system provided RNG. */
class AutoSeededRandomPool : public RandomPool
{
public:
	//! blocking will be ignored if the prefered RNG isn't available
	explicit AutoSeededRandomPool(bool blocking = false, unsigned int seedSize = 32)
		{Reseed(blocking, seedSize);}
	void Reseed(bool blocking = false, unsigned int seedSize = 32);
};

//! RNG from ANSI X9.17 Appendix C, seeded using an OS provided RNG
template <class BLOCK_CIPHER>
class AutoSeededX917RNG : public RandomNumberGenerator
{
public:
	//! blocking will be ignored if the prefered RNG isn't available
	explicit AutoSeededX917RNG(bool blocking = false)
		{Reseed(blocking);}
	void Reseed(bool blocking = false);
	// exposed for testing
	void Reseed(const byte *key, unsigned int keylength, const byte *seed, unsigned long timeVector);

	byte GenerateByte();

private:
	member_ptr<RandomNumberGenerator> m_rng;
	SecByteBlock m_lastBlock;
	bool m_isDifferent;
	unsigned int m_counter;
};

template <class BLOCK_CIPHER>
void AutoSeededX917RNG<BLOCK_CIPHER>::Reseed(const byte *key, unsigned int keylength, const byte *seed, unsigned long timeVector)
{
	m_rng.reset(new X917RNG(new typename BLOCK_CIPHER::Encryption(key, keylength), seed, timeVector));

	// for FIPS 140-2
	m_lastBlock.resize(16);
	m_rng->GenerateBlock(m_lastBlock, m_lastBlock.size());
	m_counter = 0;
	m_isDifferent = false;
}

template <class BLOCK_CIPHER>
void AutoSeededX917RNG<BLOCK_CIPHER>::Reseed(bool blocking)
{
	SecByteBlock seed(BLOCK_CIPHER::BLOCKSIZE + BLOCK_CIPHER::DEFAULT_KEYLENGTH);
	const byte *key;
	do
	{
		OS_GenerateRandomBlock(blocking, seed, seed.size());
		key = seed + BLOCK_CIPHER::BLOCKSIZE;
	}	// check that seed and key don't have same value
	while (memcmp(key, seed, STDMIN((unsigned int)BLOCK_CIPHER::BLOCKSIZE, (unsigned int)BLOCK_CIPHER::DEFAULT_KEYLENGTH)) == 0);

	Reseed(key, BLOCK_CIPHER::DEFAULT_KEYLENGTH, seed, 0);
}

template <class BLOCK_CIPHER>
byte AutoSeededX917RNG<BLOCK_CIPHER>::GenerateByte()
{
	byte b = m_rng->GenerateByte();

	// for FIPS 140-2
	m_isDifferent = m_isDifferent || b != m_lastBlock[m_counter];
	m_lastBlock[m_counter] = b;
	++m_counter;
	if (m_counter == m_lastBlock.size())
	{
		if (!m_isDifferent)
			throw SelfTestFailure("AutoSeededX917RNG: Continuous random number generator test failed.");
		m_counter = 0;
		m_isDifferent = false;
	}

	return b;
}

NAMESPACE_END

#endif

#endif
