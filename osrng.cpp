// osrng.cpp - written and placed in the public domain by Wei Dai

// Thanks to Leonard Janke for the suggestion for AutoSeededRandomPool.

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "osrng.h"

#ifdef OS_RNG_AVAILABLE

#include "rng.h"

#ifdef CRYPTOPP_WIN32_AVAILABLE
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#include <windows.h>
#include <wincrypt.h>
#endif

#ifdef CRYPTOPP_UNIX_AVAILABLE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

#if defined(NONBLOCKING_RNG_AVAILABLE) || defined(BLOCKING_RNG_AVAILABLE)
OS_RNG_Err::OS_RNG_Err(const std::string &operation)
	: Exception(OTHER_ERROR, "OS_Rng: " + operation + " operation failed with error " + 
#ifdef CRYPTOPP_WIN32_AVAILABLE
		"0x" + IntToString(GetLastError(), 16)
#else
		IntToString(errno)
#endif
		)
{
}
#endif

#ifdef NONBLOCKING_RNG_AVAILABLE

#ifdef CRYPTOPP_WIN32_AVAILABLE

MicrosoftCryptoProvider::MicrosoftCryptoProvider()
{
	if(!CryptAcquireContext(&m_hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		throw OS_RNG_Err("CryptAcquireContext");
}

MicrosoftCryptoProvider::~MicrosoftCryptoProvider()
{
	CryptReleaseContext(m_hProvider, 0);
}

#endif

NonblockingRng::NonblockingRng()
{
#ifndef CRYPTOPP_WIN32_AVAILABLE
	m_fd = open("/dev/urandom",O_RDONLY);
	if (m_fd == -1)
		throw OS_RNG_Err("open /dev/urandom");
#endif
}

NonblockingRng::~NonblockingRng()
{
#ifndef CRYPTOPP_WIN32_AVAILABLE
	close(m_fd);
#endif
}

byte NonblockingRng::GenerateByte()
{
	byte b;
	GenerateBlock(&b, 1);
	return b;
}

void NonblockingRng::GenerateBlock(byte *output, unsigned int size)
{
#ifdef CRYPTOPP_WIN32_AVAILABLE
#	ifdef WORKAROUND_MS_BUG_Q258000
		static MicrosoftCryptoProvider m_Provider;
#	endif
	if (!CryptGenRandom(m_Provider.GetProviderHandle(), size, output))
		throw OS_RNG_Err("CryptGenRandom");
#else
	if (read(m_fd, output, size) != size)
		throw OS_RNG_Err("read /dev/urandom");
#endif
}

#endif

// *************************************************************

#ifdef BLOCKING_RNG_AVAILABLE

BlockingRng::BlockingRng()
{
	m_fd = open("/dev/random",O_RDONLY);
	if (m_fd == -1)
		throw OS_RNG_Err("open /dev/random");
}

BlockingRng::~BlockingRng()
{
	close(m_fd);
}

byte BlockingRng::GenerateByte()
{
	byte b;
	GenerateBlock(&b, 1);
	return b;
}

void BlockingRng::GenerateBlock(byte *output, unsigned int size)
{
	while (size)
	{
		// on some systems /dev/random will block until all bytes
		// are available, on others it will returns immediately
		int len = read(m_fd, output, STDMIN(size, (unsigned int)INT_MAX));
		if (len == -1)
			throw OS_RNG_Err("read /dev/random");
		size -= len;
		output += len;
		if (size)
			sleep(1);
	}
}

#endif

// *************************************************************

void OS_GenerateRandomBlock(bool blocking, byte *output, unsigned int size)
{
#ifdef NONBLOCKING_RNG_AVAILABLE
	if (blocking)
#endif
	{
#ifdef BLOCKING_RNG_AVAILABLE
		BlockingRng rng;
		rng.GenerateBlock(output, size);
#endif
	}

#ifdef BLOCKING_RNG_AVAILABLE
	if (!blocking)
#endif
	{
#ifdef NONBLOCKING_RNG_AVAILABLE
		NonblockingRng rng;
		rng.GenerateBlock(output, size);
#endif
	}
}

void AutoSeededRandomPool::Reseed(bool blocking, unsigned int seedSize)
{
	SecByteBlock seed(seedSize);
	OS_GenerateRandomBlock(blocking, seed, seedSize);
	Put(seed, seedSize);
}

NAMESPACE_END

#endif

#endif
