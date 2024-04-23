// osrng.cpp - originally written and placed in the public domain by Wei Dai

// Thanks to Leonard Janke for the suggestion for AutoSeededRandomPool.

#include "pch.h"
#include "config.h"

#ifndef CRYPTOPP_IMPORTS

// Win32 has CryptoAPI and <wincrypt.h>. Windows 10 and Windows Store 10 have CNG and <bcrypt.h>.
//  There's a hole for Windows Phone 8 and Windows Store 8. There is no userland RNG available.
//  Also see http://www.drdobbs.com/windows/using-c-and-com-with-winrt/240168150 and
//  http://stackoverflow.com/questions/36974545/random-numbers-for-windows-phone-8-and-windows-store-8 and
//  https://social.msdn.microsoft.com/Forums/vstudio/en-US/25b83e13-c85f-4aa1-a057-88a279ea3fd6/what-crypto-random-generator-c-code-could-use-on-wp81
#if defined(CRYPTOPP_WIN32_AVAILABLE) && !defined(OS_RNG_AVAILABLE)
# pragma message("WARNING: Compiling for Windows but an OS RNG is not available. This is likely a Windows Phone 8 or Windows Store 8 app.")
#endif

#if !defined(NO_OS_DEPENDENCE) && defined(OS_RNG_AVAILABLE)

#include "osrng.h"
#include "rng.h"

// FreeBSD links /dev/urandom -> /dev/random. It showed up when we added
// O_NOFOLLOW to harden the non-blocking generator. Use Arc4Random instead
// for a non-blocking generator. Arc4Random is cryptographic quality prng
// based on ChaCha20. The ChaCha20 generator is seeded from /dev/random,
// so we can't completely avoid the blocking.
// https://www.freebsd.org/cgi/man.cgi?query=arc4random_buf.
#ifdef __FreeBSD__
# define DONT_USE_O_NOFOLLOW 1
# define USE_FREEBSD_ARC4RANDOM 1
# include <stdlib.h>
#endif

// Solaris links /dev/urandom -> ../devices/pseudo/random@0:urandom
// We can't access the device. Avoid O_NOFOLLOW for the platform.
#ifdef __sun
# define DONT_USE_O_NOFOLLOW 1
#endif

// And other OSes that don't define it
#ifndef O_NOFOLLOW
# define DONT_USE_O_NOFOLLOW 1
#endif

#ifdef CRYPTOPP_WIN32_AVAILABLE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifndef ERROR_INCORRECT_SIZE
# define ERROR_INCORRECT_SIZE 0x000005B6
#endif
#if defined(USE_MS_CRYPTOAPI)
#include <wincrypt.h>
#ifndef CRYPT_NEWKEYSET
# define CRYPT_NEWKEYSET 0x00000008
#endif
#ifndef CRYPT_MACHINE_KEYSET
# define CRYPT_MACHINE_KEYSET 0x00000020
#endif
#elif defined(USE_MS_CNGAPI)
#include <bcrypt.h>
#ifndef BCRYPT_SUCCESS
# define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_INVALID_PARAMETER
# define STATUS_INVALID_PARAMETER 0xC000000D
#endif
#ifndef STATUS_INVALID_HANDLE
# define STATUS_INVALID_HANDLE 0xC0000008
#endif
#endif
#endif  // Win32

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

#if defined(USE_MS_CNGAPI)
inline DWORD NtStatusToErrorCode(NTSTATUS status)
{
	if (status == static_cast<NTSTATUS>(STATUS_INVALID_PARAMETER))
		return ERROR_INVALID_PARAMETER;
	else if (status == static_cast<NTSTATUS>(STATUS_INVALID_HANDLE))
		return ERROR_INVALID_HANDLE;
	else
		return static_cast<DWORD>(status);
}
#endif

#if defined(UNICODE) || defined(_UNICODE)
# define CRYPTOPP_CONTAINER L"Crypto++ RNG"
#else
# define CRYPTOPP_CONTAINER "Crypto++ RNG"
#endif

MicrosoftCryptoProvider::MicrosoftCryptoProvider() : m_hProvider(0)
{
#if defined(USE_MS_CRYPTOAPI)
	// See http://support.microsoft.com/en-us/kb/238187 for CRYPT_NEWKEYSET fallback strategy
	if (!CryptAcquireContext(&m_hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		const DWORD firstErr = GetLastError();
		if (!CryptAcquireContext(&m_hProvider, CRYPTOPP_CONTAINER, 0, PROV_RSA_FULL, CRYPT_NEWKEYSET /*user*/) &&
		    !CryptAcquireContext(&m_hProvider, CRYPTOPP_CONTAINER, 0, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET|CRYPT_NEWKEYSET))
		{
			// Set original error with original code
			SetLastError(firstErr);
			throw OS_RNG_Err("CryptAcquireContext");
		}
	}
#elif defined(USE_MS_CNGAPI)
	NTSTATUS ret = BCryptOpenAlgorithmProvider(&m_hProvider, BCRYPT_RNG_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
	if (!(BCRYPT_SUCCESS(ret)))
	{
		// Hack... OS_RNG_Err calls GetLastError()
		SetLastError(NtStatusToErrorCode(ret));
		throw OS_RNG_Err("BCryptOpenAlgorithmProvider");
	}
#endif
}

MicrosoftCryptoProvider::~MicrosoftCryptoProvider()
{
#if defined(USE_MS_CRYPTOAPI)
	if (m_hProvider)
		CryptReleaseContext(m_hProvider, 0);
#elif defined(USE_MS_CNGAPI)
	if (m_hProvider)
		BCryptCloseAlgorithmProvider(m_hProvider, 0);
#endif
}

#endif  // CRYPTOPP_WIN32_AVAILABLE

NonblockingRng::NonblockingRng()
{
#if !defined(CRYPTOPP_WIN32_AVAILABLE) && !defined(USE_FREEBSD_ARC4RANDOM)
# ifndef DONT_USE_O_NOFOLLOW
	const int flags = O_RDONLY|O_NOFOLLOW;
# else
	const int flags = O_RDONLY;
# endif

	m_fd = open("/dev/urandom", flags);
	if (m_fd == -1)
		throw OS_RNG_Err("open /dev/urandom");

#endif
}

NonblockingRng::~NonblockingRng()
{
#if !defined(CRYPTOPP_WIN32_AVAILABLE) && !defined(USE_FREEBSD_ARC4RANDOM)
	close(m_fd);
#endif
}

void NonblockingRng::GenerateBlock(byte *output, size_t size)
{
#ifdef CRYPTOPP_WIN32_AVAILABLE
	// Acquiring a provider is expensive. Do it once and retain the reference.
# if defined(CRYPTOPP_CXX11_STATIC_INIT)
	static const MicrosoftCryptoProvider hProvider = MicrosoftCryptoProvider();
# else
	const MicrosoftCryptoProvider &hProvider = Singleton<MicrosoftCryptoProvider>().Ref();
# endif
# if defined(USE_MS_CRYPTOAPI)
	DWORD dwSize;
	CRYPTOPP_ASSERT(SafeConvert(size, dwSize));
	if (!SafeConvert(size, dwSize))
	{
		SetLastError(ERROR_INCORRECT_SIZE);
		throw OS_RNG_Err("GenerateBlock size");
	}
	BOOL ret = CryptGenRandom(hProvider.GetProviderHandle(), dwSize, output);
	CRYPTOPP_ASSERT(ret != FALSE);
	if (ret == FALSE)
		throw OS_RNG_Err("CryptGenRandom");
# elif defined(USE_MS_CNGAPI)
	ULONG ulSize;
	CRYPTOPP_ASSERT(SafeConvert(size, ulSize));
	if (!SafeConvert(size, ulSize))
	{
		SetLastError(ERROR_INCORRECT_SIZE);
		throw OS_RNG_Err("GenerateBlock size");
	}
	NTSTATUS ret = BCryptGenRandom(hProvider.GetProviderHandle(), output, ulSize, 0);
	CRYPTOPP_ASSERT(BCRYPT_SUCCESS(ret));
	if (!(BCRYPT_SUCCESS(ret)))
	{
		// Hack... OS_RNG_Err calls GetLastError()
		SetLastError(NtStatusToErrorCode(ret));
		throw OS_RNG_Err("BCryptGenRandom");
	}
# endif
#else

# if defined(USE_FREEBSD_ARC4RANDOM)
	// Cryptographic quality prng based on ChaCha20,
	// https://www.freebsd.org/cgi/man.cgi?query=arc4random_buf
	arc4random_buf(output, size);
# else
	while (size)
	{
		ssize_t len = read(m_fd, output, size);
		if (len < 0)
		{
			// /dev/urandom reads CAN give EAGAIN errors! (maybe EINTR as well)
			if (errno != EINTR && errno != EAGAIN)
				throw OS_RNG_Err("read /dev/urandom");

			continue;
		}
		output += len;
		size -= len;
	}
# endif  // USE_FREEBSD_ARC4RANDOM

#endif  // CRYPTOPP_WIN32_AVAILABLE
}

#endif  // NONBLOCKING_RNG_AVAILABLE

// *************************************************************

#ifdef BLOCKING_RNG_AVAILABLE

#ifndef CRYPTOPP_BLOCKING_RNG_FILENAME
# ifdef __OpenBSD__
#  define CRYPTOPP_BLOCKING_RNG_FILENAME "/dev/srandom"
# else
#  define CRYPTOPP_BLOCKING_RNG_FILENAME "/dev/random"
# endif
#endif

BlockingRng::BlockingRng()
{
#ifndef DONT_USE_O_NOFOLLOW
	const int flags = O_RDONLY|O_NOFOLLOW;
#else
	const int flags = O_RDONLY;
#endif

	m_fd = open(CRYPTOPP_BLOCKING_RNG_FILENAME, flags);
	if (m_fd == -1)
		throw OS_RNG_Err("open " CRYPTOPP_BLOCKING_RNG_FILENAME);
}

BlockingRng::~BlockingRng()
{
	close(m_fd);
}

void BlockingRng::GenerateBlock(byte *output, size_t size)
{
	while (size)
	{
		// on some systems /dev/random will block until all bytes
		// are available, on others it returns immediately
		ssize_t len = read(m_fd, output, size);
		if (len < 0)
		{
			// /dev/random reads CAN give EAGAIN errors! (maybe EINTR as well)
			if (errno != EINTR && errno != EAGAIN)
				throw OS_RNG_Err("read " CRYPTOPP_BLOCKING_RNG_FILENAME);

			continue;
		}

		size -= len;
		output += len;
		if (size)
			sleep(1);
	}
}

#endif  // BLOCKING_RNG_AVAILABLE

// *************************************************************

void OS_GenerateRandomBlock(bool blocking, byte *output, size_t size)
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
	IncorporateEntropy(seed, seedSize);
}

NAMESPACE_END

#endif  // OS_RNG_AVAILABLE

#endif  // CRYPTOPP_IMPORTS
