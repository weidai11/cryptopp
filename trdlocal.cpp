// trdlocal.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "config.h"

#ifndef CRYPTOPP_IMPORTS

#if !defined(NO_OS_DEPENDENCE) && defined(THREADS_AVAILABLE)

#include "trdlocal.h"
#include "stdcpp.h"

#ifdef HAS_WINTHREADS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#if CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE
# pragma GCC diagnostic ignored "-Wc++11-compat"
#endif

NAMESPACE_BEGIN(CryptoPP)

ThreadLocalStorage::Err::Err(const std::string& operation, int error)
	: OS_Error(OTHER_ERROR, "ThreadLocalStorage: " + operation + " operation failed with error 0x" + IntToString(error, 16), operation, error)
{
}

// Windows: "a process may have up to TLS_MINIMUM_AVAILABLE indexes (guaranteed to be greater than
// or equal to 64)", https://support.microsoft.com/en-us/help/94804/info-thread-local-storage-overview
ThreadLocalStorage::ThreadLocalStorage()
{
#ifdef HAS_WINTHREADS
	m_index = TlsAlloc();
	CRYPTOPP_ASSERT(m_index != TLS_OUT_OF_INDEXES);
	if (m_index == TLS_OUT_OF_INDEXES)
		throw Err("TlsAlloc", GetLastError());
#else
	m_index = 0;
	int error = pthread_key_create(&m_index, NULLPTR);
	CRYPTOPP_ASSERT(!error);
	if (error)
		throw Err("pthread_key_create", error);
#endif
}

ThreadLocalStorage::~ThreadLocalStorage() CRYPTOPP_THROW
{
#if defined(CRYPTOPP_CXX17_EXCEPTIONS)
	if (std::uncaught_exceptions() == 0)
#elif defined(CRYPTOPP_UNCAUGHT_EXCEPTION_AVAILABLE)
	if (std::uncaught_exception() == false)
#else
	try
#endif
#ifdef HAS_WINTHREADS
	{
		int rc = TlsFree(m_index);
		CRYPTOPP_ASSERT(rc);
		if (!rc)
			throw Err("TlsFree", GetLastError());
	}
#else
	{
		int error = pthread_key_delete(m_index);
		CRYPTOPP_ASSERT(!error);
		if (error)
			throw Err("pthread_key_delete", error);
	}
#endif
#if !defined(CRYPTOPP_CXX17_EXCEPTIONS) && !defined(CRYPTOPP_UNCAUGHT_EXCEPTION_AVAILABLE)
	catch(const Exception&)
	{
	}
#endif
}

void ThreadLocalStorage::SetValue(void *value)
{
#ifdef HAS_WINTHREADS
	if (!TlsSetValue(m_index, value))
		throw Err("TlsSetValue", GetLastError());
#else
	int error = pthread_setspecific(m_index, value);
	if (error)
		throw Err("pthread_key_getspecific", error);
#endif
}

void *ThreadLocalStorage::GetValue() const
{
#ifdef HAS_WINTHREADS
	void *result = TlsGetValue(m_index);
	const DWORD dwRet = GetLastError();

	CRYPTOPP_ASSERT(result || (!result && (dwRet == NO_ERROR)));
	if (!result && dwRet != NO_ERROR)
		throw Err("TlsGetValue", dwRet);
#else
	// Null is a valid return value. Posix does not provide a way to
	//  check for a "good" Null vs a "bad" Null (errno is not set).
	void *result = pthread_getspecific(m_index);
#endif
	return result;
}

NAMESPACE_END

#endif	// THREADS_AVAILABLE
#endif  // CRYPTOPP_IMPORTS
