// dll.cpp - originally written and placed in the public domain by Wei Dai

#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#define CRYPTOPP_DEFAULT_NO_DLL

#include "dll.h"
#include "config.h"
#include "iterhash.h"
#include "pkcspad.h"
#include "emsa2.h"

#if defined(CRYPTOPP_MSC_VERSION)
// Cast from FARPROC to funcptr with args, http://stackoverflow.com/q/4192058/608639
# pragma warning(disable: 4191)
#endif

#if defined(CRYPTOPP_EXPORTS) && defined(CRYPTOPP_WIN32_AVAILABLE)
# include <windows.h>
#endif

#ifndef CRYPTOPP_IMPORTS

NAMESPACE_BEGIN(CryptoPP)

// Guarding based on DLL due to Clang, http://github.com/weidai11/cryptopp/issues/300
#ifdef CRYPTOPP_IS_DLL
template<> const byte PKCS_DigestDecoration<SHA1>::decoration[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
template<> const unsigned int PKCS_DigestDecoration<SHA1>::length = sizeof(PKCS_DigestDecoration<SHA1>::decoration);

template<> const byte PKCS_DigestDecoration<SHA224>::decoration[] = {0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1c};
template<> const unsigned int PKCS_DigestDecoration<SHA224>::length = sizeof(PKCS_DigestDecoration<SHA224>::decoration);

template<> const byte PKCS_DigestDecoration<SHA256>::decoration[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
template<> const unsigned int PKCS_DigestDecoration<SHA256>::length = sizeof(PKCS_DigestDecoration<SHA256>::decoration);

template<> const byte PKCS_DigestDecoration<SHA384>::decoration[] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
template<> const unsigned int PKCS_DigestDecoration<SHA384>::length = sizeof(PKCS_DigestDecoration<SHA384>::decoration);

template<> const byte PKCS_DigestDecoration<SHA512>::decoration[] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};
template<> const unsigned int PKCS_DigestDecoration<SHA512>::length = sizeof(PKCS_DigestDecoration<SHA512>::decoration);

// http://github.com/weidai11/cryptopp/issues/517. OIDs and encoded prefixes found at
// http://www.ietf.org/archive/id/draft-jivsov-openpgp-sha3-01.txt
template<> const byte PKCS_DigestDecoration<SHA3_256>::decoration[] = {0x30,0x31,0x30,0x0d, 0x06,0x09,0x60,0x86, 0x48,0x01,0x65,0x03, 0x04,0x02,0x08,0x05, 0x00,0x04,0x20};
template<> const unsigned int PKCS_DigestDecoration<SHA3_256>::length = (unsigned int)sizeof(PKCS_DigestDecoration<SHA3_256>::decoration);

template<> const byte PKCS_DigestDecoration<SHA3_384>::decoration[] = {0x30,0x41,0x30,0x0d, 0x06,0x09,0x60,0x86, 0x48,0x01,0x65,0x03, 0x04,0x02,0x09,0x05, 0x00,0x04,0x30};
template<> const unsigned int PKCS_DigestDecoration<SHA3_384>::length = (unsigned int)sizeof(PKCS_DigestDecoration<SHA3_384>::decoration);

template<> const byte PKCS_DigestDecoration<SHA3_512>::decoration[] = {0x30,0x51,0x30,0x0d, 0x06,0x09,0x60,0x86, 0x48,0x01,0x65,0x03, 0x04,0x02,0x0a,0x05, 0x00,0x04,0x40};
template<> const unsigned int PKCS_DigestDecoration<SHA3_512>::length = (unsigned int)sizeof(PKCS_DigestDecoration<SHA3_512>::decoration);

template<> const byte EMSA2HashId<SHA1>::id = 0x33;
template<> const byte EMSA2HashId<SHA224>::id = 0x38;
template<> const byte EMSA2HashId<SHA256>::id = 0x34;
template<> const byte EMSA2HashId<SHA384>::id = 0x36;
template<> const byte EMSA2HashId<SHA512>::id = 0x35;

#endif	// CRYPTOPP_IS_DLL

NAMESPACE_END

#endif

#ifdef CRYPTOPP_EXPORTS

USING_NAMESPACE(CryptoPP)

using std::set_new_handler;

static PNew s_pNew = NULLPTR;
static PDelete s_pDelete = NULLPTR;

static void * New (size_t size)
{
	void *p;
	while ((p = malloc(size)) == NULLPTR)
		CallNewHandler();

	return p;
}

static void SetNewAndDeleteFunctionPointers()
{
	void *p = NULLPTR;
	HMODULE hModule = NULLPTR;
	MEMORY_BASIC_INFORMATION mbi;

	while (true)
	{
		VirtualQuery(p, &mbi, sizeof(mbi));

		if (p >= (char *)mbi.BaseAddress + mbi.RegionSize)
			break;

		p = (char *)mbi.BaseAddress + mbi.RegionSize;

		if (!mbi.AllocationBase || mbi.AllocationBase == hModule)
			continue;

		hModule = HMODULE(mbi.AllocationBase);
		PGetNewAndDelete pGetNewAndDelete = (PGetNewAndDelete)GetProcAddress(hModule, "GetNewAndDeleteForCryptoPP");
		if (pGetNewAndDelete)
		{
			pGetNewAndDelete(s_pNew, s_pDelete);
			return;
		}

		PSetNewAndDelete pSetNewAndDelete = (PSetNewAndDelete)GetProcAddress(hModule, "SetNewAndDeleteFromCryptoPP");
		if (pSetNewAndDelete)
		{
			s_pNew = &New;
			s_pDelete = &free;
			pSetNewAndDelete(s_pNew, s_pDelete, &set_new_handler);
			return;
		}
	}

	// try getting these directly using mangled names of new and delete operators

	hModule = GetModuleHandle("msvcrtd");
	if (!hModule)
		hModule = GetModuleHandle("msvcrt");
	if (hModule)
	{
		// 32-bit versions
		s_pNew = (PNew)GetProcAddress(hModule, "??2@YAPAXI@Z");
		s_pDelete = (PDelete)GetProcAddress(hModule, "??3@YAXPAX@Z");
		if (s_pNew && s_pDelete)
			return;

		// 64-bit versions
		s_pNew = (PNew)GetProcAddress(hModule, "??2@YAPEAX_K@Z");
		s_pDelete = (PDelete)GetProcAddress(hModule, "??3@YAXPEAX@Z");
		if (s_pNew && s_pDelete)
			return;
	}

	OutputDebugStringA("Crypto++ DLL was not able to obtain new and delete function pointers.\n");
	throw 0;
}

// Cast from FARPROC to funcptr with args
#pragma warning(default: 4191)

void * operator new (size_t size)
{
	if (!s_pNew)
		SetNewAndDeleteFunctionPointers();

	return s_pNew(size);
}

void operator delete (void * p)
{
	s_pDelete(p);
}

void * operator new [] (size_t size)
{
	return operator new (size);
}

void operator delete [] (void * p)
{
	operator delete (p);
}

#endif	// CRYPTOPP_EXPORTS
