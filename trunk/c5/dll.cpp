// dll.cpp - written and placed in the public domain by Wei Dai

#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#define CRYPTOPP_DEFAULT_NO_DLL

#include "dll.h"
#pragma warning(default: 4660)

#ifdef CRYPTOPP_WIN32_AVAILABLE
#include <windows.h>
#endif

#include "iterhash.cpp"
#include "strciphr.cpp"
#include "algebra.cpp"
#include "eprecomp.cpp"
#include "eccrypto.cpp"

#ifndef CRYPTOPP_IMPORTS

NAMESPACE_BEGIN(CryptoPP)

template<> const byte PKCS_DigestDecoration<SHA>::decoration[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
template<> const unsigned int PKCS_DigestDecoration<SHA>::length = sizeof(PKCS_DigestDecoration<SHA>::decoration);

NAMESPACE_END

#endif

#ifdef CRYPTOPP_EXPORTS

USING_NAMESPACE(CryptoPP)

#if !(defined(_MSC_VER) && (_MSC_VER < 1300))
using std::set_new_handler;
#endif

static PNew s_pNew = NULL;
static PDelete s_pDelete = NULL;

static void * CRYPTOPP_CDECL New (size_t size)
{
	void *p;
	while (!(p = malloc(size)))
		CallNewHandler();

	return p;
}

static void SetNewAndDeleteFunctionPointers()
{
	void *p = NULL;
	HMODULE hModule = NULL;
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

	hModule = GetModuleHandle("msvcrtd");
	if (!hModule)
		hModule = GetModuleHandle("msvcrt");
	if (hModule)
	{
		s_pNew = (PNew)GetProcAddress(hModule, "??2@YAPAXI@Z");		// operator new
		s_pDelete = (PDelete)GetProcAddress(hModule, "??3@YAXPAX@Z");	// operator delete
		return;
	}

	OutputDebugString("Crypto++ was not able to obtain new and delete function pointers.\n");
	throw 0;
}

void * CRYPTOPP_CDECL operator new (size_t size)
{
	if (!s_pNew)
		SetNewAndDeleteFunctionPointers();

	return s_pNew(size);
}

void CRYPTOPP_CDECL operator delete (void * p)
{
	s_pDelete(p);
}

#endif	// #ifdef CRYPTOPP_EXPORTS
