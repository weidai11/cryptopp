// dll.cpp - written and placed in the public domain by Wei Dai

#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES

#include "dll.h"
#pragma warning(default: 4660)

#include <windows.h>

#include "iterhash.cpp"
#include "strciphr.cpp"
#include "algebra.cpp"
#include "eprecomp.cpp"
#include "eccrypto.cpp"
#include "oaep.cpp"

#ifndef CRYPTOPP_IMPORTS

NAMESPACE_BEGIN(CryptoPP)

template<> const byte PKCS_DigestDecoration<SHA>::decoration[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
template<> const unsigned int PKCS_DigestDecoration<SHA>::length = sizeof(PKCS_DigestDecoration<SHA>::decoration);

static const byte s_moduleMac[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE] = "reserved for mac";
static HMODULE s_hModule = NULL;

void DoDllPowerUpSelfTest()
{
	char moduleFileName[MAX_PATH];
	GetModuleFileNameA(s_hModule, moduleFileName, sizeof(moduleFileName));
	CryptoPP::DoPowerUpSelfTest(moduleFileName, s_moduleMac);
}

NAMESPACE_END

#endif

#ifdef CRYPTOPP_EXPORTS

USING_NAMESPACE(CryptoPP)

#if !(defined(_MSC_VER) && (_MSC_VER < 1300))
using std::set_new_handler;
#endif

static PNew s_pNew = NULL;
static PDelete s_pDelete = NULL;

static void * _cdecl New (size_t size)
{
	new_handler newHandler = set_new_handler(NULL);
	if (newHandler)
		set_new_handler(newHandler);

	void *p;
	while (!(p = malloc(size)))
	{
		if (newHandler)
			newHandler();
		else
			throw std::bad_alloc();
	}

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

void * _cdecl operator new (size_t size)
{
	if (!s_pNew)
		SetNewAndDeleteFunctionPointers();

	return s_pNew(size);
}

void _cdecl operator delete (void * p)
{
	s_pDelete(p);
}

BOOL APIENTRY DllMain(HANDLE hModule, 
                      DWORD  ul_reason_for_call, 
                      LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		s_hModule = (HMODULE)hModule;
		DoDllPowerUpSelfTest();
	}
    return TRUE;
}

#endif	// #ifdef CRYPTOPP_EXPORTS
