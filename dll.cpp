// dll.cpp - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_IMPORTS

#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES

#include "dll.h"
#pragma warning(default: 4660)

#include <windows.h>
#include <new.h>

#include "strciphr.cpp"
#include "algebra.cpp"
#include "eprecomp.cpp"
#include "eccrypto.cpp"
#include "iterhash.cpp"
#include "oaep.cpp"

static const byte s_moduleMac[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE] = "reserved for mac";
static HMODULE s_hModule = NULL;

NAMESPACE_BEGIN(CryptoPP)

template<> const byte PKCS_DigestDecoration<SHA>::decoration[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
template<> const unsigned int PKCS_DigestDecoration<SHA>::length = sizeof(PKCS_DigestDecoration<SHA>::decoration);

void DoDllPowerUpSelfTest()
{
	char moduleFileName[_MAX_PATH];
	GetModuleFileNameA(s_hModule, moduleFileName, sizeof(moduleFileName));
	CryptoPP::DoPowerUpSelfTest(moduleFileName, s_moduleMac);
}

NAMESPACE_END

#endif

#ifdef CRYPTOPP_EXPORTS

USING_NAMESPACE(CryptoPP)

static PNew s_pNew = NULL;
static PDelete s_pDelete = NULL;

void * _cdecl operator new (size_t size)
{
	if (!s_pNew)
	{
		HMODULE hExe = GetModuleHandle(NULL);
		PGetNewAndDelete pGetNewAndDelete = (PGetNewAndDelete)GetProcAddress(hExe, "GetNewAndDeleteForCryptoPP");
		if (pGetNewAndDelete)
			pGetNewAndDelete(s_pNew, s_pDelete);
		else
		{
			PSetNewAndDelete pSetNewAndDelete = (PSetNewAndDelete)GetProcAddress(hExe, "SetNewAndDeleteFromCryptoPP");
			if (pSetNewAndDelete)
			{
				_set_new_mode(1);
				s_pNew = &malloc;
				s_pDelete = &free;
				pSetNewAndDelete(s_pNew, s_pDelete, &_set_new_handler);
			}
			else
			{
				HMODULE hCrt = GetModuleHandle("msvcrtd");
				if (!hCrt)
					hCrt = GetModuleHandle("msvcrt");
				if (hCrt)
				{
					s_pNew = (PNew)GetProcAddress(hCrt, "??2@YAPAXI@Z");		// operator new
					s_pDelete = (PDelete)GetProcAddress(hCrt, "??3@YAXPAX@Z");	// operator delete
				}
			}
		}

		if (!s_pNew || !s_pDelete)
			OutputDebugString("Crypto++ was not able to obtain new and delete function pointers.");
	}
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

#endif
