// dh.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "dh.h"

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_TEST_INSTANTIATIONS)
void DH_TestInstantiations()
{
	DH dh1;
	DH dh2(NullRNG(), 10);
}
#endif

NAMESPACE_END

#endif
