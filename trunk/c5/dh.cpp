// dh.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "dh.h"

NAMESPACE_BEGIN(CryptoPP)

void DH_TestInstantiations()
{
	DH dh1;
	DH dh2(NullRNG(), 10);
}

NAMESPACE_END
