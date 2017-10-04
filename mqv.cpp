// mqv.cpp - originally written and placed in the public domain by Wei Dai
//           HMQV provided by Jeffrey Walton, Ray Clayton and Uri Blumenthal.
//           FHMQV provided by Uri Blumenthal.

#include "pch.h"
#include "mqv.h"
#include "hmqv.h"
#include "fhmqv.h"

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_TEST_INSTANTIATIONS)
void TestInstantiations_MQV()
{
	MQV mqv;
}

void TestInstantiations_HMQV()
{
    HMQV hmqv;
}

void TestInstantiations_FHMQV()
{
    FHMQV fhmqv;
}
#endif

NAMESPACE_END
