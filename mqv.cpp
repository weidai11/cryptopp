// mqv.cpp - originally written and placed in the public domain by Wei Dai
//           HMQV provided by Jeffrey Walton, Ray Clayton and Uri Blumenthal.
//           FHMQV provided by Uri Blumenthal.

#include "pch.h"
#include "config.h"
#include "mqv.h"
#include "hmqv.h"
#include "fhmqv.h"

// Squash MS LNK4221 and libtool warnings
extern const char MQV_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
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
