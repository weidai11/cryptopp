// misc.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "misc.h"
#include "words.h"
#include <new>

NAMESPACE_BEGIN(CryptoPP)

void xorbuf(byte *buf, const byte *mask, size_t count)
{
	if (((size_t)buf | (size_t)mask | count) % WORD_SIZE == 0)
		XorWords((word *)buf, (const word *)mask, count/WORD_SIZE);
	else
	{
		for (unsigned int i=0; i<count; i++)
			buf[i] ^= mask[i];
	}
}

void xorbuf(byte *output, const byte *input, const byte *mask, size_t count)
{
	if (((size_t)output | (size_t)input | (size_t)mask | count) % WORD_SIZE == 0)
		XorWords((word *)output, (const word *)input, (const word *)mask, count/WORD_SIZE);
	else
	{
		for (unsigned int i=0; i<count; i++)
			output[i] = input[i] ^ mask[i];
	}
}

#if !(defined(_MSC_VER) && (_MSC_VER < 1300))
using std::new_handler;
using std::set_new_handler;
#endif

void CallNewHandler()
{
	new_handler newHandler = set_new_handler(NULL);
	if (newHandler)
		set_new_handler(newHandler);

	if (newHandler)
		newHandler();
	else
		throw std::bad_alloc();
}

NAMESPACE_END

#endif
