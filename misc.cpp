// misc.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "misc.h"
#include "words.h"
#include <new>

NAMESPACE_BEGIN(CryptoPP)

void xorbuf(byte *buf, const byte *mask, size_t count)
{
	size_t i;

	if (IsAligned<word32>(buf) && IsAligned<word32>(mask))
	{
		if (!CRYPTOPP_BOOL_SLOW_WORD64 && IsAligned<word64>(buf) && IsAligned<word64>(mask))
		{
			for (i=0; i<count/8; i++)
				((word64*)buf)[i] ^= ((word64*)mask)[i];
			count -= 8*i;
			if (!count)
				return;
			buf += 8*i;
			mask += 8*i;
		}

		for (i=0; i<count/4; i++)
			((word32*)buf)[i] ^= ((word32*)mask)[i];
		count -= 4*i;
		if (!count)
			return;
		buf += 4*i;
		mask += 4*i;
	}

	for (i=0; i<count; i++)
		buf[i] ^= mask[i];
}

void xorbuf(byte *output, const byte *input, const byte *mask, size_t count)
{
	size_t i;

	if (IsAligned<word32>(output) && IsAligned<word32>(input) && IsAligned<word32>(mask))
	{
		if (!CRYPTOPP_BOOL_SLOW_WORD64 && IsAligned<word64>(output) && IsAligned<word64>(input) && IsAligned<word64>(mask))
		{
			for (i=0; i<count/8; i++)
				((word64*)output)[i] = ((word64*)input)[i] ^ ((word64*)mask)[i];
			count -= 8*i;
			if (!count)
				return;
			output += 8*i;
			input += 8*i;
			mask += 8*i;
		}

		for (i=0; i<count/4; i++)
			((word32*)output)[i] = ((word32*)input)[i] ^ ((word32*)mask)[i];
		count -= 4*i;
		if (!count)
			return;
		output += 4*i;
		input += 4*i;
		mask += 4*i;
	}

	for (i=0; i<count; i++)
		output[i] = input[i] ^ mask[i];
}

bool VerifyBufsEqual(const byte *buf, const byte *mask, size_t count)
{
	size_t i;
	byte acc8 = 0;

	if (IsAligned<word32>(buf) && IsAligned<word32>(mask))
	{
		word32 acc32 = 0;
		if (!CRYPTOPP_BOOL_SLOW_WORD64 && IsAligned<word64>(buf) && IsAligned<word64>(mask))
		{
			word64 acc64 = 0;
			for (i=0; i<count/8; i++)
				acc64 |= ((word64*)buf)[i] ^ ((word64*)mask)[i];
			count -= 8*i;
			if (!count)
				return acc64 == 0;
			buf += 8*i;
			mask += 8*i;
			acc32 = word32(acc64) | word32(acc64>>32);
		}

		for (i=0; i<count/4; i++)
			acc32 |= ((word32*)buf)[i] ^ ((word32*)mask)[i];
		count -= 4*i;
		if (!count)
			return acc32 == 0;
		buf += 4*i;
		mask += 4*i;
		acc8 = byte(acc32) | byte(acc32>>8) | byte(acc32>>16) | byte(acc32>>24);
	}

	for (i=0; i<count; i++)
		acc8 |= buf[i] ^ mask[i];
	return acc8 == 0;
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
