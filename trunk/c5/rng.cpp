// rng.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#include "rng.h"

#include <time.h>
#include <math.h>

NAMESPACE_BEGIN(CryptoPP)

// linear congruential generator
// originally by William S. England

// do not use for cryptographic purposes

/*
** Original_numbers are the original published m and q in the
** ACM article above.  John Burton has furnished numbers for
** a reportedly better generator.  The new numbers are now
** used in this program by default.
*/

#ifndef LCRNG_ORIGINAL_NUMBERS
const word32 LC_RNG::m=2147483647L;
const word32 LC_RNG::q=44488L;

const word16 LC_RNG::a=(unsigned int)48271L;
const word16 LC_RNG::r=3399;
#else
const word32 LC_RNG::m=2147483647L;
const word32 LC_RNG::q=127773L;

const word16 LC_RNG::a=16807;
const word16 LC_RNG::r=2836;
#endif

byte LC_RNG::GenerateByte()
{
	word32 hi = seed/q;
	word32 lo = seed%q;

	long test = a*lo - r*hi;

	if (test > 0)
		seed = test;
	else
		seed = test+ m;

	return (GETBYTE(seed, 0) ^ GETBYTE(seed, 1) ^ GETBYTE(seed, 2) ^ GETBYTE(seed, 3));
}

// ********************************************************

#ifndef CRYPTOPP_IMPORTS

X917RNG::X917RNG(BlockTransformation *c, const byte *seed, unsigned long deterministicTimeVector)
	: cipher(c),
	  S(cipher->BlockSize()),
	  dtbuf(S),
	  randseed(seed, S),
	  randbuf(S),
	  randbuf_counter(0),
	  m_deterministicTimeVector(deterministicTimeVector)
{
	if (m_deterministicTimeVector)
	{
		memset(dtbuf, 0, S);
		memcpy(dtbuf, (byte *)&m_deterministicTimeVector, STDMIN((int)sizeof(m_deterministicTimeVector), S));
	}
	else
	{
		time_t tstamp1 = time(0);
		xorbuf(dtbuf, (byte *)&tstamp1, STDMIN((int)sizeof(tstamp1), S));
		cipher->ProcessBlock(dtbuf);
		clock_t tstamp2 = clock();
		xorbuf(dtbuf, (byte *)&tstamp2, STDMIN((int)sizeof(tstamp2), S));
		cipher->ProcessBlock(dtbuf);
	}
}

byte X917RNG::GenerateByte()
{
	if (randbuf_counter==0)
	{
		// calculate new enciphered timestamp
		if (m_deterministicTimeVector)
		{
			xorbuf(dtbuf, (byte *)&m_deterministicTimeVector, STDMIN((int)sizeof(m_deterministicTimeVector), S));
			while (++m_deterministicTimeVector == 0) {}	// skip 0
		}
		else
		{
			clock_t tstamp = clock();
			xorbuf(dtbuf, (byte *)&tstamp, STDMIN((int)sizeof(tstamp), S));
		}
		cipher->ProcessBlock(dtbuf);

		// combine enciphered timestamp with seed
		xorbuf(randseed, dtbuf, S);

		// generate a new block of random bytes
		cipher->ProcessBlock(randseed, randbuf);

		// compute new seed vector
		for (int i=0; i<S; i++)
			randseed[i] = randbuf[i] ^ dtbuf[i];
		cipher->ProcessBlock(randseed);

		randbuf_counter=S;
	}
	return(randbuf[--randbuf_counter]);
}

#endif

MaurerRandomnessTest::MaurerRandomnessTest()
	: sum(0.0), n(0)
{
	for (unsigned i=0; i<V; i++)
		tab[i] = 0;
}

unsigned int MaurerRandomnessTest::Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
{
	while (length--)
	{
		byte inByte = *inString++;
		if (n >= Q)
			sum += log(double(n - tab[inByte]));
		tab[inByte] = n;
		n++;
	}
	return 0;
}

double MaurerRandomnessTest::GetTestValue() const
{
	if (BytesNeeded() > 0)
		throw Exception(Exception::OTHER_ERROR, "MaurerRandomnessTest: " + IntToString(BytesNeeded()) + " more bytes of input needed");

	double fTu = (sum/(n-Q))/log(2.0);	// this is the test value defined by Maurer

	double value = fTu * 0.1392;		// arbitrarily normalize it to
	return value > 1.0 ? 1.0 : value;	// a number between 0 and 1
}

NAMESPACE_END
