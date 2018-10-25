// hc256.cpp - written and placed in the public domain by Jeffrey Walton
//             based on public domain code by Hongjun Wu.
//
//             The reference materials and source files are available at
//             The eSTREAM Project, http://www.ecrypt.eu.org/stream/hc256.html.

#include "pch.h"
#include "config.h"

#include "hc256.h"
#include "secblock.h"
#include "misc.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::rotrConstant;

inline word32 f1(word32 x)
{
	return rotrConstant<7>(x) ^ rotrConstant<18>(x) ^ (x >> 3);
}

inline word32 f2(word32 x)
{
	return rotrConstant<17>(x) ^ rotrConstant<19>(x) ^ (x >> 10);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

inline word32 HC256Policy::H1(word32 u)
{
	word32 tem;
	byte a, b, c, d;
	a = (byte)(u);
	b = (byte)(u >> 8);
	c = (byte)(u >> 16);
	d = (byte)(u >> 24);
	tem = m_Q[a] + m_Q[256 + b] + m_Q[512 + c] + m_Q[768 + d];
	return (tem);
}

inline word32 HC256Policy::H2(word32 u)
{
	word32 tem;
	byte a, b, c, d;
	a = (byte)(u);
	b = (byte)(u >> 8);
	c = (byte)(u >> 16);
	d = (byte)(u >> 24);
	tem = m_P[a] + m_P[256 + b] + m_P[512 + c] + m_P[768 + d];
	return (tem);
}

inline word32 HC256Policy::Generate() /*one step of the cipher*/
{
	word32 i, i3, i10, i12, i1023;
	word32 output;

	i = m_ctr & 0x3ff;
	i3 = (i - 3) & 0x3ff;
	i10 = (i - 10) & 0x3ff;
	i12 = (i - 12) & 0x3ff;
	i1023 = (i - 1023) & 0x3ff;

	if (m_ctr < 1024) {
		m_P[i] = m_P[i] + m_P[i10] + (rotrConstant<10>(m_P[i3]) ^ rotrConstant<23>(m_P[i1023])) + m_Q[(m_P[i3] ^ m_P[i1023]) & 0x3ff];
		output = H1(m_P[i12]) ^ m_P[i];
	}
	else {
		m_Q[i] = m_Q[i] + m_Q[i10] + (rotrConstant<10>(m_Q[i3]) ^ rotrConstant<23>(m_Q[i1023])) + m_P[(m_Q[i3] ^ m_Q[i1023]) & 0x3ff];
		output = H2(m_Q[i12]) ^ m_Q[i];
	}
	m_ctr = (m_ctr + 1) & 0x7ff;
	return (output);
}

void HC256Policy::CipherSetKey(const NameValuePairs &params, const byte *userKey, size_t keylen)
{
	CRYPTOPP_UNUSED(params); CRYPTOPP_UNUSED(keylen);
	CRYPTOPP_ASSERT(keylen == 32);

	for (unsigned int i = 0; i < 8; i++)
		m_key[i] = 0;

	for (unsigned int i = 0; i < 32; i++)
	{
		m_key[i >> 2] = m_key[i >> 2] | userKey[i];
		m_key[i >> 2] = rotlConstant<8>(m_key[i >> 2]);
	}
}

void HC256Policy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount)
{
	while (iterationCount--)
	{
		PutWord(false, LITTLE_ENDIAN_ORDER, output +  0, Generate());
		PutWord(false, LITTLE_ENDIAN_ORDER, output +  4, Generate());
		PutWord(false, LITTLE_ENDIAN_ORDER, output +  8, Generate());
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 12, Generate());

		// If AdditiveCipherTemplate does not have an accumulated keystream
		//  then it will ask OperateKeystream to generate one. Optionally it
		//  will ask for an XOR of the input with the keystream while
		//  writing the result to the output buffer. In all cases the
		//  keystream is written to the output buffer. The optional part is
		//  adding the input buffer and keystream.
		if ((operation & INPUT_NULL) != INPUT_NULL)
		{
			xorbuf(output, input, BYTES_PER_ITERATION);
			input += BYTES_PER_ITERATION;
		}

		output += BYTES_PER_ITERATION;
	}
}

void HC256Policy::CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length)
{
	CRYPTOPP_UNUSED(keystreamBuffer); CRYPTOPP_UNUSED(length);
	CRYPTOPP_ASSERT(length == 32);

	/* initialize the iv */
	word32 W[2560];
	for (unsigned int i = 0; i < 8; i++)
		m_iv[i] = 0;

	for (unsigned int i = 0; i < 32; i++)
	{
		m_iv[i >> 2] = m_iv[i >> 2] | iv[i];
		m_iv[i >> 2] = rotlConstant<8>(m_iv[i >> 2]);
	}

	/* setup the table P and Q */

	for (unsigned int i = 0; i < 8; i++)
		W[i] = m_key[i];
	for (unsigned int i = 8; i < 16; i++)
		W[i] = m_iv[i - 8];

	for (unsigned int i = 16; i < 2560; i++)
		W[i] = f2(W[i - 2]) + W[i - 7] + f1(W[i - 15]) + W[i - 16] + i;

	for (unsigned int i = 0; i < 1024; i++)
		m_P[i] = W[i + 512];
	for (unsigned int i = 0; i < 1024; i++)
		m_Q[i] = W[i + 1536];

	m_ctr = 0;

	/* run the cipher 4096 steps before generating the output */
	for (unsigned int i = 0; i < 4096; i++)
		Generate();
}

NAMESPACE_END
