// rabbit.cpp - written and placed in the public domain by Jeffrey Walton
//              based on public domain code by Martin Boesgaard, Mette Vesterager,
//              Thomas Pedersen, Jesper Christiansen and Ove Scavenius.
//
//              The reference materials and source files are available at
//              The eSTREAM Project, http://www.ecrypt.eu.org/stream/e2-rabbit.html.

#include "pch.h"
#include "config.h"

#include "rabbit.h"
#include "secblock.h"
#include "misc.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlConstant;

word32 G_func(word32 x)
{
#if 0
	/* Temporary variables */
	word32 a, b, h, l;

	/* Construct high and low argument for squaring */
	a = x & 0xFFFF;
	b = x >> 16;

	/* Calculate high and low result of squaring */
	h = (((static_cast<word32>(a*a) >> 17U) + static_cast<word32>(a*b)) >> 15U) + b*b;
	l = x*x;

	/* Return high XOR low */
	return static_cast<word32>(h^l);
#endif

	// Thanks to Jack Lloyd for suggesting the 64-bit multiply.
	word64 z = x;
	z *= x;
	return static_cast<word32>((z >> 32) ^ z);
}

word32 NextState(word32 c[8], word32 x[8], word32 carry)
{
	/* Temporary variables */
	word32 g[8], c_old[8], i;

	/* Save old counter values */
	for (i = 0; i<8; i++)
		c_old[i] = c[i];

	/* Calculate new counter values */
	c[0] = static_cast<word32>(c[0] + 0x4D34D34D + carry);
	c[1] = static_cast<word32>(c[1] + 0xD34D34D3 + (c[0] < c_old[0]));
	c[2] = static_cast<word32>(c[2] + 0x34D34D34 + (c[1] < c_old[1]));
	c[3] = static_cast<word32>(c[3] + 0x4D34D34D + (c[2] < c_old[2]));
	c[4] = static_cast<word32>(c[4] + 0xD34D34D3 + (c[3] < c_old[3]));
	c[5] = static_cast<word32>(c[5] + 0x34D34D34 + (c[4] < c_old[4]));
	c[6] = static_cast<word32>(c[6] + 0x4D34D34D + (c[5] < c_old[5]));
	c[7] = static_cast<word32>(c[7] + 0xD34D34D3 + (c[6] < c_old[6]));
	carry = (c[7] < c_old[7]);

	/* Calculate the g-values */
	for (i = 0; i<8; i++)
		g[i] = G_func(static_cast<word32>(x[i] + c[i]));

	/* Calculate new state values */
	x[0] = static_cast<word32>(g[0] + rotlConstant<16>(g[7]) + rotlConstant<16>(g[6]));
	x[1] = static_cast<word32>(g[1] + rotlConstant<8>(g[0]) + g[7]);
	x[2] = static_cast<word32>(g[2] + rotlConstant<16>(g[1]) + rotlConstant<16>(g[0]));
	x[3] = static_cast<word32>(g[3] + rotlConstant<8>(g[2]) + g[1]);
	x[4] = static_cast<word32>(g[4] + rotlConstant<16>(g[3]) + rotlConstant<16>(g[2]));
	x[5] = static_cast<word32>(g[5] + rotlConstant<8>(g[4]) + g[3]);
	x[6] = static_cast<word32>(g[6] + rotlConstant<16>(g[5]) + rotlConstant<16>(g[4]));
	x[7] = static_cast<word32>(g[7] + rotlConstant<8>(g[6]) + g[5]);

	return carry;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void RabbitPolicy::CipherSetKey(const NameValuePairs &params, const byte *userKey, size_t keylen)
{
	/* Generate four subkeys */
	CRYPTOPP_UNUSED(params);
	GetUserKey(LITTLE_ENDIAN_ORDER, m_t.begin(), 4, userKey, keylen);

	/* Generate initial state variables */
	m_mx[0] = m_t[0];
	m_mx[2] = m_t[1];
	m_mx[4] = m_t[2];
	m_mx[6] = m_t[3];
	m_mx[1] = static_cast<word32>(m_t[3] << 16) | (m_t[2] >> 16);
	m_mx[3] = static_cast<word32>(m_t[0] << 16) | (m_t[3] >> 16);
	m_mx[5] = static_cast<word32>(m_t[1] << 16) | (m_t[0] >> 16);
	m_mx[7] = static_cast<word32>(m_t[2] << 16) | (m_t[1] >> 16);

	/* Generate initial counter values */
	m_mc[0] = rotlConstant<16>(m_t[2]);
	m_mc[2] = rotlConstant<16>(m_t[3]);
	m_mc[4] = rotlConstant<16>(m_t[0]);
	m_mc[6] = rotlConstant<16>(m_t[1]);
	m_mc[1] = (m_t[0] & 0xFFFF0000) | (m_t[1] & 0xFFFF);
	m_mc[3] = (m_t[1] & 0xFFFF0000) | (m_t[2] & 0xFFFF);
	m_mc[5] = (m_t[2] & 0xFFFF0000) | (m_t[3] & 0xFFFF);
	m_mc[7] = (m_t[3] & 0xFFFF0000) | (m_t[0] & 0xFFFF);

	/* Clear carry bit */
	m_mcy = 0;

	/* Iterate the system four times */
	for (unsigned int i = 0; i<4; i++)
		m_mcy = NextState(m_mc, m_mx, m_mcy);

	/* Modify the counters */
	for (unsigned int i = 0; i<8; i++)
		m_mc[i] ^= m_mx[(i + 4) & 0x7];

	/* Copy master instance to work instance */
	for (unsigned int i = 0; i<8; i++)
	{
		m_wx[i] = m_mx[i];
		m_wc[i] = m_mc[i];
	}
	m_wcy = m_mcy;
}

void RabbitPolicy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount)
{
	byte* out = output;
	for (size_t i = 0; i<iterationCount; ++i, out += 16)
	{
		/* Iterate the system */
		m_wcy = NextState(m_wc, m_wx, m_wcy);

		/* Encrypt/decrypt 16 bytes of data */
		PutWord(false, LITTLE_ENDIAN_ORDER, out +  0, m_wx[0] ^ (m_wx[5] >> 16) ^ (m_wx[3] << 16));
		PutWord(false, LITTLE_ENDIAN_ORDER, out +  4, m_wx[2] ^ (m_wx[7] >> 16) ^ (m_wx[5] << 16));
		PutWord(false, LITTLE_ENDIAN_ORDER, out +  8, m_wx[4] ^ (m_wx[1] >> 16) ^ (m_wx[7] << 16));
		PutWord(false, LITTLE_ENDIAN_ORDER, out + 12, m_wx[6] ^ (m_wx[3] >> 16) ^ (m_wx[1] << 16));
	}

	// If AdditiveCipherTemplate does not have an accumulated keystream
	//  then it will ask OperateKeystream to generate one. Optionally it
	//  will ask for an XOR of the input with the keystream while
	//  writing the result to the output buffer. In all cases the
	//  keystream is written to the output buffer. The optional part is
	//  adding the input buffer and keystream.
	if ((operation & INPUT_NULL) != INPUT_NULL)
		xorbuf(output, input, GetBytesPerIteration() * iterationCount);
}

void RabbitWithIVPolicy::CipherSetKey(const NameValuePairs &params, const byte *userKey, size_t keylen)
{
	/* Generate four subkeys */
	CRYPTOPP_UNUSED(params);
	GetUserKey(LITTLE_ENDIAN_ORDER, m_t.begin(), 4, userKey, keylen);

	/* Generate initial state variables */
	m_mx[0] = m_t[0];
	m_mx[2] = m_t[1];
	m_mx[4] = m_t[2];
	m_mx[6] = m_t[3];
	m_mx[1] = static_cast<word32>(m_t[3] << 16) | (m_t[2] >> 16);
	m_mx[3] = static_cast<word32>(m_t[0] << 16) | (m_t[3] >> 16);
	m_mx[5] = static_cast<word32>(m_t[1] << 16) | (m_t[0] >> 16);
	m_mx[7] = static_cast<word32>(m_t[2] << 16) | (m_t[1] >> 16);

	/* Generate initial counter values */
	m_mc[0] = rotlConstant<16>(m_t[2]);
	m_mc[2] = rotlConstant<16>(m_t[3]);
	m_mc[4] = rotlConstant<16>(m_t[0]);
	m_mc[6] = rotlConstant<16>(m_t[1]);
	m_mc[1] = (m_t[0] & 0xFFFF0000) | (m_t[1] & 0xFFFF);
	m_mc[3] = (m_t[1] & 0xFFFF0000) | (m_t[2] & 0xFFFF);
	m_mc[5] = (m_t[2] & 0xFFFF0000) | (m_t[3] & 0xFFFF);
	m_mc[7] = (m_t[3] & 0xFFFF0000) | (m_t[0] & 0xFFFF);

	/* Clear carry bit */
	m_mcy = 0;

	/* Iterate the system four times */
	for (unsigned int i = 0; i<4; i++)
		m_mcy = NextState(m_mc, m_mx, m_mcy);

	/* Modify the counters */
	for (unsigned int i = 0; i<8; i++)
		m_mc[i] ^= m_mx[(i + 4) & 0x7];

	/* Copy master instance to work instance */
	for (unsigned int i = 0; i<8; i++)
	{
		m_wx[i] = m_mx[i];
		m_wc[i] = m_mc[i];
	}
	m_wcy = m_mcy;
}

void RabbitWithIVPolicy::CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length)
{
	CRYPTOPP_UNUSED(keystreamBuffer);
	CRYPTOPP_UNUSED(length);
	CRYPTOPP_ASSERT(length == 8);

	/* Generate four subvectors */
	GetBlock<word32, LittleEndian> v(iv); v(m_t[0])(m_t[2]);
	m_t[1] = (m_t[0] >> 16) | (m_t[2] & 0xFFFF0000);
	m_t[3] = (m_t[2] << 16) | (m_t[0] & 0x0000FFFF);

	/* Modify counter values */
	m_wc[0] = m_mc[0] ^ m_t[0];
	m_wc[1] = m_mc[1] ^ m_t[1];
	m_wc[2] = m_mc[2] ^ m_t[2];
	m_wc[3] = m_mc[3] ^ m_t[3];
	m_wc[4] = m_mc[4] ^ m_t[0];
	m_wc[5] = m_mc[5] ^ m_t[1];
	m_wc[6] = m_mc[6] ^ m_t[2];
	m_wc[7] = m_mc[7] ^ m_t[3];

	/* Copy state variables */
	for (unsigned int i = 0; i<8; i++)
		m_wx[i] = m_mx[i];
	m_wcy = m_mcy;

	/* Iterate the system four times */
	for (unsigned int i = 0; i<4; i++)
		m_wcy = NextState(m_wc, m_wx, m_wcy);
}

void RabbitWithIVPolicy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount)
{
	byte* out = output;
	for (unsigned int i = 0; i<iterationCount; ++i, out += 16)
	{
		/* Iterate the system */
		m_wcy = NextState(m_wc, m_wx, m_wcy);

		/* Encrypt/decrypt 16 bytes of data */
		PutWord(false, LITTLE_ENDIAN_ORDER, out +  0, m_wx[0] ^ (m_wx[5] >> 16) ^ (m_wx[3] << 16));
		PutWord(false, LITTLE_ENDIAN_ORDER, out +  4, m_wx[2] ^ (m_wx[7] >> 16) ^ (m_wx[5] << 16));
		PutWord(false, LITTLE_ENDIAN_ORDER, out +  8, m_wx[4] ^ (m_wx[1] >> 16) ^ (m_wx[7] << 16));
		PutWord(false, LITTLE_ENDIAN_ORDER, out + 12, m_wx[6] ^ (m_wx[3] >> 16) ^ (m_wx[1] << 16));
	}

	// If AdditiveCipherTemplate does not have an accumulated keystream
	//  then it will ask OperateKeystream to generate one. Optionally it
	//  will ask for an XOR of the input with the keystream while
	//  writing the result to the output buffer. In all cases the
	//  keystream is written to the output buffer. The optional part is
	//  adding the input buffer and keystream.
	if ((operation & INPUT_NULL) != INPUT_NULL)
		xorbuf(output, input, GetBytesPerIteration() * iterationCount);
}

NAMESPACE_END
