// hc128.cpp - written and placed in the public domain by Jeffrey Walton
//             based on public domain code by Hongjun Wu.
//
//             The reference materials and source files are available at
//             The eSTREAM Project, http://www.ecrypt.eu.org/stream/e2-hc128.html.

#include "pch.h"
#include "config.h"

#include "hc128.h"
#include "secblock.h"
#include "misc.h"

/*h1 function*/
#define h1(x, y) {           \
     byte a,c;               \
     a = (byte) (x);         \
     c = (byte) ((x) >> 16); \
     y = (m_T[512+a])+(m_T[512+256+c]); \
}

/*h2 function*/
#define h2(x, y) {           \
     byte a,c;               \
     a = (byte) (x);         \
     c = (byte) ((x) >> 16); \
     y = (m_T[a])+(m_T[256+c]); \
}

/*one step of HC-128, update P and generate 32 bits keystream*/
#define step_P(u,v,a,b,c,d,n){           \
     word32 tem0,tem1,tem2,tem3;         \
     h1(m_X[(d)],tem3);                  \
     tem0 = rotrConstant<23>(m_T[(v)]);  \
     tem1 = rotrConstant<10>(m_X[(c)]);  \
     tem2 = rotrConstant<8>(m_X[(b)]);   \
     (m_T[(u)]) += tem2+(tem0 ^ tem1);   \
     (m_X[(a)]) = (m_T[(u)]);            \
     (n) = tem3 ^ (m_T[(u)]);            \
}

/*one step of HC-128, update Q and generate 32 bits keystream*/
#define step_Q(u,v,a,b,c,d,n){                \
     word32 tem0,tem1,tem2,tem3;              \
     h2(m_Y[(d)],tem3);                       \
     tem0 = rotrConstant<(32-23)>(m_T[(v)]);  \
     tem1 = rotrConstant<(32-10)>(m_Y[(c)]);  \
     tem2 = rotrConstant<(32-8)>(m_Y[(b)]);   \
     (m_T[(u)]) += tem2 + (tem0 ^ tem1);      \
     (m_Y[(a)]) = (m_T[(u)]);                 \
     (n) = tem3 ^ (m_T[(u)]) ;                \
}

/*update table P*/
#define update_P(u,v,a,b,c,d){                \
     word32 tem0,tem1,tem2,tem3;              \
     tem0 = rotrConstant<23>(m_T[(v)]);       \
     tem1 = rotrConstant<10>(m_X[(c)]);       \
     tem2 = rotrConstant<8>(m_X[(b)]);        \
     h1(m_X[(d)],tem3);                       \
     (m_T[(u)]) = ((m_T[(u)]) + tem2+(tem0^tem1)) ^ tem3;  \
     (m_X[(a)]) = (m_T[(u)]);                 \
}

/*update table Q*/
#define update_Q(u,v,a,b,c,d){                \
     word32 tem0,tem1,tem2,tem3;              \
     tem0 = rotrConstant<(32-23)>(m_T[(v)]);  \
     tem1 = rotrConstant<(32-10)>(m_Y[(c)]);  \
     tem2 = rotrConstant<(32-8)>(m_Y[(b)]);   \
     h2(m_Y[(d)],tem3);                       \
     (m_T[(u)]) = ((m_T[(u)]) + tem2+(tem0^tem1)) ^ tem3; \
     (m_Y[(a)]) = (m_T[(u)]);                 \
}

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::rotrConstant;

inline word32 f1(word32 x)
{
	return rotrConstant<7>(x) ^ rotrConstant<18>(x) ^ ((x) >> 3);
}

inline word32 f2(word32 x)
{
	return rotrConstant<17>(x) ^ rotrConstant<19>(x) ^ ((x) >> 10);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

/*16 steps of HC-128, generate 512 bits keystream*/
void HC128Policy::GenerateKeystream(word32 keystream[16])
{
	unsigned int cc = m_ctr & 0x1ff;
	unsigned int dd = (cc + 16) & 0x1ff;

	if (m_ctr < 512)
	{
		m_ctr = (m_ctr + 16) & 0x3ff;
		step_P(cc + 0, cc + 1, 0, 6, 13, 4, keystream[0]);
		step_P(cc + 1, cc + 2, 1, 7, 14, 5, keystream[1]);
		step_P(cc + 2, cc + 3, 2, 8, 15, 6, keystream[2]);
		step_P(cc + 3, cc + 4, 3, 9, 0, 7, keystream[3]);
		step_P(cc + 4, cc + 5, 4, 10, 1, 8, keystream[4]);
		step_P(cc + 5, cc + 6, 5, 11, 2, 9, keystream[5]);
		step_P(cc + 6, cc + 7, 6, 12, 3, 10, keystream[6]);
		step_P(cc + 7, cc + 8, 7, 13, 4, 11, keystream[7]);
		step_P(cc + 8, cc + 9, 8, 14, 5, 12, keystream[8]);
		step_P(cc + 9, cc + 10, 9, 15, 6, 13, keystream[9]);
		step_P(cc + 10, cc + 11, 10, 0, 7, 14, keystream[10]);
		step_P(cc + 11, cc + 12, 11, 1, 8, 15, keystream[11]);
		step_P(cc + 12, cc + 13, 12, 2, 9, 0, keystream[12]);
		step_P(cc + 13, cc + 14, 13, 3, 10, 1, keystream[13]);
		step_P(cc + 14, cc + 15, 14, 4, 11, 2, keystream[14]);
		step_P(cc + 15, dd + 0, 15, 5, 12, 3, keystream[15]);
	}
	else
	{
		m_ctr = (m_ctr + 16) & 0x3ff;
		step_Q(512 + cc + 0, 512 + cc + 1, 0, 6, 13, 4, keystream[0]);
		step_Q(512 + cc + 1, 512 + cc + 2, 1, 7, 14, 5, keystream[1]);
		step_Q(512 + cc + 2, 512 + cc + 3, 2, 8, 15, 6, keystream[2]);
		step_Q(512 + cc + 3, 512 + cc + 4, 3, 9, 0, 7, keystream[3]);
		step_Q(512 + cc + 4, 512 + cc + 5, 4, 10, 1, 8, keystream[4]);
		step_Q(512 + cc + 5, 512 + cc + 6, 5, 11, 2, 9, keystream[5]);
		step_Q(512 + cc + 6, 512 + cc + 7, 6, 12, 3, 10, keystream[6]);
		step_Q(512 + cc + 7, 512 + cc + 8, 7, 13, 4, 11, keystream[7]);
		step_Q(512 + cc + 8, 512 + cc + 9, 8, 14, 5, 12, keystream[8]);
		step_Q(512 + cc + 9, 512 + cc + 10, 9, 15, 6, 13, keystream[9]);
		step_Q(512 + cc + 10, 512 + cc + 11, 10, 0, 7, 14, keystream[10]);
		step_Q(512 + cc + 11, 512 + cc + 12, 11, 1, 8, 15, keystream[11]);
		step_Q(512 + cc + 12, 512 + cc + 13, 12, 2, 9, 0, keystream[12]);
		step_Q(512 + cc + 13, 512 + cc + 14, 13, 3, 10, 1, keystream[13]);
		step_Q(512 + cc + 14, 512 + cc + 15, 14, 4, 11, 2, keystream[14]);
		step_Q(512 + cc + 15, 512 + dd + 0, 15, 5, 12, 3, keystream[15]);
	}
}

/*16 steps of HC-128, without generating keystream, */
/*but use the outputs to update P and Q*/
void HC128Policy::SetupUpdate()  /*each time 16 steps*/
{
	unsigned int cc = m_ctr & 0x1ff;
	unsigned int dd = (cc + 16) & 0x1ff;

	if (m_ctr < 512)
	{
		m_ctr = (m_ctr + 16) & 0x3ff;
		update_P(cc + 0, cc + 1, 0, 6, 13, 4);
		update_P(cc + 1, cc + 2, 1, 7, 14, 5);
		update_P(cc + 2, cc + 3, 2, 8, 15, 6);
		update_P(cc + 3, cc + 4, 3, 9, 0, 7);
		update_P(cc + 4, cc + 5, 4, 10, 1, 8);
		update_P(cc + 5, cc + 6, 5, 11, 2, 9);
		update_P(cc + 6, cc + 7, 6, 12, 3, 10);
		update_P(cc + 7, cc + 8, 7, 13, 4, 11);
		update_P(cc + 8, cc + 9, 8, 14, 5, 12);
		update_P(cc + 9, cc + 10, 9, 15, 6, 13);
		update_P(cc + 10, cc + 11, 10, 0, 7, 14);
		update_P(cc + 11, cc + 12, 11, 1, 8, 15);
		update_P(cc + 12, cc + 13, 12, 2, 9, 0);
		update_P(cc + 13, cc + 14, 13, 3, 10, 1);
		update_P(cc + 14, cc + 15, 14, 4, 11, 2);
		update_P(cc + 15, dd + 0, 15, 5, 12, 3);
	}
	else
	{
		m_ctr = (m_ctr + 16) & 0x3ff;
		update_Q(512 + cc + 0, 512 + cc + 1, 0, 6, 13, 4);
		update_Q(512 + cc + 1, 512 + cc + 2, 1, 7, 14, 5);
		update_Q(512 + cc + 2, 512 + cc + 3, 2, 8, 15, 6);
		update_Q(512 + cc + 3, 512 + cc + 4, 3, 9, 0, 7);
		update_Q(512 + cc + 4, 512 + cc + 5, 4, 10, 1, 8);
		update_Q(512 + cc + 5, 512 + cc + 6, 5, 11, 2, 9);
		update_Q(512 + cc + 6, 512 + cc + 7, 6, 12, 3, 10);
		update_Q(512 + cc + 7, 512 + cc + 8, 7, 13, 4, 11);
		update_Q(512 + cc + 8, 512 + cc + 9, 8, 14, 5, 12);
		update_Q(512 + cc + 9, 512 + cc + 10, 9, 15, 6, 13);
		update_Q(512 + cc + 10, 512 + cc + 11, 10, 0, 7, 14);
		update_Q(512 + cc + 11, 512 + cc + 12, 11, 1, 8, 15);
		update_Q(512 + cc + 12, 512 + cc + 13, 12, 2, 9, 0);
		update_Q(512 + cc + 13, 512 + cc + 14, 13, 3, 10, 1);
		update_Q(512 + cc + 14, 512 + cc + 15, 14, 4, 11, 2);
		update_Q(512 + cc + 15, 512 + dd + 0, 15, 5, 12, 3);
	}
}

void HC128Policy::CipherSetKey(const NameValuePairs &params, const byte *userKey, size_t keylen)
{
	CRYPTOPP_UNUSED(params);

	GetUserKey(LITTLE_ENDIAN_ORDER, m_key.begin(), 4, userKey, keylen);
	for (unsigned int i = 4; i < 8; i++)
		m_key[i] = m_key[i - 4];
}

void HC128Policy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount)
{
	while (iterationCount--)
	{
		word32 keystream[16];
		GenerateKeystream(keystream);

		PutWord(false, LITTLE_ENDIAN_ORDER, output + 0, keystream[0]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 4, keystream[1]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 8, keystream[2]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 12, keystream[3]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 16, keystream[4]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 20, keystream[5]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 24, keystream[6]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 28, keystream[7]);

		PutWord(false, LITTLE_ENDIAN_ORDER, output + 32, keystream[8]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 36, keystream[9]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 40, keystream[10]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 44, keystream[11]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 48, keystream[12]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 52, keystream[13]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 56, keystream[14]);
		PutWord(false, LITTLE_ENDIAN_ORDER, output + 60, keystream[15]);

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

void HC128Policy::CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length)
{
	CRYPTOPP_UNUSED(keystreamBuffer);

	GetUserKey(LITTLE_ENDIAN_ORDER, m_iv.begin(), 4, iv, length);
	for (unsigned int i = 4; i < 8; i++)
		m_iv[i] = m_iv[i - 4];

	/* expand the key and IV into the table T */
	/* (expand the key and IV into the table P and Q) */

	for (unsigned int i = 0; i < 8; i++)
		m_T[i] = m_key[i];
	for (unsigned int i = 8; i < 16; i++)
		m_T[i] = m_iv[i - 8];

	for (unsigned int i = 16; i < (256 + 16); i++)
		m_T[i] = f2(m_T[i - 2]) + m_T[i - 7] + f1(m_T[i - 15]) + m_T[i - 16] + i;

	for (unsigned int i = 0; i < 16; i++)
		m_T[i] = m_T[256 + i];

	for (unsigned int i = 16; i < 1024; i++)
		m_T[i] = f2(m_T[i - 2]) + m_T[i - 7] + f1(m_T[i - 15]) + m_T[i - 16] + 256 + i;

	/* initialize counter1024, X and Y */
	m_ctr = 0;
	for (unsigned int i = 0; i < 16; i++)
		m_X[i] = m_T[512 - 16 + i];
	for (unsigned int i = 0; i < 16; i++)
		m_Y[i] = m_T[512 + 512 - 16 + i];

	/* run the cipher 1024 steps before generating the output */
	for (unsigned int i = 0; i < 64; i++)
		SetupUpdate();
}

NAMESPACE_END
