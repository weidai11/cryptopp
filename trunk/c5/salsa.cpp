// salsa.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "salsa.h"
#include "misc.h"
#include "argnames.h"

NAMESPACE_BEGIN(CryptoPP)

void Salsa20_TestInstantiations()
{
	Salsa20::Encryption x;
}

void Salsa20_Policy::GetNextIV(byte *IV) const
{
	word32 j6 = m_state[6] + 1;
	word32 j7 = m_state[7] + (j6 == 0);

	UnalignedPutWord(LITTLE_ENDIAN_ORDER, IV, j6);
	UnalignedPutWord(LITTLE_ENDIAN_ORDER, IV+4, j7);
}

void Salsa20_Policy::CipherSetKey(const NameValuePairs &params, const byte *key, size_t length)
{
	m_rounds = params.GetIntValueWithDefault(Name::Rounds(), 20);

	if (!(m_rounds == 8 || m_rounds == 12 || m_rounds == 20))
		throw InvalidRounds(StaticAlgorithmName(), m_rounds);

	GetUserKey(LITTLE_ENDIAN_ORDER, m_state+1, 4, key, 16);
	GetUserKey(LITTLE_ENDIAN_ORDER, m_state+11, 4, key + length - 16, 16);

	// m_state[0,5,10,15] forms "expand 16-byte k" or "expand 32-byte k"
	m_state[0] = 0x61707865;
	m_state[5] = (length == 16) ? 0x3120646e : 0x3320646e;
	m_state[10] = (length == 16) ? 0x79622d36 : 0x79622d32;
	m_state[15] = 0x6b206574;
}

void Salsa20_Policy::CipherResynchronize(byte *keystreamBuffer, const byte *IV)
{
	GetUserKey(LITTLE_ENDIAN_ORDER, m_state+6, 4, IV, 8);
}

void Salsa20_Policy::SeekToIteration(lword iterationCount)
{
	m_state[8] = (word32)iterationCount;
	m_state[9] = (word32)SafeRightShift<32>(iterationCount);
}

void Salsa20_Policy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount)
{
	KeystreamOutput<LittleEndian> keystreamOutput(operation, output, input);

	word32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
	word32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;

	j0 = m_state[0];
	j1 = m_state[1];
	j2 = m_state[2];
	j3 = m_state[3];
	j4 = m_state[4];
	j5 = m_state[5];
	j6 = m_state[6];
	j7 = m_state[7];
	j8 = m_state[8];
	j9 = m_state[9];
	j10 = m_state[10];
	j11 = m_state[11];
	j12 = m_state[12];
	j13 = m_state[13];
	j14 = m_state[14];
	j15 = m_state[15];

	for (size_t iteration = 0; iteration < iterationCount; ++iteration)
	{
		x0 = j0;
		x1 = j1;
		x2 = j2;
		x3 = j3;
		x4 = j4;
		x5 = j5;
		x6 = j6;
		x7 = j7;
		x8 = j8;
		x9 = j9;
		x10 = j10;
		x11 = j11;
		x12 = j12;
		x13 = j13;
		x14 = j14;
		x15 = j15;

		for (int i=m_rounds; i>0; i-=2)
		{
#define QUARTER_ROUND(a, b, c, d)	\
	b = b ^ rotlFixed(a + d, 7);	\
	c = c ^ rotlFixed(b + a, 9);	\
	d = d ^ rotlFixed(c + b, 13);	\
	a = a ^ rotlFixed(d + c, 18);

			QUARTER_ROUND(x0, x4, x8, x12)
			QUARTER_ROUND(x5, x9, x13, x1)
			QUARTER_ROUND(x10, x14, x2, x6)
			QUARTER_ROUND(x15, x3, x7, x11)

			QUARTER_ROUND(x0, x1, x2, x3)
			QUARTER_ROUND(x5, x6, x7, x4)
			QUARTER_ROUND(x10, x11, x8, x9)
			QUARTER_ROUND(x15, x12, x13, x14)
		}

		keystreamOutput	(x0 + j0)
						(x1 + j1)
						(x2 + j2)
						(x3 + j3)
						(x4 + j4)
						(x5 + j5)
						(x6 + j6)
						(x7 + j7)
						(x8 + j8)
						(x9 + j9)
						(x10 + j10)
						(x11 + j11)
						(x12 + j12)
						(x13 + j13)
						(x14 + j14)
						(x15 + j15);

		if (++j8 == 0)
			++j9;
	}

	m_state[8] = j8;
	m_state[9] = j9;
}

NAMESPACE_END
