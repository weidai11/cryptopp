// panama.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "panama.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

template <class B>
void Panama<B>::Reset()
{
	m_bstart = 0;
	memset(m_state, 0, m_state.size()*4);
}

template <class B>
void Panama<B>::Iterate(unsigned int count, const word32 *p, word32 *z, const word32 *y)
{
	unsigned int bstart = m_bstart;
	word32 *const a = m_state;
#define c (a+17)
#define b ((Stage *)(a+34))

// output
#define OA(i) z[i] = ConditionalByteReverse(B::ToEnum(), a[i+9])
#define OX(i) z[i] = y[i] ^ ConditionalByteReverse(B::ToEnum(), a[i+9])
// buffer update
#define US(i) {word32 t=b0[i]; b0[i]=ConditionalByteReverse(B::ToEnum(), p[i])^t; b25[(i+6)%8]^=t;}
#define UL(i) {word32 t=b0[i]; b0[i]=a[i+1]^t; b25[(i+6)%8]^=t;}
// gamma and pi
#define GP(i) c[5*i%17] = rotlFixed(a[i] ^ (a[(i+1)%17] | ~a[(i+2)%17]), ((5*i%17)*((5*i%17)+1)/2)%32)
// theta and sigma
#define T(i,x) a[i] = c[i] ^ c[(i+1)%17] ^ c[(i+4)%17] ^ x
#define TS1S(i) T(i+1, ConditionalByteReverse(B::ToEnum(), p[i]))
#define TS1L(i) T(i+1, b4[i])
#define TS2(i) T(i+9, b16[i])

	while (count--)
	{
		if (z)
		{
			if (y)
			{
				OX(0); OX(1); OX(2); OX(3); OX(4); OX(5); OX(6); OX(7);
				y += 8;
			}
			else
			{
				OA(0); OA(1); OA(2); OA(3); OA(4); OA(5); OA(6); OA(7);
			}
			z += 8;
		}

		word32 *const b16 = b[(bstart+16) % STAGES];
		word32 *const b4 = b[(bstart+4) % STAGES];
		bstart = (bstart + STAGES - 1) % STAGES;
		word32 *const b0 = b[bstart];
		word32 *const b25 = b[(bstart+25) % STAGES];


		if (p)
		{
			US(0); US(1); US(2); US(3); US(4); US(5); US(6); US(7);
		}
		else
		{
			UL(0); UL(1); UL(2); UL(3); UL(4); UL(5); UL(6); UL(7);
		}

		GP(0); GP(1); GP(2); GP(3); GP(4); GP(5); GP(6); GP(7);
		GP(8); GP(9); GP(10); GP(11); GP(12); GP(13); GP(14); GP(15); GP(16);

		T(0,1);

		if (p)
		{
			TS1S(0); TS1S(1); TS1S(2); TS1S(3); TS1S(4); TS1S(5); TS1S(6); TS1S(7);
			p += 8;
		}
		else
		{
			TS1L(0); TS1L(1); TS1L(2); TS1L(3); TS1L(4); TS1L(5); TS1L(6); TS1L(7);
		}

		TS2(0); TS2(1); TS2(2); TS2(3); TS2(4); TS2(5); TS2(6); TS2(7);
	}
	m_bstart = bstart;
}

template <class B>
unsigned int PanamaHash<B>::HashMultipleBlocks(const word32 *input, unsigned int length)
{
	Iterate(length / BLOCKSIZE, input);
	return length % BLOCKSIZE;
}

template <class B>
void PanamaHash<B>::TruncatedFinal(byte *hash, unsigned int size)
{
	ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(BLOCKSIZE, 0x01);
	
	HashEndianCorrectedBlock(m_data);

	Iterate(32);	// pull

	ConditionalByteReverse(B::ToEnum(), m_state+9, m_state+9, DIGESTSIZE);
	memcpy(hash, m_state+9, size);

	Restart();		// reinit for next use
}

template <class B>
void PanamaCipherPolicy<B>::CipherSetKey(const NameValuePairs &params, const byte *key, unsigned int length)
{
	FixedSizeSecBlock<word32, 8> buf;

	Reset();
	memcpy(buf, key, 32);
	Iterate(1, buf);
	if (length == 64)
		memcpy(buf, key+32, 32);
	else
		memset(buf, 0, 32);
	Iterate(1, buf);

	Iterate(32);
}

template <class B>
void PanamaCipherPolicy<B>::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, unsigned int iterationCount)
{
	Iterate(iterationCount, NULL, (word32 *)output, (const word32 *)input);
}

template class Panama<BigEndian>;
template class Panama<LittleEndian>;

template class PanamaHash<BigEndian>;
template class PanamaHash<LittleEndian>;

template class PanamaCipherPolicy<BigEndian>;
template class PanamaCipherPolicy<LittleEndian>;

NAMESPACE_END
