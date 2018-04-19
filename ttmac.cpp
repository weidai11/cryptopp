// ttmac.cpp - written and placed in the public domain by Kevin Springle

#include "pch.h"
#include "ttmac.h"
#include "misc.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::rotlVariable;
using CryptoPP::rotlConstant;

// RIPEMD-160 definitions used by Two-Track-MAC
word32 F(word32 x, word32 y, word32 z) { return x ^ y ^ z; }
word32 G(word32 x, word32 y, word32 z) { return z ^ (x & (y^z)); }
word32 H(word32 x, word32 y, word32 z) { return z ^ (x | ~y); }
word32 I(word32 x, word32 y, word32 z) { return y ^ (z & (x^y)); }
word32 J(word32 x, word32 y, word32 z) { return x ^ (y | ~z); }

typedef word32 (*Fn)(word32, word32, word32);
template <Fn f, unsigned int S>
void Subround(word32& a, word32 b, word32& c, word32 d, word32 e, word32 x, word32 k)
{
	a += f(b, c, d) + x + k;
	a = rotlVariable(a, S) + e;
	c = rotlConstant<10>(c);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

const unsigned int k0 = 0;
const unsigned int k1 = 0x5a827999;
const unsigned int k2 = 0x6ed9eba1;
const unsigned int k3 = 0x8f1bbcdc;
const unsigned int k4 = 0xa953fd4e;
const unsigned int k5 = 0x50a28be6;
const unsigned int k6 = 0x5c4dd124;
const unsigned int k7 = 0x6d703ef3;
const unsigned int k8 = 0x7a6d76e9;
const unsigned int k9 = 0;

void TTMAC_Base::UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &)
{
	AssertValidKeyLength(keylength);

	memcpy(m_key, userKey, KEYLENGTH);
	CorrectEndianess(m_key, m_key, KEYLENGTH);

	Init();
}

void TTMAC_Base::Init()
{
	m_digest[0] = m_digest[5] = m_key[0];
	m_digest[1] = m_digest[6] = m_key[1];
	m_digest[2] = m_digest[7] = m_key[2];
	m_digest[3] = m_digest[8] = m_key[3];
	m_digest[4] = m_digest[9] = m_key[4];
}

void TTMAC_Base::TruncatedFinal(byte *hash, size_t size)
{
	PadLastBlock(BlockSize() - 2*sizeof(HashWordType));
	CorrectEndianess(m_data, m_data, BlockSize() - 2*sizeof(HashWordType));

	m_data[m_data.size()-2] = GetBitCountLo();
	m_data[m_data.size()-1] = GetBitCountHi();

	Transform(m_digest, m_data, true);

	word32 t2 = m_digest[2];
	word32 t3 = m_digest[3];
	if (size != DIGESTSIZE)
	{
		switch (size)
		{
			case 16:
				m_digest[3] += m_digest[1] + m_digest[4];
				// fall through
			case 12:
				m_digest[2] += m_digest[0] + t3;
				// fall through
			case 8:
				m_digest[0] += m_digest[1] + t3;
				m_digest[1] += m_digest[4] + t2;
				break;

			case 4:
				m_digest[0] +=
						m_digest[1] +
						m_digest[2] +
						m_digest[3] +
						m_digest[4];
				break;

			case 0:
				// Used by HashTransformation::Restart()
				break;

			default:
				throw InvalidArgument("TTMAC_Base: can't truncate a Two-Track-MAC 20 byte digest to " + IntToString(size) + " bytes");
				break;
		}
	}

	CorrectEndianess(m_digest, m_digest, size);
	memcpy(hash, m_digest, size);

	Restart();		// reinit for next use
}

void TTMAC_Base::Transform(word32 *digest, const word32 *X, bool last)
{
	word32 a1, b1, c1, d1, e1, a2, b2, c2, d2, e2;
	word32 *trackA, *trackB;

	if (!last)
	{
		trackA = digest;
		trackB = digest+5;
	}
	else
	{
		trackB = digest;
		trackA = digest+5;
	}
	a1 = trackA[0];
	b1 = trackA[1];
	c1 = trackA[2];
	d1 = trackA[3];
	e1 = trackA[4];
	a2 = trackB[0];
	b2 = trackB[1];
	c2 = trackB[2];
	d2 = trackB[3];
	e2 = trackB[4];

	Subround<F,11>(a1, b1, c1, d1, e1, X[ 0], k0);
	Subround<F,14>(e1, a1, b1, c1, d1, X[ 1], k0);
	Subround<F,15>(d1, e1, a1, b1, c1, X[ 2], k0);
	Subround<F,12>(c1, d1, e1, a1, b1, X[ 3], k0);
	Subround<F, 5>(b1, c1, d1, e1, a1, X[ 4], k0);
	Subround<F, 8>(a1, b1, c1, d1, e1, X[ 5], k0);
	Subround<F, 7>(e1, a1, b1, c1, d1, X[ 6], k0);
	Subround<F, 9>(d1, e1, a1, b1, c1, X[ 7], k0);
	Subround<F,11>(c1, d1, e1, a1, b1, X[ 8], k0);
	Subround<F,13>(b1, c1, d1, e1, a1, X[ 9], k0);
	Subround<F,14>(a1, b1, c1, d1, e1, X[10], k0);
	Subround<F,15>(e1, a1, b1, c1, d1, X[11], k0);
	Subround<F, 6>(d1, e1, a1, b1, c1, X[12], k0);
	Subround<F, 7>(c1, d1, e1, a1, b1, X[13], k0);
	Subround<F, 9>(b1, c1, d1, e1, a1, X[14], k0);
	Subround<F, 8>(a1, b1, c1, d1, e1, X[15], k0);

	Subround<G, 7>(e1, a1, b1, c1, d1, X[ 7], k1);
	Subround<G, 6>(d1, e1, a1, b1, c1, X[ 4], k1);
	Subround<G, 8>(c1, d1, e1, a1, b1, X[13], k1);
	Subround<G,13>(b1, c1, d1, e1, a1, X[ 1], k1);
	Subround<G,11>(a1, b1, c1, d1, e1, X[10], k1);
	Subround<G, 9>(e1, a1, b1, c1, d1, X[ 6], k1);
	Subround<G, 7>(d1, e1, a1, b1, c1, X[15], k1);
	Subround<G,15>(c1, d1, e1, a1, b1, X[ 3], k1);
	Subround<G, 7>(b1, c1, d1, e1, a1, X[12], k1);
	Subround<G,12>(a1, b1, c1, d1, e1, X[ 0], k1);
	Subround<G,15>(e1, a1, b1, c1, d1, X[ 9], k1);
	Subround<G, 9>(d1, e1, a1, b1, c1, X[ 5], k1);
	Subround<G,11>(c1, d1, e1, a1, b1, X[ 2], k1);
	Subround<G, 7>(b1, c1, d1, e1, a1, X[14], k1);
	Subround<G,13>(a1, b1, c1, d1, e1, X[11], k1);
	Subround<G,12>(e1, a1, b1, c1, d1, X[ 8], k1);

	Subround<H,11>(d1, e1, a1, b1, c1, X[ 3], k2);
	Subround<H,13>(c1, d1, e1, a1, b1, X[10], k2);
	Subround<H, 6>(b1, c1, d1, e1, a1, X[14], k2);
	Subround<H, 7>(a1, b1, c1, d1, e1, X[ 4], k2);
	Subround<H,14>(e1, a1, b1, c1, d1, X[ 9], k2);
	Subround<H, 9>(d1, e1, a1, b1, c1, X[15], k2);
	Subround<H,13>(c1, d1, e1, a1, b1, X[ 8], k2);
	Subround<H,15>(b1, c1, d1, e1, a1, X[ 1], k2);
	Subround<H,14>(a1, b1, c1, d1, e1, X[ 2], k2);
	Subround<H, 8>(e1, a1, b1, c1, d1, X[ 7], k2);
	Subround<H,13>(d1, e1, a1, b1, c1, X[ 0], k2);
	Subround<H, 6>(c1, d1, e1, a1, b1, X[ 6], k2);
	Subround<H, 5>(b1, c1, d1, e1, a1, X[13], k2);
	Subround<H,12>(a1, b1, c1, d1, e1, X[11], k2);
	Subround<H, 7>(e1, a1, b1, c1, d1, X[ 5], k2);
	Subround<H, 5>(d1, e1, a1, b1, c1, X[12], k2);

	Subround<I,11>(c1, d1, e1, a1, b1, X[ 1], k3);
	Subround<I,12>(b1, c1, d1, e1, a1, X[ 9], k3);
	Subround<I,14>(a1, b1, c1, d1, e1, X[11], k3);
	Subround<I,15>(e1, a1, b1, c1, d1, X[10], k3);
	Subround<I,14>(d1, e1, a1, b1, c1, X[ 0], k3);
	Subround<I,15>(c1, d1, e1, a1, b1, X[ 8], k3);
	Subround<I, 9>(b1, c1, d1, e1, a1, X[12], k3);
	Subround<I, 8>(a1, b1, c1, d1, e1, X[ 4], k3);
	Subround<I, 9>(e1, a1, b1, c1, d1, X[13], k3);
	Subround<I,14>(d1, e1, a1, b1, c1, X[ 3], k3);
	Subround<I, 5>(c1, d1, e1, a1, b1, X[ 7], k3);
	Subround<I, 6>(b1, c1, d1, e1, a1, X[15], k3);
	Subround<I, 8>(a1, b1, c1, d1, e1, X[14], k3);
	Subround<I, 6>(e1, a1, b1, c1, d1, X[ 5], k3);
	Subround<I, 5>(d1, e1, a1, b1, c1, X[ 6], k3);
	Subround<I,12>(c1, d1, e1, a1, b1, X[ 2], k3);

	Subround<J, 9>(b1, c1, d1, e1, a1, X[ 4], k4);
	Subround<J,15>(a1, b1, c1, d1, e1, X[ 0], k4);
	Subround<J, 5>(e1, a1, b1, c1, d1, X[ 5], k4);
	Subround<J,11>(d1, e1, a1, b1, c1, X[ 9], k4);
	Subround<J, 6>(c1, d1, e1, a1, b1, X[ 7], k4);
	Subround<J, 8>(b1, c1, d1, e1, a1, X[12], k4);
	Subround<J,13>(a1, b1, c1, d1, e1, X[ 2], k4);
	Subround<J,12>(e1, a1, b1, c1, d1, X[10], k4);
	Subround<J, 5>(d1, e1, a1, b1, c1, X[14], k4);
	Subround<J,12>(c1, d1, e1, a1, b1, X[ 1], k4);
	Subround<J,13>(b1, c1, d1, e1, a1, X[ 3], k4);
	Subround<J,14>(a1, b1, c1, d1, e1, X[ 8], k4);
	Subround<J,11>(e1, a1, b1, c1, d1, X[11], k4);
	Subround<J, 8>(d1, e1, a1, b1, c1, X[ 6], k4);
	Subround<J, 5>(c1, d1, e1, a1, b1, X[15], k4);
	Subround<J, 6>(b1, c1, d1, e1, a1, X[13], k4);

	Subround<J, 8>(a2, b2, c2, d2, e2, X[ 5], k5);
	Subround<J, 9>(e2, a2, b2, c2, d2, X[14], k5);
	Subround<J, 9>(d2, e2, a2, b2, c2, X[ 7], k5);
	Subround<J,11>(c2, d2, e2, a2, b2, X[ 0], k5);
	Subround<J,13>(b2, c2, d2, e2, a2, X[ 9], k5);
	Subround<J,15>(a2, b2, c2, d2, e2, X[ 2], k5);
	Subround<J,15>(e2, a2, b2, c2, d2, X[11], k5);
	Subround<J, 5>(d2, e2, a2, b2, c2, X[ 4], k5);
	Subround<J, 7>(c2, d2, e2, a2, b2, X[13], k5);
	Subround<J, 7>(b2, c2, d2, e2, a2, X[ 6], k5);
	Subround<J, 8>(a2, b2, c2, d2, e2, X[15], k5);
	Subround<J,11>(e2, a2, b2, c2, d2, X[ 8], k5);
	Subround<J,14>(d2, e2, a2, b2, c2, X[ 1], k5);
	Subround<J,14>(c2, d2, e2, a2, b2, X[10], k5);
	Subround<J,12>(b2, c2, d2, e2, a2, X[ 3], k5);
	Subround<J, 6>(a2, b2, c2, d2, e2, X[12], k5);

	Subround<I, 9>(e2, a2, b2, c2, d2, X[ 6], k6);
	Subround<I,13>(d2, e2, a2, b2, c2, X[11], k6);
	Subround<I,15>(c2, d2, e2, a2, b2, X[ 3], k6);
	Subround<I, 7>(b2, c2, d2, e2, a2, X[ 7], k6);
	Subround<I,12>(a2, b2, c2, d2, e2, X[ 0], k6);
	Subround<I, 8>(e2, a2, b2, c2, d2, X[13], k6);
	Subround<I, 9>(d2, e2, a2, b2, c2, X[ 5], k6);
	Subround<I,11>(c2, d2, e2, a2, b2, X[10], k6);
	Subround<I, 7>(b2, c2, d2, e2, a2, X[14], k6);
	Subround<I, 7>(a2, b2, c2, d2, e2, X[15], k6);
	Subround<I,12>(e2, a2, b2, c2, d2, X[ 8], k6);
	Subround<I, 7>(d2, e2, a2, b2, c2, X[12], k6);
	Subround<I, 6>(c2, d2, e2, a2, b2, X[ 4], k6);
	Subround<I,15>(b2, c2, d2, e2, a2, X[ 9], k6);
	Subround<I,13>(a2, b2, c2, d2, e2, X[ 1], k6);
	Subround<I,11>(e2, a2, b2, c2, d2, X[ 2], k6);

	Subround<H, 9>(d2, e2, a2, b2, c2, X[15], k7);
	Subround<H, 7>(c2, d2, e2, a2, b2, X[ 5], k7);
	Subround<H,15>(b2, c2, d2, e2, a2, X[ 1], k7);
	Subround<H,11>(a2, b2, c2, d2, e2, X[ 3], k7);
	Subround<H, 8>(e2, a2, b2, c2, d2, X[ 7], k7);
	Subround<H, 6>(d2, e2, a2, b2, c2, X[14], k7);
	Subround<H, 6>(c2, d2, e2, a2, b2, X[ 6], k7);
	Subround<H,14>(b2, c2, d2, e2, a2, X[ 9], k7);
	Subround<H,12>(a2, b2, c2, d2, e2, X[11], k7);
	Subround<H,13>(e2, a2, b2, c2, d2, X[ 8], k7);
	Subround<H, 5>(d2, e2, a2, b2, c2, X[12], k7);
	Subround<H,14>(c2, d2, e2, a2, b2, X[ 2], k7);
	Subround<H,13>(b2, c2, d2, e2, a2, X[10], k7);
	Subround<H,13>(a2, b2, c2, d2, e2, X[ 0], k7);
	Subround<H, 7>(e2, a2, b2, c2, d2, X[ 4], k7);
	Subround<H, 5>(d2, e2, a2, b2, c2, X[13], k7);

	Subround<G,15>(c2, d2, e2, a2, b2, X[ 8], k8);
	Subround<G, 5>(b2, c2, d2, e2, a2, X[ 6], k8);
	Subround<G, 8>(a2, b2, c2, d2, e2, X[ 4], k8);
	Subround<G,11>(e2, a2, b2, c2, d2, X[ 1], k8);
	Subround<G,14>(d2, e2, a2, b2, c2, X[ 3], k8);
	Subround<G,14>(c2, d2, e2, a2, b2, X[11], k8);
	Subround<G, 6>(b2, c2, d2, e2, a2, X[15], k8);
	Subround<G,14>(a2, b2, c2, d2, e2, X[ 0], k8);
	Subround<G, 6>(e2, a2, b2, c2, d2, X[ 5], k8);
	Subround<G, 9>(d2, e2, a2, b2, c2, X[12], k8);
	Subround<G,12>(c2, d2, e2, a2, b2, X[ 2], k8);
	Subround<G, 9>(b2, c2, d2, e2, a2, X[13], k8);
	Subround<G,12>(a2, b2, c2, d2, e2, X[ 9], k8);
	Subround<G, 5>(e2, a2, b2, c2, d2, X[ 7], k8);
	Subround<G,15>(d2, e2, a2, b2, c2, X[10], k8);
	Subround<G, 8>(c2, d2, e2, a2, b2, X[14], k8);

	Subround<F, 8>(b2, c2, d2, e2, a2, X[12], k9);
	Subround<F, 5>(a2, b2, c2, d2, e2, X[15], k9);
	Subround<F,12>(e2, a2, b2, c2, d2, X[10], k9);
	Subround<F, 9>(d2, e2, a2, b2, c2, X[ 4], k9);
	Subround<F,12>(c2, d2, e2, a2, b2, X[ 1], k9);
	Subround<F, 5>(b2, c2, d2, e2, a2, X[ 5], k9);
	Subround<F,14>(a2, b2, c2, d2, e2, X[ 8], k9);
	Subround<F, 6>(e2, a2, b2, c2, d2, X[ 7], k9);
	Subround<F, 8>(d2, e2, a2, b2, c2, X[ 6], k9);
	Subround<F,13>(c2, d2, e2, a2, b2, X[ 2], k9);
	Subround<F, 6>(b2, c2, d2, e2, a2, X[13], k9);
	Subround<F, 5>(a2, b2, c2, d2, e2, X[14], k9);
	Subround<F,15>(e2, a2, b2, c2, d2, X[ 0], k9);
	Subround<F,13>(d2, e2, a2, b2, c2, X[ 3], k9);
	Subround<F,11>(c2, d2, e2, a2, b2, X[ 9], k9);
	Subround<F,11>(b2, c2, d2, e2, a2, X[11], k9);

	a1 -= trackA[0];
	b1 -= trackA[1];
	c1 -= trackA[2];
	d1 -= trackA[3];
	e1 -= trackA[4];
	a2 -= trackB[0];
	b2 -= trackB[1];
	c2 -= trackB[2];
	d2 -= trackB[3];
	e2 -= trackB[4];

	if (!last)
	{
		trackA[0] = (b1 + e1) - d2;
		trackA[1] = c1 - e2;
		trackA[2] = d1 - a2;
		trackA[3] = e1 - b2;
		trackA[4] = a1 - c2;
		trackB[0] = d1 - e2;
		trackB[1] = (e1 + c1) - a2;
		trackB[2] = a1 - b2;
		trackB[3] = b1 - c2;
		trackB[4] = c1 - d2;
	}
	else
	{
		trackB[0] = a2 - a1;
		trackB[1] = b2 - b1;
		trackB[2] = c2 - c1;
		trackB[3] = d2 - d1;
		trackB[4] = e2 - e1;
		trackA[0] = 0;
		trackA[1] = 0;
		trackA[2] = 0;
		trackA[3] = 0;
		trackA[4] = 0;
	}
}

NAMESPACE_END
