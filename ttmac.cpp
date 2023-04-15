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

template <unsigned int S, typename Fn>
void Subround(Fn fn, word32& a, word32 b, word32& c, word32 d, word32 e, word32 x, word32 k)
{
	a += fn(b, c, d) + x + k;
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

	std::memcpy(m_key, userKey, KEYLENGTH);
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
	std::memcpy(hash, m_digest, size);

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

	Subround<11>(F, a1, b1, c1, d1, e1, X[ 0], k0);
	Subround<14>(F, e1, a1, b1, c1, d1, X[ 1], k0);
	Subround<15>(F, d1, e1, a1, b1, c1, X[ 2], k0);
	Subround<12>(F, c1, d1, e1, a1, b1, X[ 3], k0);
	Subround< 5>(F, b1, c1, d1, e1, a1, X[ 4], k0);
	Subround< 8>(F, a1, b1, c1, d1, e1, X[ 5], k0);
	Subround< 7>(F, e1, a1, b1, c1, d1, X[ 6], k0);
	Subround< 9>(F, d1, e1, a1, b1, c1, X[ 7], k0);
	Subround<11>(F, c1, d1, e1, a1, b1, X[ 8], k0);
	Subround<13>(F, b1, c1, d1, e1, a1, X[ 9], k0);
	Subround<14>(F, a1, b1, c1, d1, e1, X[10], k0);
	Subround<15>(F, e1, a1, b1, c1, d1, X[11], k0);
	Subround< 6>(F, d1, e1, a1, b1, c1, X[12], k0);
	Subround< 7>(F, c1, d1, e1, a1, b1, X[13], k0);
	Subround< 9>(F, b1, c1, d1, e1, a1, X[14], k0);
	Subround< 8>(F, a1, b1, c1, d1, e1, X[15], k0);

	Subround< 7>(G, e1, a1, b1, c1, d1, X[ 7], k1);
	Subround< 6>(G, d1, e1, a1, b1, c1, X[ 4], k1);
	Subround< 8>(G, c1, d1, e1, a1, b1, X[13], k1);
	Subround<13>(G, b1, c1, d1, e1, a1, X[ 1], k1);
	Subround<11>(G, a1, b1, c1, d1, e1, X[10], k1);
	Subround< 9>(G, e1, a1, b1, c1, d1, X[ 6], k1);
	Subround< 7>(G, d1, e1, a1, b1, c1, X[15], k1);
	Subround<15>(G, c1, d1, e1, a1, b1, X[ 3], k1);
	Subround< 7>(G, b1, c1, d1, e1, a1, X[12], k1);
	Subround<12>(G, a1, b1, c1, d1, e1, X[ 0], k1);
	Subround<15>(G, e1, a1, b1, c1, d1, X[ 9], k1);
	Subround< 9>(G, d1, e1, a1, b1, c1, X[ 5], k1);
	Subround<11>(G, c1, d1, e1, a1, b1, X[ 2], k1);
	Subround< 7>(G, b1, c1, d1, e1, a1, X[14], k1);
	Subround<13>(G, a1, b1, c1, d1, e1, X[11], k1);
	Subround<12>(G, e1, a1, b1, c1, d1, X[ 8], k1);

	Subround<11>(H, d1, e1, a1, b1, c1, X[ 3], k2);
	Subround<13>(H, c1, d1, e1, a1, b1, X[10], k2);
	Subround< 6>(H, b1, c1, d1, e1, a1, X[14], k2);
	Subround< 7>(H, a1, b1, c1, d1, e1, X[ 4], k2);
	Subround<14>(H, e1, a1, b1, c1, d1, X[ 9], k2);
	Subround< 9>(H, d1, e1, a1, b1, c1, X[15], k2);
	Subround<13>(H, c1, d1, e1, a1, b1, X[ 8], k2);
	Subround<15>(H, b1, c1, d1, e1, a1, X[ 1], k2);
	Subround<14>(H, a1, b1, c1, d1, e1, X[ 2], k2);
	Subround< 8>(H, e1, a1, b1, c1, d1, X[ 7], k2);
	Subround<13>(H, d1, e1, a1, b1, c1, X[ 0], k2);
	Subround< 6>(H, c1, d1, e1, a1, b1, X[ 6], k2);
	Subround< 5>(H, b1, c1, d1, e1, a1, X[13], k2);
	Subround<12>(H, a1, b1, c1, d1, e1, X[11], k2);
	Subround< 7>(H, e1, a1, b1, c1, d1, X[ 5], k2);
	Subround< 5>(H, d1, e1, a1, b1, c1, X[12], k2);

	Subround<11>(I, c1, d1, e1, a1, b1, X[ 1], k3);
	Subround<12>(I, b1, c1, d1, e1, a1, X[ 9], k3);
	Subround<14>(I, a1, b1, c1, d1, e1, X[11], k3);
	Subround<15>(I, e1, a1, b1, c1, d1, X[10], k3);
	Subround<14>(I, d1, e1, a1, b1, c1, X[ 0], k3);
	Subround<15>(I, c1, d1, e1, a1, b1, X[ 8], k3);
	Subround< 9>(I, b1, c1, d1, e1, a1, X[12], k3);
	Subround< 8>(I, a1, b1, c1, d1, e1, X[ 4], k3);
	Subround< 9>(I, e1, a1, b1, c1, d1, X[13], k3);
	Subround<14>(I, d1, e1, a1, b1, c1, X[ 3], k3);
	Subround< 5>(I, c1, d1, e1, a1, b1, X[ 7], k3);
	Subround< 6>(I, b1, c1, d1, e1, a1, X[15], k3);
	Subround< 8>(I, a1, b1, c1, d1, e1, X[14], k3);
	Subround< 6>(I, e1, a1, b1, c1, d1, X[ 5], k3);
	Subround< 5>(I, d1, e1, a1, b1, c1, X[ 6], k3);
	Subround<12>(I, c1, d1, e1, a1, b1, X[ 2], k3);

	Subround< 9>(J, b1, c1, d1, e1, a1, X[ 4], k4);
	Subround<15>(J, a1, b1, c1, d1, e1, X[ 0], k4);
	Subround< 5>(J, e1, a1, b1, c1, d1, X[ 5], k4);
	Subround<11>(J, d1, e1, a1, b1, c1, X[ 9], k4);
	Subround< 6>(J, c1, d1, e1, a1, b1, X[ 7], k4);
	Subround< 8>(J, b1, c1, d1, e1, a1, X[12], k4);
	Subround<13>(J, a1, b1, c1, d1, e1, X[ 2], k4);
	Subround<12>(J, e1, a1, b1, c1, d1, X[10], k4);
	Subround< 5>(J, d1, e1, a1, b1, c1, X[14], k4);
	Subround<12>(J, c1, d1, e1, a1, b1, X[ 1], k4);
	Subround<13>(J, b1, c1, d1, e1, a1, X[ 3], k4);
	Subround<14>(J, a1, b1, c1, d1, e1, X[ 8], k4);
	Subround<11>(J, e1, a1, b1, c1, d1, X[11], k4);
	Subround< 8>(J, d1, e1, a1, b1, c1, X[ 6], k4);
	Subround< 5>(J, c1, d1, e1, a1, b1, X[15], k4);
	Subround< 6>(J, b1, c1, d1, e1, a1, X[13], k4);

	Subround< 8>(J, a2, b2, c2, d2, e2, X[ 5], k5);
	Subround< 9>(J, e2, a2, b2, c2, d2, X[14], k5);
	Subround< 9>(J, d2, e2, a2, b2, c2, X[ 7], k5);
	Subround<11>(J, c2, d2, e2, a2, b2, X[ 0], k5);
	Subround<13>(J, b2, c2, d2, e2, a2, X[ 9], k5);
	Subround<15>(J, a2, b2, c2, d2, e2, X[ 2], k5);
	Subround<15>(J, e2, a2, b2, c2, d2, X[11], k5);
	Subround< 5>(J, d2, e2, a2, b2, c2, X[ 4], k5);
	Subround< 7>(J, c2, d2, e2, a2, b2, X[13], k5);
	Subround< 7>(J, b2, c2, d2, e2, a2, X[ 6], k5);
	Subround< 8>(J, a2, b2, c2, d2, e2, X[15], k5);
	Subround<11>(J, e2, a2, b2, c2, d2, X[ 8], k5);
	Subround<14>(J, d2, e2, a2, b2, c2, X[ 1], k5);
	Subround<14>(J, c2, d2, e2, a2, b2, X[10], k5);
	Subround<12>(J, b2, c2, d2, e2, a2, X[ 3], k5);
	Subround< 6>(J, a2, b2, c2, d2, e2, X[12], k5);

	Subround< 9>(I, e2, a2, b2, c2, d2, X[ 6], k6);
	Subround<13>(I, d2, e2, a2, b2, c2, X[11], k6);
	Subround<15>(I, c2, d2, e2, a2, b2, X[ 3], k6);
	Subround< 7>(I, b2, c2, d2, e2, a2, X[ 7], k6);
	Subround<12>(I, a2, b2, c2, d2, e2, X[ 0], k6);
	Subround< 8>(I, e2, a2, b2, c2, d2, X[13], k6);
	Subround< 9>(I, d2, e2, a2, b2, c2, X[ 5], k6);
	Subround<11>(I, c2, d2, e2, a2, b2, X[10], k6);
	Subround< 7>(I, b2, c2, d2, e2, a2, X[14], k6);
	Subround< 7>(I, a2, b2, c2, d2, e2, X[15], k6);
	Subround<12>(I, e2, a2, b2, c2, d2, X[ 8], k6);
	Subround< 7>(I, d2, e2, a2, b2, c2, X[12], k6);
	Subround< 6>(I, c2, d2, e2, a2, b2, X[ 4], k6);
	Subround<15>(I, b2, c2, d2, e2, a2, X[ 9], k6);
	Subround<13>(I, a2, b2, c2, d2, e2, X[ 1], k6);
	Subround<11>(I, e2, a2, b2, c2, d2, X[ 2], k6);

	Subround< 9>(H, d2, e2, a2, b2, c2, X[15], k7);
	Subround< 7>(H, c2, d2, e2, a2, b2, X[ 5], k7);
	Subround<15>(H, b2, c2, d2, e2, a2, X[ 1], k7);
	Subround<11>(H, a2, b2, c2, d2, e2, X[ 3], k7);
	Subround< 8>(H, e2, a2, b2, c2, d2, X[ 7], k7);
	Subround< 6>(H, d2, e2, a2, b2, c2, X[14], k7);
	Subround< 6>(H, c2, d2, e2, a2, b2, X[ 6], k7);
	Subround<14>(H, b2, c2, d2, e2, a2, X[ 9], k7);
	Subround<12>(H, a2, b2, c2, d2, e2, X[11], k7);
	Subround<13>(H, e2, a2, b2, c2, d2, X[ 8], k7);
	Subround< 5>(H, d2, e2, a2, b2, c2, X[12], k7);
	Subround<14>(H, c2, d2, e2, a2, b2, X[ 2], k7);
	Subround<13>(H, b2, c2, d2, e2, a2, X[10], k7);
	Subround<13>(H, a2, b2, c2, d2, e2, X[ 0], k7);
	Subround< 7>(H, e2, a2, b2, c2, d2, X[ 4], k7);
	Subround< 5>(H, d2, e2, a2, b2, c2, X[13], k7);

	Subround<15>(G, c2, d2, e2, a2, b2, X[ 8], k8);
	Subround< 5>(G, b2, c2, d2, e2, a2, X[ 6], k8);
	Subround< 8>(G, a2, b2, c2, d2, e2, X[ 4], k8);
	Subround<11>(G, e2, a2, b2, c2, d2, X[ 1], k8);
	Subround<14>(G, d2, e2, a2, b2, c2, X[ 3], k8);
	Subround<14>(G, c2, d2, e2, a2, b2, X[11], k8);
	Subround< 6>(G, b2, c2, d2, e2, a2, X[15], k8);
	Subround<14>(G, a2, b2, c2, d2, e2, X[ 0], k8);
	Subround< 6>(G, e2, a2, b2, c2, d2, X[ 5], k8);
	Subround< 9>(G, d2, e2, a2, b2, c2, X[12], k8);
	Subround<12>(G, c2, d2, e2, a2, b2, X[ 2], k8);
	Subround< 9>(G, b2, c2, d2, e2, a2, X[13], k8);
	Subround<12>(G, a2, b2, c2, d2, e2, X[ 9], k8);
	Subround< 5>(G, e2, a2, b2, c2, d2, X[ 7], k8);
	Subround<15>(G, d2, e2, a2, b2, c2, X[10], k8);
	Subround< 8>(G, c2, d2, e2, a2, b2, X[14], k8);

	Subround< 8>(F, b2, c2, d2, e2, a2, X[12], k9);
	Subround< 5>(F, a2, b2, c2, d2, e2, X[15], k9);
	Subround<12>(F, e2, a2, b2, c2, d2, X[10], k9);
	Subround< 9>(F, d2, e2, a2, b2, c2, X[ 4], k9);
	Subround<12>(F, c2, d2, e2, a2, b2, X[ 1], k9);
	Subround< 5>(F, b2, c2, d2, e2, a2, X[ 5], k9);
	Subround<14>(F, a2, b2, c2, d2, e2, X[ 8], k9);
	Subround< 6>(F, e2, a2, b2, c2, d2, X[ 7], k9);
	Subround< 8>(F, d2, e2, a2, b2, c2, X[ 6], k9);
	Subround<13>(F, c2, d2, e2, a2, b2, X[ 2], k9);
	Subround< 6>(F, b2, c2, d2, e2, a2, X[13], k9);
	Subround< 5>(F, a2, b2, c2, d2, e2, X[14], k9);
	Subround<15>(F, e2, a2, b2, c2, d2, X[ 0], k9);
	Subround<13>(F, d2, e2, a2, b2, c2, X[ 3], k9);
	Subround<11>(F, c2, d2, e2, a2, b2, X[ 9], k9);
	Subround<11>(F, b2, c2, d2, e2, a2, X[11], k9);

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
