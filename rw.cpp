// rw.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "rw.h"
#include "nbtheory.h"
#include "asn.h"

NAMESPACE_BEGIN(CryptoPP)

template<> const byte EMSA2DigestDecoration<SHA>::decoration = 0x33;
template<> const byte EMSA2DigestDecoration<RIPEMD160>::decoration = 0x31;

void EMSA2Pad::Pad(RandomNumberGenerator &, const byte *input, unsigned int inputLen, byte *emsa2Block, unsigned int emsa2BlockLen) const
{
	assert (inputLen > 0 && inputLen <= MaxUnpaddedLength(emsa2BlockLen));

	// convert from bit length to byte length
	emsa2BlockLen++;
	if (emsa2BlockLen % 8 > 1)
	{
		emsa2Block[0] = 0;
		emsa2Block++;
	}
	emsa2BlockLen /= 8;

	emsa2Block[0] = input[0];			// indicate empty or non-empty message
	memset(emsa2Block+1, 0xbb, emsa2BlockLen-inputLen-2);	// padd with 0xbb
	emsa2Block[emsa2BlockLen-inputLen-1] = 0xba;	// separator
	memcpy(emsa2Block+emsa2BlockLen-inputLen, input+1, inputLen-1);
	emsa2Block[emsa2BlockLen-1] = 0xcc;	// make it congruent to 12 mod 16
}

DecodingResult EMSA2Pad::Unpad(const byte *emsa2Block, unsigned int emsa2BlockLen, byte *output) const
{
	// convert from bit length to byte length
	emsa2BlockLen++;
	if (emsa2BlockLen % 8 > 1)
	{
		if (emsa2Block[0] != 0)
			return DecodingResult();
		emsa2Block++;
	}
	emsa2BlockLen /= 8;

	// check last byte
	if (emsa2Block[emsa2BlockLen-1] != 0xcc)
		return DecodingResult();

	// skip past the padding until we find the seperator
	unsigned i=1;
	while (i<emsa2BlockLen-1 && emsa2Block[i++] != 0xba)
		if (emsa2Block[i-1] != 0xbb)     // not valid padding
			return DecodingResult();
	assert(i==emsa2BlockLen-1 || emsa2Block[i-1]==0xba);

	unsigned int outputLen = emsa2BlockLen - i;
	output[0] = emsa2Block[0];
	memcpy (output+1, emsa2Block+i, outputLen-1);
	return DecodingResult(outputLen);
}

// *****************************************************************************

template <word r>
void RWFunction<r>::BERDecode(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	m_n.BERDecode(seq);
	seq.MessageEnd();
}

template <word r>
void RWFunction<r>::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	m_n.DEREncode(seq);
	seq.MessageEnd();
}

template <word r>
Integer RWFunction<r>::ApplyFunction(const Integer &in) const
{
	DoQuickSanityCheck();

	Integer out = in.Squared()%m_n;
	const word r2 = r/2;
	const word r3a = (16 + 5 - r) % 16;	// n%16 could be 5 or 13
	const word r3b = (16 + 13 - r) % 16;
	const word r4 = (8 + 5 - r/2) % 8;	// n%8 == 5
	switch (out % 16)
	{
	case r:
		break;
	case r2:
	case r2+8:
		out <<= 1;
		break;
	case r3a:
	case r3b:
		out.Negate();
		out += m_n;
		break;
	case r4:
	case r4+8:
		out.Negate();
		out += m_n;
		out <<= 1;
		break;
	default:
		out = Integer::Zero();
	}
	return out;
}

template <word r>
bool RWFunction<r>::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
	bool pass = true;
	pass = pass && m_n > Integer::One() && m_n%8 == 5;
	return pass;
}

template <word r>
bool RWFunction<r>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	return GetValueHelper(this, name, valueType, pValue).Assignable()
		CRYPTOPP_GET_FUNCTION_ENTRY(Modulus)
		;
}

template <word r>
void RWFunction<r>::AssignFrom(const NameValuePairs &source)
{
	AssignFromHelper(this, source)
		CRYPTOPP_SET_FUNCTION_ENTRY(Modulus)
		;
}

// *****************************************************************************
// private key operations:

// generate a random private key
template <word r>
void InvertibleRWFunction<r>::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg)
{
	int modulusSize = 2048;
	alg.GetIntValue("ModulusSize", modulusSize) || alg.GetIntValue("KeySize", modulusSize);

	if (modulusSize < 16)
		throw InvalidArgument("InvertibleRWFunction: specified modulus length is too small");

	const NameValuePairs &primeParam = MakeParametersForTwoPrimesOfEqualSize(modulusSize);
	m_p.GenerateRandom(rng, CombinedNameValuePairs(primeParam, MakeParameters("EquivalentTo", 3)("Mod", 8)));
	m_q.GenerateRandom(rng, CombinedNameValuePairs(primeParam, MakeParameters("EquivalentTo", 7)("Mod", 8)));

	m_n = m_p * m_q;
	m_u = m_q.InverseMod(m_p);
}

template <word r>
void InvertibleRWFunction<r>::BERDecode(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	m_n.BERDecode(seq);
	m_p.BERDecode(seq);
	m_q.BERDecode(seq);
	m_u.BERDecode(seq);
	seq.MessageEnd();
}

template <word r>
void InvertibleRWFunction<r>::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	m_n.DEREncode(seq);
	m_p.DEREncode(seq);
	m_q.DEREncode(seq);
	m_u.DEREncode(seq);
	seq.MessageEnd();
}

template <word r>
Integer InvertibleRWFunction<r>::CalculateInverse(const Integer &in) const
{
	DoQuickSanityCheck();

	Integer cp=in%m_p, cq=in%m_q;

	if (Jacobi(cp, m_p) * Jacobi(cq, m_q) != 1)
	{
		cp = cp%2 ? (cp+m_p) >> 1 : cp >> 1;
		cq = cq%2 ? (cq+m_q) >> 1 : cq >> 1;
	}

	cp = ModularSquareRoot(cp, m_p);
	cq = ModularSquareRoot(cq, m_q);

	Integer out = CRT(cq, m_q, cp, m_p, m_u);

	return STDMIN(out, m_n-out);
}

template <word r>
bool InvertibleRWFunction<r>::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
	bool pass = RWFunction<r>::Validate(rng, level);
	pass = pass && m_p > Integer::One() && m_p%8 == 3 && m_p < m_n;
	pass = pass && m_q > Integer::One() && m_q%8 == 7 && m_q < m_n;
	pass = pass && m_u.IsPositive() && m_u < m_p;
	if (level >= 1)
	{
		pass = pass && m_p * m_q == m_n;
		pass = pass && m_u * m_q % m_p == 1;
	}
	if (level >= 2)
		pass = pass && VerifyPrime(rng, m_p, level-2) && VerifyPrime(rng, m_q, level-2);
	return pass;
}

template <word r>
bool InvertibleRWFunction<r>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	return GetValueHelper<RWFunction<r> >(this, name, valueType, pValue).Assignable()
		CRYPTOPP_GET_FUNCTION_ENTRY(Prime1)
		CRYPTOPP_GET_FUNCTION_ENTRY(Prime2)
		CRYPTOPP_GET_FUNCTION_ENTRY(MultiplicativeInverseOfPrime2ModPrime1)
		;
}

template <word r>
void InvertibleRWFunction<r>::AssignFrom(const NameValuePairs &source)
{
	AssignFromHelper<RWFunction<r> >(this, source)
		CRYPTOPP_SET_FUNCTION_ENTRY(Prime1)
		CRYPTOPP_SET_FUNCTION_ENTRY(Prime2)
		CRYPTOPP_SET_FUNCTION_ENTRY(MultiplicativeInverseOfPrime2ModPrime1)
		;
}

template class RWFunction<IFSSA_R>;
template class InvertibleRWFunction<IFSSA_R>;

NAMESPACE_END
