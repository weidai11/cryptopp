// rw.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "rw.h"
#include "nbtheory.h"
#include "asn.h"

NAMESPACE_BEGIN(CryptoPP)

void EMSA2Pad::ComputeMessageRepresentative(RandomNumberGenerator &rng, 
	const byte *recoverableMessage, unsigned int recoverableMessageLength,
	HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
	byte *representative, unsigned int representativeBitLength) const
{
	if (representativeBitLength % 8 != 7)
		throw PK_SignatureScheme::InvalidKeyLength("EMSA2: EMSA2 requires a key length that is a multiple of 8");

	unsigned int digestSize = hash.DigestSize();
	if (representativeBitLength < 8*digestSize + 31)
		throw PK_SignatureScheme::KeyTooShort();

	unsigned int representativeByteLength = BitsToBytes(representativeBitLength);

	representative[0] = messageEmpty ? 0x4b : 0x6b;
	memset(representative+1, 0xbb, representativeByteLength-digestSize-4);	// pad with 0xbb
	byte *afterP2 = representative+representativeByteLength-digestSize-3;
	afterP2[0] = 0xba;
	hash.Final(afterP2+1);
	representative[representativeByteLength-2] = *hashIdentifier.first;
	representative[representativeByteLength-1] = 0xcc;
}

// *****************************************************************************

void RWFunction::BERDecode(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	m_n.BERDecode(seq);
	seq.MessageEnd();
}

void RWFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	m_n.DEREncode(seq);
	seq.MessageEnd();
}

Integer RWFunction::ApplyFunction(const Integer &in) const
{
	DoQuickSanityCheck();

	Integer out = in.Squared()%m_n;
	const word r = 12;
	// this code was written to handle both r = 6 and r = 12,
	// but now only r = 12 is used in P1363
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

bool RWFunction::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
	bool pass = true;
	pass = pass && m_n > Integer::One() && m_n%8 == 5;
	return pass;
}

bool RWFunction::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	return GetValueHelper(this, name, valueType, pValue).Assignable()
		CRYPTOPP_GET_FUNCTION_ENTRY(Modulus)
		;
}

void RWFunction::AssignFrom(const NameValuePairs &source)
{
	AssignFromHelper(this, source)
		CRYPTOPP_SET_FUNCTION_ENTRY(Modulus)
		;
}

// *****************************************************************************
// private key operations:

// generate a random private key
void InvertibleRWFunction::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg)
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

void InvertibleRWFunction::BERDecode(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	m_n.BERDecode(seq);
	m_p.BERDecode(seq);
	m_q.BERDecode(seq);
	m_u.BERDecode(seq);
	seq.MessageEnd();
}

void InvertibleRWFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	m_n.DEREncode(seq);
	m_p.DEREncode(seq);
	m_q.DEREncode(seq);
	m_u.DEREncode(seq);
	seq.MessageEnd();
}

Integer InvertibleRWFunction::CalculateInverse(RandomNumberGenerator &rng, const Integer &in) const
{
	// no need to do blinding because RW is only used for signatures

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

bool InvertibleRWFunction::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
	bool pass = RWFunction::Validate(rng, level);
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

bool InvertibleRWFunction::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	return GetValueHelper<RWFunction>(this, name, valueType, pValue).Assignable()
		CRYPTOPP_GET_FUNCTION_ENTRY(Prime1)
		CRYPTOPP_GET_FUNCTION_ENTRY(Prime2)
		CRYPTOPP_GET_FUNCTION_ENTRY(MultiplicativeInverseOfPrime2ModPrime1)
		;
}

void InvertibleRWFunction::AssignFrom(const NameValuePairs &source)
{
	AssignFromHelper<RWFunction>(this, source)
		CRYPTOPP_SET_FUNCTION_ENTRY(Prime1)
		CRYPTOPP_SET_FUNCTION_ENTRY(Prime2)
		CRYPTOPP_SET_FUNCTION_ENTRY(MultiplicativeInverseOfPrime2ModPrime1)
		;
}

NAMESPACE_END
