#ifndef CRYPTOPP_RW_H
#define CRYPTOPP_RW_H

/** \file
	This file contains classes that implement the
	Rabin-Williams signature schemes as defined in IEEE P1363.
*/

#include "integer.h"
#include "pssr.h"

NAMESPACE_BEGIN(CryptoPP)

//! .
class RWFunction : virtual public TrapdoorFunction, public PublicKey
{
	typedef RWFunction ThisClass;

public:
	void Initialize(const Integer &n)
		{m_n = n;}

	void BERDecode(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	Integer ApplyFunction(const Integer &x) const;
	Integer PreimageBound() const {return ++(m_n>>1);}
	Integer ImageBound() const {return m_n;}

	bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);

	const Integer& GetModulus() const {return m_n;}
	void SetModulus(const Integer &n) {m_n = n;}

protected:
	Integer m_n;
};

//! .
class InvertibleRWFunction : public RWFunction, public TrapdoorFunctionInverse, public PrivateKey
{
	typedef InvertibleRWFunction ThisClass;

public:
	void Initialize(const Integer &n, const Integer &p, const Integer &q, const Integer &u)
		{m_n = n; m_p = p; m_q = q; m_u = u;}
	// generate a random private key
	void Initialize(RandomNumberGenerator &rng, unsigned int modulusBits)
		{GenerateRandomWithKeySize(rng, modulusBits);}

	void BERDecode(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	Integer CalculateInverse(RandomNumberGenerator &rng, const Integer &x) const;

	// GeneratibleCryptoMaterial
	bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);
	/*! parameters: (ModulusSize) */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);

	const Integer& GetPrime1() const {return m_p;}
	const Integer& GetPrime2() const {return m_q;}
	const Integer& GetMultiplicativeInverseOfPrime2ModPrime1() const {return m_u;}

	void SetPrime1(const Integer &p) {m_p = p;}
	void SetPrime2(const Integer &q) {m_q = q;}
	void SetMultiplicativeInverseOfPrime2ModPrime1(const Integer &u) {m_u = u;}

protected:
	Integer m_p, m_q, m_u;
};

//! .
class EMSA2Pad : public EMSA2HashIdLookup<PK_DeterministicSignatureMessageEncodingMethod>
{
public:
	static const char *StaticAlgorithmName() {return "EMSA2";}
	
	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const {return (paddedLength+1)/8-2;}

	void ComputeMessageRepresentative(RandomNumberGenerator &rng, 
		const byte *recoverableMessage, unsigned int recoverableMessageLength,
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const;
};

//! EMSA2, for use with RW
/*! The following hash functions are supported: SHA, RIPEMD160. */
struct P1363_EMSA2 : public SignatureStandard
{
	typedef EMSA2Pad SignatureMessageEncodingMethod;
};

//! .
struct RW
{
	static std::string StaticAlgorithmName() {return "RW";}
	typedef RWFunction PublicKey;
	typedef InvertibleRWFunction PrivateKey;
};

//! RWSS
template <class STANDARD, class H>
struct RWSS : public TF_SS<STANDARD, H, RW>
{
};

NAMESPACE_END

#endif
