// ecpm.h - written and placed in public domain by Jean-Pierre Muench. Copyright assigned to Crypto++ project.

//! \file ecpm.h
//! \brief Classes for montgomery curves over prime fields

#ifndef CRYPTOPP_ECPM_H
#define CRYPTOPP_ECPM_H

#include "cryptlib.h"
#include "integer.h"
#include "modarith.h"
#include "eprecomp.h"
#include "smartptr.h"
#include "pubkey.h"
#include "ecp.h"

NAMESPACE_BEGIN(CryptoPP)

// strategy:
// first do it the conservative way: each SimultaneousMultiply is followed and preceeded by a transformation
// later replace this algorithm using an optimized algorithm using the Montgomery Ladder
class CRYPTOPP_DLL ECPM : public AbstractGroup<ECPPoint>
{
public:
	typedef ModularArithmetic Field;
	typedef Integer FieldElement;
	typedef ECPPoint Point;

	ECPM() {}
	ECPM(const ECPM &ecp, bool convertToMontgomeryRepresentation = false);
	ECPM(const Integer &modulus, const FieldElement &A, const FieldElement &B);
	// construct from BER encoded parameters
	// this constructor will decode and extract the the fields fieldID and curve of the sequence ECParameters
	ECPM(BufferedTransformation &bt);

	// encode the fields fieldID and curve of the sequence ECParameters
	void DEREncode(BufferedTransformation &bt) const;

	bool Equal(const Point &P, const Point &Q) const;
	const Point& Identity() const;
	const Point& Inverse(const Point &P) const;
	bool InversionIsFast() const { return true; }
	const Point& Add(const Point &P, const Point &Q) const;
	const Point& Double(const Point &P) const;
	Point ScalarMultiply(const Point &P, const Integer &k) const;
	Point CascadeScalarMultiply(const Point &P, const Integer &k1, const Point &Q, const Integer &k2) const;
	void SimultaneousMultiply(Point *results, const Point &base, const Integer *exponents, unsigned int exponentsCount) const;

	Point Multiply(const Integer &k, const Point &P) const
	{
		return ScalarMultiply(P, k);
	}
	Point CascadeMultiply(const Integer &k1, const Point &P, const Integer &k2, const Point &Q) const
	{
		return CascadeScalarMultiply(P, k1, Q, k2);
	}

	bool ValidateParameters(RandomNumberGenerator &rng, unsigned int level = 3) const;
	bool VerifyPoint(const Point &P) const;

	unsigned int EncodedPointSize(bool compressed = false) const
	{
		return 1 + (compressed ? 1 : 2)*GetField().MaxElementByteLength();
	}
	// returns false if point is compressed and not valid (doesn't check if uncompressed)
	bool DecodePoint(Point &P, BufferedTransformation &bt, size_t len) const;
	bool DecodePoint(Point &P, const byte *encodedPoint, size_t len) const;
	void EncodePoint(byte *encodedPoint, const Point &P, bool compressed) const;
	void EncodePoint(BufferedTransformation &bt, const Point &P, bool compressed) const;

	Point BERDecodePoint(BufferedTransformation &bt) const;
	void DEREncodePoint(BufferedTransformation &bt, const Point &P, bool compressed) const;

	Integer FieldSize() const { return GetField().GetModulus(); }
	const Field & GetField() const { return *m_fieldPtr; }
	const FieldElement & GetA() const { return m_A; }
	const FieldElement & GetB() const { return m_B; }

	bool operator==(const ECPM &rhs) const
	{
		return GetField() == rhs.GetField() && m_A == rhs.m_A && m_B == rhs.m_B;
	}

	void operator=(const ECPM &rhs);

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~ECPM() {}
#endif

private:
	inline Point WeierstrassToMontgomery(const Point& In) const;
	inline Point MontgomeryToWeierstrass(const Point& In) const;

	clonable_ptr<Field> m_fieldPtr;
	clonable_ptr<ECP> m_ComputeEngine; // does the heavy lifting on the scalar multiplication
	FieldElement m_A, m_B; // M_B * y^2 = x^3 + m_A * x^2 + x (mod p)
	FieldElement m_AThirds, m_BInv; // for faster conversion, A/3 and 1/B
	mutable Point m_R;

};

template <class T> class EcPrecomputation;

//! ECPM precomputation
template<> class EcPrecomputation<ECPM> : public DL_GroupPrecomputation<ECPM::Point>
{
public:
	typedef ECPM EllipticCurve;

	// DL_GroupPrecomputation
	bool NeedConversions() const { return true; }
	Element ConvertIn(const Element &P) const
	{
		return P.identity ? P : ECPM::Point(m_ec->GetField().ConvertIn(P.x), m_ec->GetField().ConvertIn(P.y));
	};
	Element ConvertOut(const Element &P) const
	{
		return P.identity ? P : ECPM::Point(m_ec->GetField().ConvertOut(P.x), m_ec->GetField().ConvertOut(P.y));
	}
	const AbstractGroup<Element> & GetGroup() const { return *m_ec; }
	Element BERDecodeElement(BufferedTransformation &bt) const { return m_ec->BERDecodePoint(bt); }
	void DEREncodeElement(BufferedTransformation &bt, const Element &v) const { m_ec->DEREncodePoint(bt, v, false); }

	// non-inherited
	void SetCurve(const ECPM &ec)
	{
		m_ec.reset(new ECPM(ec, true));
		m_ecOriginal = ec;
	}
	const ECPM & GetCurve() const { return *m_ecOriginal; }

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~EcPrecomputation() {}
#endif

private:
	value_ptr<ECPM> m_ec, m_ecOriginal;
};

NAMESPACE_END

#endif