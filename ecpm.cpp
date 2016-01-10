// ecpm.cpp - written and placed in public domain by Jean-Pierre Muench. Copyright assigned to the Crypto++ project.

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "ecp.h"
#include "ecpm.h"
#include "asn.h"
#include "integer.h"
#include "nbtheory.h"
#include "modarith.h"
#include "filters.h"
#include "algebra.cpp"

NAMESPACE_BEGIN(CryptoPP)

ANONYMOUS_NAMESPACE_BEGIN
static inline ECP::Point ToMontgomery(const ModularArithmetic &mr, const ECP::Point &P) // straight from ecp.cpp
{
	return P.identity ? P : ECP::Point(mr.ConvertIn(P.x), mr.ConvertIn(P.y));
}

static inline ECP::Point FromMontgomery(const ModularArithmetic &mr, const ECP::Point &P) // straight from ecp.cpp
{
	return P.identity ? P : ECP::Point(mr.ConvertOut(P.x), mr.ConvertOut(P.y));
}
static inline ECP* GenerateWeierstrassCurve(const ECPM& MontgomeryCurve)
{
	const Integer& A = MontgomeryCurve.GetA();
	const Integer& B = MontgomeryCurve.GetB();
	const ModularArithmetic& Field = MontgomeryCurve.GetField();

	// now construct the equivalent Weierstrass curve
	// refer to https://crypto.stackexchange.com/q/27842 for the details
	// use m_FieldPtr to ensure encoding (eventual Montgomery Representation) is handled correctly
	//the transformations also appear independently on http ://safecurves.cr.yp.to/equation.html

	// a = (3-A)/(3B^2)
	Integer aWeierstrass = Field.Subtract(3, Field.Square(A)); // a = 3 - A
	aWeierstrass = Field.Divide(aWeierstrass, Field.Multiply(3, Field.Square(B))); // a = a / (3B^2)
	// b = (2A^3-9A) / (27 B^3)
	Integer bWeierstrass = Field.Multiply(A, Field.Subtract(Field.Multiply(2, Field.Square(A)), 9)); // b = A(2A^2-9)
	bWeierstrass = Field.Divide(bWeierstrass, Field.Multiply(27, Field.Exponentiate(B, 3))); // b = b / (27 B^3)

	return new ECP(MontgomeryCurve.GetField().GetModulus(), aWeierstrass, bWeierstrass);
}
NAMESPACE_END

ECPM::ECPM(const Integer &modulus, const FieldElement &A, const FieldElement &B): 
	m_fieldPtr(new Field(modulus))
{
	// store A and B for later use
	m_A = A.IsNegative() ? (A + modulus) : A;// straight from ecp.cpp
	m_B = B.IsNegative() ? (B + modulus) : B;// straight from ecp.cpp

	m_ComputeEngine.reset(GenerateWeierstrassCurve(*this));

	// to speed up the conversions
	m_AThirds = m_fieldPtr->Divide(m_A, 3);
	m_BInv = m_fieldPtr->MultiplicativeInverse(m_B);
}

// straight adaption from ecp.cpp
ECPM::ECPM(const ECPM &ecpm, bool convertToMontgomeryRepresentation)
{
	if (convertToMontgomeryRepresentation && !ecpm.GetField().IsMontgomeryRepresentation())
	{
		m_fieldPtr.reset(new MontgomeryRepresentation(ecpm.GetField().GetModulus()));
		m_ComputeEngine.reset(new ECP(*ecpm.m_ComputeEngine.get(),convertToMontgomeryRepresentation));
		m_A = GetField().ConvertIn(ecpm.m_A);
		m_B = GetField().ConvertIn(ecpm.m_B);
		m_AThirds = GetField().ConvertIn(ecpm.m_AThirds);
		m_BInv = GetField().ConvertIn(ecpm.m_BInv);
	}
	else
		operator=(ecpm);
}

ECPM::ECPM(BufferedTransformation &bt)
	: m_fieldPtr(new Field(bt))
{
	BERSequenceDecoder seq(bt);
	GetField().BERDecodeElement(seq, m_A);
	GetField().BERDecodeElement(seq, m_B);
	// skip optional seed
	if (!seq.EndReached())
	{
		SecByteBlock seed;
		unsigned int unused;
		BERDecodeBitString(seq, seed, unused);
	}
	seq.MessageEnd();

	m_ComputeEngine.reset(GenerateWeierstrassCurve(*this));

	m_AThirds = m_fieldPtr->Divide(m_A, 3);
	m_BInv = m_fieldPtr->MultiplicativeInverse(m_B);
}

// straight adaption from ecp.cpp
void ECPM::DEREncode(BufferedTransformation &bt) const
{
	GetField().DEREncode(bt);
	DERSequenceEncoder seq(bt);
	GetField().DEREncodeElement(seq, m_A);
	GetField().DEREncodeElement(seq, m_B);
	seq.MessageEnd();
}

// straight adaption from ecp.cpp
bool ECPM::DecodePoint(ECPM::Point &P, const byte *encodedPoint, size_t encodedPointLen) const
{
	StringStore store(encodedPoint, encodedPointLen);
	return DecodePoint(P, store, encodedPointLen);
}

// straight adaption from ecp.cpp
bool ECPM::DecodePoint(ECPM::Point &P, BufferedTransformation &bt, size_t encodedPointLen) const
{
	byte type;
	if (encodedPointLen < 1 || !bt.Get(type))
		return false;

	switch (type)
	{
	case 0:
		P.identity = true;
		return true;
	case 2:
	case 3:
	{
		if (encodedPointLen != EncodedPointSize(true))
			return false;

		Integer p = FieldSize();

		P.identity = false;
		P.x.Decode(bt, GetField().MaxElementByteLength());
		// curve is: By^2=x^3+Ax^2+x <=> y=sqrt(x/B(x(A+x)+1)
		P.y = (m_BInv * P.x *(P.x * (P.x + m_A) + Integer::One()))%p;

		if (Jacobi(P.y, p) != 1)
			return false;

		P.y = ModularSquareRoot(P.y, p);

		if ((type & 1) != P.y.GetBit(0))
			P.y = p - P.y;

		return true;
	}
	case 4:
	{
		if (encodedPointLen != EncodedPointSize(false))
			return false;

		unsigned int len = GetField().MaxElementByteLength();
		P.identity = false;
		P.x.Decode(bt, len);
		P.y.Decode(bt, len);
		return true;
	}
	default:
		return false;
	}
}

// straight adaption from ecp.cpp
void ECPM::EncodePoint(BufferedTransformation &bt, const Point &P, bool compressed) const
{
	if (P.identity)
		NullStore().TransferTo(bt, EncodedPointSize(compressed));
	else if (compressed)
	{
		bt.Put(2 + P.y.GetBit(0));
		P.x.Encode(bt, GetField().MaxElementByteLength());
	}
	else
	{
		unsigned int len = GetField().MaxElementByteLength();
		bt.Put(4);	// uncompressed
		P.x.Encode(bt, len);
		P.y.Encode(bt, len);
	}
}

// straight adaption from ecp.cpp
void ECPM::EncodePoint(byte *encodedPoint, const Point &P, bool compressed) const
{
	ArraySink sink(encodedPoint, EncodedPointSize(compressed));
	EncodePoint(sink, P, compressed);
	assert(sink.TotalPutLength() == EncodedPointSize(compressed));
}

// straight adaption from ecp.cpp
ECPM::Point ECPM::BERDecodePoint(BufferedTransformation &bt) const
{
	SecByteBlock str;
	BERDecodeOctetString(bt, str);
	Point P;
	if (!DecodePoint(P, str, str.size()))
		BERDecodeError();
	return P;
}

// straight adaption from ecp.cpp
void ECPM::DEREncodePoint(BufferedTransformation &bt, const Point &P, bool compressed) const
{
	SecByteBlock str(EncodedPointSize(compressed));
	EncodePoint(str, P, compressed);
	DEREncodeOctetString(bt, str);
}

// straight adaption from ecp.cpp
bool ECPM::ValidateParameters(RandomNumberGenerator &rng, unsigned int level) const
{
	Integer p = FieldSize();

	bool pass = p.IsOdd();
	pass = pass && !m_A.IsNegative() && m_A<p && !m_B.IsNegative() && m_B<p;

	if (level >= 1)
		pass = pass && ((m_B * (m_A * m_A - 4)) % p).IsPositive();

	if (level >= 2)
		pass = pass && VerifyPrime(rng, p);

	return pass;
}

// straight adaption from ecp.cpp
bool ECPM::VerifyPoint(const Point &P) const
{
	const FieldElement &x = P.x, &y = P.y;
	Integer p = FieldSize();

	// use the field arithmetic here, in case our data is in Montgomery form
	// ecp.cpp does this with plain integer arithmetic -> will fail if montgomery representation is on, but was never called when montgomery representation was on
	const FieldElement IsOnCurve = m_fieldPtr->Subtract(m_fieldPtr->Multiply(x,(m_fieldPtr->Add(1,m_fieldPtr->Multiply(x,(m_fieldPtr->Add(m_A,x)))))),m_fieldPtr->Multiply(m_B,m_fieldPtr->Square(y)));

	return P.identity ||
		(!x.IsNegative() && x<p && !y.IsNegative() && y<p
			&& !(IsOnCurve));
	// By^2=x^3+Ax^2+x <=> 0 == x(1+x(A+x))-By^2
}

// straight adaption from ecp.cpp
bool ECPM::Equal(const Point &P, const Point &Q) const
{
	if (P.identity && Q.identity)
		return true;

	if (P.identity && !Q.identity)
		return false;

	if (!P.identity && Q.identity)
		return false;

	return (GetField().Equal(P.x, Q.x) && GetField().Equal(P.y, Q.y));
}

// straight adaption from ecp.cpp
const ECPM::Point& ECPM::Identity() const
{
	return Singleton<Point>().Ref();
}

// straight adaption from ecp.cpp
const ECPM::Point& ECPM::Inverse(const Point &P) const
{
	if (P.identity)
		return P;
	else
	{
		m_R.identity = false;
		m_R.x = P.x;
		m_R.y = GetField().Inverse(P.y);
		return m_R;
	}
}

// straight adaption from ecp.cpp
const ECPM::Point& ECPM::Add(const Point &P, const Point &Q) const
{
	if (P.identity) return Q;
	if (Q.identity) return P;
	if (GetField().Equal(P.x, Q.x))
		return GetField().Equal(P.y, Q.y) ? Double(P) : Identity();

	FieldElement t = GetField().Subtract(Q.y, P.y); // t = y_Q - y_P
	t = GetField().Divide(t, GetField().Subtract(Q.x, P.x)); // t = (y_Q - y_P) / (x_Q - x_P)
	FieldElement x = GetField().Subtract(GetField().Subtract(GetField().Subtract(GetField().Multiply(m_B,GetField().Square(t)), P.x), Q.x),m_A); // x = B*t^2-x_P-x_Q-A
	m_R.y = GetField().Subtract(GetField().Multiply(t, GetField().Subtract(P.x, x)), P.y); // y = t * (x_P - x) - y_P

	m_R.x.swap(x);
	m_R.identity = false;
	return m_R;
}

// straight adaption from ecp.cpp
const ECPM::Point& ECPM::Double(const Point &P) const
{
	if (P.identity || P.y == GetField().Identity()) return Identity();

	FieldElement t = GetField().Add(GetField().Double(P.x), P.x);// t = 2x_P + x_P = 3x_P 
	t = GetField().Add(GetField().Multiply(P.x,GetField().Add(t,GetField().Double(m_A))), GetField().ConvertIn(1)); // x_P * ( t + 2 * A)+1
	FieldElement h1= GetField().Multiply(t, m_BInv), h2= GetField().Double(P.y); // put this in two steps or it fails somehow otherwise
	t = GetField().Divide(h1, h2); // t = (x_P(3x_P + 2A)+1)/(2B*y_P)
	FieldElement& x = m_R.x;
	x = GetField().Multiply(m_B, GetField().Square(t)); // put this in two steps or it fails somehow otherwise
	x = GetField().Subtract(GetField().Subtract(x, GetField().Double(P.x)), m_A); // x = B * t^2 - A -  x_1 - x_2
	m_R.y = GetField().Subtract(GetField().Multiply(t, GetField().Subtract(P.x, x)), P.y); // t (x_P - x) -y_P

	m_R.identity = false;
	return m_R;
}

// straight adaption from ecp.cpp
ECPM::Point ECPM::ScalarMultiply(const Point &P, const Integer &k) const
{
	Element result;
	if (k.BitCount() <= 5)
		AbstractGroup<ECPPoint>::SimultaneousMultiply(&result, P, &k, 1);
	else
		ECPM::SimultaneousMultiply(&result, P, &k, 1);
	
	return result;
}

// this is probably the cause of the issue 
void ECPM::SimultaneousMultiply(ECPM::Point *results, const ECPM::Point &P, const Integer *expBegin, unsigned int expCount) const
{
	Point ConvertedBase = MontgomeryToWeierstrass(P);
	// let the compute engine do its optimized work
	m_ComputeEngine->SimultaneousMultiply(results, ConvertedBase, expBegin, expCount);

	// fetch the results and convert them back to our preferred form
	for (unsigned int i = 0; i < expCount; ++i)
		results[i] = WeierstrassToMontgomery(results[i]);

	return;

	// implement Montgomery ladder below
}

// straight adaption from ecp.cpp
ECPM::Point ECPM::CascadeScalarMultiply(const Point &P, const Integer &k1, const Point &Q, const Integer &k2) const
{
	if (!GetField().IsMontgomeryRepresentation())
	{
		ECPM ecpmr(*this, true);
		const ModularArithmetic &mr = ecpmr.GetField();
		return FromMontgomery(mr, ecpmr.CascadeScalarMultiply(ToMontgomery(mr, P), k1, ToMontgomery(mr, Q), k2));
	}
	else
		return AbstractGroup<Point>::CascadeScalarMultiply(P, k1, Q, k2);
}

// added as ECP doesn't offer a Clone() function which is required for assignment
void ECPM::operator=(const ECPM& rhs)
{
	m_A = rhs.m_A;
	m_AThirds = rhs.m_AThirds;
	m_B = rhs.m_B;
	m_BInv = rhs.m_BInv;
	m_fieldPtr = rhs.m_fieldPtr->Clone();
	m_ComputeEngine.reset(new ECP(*rhs.m_ComputeEngine,rhs.m_ComputeEngine->GetField().IsMontgomeryRepresentation()));
}

// converts weierstrass points to montgomery points
// it can be checked at https://crypto.stackexchange.com/q/27842 and http://safecurves.cr.yp.to/equation.html
inline ECPM::Point ECPM::WeierstrassToMontgomery(const Point& In) const
{
	// (x,y) -> (Bx-A/3,By)
	ECPPoint Out;
	Out.identity = In.identity;
	Out.x = GetField().Subtract(m_fieldPtr->Multiply(m_B,In.x),m_AThirds);
	Out.y = GetField().Multiply(In.y,m_B);
	return Out;
}

// converts weierstrass points to montgomery points, the math *should* be right
inline ECPM::Point ECPM::MontgomeryToWeierstrass(const Point& In) const
{
	// (x,y) -> ((x+A/3)/B,y/B)
	ECPPoint Out;
	Out.identity = In.identity;
	Out.x = GetField().Multiply(m_fieldPtr->Add(In.x,m_AThirds),m_BInv);
	Out.y = GetField().Multiply(In.y, m_BInv);
	return Out;
}

NAMESPACE_END

#endif
