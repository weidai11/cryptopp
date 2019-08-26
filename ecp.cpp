// ecp.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "ecp.h"
#include "asn.h"
#include "integer.h"
#include "nbtheory.h"
#include "modarith.h"
#include "filters.h"
#include "algebra.cpp"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::ECP;
using CryptoPP::Integer;
using CryptoPP::ModularArithmetic;

#if defined(HAVE_GCC_INIT_PRIORITY)
  #define INIT_ATTRIBUTE __attribute__ ((init_priority (CRYPTOPP_INIT_PRIORITY + 50)))
  const ECP::Point g_identity INIT_ATTRIBUTE = ECP::Point();
#elif defined(HAVE_MSC_INIT_PRIORITY)
  #pragma warning(disable: 4075)
  #pragma init_seg(".CRT$XCU")
  const ECP::Point g_identity;
  #pragma warning(default: 4075)
#elif defined(HAVE_XLC_INIT_PRIORITY)
  #pragma priority(290)
  const ECP::Point g_identity;
#endif

inline ECP::Point ToMontgomery(const ModularArithmetic &mr, const ECP::Point &P)
{
	return P.identity ? P : ECP::Point(mr.ConvertIn(P.x), mr.ConvertIn(P.y));
}

inline ECP::Point FromMontgomery(const ModularArithmetic &mr, const ECP::Point &P)
{
	return P.identity ? P : ECP::Point(mr.ConvertOut(P.x), mr.ConvertOut(P.y));
}

inline Integer IdentityToInteger(bool val)
{
	return val ? Integer::One() : Integer::Zero();
}

struct ProjectivePoint
{
	ProjectivePoint() {}
	ProjectivePoint(const Integer &x, const Integer &y, const Integer &z)
		: x(x), y(y), z(z)	{}

	Integer x, y, z;
};

/// \brief Addition and Double functions
/// \sa <A HREF="https://eprint.iacr.org/2015/1060.pdf">Complete
///  addition formulas for prime order elliptic curves</A>
struct AdditionFunction
{
	explicit AdditionFunction(const ECP::Field& field,
		const ECP::FieldElement &a, const ECP::FieldElement &b, ECP::Point &r);

	// Double(P)
	ECP::Point operator()(const ECP::Point& P) const;
	// Add(P, Q)
	ECP::Point operator()(const ECP::Point& P, const ECP::Point& Q) const;

protected:
	/// \brief Parameters and representation for Addition
	/// \details Addition and Doubling will use different algorithms,
	///  depending on the <tt>A</tt> coefficient and the representation
	///  (Affine or Montgomery with precomputation).
	enum Alpha {
		/// \brief Coefficient A is 0
		A_0 = 1,
		/// \brief Coefficient A is -3
		A_3 = 2,
		/// \brief Coefficient A is arbitrary
		A_Star = 4,
		/// \brief Representation is Montgomery
		A_Montgomery = 8
	};

	const ECP::Field& field;
	const ECP::FieldElement &a, &b;
	ECP::Point &R;

	Alpha m_alpha;
};

#define X p.x
#define Y p.y
#define Z p.z

#define X1 p.x
#define Y1 p.y
#define Z1 p.z

#define X2 q.x
#define Y2 q.y
#define Z2 q.z

#define X3 r.x
#define Y3 r.y
#define Z3 r.z

AdditionFunction::AdditionFunction(const ECP::Field& field,
	const ECP::FieldElement &a, const ECP::FieldElement &b, ECP::Point &r)
	: field(field), a(a), b(b), R(r), m_alpha(static_cast<Alpha>(0))
{
	if (field.IsMontgomeryRepresentation())
	{
		m_alpha = A_Montgomery;
	}
	else
	{
		if (a == 0)
		{
			m_alpha = A_0;
		}
		else if (a == -3 || (a - field.GetModulus()) == -3)
		{
			m_alpha = A_3;
		}
		else
		{
			m_alpha = A_Star;
		}
	}
}

ECP::Point AdditionFunction::operator()(const ECP::Point& P) const
{
	if (m_alpha == A_3)
	{
		// Gyrations attempt to maintain constant-timeness
		// We need either (P.x, P.y, 1) or (0, 1, 0).
		const Integer x = P.x * IdentityToInteger(!P.identity);
		const Integer y = P.y * IdentityToInteger(!P.identity) + 1 * IdentityToInteger(P.identity);
		const Integer z = 1 * IdentityToInteger(!P.identity);

		ProjectivePoint p(x, y, z), r;

		ECP::FieldElement t0 = field.Square(X);
		ECP::FieldElement t1 = field.Square(Y);
		ECP::FieldElement t2 = field.Square(Z);
		ECP::FieldElement t3 = field.Multiply(X, Y);
		t3 = field.Add(t3, t3);
		Z3 = field.Multiply(X, Z);
		Z3 = field.Add(Z3, Z3);
		Y3 = field.Multiply(b, t2);
		Y3 = field.Subtract(Y3, Z3);
		X3 = field.Add(Y3, Y3);
		Y3 = field.Add(X3, Y3);
		X3 = field.Subtract(t1, Y3);
		Y3 = field.Add(t1, Y3);
		Y3 = field.Multiply(X3, Y3);
		X3 = field.Multiply(X3, t3);
		t3 = field.Add(t2, t2);
		t2 = field.Add(t2, t3);
		Z3 = field.Multiply(b, Z3);
		Z3 = field.Subtract(Z3, t2);
		Z3 = field.Subtract(Z3, t0);
		t3 = field.Add(Z3, Z3);
		Z3 = field.Add(Z3, t3);
		t3 = field.Add(t0, t0);
		t0 = field.Add(t3, t0);
		t0 = field.Subtract(t0, t2);
		t0 = field.Multiply(t0, Z3);
		Y3 = field.Add(Y3, t0);
		t0 = field.Multiply(Y, Z);
		t0 = field.Add(t0, t0);
		Z3 = field.Multiply(t0, Z3);
		X3 = field.Subtract(X3, Z3);
		Z3 = field.Multiply(t0, t1);
		Z3 = field.Add(Z3, Z3);
		Z3 = field.Add(Z3, Z3);

		const ECP::FieldElement inv = field.MultiplicativeInverse(Z3.IsZero() ? Integer::One() : Z3);
		X3 = field.Multiply(X3, inv); Y3 = field.Multiply(Y3, inv);

		// More gyrations
		R.x = X3*Z3.NotZero();
		R.y = Y3*Z3.NotZero();
		R.identity = Z3.IsZero();

		return R;
	}
	else if (m_alpha == A_0)
	{
		// Gyrations attempt to maintain constant-timeness
		// We need either (P.x, P.y, 1) or (0, 1, 0).
		const Integer x = P.x * IdentityToInteger(!P.identity);
		const Integer y = P.y * IdentityToInteger(!P.identity) + 1 * IdentityToInteger(P.identity);
		const Integer z = 1 * IdentityToInteger(!P.identity);

		ProjectivePoint p(x, y, z), r;
		const ECP::FieldElement b3 = field.Multiply(b, 3);

		ECP::FieldElement t0 = field.Square(Y);
		Z3 = field.Add(t0, t0);
		Z3 = field.Add(Z3, Z3);
		Z3 = field.Add(Z3, Z3);
		ECP::FieldElement t1 = field.Add(Y, Z);
		ECP::FieldElement t2 = field.Square(Z);
		t2 = field.Multiply(b3, t2);
		X3 = field.Multiply(t2, Z3);
		Y3 = field.Add(t0, t2);
		Z3 = field.Multiply(t1, Z3);
		t1 = field.Add(t2, t2);
		t2 = field.Add(t1, t2);
		t0 = field.Subtract(t0, t2);
		Y3 = field.Multiply(t0, Y3);
		Y3 = field.Add(X3, Y3);
		t1 = field.Multiply(X, Y);
		X3 = field.Multiply(t0, t1);
		X3 = field.Add(X3, X3);

		const ECP::FieldElement inv = field.MultiplicativeInverse(Z3.IsZero() ? Integer::One() : Z3);
		X3 = field.Multiply(X3, inv); Y3 = field.Multiply(Y3, inv);

		// More gyrations
		R.x = X3*Z3.NotZero();
		R.y = Y3*Z3.NotZero();
		R.identity = Z3.IsZero();

		return R;
	}
#if 0
	// Code path disabled at the moment due to https://github.com/weidai11/cryptopp/issues/878
	else if (m_alpha == A_Star)
	{
		// Gyrations attempt to maintain constant-timeness
		// We need either (P.x, P.y, 1) or (0, 1, 0).
		const Integer x = P.x * IdentityToInteger(!P.identity);
		const Integer y = P.y * IdentityToInteger(!P.identity) + 1 * IdentityToInteger(P.identity);
		const Integer z = 1 * IdentityToInteger(!P.identity);

		ProjectivePoint p(x, y, z), r;
		const ECP::FieldElement b3 = field.Multiply(b, 3);

		ECP::FieldElement t0 = field.Square(Y);
		Z3 = field.Add(t0, t0);
		Z3 = field.Add(Z3, Z3);
		Z3 = field.Add(Z3, Z3);
		ECP::FieldElement t1 = field.Add(Y, Z);
		ECP::FieldElement t2 = field.Square(Z);
		t2 = field.Multiply(b3, t2);
		X3 = field.Multiply(t2, Z3);
		Y3 = field.Add(t0, t2);
		Z3 = field.Multiply(t1, Z3);
		t1 = field.Add(t2, t2);
		t2 = field.Add(t1, t2);
		t0 = field.Subtract(t0, t2);
		Y3 = field.Multiply(t0, Y3);
		Y3 = field.Add(X3, Y3);
		t1 = field.Multiply(X, Y);
		X3 = field.Multiply(t0, t1);
		X3 = field.Add(X3, X3);

		const ECP::FieldElement inv = field.MultiplicativeInverse(Z3.IsZero() ? Integer::One() : Z3);
		X3 = field.Multiply(X3, inv); Y3 = field.Multiply(Y3, inv);

		// More gyrations
		R.x = X3*Z3.NotZero();
		R.y = Y3*Z3.NotZero();
		R.identity = Z3.IsZero();

		return R;
	}
#endif
	else  // A_Montgomery
	{
		// More gyrations
		bool identity = !!(P.identity + (P.y == field.Identity()));

		ECP::FieldElement t = field.Square(P.x);
		t = field.Add(field.Add(field.Double(t), t), a);
		t = field.Divide(t, field.Double(P.y));
		ECP::FieldElement x = field.Subtract(field.Subtract(field.Square(t), P.x), P.x);
		R.y = field.Subtract(field.Multiply(t, field.Subtract(P.x, x)), P.y);
		R.x.swap(x);

		// More gyrations
		R.x *= IdentityToInteger(!identity);
		R.y *= IdentityToInteger(!identity);
		R.identity = identity;

		return R;
	}
}

ECP::Point AdditionFunction::operator()(const ECP::Point& P, const ECP::Point& Q) const
{
	if (m_alpha == A_3)
	{
		// Gyrations attempt to maintain constant-timeness
		// We need either (P.x, P.y, 1) or (0, 1, 0).
		const Integer x1 = P.x * IdentityToInteger(!P.identity);
		const Integer y1 = P.y * IdentityToInteger(!P.identity) + 1 * IdentityToInteger(P.identity);
		const Integer z1 = 1 * IdentityToInteger(!P.identity);

		const Integer x2 = Q.x * IdentityToInteger(!Q.identity);
		const Integer y2 = Q.y * IdentityToInteger(!Q.identity) + 1 * IdentityToInteger(Q.identity);
		const Integer z2 = 1 * IdentityToInteger(!Q.identity);

		ProjectivePoint p(x1, y1, z1), q(x2, y2, z2), r;

		ECP::FieldElement t0 = field.Multiply(X1, X2);
		ECP::FieldElement t1 = field.Multiply(Y1, Y2);
		ECP::FieldElement t2 = field.Multiply(Z1, Z2);
		ECP::FieldElement t3 = field.Add(X1, Y1);
		ECP::FieldElement t4 = field.Add(X2, Y2);
		t3 = field.Multiply(t3, t4);
		t4 = field.Add(t0, t1);
		t3 = field.Subtract(t3, t4);
		t4 = field.Add(Y1, Z1);
		X3 = field.Add(Y2, Z2);
		t4 = field.Multiply(t4, X3);
		X3 = field.Add(t1, t2);
		t4 = field.Subtract(t4, X3);
		X3 = field.Add(X1, Z1);
		Y3 = field.Add(X2, Z2);
		X3 = field.Multiply(X3, Y3);
		Y3 = field.Add(t0, t2);
		Y3 = field.Subtract(X3, Y3);
		Z3 = field.Multiply(b, t2);
		X3 = field.Subtract(Y3, Z3);
		Z3 = field.Add(X3, X3);
		X3 = field.Add(X3, Z3);
		Z3 = field.Subtract(t1, X3);
		X3 = field.Add(t1, X3);
		Y3 = field.Multiply(b, Y3);
		t1 = field.Add(t2, t2);
		t2 = field.Add(t1, t2);
		Y3 = field.Subtract(Y3, t2);
		Y3 = field.Subtract(Y3, t0);
		t1 = field.Add(Y3, Y3);
		Y3 = field.Add(t1, Y3);
		t1 = field.Add(t0, t0);
		t0 = field.Add(t1, t0);
		t0 = field.Subtract(t0, t2);
		t1 = field.Multiply(t4, Y3);
		t2 = field.Multiply(t0, Y3);
		Y3 = field.Multiply(X3, Z3);
		Y3 = field.Add(Y3, t2);
		X3 = field.Multiply(t3, X3);
		X3 = field.Subtract(X3, t1);
		Z3 = field.Multiply(t4, Z3);
		t1 = field.Multiply(t3, t0);
		Z3 = field.Add(Z3, t1);

		const ECP::FieldElement inv = field.MultiplicativeInverse(Z3.IsZero() ? Integer::One() : Z3);
		X3 = field.Multiply(X3, inv); Y3 = field.Multiply(Y3, inv);

		// More gyrations
		R.x = X3*Z3.NotZero();
		R.y = Y3*Z3.NotZero();
		R.identity = Z3.IsZero();

		return R;
	}
	else if (m_alpha == A_0)
	{
		// Gyrations attempt to maintain constant-timeness
		// We need either (P.x, P.y, 1) or (0, 1, 0).
		const Integer x1 = P.x * IdentityToInteger(!P.identity);
		const Integer y1 = P.y * IdentityToInteger(!P.identity) + 1 * IdentityToInteger(P.identity);
		const Integer z1 = 1 * IdentityToInteger(!P.identity);

		const Integer x2 = Q.x * IdentityToInteger(!Q.identity);
		const Integer y2 = Q.y * IdentityToInteger(!Q.identity) + 1 * IdentityToInteger(Q.identity);
		const Integer z2 = 1 * IdentityToInteger(!Q.identity);

		ProjectivePoint p(x1, y1, z1), q(x2, y2, z2), r;
		const ECP::FieldElement b3 = field.Multiply(b, 3);

		ECP::FieldElement t0 = field.Square(Y);
		Z3 = field.Add(t0, t0);
		Z3 = field.Add(Z3, Z3);
		Z3 = field.Add(Z3, Z3);
		ECP::FieldElement t1 = field.Add(Y, Z);
		ECP::FieldElement t2 = field.Square(Z);
		t2 = field.Multiply(b3, t2);
		X3 = field.Multiply(t2, Z3);
		Y3 = field.Add(t0, t2);
		Z3 = field.Multiply(t1, Z3);
		t1 = field.Add(t2, t2);
		t2 = field.Add(t1, t2);
		t0 = field.Subtract(t0, t2);
		Y3 = field.Multiply(t0, Y3);
		Y3 = field.Add(X3, Y3);
		t1 = field.Multiply(X, Y);
		X3 = field.Multiply(t0, t1);
		X3 = field.Add(X3, X3);

		const ECP::FieldElement inv = field.MultiplicativeInverse(Z3.IsZero() ? Integer::One() : Z3);
		X3 = field.Multiply(X3, inv); Y3 = field.Multiply(Y3, inv);

		// More gyrations
		R.x = X3*Z3.NotZero();
		R.y = Y3*Z3.NotZero();
		R.identity = Z3.IsZero();

		return R;
	}
#if 0
	// Code path disabled at the moment due to https://github.com/weidai11/cryptopp/issues/878
	else if (m_alpha == A_Star)
	{
		// Gyrations attempt to maintain constant-timeness
		// We need either (P.x, P.y, 1) or (0, 1, 0).
		const Integer x1 = P.x * IdentityToInteger(!P.identity);
		const Integer y1 = P.y * IdentityToInteger(!P.identity) + 1 * IdentityToInteger(P.identity);
		const Integer z1 = 1 * IdentityToInteger(!P.identity);

		const Integer x2 = Q.x * IdentityToInteger(!Q.identity);
		const Integer y2 = Q.y * IdentityToInteger(!Q.identity) + 1 * IdentityToInteger(Q.identity);
		const Integer z2 = 1 * IdentityToInteger(!Q.identity);

		ProjectivePoint p(x1, y1, z1), q(x2, y2, z2), r;
		const ECP::FieldElement b3 = field.Multiply(b, 3);

		ECP::FieldElement t0 = field.Multiply(X1, X2);
		ECP::FieldElement t1 = field.Multiply(Y1, Y2);
		ECP::FieldElement t2 = field.Multiply(Z1, Z2);
		ECP::FieldElement t3 = field.Add(X1, Y1);
		ECP::FieldElement t4 = field.Add(X2, Y2);
		t3 = field.Multiply(t3, t4);
		t4 = field.Add(t0, t1);
		t3 = field.Subtract(t3, t4);
		t4 = field.Add(X1, Z1);
		ECP::FieldElement t5 = field.Add(X2, Z2);
		t4 = field.Multiply(t4, t5);
		t5 = field.Add(t0, t2);
		t4 = field.Subtract(t4, t5);
		t5 = field.Add(Y1, Z1);
		X3 = field.Add(Y2, Z2);
		t5 = field.Multiply(t5, X3);
		X3 = field.Add(t1, t2);
		t5 = field.Subtract(t5, X3);
		Z3 = field.Multiply(a, t4);
		X3 = field.Multiply(b3, t2);
		Z3 = field.Add(X3, Z3);
		X3 = field.Subtract(t1, Z3);
		Z3 = field.Add(t1, Z3);
		Y3 = field.Multiply(X3, Z3);
		t1 = field.Add(t0, t0);
		t1 = field.Add(t1, t0);
		t2 = field.Multiply(a, t2);
		t4 = field.Multiply(b3, t4);
		t1 = field.Add(t1, t2);
		t2 = field.Subtract(t0, t2);
		t2 = field.Multiply(a, t2);
		t4 = field.Add(t4, t2);
		t0 = field.Multiply(t1, t4);
		Y3 = field.Add(Y3, t0);
		t0 = field.Multiply(t5, t4);
		X3 = field.Multiply(t3, X3);
		X3 = field.Subtract(X3, t0);
		t0 = field.Multiply(t3, t1);
		Z3 = field.Multiply(t5, Z3);
		Z3 = field.Add(Z3, t0);

		const ECP::FieldElement inv = field.MultiplicativeInverse(Z3.IsZero() ? Integer::One() : Z3);
		X3 = field.Multiply(X3, inv); Y3 = field.Multiply(Y3, inv);

		// More gyrations
		R.x = X3*Z3.NotZero();
		R.y = Y3*Z3.NotZero();
		R.identity = Z3.IsZero();

		return R;
	}
#endif
	else  // A_Montgomery
	{
		// More gyrations
		bool return_Q = P.identity;
		bool return_P = Q.identity;
		bool double_P = field.Equal(P.x, Q.x) && field.Equal(P.y, Q.y);
		bool identity = field.Equal(P.x, Q.x) && !field.Equal(P.y, Q.y);

		// This code taken from Double(P) for below
		identity = !!((double_P * (P.identity + (P.y == field.Identity()))) + identity);

		ECP::Point S = R;
		if (double_P)
		{
			// This code taken from Double(P)
			ECP::FieldElement t = field.Square(P.x);
			t = field.Add(field.Add(field.Double(t), t), a);
			t = field.Divide(t, field.Double(P.y));
			ECP::FieldElement x = field.Subtract(field.Subtract(field.Square(t), P.x), P.x);
			R.y = field.Subtract(field.Multiply(t, field.Subtract(P.x, x)), P.y);
			R.x.swap(x);
		}
		else
		{
			// Original Add(P,Q) code
			ECP::FieldElement t = field.Subtract(Q.y, P.y);
			t = field.Divide(t, field.Subtract(Q.x, P.x));
			ECP::FieldElement x = field.Subtract(field.Subtract(field.Square(t), P.x), Q.x);
			R.y = field.Subtract(field.Multiply(t, field.Subtract(P.x, x)), P.y);
			R.x.swap(x);
		}

		// More gyrations
		R.x = R.x * IdentityToInteger(!identity);
		R.y = R.y * IdentityToInteger(!identity);
		R.identity = identity;

		if (return_Q)
			return (R = S), Q;
		else if (return_P)
			return (R = S), P;
		else
			return (S = R), R;
	}
}

#undef X
#undef Y
#undef Z

#undef X1
#undef Y1
#undef Z1

#undef X2
#undef Y2
#undef Z2

#undef X3
#undef Y3
#undef Z3

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

ECP::ECP(const ECP &ecp, bool convertToMontgomeryRepresentation)
{
	if (convertToMontgomeryRepresentation && !ecp.GetField().IsMontgomeryRepresentation())
	{
		m_fieldPtr.reset(new MontgomeryRepresentation(ecp.GetField().GetModulus()));
		m_a = GetField().ConvertIn(ecp.m_a);
		m_b = GetField().ConvertIn(ecp.m_b);
	}
	else
		operator=(ecp);
}

ECP::ECP(BufferedTransformation &bt)
	: m_fieldPtr(new Field(bt))
{
	BERSequenceDecoder seq(bt);
	GetField().BERDecodeElement(seq, m_a);
	GetField().BERDecodeElement(seq, m_b);
	// skip optional seed
	if (!seq.EndReached())
	{
		SecByteBlock seed;
		unsigned int unused;
		BERDecodeBitString(seq, seed, unused);
	}
	seq.MessageEnd();
}

void ECP::DEREncode(BufferedTransformation &bt) const
{
	GetField().DEREncode(bt);
	DERSequenceEncoder seq(bt);
	GetField().DEREncodeElement(seq, m_a);
	GetField().DEREncodeElement(seq, m_b);
	seq.MessageEnd();
}

bool ECP::DecodePoint(ECP::Point &P, const byte *encodedPoint, size_t encodedPointLen) const
{
	StringStore store(encodedPoint, encodedPointLen);
	return DecodePoint(P, store, encodedPointLen);
}

bool ECP::DecodePoint(ECP::Point &P, BufferedTransformation &bt, size_t encodedPointLen) const
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
		P.y = ((P.x*P.x+m_a)*P.x+m_b) % p;

		if (Jacobi(P.y, p) !=1)
			return false;

		P.y = ModularSquareRoot(P.y, p);

		if ((type & 1) != P.y.GetBit(0))
			P.y = p-P.y;

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

void ECP::EncodePoint(BufferedTransformation &bt, const Point &P, bool compressed) const
{
	if (P.identity)
		NullStore().TransferTo(bt, EncodedPointSize(compressed));
	else if (compressed)
	{
		bt.Put((byte)(2U + P.y.GetBit(0)));
		P.x.Encode(bt, GetField().MaxElementByteLength());
	}
	else
	{
		unsigned int len = GetField().MaxElementByteLength();
		bt.Put(4U);	// uncompressed
		P.x.Encode(bt, len);
		P.y.Encode(bt, len);
	}
}

void ECP::EncodePoint(byte *encodedPoint, const Point &P, bool compressed) const
{
	ArraySink sink(encodedPoint, EncodedPointSize(compressed));
	EncodePoint(sink, P, compressed);
	CRYPTOPP_ASSERT(sink.TotalPutLength() == EncodedPointSize(compressed));
}

ECP::Point ECP::BERDecodePoint(BufferedTransformation &bt) const
{
	SecByteBlock str;
	BERDecodeOctetString(bt, str);
	Point P;
	if (!DecodePoint(P, str, str.size()))
		BERDecodeError();
	return P;
}

void ECP::DEREncodePoint(BufferedTransformation &bt, const Point &P, bool compressed) const
{
	SecByteBlock str(EncodedPointSize(compressed));
	EncodePoint(str, P, compressed);
	DEREncodeOctetString(bt, str);
}

bool ECP::ValidateParameters(RandomNumberGenerator &rng, unsigned int level) const
{
	Integer p = FieldSize();

	bool pass = p.IsOdd();
	pass = pass && !m_a.IsNegative() && m_a<p && !m_b.IsNegative() && m_b<p;

	if (level >= 1)
		pass = pass && ((4*m_a*m_a*m_a+27*m_b*m_b)%p).IsPositive();

	if (level >= 2)
		pass = pass && VerifyPrime(rng, p);

	return pass;
}

bool ECP::VerifyPoint(const Point &P) const
{
	const FieldElement &x = P.x, &y = P.y;
	Integer p = FieldSize();
	return P.identity ||
		(!x.IsNegative() && x<p && !y.IsNegative() && y<p
		&& !(((x*x+m_a)*x+m_b-y*y)%p));
}

bool ECP::Equal(const Point &P, const Point &Q) const
{
	if (P.identity && Q.identity)
		return true;

	if (P.identity && !Q.identity)
		return false;

	if (!P.identity && Q.identity)
		return false;

	return (GetField().Equal(P.x,Q.x) && GetField().Equal(P.y,Q.y));
}

const ECP::Point& ECP::Identity() const
{
#if defined(HAVE_GCC_INIT_PRIORITY) || defined(HAVE_MSC_INIT_PRIORITY) || defined(HAVE_XLC_INIT_PRIORITY)
	return g_identity;
#elif defined(CRYPTOPP_CXX11_DYNAMIC_INIT)
	static const ECP::Point g_identity;
	return g_identity;
#else
	return Singleton<Point>().Ref();
#endif
}

const ECP::Point& ECP::Inverse(const Point &P) const
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

const ECP::Point& ECP::Add(const Point &P, const Point &Q) const
{
	AdditionFunction add(GetField(), m_a, m_b, m_R);
	return (m_R = add(P, Q));
}

const ECP::Point& ECP::Double(const Point &P) const
{
	AdditionFunction add(GetField(), m_a, m_b, m_R);
	return (m_R = add(P));
}

template <class T, class Iterator> void ParallelInvert(const AbstractRing<T> &ring, Iterator begin, Iterator end)
{
	size_t n = end-begin;
	if (n == 1)
		*begin = ring.MultiplicativeInverse(*begin);
	else if (n > 1)
	{
		std::vector<T> vec((n+1)/2);
		unsigned int i;
		Iterator it;

		for (i=0, it=begin; i<n/2; i++, it+=2)
			vec[i] = ring.Multiply(*it, *(it+1));
		if (n%2 == 1)
			vec[n/2] = *it;

		ParallelInvert(ring, vec.begin(), vec.end());

		for (i=0, it=begin; i<n/2; i++, it+=2)
		{
			if (!vec[i])
			{
				*it = ring.MultiplicativeInverse(*it);
				*(it+1) = ring.MultiplicativeInverse(*(it+1));
			}
			else
			{
				std::swap(*it, *(it+1));
				*it = ring.Multiply(*it, vec[i]);
				*(it+1) = ring.Multiply(*(it+1), vec[i]);
			}
		}
		if (n%2 == 1)
			*it = vec[n/2];
	}
}

class ProjectiveDoubling
{
public:
	ProjectiveDoubling(const ModularArithmetic &m_mr, const Integer &m_a, const Integer &m_b, const ECPPoint &Q)
		: mr(m_mr)
	{
		CRYPTOPP_UNUSED(m_b);
		if (Q.identity)
		{
			sixteenY4 = P.x = P.y = mr.MultiplicativeIdentity();
			aZ4 = P.z = mr.Identity();
		}
		else
		{
			P.x = Q.x;
			P.y = Q.y;
			sixteenY4 = P.z = mr.MultiplicativeIdentity();
			aZ4 = m_a;
		}
	}

	void Double()
	{
		twoY = mr.Double(P.y);
		P.z = mr.Multiply(P.z, twoY);
		fourY2 = mr.Square(twoY);
		S = mr.Multiply(fourY2, P.x);
		aZ4 = mr.Multiply(aZ4, sixteenY4);
		M = mr.Square(P.x);
		M = mr.Add(mr.Add(mr.Double(M), M), aZ4);
		P.x = mr.Square(M);
		mr.Reduce(P.x, S);
		mr.Reduce(P.x, S);
		mr.Reduce(S, P.x);
		P.y = mr.Multiply(M, S);
		sixteenY4 = mr.Square(fourY2);
		mr.Reduce(P.y, mr.Half(sixteenY4));
	}

	const ModularArithmetic &mr;
	ProjectivePoint P;
	Integer sixteenY4, aZ4, twoY, fourY2, S, M;
};

struct ZIterator
{
	ZIterator() {}
	ZIterator(std::vector<ProjectivePoint>::iterator it) : it(it) {}
	Integer& operator*() {return it->z;}
	int operator-(ZIterator it2) {return int(it-it2.it);}
	ZIterator operator+(int i) {return ZIterator(it+i);}
	ZIterator& operator+=(int i) {it+=i; return *this;}
	std::vector<ProjectivePoint>::iterator it;
};

ECP::Point ECP::ScalarMultiply(const Point &P, const Integer &k) const
{
	Element result;
	if (k.BitCount() <= 5)
		AbstractGroup<ECPPoint>::SimultaneousMultiply(&result, P, &k, 1);
	else
		ECP::SimultaneousMultiply(&result, P, &k, 1);
	return result;
}

void ECP::SimultaneousMultiply(ECP::Point *results, const ECP::Point &P, const Integer *expBegin, unsigned int expCount) const
{
	if (!GetField().IsMontgomeryRepresentation())
	{
		ECP ecpmr(*this, true);
		const ModularArithmetic &mr = ecpmr.GetField();
		ecpmr.SimultaneousMultiply(results, ToMontgomery(mr, P), expBegin, expCount);
		for (unsigned int i=0; i<expCount; i++)
			results[i] = FromMontgomery(mr, results[i]);
		return;
	}

	ProjectiveDoubling rd(GetField(), m_a, m_b, P);
	std::vector<ProjectivePoint> bases;
	std::vector<WindowSlider> exponents;
	exponents.reserve(expCount);
	std::vector<std::vector<word32> > baseIndices(expCount);
	std::vector<std::vector<bool> > negateBase(expCount);
	std::vector<std::vector<word32> > exponentWindows(expCount);
	unsigned int i;

	for (i=0; i<expCount; i++)
	{
		CRYPTOPP_ASSERT(expBegin->NotNegative());
		exponents.push_back(WindowSlider(*expBegin++, InversionIsFast(), 5));
		exponents[i].FindNextWindow();
	}

	unsigned int expBitPosition = 0;
	bool notDone = true;

	while (notDone)
	{
		notDone = false;
		bool baseAdded = false;
		for (i=0; i<expCount; i++)
		{
			if (!exponents[i].finished && expBitPosition == exponents[i].windowBegin)
			{
				if (!baseAdded)
				{
					bases.push_back(rd.P);
					baseAdded =true;
				}

				exponentWindows[i].push_back(exponents[i].expWindow);
				baseIndices[i].push_back((word32)bases.size()-1);
				negateBase[i].push_back(exponents[i].negateNext);

				exponents[i].FindNextWindow();
			}
			notDone = notDone || !exponents[i].finished;
		}

		if (notDone)
		{
			rd.Double();
			expBitPosition++;
		}
	}

	// convert from projective to affine coordinates
	ParallelInvert(GetField(), ZIterator(bases.begin()), ZIterator(bases.end()));
	for (i=0; i<bases.size(); i++)
	{
		if (bases[i].z.NotZero())
		{
			bases[i].y = GetField().Multiply(bases[i].y, bases[i].z);
			bases[i].z = GetField().Square(bases[i].z);
			bases[i].x = GetField().Multiply(bases[i].x, bases[i].z);
			bases[i].y = GetField().Multiply(bases[i].y, bases[i].z);
		}
	}

	std::vector<BaseAndExponent<Point, Integer> > finalCascade;
	for (i=0; i<expCount; i++)
	{
		finalCascade.resize(baseIndices[i].size());
		for (unsigned int j=0; j<baseIndices[i].size(); j++)
		{
			ProjectivePoint &base = bases[baseIndices[i][j]];
			if (base.z.IsZero())
				finalCascade[j].base.identity = true;
			else
			{
				finalCascade[j].base.identity = false;
				finalCascade[j].base.x = base.x;
				if (negateBase[i][j])
					finalCascade[j].base.y = GetField().Inverse(base.y);
				else
					finalCascade[j].base.y = base.y;
			}
			finalCascade[j].exponent = Integer(Integer::POSITIVE, 0, exponentWindows[i][j]);
		}
		results[i] = GeneralCascadeMultiplication(*this, finalCascade.begin(), finalCascade.end());
	}
}

ECP::Point ECP::CascadeScalarMultiply(const Point &P, const Integer &k1, const Point &Q, const Integer &k2) const
{
	if (!GetField().IsMontgomeryRepresentation())
	{
		ECP ecpmr(*this, true);
		const ModularArithmetic &mr = ecpmr.GetField();
		return FromMontgomery(mr, ecpmr.CascadeScalarMultiply(ToMontgomery(mr, P), k1, ToMontgomery(mr, Q), k2));
	}
	else
		return AbstractGroup<Point>::CascadeScalarMultiply(P, k1, Q, k2);
}

NAMESPACE_END

#endif
