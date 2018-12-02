// polynomi.h - originally written and placed in the public domain by Wei Dai

/// \file polynomi.h
/// \brief Classes for polynomial basis and operations

#ifndef CRYPTOPP_POLYNOMI_H
#define CRYPTOPP_POLYNOMI_H

#include "cryptlib.h"
#include "secblock.h"
#include "algebra.h"
#include "modarith.h"
#include "misc.h"

#include <sstream>
#include <iostream>
#include <iosfwd>
#include <vector>

NAMESPACE_BEGIN(CryptoPP)

/// represents single-variable polynomials over arbitrary rings
/*!	\nosubgrouping */
template <class T> class PolynomialOver
{
public:
	/// \name ENUMS, EXCEPTIONS, and TYPEDEFS
	//@{
	typedef T Ring;
	typedef typename T::Element CoefficientType;

	/// division by zero exception
	class DivideByZero : public Exception
	{
	public:
		DivideByZero() : Exception(OTHER_ERROR, "PolynomialOver<T>: division by zero") {}
	};

	/// specify the distribution for randomization functions
	class RandomizationParameter
	{
	public:
		RandomizationParameter(unsigned int coefficientCount, const typename T::RandomizationParameter &coefficientParameter )
	: m_coefficientCount(coefficientCount), m_coefficientParameter(coefficientParameter) {}

	private:
		unsigned int m_coefficientCount;
		typename T::RandomizationParameter m_coefficientParameter;
		friend class PolynomialOver<T>;
	};

	class InterpolationFailed : public Exception
	{
	public:
		InterpolationFailed() : Exception(OTHER_ERROR, "PolynomialOver<T>: interpolation failed") {}
	};

	/// \brief Class to tie together values of x and P(x) to reduce potential
	/// of errors when interpolation arguments are prepared
	class XYPair
	{
	public:
		XYPair(const CoefficientType& x, const CoefficientType& y) : m_x_i(x), m_y_i(y) { }
		XYPair(const XYPair& xy) : m_x_i(xy.GetX()), m_y_i(xy.GetY()) { }

		const CoefficientType& GetX() const { return m_x_i; }
		const CoefficientType& GetY() const { return m_y_i; }

	private:
		const CoefficientType m_x_i;
		const CoefficientType m_y_i;
	};
	//@}

	/// \name CREATORS
	//@{
	/// creates the zero polynomial
	PolynomialOver() : m_coefficients((size_t)0), m_ringSet(false)
	{}

	///
	PolynomialOver(const Ring &ring, unsigned int count)
	: m_coefficients((size_t)count, ring.Identity()),
	  m_ring(ring), m_ringSet(true) {}

	/// copy constructor
	PolynomialOver(const PolynomialOver<Ring> &t)
	  : m_coefficients(t.m_coefficients.size()), m_ring(t.m_ring), m_ringSet(t.isRingSet())
	{
		//std::cout << "Polynomial<>: inside copy-constructor" << std::endl;
		//std::cout.flush();
		*this = t;
	}

	/// construct constant polynomial
	PolynomialOver(const CoefficientType &element)
	  : m_coefficients(1, element), m_ringSet(false) {}

	/// construct polynomial with specified coefficients, starting from coefficient of x^0
	template <typename Iterator> PolynomialOver(Iterator begin, Iterator end)
	  : m_coefficients(begin, end), m_ringSet(false) {}

	/// convert from string
	PolynomialOver(const char *str, const Ring &ring) : m_ring(ring), m_ringSet(true)
	{ FromStr(str, ring); }

	/// convert from big-endian byte array
	PolynomialOver(const byte *encodedPolynomialOver, unsigned int byteCount);

	/// convert from Basic Encoding Rules encoded byte array
	explicit PolynomialOver(const byte *BEREncodedPolynomialOver);

	/// convert from BER encoded byte array stored in a BufferedTransformation object
	explicit PolynomialOver(BufferedTransformation &bt);

	/// create a random PolynomialOver<T>
	PolynomialOver(RandomNumberGenerator &rng,
			const RandomizationParameter &parameter,
			const Ring &ring) : m_ring(ring), m_ringSet(true)
	{ Randomize(rng, parameter, ring); }


	virtual void ClearCoefficients() {
		this->m_coefficients.clear();
		this->m_coefficients.shrink_to_fit();
	}

	virtual ~PolynomialOver() {
		this->ClearCoefficients();
		this->m_ringSet = false;
	}

	void setRing(const Ring &ring) {
		this->m_ring = ring;
		this->m_ringSet = true;
	}
	//@}

	/// \name ACCESSORS
	//@{
	/// the zero polynomial will return a degree of -1
	int Degree(const Ring &ring) const {
		return int(CoefficientCount(ring))-1;
	}
	int Degree() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Degree(this->m_ring);
	}
	///
	unsigned int CoefficientCount() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->CoefficientCount(this->m_ring);
	}
	unsigned int CoefficientCount(const Ring &ring) const
	{
		unsigned count = m_coefficients.size();
		while (count && ring.Equal(m_coefficients[count-1], ring.Identity()))
			count--;
		const_cast<std::vector<CoefficientType> &>(m_coefficients).resize(count);
		return count;
	}
	/// return coefficient for x^i
	CoefficientType GetCoefficient(unsigned int i, const Ring &ring) const
	{
		return (i < m_coefficients.size()) ? m_coefficients[i] : ring.Identity();
	}
	CoefficientType GetCoefficient(unsigned int i) const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->GetCoefficient(i, this->m_ring);
	}

	/// \brief tells whether Ring was set, without throwing exception
	const bool isRingSet() const {
		return m_ringSet;
	}

	/// get ring this polynomial is over
	const Ring& GetRing() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->m_ring;
	}
	//@}

	/// \name MANIPULATORS
	//@{
	/// assignment operator
	PolynomialOver<Ring>&  operator=(const PolynomialOver<Ring>& t)
	{
		//std::cout << "Polynomial<>: inside operator=..." << std::endl;
		if (this == &t) return *this;

		m_coefficients.resize(t.m_coefficients.size());
		for (size_t i = 0; i < t.m_coefficients.size(); i++)
			m_coefficients[i] = t.m_coefficients[i];

		// And the ring, RandomizationParameter, and ringSet flag
		if (t.isRingSet())
			m_ring = t.GetRing();
		m_ringSet = t.isRingSet();

		//			std::cout << "Polynomial<> op=: "
		//					<< "size: " << m_coefficients.size()
		//					<< "   ring_set=" << m_ringSet << std::endl;
		//			std::cout.flush();

		return *this;
	}

	/// \brief assign random values to all the polynomial coefficients
	/// \param rng Random Number Generator
	/// \param parameter contains the number of coefficients that the randomized polynomial
	/// will have, and the value 0
	/// \param ring ring that this polynomial coefficients belong to
	void Randomize(RandomNumberGenerator &rng, const RandomizationParameter &parameter, const Ring &ring)
	{
		m_coefficients.resize(parameter.m_coefficientCount);
		for (unsigned int i=0; i<m_coefficients.size(); ++i)
			m_coefficients[i] = ring.RandomElement(rng, parameter.m_coefficientParameter);
	}
	/// \brief assign random values to all the polynomial coefficients
	/// \param rng Random Number Generator
	/// \param parameter contains the number of coefficients that the randomized polynomial
	/// will have, and the value 0
	void Randomize(RandomNumberGenerator &rng, const RandomizationParameter &parameter) {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Randomize(rng, parameter, this->m_ring);
	}

	/// set the coefficient for x^i to value
	void SetCoefficient(unsigned int i, const CoefficientType &value, const Ring &ring)
	{
		if (i >= m_coefficients.size())
			m_coefficients.resize(i+1, ring.Identity());
		m_coefficients[i] = value;
	}
	void SetCoefficient(unsigned int i, const CoefficientType &value) {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		this->SetCoefficient(i, value, this->m_ring);
	}
	///
	void Negate(const Ring &ring)
	{
		unsigned int count = CoefficientCount(ring);
		for (unsigned int i=0; i<count; i++)
			m_coefficients[i] = ring.Inverse(m_coefficients[i]);
	}
	void Negate() {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		this->Negate(this->m_ring);
	}

	///
	void swap(PolynomialOver<Ring> &t)
	{
		m_coefficients.swap(t.m_coefficients);
	}
	//@}


	/// \name BASIC ARITHMETIC ON POLYNOMIALS
	//@{
	bool Equals(const PolynomialOver<Ring> &t, const Ring &ring) const {
		unsigned int count = CoefficientCount(ring);

		if (count != t.CoefficientCount(ring))
			return false;

		for (unsigned int i=0; i<count; i++)
			if (!ring.Equal(m_coefficients[i], t.m_coefficients[i]))
				return false;

		return true;
	}
	bool Equals(const PolynomialOver<Ring> &t) const {
		if(!this->m_ringSet
				|| !(t.isRingSet())) // if no ring - no real polynomial
			throw InvalidArgument( "Ring was not set!" );
		// if rings over different moduli - different polynomials
		if (m_ring.GetModulus() != t.GetRing().GetModulus())
			return false;
		return this->Equals(t, this->m_ring);
	}
	bool operator==(const PolynomialOver<Ring> &t) const {
		return Equals(t);
	}
	bool operator!=(const PolynomialOver<Ring> &t) const {
		return !(Equals(t));
	}

	bool IsZero(const Ring &ring) const {
		return CoefficientCount(ring)==0;
	};
	bool IsZero() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->IsZero(this->m_ring);
	}

	PolynomialOver<Ring> Plus(const PolynomialOver<Ring>& t, const Ring &ring) const {
		unsigned int i;
		unsigned int count = CoefficientCount(ring);
		unsigned int tCount = t.CoefficientCount(ring);

		if (count > tCount)
		{
			PolynomialOver<T> result(ring, count);

			for (i=0; i<tCount; i++)
				result.m_coefficients[i] = ring.Add(m_coefficients[i], t.m_coefficients[i]);
			for (; i<count; i++)
				result.m_coefficients[i] = m_coefficients[i];

			return result;
		}
		else
		{
			PolynomialOver<T> result(ring, tCount);

			for (i=0; i<count; i++)
				result.m_coefficients[i] = ring.Add(m_coefficients[i], t.m_coefficients[i]);
			for (; i<tCount; i++)
				result.m_coefficients[i] = t.m_coefficients[i];

			return result;
		}
	}
	PolynomialOver<Ring> Plus(const PolynomialOver<Ring>& t) const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Plus(t, this->m_ring);
	}

	PolynomialOver<Ring> Minus(const PolynomialOver<Ring>& t, const Ring &ring) const {
		unsigned int i;
		unsigned int count = CoefficientCount(ring);
		unsigned int tCount = t.CoefficientCount(ring);

		if (count > tCount)
		{
			PolynomialOver<T> result(ring, count);
			for (i=0; i<tCount; i++)
				result.m_coefficients[i] = ring.Subtract(m_coefficients[i], t.m_coefficients[i]);
			for (; i<count; i++)
				result.m_coefficients[i] = m_coefficients[i];

			return result;
		}
		else
		{
			PolynomialOver<T> result(ring, tCount);

			for (i=0; i<count; i++)
				result.m_coefficients[i] = ring.Subtract(m_coefficients[i], t.m_coefficients[i]);
			for (; i<tCount; i++)
				result.m_coefficients[i] = ring.Inverse(t.m_coefficients[i]);

			return result;
		}
	}
	PolynomialOver<Ring> Minus(const PolynomialOver<Ring>& t) const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Minus(t, this->m_ring);
	}

	PolynomialOver<Ring> Inverse(const Ring &ring) const {
		unsigned int count = CoefficientCount(ring);
		PolynomialOver<T> result(ring, count);

		for (unsigned int i=0; i<count; i++)
			result.m_coefficients[i] = ring.Inverse(m_coefficients[i]);

		return result;
	}
	PolynomialOver<Ring> Inverse() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Inverse(this->m_ring);
	}

	PolynomialOver<Ring> Times(const PolynomialOver<Ring>& t, const Ring &ring) const {
		if (IsZero(ring) || t.IsZero(ring))
			return PolynomialOver<T>();

		unsigned int count1 = CoefficientCount(ring), count2 = t.CoefficientCount(ring);
		PolynomialOver<T> result(ring, count1 + count2 - 1);

		for (unsigned int i=0; i<count1; i++)
			for (unsigned int j=0; j<count2; j++)
				ring.Accumulate(result.m_coefficients[i+j], ring.Multiply(m_coefficients[i], t.m_coefficients[j]));

		return result;
	}
	PolynomialOver<Ring> Times(const PolynomialOver<Ring>& t) const {
		if(this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Times(t, this->m_ring);
	}

	PolynomialOver<Ring> DividedBy(const PolynomialOver<Ring>& t, const Ring &ring) const {
		PolynomialOver<T> remainder, quotient;
		Divide(remainder, quotient, *this, t, ring);
		return quotient;
	}
	PolynomialOver<Ring> DividedBy(const PolynomialOver<Ring>& t) const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->DivideBy(t, this->m_ring);
	}
	PolynomialOver<Ring> Modulo(const PolynomialOver<Ring>& t, const Ring &ring) const {
		PolynomialOver<T> remainder, quotient;
		Divide(remainder, quotient, *this, t, ring);
		return remainder;
	}
	PolynomialOver<Ring> Modulo(const PolynomialOver<Ring>& t) const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Modulo(t, this->m_ring);
	}
	PolynomialOver<Ring> MultiplicativeInverse(const Ring &ring) const  {
		return Degree(ring)==0 ? ring.MultiplicativeInverse(m_coefficients[0]) : ring.Identity();
	}
	PolynomialOver<Ring> MultiplicativeInverse() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->MultiplicativeInverse(this->m_ring);
	}
	bool IsUnit(const Ring &ring) const
	{
		return Degree(ring)==0 && ring.IsUnit(m_coefficients[0]);
	}
	bool IsUnit() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->IsUnit(this->m_ring);
	}

	PolynomialOver<Ring>& Accumulate(const PolynomialOver<Ring>& t, const Ring &ring) {
		unsigned int count = t.CoefficientCount(ring);

		if (count > CoefficientCount(ring))
			m_coefficients.resize(count, ring.Identity());

		for (unsigned int i=0; i<count; i++)
			ring.Accumulate(m_coefficients[i], t.GetCoefficient(i, ring));

		return *this;
	}
	PolynomialOver<Ring>& Accumulate(const PolynomialOver<Ring>& t) {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Accumulate(t, this->m_ring);
	}

	PolynomialOver<Ring>& Reduce(const PolynomialOver<Ring>& t, const Ring &ring) {
		unsigned int count = t.CoefficientCount(ring);

		if (count > CoefficientCount(ring))
			m_coefficients.resize(count, ring.Identity());

		for (unsigned int i=0; i<count; i++)
			ring.Reduce(m_coefficients[i], t.GetCoefficient(i, ring));

		return *this;
	}
	PolynomialOver<Ring>& Reduce(const PolynomialOver<Ring>& t) {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Reduce(t, this->m_ring);
	}
	///

	PolynomialOver<Ring> Doubled(const Ring &ring) const {return Plus(*this, ring);}
	PolynomialOver<Ring> Doubled() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return Plus(*this, this->m_ring);
	}
	///

	PolynomialOver<Ring> Squared(const Ring &ring) const {return Times(*this, ring);}
	PolynomialOver<Ring> Squared() const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return Times(*this, this->m_ring);
	}

	CoefficientType EvaluateAt(const CoefficientType &x, const Ring &ring) const
	{
		int degree = Degree(ring);
		if (degree < 0)
			return ring.Identity();

		CoefficientType x1 = ring.ConvertIn(x);
		CoefficientType result = m_coefficients[degree];
		for (int j=degree-1; j>=0; j--)
		{
			result = ring.Multiply(result, x1);
			ring.Accumulate(result, m_coefficients[j]);
		}
		return result;
	}
	CoefficientType EvaluateAt(const CoefficientType &x) const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->EvaluateAt(x, this->m_ring);
	}

	/// \brief Slower Lagrange Interpolation of polynomial of degree N based on N+1 values
	/// of this polynomial at N+1 points, i.e., i \in 0..N | y_i = P(x_i)
	/// \param x value of x that we want P(x) at
	/// \param x_i vector of known input data points (must have degree+1 of these)
	/// \param y_i vector of y_i = P(x_i), values of the polynomial at x_i
	/// \returns value of the polynomial at x
	CoefficientType LagrangeInterpolateAt(const CoefficientType &x, const std::vector<CoefficientType>& x_i, const std::vector<CoefficientType>& y_i) const
	{
		if (x_i.size() != m_coefficients.size() || y_i.size() != m_coefficients.size())
			throw InvalidArgument("size of x_i and y_i must be equal to degree+1");

		CoefficientType res = CoefficientType::Zero();
		for (int i = 0; i < x_i.size(); i++) {
			res = m_ring.Add(res, m_ring.Multiply(Lambda_i(i, x, x_i), y_i[i]));
		}
		return res;
	}

	CoefficientType Lambda_i(const int i, const CoefficientType& x, const std::vector<CoefficientType>& x_i) const
	{
		CoefficientType li = CoefficientType::One();
		for (int j = 0; j < x_i.size(); j++) {
			if (i != j) {
				CoefficientType num = m_ring.Subtract(x, x_i[j]);
				CoefficientType den = m_ring.Subtract(x_i[i], x_i[j]);
				li = m_ring.Multiply(li, m_ring.Divide(num, den));
			}
		}
		return li;
	}

	// a faster version of Interpolate(x, y, n).EvaluateAt(position)
	/// \brief Newton Interpolation of polynomial of degree N based on N+1 values
	/// of this polynomial at N+1 points, i.e., i \in 0..N | y_i = P(x_i)
	/// \param position value of x that we want P(x) at
	/// \param x vector of x_i - known input data points (must have degree+1 of these)
	/// \param y vector of y_i = P(x_i), values of the polynomial at x_i
	/// \returns value of the polynomial at x=position
	CoefficientType InterpolateAt(const CoefficientType &position, const std::vector<CoefficientType>& x, const std::vector<CoefficientType>& y) const
	{
		unsigned int n = x.size();
		CRYPTOPP_ASSERT(n > 0);

		if (n != m_coefficients.size() || y.size() != n)
			throw InvalidArgument("number of provided x[] and y[] must be equal to polynomial degree+1");

		std::vector<CoefficientType> alpha(n);
		CalculateAlpha(alpha, x, y, n);

		CoefficientType result = alpha[n-1];
		for (int j=n-2; j>=0; --j)
		{
			result = m_ring.Multiply(result, m_ring.Subtract(position, x[j]));
			m_ring.Accumulate(result, alpha[j]);
		}
		return result;
	}

	CoefficientType InterpolateAt(const CoefficientType& position, const std::vector<XYPair>& xy) const
	{
		unsigned int n = xy.size();
		CRYPTOPP_ASSERT(n > 0);

		if (n != m_coefficients.size())
			throw InvalidArgument("number of provided x-y pairs must be equal to polynomial degree + 1");

		std::vector<CoefficientType> alpha(n);
		CalculateAlpha(alpha, xy, n);

		CoefficientType result = alpha[n-1];
		for (int j=n-2; j>=0; --j)
		{
			result = m_ring.Multiply(result, m_ring.Subtract(position, xy[j].GetX()));
			m_ring.Accumulate(result, alpha[j]);
		}
		return result;
	}

	PolynomialOver<Ring>& ShiftLeft(unsigned int n, const Ring &ring) {
		unsigned int i = CoefficientCount(ring) + n;
		m_coefficients.resize(i, ring.Identity());
		while (i > n)
		{
			i--;
			m_coefficients[i] = m_coefficients[i-n];
		}
		while (i)
		{
			i--;
			m_coefficients[i] = ring.Identity();
		}
		return *this;
	}
	PolynomialOver<Ring>& ShiftLeft(unsigned int n) {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->ShiftLeft(n, this->m_ring);
	}

	PolynomialOver<Ring>& ShiftRight(unsigned int n, const Ring &ring) {
		unsigned int count = CoefficientCount(ring);
		if (count > n)
		{
			for (unsigned int i=0; i<count-n; i++)
				m_coefficients[i] = m_coefficients[i+n];
			m_coefficients.resize(count-n, ring.Identity());
		}
		else
			m_coefficients.resize(0, ring.Identity());
		return *this;
	}
	PolynomialOver<Ring>& ShiftRight(unsigned int n) {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->ShiftRight(n, this->m_ring);
	}

	/// calculate r and q such that (a == d*q + r) && (0 <= degree of r < degree of d)
	static void Divide(PolynomialOver<Ring> &r, PolynomialOver<Ring> &q, const PolynomialOver<Ring> &a, const PolynomialOver<Ring> &d, const Ring &ring)
	{
		unsigned int i = a.CoefficientCount(ring);
		const int dDegree = d.Degree(ring);

		if (dDegree < 0)
			throw DivideByZero();

		r = a;
		q.m_coefficients.resize(STDMAX(0, int(i - dDegree)));

		while (i > (unsigned int)dDegree)
		{
			--i;
			q.m_coefficients[i-dDegree] = ring.Divide(r.m_coefficients[i], d.m_coefficients[dDegree]);
			for (int j=0; j<=dDegree; j++)
				ring.Reduce(r.m_coefficients[i-dDegree+j], ring.Multiply(q.m_coefficients[i-dDegree], d.m_coefficients[j]));
		}

		r.CoefficientCount(ring);   // resize r.m_coefficients
	}
	void Divide(PolynomialOver<Ring> &r, PolynomialOver<Ring> &q, const PolynomialOver<Ring> &a, const PolynomialOver<Ring> &d)
	{
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return Divide(r, q, a, d, this->m_ring);
	}
	//@}

	/// \name INPUT/OUTPUT
	//@{
	std::istream& Input(std::istream &in, const Ring &ring)
	{
		char c;
		unsigned int length = 0;
		SecBlock<char> str(length + 16);
		bool paren = false;

		std::ws(in);

		if (in.peek() == '(')
				{
			paren = true;
			in.get();
				}

		do
		{
			in.read(&c, 1);
			str[length++] = c;
			if (length >= str.size())
				str.Grow(length + 16);
		}
		// if we started with a left paren, then read until we find a right paren,
		// otherwise read until the end of the line
		while (in && ((paren && c != ')') || (!paren && c != '\n')));

		str[length-1] = '\0';
		*this = PolynomialOver<T>(str, ring);

		return in;
	}
	std::istream& Input(std::istream &in) {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return Input(in, this->m_ring);
	}

	std::ostream& Output(std::ostream &out) const {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		return this->Output(out, m_ring);
	}
	std::ostream& Output(std::ostream &out, const Ring &ring) const
	{
		unsigned int i = CoefficientCount(ring);
		if (i)
		{
			bool firstTerm = true;

			while (i--)
			{
				if (m_coefficients[i] != ring.Identity())
				{
					if (firstTerm)
					{
						firstTerm = false;
						if (!i || !ring.Equal(m_coefficients[i], ring.MultiplicativeIdentity()))
							out << m_coefficients[i];
					}
					else
					{
						//		                    CoefficientType inverse = ring.Inverse(m_coefficients[i]);
						//		                    std::ostringstream pstr, nstr;
						//
						//		                    pstr << m_coefficients[i];
						//		                    nstr << inverse;

						out << " + ";
						if (!i || !ring.Equal(m_coefficients[i], ring.MultiplicativeIdentity()))
							out << m_coefficients[i];
						//		                    if (pstr.str().size() <= nstr.str().size())
						//		                    {
						//		                        out << " + ";
						//		                        if (!i || !ring.Equal(m_coefficients[i], ring.MultiplicativeIdentity()))
						//		                            out << m_coefficients[i];
						//		                    }
						//		                    else
						//		                    {
						//		                        out << " - ";
						//		                        if (!i || !ring.Equal(inverse, ring.MultiplicativeIdentity()))
						//		                            out << inverse;
						//		                    }
					}

					switch (i)
					{
					case 0:
						break;
					case 1:
						out << "x";
						break;
					default:
						out << "x^" << i;
					}
				}
			}
		}
		else
		{
			out << ring.Identity();
		}
		return out;
	}

	//		friend std::istream& operator>>(std::istream& in, ThisType &a)
	//		{
	//			CRYPTOPP_ASSERT(this->m_ringSet);
	//			return a.Input(in, this->m_ring);
	//		}
	//		///
	//		friend std::ostream& operator<<(std::ostream& out, const ThisType &a)
	//		{
	//			CRYPTOPP_ASSERT(this->m_ringSet);
	//			return a.Output(out, this->m_Ring);
	//		}
	//@}
	protected:
	void CalculateAlpha(std::vector<CoefficientType> &alpha, const std::vector<CoefficientType>& x, const std::vector<CoefficientType>& y, unsigned int n) const
	{
		for (unsigned int j=0; j<n; ++j)
			alpha[j] = y[j];

		for (unsigned int k=1; k<n; ++k)
		{
			for (unsigned int j=n-1; j>=k; --j)
			{
				m_ring.Reduce(alpha[j], alpha[j-1]);

				CoefficientType d = m_ring.Subtract(x[j], x[j-k]);
				if (!m_ring.IsUnit(d))
					throw InterpolationFailed();
				alpha[j] = m_ring.Divide(alpha[j], d);
			}
		}
	}

	void CalculateAlpha(std::vector<CoefficientType> &alpha, const std::vector<XYPair>& xy, unsigned int n) const
	{
		for (unsigned int j=0; j<n; ++j)
			alpha[j] = xy[j].GetY();

		for (unsigned int k=1; k<n; ++k)
		{
			for (unsigned int j=n-1; j>=k; --j)
			{
				m_ring.Reduce(alpha[j], alpha[j-1]);

				CoefficientType d = m_ring.Subtract(xy[j].GetX(), xy[j-k].GetX());
				if (!m_ring.IsUnit(d))
					throw InterpolationFailed();
				alpha[j] = m_ring.Divide(alpha[j], d);
			}
		}
	}
	private:
	void FromStr(const char *str, const Ring &ring)
	{
		std::istringstream in((char *)str);
		bool positive = true;
		CoefficientType coef;
		unsigned int power;

		while (in)
		{
			std::ws(in);
			if (in.peek() == 'x')
				coef = ring.MultiplicativeIdentity();
			else
				in >> coef;

			std::ws(in);
			if (in.peek() == 'x')
			{
				in.get();
				std::ws(in);
				if (in.peek() == '^')
				{
					in.get();
					in >> power;
				}
				else
					power = 1;
			}
			else
				power = 0;

			if (!positive)
				coef = ring.Inverse(coef);

			SetCoefficient(power, coef, ring);

			std::ws(in);
			switch (in.get())
			{
			case '+':
			positive = true;
			break;
			case '-':
				positive = false;
				break;
			default:
				return;     // something's wrong with the input string
			}
		}
	}
	void fromStr(const char *str) {
		if(!this->m_ringSet)
			throw InvalidArgument( "Ring was not set!" );
		this->fromStr(str, m_ring);
	}

	std::vector<CoefficientType> m_coefficients;
	Ring m_ring;
#if __cplusplus >= 201103L
	bool m_ringSet = false; // Depends on C++11 compiler support
#else
	bool m_ringSet; // Since C++11 feature may not work for earlier versions of C++ standard
        // in which case just leave it uninitialized and hope that the constructor will do the job.
#endif /* C++11 or higher */
};

/// Polynomials over a fixed ring
/*! Having a fixed ring allows overloaded operators */
template <class T, int instance> class PolynomialOverFixedRing : private PolynomialOver<T>
{
	typedef PolynomialOver<T> B;
	typedef PolynomialOverFixedRing<T, instance> ThisType;

public:
	typedef T Ring;
	typedef typename T::Element CoefficientType;
	typedef typename B::DivideByZero DivideByZero;
	typedef typename B::RandomizationParameter RandomizationParameter;

	/// \name CREATORS
	//@{
		/// creates the zero polynomial
		PolynomialOverFixedRing(unsigned int count = 0) : B(ms_fixedRing, count) {}

		/// copy constructor
		PolynomialOverFixedRing(const ThisType &t) : B(t) {}

		explicit PolynomialOverFixedRing(const B &t) : B(t) {}

		/// construct constant polynomial
		PolynomialOverFixedRing(const CoefficientType &element) : B(element) {}

		/// construct polynomial with specified coefficients, starting from coefficient of x^0
		template <typename Iterator> PolynomialOverFixedRing(Iterator first, Iterator last)
			: B(first, last) {}

		/// convert from string
		explicit PolynomialOverFixedRing(const char *str) : B(str, ms_fixedRing) {}

		/// convert from big-endian byte array
		PolynomialOverFixedRing(const byte *encodedPoly, unsigned int byteCount) : B(encodedPoly, byteCount) {}

		/// convert from Basic Encoding Rules encoded byte array
		explicit PolynomialOverFixedRing(const byte *BEREncodedPoly) : B(BEREncodedPoly) {}

		/// convert from BER encoded byte array stored in a BufferedTransformation object
		explicit PolynomialOverFixedRing(BufferedTransformation &bt) : B(bt) {}

		/// create a random PolynomialOverFixedRing
		PolynomialOverFixedRing(RandomNumberGenerator &rng, const RandomizationParameter &parameter) : B(rng, parameter, ms_fixedRing) {}

		static const ThisType &Zero()
		{
		    return Singleton<ThisType>().Ref();
		}
		static const ThisType &One()
		{
		    return Singleton<ThisType, NewOnePolynomial>().Ref();
		}
	//@}

	/// \name ACCESSORS
	//@{
		/// the zero polynomial will return a degree of -1
		int Degree() const {return B::Degree(ms_fixedRing);}
		/// degree + 1
		unsigned int CoefficientCount() const {return B::CoefficientCount(ms_fixedRing);}
		/// return coefficient for x^i
		CoefficientType GetCoefficient(unsigned int i) const {return B::GetCoefficient(i, ms_fixedRing);}
		/// return coefficient for x^i
		CoefficientType operator[](unsigned int i) const {return B::GetCoefficient(i, ms_fixedRing);}
	//@}

	/// \name MANIPULATORS
	//@{
		///
		ThisType&  operator=(const ThisType& t) {B::operator=(t); return *this;}
		///
		ThisType&  operator+=(const ThisType& t) {Accumulate(t, ms_fixedRing); return *this;}
		///
		ThisType&  operator-=(const ThisType& t) {Reduce(t, ms_fixedRing); return *this;}
		///
		ThisType&  operator*=(const ThisType& t) {return *this = *this*t;}
		///
		ThisType&  operator/=(const ThisType& t) {return *this = *this/t;}
		///
		ThisType&  operator%=(const ThisType& t) {return *this = *this%t;}

		///
		ThisType&  operator<<=(unsigned int n) {ShiftLeft(n, ms_fixedRing); return *this;}
		///
		ThisType&  operator>>=(unsigned int n) {ShiftRight(n, ms_fixedRing); return *this;}

		/// set the coefficient for x^i to value
		void SetCoefficient(unsigned int i, const CoefficientType &value) {B::SetCoefficient(i, value, ms_fixedRing);}

		///
		void Randomize(RandomNumberGenerator &rng, const RandomizationParameter &parameter) {B::Randomize(rng, parameter, ms_fixedRing);}

		///
		void Negate() {B::Negate(ms_fixedRing);}

		void swap(ThisType &t) {B::swap(t);}
	//@}

	/// \name UNARY OPERATORS
	//@{
		///
		bool operator!() const {return CoefficientCount()==0;}
		///
		ThisType operator+() const {return *this;}
		///
		ThisType operator-() const {return ThisType(Inverse(ms_fixedRing));}
	//@}

	/// \name BINARY OPERATORS
	//@{
		///
		friend ThisType operator>>(ThisType a, unsigned int n)	{return ThisType(a>>=n);}
		///
		friend ThisType operator<<(ThisType a, unsigned int n)	{return ThisType(a<<=n);}
	//@}

	/// \name OTHER ARITHMETIC FUNCTIONS
	//@{
		///
		ThisType MultiplicativeInverse() const {return ThisType(B::MultiplicativeInverse(ms_fixedRing));}
		///
		bool IsUnit() const {return B::IsUnit(ms_fixedRing);}

		///
		ThisType Doubled() const {return ThisType(B::Doubled(ms_fixedRing));}
		///
		ThisType Squared() const {return ThisType(B::Squared(ms_fixedRing));}

		CoefficientType EvaluateAt(const CoefficientType &x) const {return B::EvaluateAt(x, ms_fixedRing);}

		/// calculate r and q such that (a == d*q + r) && (0 <= r < abs(d))
		static void Divide(ThisType &r, ThisType &q, const ThisType &a, const ThisType &d)
			{B::Divide(r, q, a, d, ms_fixedRing);}
	//@}

	/// \name INPUT/OUTPUT
	//@{
		///
		friend std::istream& operator>>(std::istream& in, ThisType &a)
			{return a.Input(in, ms_fixedRing);}
		///
		friend std::ostream& operator<<(std::ostream& out, const ThisType &a)
			{return a.Output(out, ms_fixedRing);}
	//@}

private:
	struct NewOnePolynomial
	{
		ThisType * operator()() const
		{
			return new ThisType(ms_fixedRing.MultiplicativeIdentity());
		}
	};

protected:
	static const Ring ms_fixedRing;
};

/// Ring of polynomials over another ring
template <class T> class RingOfPolynomialsOver : public AbstractEuclideanDomain<PolynomialOver<T> >
{
public:
	typedef T CoefficientRing;
	typedef PolynomialOver<T> Element;
	typedef typename Element::CoefficientType CoefficientType;
	typedef typename Element::RandomizationParameter RandomizationParameter;

	RingOfPolynomialsOver(const CoefficientRing &ring) : m_ring(ring) {}

	Element RandomElement(RandomNumberGenerator &rng, const RandomizationParameter &parameter)
		{return Element(rng, parameter, m_ring);}

	bool Equal(const Element &a, const Element &b) const
		{return a.Equals(b, m_ring);}

	const Element& Identity() const
		{return this->result = m_ring.Identity();}

	const Element& Add(const Element &a, const Element &b) const
		{return this->result = a.Plus(b, m_ring);}

	Element& Accumulate(Element &a, const Element &b) const
		{a.Accumulate(b, m_ring); return a;}

	const Element& Inverse(const Element &a) const
		{return this->result = a.Inverse(m_ring);}

	const Element& Subtract(const Element &a, const Element &b) const
		{return this->result = a.Minus(b, m_ring);}

	Element& Reduce(Element &a, const Element &b) const
		{return a.Reduce(b, m_ring);}

	const Element& Double(const Element &a) const
		{return this->result = a.Doubled(m_ring);}

	const Element& MultiplicativeIdentity() const
		{return this->result = m_ring.MultiplicativeIdentity();}

	const Element& Multiply(const Element &a, const Element &b) const
		{return this->result = a.Times(b, m_ring);}

	const Element& Square(const Element &a) const
		{return this->result = a.Squared(m_ring);}

	bool IsUnit(const Element &a) const
		{return a.IsUnit(m_ring);}

	const Element& MultiplicativeInverse(const Element &a) const
		{return this->result = a.MultiplicativeInverse(m_ring);}

	const Element& Divide(const Element &a, const Element &b) const
		{return this->result = a.DividedBy(b, m_ring);}

	const Element& Mod(const Element &a, const Element &b) const
		{return this->result = a.Modulo(b, m_ring);}

	void DivisionAlgorithm(Element &r, Element &q, const Element &a, const Element &d) const
		{Element::Divide(r, q, a, d, m_ring);}

	class InterpolationFailed : public Exception
	{
	public:
		InterpolationFailed() : Exception(OTHER_ERROR, "RingOfPolynomialsOver<T>: interpolation failed") {}
	};

	Element Interpolate(const CoefficientType x[], const CoefficientType y[], unsigned int n) const
	{
	    CRYPTOPP_ASSERT(n > 0);

	    std::vector<CoefficientType> alpha(n);
	    CalculateAlpha(alpha, x, y, n);

	    std::vector<CoefficientType> coefficients((size_t)n, m_ring.Identity());
	    coefficients[0] = alpha[n-1];

	    for (int j=n-2; j>=0; --j)
	    {
	        for (unsigned int i=n-j-1; i>0; i--)
	            coefficients[i] = m_ring.Subtract(coefficients[i-1], m_ring.Multiply(coefficients[i], x[j]));

	        coefficients[0] = m_ring.Subtract(alpha[j], m_ring.Multiply(coefficients[0], x[j]));
	    }

	    return PolynomialOver<T>(coefficients.begin(), coefficients.end());
	}

	// a faster version of Interpolate(x, y, n).EvaluateAt(position)
	CoefficientType InterpolateAt(const CoefficientType &position, const CoefficientType x[], const CoefficientType y[], unsigned int n) const
	{
	    CRYPTOPP_ASSERT(n > 0);

	    std::vector<CoefficientType> alpha(n);
	    CalculateAlpha(alpha, x, y, n);

	    CoefficientType result = alpha[n-1];
	    for (int j=n-2; j>=0; --j)
	    {
	        result = m_ring.Multiply(result, m_ring.Subtract(position, x[j]));
	        m_ring.Accumulate(result, alpha[j]);
	    }
	    return result;
	}
/*
	void PrepareBulkInterpolation(CoefficientType *w, const CoefficientType x[], unsigned int n) const;
	void PrepareBulkInterpolationAt(CoefficientType *v, const CoefficientType &position, const CoefficientType x[], const CoefficientType w[], unsigned int n) const;
	CoefficientType BulkInterpolateAt(const CoefficientType y[], const CoefficientType v[], unsigned int n) const;
*/
protected:
	void CalculateAlpha(std::vector<CoefficientType> &alpha, const CoefficientType x[], const CoefficientType y[], unsigned int n) const
	{
	    for (unsigned int j=0; j<n; ++j)
	        alpha[j] = y[j];

	    for (unsigned int k=1; k<n; ++k)
	    {
	        for (unsigned int j=n-1; j>=k; --j)
	        {
	            m_ring.Reduce(alpha[j], alpha[j-1]);

	            CoefficientType d = m_ring.Subtract(x[j], x[j-k]);
	            if (!m_ring.IsUnit(d))
	                throw InterpolationFailed();
	            alpha[j] = m_ring.Divide(alpha[j], d);
	        }
	    }
	}

	CoefficientRing m_ring;
};

template <class Ring, class Element>
void PrepareBulkPolynomialInterpolation(const Ring &ring, Element *w, const Element x[], unsigned int n);
template <class Ring, class Element>
void PrepareBulkPolynomialInterpolationAt(const Ring &ring, Element *v, const Element &position, const Element x[], const Element w[], unsigned int n);
template <class Ring, class Element>
Element BulkPolynomialInterpolateAt(const Ring &ring, const Element y[], const Element v[], unsigned int n);

///
template <class T, int instance>
inline bool operator==(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return a.Equals(b, a.ms_fixedRing);}
///
template <class T, int instance>
inline bool operator!=(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return !(a==b);}

///
template <class T, int instance>
inline bool operator> (const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return a.Degree() > b.Degree();}
///
template <class T, int instance>
inline bool operator>=(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return a.Degree() >= b.Degree();}
///
template <class T, int instance>
inline bool operator< (const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return a.Degree() < b.Degree();}
///
template <class T, int instance>
inline bool operator<=(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return a.Degree() <= b.Degree();}

///
template <class T, int instance>
inline CryptoPP::PolynomialOverFixedRing<T, instance> operator+(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return CryptoPP::PolynomialOverFixedRing<T, instance>(a.Plus(b, a.ms_fixedRing));}
///
template <class T, int instance>
inline CryptoPP::PolynomialOverFixedRing<T, instance> operator-(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return CryptoPP::PolynomialOverFixedRing<T, instance>(a.Minus(b, a.ms_fixedRing));}
///
template <class T, int instance>
inline CryptoPP::PolynomialOverFixedRing<T, instance> operator*(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return CryptoPP::PolynomialOverFixedRing<T, instance>(a.Times(b, a.ms_fixedRing));}
///
template <class T, int instance>
inline CryptoPP::PolynomialOverFixedRing<T, instance> operator/(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return CryptoPP::PolynomialOverFixedRing<T, instance>(a.DividedBy(b, a.ms_fixedRing));}
///
template <class T, int instance>
inline CryptoPP::PolynomialOverFixedRing<T, instance> operator%(const CryptoPP::PolynomialOverFixedRing<T, instance> &a, const CryptoPP::PolynomialOverFixedRing<T, instance> &b)
	{return CryptoPP::PolynomialOverFixedRing<T, instance>(a.Modulo(b, a.ms_fixedRing));}

NAMESPACE_END

NAMESPACE_BEGIN(std)
template<class T> inline void swap(CryptoPP::PolynomialOver<T> &a, CryptoPP::PolynomialOver<T> &b)
{
	a.swap(b);
}
template<class T, int i> inline void swap(CryptoPP::PolynomialOverFixedRing<T,i> &a, CryptoPP::PolynomialOverFixedRing<T,i> &b)
{
	a.swap(b);
}
NAMESPACE_END

#endif
