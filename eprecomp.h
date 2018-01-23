// eprecomp.h - originally written and placed in the public domain by Wei Dai

/// \file eprecomp.h
/// \brief Classes for precomputation in a group

#ifndef CRYPTOPP_EPRECOMP_H
#define CRYPTOPP_EPRECOMP_H

#include "cryptlib.h"
#include "integer.h"
#include "algebra.h"
#include "stdcpp.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief DL_GroupPrecomputation interface
/// \tparam T Field element
template <class T>
class DL_GroupPrecomputation
{
public:
	typedef T Element;

	virtual ~DL_GroupPrecomputation() {}

	/// \brief Determines if elements needs conversion
	/// \returns true if the element needs conversion, false otherwise
	/// \details NeedConversions determines if an element must convert between representations.
	virtual bool NeedConversions() const {return false;}

	/// \brief Converts an element between representations
	/// \param v element to convert
	/// \returns an element converted to an alternate representation for internal use
	/// \details ConvertIn is used when an element must convert between representations.
	virtual Element ConvertIn(const Element &v) const {return v;}

	/// \brief Converts an element between representations
	/// \param v element to convert
	/// \returns an element converted from an alternate representation
	virtual Element ConvertOut(const Element &v) const {return v;}

	/// \brief Retrieves AbstractGroup interface
	/// \returns GetGroup() returns the AbstractGroup interface
	virtual const AbstractGroup<Element> & GetGroup() const =0;

	/// \brief Decodes element in DER format
	/// \param bt BufferedTransformation object
	/// \param P Element to decode
	virtual Element BERDecodeElement(BufferedTransformation &bt) const =0;

	/// \brief Encodes element in DER format
	/// \param bt BufferedTransformation object
	/// \param P Element to encode
	virtual void DEREncodeElement(BufferedTransformation &bt, const Element &P) const =0;
};

/// \brief DL_FixedBasePrecomputation interface
/// \tparam T Field element
template <class T>
class DL_FixedBasePrecomputation
{
public:
	typedef T Element;

	virtual ~DL_FixedBasePrecomputation() {}

	virtual bool IsInitialized() const =0;
	virtual void SetBase(const DL_GroupPrecomputation<Element> &group, const Element &base) =0;
	virtual const Element & GetBase(const DL_GroupPrecomputation<Element> &group) const =0;
	virtual void Precompute(const DL_GroupPrecomputation<Element> &group, unsigned int maxExpBits, unsigned int storage) =0;
	virtual void Load(const DL_GroupPrecomputation<Element> &group, BufferedTransformation &storedPrecomputation) =0;
	virtual void Save(const DL_GroupPrecomputation<Element> &group, BufferedTransformation &storedPrecomputation) const =0;
	virtual Element Exponentiate(const DL_GroupPrecomputation<Element> &group, const Integer &exponent) const =0;
	virtual Element CascadeExponentiate(const DL_GroupPrecomputation<Element> &group, const Integer &exponent, const DL_FixedBasePrecomputation<Element> &pc2, const Integer &exponent2) const =0;
};

/// \brief DL_FixedBasePrecomputation adapter class
/// \tparam T Field element
template <class T>
class DL_FixedBasePrecomputationImpl : public DL_FixedBasePrecomputation<T>
{
public:
	typedef T Element;

	virtual ~DL_FixedBasePrecomputationImpl() {}

	DL_FixedBasePrecomputationImpl() : m_windowSize(0) {}

	// DL_FixedBasePrecomputation
	bool IsInitialized() const
		{return !m_bases.empty();}
	void SetBase(const DL_GroupPrecomputation<Element> &group, const Element &base);
	const Element & GetBase(const DL_GroupPrecomputation<Element> &group) const
		{return group.NeedConversions() ? m_base : m_bases[0];}
	void Precompute(const DL_GroupPrecomputation<Element> &group, unsigned int maxExpBits, unsigned int storage);
	void Load(const DL_GroupPrecomputation<Element> &group, BufferedTransformation &storedPrecomputation);
	void Save(const DL_GroupPrecomputation<Element> &group, BufferedTransformation &storedPrecomputation) const;
	Element Exponentiate(const DL_GroupPrecomputation<Element> &group, const Integer &exponent) const;
	Element CascadeExponentiate(const DL_GroupPrecomputation<Element> &group, const Integer &exponent, const DL_FixedBasePrecomputation<Element> &pc2, const Integer &exponent2) const;

private:
	void PrepareCascade(const DL_GroupPrecomputation<Element> &group, std::vector<BaseAndExponent<Element> > &eb, const Integer &exponent) const;

	Element m_base;
	unsigned int m_windowSize;
	Integer m_exponentBase;			// what base to represent the exponent in
	std::vector<Element> m_bases;	// precalculated bases
};

NAMESPACE_END

#ifdef CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#include "eprecomp.cpp"
#endif

#endif
