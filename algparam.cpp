// algparam.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

PAssignIntToInteger g_pAssignIntToInteger = NULL;

bool CombinedNameValuePairs::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	if (strcmp(name, "ValueNames") == 0)
		return m_pairs1.GetVoidValue(name, valueType, pValue) && m_pairs2.GetVoidValue(name, valueType, pValue);
	else
		return m_pairs1.GetVoidValue(name, valueType, pValue) || m_pairs2.GetVoidValue(name, valueType, pValue);
}

void AlgorithmParametersBase::operator=(const AlgorithmParametersBase& rhs)
{
	assert(false);
}

bool AlgorithmParametersBase::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	if (strcmp(name, "ValueNames") == 0)
	{
		NameValuePairs::ThrowIfTypeMismatch(name, typeid(std::string), valueType);
		if (m_next.get())
		    m_next->GetVoidValue(name, valueType, pValue);
		(*reinterpret_cast<std::string *>(pValue) += m_name) += ";";
		return true;
	}
	else if (strcmp(name, m_name) == 0)
	{
		AssignValue(name, valueType, pValue);
		m_used = true;
		return true;
	}
	else if (m_next.get())
		return m_next->GetVoidValue(name, valueType, pValue);
	else
	    return false;
}

AlgorithmParameters::AlgorithmParameters()
	: m_constructed(false), m_defaultThrowIfNotUsed(true)
{
	new(m_first) member_ptr<AlgorithmParametersBase>;
}

AlgorithmParameters::AlgorithmParameters(const AlgorithmParameters &x)
	: m_constructed(false), m_defaultThrowIfNotUsed(x.m_defaultThrowIfNotUsed)
{
	if (x.m_constructed)
	{
		x.First().MoveInto(m_first);
		m_constructed = true;
	}
	else
		new(m_first) member_ptr<AlgorithmParametersBase>(x.Next().release());
}

AlgorithmParameters::~AlgorithmParameters()
{
	if (m_constructed)
		First().~AlgorithmParametersBase();
	else
		Next().~member_ptr<AlgorithmParametersBase>();
}

AlgorithmParameters & AlgorithmParameters::operator=(const AlgorithmParameters &x)
{
	if (this == &x)
		return *this;
	this->~AlgorithmParameters();
	new (this) AlgorithmParameters(x);
	return *this;
}

bool AlgorithmParameters::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	if (m_constructed)
		return First().GetVoidValue(name, valueType, pValue);
	else if (Next().get())
		return Next()->GetVoidValue(name, valueType, pValue);
	else
		return false;
}

AlgorithmParametersBase & AlgorithmParameters::First()
{
	return *reinterpret_cast<AlgorithmParametersBase *>(m_first);
}

member_ptr<AlgorithmParametersBase> & AlgorithmParameters::Next()
{
	if (m_constructed)
		return First().m_next;
	else
		return *reinterpret_cast<member_ptr<AlgorithmParametersBase> *>(m_first);
}

NAMESPACE_END

#endif
