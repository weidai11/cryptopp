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

bool AlgorithmParametersBase::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	if (strcmp(name, "ValueNames") == 0)
	{
		ThrowIfTypeMismatch(name, typeid(std::string), valueType);
		GetParent().GetVoidValue(name, valueType, pValue);
		(*reinterpret_cast<std::string *>(pValue) += m_name) += ";";
		return true;
	}
	else if (strcmp(name, m_name) == 0)
	{
		AssignValue(name, valueType, pValue);
		m_used = true;
		return true;
	}
	else
		return GetParent().GetVoidValue(name, valueType, pValue);
}

NAMESPACE_END

#endif
