// algparam.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "algparam.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

const std::type_info & IntegerTypeId()
{
	static const std::type_info &s_typeidInteger = typeid(Integer);
	return s_typeidInteger;
}

void AssignIntToInteger(void *pInteger, const void *pInt)
{
	*reinterpret_cast<Integer *>(pInteger) = *reinterpret_cast<const int *>(pInt);
}

NAMESPACE_END
