// algparam.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "algparam.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

const std::type_info &g_typeidInteger = typeid(Integer);

void AssignIntToInteger(void *pInteger, const void *pInt)
{
	*reinterpret_cast<Integer *>(pInteger) = *reinterpret_cast<const int *>(pInt);
}

NAMESPACE_END
