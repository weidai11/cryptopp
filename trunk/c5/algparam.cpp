// algparam.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

bool (*AssignIntToInteger)(const std::type_info &valueType, void *pInteger, const void *pInt) = NULL;

NAMESPACE_END
