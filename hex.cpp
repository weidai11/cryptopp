// hex.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "hex.h"

NAMESPACE_BEGIN(CryptoPP)
ANONYMOUS_NAMESPACE_BEGIN

const byte s_vecUpper[] = "0123456789ABCDEF";
const byte s_vecLower[] = "0123456789abcdef";
const int s_array[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

ANONYMOUS_NAMESPACE_END

void HexEncoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	bool uppercase = parameters.GetValueWithDefault(Name::Uppercase(), true);
	m_filter->Initialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::EncodingLookupArray(), uppercase ? &s_vecUpper[0] : &s_vecLower[0], false)(Name::Log2Base(), 4, true)));
}

void HexDecoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	BaseN_Decoder::IsolatedInitialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::DecodingLookupArray(), GetDefaultDecodingLookupArray(), false)(Name::Log2Base(), 4, true)));
}

// Unrolled initialization, http://github.com/weidai11/cryptopp/issues/376
const int *HexDecoder::GetDefaultDecodingLookupArray()
{
	return s_array;
}

NAMESPACE_END

#endif  // CRYPTOPP_IMPORTS
