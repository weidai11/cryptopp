// base64.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "config.h"
#include "base64.h"

NAMESPACE_BEGIN(CryptoPP)
ANONYMOUS_NAMESPACE_BEGIN

const byte s_stdVec[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const byte s_urlVec[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const byte s_padding = '=';
const int s_stdArray[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};
const int s_urlArray[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
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

void Base64Encoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	bool insertLineBreaks = parameters.GetValueWithDefault(Name::InsertLineBreaks(), true);
	int maxLineLength = parameters.GetIntValueWithDefault(Name::MaxLineLength(), 72);

	const char *lineBreak = insertLineBreaks ? "\n" : "";

	m_filter->Initialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::EncodingLookupArray(), &s_stdVec[0], false)
			(Name::PaddingByte(), s_padding)
			(Name::GroupSize(), insertLineBreaks ? maxLineLength : 0)
			(Name::Separator(), ConstByteArrayParameter(lineBreak))
			(Name::Terminator(), ConstByteArrayParameter(lineBreak))
			(Name::Log2Base(), 6, true)));
}

void Base64URLEncoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	bool insertLineBreaks = parameters.GetValueWithDefault(Name::InsertLineBreaks(), true);
	int maxLineLength = parameters.GetIntValueWithDefault(Name::MaxLineLength(), 72);

	const char *lineBreak = insertLineBreaks ? "\n" : "";

	m_filter->Initialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::EncodingLookupArray(), &s_urlVec[0], false)
			(Name::PaddingByte(), s_padding)
			(Name::GroupSize(), insertLineBreaks ? maxLineLength : 0)
			(Name::Separator(), ConstByteArrayParameter(lineBreak))
			(Name::Terminator(), ConstByteArrayParameter(lineBreak))
			(Name::Log2Base(), 6, true)));
}

void Base64Decoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	BaseN_Decoder::IsolatedInitialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::DecodingLookupArray(), GetDecodingLookupArray(), false)(Name::Log2Base(), 6, true)));
}

const int *Base64Decoder::GetDecodingLookupArray()
{
	return s_stdArray;
}

void Base64URLDecoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	BaseN_Decoder::IsolatedInitialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::DecodingLookupArray(), GetDecodingLookupArray(), false)(Name::Log2Base(), 6, true)));
}

// Unrolled initialization, http://github.com/weidai11/cryptopp/issues/376
const int *Base64URLDecoder::GetDecodingLookupArray()
{
	return s_urlArray;
}

NAMESPACE_END
