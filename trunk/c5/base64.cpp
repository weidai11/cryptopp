// base64.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "base64.h"

NAMESPACE_BEGIN(CryptoPP)

static const byte s_vec[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const byte s_padding = '=';

void Base64Encoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	bool insertLineBreaks = parameters.GetValueWithDefault("InsertLineBreaks", true);
	int maxLineLength = parameters.GetIntValueWithDefault("MaxLineLength", 72);
	
	m_filter->Initialize(CombinedNameValuePairs(
		parameters,
		MakeParameters("EncodingLookupArray", (const byte *)s_vec)
			("PaddingByte", s_padding)
			("Log2Base", 6)
			("GroupSize", insertLineBreaks ? maxLineLength : 0)
			("Seperator", ConstByteArrayParameter("\n"))
			("Terminator", ConstByteArrayParameter("\n"))));
}

const int *Base64Decoder::GetDecodingLookupArray()
{
	static bool s_initialized = false;
	static int s_array[256];

	if (!s_initialized)
	{
		InitializeDecodingLookupArray(s_array, s_vec, 64, false);
		s_initialized = true;
	}
	return s_array;
}

NAMESPACE_END
