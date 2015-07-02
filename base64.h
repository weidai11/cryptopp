#ifndef CRYPTOPP_BASE64_H
#define CRYPTOPP_BASE64_H

#include "basecode.h"

NAMESPACE_BEGIN(CryptoPP)

//! Base64 Encoder Class
// https://tools.ietf.org/html/rfc4648#section-4
class Base64Encoder : public SimpleProxyFilter
{
public:
	Base64Encoder(BufferedTransformation *attachment = NULL, bool insertLineBreaks = true, int maxLineLength = 72)
		: SimpleProxyFilter(new BaseN_Encoder(new Grouper), attachment)
	{
		IsolatedInitialize(MakeParameters(Name::InsertLineBreaks(), insertLineBreaks)(Name::MaxLineLength(), maxLineLength));
	}
    
	void IsolatedInitialize(const NameValuePairs &parameters);
};

//! Base64 Decoder Class
// https://tools.ietf.org/html/rfc4648#section-4
class Base64Decoder : public BaseN_Decoder
{
public:
	Base64Decoder(BufferedTransformation *attachment = NULL)
		: BaseN_Decoder(GetDecodingLookupArray(), 6, attachment) {}
    
	void IsolatedInitialize(const NameValuePairs &parameters) {}
    
private:
	static const int * CRYPTOPP_API GetDecodingLookupArray();
};

//! Base64 URL Encoder Class
// https://tools.ietf.org/html/rfc4648#section-5
class Base64URLEncoder : public SimpleProxyFilter
{
public:
	Base64URLEncoder(BufferedTransformation *attachment = NULL, bool insertLineBreaks = false, int maxLineLength = -1)
		: SimpleProxyFilter(new BaseN_Encoder(new Grouper), attachment)
	{
		IsolatedInitialize(MakeParameters(Name::InsertLineBreaks(), insertLineBreaks)(Name::MaxLineLength(), maxLineLength));
	}
    
	void IsolatedInitialize(const NameValuePairs &parameters);
};

//! Base64 URL Decoder Class
class Base64URLDecoder : public BaseN_Decoder
{
public:
	Base64URLDecoder(BufferedTransformation *attachment = NULL)
		: BaseN_Decoder(GetDecodingLookupArray(), 6, attachment) {}
    
	void IsolatedInitialize(const NameValuePairs &parameters) {}
    
private:
	static const int * CRYPTOPP_API GetDecodingLookupArray();
};

NAMESPACE_END

#endif
