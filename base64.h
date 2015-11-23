// base64.h - written and placed in the public domain by Wei Dai

//! \file
//! \brief Classes for the Base64Encoder, Base64Decoder, Base64URLEncoder and Base64URLDecoder

#ifndef CRYPTOPP_BASE64_H
#define CRYPTOPP_BASE64_H

#include "cryptlib.h"
#include "basecode.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class Base64Encoder
//! \brief Base64 encodes data
//! \details Base64 encodes data per RFC 4648 (http://tools.ietf.org/html/rfc4648#section-4)
//! \details To specify alternative alpahabet or code, call Initialize() with EncodingLookupArray parameter.
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

//! \class Base64Decoder
//! \brief Base64 decodes data
//! \details Base64 decodes data per RFC 4648 (http://tools.ietf.org/html/rfc4648#section-4)
//! \details To specify alternative alpahabet or code, call Initialize() with EncodingLookupArray parameter.
class Base64Decoder : public BaseN_Decoder
{
public:
	Base64Decoder(BufferedTransformation *attachment = NULL)
		: BaseN_Decoder(GetDecodingLookupArray(), 6, attachment) {}
    
	void IsolatedInitialize(const NameValuePairs &parameters)
		{CRYPTOPP_UNUSED(parameters);}
    
private:
	static const int * CRYPTOPP_API GetDecodingLookupArray();
};

//! \class Base64URLEncoder
//! \brief Base64 encodes data using a web safe alphabet
//! \details Base64 encodes data using a web safe alphabet per RFC 4648 (http://tools.ietf.org/html/rfc4648#section-5)
//! \details To specify alternative alpahabet or code, call Initialize() with EncodingLookupArray parameter.
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

//! \class Base64URLDecoder
//! \brief Base64 decodes data using a web safe alphabet
//! \details Base64 decodes data using a web safe alphabet per RFC 4648 (http://tools.ietf.org/html/rfc4648#section-5)
//! \details To specify alternative alpahabet or code, call Initialize() with EncodingLookupArray parameter.
class Base64URLDecoder : public BaseN_Decoder
{
public:
	Base64URLDecoder(BufferedTransformation *attachment = NULL)
		: BaseN_Decoder(GetDecodingLookupArray(), 6, attachment) {}
    
	void IsolatedInitialize(const NameValuePairs &parameters)
		{CRYPTOPP_UNUSED(parameters);}
    
private:
	static const int * CRYPTOPP_API GetDecodingLookupArray();
};

NAMESPACE_END

#endif
