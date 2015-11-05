// base32.h - written and placed in the public domain by Wei Dai

//! \file
//! \brief Class files for the Base32 encoder and decoder

#ifndef CRYPTOPP_BASE32_H
#define CRYPTOPP_BASE32_H

#include "cryptlib.h"
#include "basecode.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class Base32Encoder
//! \brief Base32 encodes data
//! \details Converts data to base32. The default code is based on draft-ietf-idn-dude-02.txt.
//! \details To specify alternative alpahabet or code, call Initialize() with EncodingLookupArray parameter.
class Base32Encoder : public SimpleProxyFilter
{
public:
	Base32Encoder(BufferedTransformation *attachment = NULL, bool uppercase = true, int outputGroupSize = 0, const std::string &separator = ":", const std::string &terminator = "")
		: SimpleProxyFilter(new BaseN_Encoder(new Grouper), attachment)
	{
		IsolatedInitialize(MakeParameters(Name::Uppercase(), uppercase)(Name::GroupSize(), outputGroupSize)(Name::Separator(), ConstByteArrayParameter(separator))(Name::Terminator(), ConstByteArrayParameter(terminator)));
	}

	void IsolatedInitialize(const NameValuePairs &parameters);
};

//! \class Base32Decoder
//! \brief Base32 decodes data
//! \details Decode base32 data. The default code is based on draft-ietf-idn-dude-02.txt
//! \details To specify alternative alpahabet or code, call Initialize() with EncodingLookupArray parameter.
class Base32Decoder : public BaseN_Decoder
{
public:
	Base32Decoder(BufferedTransformation *attachment = NULL)
		: BaseN_Decoder(GetDefaultDecodingLookupArray(), 5, attachment) {}

	void IsolatedInitialize(const NameValuePairs &parameters);

private:
	static const int * CRYPTOPP_API GetDefaultDecodingLookupArray();
};

NAMESPACE_END

#endif
