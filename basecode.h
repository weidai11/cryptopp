// basecode.h - written and placed in the public domain by Wei Dai

//! \file
//! \brief Base classes for working with encoders and decoders.

#ifndef CRYPTOPP_BASECODE_H
#define CRYPTOPP_BASECODE_H

#include "cryptlib.h"
#include "filters.h"
#include "algparam.h"
#include "argnames.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class BaseN_Encoder
//! \details base n encoder, where n is a power of 2
class CRYPTOPP_DLL BaseN_Encoder : public Unflushable<Filter>
{
public:
	BaseN_Encoder(BufferedTransformation *attachment=NULL)
		: m_alphabet(NULL), m_padding(0), m_bitsPerChar(0)
		, m_outputBlockSize(0), m_bytePos(0), m_bitPos(0)
			{Detach(attachment);}

	BaseN_Encoder(const byte *alphabet, int log2base, BufferedTransformation *attachment=NULL, int padding=-1)
		: m_alphabet(NULL), m_padding(0), m_bitsPerChar(0)
		, m_outputBlockSize(0), m_bytePos(0), m_bitPos(0)
	{
		Detach(attachment);
		IsolatedInitialize(MakeParameters(Name::EncodingLookupArray(), alphabet)
			(Name::Log2Base(), log2base)
			(Name::Pad(), padding != -1)
			(Name::PaddingByte(), byte(padding)));
	}

	void IsolatedInitialize(const NameValuePairs &parameters);
	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking);

private:
	const byte *m_alphabet;
	int m_padding, m_bitsPerChar, m_outputBlockSize;
	int m_bytePos, m_bitPos;
	SecByteBlock m_outBuf;
};

//! \class BaseN_Decoder
//! \details base n encoder, where n is a power of 2
class CRYPTOPP_DLL BaseN_Decoder : public Unflushable<Filter>
{
public:
	BaseN_Decoder(BufferedTransformation *attachment=NULL)
		: m_lookup(0), m_padding(0), m_bitsPerChar(0)
		, m_outputBlockSize(0), m_bytePos(0), m_bitPos(0)
			{Detach(attachment);}

	BaseN_Decoder(const int *lookup, int log2base, BufferedTransformation *attachment=NULL)
		: m_lookup(0), m_padding(0), m_bitsPerChar(0)
		, m_outputBlockSize(0), m_bytePos(0), m_bitPos(0)
	{
		Detach(attachment);
		IsolatedInitialize(MakeParameters(Name::DecodingLookupArray(), lookup)(Name::Log2Base(), log2base));
	}

	void IsolatedInitialize(const NameValuePairs &parameters);
	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking);

	static void CRYPTOPP_API InitializeDecodingLookupArray(int *lookup, const byte *alphabet, unsigned int base, bool caseInsensitive);

private:
	const int *m_lookup;
	int m_padding, m_bitsPerChar, m_outputBlockSize;
	int m_bytePos, m_bitPos;
	SecByteBlock m_outBuf;
};

//! filter that breaks input stream into groups of fixed size
class CRYPTOPP_DLL Grouper : public Bufferless<Filter>
{
public:
	Grouper(BufferedTransformation *attachment=NULL)
		: m_groupSize(0), m_counter(0) {Detach(attachment);}

	Grouper(int groupSize, const std::string &separator, const std::string &terminator, BufferedTransformation *attachment=NULL)
		: m_groupSize(0), m_counter(0)
	{
		Detach(attachment);
		IsolatedInitialize(MakeParameters(Name::GroupSize(), groupSize)
			(Name::Separator(), ConstByteArrayParameter(separator))
			(Name::Terminator(), ConstByteArrayParameter(terminator)));
	}

	void IsolatedInitialize(const NameValuePairs &parameters);
	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking);

private:
	SecByteBlock m_separator, m_terminator;
	size_t m_groupSize, m_counter;
};

NAMESPACE_END

#endif
