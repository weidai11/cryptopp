#ifndef CRYPTOPP_BASECODE_H
#define CRYPTOPP_BASECODE_H

#include "filters.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

class BaseN_Encoder : public Unflushable<Filter>
{
public:
	BaseN_Encoder(BufferedTransformation *attachment=NULL)
		: Unflushable<Filter>(attachment) {}

	BaseN_Encoder(const byte *alphabet, int log2base, BufferedTransformation *attachment=NULL, int padding=-1)
		: Unflushable<Filter>(attachment)
	{
		IsolatedInitialize(MakeParameters("EncodingLookupArray", alphabet)
			("Log2Base", log2base)
			("Pad", padding != -1)
			("PaddingByte", byte(padding)));
	}

	void IsolatedInitialize(const NameValuePairs &parameters);
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking);

private:
	const byte *m_alphabet;
	int m_padding, m_bitsPerChar, m_outputBlockSize;
	int m_bytePos, m_bitPos;
	SecByteBlock m_outBuf;
};

class BaseN_Decoder : public Unflushable<Filter>
{
public:
	BaseN_Decoder(BufferedTransformation *attachment=NULL)
		: Unflushable<Filter>(attachment) {}

	BaseN_Decoder(const int *lookup, int log2base, BufferedTransformation *attachment=NULL)
		: Unflushable<Filter>(attachment)
	{
		IsolatedInitialize(MakeParameters("DecodingLookupArray", lookup)("Log2Base", log2base));
	}

	void IsolatedInitialize(const NameValuePairs &parameters);
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking);

	static void InitializeDecodingLookupArray(int *lookup, const byte *alphabet, unsigned int log2base, bool caseInsensitive);

private:
	const int *m_lookup;
	int m_padding, m_bitsPerChar, m_outputBlockSize;
	int m_bytePos, m_bitPos;
	SecByteBlock m_outBuf;
};

class Grouper : public Bufferless<Filter>
{
public:
	Grouper(BufferedTransformation *attachment=NULL)
		: Bufferless<Filter>(attachment) {}

	Grouper(int groupSize, const std::string &separator, const std::string &terminator, BufferedTransformation *attachment=NULL)
		: Bufferless<Filter>(attachment)
	{
		IsolatedInitialize(MakeParameters("GroupSize", groupSize)
			("Separator", ConstByteArrayParameter(separator))
			("Terminator", ConstByteArrayParameter(terminator)));
	}

	void IsolatedInitialize(const NameValuePairs &parameters);
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking);

private:
	SecByteBlock m_separator, m_terminator;
	unsigned int m_groupSize, m_counter;
};

NAMESPACE_END

#endif
