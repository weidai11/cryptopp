// asn.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "asn.h"

#include <iomanip>
#include <time.h>

NAMESPACE_BEGIN(CryptoPP)
USING_NAMESPACE(std)

/// DER Length
unsigned int DERLengthEncode(BufferedTransformation &bt, unsigned int length)
{
	unsigned int i=0;
	if (length <= 0x7f)
	{
		bt.Put(byte(length));
		i++;
	}
	else
	{
		bt.Put(byte(BytePrecision(length) | 0x80));
		i++;
		for (int j=BytePrecision(length); j; --j)
		{
			bt.Put(byte(length >> (j-1)*8));
			i++;
		}
	}
	return i;
}

bool BERLengthDecode(BufferedTransformation &bt, unsigned int &length, bool &definiteLength)
{
	byte b;

	if (!bt.Get(b))
		return false;

	if (!(b & 0x80))
	{
		definiteLength = true;
		length = b;
	}
	else
	{
		unsigned int lengthBytes = b & 0x7f;

		if (lengthBytes == 0)
		{
			definiteLength = false;
			return true;
		}

		definiteLength = true;
		length = 0;
		while (lengthBytes--)
		{
			if (length >> (8*(sizeof(length)-1)))
				BERDecodeError();	// length about to overflow

			if (!bt.Get(b))
				return false;

			length = (length << 8) | b;
		}
	}
	return true;
}

bool BERLengthDecode(BufferedTransformation &bt, unsigned int &length)
{
	bool definiteLength;
	if (!BERLengthDecode(bt, length, definiteLength))
		BERDecodeError();
	return definiteLength;
}

void DEREncodeNull(BufferedTransformation &out)
{
	out.Put(TAG_NULL);
	out.Put(0);
}

void BERDecodeNull(BufferedTransformation &in)
{
	byte b;
	if (!in.Get(b) || b != TAG_NULL)
		BERDecodeError();
	unsigned int length;
	if (!BERLengthDecode(in, length) || length != 0)
		BERDecodeError();
}

/// ASN Strings
unsigned int DEREncodeOctetString(BufferedTransformation &bt, const byte *str, unsigned int strLen)
{
	bt.Put(OCTET_STRING);
	unsigned int lengthBytes = DERLengthEncode(bt, strLen);
	bt.Put(str, strLen);
	return 1+lengthBytes+strLen;
}

unsigned int DEREncodeOctetString(BufferedTransformation &bt, const SecByteBlock &str)
{
	return DEREncodeOctetString(bt, str.begin(), str.size());
}

unsigned int BERDecodeOctetString(BufferedTransformation &bt, SecByteBlock &str)
{
	byte b;
	if (!bt.Get(b) || b != OCTET_STRING)
		BERDecodeError();

	unsigned int bc;
	if (!BERLengthDecode(bt, bc))
		BERDecodeError();

	str.resize(bc);
	if (bc != bt.Get(str, bc))
		BERDecodeError();
	return bc;
}

unsigned int BERDecodeOctetString(BufferedTransformation &bt, BufferedTransformation &str)
{
	byte b;
	if (!bt.Get(b) || b != OCTET_STRING)
		BERDecodeError();

	unsigned int bc;
	if (!BERLengthDecode(bt, bc))
		BERDecodeError();

	bt.TransferTo(str, bc);
	return bc;
}

unsigned int DEREncodeTextString(BufferedTransformation &bt, const std::string &str, byte asnTag)
{
	bt.Put(asnTag);
	unsigned int lengthBytes = DERLengthEncode(bt, str.size());
	bt.Put((const byte *)str.data(), str.size());
	return 1+lengthBytes+str.size();
}

unsigned int BERDecodeTextString(BufferedTransformation &bt, std::string &str, byte asnTag)
{
	byte b;
	if (!bt.Get(b) || b != asnTag)
		BERDecodeError();

	unsigned int bc;
	if (!BERLengthDecode(bt, bc))
		BERDecodeError();

	SecByteBlock temp(bc);
	if (bc != bt.Get(temp, bc))
		BERDecodeError();
	str.assign((char *)temp.begin(), bc);
	return bc;
}

/// ASN BitString
unsigned int DEREncodeBitString(BufferedTransformation &bt, const byte *str, unsigned int strLen, unsigned int unusedBits)
{
	bt.Put(BIT_STRING);
	unsigned int lengthBytes = DERLengthEncode(bt, strLen+1);
	bt.Put((byte)unusedBits);
	bt.Put(str, strLen);
	return 2+lengthBytes+strLen;
}

unsigned int BERDecodeBitString(BufferedTransformation &bt, SecByteBlock &str, unsigned int &unusedBits)
{
	byte b;
	if (!bt.Get(b) || b != BIT_STRING)
		BERDecodeError();

	unsigned int bc;
	if (!BERLengthDecode(bt, bc))
		BERDecodeError();

	byte unused;
	if (!bt.Get(unused))
		BERDecodeError();
	unusedBits = unused;
	str.resize(bc-1);
	if ((bc-1) != bt.Get(str, bc-1))
		BERDecodeError();
	return bc-1;
}

void OID::EncodeValue(BufferedTransformation &bt, unsigned long v)
{
	for (unsigned int i=RoundUpToMultipleOf(STDMAX(7U,BitPrecision(v)), 7U)-7; i != 0; i-=7)
		bt.Put((byte)(0x80 | ((v >> i) & 0x7f)));
	bt.Put((byte)(v & 0x7f));
}

unsigned int OID::DecodeValue(BufferedTransformation &bt, unsigned long &v)
{
	byte b;
	unsigned int i=0;
	v = 0;
	while (true)
	{
		if (!bt.Get(b))
			BERDecodeError();
		i++;
		v <<= 7;
		v += b & 0x7f;
		if (!(b & 0x80))
			return i;
	}
}

void OID::DEREncode(BufferedTransformation &bt) const
{
	assert(m_values.size() >= 2);
	ByteQueue temp;
	temp.Put(byte(m_values[0] * 40 + m_values[1]));
	for (unsigned int i=2; i<m_values.size(); i++)
		EncodeValue(temp, m_values[i]);
	bt.Put(OBJECT_IDENTIFIER);
	DERLengthEncode(bt, temp.CurrentSize());
	temp.TransferTo(bt);
}

void OID::BERDecode(BufferedTransformation &bt)
{
	byte b;
	if (!bt.Get(b) || b != OBJECT_IDENTIFIER)
		BERDecodeError();

	unsigned int length;
	if (!BERLengthDecode(bt, length) || length < 1)
		BERDecodeError();

	if (!bt.Get(b))
		BERDecodeError();
	
	length--;
	m_values.resize(2);
	m_values[0] = b / 40;
	m_values[1] = b % 40;

	while (length > 0)
	{
		unsigned long v;
		unsigned int valueLen = DecodeValue(bt, v);
		if (valueLen > length)
			BERDecodeError();
		m_values.push_back(v);
		length -= valueLen;
	}
}

void OID::BERDecodeAndCheck(BufferedTransformation &bt) const
{
	OID oid(bt);
	if (*this != oid)
		BERDecodeError();
}

inline BufferedTransformation & EncodedObjectFilter::CurrentTarget()
{
	if (m_flags & PUT_OBJECTS) 
		return *AttachedTransformation();
	else
		return TheBitBucket();
}

void EncodedObjectFilter::Put(const byte *inString, unsigned int length)
{
	if (m_nCurrentObject == m_nObjects)
	{
		AttachedTransformation()->Put(inString, length);
		return;
	}

	LazyPutter lazyPutter(m_queue, inString, length);

	while (m_queue.AnyRetrievable())
	{
		switch (m_state)
		{
		case IDENTIFIER:
			if (!m_queue.Get(m_id))
				return;
			m_queue.TransferTo(CurrentTarget(), 1);
			m_state = LENGTH;	// fall through
		case LENGTH:
		{
			byte b;
			if (m_level > 0 && m_id == 0 && m_queue.Peek(b) && b == 0)
			{
				m_queue.TransferTo(CurrentTarget(), 1);
				m_level--;
				m_state = IDENTIFIER;
				break;
			}
			ByteQueue::Walker walker(m_queue);
			bool definiteLength;
			if (!BERLengthDecode(walker, m_lengthRemaining, definiteLength))
				return;
			m_queue.TransferTo(CurrentTarget(), walker.GetCurrentPosition());
			if (!((m_id & CONSTRUCTED) || definiteLength))
				BERDecodeError();
			if (!definiteLength)
			{
				if (!(m_id & CONSTRUCTED))
					BERDecodeError();
				m_level++;
				m_state = IDENTIFIER;
				break;
			}
			m_state = BODY;		// fall through
		}
		case BODY:
			m_lengthRemaining -= m_queue.TransferTo(CurrentTarget(), m_lengthRemaining);

			if (m_lengthRemaining == 0)
				m_state = IDENTIFIER;
		}

		if (m_state == IDENTIFIER && m_level == 0)
		{
			// just finished processing a level 0 object
			++m_nCurrentObject;

			if (m_flags & PUT_MESSANGE_END_AFTER_EACH_OBJECT)
				AttachedTransformation()->MessageEnd();

			if (m_nCurrentObject == m_nObjects)
			{
				if (m_flags & PUT_MESSANGE_END_AFTER_ALL_OBJECTS)
					AttachedTransformation()->MessageEnd();

				if (m_flags & PUT_MESSANGE_SERIES_END_AFTER_ALL_OBJECTS)
					AttachedTransformation()->MessageSeriesEnd();

				m_queue.TransferAllTo(*AttachedTransformation());
				return;
			}
		}
	}
}

BERGeneralDecoder::BERGeneralDecoder(BufferedTransformation &inQueue, byte asnTag)
	: m_inQueue(inQueue), m_finished(false)
{
	byte b;
	if (!m_inQueue.Get(b) || b != asnTag)
		BERDecodeError();

	m_definiteLength = BERLengthDecode(m_inQueue, m_length);
}

BERGeneralDecoder::BERGeneralDecoder(BERGeneralDecoder &inQueue, byte asnTag)
	: m_inQueue(inQueue), m_finished(false)
{
	byte b;
	if (!m_inQueue.Get(b) || b != asnTag)
		BERDecodeError();

	m_definiteLength = BERLengthDecode(m_inQueue, m_length);
	if (!m_definiteLength && !(asnTag & CONSTRUCTED))
		BERDecodeError();	// cannot be primitive have indefinite length
}

BERGeneralDecoder::~BERGeneralDecoder()
{
	try	// avoid throwing in constructor
	{
		if (!m_finished)
			MessageEnd();
	}
	catch (...)
	{
	}
}

bool BERGeneralDecoder::EndReached() const
{
	if (m_definiteLength)
		return m_length == 0;
	else
	{	// check end-of-content octets
		word16 i;
		return (m_inQueue.PeekWord16(i)==2 && i==0);
	}
}

byte BERGeneralDecoder::PeekByte() const
{
	byte b;
	if (!Peek(b))
		BERDecodeError();
	return b;
}

void BERGeneralDecoder::CheckByte(byte check)
{
	byte b;
	if (!Get(b) || b != check)
		BERDecodeError();
}

void BERGeneralDecoder::MessageEnd()
{
	m_finished = true;
	if (m_definiteLength)
	{
		if (m_length != 0)
			BERDecodeError();
	}
	else
	{	// remove end-of-content octets
		word16 i;
		if (m_inQueue.GetWord16(i) != 2 || i != 0)
			BERDecodeError();
	}
}

unsigned int BERGeneralDecoder::TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel, bool blocking)
{
	if (m_definiteLength && transferBytes > m_length)
		transferBytes = m_length;
	unsigned int blockedBytes = m_inQueue.TransferTo2(target, transferBytes, channel, blocking);
	ReduceLength(transferBytes);
	return blockedBytes;
}

unsigned int BERGeneralDecoder::CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end, const std::string &channel, bool blocking) const
{
	if (m_definiteLength)
		end = STDMIN((unsigned long)m_length, end);
	return m_inQueue.CopyRangeTo2(target, begin, end, channel, blocking);
}

unsigned int BERGeneralDecoder::ReduceLength(unsigned int delta)
{
	if (m_definiteLength)
	{
		if (m_length < delta)
			BERDecodeError();
		m_length -= delta;
	}
	return delta;
}

DERGeneralEncoder::DERGeneralEncoder(BufferedTransformation &outQueue, byte asnTag)
	: m_outQueue(outQueue), m_finished(false), m_asnTag(asnTag)
{
}

DERGeneralEncoder::DERGeneralEncoder(DERGeneralEncoder &outQueue, byte asnTag)
	: m_outQueue(outQueue), m_finished(false), m_asnTag(asnTag)
{
}

DERGeneralEncoder::~DERGeneralEncoder()
{
	try	// avoid throwing in constructor
	{
		if (!m_finished)
			MessageEnd();
	}
	catch (...)
	{
	}
}

void DERGeneralEncoder::MessageEnd()
{
	m_finished = true;
	unsigned int length = (unsigned int)CurrentSize();
	m_outQueue.Put(m_asnTag);
	DERLengthEncode(m_outQueue, length);
	TransferTo(m_outQueue);
}

// *************************************************************

void X509PublicKey::BERDecode(BufferedTransformation &bt)
{
	BERSequenceDecoder subjectPublicKeyInfo(bt);
		BERSequenceDecoder algorithm(subjectPublicKeyInfo);
			GetAlgorithmID().BERDecodeAndCheck(algorithm);
			bool parametersPresent = algorithm.EndReached() ? false : BERDecodeAlgorithmParameters(algorithm);
		algorithm.MessageEnd();

		BERGeneralDecoder subjectPublicKey(subjectPublicKeyInfo, BIT_STRING);
			subjectPublicKey.CheckByte(0);	// unused bits
			BERDecodeKey2(subjectPublicKey, parametersPresent, subjectPublicKey.RemainingLength());
		subjectPublicKey.MessageEnd();
	subjectPublicKeyInfo.MessageEnd();
}

void X509PublicKey::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder subjectPublicKeyInfo(bt);

		DERSequenceEncoder algorithm(subjectPublicKeyInfo);
			GetAlgorithmID().DEREncode(algorithm);
			DEREncodeAlgorithmParameters(algorithm);
		algorithm.MessageEnd();

		DERGeneralEncoder subjectPublicKey(subjectPublicKeyInfo, BIT_STRING);
			subjectPublicKey.Put(0);	// unused bits
			DEREncodeKey(subjectPublicKey);
		subjectPublicKey.MessageEnd();

	subjectPublicKeyInfo.MessageEnd();
}

void PKCS8PrivateKey::BERDecode(BufferedTransformation &bt)
{
	BERSequenceDecoder privateKeyInfo(bt);
		word32 version;
		BERDecodeUnsigned<word32>(privateKeyInfo, version, INTEGER, 0, 0);	// check version

		BERSequenceDecoder algorithm(privateKeyInfo);
			GetAlgorithmID().BERDecodeAndCheck(algorithm);
			bool parametersPresent = BERDecodeAlgorithmParameters(algorithm);
		algorithm.MessageEnd();

		BERGeneralDecoder octetString(privateKeyInfo, OCTET_STRING);
			BERDecodeKey2(octetString, parametersPresent, privateKeyInfo.RemainingLength());
		octetString.MessageEnd();

		BERDecodeOptionalAttributes(privateKeyInfo);
	privateKeyInfo.MessageEnd();
}

void PKCS8PrivateKey::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder privateKeyInfo(bt);
		DEREncodeUnsigned<word32>(privateKeyInfo, 0);	// version

		DERSequenceEncoder algorithm(privateKeyInfo);
			GetAlgorithmID().DEREncode(algorithm);
			DEREncodeAlgorithmParameters(algorithm);
		algorithm.MessageEnd();

		DERGeneralEncoder octetString(privateKeyInfo, OCTET_STRING);
			DEREncodeKey(octetString);
		octetString.MessageEnd();

		DEREncodeOptionalAttributes(privateKeyInfo);
	privateKeyInfo.MessageEnd();
}

NAMESPACE_END
