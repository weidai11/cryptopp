// simple.h - written and placed in the public domain by Wei Dai
/*! \file
 	Simple non-interface classes derived from classes in cryptlib.h.
*/

#ifndef CRYPTOPP_SIMPLE_H
#define CRYPTOPP_SIMPLE_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

template <class BASE, class ALGORITHM_INFO = BASE>
class AlgorithmImpl : public BASE
{
public:
	std::string AlgorithmName() const {return ALGORITHM_INFO::StaticAlgorithmName();}
};

//! .
class InvalidKeyLength : public InvalidArgument
{
public:
	explicit InvalidKeyLength(const std::string &algorithm, unsigned int length) : InvalidArgument(algorithm + ": " + IntToString(length) + " is not a valid key length") {}
};

//! .
class InvalidRounds : public InvalidArgument
{
public:
	explicit InvalidRounds(const std::string &algorithm, unsigned int rounds) : InvalidArgument(algorithm + ": " + IntToString(rounds) + " is not a valid number of rounds") {}
};

class HashTransformationWithDefaultTruncation : public HashTransformation
{
public:
	virtual void Final(byte *digest) =0;
	void TruncatedFinal(byte *digest, unsigned int digestSize);
};

//! .
// TODO: look into this virtual inheritance
class ASN1CryptoMaterial : virtual public ASN1Object, virtual public CryptoMaterial
{
public:
	void Save(BufferedTransformation &bt) const
		{BEREncode(bt);}
	void Load(BufferedTransformation &bt)
		{BERDecode(bt);}
};

// *****************************

template <class T>
class Bufferless : public T
{
public:
	Bufferless() {}
	Bufferless(BufferedTransformation *q) : T(q) {}
	bool IsolatedFlush(bool hardFlush, bool blocking) {return false;}
};

template <class T>
class Unflushable : public T
{
public:
	Unflushable() {}
	Unflushable(BufferedTransformation *q) : T(q) {}
	bool Flush(bool completeFlush, int propagation=-1, bool blocking=true)
		{return ChannelFlush(NULL_CHANNEL, completeFlush, propagation);}
	bool IsolatedFlush(bool hardFlush, bool blocking)
		{assert(false); return false;}
	bool ChannelFlush(const std::string &channel, bool hardFlush, int propagation=-1, bool blocking=true)
	{
		if (hardFlush && !InputBufferIsEmpty())
			throw CannotFlush("Unflushable<T>: this object has buffered input that cannot be flushed");
		else 
		{
			BufferedTransformation *attached = AttachedTransformation();
			return attached && propagation ? attached->ChannelFlush(channel, hardFlush, propagation-1, blocking) : false;
		}
	}

protected:
	virtual bool InputBufferIsEmpty() const {return false;}
};

template <class T>
class InputRejecting : public T
{
public:
	InputRejecting() {}
	InputRejecting(BufferedTransformation *q) : T(q) {}

protected:
	struct InputRejected : public NotImplemented
		{InputRejected() : NotImplemented("BufferedTransformation: this object doesn't allow input") {}};

	// shouldn't be calling these functions on this class
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
		{throw InputRejected();}
	bool IsolatedFlush(bool, bool) {return false;}
	bool IsolatedMessageSeriesEnd(bool) {throw InputRejected();}

	unsigned int ChannelPut2(const std::string &channel, const byte *begin, unsigned int length, int messageEnd, bool blocking)
		{throw InputRejected();}
	bool ChannelMessageSeriesEnd(const std::string &, int, bool) {throw InputRejected();}
};

template <class T>
class CustomSignalPropagation : public T
{
public:
	CustomSignalPropagation() {}
	CustomSignalPropagation(BufferedTransformation *q) : T(q) {}

	virtual void Initialize(const NameValuePairs &parameters=g_nullNameValuePairs, int propagation=-1) =0;
	virtual bool Flush(bool hardFlush, int propagation=-1, bool blocking=true) =0;

private:
	void IsolatedInitialize(const NameValuePairs &parameters) {assert(false);}
	bool IsolatedFlush(bool hardFlush, bool blocking) {assert(false); return false;}
};

template <class T>
class Multichannel : public CustomSignalPropagation<T>
{
public:
	Multichannel() {}
	Multichannel(BufferedTransformation *q) : CustomSignalPropagation<T>(q) {}

	void Initialize(const NameValuePairs &parameters, int propagation)
		{ChannelInitialize(NULL_CHANNEL, parameters, propagation);}
	bool Flush(bool hardFlush, int propagation=-1, bool blocking=true)
		{return ChannelFlush(NULL_CHANNEL, hardFlush, propagation, blocking);}
	bool MessageSeriesEnd(int propagation=-1, bool blocking=true)
		{return ChannelMessageSeriesEnd(NULL_CHANNEL, propagation, blocking);}
	byte * CreatePutSpace(unsigned int &size)
		{return ChannelCreatePutSpace(NULL_CHANNEL, size);}
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return ChannelPut2(NULL_CHANNEL, begin, length, messageEnd, blocking);}
	unsigned int PutModifiable2(byte *inString, unsigned int length, int messageEnd, bool blocking)
		{return ChannelPutModifiable2(NULL_CHANNEL, inString, length, messageEnd, blocking);}

//	void ChannelMessageSeriesEnd(const std::string &channel, int propagation=-1)
//		{PropagateMessageSeriesEnd(propagation, channel);}
	byte * ChannelCreatePutSpace(const std::string &channel, unsigned int &size)
		{size = 0; return NULL;}
	bool ChannelPutModifiable(const std::string &channel, byte *inString, unsigned int length)
		{ChannelPut(channel, inString, length); return false;}

	virtual unsigned int ChannelPut2(const std::string &channel, const byte *begin, unsigned int length, int messageEnd, bool blocking) =0;
	unsigned int ChannelPutModifiable2(const std::string &channel, byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return ChannelPut2(channel, begin, length, messageEnd, blocking);}

	virtual void ChannelInitialize(const std::string &channel, const NameValuePairs &parameters=g_nullNameValuePairs, int propagation=-1) =0;
	virtual bool ChannelFlush(const std::string &channel, bool hardFlush, int propagation=-1, bool blocking=true) =0;
};

template <class T>
class AutoSignaling : public T
{
public:
	AutoSignaling(int propagation=-1) : m_autoSignalPropagation(propagation) {}
	AutoSignaling(BufferedTransformation *q, int propagation=-1) : T(q), m_autoSignalPropagation(propagation) {}

	void SetAutoSignalPropagation(int propagation)
		{m_autoSignalPropagation = propagation;}
	int GetAutoSignalPropagation() const
		{return m_autoSignalPropagation;}

private:
	int m_autoSignalPropagation;
};

//! A BufferedTransformation that only contains pre-existing data as "output"
class Store : public AutoSignaling<InputRejecting<BufferedTransformation> >
{
public:
	Store() : m_messageEnd(false) {}

	void IsolatedInitialize(const NameValuePairs &parameters)
	{
		m_messageEnd = false;
		StoreInitialize(parameters);
	}

	unsigned int NumberOfMessages() const {return m_messageEnd ? 0 : 1;}
	bool GetNextMessage();
	unsigned int CopyMessagesTo(BufferedTransformation &target, unsigned int count=UINT_MAX, const std::string &channel=NULL_CHANNEL) const;

protected:
	virtual void StoreInitialize(const NameValuePairs &parameters) =0;

	bool m_messageEnd;
};

//! A BufferedTransformation that doesn't produce any retrievable output
class Sink : public BufferedTransformation
{
protected:
	// make these functions protected to help prevent unintentional calls to them
	BufferedTransformation::Get;
	BufferedTransformation::Peek;
	BufferedTransformation::TransferTo;
	BufferedTransformation::CopyTo;
	BufferedTransformation::CopyRangeTo;
	BufferedTransformation::TransferMessagesTo;
	BufferedTransformation::CopyMessagesTo;
	BufferedTransformation::TransferAllTo;
	BufferedTransformation::CopyAllTo;
	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true)
		{transferBytes = 0; return 0;}
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const
		{return 0;}
};

class BitBucket : public Bufferless<Sink>
{
public:
	std::string AlgorithmName() const {return "BitBucket";}
	void IsolatedInitialize(const NameValuePairs &parameters) {}
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return 0;}
};

NAMESPACE_END

#endif
