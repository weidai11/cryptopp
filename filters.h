#ifndef CRYPTOPP_FILTERS_H
#define CRYPTOPP_FILTERS_H

#include "simple.h"
#include "secblock.h"
#include "misc.h"
#include "smartptr.h"
#include "queue.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

/// provides an implementation of BufferedTransformation's attachment interface
class Filter : public BufferedTransformation, public NotCopyable
{
public:
	Filter(BufferedTransformation *attachment);

	bool Attachable() {return true;}
	BufferedTransformation *AttachedTransformation();
	const BufferedTransformation *AttachedTransformation() const;
	void Detach(BufferedTransformation *newAttachment = NULL);

	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const;

	void Initialize(const NameValuePairs &parameters=g_nullNameValuePairs, int propagation=-1);
	bool Flush(bool hardFlush, int propagation=-1, bool blocking=true);
	bool MessageSeriesEnd(int propagation=-1, bool blocking=true);

protected:
	virtual void NotifyAttachmentChange() {}
	virtual BufferedTransformation * NewDefaultAttachment() const;
	void Insert(Filter *nextFilter);	// insert filter after this one

	virtual bool ShouldPropagateMessageEnd() const {return true;}
	virtual bool ShouldPropagateMessageSeriesEnd() const {return true;}

	void PropagateInitialize(const NameValuePairs &parameters, int propagation, const std::string &channel=NULL_CHANNEL);

	unsigned int Output(int outputSite, const byte *inString, unsigned int length, int messageEnd, bool blocking, const std::string &channel=NULL_CHANNEL);
	bool OutputMessageEnd(int outputSite, int propagation, bool blocking, const std::string &channel=NULL_CHANNEL);
	bool OutputFlush(int outputSite, bool hardFlush, int propagation, bool blocking, const std::string &channel=NULL_CHANNEL);
	bool OutputMessageSeriesEnd(int outputSite, int propagation, bool blocking, const std::string &channel=NULL_CHANNEL);

private:
	member_ptr<BufferedTransformation> m_attachment;
	
protected:
	unsigned int m_inputPosition;
	int m_continueAt;
};

struct FilterPutSpaceHelper
{
	// desiredSize is how much to ask target, bufferSize is how much to allocate in m_tempSpace
	byte *HelpCreatePutSpace(BufferedTransformation &target, const std::string &channel, unsigned int minSize, unsigned int desiredSize, unsigned int &bufferSize)
	{
		assert(desiredSize >= minSize && bufferSize >= minSize);
		if (m_tempSpace.size() < minSize)
		{
			byte *result = target.ChannelCreatePutSpace(channel, desiredSize);
			if (desiredSize >= minSize)
			{
				bufferSize = desiredSize;
				return result;
			}
			m_tempSpace.New(bufferSize);
		}

		bufferSize = m_tempSpace.size();
		return m_tempSpace.begin();
	}
	byte *HelpCreatePutSpace(BufferedTransformation &target, const std::string &channel, unsigned int minSize)
		{return HelpCreatePutSpace(target, channel, minSize, minSize, minSize);}
	byte *HelpCreatePutSpace(BufferedTransformation &target, const std::string &channel, unsigned int minSize, unsigned int bufferSize)
		{return HelpCreatePutSpace(target, channel, minSize, minSize, bufferSize);}
	SecByteBlock m_tempSpace;
};

//! measure how many byte and messages pass through, also serves as valve
class MeterFilter : public Bufferless<Filter>
{
public:
	MeterFilter(BufferedTransformation *attachment=NULL, bool transparent=true)
		: Bufferless<Filter>(attachment), m_transparent(transparent) {ResetMeter();}

	void SetTransparent(bool transparent) {m_transparent = transparent;}
	void ResetMeter() {m_currentMessageBytes = m_totalBytes = m_currentSeriesMessages = m_totalMessages = m_totalMessageSeries = 0;}

	unsigned long GetCurrentMessageBytes() const {return m_currentMessageBytes;}
	unsigned long GetTotalBytes() {return m_totalBytes;}
	unsigned int GetCurrentSeriesMessages() {return m_currentSeriesMessages;}
	unsigned int GetTotalMessages() {return m_totalMessages;}
	unsigned int GetTotalMessageSeries() {return m_totalMessageSeries;}

	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking);
	bool IsolatedMessageSeriesEnd(bool blocking);

private:
	bool ShouldPropagateMessageEnd() const {return m_transparent;}
	bool ShouldPropagateMessageSeriesEnd() const {return m_transparent;}

	bool m_transparent;
	unsigned long m_currentMessageBytes, m_totalBytes;
	unsigned int m_currentSeriesMessages, m_totalMessages, m_totalMessageSeries;
};

//! .
class TransparentFilter : public MeterFilter
{
public:
	TransparentFilter(BufferedTransformation *attachment=NULL) : MeterFilter(attachment, true) {}
};

//! .
class OpaqueFilter : public MeterFilter
{
public:
	OpaqueFilter(BufferedTransformation *attachment=NULL) : MeterFilter(attachment, false) {}
};

/*! FilterWithBufferedInput divides up the input stream into
	a first block, a number of middle blocks, and a last block.
	First and last blocks are optional, and middle blocks may
	be a stream instead (i.e. blockSize == 1).
*/
class FilterWithBufferedInput : public Filter
{
public:
	FilterWithBufferedInput(BufferedTransformation *attachment);
	//! firstSize and lastSize may be 0, blockSize must be at least 1
	FilterWithBufferedInput(unsigned int firstSize, unsigned int blockSize, unsigned int lastSize, BufferedTransformation *attachment);

	void IsolatedInitialize(const NameValuePairs &parameters);
	unsigned int Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
	{
		return PutMaybeModifiable(const_cast<byte *>(inString), length, messageEnd, blocking, false);
	}
	unsigned int PutModifiable2(byte *inString, unsigned int length, int messageEnd, bool blocking)
	{
		return PutMaybeModifiable(inString, length, messageEnd, blocking, true);
	}
	/*! calls ForceNextPut() if hardFlush is true */
	bool IsolatedFlush(bool hardFlush, bool blocking);

	/*! The input buffer may contain more than blockSize bytes if lastSize != 0.
		ForceNextPut() forces a call to NextPut() if this is the case.
	*/
	void ForceNextPut();

protected:
	bool DidFirstPut() {return m_firstInputDone;}

	virtual void InitializeDerivedAndReturnNewSizes(const NameValuePairs &parameters, unsigned int &firstSize, unsigned int &blockSize, unsigned int &lastSize)
		{InitializeDerived(parameters);}
	virtual void InitializeDerived(const NameValuePairs &parameters) {}
	// FirstPut() is called if (firstSize != 0 and totalLength >= firstSize)
	// or (firstSize == 0 and (totalLength > 0 or a MessageEnd() is received))
	virtual void FirstPut(const byte *inString) =0;
	// NextPut() is called if totalLength >= firstSize+blockSize+lastSize
	virtual void NextPutSingle(const byte *inString) {assert(false);}
	// Same as NextPut() except length can be a multiple of blockSize
	// Either NextPut() or NextPutMultiple() must be overriden
	virtual void NextPutMultiple(const byte *inString, unsigned int length);
	// Same as NextPutMultiple(), but inString can be modified
	virtual void NextPutModifiable(byte *inString, unsigned int length)
		{NextPutMultiple(inString, length);}
	// LastPut() is always called
	// if totalLength < firstSize then length == totalLength
	// else if totalLength <= firstSize+lastSize then length == totalLength-firstSize
	// else lastSize <= length < lastSize+blockSize
	virtual void LastPut(const byte *inString, unsigned int length) =0;
	virtual void FlushDerived() {}

private:
	unsigned int PutMaybeModifiable(byte *begin, unsigned int length, int messageEnd, bool blocking, bool modifiable);
	void NextPutMaybeModifiable(byte *inString, unsigned int length, bool modifiable)
	{
		if (modifiable) NextPutModifiable(inString, length);
		else NextPutMultiple(inString, length);
	}

	// This function should no longer be used, put this here to cause a compiler error
	// if someone tries to override NextPut().
	virtual int NextPut(const byte *inString, unsigned int length) {assert(false); return 0;}

	class BlockQueue
	{
	public:
		void ResetQueue(unsigned int blockSize, unsigned int maxBlocks);
		byte *GetBlock();
		byte *GetContigousBlocks(unsigned int &numberOfBytes);
		unsigned int GetAll(byte *outString);
		void Put(const byte *inString, unsigned int length);
		unsigned int CurrentSize() const {return m_size;}
		unsigned int MaxSize() const {return m_buffer.size();}

	private:
		SecByteBlock m_buffer;
		unsigned int m_blockSize, m_maxBlocks, m_size;
		byte *m_begin;
	};

	unsigned int m_firstSize, m_blockSize, m_lastSize;
	bool m_firstInputDone;
	BlockQueue m_queue;
};

//! .
class FilterWithInputQueue : public Filter
{
public:
	FilterWithInputQueue(BufferedTransformation *attachment) : Filter(attachment) {}
	unsigned int Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
	{
		if (!blocking)
			throw BlockingInputOnly("FilterWithInputQueue");
		
		m_inQueue.Put(inString, length);
		if (messageEnd)
		{
			IsolatedMessageEnd(blocking);
			Output(0, NULL, 0, messageEnd, blocking);
		}
		return 0;
	}

protected:
	virtual bool IsolatedMessageEnd(bool blocking) =0;
	void IsolatedInitialize(const NameValuePairs &parameters) {m_inQueue.Clear();}

	ByteQueue m_inQueue;
};

//! Filter Wrapper for StreamTransformation
class StreamTransformationFilter : public FilterWithBufferedInput, private FilterPutSpaceHelper
{
public:
	enum BlockPaddingScheme {NO_PADDING, ZEROS_PADDING, PKCS_PADDING, ONE_AND_ZEROS_PADDING, DEFAULT_PADDING};
	/*! DEFAULT_PADDING means PKCS_PADDING if c.MandatoryBlockSize() > 1 && c.MinLastBlockSize() == 0 (e.g. ECB or CBC mode),
		otherwise NO_PADDING (OFB, CFB, CTR, CBC-CTS modes) */
	StreamTransformationFilter(StreamTransformation &c, BufferedTransformation *attachment = NULL, BlockPaddingScheme padding = DEFAULT_PADDING);

	void FirstPut(const byte *inString);
	void NextPutMultiple(const byte *inString, unsigned int length);
	void NextPutModifiable(byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);
//	byte * CreatePutSpace(unsigned int &size);

protected:
	static unsigned int LastBlockSize(StreamTransformation &c, BlockPaddingScheme padding);

	StreamTransformation &m_cipher;
	BlockPaddingScheme m_padding;
	unsigned int m_optimalBufferSize;
};

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
typedef StreamTransformationFilter StreamCipherFilter;
#endif

//! Filter Wrapper for HashTransformation
class HashFilter : public Bufferless<Filter>, private FilterPutSpaceHelper
{
public:
	HashFilter(HashTransformation &hm, BufferedTransformation *attachment = NULL, bool putMessage=false)
		: Bufferless<Filter>(attachment), m_hashModule(hm), m_putMessage(putMessage) {}

	void IsolatedInitialize(const NameValuePairs &parameters);
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking);

	byte * CreatePutSpace(unsigned int &size) {return m_hashModule.CreateUpdateSpace(size);}

private:
	HashTransformation &m_hashModule;
	bool m_putMessage;
	byte *m_space;
};

//! Filter Wrapper for HashTransformation
class HashVerificationFilter : public FilterWithBufferedInput
{
public:
	class HashVerificationFailed : public Exception
	{
	public:
		HashVerificationFailed()
			: Exception(DATA_INTEGRITY_CHECK_FAILED, "HashVerifier: message hash not valid") {}
	};

	enum Flags {HASH_AT_BEGIN=1, PUT_MESSAGE=2, PUT_HASH=4, PUT_RESULT=8, THROW_EXCEPTION=16, DEFAULT_FLAGS = HASH_AT_BEGIN | PUT_RESULT};
	HashVerificationFilter(HashTransformation &hm, BufferedTransformation *attachment = NULL, word32 flags = DEFAULT_FLAGS);

	bool GetLastResult() const {return m_verified;}

protected:
	void InitializeDerivedAndReturnNewSizes(const NameValuePairs &parameters, unsigned int &firstSize, unsigned int &blockSize, unsigned int &lastSize);
	void FirstPut(const byte *inString);
	void NextPutMultiple(const byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);

private:
	static inline unsigned int FirstSize(word32 flags, HashTransformation &hm) {return flags & HASH_AT_BEGIN ? hm.DigestSize() : 0;}
	static inline unsigned int LastSize(word32 flags, HashTransformation &hm) {return flags & HASH_AT_BEGIN ? 0 : hm.DigestSize();}

	HashTransformation &m_hashModule;
	word32 m_flags;
	SecByteBlock m_expectedHash;
	bool m_verified;
};

typedef HashVerificationFilter HashVerifier;	// for backwards compatibility

//! Filter Wrapper for PK_Signer
class SignerFilter : public Unflushable<Filter>
{
public:
	SignerFilter(RandomNumberGenerator &rng, const PK_Signer &signer, BufferedTransformation *attachment = NULL, bool putMessage=false)
		: Unflushable<Filter>(attachment), m_rng(rng), m_signer(signer), m_messageAccumulator(signer.NewSignatureAccumulator()), m_putMessage(putMessage) {}

	void IsolatedInitialize(const NameValuePairs &parameters);
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking);

private:
	RandomNumberGenerator &m_rng;
	const PK_Signer	&m_signer;
	member_ptr<PK_MessageAccumulator> m_messageAccumulator;
	bool m_putMessage;
	SecByteBlock m_buf;
};

//! Filter Wrapper for PK_Verifier
class SignatureVerificationFilter : public FilterWithBufferedInput
{
public:
	class SignatureVerificationFailed : public Exception
	{
	public:
		SignatureVerificationFailed()
			: Exception(DATA_INTEGRITY_CHECK_FAILED, "VerifierFilter: digital signature not valid") {}
	};

	enum Flags {SIGNATURE_AT_BEGIN=1, PUT_MESSAGE=2, PUT_SIGNATURE=4, PUT_RESULT=8, THROW_EXCEPTION=16, DEFAULT_FLAGS = SIGNATURE_AT_BEGIN | PUT_RESULT};
	SignatureVerificationFilter(const PK_Verifier &verifier, BufferedTransformation *attachment = NULL, word32 flags = DEFAULT_FLAGS);

	bool GetLastResult() const {return m_verified;}

protected:
	void InitializeDerivedAndReturnNewSizes(const NameValuePairs &parameters, unsigned int &firstSize, unsigned int &blockSize, unsigned int &lastSize);
	void FirstPut(const byte *inString);
	void NextPutMultiple(const byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);

private:
	const PK_Verifier &m_verifier;
	member_ptr<PK_MessageAccumulator> m_messageAccumulator;
	word32 m_flags;
	SecByteBlock m_signature;
	bool m_verified;
};

typedef SignatureVerificationFilter VerifierFilter; // for backwards compatibility

//! Redirect input to another BufferedTransformation without owning it
class Redirector : public CustomSignalPropagation<Sink>
{
public:
	Redirector() : m_target(NULL), m_passSignal(true) {}
	Redirector(BufferedTransformation &target, bool passSignal=true) : m_target(&target), m_passSignal(passSignal) {}

	void Redirect(BufferedTransformation &target) {m_target = &target;}
	void StopRedirection() {m_target = NULL;}
	bool GetPassSignal() const {return m_passSignal;}
	void SetPassSignal(bool passSignal) {m_passSignal = passSignal;}

	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return m_target ? m_target->Put2(begin, length, m_passSignal ? messageEnd : 0, blocking) : 0;}
	void Initialize(const NameValuePairs &parameters, int propagation)
		{ChannelInitialize(NULL_CHANNEL, parameters, propagation);}
	bool Flush(bool hardFlush, int propagation=-1, bool blocking=true)
		{return m_target && m_passSignal ? m_target->Flush(hardFlush, propagation, blocking) : false;}
	bool MessageSeriesEnd(int propagation=-1, bool blocking=true)
		{return m_target && m_passSignal ? m_target->MessageSeriesEnd(propagation, blocking) : false;}

	void ChannelInitialize(const std::string &channel, const NameValuePairs &parameters=g_nullNameValuePairs, int propagation=-1);
	unsigned int ChannelPut2(const std::string &channel, const byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return m_target ? m_target->ChannelPut2(channel, begin, length, m_passSignal ? messageEnd : 0, blocking) : 0;}
	unsigned int ChannelPutModifiable2(const std::string &channel, byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return m_target ? m_target->ChannelPutModifiable2(channel, begin, length, m_passSignal ? messageEnd : 0, blocking) : 0;}
	bool ChannelFlush(const std::string &channel, bool completeFlush, int propagation=-1, bool blocking=true)
		{return m_target && m_passSignal ? m_target->ChannelFlush(channel, completeFlush, propagation, blocking) : false;}
	bool ChannelMessageSeriesEnd(const std::string &channel, int propagation=-1, bool blocking=true)
		{return m_target && m_passSignal ? m_target->ChannelMessageSeriesEnd(channel, propagation, blocking) : false;}

private:
	BufferedTransformation *m_target;
	bool m_passSignal;
};

// Used By ProxyFilter
class OutputProxy : public CustomSignalPropagation<Sink>
{
public:
	OutputProxy(BufferedTransformation &owner, bool passSignal) : m_owner(owner), m_passSignal(passSignal) {}

	bool GetPassSignal() const {return m_passSignal;}
	void SetPassSignal(bool passSignal) {m_passSignal = passSignal;}

	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return m_owner.AttachedTransformation()->Put2(begin, length, m_passSignal ? messageEnd : 0, blocking);}
	unsigned int PutModifiable2(byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return m_owner.AttachedTransformation()->PutModifiable2(begin, length, m_passSignal ? messageEnd : 0, blocking);}
	void Initialize(const NameValuePairs &parameters=g_nullNameValuePairs, int propagation=-1)
		{if (m_passSignal) m_owner.AttachedTransformation()->Initialize(parameters, propagation);}
	bool Flush(bool hardFlush, int propagation=-1, bool blocking=true)
		{return m_passSignal ? m_owner.AttachedTransformation()->Flush(hardFlush, propagation, blocking) : false;}
	bool MessageSeriesEnd(int propagation=-1, bool blocking=true)
		{return m_passSignal ? m_owner.AttachedTransformation()->MessageSeriesEnd(propagation, blocking) : false;}

	unsigned int ChannelPut2(const std::string &channel, const byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return m_owner.AttachedTransformation()->ChannelPut2(channel, begin, length, m_passSignal ? messageEnd : 0, blocking);}
	unsigned int ChannelPutModifiable2(const std::string &channel, byte *begin, unsigned int length, int messageEnd, bool blocking)
		{return m_owner.AttachedTransformation()->ChannelPutModifiable2(channel, begin, length, m_passSignal ? messageEnd : 0, blocking);}
	void ChannelInitialize(const std::string &channel, const NameValuePairs &parameters, int propagation=-1)
		{if (m_passSignal) m_owner.AttachedTransformation()->ChannelInitialize(channel, parameters, propagation);}
	bool ChannelFlush(const std::string &channel, bool completeFlush, int propagation=-1, bool blocking=true)
		{return m_passSignal ? m_owner.AttachedTransformation()->ChannelFlush(channel, completeFlush, propagation, blocking) : false;}
	bool ChannelMessageSeriesEnd(const std::string &channel, int propagation=-1, bool blocking=true)
		{return m_passSignal ? m_owner.AttachedTransformation()->ChannelMessageSeriesEnd(channel, propagation, blocking) : false;}

private:
	BufferedTransformation &m_owner;
	bool m_passSignal;
};

//! Base class for Filter classes that are proxies for a chain of other filters.
class ProxyFilter : public FilterWithBufferedInput
{
public:
	ProxyFilter(BufferedTransformation *filter, unsigned int firstSize, unsigned int lastSize, BufferedTransformation *attachment);

	bool IsolatedFlush(bool hardFlush, bool blocking);

	void SetFilter(Filter *filter);
	void NextPutMultiple(const byte *s, unsigned int len);

protected:
	member_ptr<BufferedTransformation> m_filter;
};

//! simple proxy filter that doesn't modify the underlying filter's input or output
class SimpleProxyFilter : public ProxyFilter
{
public:
	SimpleProxyFilter(BufferedTransformation *filter, BufferedTransformation *attachment)
		: ProxyFilter(filter, 0, 0, attachment) {}

	void FirstPut(const byte *) {}
	void LastPut(const byte *, unsigned int) {m_filter->MessageEnd();}
};

//! proxy for the filter created by PK_Encryptor::CreateEncryptionFilter
/*! This class is here just to provide symmetry with VerifierFilter. */
class PK_EncryptorFilter : public SimpleProxyFilter
{
public:
	PK_EncryptorFilter(RandomNumberGenerator &rng, const PK_Encryptor &encryptor, BufferedTransformation *attachment = NULL)
		: SimpleProxyFilter(encryptor.CreateEncryptionFilter(rng), attachment) {}
};

//! proxy for the filter created by PK_Decryptor::CreateDecryptionFilter
/*! This class is here just to provide symmetry with SignerFilter. */
class PK_DecryptorFilter : public SimpleProxyFilter
{
public:
	PK_DecryptorFilter(RandomNumberGenerator &rng, const PK_Decryptor &decryptor, BufferedTransformation *attachment = NULL)
		: SimpleProxyFilter(decryptor.CreateDecryptionFilter(rng), attachment) {}
};

//! Append input to a string object
template <class T>
class StringSinkTemplate : public Bufferless<Sink>
{
public:
	// VC60 workaround: no T::char_type
	typedef typename T::traits_type::char_type char_type;

	StringSinkTemplate(T &output)
		: m_output(&output) {assert(sizeof(output[0])==1);}

	void IsolatedInitialize(const NameValuePairs &parameters)
		{if (!parameters.GetValue("OutputStringPointer", m_output)) throw InvalidArgument("StringSink: OutputStringPointer not specified");}

	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
	{
		if (length > 0)
		{
			typename T::size_type size = m_output->size();
			if (length < size && size + length > m_output->capacity())
				m_output->reserve(2*size);
			m_output->append((const char_type *)begin, (const char_type *)begin+length);
		}
		return 0;
	}

private:	
	T *m_output;
};

//! Append input to an std::string
typedef StringSinkTemplate<std::string> StringSink;

//! Copy input to a memory buffer
class ArraySink : public Bufferless<Sink>
{
public:
	ArraySink(const NameValuePairs &parameters = g_nullNameValuePairs) {IsolatedInitialize(parameters);}
	ArraySink(byte *buf, unsigned int size) : m_buf(buf), m_size(size), m_total(0) {}

	unsigned int AvailableSize() {return m_size - STDMIN(m_total, (unsigned long)m_size);}
	unsigned long TotalPutLength() {return m_total;}

	void IsolatedInitialize(const NameValuePairs &parameters);
	byte * CreatePutSpace(unsigned int &size);
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking);

protected:
	byte *m_buf;
	unsigned int m_size;
	unsigned long m_total;
};

//! Xor input to a memory buffer
class ArrayXorSink : public ArraySink
{
public:
	ArrayXorSink(byte *buf, unsigned int size)
		: ArraySink(buf, size) {}

	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking);
	byte * CreatePutSpace(unsigned int &size) {return BufferedTransformation::CreatePutSpace(size);}
};

//! .
class StringStore : public Store
{
public:
	StringStore(const char *string = NULL)
		{StoreInitialize(MakeParameters("InputBuffer", ConstByteArrayParameter(string)));}
	StringStore(const byte *string, unsigned int length)
		{StoreInitialize(MakeParameters("InputBuffer", ConstByteArrayParameter(string, length)));}
	template <class T> StringStore(const T &string)
		{StoreInitialize(MakeParameters("InputBuffer", ConstByteArrayParameter(string)));}

	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const;

private:
	void StoreInitialize(const NameValuePairs &parameters);

	const byte *m_store;
	unsigned int m_length, m_count;
};

//! .
class RandomNumberStore : public Store
{
public:
	RandomNumberStore(RandomNumberGenerator &rng, unsigned long length)
		: m_rng(rng), m_length(length), m_count(0) {}

	bool AnyRetrievable() const {return MaxRetrievable() != 0;}
	unsigned long MaxRetrievable() const {return m_length-m_count;}

	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const
	{
		throw NotImplemented("RandomNumberStore: CopyRangeTo2() is not supported by this store");
	}

private:
	void StoreInitialize(const NameValuePairs &parameters) {m_count = 0;}

	RandomNumberGenerator &m_rng;
	const unsigned long m_length;
	unsigned long m_count;
};

//! .
class NullStore : public Store
{
public:
	NullStore(unsigned long size = ULONG_MAX) : m_size(size) {}
	void StoreInitialize(const NameValuePairs &parameters) {}
	unsigned long MaxRetrievable() const {return m_size;}
	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const;

private:
	unsigned long m_size;
};

//! A Filter that pumps data into its attachment as input
class Source : public InputRejecting<Filter>
{
public:
	Source(BufferedTransformation *attachment)
		: InputRejecting<Filter>(attachment) {}

	unsigned long Pump(unsigned long pumpMax=ULONG_MAX)
		{Pump2(pumpMax); return pumpMax;}
	unsigned int PumpMessages(unsigned int count=UINT_MAX)
		{PumpMessages2(count); return count;}
	void PumpAll()
		{PumpAll2();}
	virtual unsigned int Pump2(unsigned long &byteCount, bool blocking=true) =0;
	virtual unsigned int PumpMessages2(unsigned int &messageCount, bool blocking=true) =0;
	virtual unsigned int PumpAll2(bool blocking=true);
	virtual bool SourceExhausted() const =0;

protected:
	void SourceInitialize(bool pumpAll, const NameValuePairs &parameters)
	{
		IsolatedInitialize(parameters);
		if (pumpAll)
			PumpAll();
	}
};

//! Turn a Store into a Source
template <class T>
class SourceTemplate : public Source
{
public:
	SourceTemplate<T>(BufferedTransformation *attachment)
		: Source(attachment) {}
	SourceTemplate<T>(BufferedTransformation *attachment, T store)
		: Source(attachment), m_store(store) {}
	void IsolatedInitialize(const NameValuePairs &parameters)
		{m_store.IsolatedInitialize(parameters);}
	unsigned int Pump2(unsigned long &byteCount, bool blocking=true)
		{return m_store.TransferTo2(*AttachedTransformation(), byteCount, NULL_CHANNEL, blocking);}
	unsigned int PumpMessages2(unsigned int &messageCount, bool blocking=true)
		{return m_store.TransferMessagesTo2(*AttachedTransformation(), messageCount, NULL_CHANNEL, blocking);}
	unsigned int PumpAll2(bool blocking=true)
		{return m_store.TransferAllTo2(*AttachedTransformation(), NULL_CHANNEL, blocking);}
	bool SourceExhausted() const
		{return !m_store.AnyRetrievable() && !m_store.AnyMessages();}
	void SetAutoSignalPropagation(int propagation)
		{m_store.SetAutoSignalPropagation(propagation);}
	int GetAutoSignalPropagation() const
		{return m_store.GetAutoSignalPropagation();}

protected:
	T m_store;
};

//! .
class StringSource : public SourceTemplate<StringStore>
{
public:
	StringSource(BufferedTransformation *attachment = NULL)
		: SourceTemplate<StringStore>(attachment) {}
	StringSource(const char *string, bool pumpAll, BufferedTransformation *attachment = NULL)
		: SourceTemplate<StringStore>(attachment) {SourceInitialize(pumpAll, MakeParameters("InputBuffer", ConstByteArrayParameter(string)));}
	StringSource(const byte *string, unsigned int length, bool pumpAll, BufferedTransformation *attachment = NULL)
		: SourceTemplate<StringStore>(attachment) {SourceInitialize(pumpAll, MakeParameters("InputBuffer", ConstByteArrayParameter(string, length)));}

#ifdef __MWERKS__	// CW60 workaround
	StringSource(const std::string &string, bool pumpAll, BufferedTransformation *attachment = NULL)
#else
	template <class T> StringSource(const T &string, bool pumpAll, BufferedTransformation *attachment = NULL)
#endif
		: SourceTemplate<StringStore>(attachment) {SourceInitialize(pumpAll, MakeParameters("InputBuffer", ConstByteArrayParameter(string)));}
};

//! .
class RandomNumberSource : public SourceTemplate<RandomNumberStore>
{
public:
	RandomNumberSource(RandomNumberGenerator &rng, unsigned int length, bool pumpAll, BufferedTransformation *attachment = NULL)
		: SourceTemplate<RandomNumberStore>(attachment, RandomNumberStore(rng, length)) {if (pumpAll) PumpAll();}
};

NAMESPACE_END

#endif
