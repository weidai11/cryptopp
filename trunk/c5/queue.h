// specification file for an unlimited queue for storing bytes

#ifndef CRYPTOPP_QUEUE_H
#define CRYPTOPP_QUEUE_H

#include "simple.h"
//#include <algorithm>

NAMESPACE_BEGIN(CryptoPP)

/** The queue is implemented as a linked list of byte arrays, but you don't need to
    know about that.  So just ignore this next line. :) */
class ByteQueueNode;

//! Byte Queue
class ByteQueue : public Bufferless<BufferedTransformation>
{
public:
	ByteQueue(unsigned int m_nodeSize=256);
	ByteQueue(const ByteQueue &copy);
	~ByteQueue();

	unsigned long MaxRetrievable() const
		{return CurrentSize();}
	bool AnyRetrievable() const
		{return !IsEmpty();}

	void IsolatedInitialize(const NameValuePairs &parameters);
	byte * CreatePutSpace(unsigned int &size);
	unsigned int Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking);

	unsigned int Get(byte &outByte);
	unsigned int Get(byte *outString, unsigned int getMax);

	unsigned int Peek(byte &outByte) const;
	unsigned int Peek(byte *outString, unsigned int peekMax) const;

	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const;

	// these member functions are not inherited
	void SetNodeSize(unsigned int nodeSize) {m_nodeSize = nodeSize;}

	unsigned long CurrentSize() const;
	bool IsEmpty() const;

	void Clear();

	void Unget(byte inByte);
	void Unget(const byte *inString, unsigned int length);

	const byte * Spy(unsigned int &contiguousSize) const;

	void LazyPut(const byte *inString, unsigned int size);
	void UndoLazyPut(unsigned int size);
	void FinalizeLazyPut();

	ByteQueue & operator=(const ByteQueue &rhs);
	bool operator==(const ByteQueue &rhs) const;
	byte operator[](unsigned long i) const;
	void swap(ByteQueue &rhs);

	class Walker : public InputRejecting<BufferedTransformation>
	{
	public:
		Walker(const ByteQueue &queue)
			: m_queue(queue) {Initialize();}

		unsigned long GetCurrentPosition() {return m_position;}

		unsigned long MaxRetrievable() const
			{return m_queue.CurrentSize() - m_position;}

		void IsolatedInitialize(const NameValuePairs &parameters);

		unsigned int Get(byte &outByte);
		unsigned int Get(byte *outString, unsigned int getMax);

		unsigned int Peek(byte &outByte) const;
		unsigned int Peek(byte *outString, unsigned int peekMax) const;

		unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
		unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const;

	private:
		const ByteQueue &m_queue;
		const ByteQueueNode *m_node;
		unsigned long m_position;
		unsigned int m_offset;
		const byte *m_lazyString;
		unsigned int m_lazyLength;
	};

	friend class Walker;

private:
	void CleanupUsedNodes();
	void CopyFrom(const ByteQueue &copy);
	void Destroy();

	unsigned int m_nodeSize;
	ByteQueueNode *m_head, *m_tail;
	const byte *m_lazyString;
	unsigned int m_lazyLength;
};

//! use this to make sure LazyPut is finalized in event of exception
class LazyPutter
{
public:
	LazyPutter(ByteQueue &bq, const byte *inString, unsigned int size)
		: m_bq(bq) {bq.LazyPut(inString, size);}
	~LazyPutter()
		{try {m_bq.FinalizeLazyPut();} catch(...) {}}
private:
	ByteQueue &m_bq;
};

NAMESPACE_END

NAMESPACE_BEGIN(std)
template<> inline void swap(CryptoPP::ByteQueue &a, CryptoPP::ByteQueue &b)
{
	a.swap(b);
}
NAMESPACE_END

#endif
