#ifndef CRYPTOPP_NETWORK_H
#define CRYPTOPP_NETWORK_H

#include "filters.h"
#include "hrtimer.h"

NAMESPACE_BEGIN(CryptoPP)

//! a Source class that can pump from a device for a specified amount of time.
class CRYPTOPP_NO_VTABLE NonblockingSource : public AutoSignaling<Source>
{
public:
	NonblockingSource(BufferedTransformation *attachment)
		: m_messageEndSent(false) {Detach(attachment);}

	//!	\name NONBLOCKING SOURCE
	//@{

	//! pump up to maxSize bytes using at most maxTime milliseconds
	/*! If checkDelimiter is true, pump up to delimiter, which itself is not extracted or pumped. */
	virtual size_t GeneralPump2(lword &byteCount, bool blockingOutput=true, unsigned long maxTime=INFINITE_TIME, bool checkDelimiter=false, byte delimiter='\n') =0;

	lword GeneralPump(lword maxSize=LWORD_MAX, unsigned long maxTime=INFINITE_TIME, bool checkDelimiter=false, byte delimiter='\n')
	{
		GeneralPump2(maxSize, true, maxTime, checkDelimiter, delimiter);
		return maxSize;
	}
	lword TimedPump(unsigned long maxTime)
		{return GeneralPump(LWORD_MAX, maxTime);}
	lword PumpLine(byte delimiter='\n', lword maxSize=1024)
		{return GeneralPump(maxSize, INFINITE_TIME, true, delimiter);}

	size_t Pump2(lword &byteCount, bool blocking=true)
		{return GeneralPump2(byteCount, blocking, blocking ? INFINITE_TIME : 0);}
	size_t PumpMessages2(unsigned int &messageCount, bool blocking=true);
	//@}

private:
	bool m_messageEndSent;
};

//! Network Receiver
class CRYPTOPP_NO_VTABLE NetworkReceiver : public Waitable
{
public:
	virtual bool MustWaitToReceive() {return false;}
	virtual bool MustWaitForResult() {return false;}
	//! receive data from network source, returns whether result is immediately available
	virtual bool Receive(byte* buf, size_t bufLen) =0;
	virtual unsigned int GetReceiveResult() =0;
	virtual bool EofReceived() const =0;
};

class CRYPTOPP_NO_VTABLE NonblockingSinkInfo
{
public:
	virtual ~NonblockingSinkInfo() {}
	virtual size_t GetMaxBufferSize() const =0;
	virtual size_t GetCurrentBufferSize() const =0;
	//! compute the current speed of this sink in bytes per second
	virtual float ComputeCurrentSpeed() =0;
	//! get the maximum observed speed of this sink in bytes per second
	virtual float GetMaxObservedSpeed() const =0;
};

//! a Sink class that queues input and can flush to a device for a specified amount of time.
class CRYPTOPP_NO_VTABLE NonblockingSink : public Sink, public NonblockingSinkInfo
{
public:
	bool IsolatedFlush(bool hardFlush, bool blocking);

	//! flush to device for no more than maxTime milliseconds
	/*! This function will repeatedly attempt to flush data to some device, until
		the queue is empty, or a total of maxTime milliseconds have elapsed.
		If maxTime == 0, at least one attempt will be made to flush some data, but
		it is likely that not all queued data will be flushed, even if the device
		is ready to receive more data without waiting. If you want to flush as much data
		as possible without waiting for the device, call this function in a loop.
		For example: while (sink.TimedFlush(0) > 0) {}
		\return number of bytes flushed
	*/
	virtual lword TimedFlush(unsigned long maxTime, size_t targetSize=0) =0;

	virtual void SetMaxBufferSize(size_t maxBufferSize) =0;
	//! set a bound which will cause sink to flush if exceeded by GetCurrentBufferSize()
	virtual void SetAutoFlushBound(size_t bound) =0;
};

//! Network Sender
class CRYPTOPP_NO_VTABLE NetworkSender : public Waitable
{
public:
	virtual bool MustWaitToSend() {return false;}
	virtual bool MustWaitForResult() {return false;}
	virtual void Send(const byte* buf, size_t bufLen) =0;
	virtual unsigned int GetSendResult() =0;
	virtual void SendEof() =0;
};

#ifdef HIGHRES_TIMER_AVAILABLE

//! Network Source
class CRYPTOPP_NO_VTABLE NetworkSource : public NonblockingSource
{
public:
	NetworkSource(BufferedTransformation *attachment);

	unsigned int GetMaxWaitObjectCount() const
		{return GetReceiver().GetMaxWaitObjectCount() + AttachedTransformation()->GetMaxWaitObjectCount();}
	void GetWaitObjects(WaitObjectContainer &container);

	size_t GeneralPump2(lword &byteCount, bool blockingOutput=true, unsigned long maxTime=INFINITE_TIME, bool checkDelimiter=false, byte delimiter='\n');
	bool SourceExhausted() const {return m_dataBegin == m_dataEnd && GetReceiver().EofReceived();}

protected:
	virtual NetworkReceiver & AccessReceiver() =0;
	const NetworkReceiver & GetReceiver() const {return const_cast<NetworkSource *>(this)->AccessReceiver();}

private:
	SecByteBlock m_buf;
	size_t m_putSize, m_dataBegin, m_dataEnd;
	bool m_waitingForResult, m_outputBlocked;
};

//! Network Sink
class CRYPTOPP_NO_VTABLE NetworkSink : public NonblockingSink
{
public:
	NetworkSink(unsigned int maxBufferSize, unsigned int autoFlushBound);

	unsigned int GetMaxWaitObjectCount() const
		{return GetSender().GetMaxWaitObjectCount();}
	void GetWaitObjects(WaitObjectContainer &container)
		{if (m_wasBlocked || !m_buffer.IsEmpty()) AccessSender().GetWaitObjects(container);}

	size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking);

	lword TimedFlush(unsigned long maxTime, size_t targetSize = 0);

	void SetMaxBufferSize(size_t maxBufferSize) {m_maxBufferSize = maxBufferSize; m_buffer.SetNodeSize(UnsignedMin(maxBufferSize, 16U*1024U+256U));}
	void SetAutoFlushBound(size_t bound) {m_autoFlushBound = bound;}

	size_t GetMaxBufferSize() const {return m_maxBufferSize;}
	size_t GetCurrentBufferSize() const {return (size_t)m_buffer.CurrentSize();}

	void ClearBuffer() {m_buffer.Clear();}

	//! compute the current speed of this sink in bytes per second
	float ComputeCurrentSpeed();
	//! get the maximum observed speed of this sink in bytes per second
	float GetMaxObservedSpeed() const {return m_maxObservedSpeed;}

protected:
	virtual NetworkSender & AccessSender() =0;
	const NetworkSender & GetSender() const {return const_cast<NetworkSink *>(this)->AccessSender();}

private:
	size_t m_maxBufferSize, m_autoFlushBound;
	bool m_needSendResult, m_wasBlocked;
	ByteQueue m_buffer;
	size_t m_skipBytes;
	Timer m_speedTimer;
	float m_byteCountSinceLastTimerReset, m_currentSpeed, m_maxObservedSpeed;
};

#endif	// #ifdef HIGHRES_TIMER_AVAILABLE

NAMESPACE_END

#endif
