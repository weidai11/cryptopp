// network.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "network.h"
#include "wait.h"

#define CRYPTOPP_TRACE_NETWORK 0

NAMESPACE_BEGIN(CryptoPP)

size_t NonblockingSource::PumpMessages2(unsigned int &messageCount, bool blocking)
{
	if (messageCount == 0)
		return 0;

	messageCount = 0;

	lword byteCount;
	do {
		byteCount = LWORD_MAX;
		RETURN_IF_NONZERO(Pump2(byteCount, blocking));
	} while(byteCount == LWORD_MAX);

	if (!m_messageEndSent && SourceExhausted())
	{
		RETURN_IF_NONZERO(AttachedTransformation()->Put2(NULL, 0, GetAutoSignalPropagation(), true));
		m_messageEndSent = true;
		messageCount = 1;
	}
	return 0;
}

bool NonblockingSink::IsolatedFlush(bool hardFlush, bool blocking)
{
	TimedFlush(blocking ? INFINITE_TIME : 0);
	return hardFlush && !!GetCurrentBufferSize();
}

// *************************************************************

#ifdef HIGHRES_TIMER_AVAILABLE

NetworkSource::NetworkSource(BufferedTransformation *attachment)
	: NonblockingSource(attachment), m_buf(1024*16)
	, m_waitingForResult(false), m_outputBlocked(false)
	, m_dataBegin(0), m_dataEnd(0)
{
}

void NetworkSource::GetWaitObjects(WaitObjectContainer &container)
{
	if (!m_outputBlocked)
	{
		if (m_dataBegin == m_dataEnd)
			AccessReceiver().GetWaitObjects(container); 
		else
			container.SetNoWait();
	}
	AttachedTransformation()->GetWaitObjects(container);
}

size_t NetworkSource::GeneralPump2(lword &byteCount, bool blockingOutput, unsigned long maxTime, bool checkDelimiter, byte delimiter)
{
	NetworkReceiver &receiver = AccessReceiver();

	lword maxSize = byteCount;
	byteCount = 0;
	bool forever = maxTime == INFINITE_TIME;
	Timer timer(Timer::MILLISECONDS, forever);
	BufferedTransformation *t = AttachedTransformation();

	if (m_outputBlocked)
		goto DoOutput;

	while (true)
	{
		if (m_dataBegin == m_dataEnd)
		{
			if (receiver.EofReceived())
				break;

			if (m_waitingForResult)
			{
				if (receiver.MustWaitForResult() && !receiver.Wait(SaturatingSubtract(maxTime, timer.ElapsedTime())))
					break;

				unsigned int recvResult = receiver.GetReceiveResult();
#if CRYPTOPP_TRACE_NETWORK
				OutputDebugString((IntToString((unsigned int)this) + ": Received " + IntToString(recvResult) + " bytes\n").c_str());
#endif
				m_dataEnd += recvResult;
				m_waitingForResult = false;

				if (!receiver.MustWaitToReceive() && !receiver.EofReceived() && m_dataEnd != m_buf.size())
					goto ReceiveNoWait;
			}
			else
			{
				m_dataEnd = m_dataBegin = 0;

				if (receiver.MustWaitToReceive())
				{
					if (!receiver.Wait(SaturatingSubtract(maxTime, timer.ElapsedTime())))
						break;

					receiver.Receive(m_buf+m_dataEnd, m_buf.size()-m_dataEnd);
					m_waitingForResult = true;
				}
				else
				{
ReceiveNoWait:
					m_waitingForResult = true;
					// call Receive repeatedly as long as data is immediately available,
					// because some receivers tend to return data in small pieces
#if CRYPTOPP_TRACE_NETWORK
					OutputDebugString((IntToString((unsigned int)this) + ": Receiving " + IntToString(m_buf.size()-m_dataEnd) + " bytes\n").c_str());
#endif
					while (receiver.Receive(m_buf+m_dataEnd, m_buf.size()-m_dataEnd))
					{
						unsigned int recvResult = receiver.GetReceiveResult();
#if CRYPTOPP_TRACE_NETWORK
						OutputDebugString((IntToString((unsigned int)this) + ": Received " + IntToString(recvResult) + " bytes\n").c_str());
#endif
						m_dataEnd += recvResult;
						if (receiver.EofReceived() || m_dataEnd > m_buf.size() /2)
						{
							m_waitingForResult = false;
							break;
						}
					}
				}
			}
		}
		else
		{
			m_putSize = (size_t)STDMIN((lword)m_dataEnd-m_dataBegin, maxSize-byteCount);
			if (checkDelimiter)
				m_putSize = std::find(m_buf+m_dataBegin, m_buf+m_dataBegin+m_putSize, delimiter) - (m_buf+m_dataBegin);

DoOutput:
			size_t result = t->PutModifiable2(m_buf+m_dataBegin, m_putSize, 0, forever || blockingOutput);
			if (result)
			{
				if (t->Wait(SaturatingSubtract(maxTime, timer.ElapsedTime())))
					goto DoOutput;
				else
				{
					m_outputBlocked = true;
					return result;
				}
			}
			m_outputBlocked = false;

			byteCount += m_putSize;
			m_dataBegin += m_putSize;
			if (checkDelimiter && m_dataBegin < m_dataEnd && m_buf[m_dataBegin] == delimiter)
				break;
			if (byteCount == maxSize)
				break;
			// once time limit is reached, return even if there is more data waiting
			// but make 0 a special case so caller can request a large amount of data to be
			// pumped as long as it is immediately available
			if (maxTime > 0 && timer.ElapsedTime() > maxTime)
				break;
		}
	}

	return 0;
}

// *************************************************************

NetworkSink::NetworkSink(unsigned int maxBufferSize, unsigned int autoFlushBound)
	: m_maxBufferSize(maxBufferSize), m_autoFlushBound(autoFlushBound)
	, m_needSendResult(false), m_wasBlocked(false)
	, m_buffer(STDMIN(16U*1024U+256, maxBufferSize)), m_skipBytes(0) 
	, m_speedTimer(Timer::MILLISECONDS), m_byteCountSinceLastTimerReset(0)
	, m_currentSpeed(0), m_maxObservedSpeed(0)
{
}

float NetworkSink::ComputeCurrentSpeed()
{
	if (m_speedTimer.ElapsedTime() > 1000)
	{
		m_currentSpeed = m_byteCountSinceLastTimerReset * 1000 / m_speedTimer.ElapsedTime();
		m_maxObservedSpeed = STDMAX(m_currentSpeed, m_maxObservedSpeed * 0.98f);
		m_byteCountSinceLastTimerReset = 0;
		m_speedTimer.StartTimer();
//		OutputDebugString(("max speed: " + IntToString((int)m_maxObservedSpeed) + " current speed: " + IntToString((int)m_currentSpeed) + "\n").c_str());
	}
	return m_currentSpeed;
}

size_t NetworkSink::Put2(const byte *inString, size_t length, int messageEnd, bool blocking)
{
	if (m_skipBytes)
	{
		assert(length >= m_skipBytes);
		inString += m_skipBytes;
		length -= m_skipBytes;
	}
	m_buffer.LazyPut(inString, length);

	if (!blocking || m_buffer.CurrentSize() > m_autoFlushBound)
		TimedFlush(0, 0);

	size_t targetSize = messageEnd ? 0 : m_maxBufferSize;
	if (blocking)
		TimedFlush(INFINITE_TIME, targetSize);

	if (m_buffer.CurrentSize() > targetSize)
	{
		assert(!blocking);
		size_t blockedBytes = (size_t)STDMIN(m_buffer.CurrentSize() - targetSize, (lword)length);
		m_buffer.UndoLazyPut(blockedBytes);
		m_buffer.FinalizeLazyPut();
		m_wasBlocked = true;
		m_skipBytes += length - blockedBytes;
		return UnsignedMin(1, blockedBytes);
	}

	m_buffer.FinalizeLazyPut();
	m_wasBlocked = false;
	m_skipBytes = 0;

	if (messageEnd)
		AccessSender().SendEof();
	return 0;
}

lword NetworkSink::TimedFlush(unsigned long maxTime, size_t targetSize)
{
	NetworkSender &sender = AccessSender();

	bool forever = maxTime == INFINITE_TIME;
	Timer timer(Timer::MILLISECONDS, forever);
	unsigned int totalFlushSize = 0;

	while (true)
	{
		if (m_buffer.CurrentSize() <= targetSize)
			break;
		
		if (m_needSendResult)
		{
			if (sender.MustWaitForResult() && !sender.Wait(SaturatingSubtract(maxTime, timer.ElapsedTime())))
				break;

			unsigned int sendResult = sender.GetSendResult();
#if CRYPTOPP_TRACE_NETWORK
			OutputDebugString((IntToString((unsigned int)this) + ": Sent " + IntToString(sendResult) + " bytes\n").c_str());
#endif
			m_buffer.Skip(sendResult);
			totalFlushSize += sendResult;
			m_needSendResult = false;

			if (!m_buffer.AnyRetrievable())
				break;
		}

		unsigned long timeOut = maxTime ? SaturatingSubtract(maxTime, timer.ElapsedTime()) : 0;
		if (sender.MustWaitToSend() && !sender.Wait(timeOut))
			break;

		size_t contiguousSize = 0;
		const byte *block = m_buffer.Spy(contiguousSize);

#if CRYPTOPP_TRACE_NETWORK
		OutputDebugString((IntToString((unsigned int)this) + ": Sending " + IntToString(contiguousSize) + " bytes\n").c_str());
#endif
		sender.Send(block, contiguousSize);
		m_needSendResult = true;

		if (maxTime > 0 && timeOut == 0)
			break;	// once time limit is reached, return even if there is more data waiting
	}

	m_byteCountSinceLastTimerReset += totalFlushSize;
	ComputeCurrentSpeed();
	
	return totalFlushSize;
}

#endif	// #ifdef HIGHRES_TIMER_AVAILABLE

NAMESPACE_END
