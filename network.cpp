// network.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "network.h"
#include "wait.h"

NAMESPACE_BEGIN(CryptoPP)

unsigned int NonblockingSource::PumpMessages2(unsigned int &messageCount, bool blocking)
{
	if (messageCount == 0)
		return 0;

	unsigned long byteCount = ULONG_MAX;
	messageCount = 0;
	RETURN_IF_NONZERO(Pump2(byteCount, blocking));
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

unsigned int NetworkSource::GeneralPump2(unsigned long &byteCount, bool blockingOutput, unsigned long maxTime, bool checkDelimiter, byte delimiter)
{
	NetworkReceiver &receiver = AccessReceiver();

	unsigned long maxSize = byteCount;
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
					while (receiver.Receive(m_buf+m_dataEnd, m_buf.size()-m_dataEnd))
					{
						unsigned int recvResult = receiver.GetReceiveResult();
						m_dataEnd += recvResult;
						if (receiver.EofReceived() || m_dataEnd == m_buf.size())
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
			m_putSize = STDMIN((unsigned long)m_dataEnd-m_dataBegin, maxSize-byteCount);
			if (checkDelimiter)
				m_putSize = std::find(m_buf+m_dataBegin, m_buf+m_dataBegin+m_putSize, delimiter) - (m_buf+m_dataBegin);

DoOutput:
			unsigned int result = t->PutModifiable2(m_buf+m_dataBegin, m_putSize, 0, forever || blockingOutput);
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

NetworkSink::NetworkSink(unsigned int maxBufferSize, bool autoFlush)
	: m_maxBufferSize(maxBufferSize), m_autoFlush(autoFlush)
	, m_needSendResult(false), m_buffer(STDMIN(16U*1024U, maxBufferSize)), m_blockedBytes(0) 
{
}

unsigned int NetworkSink::Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
{
	if (m_blockedBytes)
	{
		assert(length >= m_blockedBytes);
		inString += length - m_blockedBytes;
		length = m_blockedBytes;
	}
	LazyPutter lp(m_buffer, inString, length);

	unsigned int targetSize = messageEnd ? 0 : m_maxBufferSize;
	TimedFlush(blocking ? INFINITE_TIME : 0, m_autoFlush ? 0 : targetSize);

	if (m_buffer.CurrentSize() > targetSize)
	{
		assert(!blocking);
		m_blockedBytes = STDMIN(m_buffer.CurrentSize() - targetSize, (unsigned long)length);
		m_buffer.UndoLazyPut(m_blockedBytes);
		return STDMAX(m_blockedBytes, 1U);
	}
	m_blockedBytes = 0;

	if (messageEnd)
		AccessSender().SendEof();
	return 0;
}

unsigned int NetworkSink::TimedFlush(unsigned long maxTime, unsigned int targetSize)
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
			m_buffer.Skip(sendResult);
			totalFlushSize += sendResult;
			m_needSendResult = false;

			if (!m_buffer.AnyRetrievable())
				break;
		}

		unsigned long timeOut = maxTime ? SaturatingSubtract(maxTime, timer.ElapsedTime()) : 0;
		if (sender.MustWaitToSend() && !sender.Wait(timeOut))
			break;

		unsigned int contiguousSize = 0;
		const byte *block = m_buffer.Spy(contiguousSize);

		sender.Send(block, contiguousSize);
		m_needSendResult = true;

		if (maxTime > 0 && timeOut == 0)
			break;	// once time limit is reached, return even if there is more data waiting
	}

	return totalFlushSize;
}

#endif	// #ifdef HIGHRES_TIMER_AVAILABLE

NAMESPACE_END
