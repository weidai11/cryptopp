// network.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "network.h"

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
	: NonblockingSource(attachment), m_buf(1024*4), m_bufSize(0), m_state(NORMAL)
{
}

unsigned int NetworkSource::GeneralPump2(unsigned long &byteCount, bool blockingOutput, unsigned long maxTime, bool checkDelimiter, byte delimiter)
{
	NetworkReceiver &receiver = AccessReceiver();

	unsigned long maxSize = byteCount;
	byteCount = 0;
	bool forever = maxTime == INFINITE_TIME;
	Timer timer(Timer::MILLISECONDS, forever);
	unsigned long timeout;
	BufferedTransformation *t = AttachedTransformation();

	if (m_state == OUTPUT_BLOCKED)
		goto DoOutput;

	while (true)
	{
		if (m_state == WAITING_FOR_RESULT)
		{
			if (receiver.MustWaitForResult())
			{
				timeout = SaturatingSubtract(maxTime, timer.ElapsedTime());
				if (!receiver.Wait(timeout))
					break;
			}

			unsigned int recvResult = receiver.GetReceiveResult();
//			assert(recvResult > 0 || receiver.EofReceived());
			m_bufSize += recvResult;
			m_state = NORMAL;
		}

		if (m_bufSize == 0)
		{
			if (receiver.EofReceived())
				break;
		}
		else
		{
			m_putSize = STDMIN((unsigned long)m_bufSize, maxSize - byteCount);
			if (checkDelimiter)
				m_putSize = std::find(m_buf.begin(), m_buf+m_putSize, delimiter) - m_buf;

DoOutput:
			unsigned int result = t->PutModifiable2(m_buf, m_putSize, 0, forever || blockingOutput);
			if (result)
			{
				timeout = SaturatingSubtract(maxTime, timer.ElapsedTime());
				if (t->Wait(timeout))
					goto DoOutput;
				else
				{
					m_state = OUTPUT_BLOCKED;
					return result;
				}
			}
			m_state = NORMAL;

			byteCount += m_putSize;
			m_bufSize -= m_putSize;
			if (m_bufSize > 0)
			{
				memmove(m_buf, m_buf+m_putSize, m_bufSize);
				if (checkDelimiter && m_buf[0] == delimiter)
					break;
			}
		}

		if (byteCount == maxSize)
			break;

		unsigned long elapsed = timer.ElapsedTime();
		if (elapsed > maxTime)
			break;	// once time limit is reached, return even if there is more data waiting

		if (receiver.MustWaitToReceive())
		{
			if (!receiver.Wait(maxTime - elapsed))
				break;
		}

		receiver.Receive(m_buf+m_bufSize, m_buf.size()-m_bufSize);
		m_state = WAITING_FOR_RESULT;
	}

	return 0;
}

// *************************************************************

unsigned int NetworkSink::Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
{
	if (m_blockedBytes)
	{
		assert(length >= m_blockedBytes);
		inString += length - m_blockedBytes;
		length = m_blockedBytes;
	}
	m_buffer.LazyPut(inString, length);

	unsigned int targetSize = messageEnd ? 0 : m_maxBufferSize;
	TimedFlush(blocking ? INFINITE_TIME : 0, m_autoFlush ? 0 : targetSize);

	if (m_buffer.CurrentSize() > targetSize)
	{
		assert(!blocking);
		m_blockedBytes = STDMIN(m_buffer.CurrentSize() - targetSize, (unsigned long)length);
		m_buffer.UndoLazyPut(m_blockedBytes);
		m_buffer.FinalizeLazyPut();
		return STDMAX(m_blockedBytes, 1U);
	}
	m_blockedBytes = 0;

	if (messageEnd)
		AccessSender().SendEof();
	return 0;
}

unsigned int NetworkSink::TimedFlush(unsigned long maxTime, unsigned int targetSize)
{
	if (m_buffer.IsEmpty())
		return 0;

	NetworkSender &sender = AccessSender();

	bool forever = maxTime == INFINITE_TIME;
	Timer timer(Timer::MILLISECONDS, forever);
	unsigned long timeout;
	unsigned int totalFlushSize = 0;

	while (true)
	{
		if (m_needSendResult)
		{
			if (sender.MustWaitForResult())
			{
				timeout = SaturatingSubtract(maxTime, timer.ElapsedTime());
				if (!sender.Wait(timeout))
					break;
			}

			unsigned int sendResult = sender.GetSendResult();
			m_buffer.Skip(sendResult);
			totalFlushSize += sendResult;
			m_needSendResult = false;

			if (m_buffer.CurrentSize() <= targetSize)
				break;
		}

		unsigned long elapsed = timer.ElapsedTime();
		if (elapsed > maxTime)
			break;	// once time limit is reached, return even if there is more data waiting

		if (sender.MustWaitToSend())
		{
			if (!sender.Wait(maxTime - elapsed))
				break;
		}

		unsigned int contiguousSize = 0;
		const byte *block = m_buffer.Spy(contiguousSize);

		sender.Send(block, contiguousSize);
		m_needSendResult = true;
	}

	return totalFlushSize;
}

#endif	// #ifdef HIGHRES_TIMER_AVAILABLE

NAMESPACE_END
