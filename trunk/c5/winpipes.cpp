// winpipes.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "winpipes.h"

#ifdef WINDOWS_PIPES_AVAILABLE

#include "wait.h"

NAMESPACE_BEGIN(CryptoPP)

WindowsHandle::WindowsHandle(HANDLE h, bool own)
	: m_h(h), m_own(own)
{
}

WindowsHandle::~WindowsHandle()
{
	if (m_own)
	{
		try
		{
			CloseHandle();
		}
		catch (...)
		{
		}
	}
}

bool WindowsHandle::HandleValid() const
{
	return m_h && m_h != INVALID_HANDLE_VALUE;
}

void WindowsHandle::AttachHandle(HANDLE h, bool own)
{
	if (m_own)
		CloseHandle();

	m_h = h;
	m_own = own;
	HandleChanged();
}

HANDLE WindowsHandle::DetachHandle()
{
	HANDLE h = m_h;
	m_h = INVALID_HANDLE_VALUE;
	HandleChanged();
	return h;
}

void WindowsHandle::CloseHandle()
{
	if (m_h != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(m_h);
		m_h = INVALID_HANDLE_VALUE;
		HandleChanged();
	}
}

// ********************************************************

void WindowsPipe::HandleError(const char *operation) const
{
	DWORD err = GetLastError();
	throw Err(GetHandle(), operation, err);
}

WindowsPipe::Err::Err(HANDLE s, const std::string& operation, int error)
	: OS_Error(IO_ERROR, "WindowsPipe: " + operation + " operation failed with error 0x" + IntToString(error, 16), operation, error)
	, m_h(s)
{
}

// *************************************************************

WindowsPipeReceiver::WindowsPipeReceiver()
	: m_resultPending(false), m_eofReceived(false)
{
	m_event.AttachHandle(CreateEvent(NULL, true, false, NULL), true);
	CheckAndHandleError("CreateEvent", m_event.HandleValid());
	memset(&m_overlapped, 0, sizeof(m_overlapped));
	m_overlapped.hEvent = m_event;
}

bool WindowsPipeReceiver::Receive(byte* buf, unsigned int bufLen)
{
	assert(!m_resultPending && !m_eofReceived);

	HANDLE h = GetHandle();
	// don't queue too much at once, or we might use up non-paged memory
	if (ReadFile(h, buf, STDMIN(bufLen, 128U*1024U), &m_lastResult, &m_overlapped))
	{
		if (m_lastResult == 0)
			m_eofReceived = true;
	}
	else
	{
		switch (GetLastError())
		{
		default:
			CheckAndHandleError("ReadFile", false);
		case ERROR_BROKEN_PIPE:
		case ERROR_HANDLE_EOF:
			m_lastResult = 0;
			m_eofReceived = true;
			break;
		case ERROR_IO_PENDING:
			m_resultPending = true;
		}
	}
	return !m_resultPending;
}

void WindowsPipeReceiver::GetWaitObjects(WaitObjectContainer &container)
{
	if (m_resultPending)
		container.AddHandle(m_event);
	else if (!m_eofReceived)
		container.SetNoWait();
}

unsigned int WindowsPipeReceiver::GetReceiveResult()
{
	if (m_resultPending)
	{
		HANDLE h = GetHandle();
		if (GetOverlappedResult(h, &m_overlapped, &m_lastResult, false))
		{
			if (m_lastResult == 0)
				m_eofReceived = true;
		}
		else
		{
			switch (GetLastError())
			{
			default:
				CheckAndHandleError("GetOverlappedResult", false);
			case ERROR_BROKEN_PIPE:
			case ERROR_HANDLE_EOF:
				m_lastResult = 0;
				m_eofReceived = true;
			}
		}
		m_resultPending = false;
	}
	return m_lastResult;
}

// *************************************************************

WindowsPipeSender::WindowsPipeSender()
	: m_resultPending(false), m_lastResult(0)
{
	m_event.AttachHandle(CreateEvent(NULL, true, false, NULL), true);
	CheckAndHandleError("CreateEvent", m_event.HandleValid());
	memset(&m_overlapped, 0, sizeof(m_overlapped));
	m_overlapped.hEvent = m_event;
}

void WindowsPipeSender::Send(const byte* buf, unsigned int bufLen)
{
	DWORD written = 0;
	HANDLE h = GetHandle();
	// don't queue too much at once, or we might use up non-paged memory
	if (WriteFile(h, buf, STDMIN(bufLen, 128U*1024U), &written, &m_overlapped))
	{
		m_resultPending = false;
		m_lastResult = written;
	}
	else
	{
		if (GetLastError() != ERROR_IO_PENDING)
			CheckAndHandleError("WriteFile", false);

		m_resultPending = true;
	}
}

void WindowsPipeSender::GetWaitObjects(WaitObjectContainer &container)
{
	if (m_resultPending)
		container.AddHandle(m_event);
	else
		container.SetNoWait();
}

unsigned int WindowsPipeSender::GetSendResult()
{
	if (m_resultPending)
	{
		HANDLE h = GetHandle();
		BOOL result = GetOverlappedResult(h, &m_overlapped, &m_lastResult, false);
		CheckAndHandleError("GetOverlappedResult", result);
		m_resultPending = false;
	}
	return m_lastResult;
}

NAMESPACE_END

#endif
