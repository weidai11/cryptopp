// wait.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "wait.h"
#include "misc.h"

#ifdef SOCKETS_AVAILABLE

#ifdef USE_BERKELEY_STYLE_SOCKETS
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

WaitObjectContainer::WaitObjectContainer()
{
	Clear();
}

void WaitObjectContainer::Clear()
{
#ifdef USE_WINDOWS_STYLE_SOCKETS
	m_handles.clear();
#else
	m_maxFd = 0;
	FD_ZERO(&m_readfds);
	FD_ZERO(&m_writefds);
#endif
	m_noWait = false;
}

#ifdef USE_WINDOWS_STYLE_SOCKETS

void WaitObjectContainer::AddHandle(HANDLE handle)
{
	m_handles.push_back(handle);
}

bool WaitObjectContainer::Wait(unsigned long milliseconds)
{
	if (m_noWait || m_handles.empty())
		return true;

	DWORD result = ::WaitForMultipleObjects(m_handles.size(), &m_handles[0], FALSE, milliseconds);

	if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + m_handles.size())
		return true;
	else if (result == WAIT_TIMEOUT)
		return false;
	else
		throw Err("WaitObjectContainer: WaitForMultipleObjects failed with error " + IntToString(::GetLastError()));
}

#else

void WaitObjectContainer::AddReadFd(int fd)
{
	FD_SET(fd, &m_readfds);
	m_maxFd = STDMAX(m_maxFd, fd);
}

void WaitObjectContainer::AddWriteFd(int fd)
{
	FD_SET(fd, &m_writefds);
	m_maxFd = STDMAX(m_maxFd, fd);
}

bool WaitObjectContainer::Wait(unsigned long milliseconds)
{
	if (m_noWait || m_maxFd == 0)
		return true;

	timeval tv, *timeout;

	if (milliseconds == INFINITE_TIME)
		timeout = NULL;
	else
	{
		tv.tv_sec = milliseconds / 1000;
		tv.tv_usec = (milliseconds % 1000) * 1000;
		timeout = &tv;
	}

	int result = select(m_maxFd+1, &m_readfds, &m_writefds, NULL, timeout);

	if (result > 0)
		return true;
	else if (result == 0)
		return false;
	else
		throw Err("WaitObjectContainer: select failed with error " + errno);
}

#endif

// ********************************************************

bool Waitable::Wait(unsigned long milliseconds)
{
	WaitObjectContainer container;
	GetWaitObjects(container);
	return container.Wait(milliseconds);
}

NAMESPACE_END

#endif
