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

struct WaitingThreadData
{
	bool waitingToWait, terminate;
	HANDLE startWaiting, stopWaiting;
	const HANDLE *waitHandles;
	unsigned int count;
	HANDLE threadHandle;
	DWORD threadId;
	DWORD* error;
};

WaitObjectContainer::~WaitObjectContainer()
{
	if (!m_threads.empty())
	{
		HANDLE threadHandles[MAXIMUM_WAIT_OBJECTS];
		unsigned int i;
		for (i=0; i<m_threads.size(); i++)
		{
			WaitingThreadData &thread = *m_threads[i];
			while (!thread.waitingToWait)	// spin until thread is in the initial "waiting to wait" state
				Sleep(0);
			thread.terminate = true;
			threadHandles[i] = thread.threadHandle;
		}
		PulseEvent(m_startWaiting);
		::WaitForMultipleObjects(m_threads.size(), threadHandles, TRUE, INFINITE);
		for (i=0; i<m_threads.size(); i++)
			CloseHandle(threadHandles[i]);
		CloseHandle(m_startWaiting);
		CloseHandle(m_stopWaiting);
	}
}

void WaitObjectContainer::AddHandle(HANDLE handle)
{
	m_handles.push_back(handle);
}

DWORD WINAPI WaitingThread(LPVOID lParam)
{
	std::auto_ptr<WaitingThreadData> pThread((WaitingThreadData *)lParam);
	WaitingThreadData &thread = *pThread;
	std::vector<HANDLE> handles;

	while (true)
	{
		thread.waitingToWait = true;
		::WaitForSingleObject(thread.startWaiting, INFINITE);
		thread.waitingToWait = false;

		if (thread.terminate)
			return S_OK;
		if (!thread.count)
			continue;

		handles.resize(thread.count + 1);
		handles[0] = thread.stopWaiting;
		std::copy(thread.waitHandles, thread.waitHandles+thread.count, handles.begin()+1);

		DWORD result = ::WaitForMultipleObjects(handles.size(), &handles[0], FALSE, INFINITE);

		if (result == WAIT_OBJECT_0)
			continue;	// another thread finished waiting first, so do nothing
		SetEvent(thread.stopWaiting);
		if (!(result > WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + handles.size()))
		{
			assert(!"error in WaitingThread");	// break here so we can see which thread has an error
			*thread.error = ::GetLastError();
		}
	}
}

void WaitObjectContainer::CreateThreads(unsigned int count)
{
	unsigned int currentCount = m_threads.size();
	if (currentCount == 0)
	{
		m_startWaiting = ::CreateEvent(NULL, TRUE, FALSE, NULL);
		m_stopWaiting = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	}

	if (currentCount < count)
	{
		m_threads.resize(count);
		for (unsigned int i=currentCount; i<count; i++)
		{
			m_threads[i] = new WaitingThreadData;
			WaitingThreadData &thread = *m_threads[i];
			thread.terminate = false;
			thread.startWaiting = m_startWaiting;
			thread.stopWaiting = m_stopWaiting;
			thread.waitingToWait = false;
			thread.threadHandle = CreateThread(NULL, 0, &WaitingThread, &thread, 0, &thread.threadId);
		}
	}
}

bool WaitObjectContainer::Wait(unsigned long milliseconds)
{
	if (m_noWait || m_handles.empty())
		return true;

	if (m_handles.size() > MAXIMUM_WAIT_OBJECTS)
	{
		// too many wait objects for a single WaitForMultipleObjects call, so use multiple threads
		static const unsigned int WAIT_OBJECTS_PER_THREAD = MAXIMUM_WAIT_OBJECTS-1;
		unsigned int nThreads = (m_handles.size() + WAIT_OBJECTS_PER_THREAD - 1) / WAIT_OBJECTS_PER_THREAD;
		if (nThreads > MAXIMUM_WAIT_OBJECTS)	// still too many wait objects, maybe implement recursive threading later?
			throw Err("WaitObjectContainer: number of wait objects exceeds limit");
		CreateThreads(nThreads);
		DWORD error = S_OK;
		
		for (unsigned int i=0; i<m_threads.size(); i++)
		{
			WaitingThreadData &thread = *m_threads[i];
			while (!thread.waitingToWait)	// spin until thread is in the initial "waiting to wait" state
				Sleep(0);
			if (i<nThreads)
			{
				thread.waitHandles = &m_handles[i*WAIT_OBJECTS_PER_THREAD];
				thread.count = STDMIN(WAIT_OBJECTS_PER_THREAD, m_handles.size() - i*WAIT_OBJECTS_PER_THREAD);
				thread.error = &error;
			}
			else
				thread.count = 0;
		}

		ResetEvent(m_stopWaiting);
		PulseEvent(m_startWaiting);

		DWORD result = ::WaitForSingleObject(m_stopWaiting, milliseconds);
		if (result == WAIT_OBJECT_0)
		{
			if (error == S_OK)
				return true;
			else
				throw Err("WaitObjectContainer: WaitForMultipleObjects failed with error " + IntToString(error));
		}
		SetEvent(m_stopWaiting);
		if (result == WAIT_TIMEOUT)
			return false;
		else
			throw Err("WaitObjectContainer: WaitForSingleObject failed with error " + IntToString(::GetLastError()));
	}
	else
	{
		DWORD result = ::WaitForMultipleObjects(m_handles.size(), &m_handles[0], FALSE, milliseconds);
		if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + m_handles.size())
			return true;
		else if (result == WAIT_TIMEOUT)
			return false;
		else
			throw Err("WaitObjectContainer: WaitForMultipleObjects failed with error " + IntToString(::GetLastError()));
	}
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
