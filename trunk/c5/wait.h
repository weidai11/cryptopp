#ifndef CRYPTOPP_WAIT_H
#define CRYPTOPP_WAIT_H

#include "config.h"

#ifdef SOCKETS_AVAILABLE

#include "cryptlib.h"
#include <vector>

#ifdef USE_WINDOWS_STYLE_SOCKETS
#include <windows.h>
#else
#include <sys/types.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

struct WaitingThreadData;

//! container of wait objects
class WaitObjectContainer
{
public:
	//! exception thrown by WaitObjectContainer
	class Err : public Exception
	{
	public:
		Err(const std::string& s) : Exception(IO_ERROR, s) {}
	};

	static unsigned int MaxWaitObjects();

	WaitObjectContainer();

	void Clear();
	void SetNoWait() {m_noWait = true;}
	bool Wait(unsigned long milliseconds);

#ifdef USE_WINDOWS_STYLE_SOCKETS
	~WaitObjectContainer();
	void AddHandle(HANDLE handle);
#else
	void AddReadFd(int fd);
	void AddWriteFd(int fd);
#endif

private:
#ifdef USE_WINDOWS_STYLE_SOCKETS
	void CreateThreads(unsigned int count);
	std::vector<HANDLE> m_handles;
	std::vector<WaitingThreadData *> m_threads;
	HANDLE m_startWaiting;
	HANDLE m_stopWaiting;
#else
	fd_set m_readfds, m_writefds;
	int m_maxFd;
#endif
	bool m_noWait;
};

NAMESPACE_END

#endif

#endif
