// hrtimer.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "hrtimer.h"
#include "misc.h"
#include <stddef.h>		// for NULL

#ifdef HIGHRES_TIMER_AVAILABLE

#if defined(CRYPTOPP_WIN32_AVAILABLE)
#include <windows.h>
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
#include <sys/time.h>
#include <sys/times.h>
#include <unistd.h>
#endif

#include <assert.h>

NAMESPACE_BEGIN(CryptoPP)

word64 Timer::GetCurrentTimerValue()
{
#if defined(CRYPTOPP_WIN32_AVAILABLE)
	LARGE_INTEGER now;
	if (!QueryPerformanceCounter(&now))
		throw Exception(Exception::OTHER_ERROR, "Timer: QueryPerformanceCounter failed with error " + IntToString(GetLastError()));
	return now.QuadPart;
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
	timeval now;
	gettimeofday(&now, NULL);
	return (word64)now.tv_sec * 1000000 + now.tv_usec;
#endif
}

word64 Timer::TicksPerSecond()
{
#if defined(CRYPTOPP_WIN32_AVAILABLE)
	static LARGE_INTEGER freq = {0};
	if (freq.QuadPart == 0)
	{
		if (!QueryPerformanceFrequency(&freq))
			throw Exception(Exception::OTHER_ERROR, "Timer: QueryPerformanceFrequency failed with error " + IntToString(GetLastError()));
	}
	return freq.QuadPart;
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
	return 1000000;
#endif
}

word64 ThreadUserTimer::GetCurrentTimerValue()
{
#if defined(CRYPTOPP_WIN32_AVAILABLE)
	static bool getCurrentThreadImplemented = true;
	if (getCurrentThreadImplemented)
	{
		FILETIME now, ignored;
		if (!GetThreadTimes(GetCurrentThread(), &ignored, &ignored, &ignored, &now))
		{
			DWORD lastError = GetLastError();
			if (lastError == ERROR_CALL_NOT_IMPLEMENTED)
			{
				getCurrentThreadImplemented = false;
				goto GetCurrentThreadNotImplemented;
			}
			throw Exception(Exception::OTHER_ERROR, "ThreadUserTimer: GetThreadTimes failed with error " + IntToString(lastError));
		}
		return now.dwLowDateTime + ((word64)now.dwHighDateTime << 32);
	}
GetCurrentThreadNotImplemented:
	return (word64)clock() * (10*1000*1000 / CLOCKS_PER_SEC);
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
	tms now;
	times(&now);
	return now.tms_utime;
#endif
}

word64 ThreadUserTimer::TicksPerSecond()
{
#if defined(CRYPTOPP_WIN32_AVAILABLE)
	return 10*1000*1000;
#elif defined(CRYPTOPP_UNIX_AVAILABLE)
	static const long ticksPerSecond = sysconf(_SC_CLK_TCK);
	return ticksPerSecond;
#endif
}

double TimerBase::ConvertTo(word64 t, Unit unit)
{
	static unsigned long unitsPerSecondTable[] = {1, 1000, 1000*1000, 1000*1000*1000};

	assert(unit < sizeof(unitsPerSecondTable) / sizeof(unitsPerSecondTable[0]));
	return (double)t * unitsPerSecondTable[unit] / TicksPerSecond();
}

void TimerBase::StartTimer()
{
	m_start = GetCurrentTimerValue();
	m_started = true;
}

double TimerBase::ElapsedTimeAsDouble()
{
	if (m_stuckAtZero)
		return 0;
	else if (m_started)
		return ConvertTo(GetCurrentTimerValue() - m_start, m_timerUnit);
	else
	{
		StartTimer();
		return 0;
	}
}

unsigned long TimerBase::ElapsedTime()
{
	double elapsed = ElapsedTimeAsDouble();
	assert(elapsed <= ULONG_MAX);
	return (unsigned long)elapsed;
}

NAMESPACE_END

#endif
