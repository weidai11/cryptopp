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
#elif defined(macintosh)
#include <Timer.h>
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
#elif defined(macintosh)
	UnsignedWide now;
	Microseconds(&now);
	return now.lo + ((word64)now.hi << 32);
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
#elif defined(CRYPTOPP_UNIX_AVAILABLE) || defined(macintosh)
	return 1000000;
#endif
}

word64 Timer::ConvertTo(word64 t, Unit unit)
{
	static unsigned long unitsPerSecondTable[] = {1, 1000, 1000*1000, 1000*1000*1000};

	assert(unit < sizeof(unitsPerSecondTable) / sizeof(unitsPerSecondTable[0]));
	unsigned long unitsPerSecond = unitsPerSecondTable[unit];
	const word64 freq = TicksPerSecond();

	if (freq % unitsPerSecond == 0)
		return t / (freq / unitsPerSecond);
	else
		return word64((double)t * unitsPerSecond / freq);
}

void Timer::StartTimer()
{
	m_start = GetCurrentTimerValue();
	m_started = true;
}

word64 Timer::ElapsedTimeInWord64()
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

unsigned long Timer::ElapsedTime()
{
	word64 elapsed = ElapsedTimeInWord64();
	assert(elapsed <= ULONG_MAX);
	return (unsigned long)elapsed;
}

NAMESPACE_END

#endif
