#ifndef CRYPTOPP_HRTIMER_H
#define CRYPTOPP_HRTIMER_H

#include "config.h"

NAMESPACE_BEGIN(CryptoPP)

#ifdef HIGHRES_TIMER_AVAILABLE

//! high resolution timer
class Timer
{
public:
	enum Unit {SECONDS, MILLISECONDS, MICROSECONDS};
	Timer(Unit unit, bool stuckAtZero = false)	: m_timerUnit(unit), m_stuckAtZero(stuckAtZero), m_started(false) {}

	static word64 GetCurrentTimerValue();	// GetCurrentTime is a macro in MSVC 6.0
	static unsigned long ConvertTo(word64 t, Unit unit);

	// this is not the resolution, just a conversion factor into milliseconds
	static inline unsigned int TicksPerMillisecond()
	{
#if defined(CRYPTOPP_WIN32_AVAILABLE)
		return 10000;
#elif defined(CRYPTOPP_UNIX_AVAILABLE) || defined(macintosh)
		return 1000;
#endif
	}

	void StartTimer();
	unsigned long ElapsedTime();

private:
	Unit m_timerUnit;	// HPUX workaround: m_unit is a system macro on HPUX
	bool m_stuckAtZero, m_started;
	word64 m_start;
};

#endif

NAMESPACE_END

#endif
