#ifndef CRYPTOPP_HRTIMER_H
#define CRYPTOPP_HRTIMER_H

#include "config.h"

NAMESPACE_BEGIN(CryptoPP)

#ifdef HIGHRES_TIMER_AVAILABLE

//! high resolution timer
class Timer
{
public:
	enum Unit {SECONDS = 0, MILLISECONDS, MICROSECONDS, NANOSECONDS};
	Timer(Unit unit, bool stuckAtZero = false)	: m_timerUnit(unit), m_stuckAtZero(stuckAtZero), m_started(false) {}

	static word64 GetCurrentTimerValue();	// GetCurrentTime is a macro in MSVC 6.0
	static word64 ConvertTo(word64 t, Unit unit);
	// this is not the resolution, just a conversion factor into seconds
	static word64 TicksPerSecond();

	void StartTimer();
	word64 ElapsedTimeInWord64();
	unsigned long ElapsedTime();

private:
	Unit m_timerUnit;	// HPUX workaround: m_unit is a system macro on HPUX
	bool m_stuckAtZero, m_started;
	word64 m_start;
};

#endif

NAMESPACE_END

#endif
