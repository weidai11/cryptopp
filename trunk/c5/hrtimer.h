#ifndef CRYPTOPP_HRTIMER_H
#define CRYPTOPP_HRTIMER_H

#include "config.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
class TimerBase
{
public:
	enum Unit {SECONDS = 0, MILLISECONDS, MICROSECONDS, NANOSECONDS};
	TimerBase(Unit unit, bool stuckAtZero)	: m_timerUnit(unit), m_stuckAtZero(stuckAtZero), m_started(false) {}

	virtual word64 GetCurrentTimerValue() =0;	// GetCurrentTime is a macro in MSVC 6.0
	virtual word64 TicksPerSecond() =0;	// this is not the resolution, just a conversion factor into seconds

	void StartTimer();
	double ElapsedTimeAsDouble();
	unsigned long ElapsedTime();

private:
	double ConvertTo(word64 t, Unit unit);

	Unit m_timerUnit;	// HPUX workaround: m_unit is a system macro on HPUX
	bool m_stuckAtZero, m_started;
	word64 m_start;
};

//! measure CPU time spent executing instructions of this thread (if supported by OS)
/*! /note This only works correctly on Windows NT or later. On Unix it reports process time, and others wall clock time.
*/
class ThreadUserTimer : public TimerBase
{
public:
	ThreadUserTimer(Unit unit = TimerBase::SECONDS, bool stuckAtZero = false)	: TimerBase(unit, stuckAtZero) {}
	word64 GetCurrentTimerValue();
	word64 TicksPerSecond();
};

#ifdef HIGHRES_TIMER_AVAILABLE

//! high resolution timer
class Timer : public TimerBase
{
public:
	Timer(Unit unit = TimerBase::SECONDS, bool stuckAtZero = false)	: TimerBase(unit, stuckAtZero) {}
	word64 GetCurrentTimerValue();
	word64 TicksPerSecond();
};

#endif

NAMESPACE_END

#endif
