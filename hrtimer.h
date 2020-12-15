// hrtimer.h - originally written and placed in the public domain by Wei Dai

/// \file hrtimer.h
/// \brief Classes for timers

#ifndef CRYPTOPP_HRTIMER_H
#define CRYPTOPP_HRTIMER_H

#include "config.h"

#if !defined(HIGHRES_TIMER_AVAILABLE) || (defined(CRYPTOPP_WIN32_AVAILABLE) && !defined(THREAD_TIMER_AVAILABLE))
#include <time.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifdef HIGHRES_TIMER_AVAILABLE
	typedef word64 TimerWord;
#else
	typedef clock_t TimerWord;
#endif

/// \brief Base class for timers
/// \sa ThreadUserTimer, Timer
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE TimerBase
{
public:
	/// \brief Unit of measure
	enum Unit {SECONDS = 0, MILLISECONDS, MICROSECONDS, NANOSECONDS};

	/// \brief Construct a TimerBase
	/// \param unit the unit of measure
	/// \param stuckAtZero flag
	TimerBase(Unit unit, bool stuckAtZero)
		: m_timerUnit(unit), m_stuckAtZero(stuckAtZero), m_started(false)
		, m_start(0), m_last(0) {}

	/// \brief Retrieve the current timer value
	/// \return the current timer value
	virtual TimerWord GetCurrentTimerValue() =0;

	/// \brief Retrieve ticks per second
	/// \return ticks per second
	/// \details TicksPerSecond() is not the timer resolution. It is a
	///  conversion factor into seconds.
	virtual TimerWord TicksPerSecond() =0;

	/// \brief Start the timer
	/// \return the current timer value
	void StartTimer();

	/// \brief Retrieve the elapsed time
	/// \return the elapsed time as a double
	/// \sa ElapsedTime
	double ElapsedTimeAsDouble();

	/// \brief Retrieve the elapsed time
	/// \return the elapsed time as an unsigned long
	/// \sa ElapsedTimeAsDouble
	unsigned long ElapsedTime();

private:
	double ConvertTo(TimerWord t, Unit unit);

	Unit m_timerUnit;	// HPUX workaround: m_unit is a system macro on HPUX
	bool m_stuckAtZero, m_started;
	TimerWord m_start, m_last;
};

/// \brief Measure CPU time spent executing instructions of this thread
/// \details ThreadUserTimer requires support of the OS. On Unix-based it
///  reports process time. On Windows NT or later desktops and servers it
///  reports thread times with performance counter precision.. On Windows
///  Phone and Windows Store it reports wall clock time with performance
///  counter precision. On all others it reports wall clock time.
/// \note ThreadUserTimer only works correctly on Windows NT or later
///  desktops and servers.
/// \sa Timer
class ThreadUserTimer : public TimerBase
{
public:
	/// \brief Construct a ThreadUserTimer
	/// \param unit the unit of measure
	/// \param stuckAtZero flag
	ThreadUserTimer(Unit unit = TimerBase::SECONDS, bool stuckAtZero = false) : TimerBase(unit, stuckAtZero) {}
	TimerWord GetCurrentTimerValue();
	TimerWord TicksPerSecond();
};

/// \brief High resolution timer
/// \sa ThreadUserTimer
class CRYPTOPP_DLL Timer : public TimerBase
{
public:
	/// \brief Construct a Timer
	/// \param unit the unit of measure
	/// \param stuckAtZero flag
	Timer(Unit unit = TimerBase::SECONDS, bool stuckAtZero = false)	: TimerBase(unit, stuckAtZero) {}
	TimerWord GetCurrentTimerValue();
	TimerWord TicksPerSecond();
};

NAMESPACE_END

#endif
