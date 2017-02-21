// bench.h - originally written and placed in the public domain by Wei Dai
//           CryptoPP::Test namespace added by JW in February 2017

#ifndef CRYPTOPP_BENCH_H
#define CRYPTOPP_BENCH_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

ANONYMOUS_NAMESPACE_BEGIN
#ifdef CLOCKS_PER_SEC
const double CLOCK_TICKS_PER_SECOND = (double)CLOCKS_PER_SEC;
#elif defined(CLK_TCK)
const double CLOCK_TICKS_PER_SECOND = (double)CLK_TCK;
#else
const double CLOCK_TICKS_PER_SECOND = 1000000.0;
#endif

static const byte defaultKey[] = "0123456789" // 168 + NULL
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"00000000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000000";
NAMESPACE_END

void BenchmarkAll(double t, double hertz);
void BenchmarkAll2(double t, double hertz);

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP

#endif
