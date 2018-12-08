// bench.h - originally written and placed in the public domain by Wei Dai
//           CryptoPP::Test namespace added by JW in February 2017

#ifndef CRYPTOPP_BENCH_H
#define CRYPTOPP_BENCH_H

#include "cryptlib.h"

#include <iostream>
#include <iomanip>
#include <cmath>
#include <ctime>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

// More granular control over benchmarks
enum TestClass {
	UnkeyedRNG=(1<<0),UnkeyedHash=(1<<1),UnkeyedOther=(1<<2),
	SharedKeyMAC=(1<<3),SharedKeyStream=(1<<4),SharedKeyBlock=(1<<5),SharedKeyOther=(1<<6),
	PublicKeyAgreement=(1<<7),PublicKeyEncryption=(1<<8),PublicKeySignature=(1<<9),PublicKeyOther=(1<<10),
	Unkeyed=UnkeyedRNG|UnkeyedHash|UnkeyedOther,
	SharedKey=SharedKeyMAC|SharedKeyStream|SharedKeyBlock|SharedKeyOther,
	PublicKey=PublicKeyAgreement|PublicKeyEncryption|PublicKeySignature|PublicKeyOther,
	All=Unkeyed|SharedKey|PublicKey,
	TestFirst=(0), TestLast=(1<<11)
};

extern const double CLOCK_TICKS_PER_SECOND;
extern double g_allocatedTime;
extern double g_hertz;
extern double g_logTotal;
extern unsigned int g_logCount;
extern const byte defaultKey[];

// Test book keeping
extern time_t g_testBegin;
extern time_t g_testEnd;

// Benchmark command handler
void BenchmarkWithCommand(int argc, const char* const argv[]);
// Top level, prints preamble and postamble
void Benchmark(Test::TestClass suites, double t, double hertz);
// Unkeyed systems
void Benchmark1(double t, double hertz);
// Shared key systems
void Benchmark2(double t, double hertz);
// Public key systems
void Benchmark3(double t, double hertz);

// These are defined in bench1.cpp
extern void OutputResultKeying(double iterations, double timeTaken);
extern void OutputResultBytes(const char *name, const char *provider, double length, double timeTaken);
extern void OutputResultOperations(const char *name, const char *provider, const char *operation, bool pc, unsigned long iterations, double timeTaken);

// These are defined in bench1.cpp
extern void BenchMark(const char *name, BufferedTransformation &bt, double timeTotal);
extern void BenchMark(const char *name, StreamTransformation &cipher, double timeTotal);
extern void BenchMark(const char *name, HashTransformation &ht, double timeTotal);
extern void BenchMark(const char *name, RandomNumberGenerator &rng, double timeTotal);

// These are defined in bench2.cpp
extern void BenchMarkKeying(SimpleKeyingInterface &c, size_t keyLength, const NameValuePairs &params);
extern void BenchMark(const char *name, AuthenticatedSymmetricCipher &cipher, double timeTotal);

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP

#endif
