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
	UnkeyedRNG=1,UnkeyedHash=2,UnkeyedOther=4,
	SharedKeyMAC=8,SharedKeyStream=16,SharedKeyBlock=32,SharedKeyOther=64,
	PublicKeyAgreement=128,PublicKeyEncryption=256,PublicKeySignature=512,PublicKeyOther=1024,
	Unkeyed=UnkeyedRNG|UnkeyedHash|UnkeyedOther,
	SharedKey=SharedKeyMAC|SharedKeyStream|SharedKeyBlock|SharedKeyOther,
	PublicKey=PublicKeyAgreement|PublicKeyEncryption|PublicKeySignature|PublicKeyOther,
	All=Unkeyed|SharedKey|PublicKey
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

// Command handler
void BenchmarkWithCommand(int argc, const char* const argv[]);
// Top level, prints preamble and postamble
void Benchmark(Test::TestClass suites, double t, double hertz);
// Unkeyed systems
void Benchmark1(double t, double hertz);
// Shared key systems
void Benchmark2(double t, double hertz);
// Public key systems
void Benchmark3(double t, double hertz);

void OutputResultBytes(const char *name, double length, double timeTaken);
void OutputResultOperations(const char *name, const char *operation, bool pc, unsigned long iterations, double timeTaken);

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP

#endif
