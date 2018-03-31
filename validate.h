// validate.h - originally written and placed in the public domain by Wei Dai
//              CryptoPP::Test namespace added by JW in February 2017

#ifndef CRYPTOPP_VALIDATE_H
#define CRYPTOPP_VALIDATE_H

#include "cryptlib.h"
#include "integer.h"
#include "misc.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cctype>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

bool ValidateAll(bool thorough);
bool TestSettings();
bool TestOS_RNG();
// bool TestSecRandom();
bool TestRandomPool();
#if !defined(NO_OS_DEPENDENCE)
bool TestAutoSeededX917();
#endif
#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
bool TestRDRAND();
bool TestRDSEED();
bool TestPadlockRNG();
#endif
bool ValidateBaseCode();
bool ValidateEncoder();
bool ValidateCRC32();
bool ValidateCRC32C();
bool ValidateAdler32();
bool ValidateMD2();
bool ValidateMD4();
bool ValidateMD5();
bool ValidateSHA();
bool ValidateSHA2();
bool ValidateTiger();
bool ValidateRIPEMD();
bool ValidatePanama();
bool ValidateWhirlpool();

bool ValidateSM3();
bool ValidateBLAKE2s();
bool ValidateBLAKE2b();
bool ValidatePoly1305();
bool ValidateSipHash();

bool ValidateHMAC();
bool ValidateTTMAC();

bool ValidateCipherModes();
bool ValidatePBKDF();
bool ValidateHKDF();
bool ValidateScrypt();

bool ValidateDES();
bool ValidateIDEA();
bool ValidateSAFER();
bool ValidateRC2();
bool ValidateARC4();

bool ValidateRC5();
bool ValidateBlowfish();
bool ValidateThreeWay();
bool ValidateGOST();
bool ValidateSHARK();
bool ValidateSEAL();
bool ValidateCAST();
bool ValidateSquare();
bool ValidateSKIPJACK();
bool ValidateRC6();
bool ValidateMARS();
bool ValidateRijndael();
bool ValidateTwofish();
bool ValidateSerpent();
bool ValidateSHACAL2();
bool ValidateARIA();
bool ValidateCamellia();
bool ValidateSalsa();
bool ValidateSosemanuk();
bool ValidateVMAC();
bool ValidateCCM();
bool ValidateGCM();
bool ValidateCMAC();

bool ValidateBBS();
bool ValidateDH();
bool ValidateMQV();
bool ValidateHMQV();
bool ValidateFHMQV();
bool ValidateRSA();
bool ValidateElGamal();
bool ValidateDLIES();
bool ValidateNR();
bool ValidateDSA(bool thorough);
bool ValidateLUC();
bool ValidateLUC_DL();
bool ValidateLUC_DH();
bool ValidateXTR_DH();
bool ValidateRabin();
bool ValidateRW();
bool ValidateECP();
bool ValidateEC2N();
bool ValidateECDSA();
bool ValidateECDSA_RFC6979();
bool ValidateECGDSA(bool thorough);
bool ValidateESIGN();

bool ValidateHashDRBG();
bool ValidateHmacDRBG();

bool ValidateNaCl();

// If CRYPTOPP_DEBUG or CRYPTOPP_COVERAGE is in effect, then perform additional tests
#if (defined(CRYPTOPP_DEBUG) || defined(CRYPTOPP_COVERAGE) || defined(CRYPTOPP_VALGRIND)) && !defined(CRYPTOPP_IMPORTS)
# define CRYPTOPP_EXTENDED_VALIDATION 1
#endif

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
// http://github.com/weidai11/cryptopp/issues/92
bool TestSecBlock();
// http://github.com/weidai11/cryptopp/issues/64
bool TestPolynomialMod2();
// http://github.com/weidai11/cryptopp/issues/336
bool TestIntegerBitops();
// http://github.com/weidai11/cryptopp/issues/602
bool TestIntegerOps();
// http://github.com/weidai11/cryptopp/issues/360
bool TestRounding();
// http://github.com/weidai11/cryptopp/issues/242
bool TestHuffmanCodes();
// http://github.com/weidai11/cryptopp/issues/346
bool TestASN1Parse();
// Additional tests due to no coverage
bool TestCompressors();
bool TestEncryptors();
bool TestMersenne();
bool TestSharing();
#endif

#if 1
// Coverity findings in benchmark and validation routines
class StreamState
{
public:
	StreamState(std::ostream& out)
		: m_out(out), m_prec(out.precision()), m_width(out.width()), m_fmt(out.flags()), m_fill(out.fill())
	{
	}

	~StreamState()
	{
		m_out.fill(m_fill);
		m_out.flags(m_fmt);
		m_out.width(m_width);
		m_out.precision(m_prec);
	}

private:
	std::ostream& m_out;
	std::streamsize m_prec;
	std::streamsize m_width;
	std::ios_base::fmtflags m_fmt;
	std::ostream::char_type m_fill;
};
#endif

#if 0
class StreamState
{
public:
	StreamState(std::ostream& out)
		: m_out(out), m_state(NULLPTR)
	{
		m_state.copyfmt(m_out);
	}

	~StreamState()
	{
		m_out.copyfmt(m_state);
	}

private:
	std::ostream& m_out;
	std::ios m_state;
};
#endif

// Safer functions on Windows for C&A, http://github.com/weidai11/cryptopp/issues/55
inline std::string TimeToString(const time_t& t)
{
#if (CRYPTOPP_MSC_VERSION >= 1400)
	tm localTime = {};
	char timeBuf[64];
	errno_t err;

	err = ::localtime_s(&localTime, &t);
	CRYPTOPP_ASSERT(err == 0);
	err = ::asctime_s(timeBuf, sizeof(timeBuf), &localTime);
	CRYPTOPP_ASSERT(err == 0);

	std::string str(timeBuf);
#else
	std::string str(::asctime(::localtime(&t)));
#endif

	// Cleanup whitespace
	std::string::size_type pos = 0;
	while (!str.empty() && std::isspace(*(str.end()-1)))
		{str.erase(str.end()-1);}
	while (!str.empty() && std::string::npos != (pos = str.find("  ", pos)))
		{ str.erase(pos, 1); }

	return str;
}

// Coverity finding
template <class T, bool NON_NEGATIVE>
inline T StringToValue(const std::string& str)
{
	std::istringstream iss(str);

	// Arbitrary, but we need to clear a Coverity finding TAINTED_SCALAR
	if (iss.str().length() > 25)
		throw InvalidArgument(str + "' is too long");

	T value;
	iss >> std::noskipws >> value;

	// Use fail(), not bad()
	if (iss.fail() || !iss.eof())
		throw InvalidArgument(str + "' is not a value");

	if (NON_NEGATIVE && value < 0)
		throw InvalidArgument(str + "' is negative");

	return value;
}

// Coverity finding
template<>
inline int StringToValue<int, true>(const std::string& str)
{
	Integer n(str.c_str());
	long l = n.ConvertToLong();

	int r;
	if (!SafeConvert(l, r))
		throw InvalidArgument(str + "' is not an integer value");

	return r;
}

// Functions that need a RNG; uses AES inf CFB mode with Seed.
CryptoPP::RandomNumberGenerator & GlobalRNG();

bool RunTestDataFile(const char *filename, const CryptoPP::NameValuePairs &overrideParameters=CryptoPP::g_nullNameValuePairs, bool thorough=true);

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP

#endif
