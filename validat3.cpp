// validat3.cpp - originally written and placed in the public domain by Wei Dai
//                CryptoPP::Test namespace added by JW in February 2017.
//                Source files split in July 2018 to expedite compiles.

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "cpu.h"
#include "validate.h"

#include "rng.h"
#include "drbg.h"
#include "darn.h"
#include "osrng.h"
#include "rdrand.h"
#include "mersenne.h"
#include "padlkrng.h"
#include "randpool.h"

#include "gzip.h"
#include "channels.h"

#include <iostream>
#include <iomanip>
#include <sstream>

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_VER >= 1500)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

bool ValidateAll(bool thorough)
{
	bool pass=TestSettings();
	pass=TestOS_RNG() && pass;
	pass=TestRandomPool() && pass;
#if !defined(NO_OS_DEPENDENCE) && defined(OS_RNG_AVAILABLE)
	pass=TestAutoSeededX917() && pass;
#endif
	// pass=TestSecRandom() && pass;
#if defined(CRYPTOPP_EXTENDED_VALIDATION)
	pass=TestMersenne() && pass;
#endif
#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
	pass=TestPadlockRNG() && pass;
	pass=TestRDRAND() && pass;
	pass=TestRDSEED() && pass;
#endif
#if (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)
	pass=TestDARN() && pass;
#endif
#if defined(CRYPTOPP_EXTENDED_VALIDATION)
	// http://github.com/weidai11/cryptopp/issues/92
	pass=TestSecBlock() && pass;
	// http://github.com/weidai11/cryptopp/issues/602
	pass=TestIntegerOps() && pass;
	// http://github.com/weidai11/cryptopp/issues/336
	pass=TestIntegerBitops() && pass;
	// http://github.com/weidai11/cryptopp/issues/64
	pass=TestPolynomialMod2() && pass;
	// http://github.com/weidai11/cryptopp/issues/360
	pass=TestRounding() && pass;
	// http://github.com/weidai11/cryptopp/issues/242
	pass=TestHuffmanCodes() && pass;
	// http://github.com/weidai11/cryptopp/issues/346
	pass=TestASN1Parse() && pass;
	// https://github.com/weidai11/cryptopp/pull/334
	pass=TestStringSink() && pass;
	// Always part of the self tests; call in Debug
# if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
	pass=TestAltivecOps() && pass;
# endif
	// Always part of the self tests; call in Debug
	pass=ValidateBaseCode() && pass;
	// https://github.com/weidai11/cryptopp/issues/562
	pass=ValidateEncoder() && pass;
	// Additional tests due to no coverage
	pass=TestCompressors() && pass;
	pass=TestSharing() && pass;
	pass=TestEncryptors() && pass;
	pass=TestX25519() && pass;
	pass=TestEd25519() && pass;
#endif

	pass=ValidateCRC32() && pass;
	pass=ValidateCRC32C() && pass;
	pass=ValidateAdler32() && pass;
	pass=ValidateMD2() && pass;
#if defined(CRYPTOPP_EXTENDED_VALIDATION)
	pass=ValidateMD4() && pass;
#endif
	pass=ValidateMD5() && pass;
	pass=ValidateSHA() && pass;

	pass=ValidateKeccak() && pass;
	pass=ValidateSHA3() && pass;
	pass=ValidateSHAKE() && pass;
	pass=ValidateSHAKE_XOF() && pass;

	pass=ValidateHashDRBG() && pass;
	pass=ValidateHmacDRBG() && pass;

	pass=ValidateTiger() && pass;
	pass=ValidateRIPEMD() && pass;
	pass=ValidatePanama() && pass;
	pass=ValidateWhirlpool() && pass;

	pass=ValidateSM3() && pass;
	pass=ValidateBLAKE2s() && pass;
	pass=ValidateBLAKE2b() && pass;
	pass=ValidatePoly1305() && pass;
	pass=ValidateSipHash() && pass;

	pass=ValidateHMAC() && pass;
	pass=ValidateTTMAC() && pass;

	pass=ValidatePBKDF() && pass;
	pass=ValidateHKDF() && pass;
	pass=ValidateScrypt() && pass;

	pass=ValidateDES() && pass;
	pass=ValidateCipherModes() && pass;
	pass=ValidateIDEA() && pass;
	pass=ValidateSAFER() && pass;
	pass=ValidateRC2() && pass;
	pass=ValidateARC4() && pass;
	pass=ValidateRC5() && pass;
	pass=ValidateBlowfish() && pass;
	pass=ValidateThreeWay() && pass;
	pass=ValidateGOST() && pass;
	pass=ValidateSHARK() && pass;
	pass=ValidateCAST() && pass;
	pass=ValidateSquare() && pass;
	pass=ValidateSKIPJACK() && pass;
	pass=ValidateSEAL() && pass;
	pass=ValidateRC6() && pass;
	pass=ValidateMARS() && pass;
	pass=ValidateRijndael() && pass;
	pass=ValidateTwofish() && pass;
	pass=ValidateSerpent() && pass;
	pass=ValidateSHACAL2() && pass;
	pass=ValidateARIA() && pass;
	pass=ValidateCHAM() && pass;
	pass=ValidateHIGHT() && pass;
	pass=ValidateLEA() && pass;
	pass=ValidateSIMECK() && pass;
	pass=ValidateSIMON() && pass;
	pass=ValidateSPECK() && pass;
	pass=ValidateCamellia() && pass;
	pass=ValidateSalsa() && pass;
	pass=ValidateChaCha() && pass;
	pass=ValidateChaChaTLS() && pass;
	pass=ValidateSosemanuk() && pass;
	pass=ValidateRabbit() && pass;
	pass=ValidateHC128() && pass;
	pass=ValidateHC256() && pass;
	pass=RunTestDataFile("TestVectors/seed.txt") && pass;
	pass=RunTestDataFile("TestVectors/threefish.txt") && pass;
	pass=RunTestDataFile("TestVectors/kalyna.txt") && pass;
	pass=RunTestDataFile("TestVectors/sm4.txt") && pass;
	pass=ValidateVMAC() && pass;
	pass=ValidateCCM() && pass;
	pass=ValidateGCM() && pass;
	pass=ValidateCMAC() && pass;
	pass=RunTestDataFile("TestVectors/eax.txt") && pass;

	pass=ValidateBBS() && pass;
	pass=ValidateDH() && pass;
	pass=ValidateX25519() && pass;
	pass=ValidateMQV() && pass;
	pass=ValidateHMQV() && pass;
	pass=ValidateFHMQV() && pass;
	pass=ValidateRSA() && pass;
	pass=ValidateElGamal() && pass;
	pass=ValidateDLIES() && pass;
	pass=ValidateNR() && pass;
	pass=ValidateDSA(thorough) && pass;
	pass=ValidateLUC() && pass;
	pass=ValidateLUC_DH() && pass;
	pass=ValidateLUC_DL() && pass;
	pass=ValidateXTR_DH() && pass;
	pass=ValidateRabin() && pass;
	pass=ValidateRW() && pass;
	pass=ValidateECP() && pass;
	pass=ValidateEC2N() && pass;
	pass=ValidateECDSA() && pass;
	pass=ValidateECDSA_RFC6979() && pass;
	pass=ValidateECGDSA(thorough) && pass;
	pass=ValidateESIGN() && pass;

	pass=ValidateX25519() && pass;
	pass=ValidateEd25519() && pass;
	pass=ValidateNaCl() && pass;

	if (pass)
		std::cout << "\nAll tests passed!\n";
	else
		std::cout << "\nOops!  Not all tests passed.\n";

	return pass;
}

bool TestSettings()
{
	bool pass = true;

	std::cout << "\nTesting Settings...\n\n";

	word32 w;
	const byte s[] = "\x01\x02\x03\x04";

#if (_MSC_VER >= 1500)
	std::copy(s, s+4,
		stdext::make_checked_array_iterator(reinterpret_cast<byte*>(&w), sizeof(w)));
#else
	std::copy(s, s+4, reinterpret_cast<byte*>(&w));
#endif

	if (w == 0x04030201L)
	{
#if (CRYPTOPP_LITTLE_ENDIAN)
		std::cout << "passed:  ";
#else
		std::cout << "FAILED:  ";
		pass = false;
#endif
		std::cout << "Your machine is little endian.\n";
	}
	else if (w == 0x01020304L)
	{
#if (CRYPTOPP_BIG_ENDIAN)
		std::cout << "passed:  ";
#else
		std::cout << "FAILED:  ";
		pass = false;
#endif
		std::cout << "Your machine is big endian.\n";
	}
	else
	{
		std::cout << "FAILED:  Your machine is neither big endian nor little endian.\n";
		pass = false;
	}

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
	// App and library versions, http://github.com/weidai11/cryptopp/issues/371
	const int v1 = LibraryVersion();
	const int v2 = HeaderVersion();
	if(v1/10 == v2/10)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "Library version (library): " << v1 << ", header version (app): " << v2 << "\n";
#endif

	// CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS removed at Issue 682.
	std::cout << "passed:  Aligned data access.\n";

	if (sizeof(byte) == 1)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(byte) == " << sizeof(byte) << "\n";

	if (sizeof(word16) == 2)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(word16) == " << sizeof(word16) << "\n";

	if (sizeof(word32) == 4)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(word32) == " << sizeof(word32) << "\n";

	if (sizeof(word64) == 8)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(word64) == " << sizeof(word64) << "\n";

#ifdef CRYPTOPP_WORD128_AVAILABLE
	if (sizeof(word128) == 16)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(word128) == " << sizeof(word128) << "\n";
#endif

	if (sizeof(word) == 2*sizeof(hword)
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
		&& sizeof(dword) == 2*sizeof(word)
#endif
		)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(hword) == " << sizeof(hword) << ", sizeof(word) == " << sizeof(word);
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
	std::cout << ", sizeof(dword) == " << sizeof(dword);
#endif
	std::cout << "\n";

	const int cacheLineSize = GetCacheLineSize();
	if (cacheLineSize < 16 || cacheLineSize > 256 || !IsPowerOf2(cacheLineSize))
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	else
		std::cout << "passed:  ";
	std::cout << "cacheLineSize == " << cacheLineSize << "\n";

#ifdef CRYPTOPP_CPUID_AVAILABLE
	bool hasSSE2 = HasSSE2();
	bool hasSSSE3 = HasSSSE3();
	bool hasSSE41 = HasSSE41();
	bool hasSSE42 = HasSSE42();
	bool hasAVX = HasAVX();
	bool hasAVX2 = HasAVX2();
	bool hasAESNI = HasAESNI();
	bool hasCLMUL = HasCLMUL();
	bool hasRDRAND = HasRDRAND();
	bool hasRDSEED = HasRDSEED();
	bool hasSHA = HasSHA();
	bool isP4 = IsP4();

	std::cout << "hasSSE2 == " << hasSSE2 << ", hasSSSE3 == " << hasSSSE3;
	std::cout << ", hasSSE4.1 == " << hasSSE41 << ", hasSSE4.2 == " << hasSSE42;
	std::cout << ", hasAVX == " << hasAVX << ", hasAVX2 == " << hasAVX2;
	std::cout << ", hasAESNI == " << hasAESNI << ", hasCLMUL == " << hasCLMUL;
	std::cout << ", hasRDRAND == " << hasRDRAND << ", hasRDSEED == " << hasRDSEED;
	std::cout << ", hasSHA == " << hasSHA << ", isP4 == " << isP4;
	std::cout << "\n";

#elif (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARMV8)

# if defined(__arm__)
	bool hasARMv7 = HasARMv7();
	bool hasNEON = HasNEON();

	std::cout << "passed:  ";
	std::cout << "hasARMv7 == " << hasARMv7 << ", hasNEON == " << hasNEON << "\n";
# else  // __arch32__ and __aarch64__
	bool hasCRC32 = HasCRC32();
	bool hasPMULL = HasPMULL();
	bool hasAES = HasAES();
	bool hasSHA1 = HasSHA1();
	bool hasSHA2 = HasSHA2();
	bool hasSHA512 = HasSHA512();
	bool hasSHA3 = HasSHA3();
	bool hasSM3 = HasSM3();
	bool hasSM4 = HasSM4();

	std::cout << "passed:  ";
	std::cout << ", hasCRC32 == " << hasCRC32 << ", hasAES == " << hasAES;
	std::cout << ", hasPMULL == " << hasPMULL << ", hasSHA1 == " << hasSHA1;
	std::cout << ", hasSHA2 == " << hasSHA2 << ", hasSHA512 == " << hasSHA512;
	std::cout << ", hasSHA3 == " << hasSHA3 << ", hasSM3 == " << hasSM3;
	std::cout << ", hasSM4 == " << hasSM4 << "\n";
# endif

#elif (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)
	const bool hasAltivec = HasAltivec();
	const bool hasPower7 = HasPower7();
	const bool hasPower8 = HasPower8();
	const bool hasPower9 = HasPower9();
	const bool hasPMULL = HasPMULL();
	const bool hasAES = HasAES();
	const bool hasSHA256 = HasSHA256();
	const bool hasSHA512 = HasSHA512();

	std::cout << "passed:  ";
	std::cout << "hasAltivec == " << hasAltivec << ", hasPower7 == " << hasPower7;
	std::cout << ", hasPower8 == " << hasPower8 << ", hasPower9 == " << hasPower9;
	std::cout << ", hasPMULL == " << hasPMULL << ", hasAES == " << hasAES;
	std::cout << ", hasSHA256 == " << hasSHA256 << ", hasSHA512 == " << hasSHA512 << "\n";

#endif

	if (!pass)
	{
		std::cerr << "Some critical setting in config.h is in error.  Please fix it and recompile.\n";
		std::abort();
	}
	return pass;
}

bool Test_RandomNumberGenerator(RandomNumberGenerator& prng, bool drain=false)
{
	bool pass = true, result = true;
	const size_t GENERATE_SIZE = 1024*10, DISCARD_SIZE = 256, ENTROPY_SIZE = 32;

	if(drain)
	{
		RandomNumberSource(prng, UINT_MAX, true, new Redirector(TheBitBucket()));
	}

	MeterFilter meter(new Redirector(TheBitBucket()));
	RandomNumberSource(prng, GENERATE_SIZE, true, new Deflator(new Redirector(meter)));

	if (meter.GetTotalBytes() < GENERATE_SIZE)
	{
		pass = false;
		result = false;
	}

	if (!pass)
		std::cout << "FAILED:";
	else
		std::cout << "passed:";
	std::cout << "  " << GENERATE_SIZE << " generated bytes compressed to ";
	std::cout << meter.GetTotalBytes() << " bytes by DEFLATE\n";

	try
	{
		pass = true;
		if(prng.CanIncorporateEntropy())
		{
			SecByteBlock entropy(ENTROPY_SIZE);
			GlobalRNG().GenerateBlock(entropy, entropy.SizeInBytes());

			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes()-1);
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes()-2);
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes()-3);
		}
	}
	catch (const Exception& /*ex*/)
	{
		pass = false;
		result = false;
	}

	if (!pass)
		std::cout << "FAILED:";
	else
		std::cout << "passed:";
	std::cout << "  IncorporateEntropy with " << 4*ENTROPY_SIZE << " bytes\n";

	try
	{
		word32 val = prng.GenerateWord32();
		val = prng.GenerateWord32((val & 0xff), 0xffffffff - (val & 0xff));

		prng.GenerateBlock(reinterpret_cast<byte*>(&val), 4);
		prng.GenerateBlock(reinterpret_cast<byte*>(&val), 3);
		prng.GenerateBlock(reinterpret_cast<byte*>(&val), 2);
		prng.GenerateBlock(reinterpret_cast<byte*>(&val), 1);
	}
	catch (const Exception&)
	{
		pass = false;
		result = false;
	}

	if (!pass)
		std::cout << "FAILED:";
	else
		std::cout << "passed:";
	std::cout << "  GenerateWord32 and Crop\n";

	try
	{
		pass = true;
		prng.DiscardBytes(DISCARD_SIZE);
		prng.DiscardBytes(DISCARD_SIZE-1);
		prng.DiscardBytes(DISCARD_SIZE-2);
		prng.DiscardBytes(DISCARD_SIZE-3);
	}
	catch (const Exception&)
	{
		pass = false;
		result = false;
	}

	if (!pass)
		std::cout << "FAILED:";
	else
		std::cout << "passed:";
	std::cout << "  DiscardBytes with " << 4*DISCARD_SIZE << " bytes\n";

	// Miscellaneous for code coverage
	(void)prng.AlgorithmName();  // "unknown"

	CRYPTOPP_ASSERT(result);
	return result;
}

bool TestOS_RNG()
{
	bool pass = true;

	member_ptr<RandomNumberGenerator> rng;

#ifdef BLOCKING_RNG_AVAILABLE
	try {rng.reset(new BlockingRng);}
	catch (const OS_RNG_Err &) {}

	if (rng.get())
	{
		std::cout << "\nTesting operating system provided blocking random number generator...\n\n";

		MeterFilter meter(new Redirector(TheBitBucket()));
		RandomNumberSource test(*rng, UINT_MAX, false, new Deflator(new Redirector(meter)));
		unsigned long total=0;
		time_t t = time(NULLPTR), t1 = 0;

		// check that it doesn't take too long to generate a reasonable amount of randomness
		while (total < 16 && (t1 < 10 || total*8 > (unsigned long)t1))
		{
			test.Pump(1);
			total += 1;
			t1 = time(NULLPTR) - t;
		}

		if (total < 16)
		{
			std::cout << "FAILED:";
			pass = false;
		}
		else
			std::cout << "passed:";
		std::cout << "  it took " << long(t1) << " seconds to generate " << total << " bytes" << std::endl;

		test.AttachedTransformation()->MessageEnd();

		if (meter.GetTotalBytes() < total)
		{
			std::cout << "FAILED:";
			pass = false;
		}
		else
			std::cout << "passed:";
		std::cout << "  " << total << " generated bytes compressed to " << meter.GetTotalBytes() << " bytes by DEFLATE\n";

		try
		{
			// Miscellaneous for code coverage
			RandomNumberGenerator& prng = *rng.get();
			(void)prng.AlgorithmName();
			word32 result = prng.GenerateWord32();
			result = prng.GenerateWord32((result & 0xff), 0xffffffff - (result & 0xff));
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 4);
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 3);
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 2);
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 1);
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 0);
			pass = true;
		}
		catch (const Exception&)
		{
			pass = false;
		}

		if (!pass)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  GenerateWord32 and Crop\n";
	}
	else
		std::cout << "\nNo operating system provided blocking random number generator, skipping test." << std::endl;
#endif

#ifdef NONBLOCKING_RNG_AVAILABLE
	try {rng.reset(new NonblockingRng);}
	catch (OS_RNG_Err &) {}

	if (rng.get())
	{
		std::cout << "\nTesting operating system provided nonblocking random number generator...\n\n";

		pass = Test_RandomNumberGenerator(*rng.get()) && pass;
	}
	else
		std::cout << "\nNo operating system provided non-blocking random number generator, skipping test." << std::endl;
#endif

	CRYPTOPP_ASSERT(pass);
	return pass;
}

bool TestRandomPool()
{
	member_ptr<RandomNumberGenerator> prng;
	bool pass=true;

	try {prng.reset(new RandomPool);}
	catch (Exception &) {}

	if(prng.get())
	{
		std::cout << "\nTesting RandomPool generator...\n\n";
		pass = Test_RandomNumberGenerator(*prng.get()) && pass;
	}

#if !defined(NO_OS_DEPENDENCE) && defined(OS_RNG_AVAILABLE)
	try {prng.reset(new AutoSeededRandomPool);}
	catch (Exception &) {}

	if(prng.get())
	{
		std::cout << "\nTesting AutoSeeded RandomPool generator...\n\n";
		pass = Test_RandomNumberGenerator(*prng.get()) && pass;
	}
#endif

	// Old, PGP 2.6 style RandomPool. Added because users were still having problems
	//  with it in 2017. The missing functionality was a barrier to upgrades.
	try {prng.reset(new OldRandomPool);}
	catch (Exception &) {}

	if(prng.get())
	{
		std::cout << "\nTesting OldRandomPool generator...\n\n";
		pass = Test_RandomNumberGenerator(*prng.get()) && pass;

		// https://github.com/weidai11/cryptopp/issues/452
		byte actual[32], expected[32] = {
			0x41,0xD1,0xEF,0x8F,0x10,0x3C,0xE2,0x94,
			0x47,0xC0,0xC3,0x86,0x66,0xBC,0x86,0x09,
			0x57,0x77,0x73,0x91,0x57,0x4D,0x93,0x66,
			0xD1,0x13,0xE1,0xBA,0x07,0x49,0x8F,0x75
		};

		prng.reset(new OldRandomPool);
		RandomNumberGenerator& old = *prng.get();

		SecByteBlock seed(384);
		for (size_t i=0; i<384; ++i)
			seed[i] = static_cast<byte>(i);
		old.IncorporateEntropy(seed, seed.size());

		old.GenerateBlock(actual, sizeof(actual));
		pass = (0 == std::memcmp(actual, expected, sizeof(expected))) && pass;

		if (!pass)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  Expected sequence from PGP-style RandomPool (circa 2007)\n";
	}

	return pass;
}

#if !defined(NO_OS_DEPENDENCE) && defined(OS_RNG_AVAILABLE)
bool TestAutoSeededX917()
{
	// This tests Auto-Seeding and GenerateIntoBufferedTransformation.
	std::cout << "\nTesting AutoSeeded X917 generator...\n\n";

	AutoSeededX917RNG<AES> prng;
	return Test_RandomNumberGenerator(prng);
}
#endif

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
bool TestMersenne()
{
	std::cout << "\nTesting Mersenne Twister...\n\n";

	member_ptr<RandomNumberGenerator> rng;
	bool pass = true;

	try {rng.reset(new MT19937ar);}
	catch (const PadlockRNG_Err &) {}

	if(rng.get())
	{
		pass = Test_RandomNumberGenerator(*rng.get());
	}

	// Reset state
	try {rng.reset(new MT19937ar);}
	catch (const PadlockRNG_Err &) {}

	if(rng.get())
	{
		// First 10; http://create.stephan-brumme.com/mersenne-twister/
		word32 result[10], expected[10] = {
			0xD091BB5C, 0x22AE9EF6, 0xE7E1FAEE, 0xD5C31F79,
			0x2082352C, 0xF807B7DF, 0xE9D30005, 0x3895AFE1,
			0xA1E24BBA, 0x4EE4092B
		};

		rng->GenerateBlock(reinterpret_cast<byte*>(result), sizeof(result));
		pass = (0 == std::memcmp(result, expected, sizeof(expected))) && pass;

		if (!pass)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  Expected sequence from MT19937\n";
	}

	return pass;
}
#endif

#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
bool TestPadlockRNG()
{
	std::cout << "\nTesting Padlock RNG generator...\n\n";

	member_ptr<RandomNumberGenerator> rng;
	bool pass = true, fail;

	try {rng.reset(new PadlockRNG);}
	catch (const PadlockRNG_Err &) {}

	if (rng.get())
	{
		PadlockRNG& padlock = dynamic_cast<PadlockRNG&>(*rng.get());
		pass = Test_RandomNumberGenerator(padlock);

		SecByteBlock zero(16), one(16), t(16);
		std::memset(zero, 0x00, zero.size());
		std::memset( one, 0xff,  one.size());

		// Cryptography Research, Inc tests
		word32 oldDivisor = padlock.SetDivisor(0);
		padlock.GenerateBlock(t, t.size());
		word32 msr = padlock.GetMSR();
		padlock.SetDivisor(oldDivisor);

		// Bit 6 should be set
		fail = !(msr & (1 << 6U));
		pass &= !fail;
		if (fail)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  VIA RNG is activated\n";

		// Bit 13 should be unset
		fail = !!(msr & (1 << 13U));
		pass &= !fail;
		if (fail)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  von Neumann corrector is activated\n";

		// Bit 14 should be unset
		fail = !!(msr & (1 << 14U));
		pass &= !fail;
		if (fail)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  String filter is deactivated\n";

		// Bit 12:10 should be unset
		fail = !!(msr & (0x7 << 10U));
		pass &= !fail;
		if (fail)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  Bias voltage is unmodified\n";

		fail = false;
		if (t == zero || t == one)
			fail = true;

		pass &= !fail;
		if (fail)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  All 0's or all 1's test\n";
	}
	else
		std::cout << "Padlock RNG generator not available, skipping test.\n";

	return pass;
}

bool TestRDRAND()
{
	std::cout << "\nTesting RDRAND generator...\n\n";

	bool pass = true;
	member_ptr<RandomNumberGenerator> rng;

	try {rng.reset(new RDRAND);}
	catch (const RDRAND_Err &) {}

	if (rng.get())
	{
		RDRAND& rdrand = dynamic_cast<RDRAND&>(*rng.get());
		pass = Test_RandomNumberGenerator(rdrand) && pass;

		MaurerRandomnessTest maurer;
		const unsigned int SIZE = 1024*10;
		RandomNumberSource(rdrand, SIZE, true, new Redirector(maurer));

		CRYPTOPP_ASSERT(0 == maurer.BytesNeeded());
		const double mv = maurer.GetTestValue();
		if (mv < 0.98f)
			pass = false;

		std::ostringstream oss;
		oss.flags(std::ios::fixed);
		oss.precision(6);

		if (!pass)
			oss << "FAILED:";
		else
			oss << "passed:";
		oss << "  Maurer Randomness Test returned value " << mv << "\n";
		std::cout << oss.str();
	}
	else
		std::cout << "RDRAND generator not available, skipping test.\n";

	return pass;
}

bool TestRDSEED()
{
	std::cout << "\nTesting RDSEED generator...\n\n";

	bool pass = true;
	member_ptr<RandomNumberGenerator> rng;

	try {rng.reset(new RDSEED);}
	catch (const RDSEED_Err &) {}

	if (rng.get())
	{
		RDSEED& rdseed = dynamic_cast<RDSEED&>(*rng.get());
		pass = Test_RandomNumberGenerator(rdseed) && pass;

		MaurerRandomnessTest maurer;
		const unsigned int SIZE = 1024*10;
		RandomNumberSource(rdseed, SIZE, true, new Redirector(maurer));

		CRYPTOPP_ASSERT(0 == maurer.BytesNeeded());
		const double mv = maurer.GetTestValue();
		if (mv < 0.98f)
			pass = false;

		std::ostringstream oss;
		oss.flags(std::ios::fixed);
		oss.precision(6);

		if (!pass)
			oss << "FAILED:";
		else
			oss << "passed:";
		oss << "  Maurer Randomness Test returned value " << mv << "\n";
		std::cout << oss.str();
	}
	else
		std::cout << "RDSEED generator not available, skipping test.\n";

	return pass;
}
#endif // x86, x32, or x64

#if (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)
bool TestDARN()
{
	std::cout << "\nTesting DARN generator...\n\n";

	bool pass = true;
	member_ptr<RandomNumberGenerator> rng;

	try {rng.reset(new DARN);}
	catch (const DARN_Err &) {}

	if (rng.get())
	{
		DARN& darn = dynamic_cast<DARN&>(*rng.get());
		pass = Test_RandomNumberGenerator(darn) && pass;

		MaurerRandomnessTest maurer;
		const unsigned int SIZE = 1024*10;
		RandomNumberSource(darn, SIZE, true, new Redirector(maurer));

		CRYPTOPP_ASSERT(0 == maurer.BytesNeeded());
		const double mv = maurer.GetTestValue();
		if (mv < 0.98f)
			pass = false;

		std::ostringstream oss;
		oss.flags(std::ios::fixed);
		oss.precision(6);

		if (!pass)
			oss << "FAILED:";
		else
			oss << "passed:";
		oss << "  Maurer Randomness Test returned value " << mv << "\n";
		std::cout << oss.str();
	}
	else
		std::cout << "DARN generator not available, skipping test.\n";

	return pass;
}
#endif  // PPC32 or PPC64

bool ValidateHashDRBG()
{
	std::cout << "\nTesting NIST Hash DRBGs...\n\n";
	bool pass=true, fail;

	// # CAVS 14.3
	// # DRBG800-90A information for "drbg_pr"
	// # Generated on Tue Apr 02 15:32:09 2013

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 0], [AdditionalInputLen = 0], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x16\x10\xb8\x28\xcc\xd2\x7d\xe0\x8c\xee\xa0\x32\xa2\x0e\x92\x08";
		const byte entropy2[] = "\x72\xd2\x8c\x90\x8e\xda\xf9\xa4\xd1\xe5\x26\xd8\xf2\xde\xd5\x44";
		const byte nonce[] = "\x49\x2c\xf1\x70\x92\x42\xf6\xb5";

		Hash_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8);
		drbg.IncorporateEntropy(entropy2, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(result, result.size());
		drbg.GenerateBlock(result, result.size());

		const byte expected[] = "\x56\xF3\x3D\x4F\xDB\xB9\xA5\xB6\x4D\x26\x23\x44\x97\xE9\xDC\xB8\x77\x98\xC6\x8D"
			"\x08\xF7\xC4\x11\x99\xD4\xBD\xDF\x97\xEB\xBF\x6C\xB5\x55\x0E\x5D\x14\x9F\xF4\xD5"
			"\xBD\x0F\x05\xF2\x5A\x69\x88\xC1\x74\x36\x39\x62\x27\x18\x4A\xF8\x4A\x56\x43\x35"
			"\x65\x8E\x2F\x85\x72\xBE\xA3\x33\xEE\xE2\xAB\xFF\x22\xFF\xA6\xDE\x3E\x22\xAC\xA2";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (COUNT=0, E=16, N=8)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 0], [AdditionalInputLen = 0], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x55\x08\x75\xb7\x4e\xc1\x1f\x90\x67\x78\xa3\x1a\x37\xa3\x29\xfd";
		const byte entropy2[] = "\x96\xc6\x39\xec\x14\x9f\x6b\x28\xe2\x79\x3b\xb9\x37\x9e\x60\x67";
		const byte nonce[] = "\x08\xdd\x8c\xd3\x5b\xfa\x00\x94";

		Hash_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8);
		drbg.IncorporateEntropy(entropy2, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(result, result.size());
		drbg.GenerateBlock(result, result.size());

		const byte expected[] = "\xEE\x44\xC6\xCF\x2C\x0C\x73\xA8\xAC\x4C\xA5\x6C\x0E\x71\x2C\xA5\x50\x9A\x19\x5D"
			"\xE4\x5B\x8D\x2B\xC9\x40\xA7\xDB\x66\xC3\xEB\x2A\xA1\xBD\xB4\xDD\x76\x85\x12\x45"
			"\x80\x2E\x68\x05\x4A\xAB\xA8\x7C\xD6\x3A\xD3\xE5\xC9\x7C\x06\xE7\xA3\x9F\xF6\xF9"
			"\x8E\xB3\xD9\x72\xD4\x11\x35\xE5\xE7\x46\x1B\x49\x9C\x56\x45\x6A\xBE\x7F\x77\xD4";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (COUNT=1, E=16, N=8)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 0], [AdditionalInputLen = 128], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\xd9\xba\xb5\xce\xdc\xa9\x6f\x61\x78\xd6\x45\x09\xa0\xdf\xdc\x5e";
		const byte entropy2[] = "\xc6\xba\xd0\x74\xc5\x90\x67\x86\xf5\xe1\xf3\x20\x99\xf5\xb4\x91";
		const byte nonce[] = "\xda\xd8\x98\x94\x14\x45\x0e\x01";
		const byte additional1[] = "\x3e\x6b\xf4\x6f\x4d\xaa\x38\x25\xd7\x19\x4e\x69\x4e\x77\x52\xf7";
		const byte additional2[] = "\x04\xfa\x28\x95\xaa\x5a\x6f\x8c\x57\x43\x34\x3b\x80\x5e\x5e\xa4";
		const byte additional3[] = "\xdf\x5d\xc4\x59\xdf\xf0\x2a\xa2\xf0\x52\xd7\x21\xec\x60\x72\x30";

		Hash_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8);
		drbg.IncorporateEntropy(entropy2, 16, additional1, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(additional2, 16, result, result.size());
		drbg.GenerateBlock(additional3, 16, result, result.size());

		const byte expected[] = "\xC4\x8B\x89\xF9\xDA\x3F\x74\x82\x45\x55\x5D\x5D\x03\x3B\x69\x3D\xD7\x1A\x4D\xF5"
			"\x69\x02\x05\xCE\xFC\xD7\x20\x11\x3C\xC2\x4E\x09\x89\x36\xFF\x5E\x77\xB5\x41\x53"
			"\x58\x70\xB3\x39\x46\x8C\xDD\x8D\x6F\xAF\x8C\x56\x16\x3A\x70\x0A\x75\xB2\x3E\x59"
			"\x9B\x5A\xEC\xF1\x6F\x3B\xAF\x6D\x5F\x24\x19\x97\x1F\x24\xF4\x46\x72\x0F\xEA\xBE";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=0, E=16, N=8, A=16)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 0], [AdditionalInputLen = 128], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x28\x00\x0f\xbf\xf0\x57\x22\xc8\x89\x93\x06\xc2\x9b\x50\x78\x0a";
		const byte entropy2[] = "\xd9\x95\x8e\x8c\x08\xaf\x5a\x41\x0e\x91\x9b\xdf\x40\x8e\x5a\x0a";
		const byte nonce[] = "\x11\x2f\x6e\x20\xc0\x29\xed\x3f";
		const byte additional1[] = "\x91\x1d\x96\x5b\x6e\x77\xa9\x6c\xfe\x3f\xf2\xd2\xe3\x0e\x2a\x86";
		const byte additional2[] = "\xcd\x44\xd9\x96\xab\x05\xef\xe8\x27\xd3\x65\x83\xf1\x43\x18\x2c";
		const byte additional3[] = "\x9f\x6a\x31\x82\x12\x18\x4e\x70\xaf\x5d\x00\x14\x1f\x42\x82\xf6";

		Hash_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8);
		drbg.IncorporateEntropy(entropy2, 16, additional1, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(additional2, 16, result, result.size());
		drbg.GenerateBlock(additional3, 16, result, result.size());

		const byte expected[] = "\x54\x61\x65\x92\x1E\x71\x4A\xD1\x39\x02\x2F\x97\xD2\x65\x3F\x0D\x47\x69\xB1\x4A"
			"\x3E\x6E\xEF\xA1\xA0\x16\xD6\x9E\xA9\x7F\x51\xD5\x81\xDC\xAA\xCF\x66\xF9\xB1\xE8"
			"\x06\x94\x41\xD6\xB5\xC5\x44\x60\x54\x07\xE8\xE7\xDC\x1C\xD8\xE4\x70\xAD\x84\x77"
			"\x5A\x65\x31\xBE\xE0\xFC\x81\x36\xE2\x8F\x0B\xFE\xEB\xE1\x98\x62\x7E\x98\xE0\xC1";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=1, E=16, N=8, A=16)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 128], [AdditionalInputLen = 0], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x0e\xd5\x4c\xef\x44\x5c\x61\x7d\x58\x86\xe0\x34\xc0\x97\x36\xd4";
		const byte entropy2[] = "\x0b\x90\x27\xb8\x01\xe7\xf7\x2e\xe6\xec\x50\x2b\x8b\x6b\xd7\x11";
		const byte nonce[] = "\x2c\x8b\x07\x13\x55\x6c\x91\x6f";
		const byte personalization[] = "\xf3\x37\x8e\xa1\x45\x34\x30\x41\x12\xe0\xee\x57\xe9\xb3\x4a\x4b";

		Hash_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8, personalization, 16);
		drbg.IncorporateEntropy(entropy2, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(result, result.size());
		drbg.GenerateBlock(result, result.size());

		const byte expected[] = "\x55\x37\x0E\xD4\xB7\xCA\xA4\xBB\x67\x3A\x0F\x58\x40\xB3\x9F\x76\x4E\xDA\xD2\x85"
			"\xD5\x6F\x01\x8F\x2D\xA7\x54\x4B\x0E\x66\x39\x62\x35\x96\x1D\xB7\xF6\xDA\xFB\x30"
			"\xB6\xC5\x68\xD8\x40\x6E\x2B\xD4\x3D\x23\xEB\x0F\x10\xBA\x5F\x24\x9C\xC9\xE9\x4A"
			"\xD3\xA5\xF1\xDF\xA4\xF2\xB4\x80\x40\x91\xED\x8C\xD6\x6D\xE7\xB7\x53\xB2\x09\xD5";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=0, E=16, N=8, A=0, P=16)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 128], [AdditionalInputLen = 0], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x8f\x2a\x33\x9f\x5f\x45\x21\x30\xa4\x57\xa9\x6f\xcb\xe2\xe6\x36";
		const byte entropy2[] = "\x1f\xff\x9e\x4f\x4d\x66\x3a\x1f\x9e\x85\x4a\x15\x7d\xad\x97\xe0";
		const byte nonce[] = "\x0e\xd0\xe9\xa5\xa4\x54\x8a\xd0";
		const byte personalization[] = "\x45\xe4\xb3\xe2\x63\x87\x62\x57\x2c\x99\xe4\x03\x45\xd6\x32\x6f";

		Hash_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8, personalization, 16);
		drbg.IncorporateEntropy(entropy2, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(result, result.size());
		drbg.GenerateBlock(result, result.size());

		const byte expected[] = "\x4F\xE8\x96\x41\xF8\xD3\x95\xC4\x43\x6E\xFB\xF8\x05\x75\xA7\x69\x74\x6E\x0C\x5F"
			"\x54\x14\x35\xB4\xE6\xA6\xB3\x40\x7C\xA2\xC4\x42\xA2\x2F\x66\x28\x28\xCF\x4A\xA8"
			"\xDC\x16\xBC\x5F\x69\xE5\xBB\x05\xD1\x43\x8F\x80\xAB\xC5\x8F\x9C\x3F\x75\x57\xEB"
			"\x44\x0D\xF5\x0C\xF4\x95\x23\x94\x67\x11\x55\x98\x14\x43\xFF\x13\x14\x85\x5A\xBC";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=1, E=16, N=8, A=0, P=16)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 128], [AdditionalInputLen = 16], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x48\xa1\xa9\x7c\xcc\x49\xd7\xcc\xf6\xe3\x78\xa2\xf1\x6b\x0f\xcd";
		const byte entropy2[] = "\xba\x5d\xa6\x79\x12\x37\x24\x3f\xea\x60\x50\xf5\xb9\x9e\xcd\xf5";
		const byte nonce[] = "\xb0\x91\xd2\xec\x12\xa8\x39\xfe";
		const byte personalization[] = "\x3d\xc1\x6c\x1a\xdd\x9c\xac\x4e\xbb\xb0\xb8\x89\xe4\x3b\x9e\x12";
		const byte additional1[] = "\xd1\x23\xe3\x8e\x4c\x97\xe8\x29\x94\xa9\x71\x7a\xc6\xf1\x7c\x08";
		const byte additional2[] = "\x80\x0b\xed\x97\x29\xcf\xad\xe6\x68\x0d\xfe\x53\xba\x0c\x1e\x28";
		const byte additional3[] = "\x25\x1e\x66\xb9\xe3\x85\xac\x1c\x17\xfb\x77\x1b\x5d\xc7\x6c\xf2";

		Hash_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8, personalization, 16);
		drbg.IncorporateEntropy(entropy2, 16, additional1, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(additional2, 16, result, result.size());
		drbg.GenerateBlock(additional3, 16, result, result.size());

		const byte expected[] = "\xA1\xB2\xEE\x86\xA0\xF1\xDA\xB7\x93\x83\x13\x3A\x62\x27\x99\x08\x95\x3A\x1C\x9A"
			"\x98\x77\x60\x12\x11\x19\xCC\x78\xB8\x51\x2B\xD5\x37\xA1\x9D\xB9\x73\xCA\x39\x7A"
			"\xDD\x92\x33\x78\x6D\x5D\x41\xFF\xFA\xE9\x80\x59\x04\x85\x21\xE2\x52\x84\xBC\x6F"
			"\xDB\x97\xF3\x4E\x6A\x12\x7A\xCD\x41\x0F\x50\x68\x28\x46\xBE\x56\x9E\x9A\x6B\xC8";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=0, E=16, N=8, A=16, P=16)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 128], [AdditionalInputLen = 16], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x3b\xcb\xa8\x3b\x6d\xfb\x06\x79\x80\xef\xc3\x1e\xd2\x9e\x68\x57";
		const byte entropy2[] = "\x2f\xc9\x87\x49\x19\xcb\x52\x4a\x5b\xac\xf0\xcd\x96\x4e\xf8\x6e";
		const byte nonce[] = "\x23\xfe\x20\x9f\xac\x70\x45\xde";
		const byte personalization[] = "\xf2\x25\xf4\xd9\x6b\x9c\xab\x49\x1e\xab\x18\x14\xb2\x5e\x78\xef";
		const byte additional1[] = "\x57\x5b\x9a\x11\x32\x7a\xab\x89\x08\xfe\x46\x11\x9a\xed\x14\x5d";
		const byte additional2[] = "\x5d\x19\xcd\xed\xb7\xe3\x44\x66\x8e\x11\x42\x96\xa0\x38\xb1\x7f";
		const byte additional3[] = "\x2b\xaf\xa0\x15\xed\xdd\x5c\x76\x32\x75\x34\x35\xd1\x37\x72\xfb";

		Hash_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8, personalization, 16);
		drbg.IncorporateEntropy(entropy2, 16, additional1, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(additional2, 16, result, result.size());
		drbg.GenerateBlock(additional3, 16, result, result.size());

		const byte expected[] = "\x1D\x12\xEB\x6D\x42\x60\xBD\xFB\xA7\x99\xB8\x53\xCC\x6F\x19\xB1\x64\xFE\x2F\x55"
			"\xBA\xA2\x1C\x89\xD4\xD0\xE9\xB4\xBA\xD4\xE5\xF8\xC5\x30\x06\x41\xBA\xC4\x3D\x2B"
			"\x73\x91\x27\xE9\x31\xC0\x55\x55\x11\xE8\xB6\x57\x02\x0D\xCE\x90\xAC\x31\xB9\x00"
			"\x31\xC1\xD4\x4F\xE7\x12\x3B\xCC\x85\x16\x2F\x12\x8F\xB2\xDF\x84\x4E\xF7\x06\xBE";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=1, E=16, N=8, A=16, P=16)\n";
	}

	{
		// [SHA-256], [PredictionResistance = False], [EntropyInputLen = 256], [NonceLen = 128]
		// [PersonalizationStringLen = 256], [AdditionalInputLen = 256], [ReturnedBitsLen = 1024]
		const byte entropy1[] = "\xf0\x5b\xab\x56\xc7\xac\x6e\xeb\x31\xa0\xcf\x8a\x8a\x06\x2a\x49\x17\x9a\xcf\x3c\x5b\x20\x4d\x60\xdd\x7a\x3e\xb7\x8f\x5d\x8e\x3b";
		const byte entropy2[] = "\x72\xd4\x02\xa2\x59\x7b\x98\xa3\xb8\xf5\x0b\x71\x6c\x63\xc6\xdb\xa7\x3a\x07\xe6\x54\x89\x06\x3f\x02\xc5\x32\xf5\xda\xc4\xd4\x18";
		const byte nonce[] = "\xa1\x45\x08\x53\x41\x68\xb6\x88\xf0\x5f\x1e\x41\x9c\x88\xcc\x30";
		const byte personalization[] = "\xa0\x34\x72\xf4\x04\x59\xe2\x87\xea\xcb\x21\x32\xc0\xb6\x54\x02\x7d\xa3\xe6\x69\x25\xb4\x21\x25\x54\xc4\x48\x18\x8c\x0e\x86\x01";
		const byte additional1[] = "\xb3\x0d\x28\xaf\xa4\x11\x6b\xbc\x13\x6e\x65\x09\xb5\x82\xa6\x93\xbc\x91\x71\x40\x46\xaa\x3c\x66\xb6\x77\xb3\xef\xf9\xad\xfd\x49";
		const byte additional2[] = "\x77\xfd\x1d\x68\xd6\xa4\xdd\xd5\xf3\x27\x25\x2d\x3f\x6b\xdf\xee\x8c\x35\xce\xd3\x83\xbe\xaf\xc9\x32\x77\xef\xf2\x1b\x6f\xf4\x1b";
		const byte additional3[] = "\x59\xa0\x1f\xf8\x6a\x58\x72\x1e\x85\xd2\xf8\x3f\x73\x99\xf1\x96\x4e\x27\xf8\x7f\xcd\x1b\xf5\xc1\xeb\xf3\x37\x10\x9b\x13\xbd\x24";

		Hash_DRBG<SHA256, 128/8, 440/8> drbg(entropy1, 32, nonce, 16, personalization, 32);
		drbg.IncorporateEntropy(entropy2, 32, additional1, 32);

		SecByteBlock result(128);
		drbg.GenerateBlock(additional2, 32, result, result.size());
		drbg.GenerateBlock(additional3, 32, result, result.size());

		const byte expected[] = "\xFF\x27\x96\x38\x5C\x32\xBF\x84\x3D\xFA\xBB\xF0\x3E\x70\x5A\x39\xCB\xA3\x4C\xF1"
			"\x4F\xAE\xC3\x05\x63\xDF\x5A\xDD\xBD\x2D\x35\x83\xF5\x7E\x05\xF9\x40\x30\x56\x18"
			"\xF2\x00\x88\x14\x03\xC2\xD9\x81\x36\x39\xE6\x67\x55\xDC\xFC\x4E\x88\xEA\x71\xDD"
			"\xB2\x25\x2E\x09\x91\x49\x40\xEB\xE2\x3D\x63\x44\xA0\xF4\xDB\x5E\xE8\x39\xE6\x70"
			"\xEC\x47\x24\x3F\xA0\xFC\xF5\x13\x61\xCE\x53\x98\xAA\xBF\xB4\x19\x1B\xFE\xD5\x00"
			"\xE1\x03\x3A\x76\x54\xFF\xD7\x24\x70\x5E\x8C\xB2\x41\x7D\x92\x0A\x2F\x4F\x27\xB8"
			"\x45\x13\x7F\xFB\x87\x90\xA9\x49";

		fail = !!memcmp(result, expected, 1024/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA256/128/440 (C0UNT=0, E=32, N=16, A=32, P=32)\n";
	}

	{
		// [SHA-256], [PredictionResistance = False], [EntropyInputLen = 256], [NonceLen = 128]
		// [PersonalizationStringLen = 256], [AdditionalInputLen = 256], [ReturnedBitsLen = 1024]
		const byte entropy1[] = "\xfe\x61\x50\x79\xf1\xad\x2a\x71\xea\x7f\x0f\x5a\x14\x34\xee\xc8\x46\x35\x54\x4a\x95\x6a\x4f\xbd\x64\xff\xba\xf6\x1d\x34\x61\x83";
		const byte entropy2[] = "\x18\x89\x7b\xd8\x3e\xff\x38\xab\xb5\x6e\x82\xa8\x1b\x8c\x5e\x59\x3c\x3d\x85\x62\x2a\xe2\x88\xe5\xb2\xc6\xc5\xd2\xad\x7d\xc9\x45";
		const byte nonce[] = "\x9d\xa7\x87\x56\xb7\x49\x17\x02\x4c\xd2\x00\x65\x11\x9b\xe8\x7e";
		const byte personalization[] = "\x77\x5d\xbf\x32\xf3\x5c\xf3\x51\xf4\xb8\x1c\xd3\xfa\x7f\x65\x0b\xcf\x31\x88\xa1\x25\x57\x0c\xdd\xac\xaa\xfe\xa1\x7b\x3b\x29\xbc";
		const byte additional1[] = "\xef\x96\xc7\x9c\xb1\x73\x1d\x82\x85\x0a\x6b\xca\x9b\x5c\x34\x39\xba\xd3\x4e\x4d\x82\x6f\x35\x9f\x61\x5c\xf6\xf2\xa3\x3e\x91\x05";
		const byte additional2[] = "\xaf\x25\xc4\x6e\x21\xfc\xc3\xaf\x1f\xbb\xf8\x76\xb4\x57\xab\x1a\x94\x0a\x85\x16\x47\x81\xa4\xab\xda\xc8\xab\xca\xd0\x84\xda\xae";
		const byte additional3[] = "\x59\x5b\x44\x94\x38\x86\x36\xff\x8e\x45\x1a\x0c\x42\xc8\xcc\x21\x06\x38\x3a\xc5\xa6\x30\x96\xb9\x14\x81\xb3\xa1\x2b\xc8\xcd\xf6";

		Hash_DRBG<SHA256, 128/8, 440/8> drbg(entropy1, 32, nonce, 16, personalization, 32);
		drbg.IncorporateEntropy(entropy2, 32, additional1, 32);

		SecByteBlock result(128);
		drbg.GenerateBlock(additional2, 32, result, result.size());
		drbg.GenerateBlock(additional3, 32, result, result.size());

		const byte expected[] = "\x8B\x1C\x9C\x76\xC4\x9B\x3B\xAE\xFD\x6E\xEB\x6C\xFF\xA3\xA1\x03\x3A\x8C\xAF\x09"
			"\xFE\xBD\x44\x00\xFC\x0F\xD3\xA8\x26\x9C\xEE\x01\xAC\xE3\x73\x0E\xBE\xDA\x9A\xC6"
			"\x23\x44\x6D\xA1\x56\x94\x29\xEC\x4B\xCD\x01\x84\x32\x25\xEF\x00\x91\x0B\xCC\xF3"
			"\x06\x3B\x80\xF5\x46\xAC\xD2\xED\x5F\x70\x2B\x56\x2F\x21\x0A\xE9\x80\x87\x38\xAD"
			"\xB0\x2A\xEB\x27\xF2\xD9\x20\x2A\x66\x0E\xF5\xC9\x20\x4A\xB4\x3C\xCE\xD6\x24\x97"
			"\xDB\xB1\xED\x94\x12\x6A\x2F\x03\x98\x4A\xD4\xD1\x72\xF3\x7A\x66\x74\x7E\x2A\x5B"
			"\xDE\xEF\x43\xBC\xB9\x8C\x49\x01";

		fail = !!memcmp(result, expected, 1024/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA256/128/440 (C0UNT=1, E=32, N=16, A=32, P=32)\n";
	}

	{
		// [SHA-512], [PredictionResistance = False], [EntropyInputLen = 256], [NonceLen = 128]
		// [PersonalizationStringLen = 256], [AdditionalInputLen = 256], [ReturnedBitsLen = 2048]
		const byte entropy1[] = "\x55\x4e\x8f\xfd\xc4\x9a\xd8\xf9\x9a\xe5\xd5\xf8\x1a\xf5\xda\xfb\x7f\x75\x53\xd7\xcb\x56\x8e\xa7\x3c\xc0\x82\xdd\x80\x76\x25\xc0";
		const byte entropy2[] = "\x78\x07\x3e\x86\x79\x4b\x10\x95\x88\xf4\x22\xf9\xbd\x04\x7e\xc0\xce\xab\xd6\x78\x6b\xdf\xe2\x89\xb3\x16\x43\x9c\x32\x2d\xb2\x59";
		const byte nonce[] = "\xf0\x89\x78\xde\x2d\xc2\xcd\xd9\xc0\xfd\x3d\x84\xd9\x8b\x8e\x8e";
		const byte personalization[] = "\x3e\x52\x7a\xb5\x81\x2b\x0c\x0e\x98\x2a\x95\x78\x93\x98\xd9\xeb\xf1\xb9\xeb\xd6\x1d\x02\x05\xed\x42\x21\x2d\x24\xb8\x37\xf8\x41";
		const byte additional1[] = "\xf2\x6b\xb1\xef\x30\xca\x8f\x97\xc0\x19\xd0\x79\xe5\xc6\x5e\xae\xd1\xa3\x9a\x52\xaf\x12\xe8\x28\xde\x03\x70\x79\x9a\x70\x11\x8b";
		const byte additional2[] = "\xb0\x9d\xb5\xa8\x45\xec\x79\x7a\x4b\x60\x7e\xe4\xd5\x58\x56\x70\x35\x20\x9b\xd8\xe5\x01\x6c\x78\xff\x1f\x6b\x93\xbf\x7c\x34\xca";
		const byte additional3[] = "\x45\x92\x2f\xb3\x5a\xd0\x6a\x84\x5f\xc9\xca\x16\x4a\x42\xbb\x59\x84\xb4\x38\x57\xa9\x16\x23\x48\xf0\x2f\x51\x61\x24\x35\xb8\x62";

		Hash_DRBG<SHA512, 256/8, 888/8> drbg(entropy1, 32, nonce, 16, personalization, 32);
		drbg.IncorporateEntropy(entropy2, 32, additional1, 32);

		SecByteBlock result(256);
		drbg.GenerateBlock(additional2, 32, result, result.size());
		drbg.GenerateBlock(additional3, 32, result, result.size());

		const byte expected[] = "\x1F\x20\x83\x9E\x22\x55\x3B\x1E\x6C\xD4\xF6\x3A\x47\xC3\x99\x54\x0F\x69\xA3\xBB"
			"\x37\x47\xA0\x2A\x12\xAC\xC7\x00\x85\xC5\xCC\xF4\x7B\x12\x5A\x4A\xEA\xED\x2F\xE5"
			"\x31\x51\x0D\xC1\x8E\x50\x29\xE2\xA6\xCB\x8F\x34\xBA\xDA\x8B\x47\x32\x33\x81\xF1"
			"\x2D\xF6\x8B\x73\x8C\xFF\x15\xC8\x8E\x8C\x31\x48\xFA\xC3\xC4\x9F\x52\x81\x23\xC2"
			"\x2A\x83\xBD\xF1\x44\xEF\x15\x49\x93\x44\x83\x6B\x37\x5D\xBB\xFF\x72\xD2\x86\x96"
			"\x62\xF8\x4D\x12\x3B\x16\xCB\xAC\xA1\x00\x12\x1F\x94\xA8\xD5\xAE\x9A\x9E\xDA\xC8"
			"\xD7\x6D\x59\x33\xFD\x55\xC9\xCC\x5B\xAD\x39\x73\xB5\x13\x8B\x96\xDF\xDB\xF5\x90"
			"\x81\xDF\x68\x6A\x30\x72\x42\xF2\x74\xAE\x7F\x1F\x7F\xFE\x8B\x3D\x49\x38\x98\x34"
			"\x7C\x63\x46\x6E\xAF\xFA\xCB\x06\x06\x08\xE6\xC8\x35\x3C\x68\xB8\xCC\x9D\x5C\xDF"
			"\xDB\xC0\x41\x44\x48\xE6\x11\xD4\x78\x50\x81\x91\xED\x1D\x75\xF3\xBD\x79\xFF\x1E"
			"\x37\xAF\xC6\x5D\x49\xD6\x5C\xAC\x5B\xCB\xD6\x91\x37\x51\xFA\x98\x70\xFC\x32\xB3"
			"\xF2\x86\xE4\xED\x74\xF2\x5D\x8B\x6C\x4D\xB8\xDE\xD8\x4A\xD6\x5E\xD6\x6D\xAE\xB1"
			"\x1B\xA2\x94\x52\x54\xAD\x3C\x3D\x25\xBD\x12\x46\x3C\xA0\x45\x9D";

		fail = !!memcmp(result, expected, 2048/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA512/256/888 (C0UNT=0, E=32, N=16, A=32, P=32)\n";
	}

	{
		// [SHA-512], [PredictionResistance = False], [EntropyInputLen = 256], [NonceLen = 128]
		// [PersonalizationStringLen = 256], [AdditionalInputLen = 256], [ReturnedBitsLen = 2048]
		const byte entropy1[] = "\x0c\x9f\xcd\x06\x21\x3c\xb2\xf6\x3c\xdf\x79\x76\x4b\x46\x74\xfc\xdf\x68\xb0\xff\xae\xc7\x21\x8a\xa2\xaf\x4e\x4c\xb9\xe6\x60\x78";
		const byte entropy2[] = "\x75\xb8\x49\x54\xdf\x30\x10\x16\x2c\x06\x8c\x12\xeb\x6c\x1d\x03\x64\x5c\xad\x10\x5c\xc3\x17\x69\xb2\x5a\xc1\x7c\xb8\x33\x5b\x45";
		const byte nonce[] = "\x43\x1c\x4d\x65\x93\x96\xad\xdc\xc1\x6d\x17\x9f\x7f\x57\x24\x4d";
		const byte personalization[] = "\x7e\x54\xbd\x87\xd2\x0a\x95\xd7\xc4\x0c\x3b\x1b\x32\x15\x26\xd2\x06\x67\xa4\xac\xc1\xaa\xfb\x55\x91\x68\x2c\xb5\xc9\xcd\x66\x05";
		const byte additional1[] = "\xd5\x74\x9e\x56\xfb\x5f\xf3\xf8\x2c\x73\x2b\x7a\x83\xe0\xde\x06\x85\x0b\xf0\x57\x50\xc8\x55\x60\x4a\x41\x4f\x86\xb1\x68\x14\x03";
		const byte additional2[] = "\x9a\x83\xbb\x06\xdf\x4d\x53\x89\xf5\x3f\x24\xff\xf7\xcd\x0c\xcf\x4f\xbe\x46\x79\x8e\xce\x82\xa8\xc4\x6b\x5f\x8e\x58\x32\x62\x23";
		const byte additional3[] = "\x48\x13\xc4\x95\x10\x99\xdd\x7f\xd4\x77\x3c\x9b\x8a\xa4\x1c\x3d\xb0\x93\x92\x50\xba\x23\x98\xef\x4b\x1b\xd2\x53\xc1\x61\xda\xc6";

		Hash_DRBG<SHA512, 256/8, 888/8> drbg(entropy1, 32, nonce, 16, personalization, 32);
		drbg.IncorporateEntropy(entropy2, 32, additional1, 32);

		SecByteBlock result(256);
		drbg.GenerateBlock(additional2, 32, result, result.size());
		drbg.GenerateBlock(additional3, 32, result, result.size());

		const byte expected[] = "\xE1\x7E\x4B\xEE\xD1\x65\x4F\xB2\xFC\xC8\xE8\xD7\xC6\x72\x7D\xD2\xE3\x15\x73\xC0"
			"\x23\xC8\x55\x5D\x2B\xD8\x28\xD8\x31\xE4\xC9\x87\x42\x51\x87\x66\x43\x1F\x2C\xA4"
			"\x73\xED\x4E\x50\x12\xC4\x50\x0E\x4C\xDD\x14\x73\xA2\xFB\xB3\x07\x0C\x66\x97\x4D"
			"\x89\xDE\x35\x1C\x93\xE7\xE6\x8F\x20\x3D\x84\xE6\x73\x46\x0F\x7C\xF4\x3B\x6C\x02"
			"\x23\x7C\x79\x6C\x86\xD9\x48\x80\x9C\x34\xCB\xA1\x23\xE7\xF7\x8A\x2E\x4B\x9D\x39"
			"\xA5\x86\x1A\x73\x58\x28\x5A\x1D\x8D\x4A\xBD\x42\xD5\x49\x2B\xDF\x53\x1D\xE7\x4A"
			"\x5F\x74\x09\x7F\xDC\x29\x7D\x58\x9C\x4B\xC5\x2F\x3B\x8F\xBF\x56\xCA\x48\x0A\x74"
			"\xAE\xFF\xDD\x12\xE4\xF6\xAB\x83\x26\x4F\x52\x8A\x19\xBB\x91\x32\xA4\x42\xEC\x4F"
			"\x3C\x76\xED\x9F\x03\xAA\x5E\x53\x79\x4C\xD0\x06\xD2\x1A\x42\x9D\xB1\xA7\xEC\xF7"
			"\x5B\xD4\x03\x70\x1E\xF2\x47\x26\x48\xAC\x35\xEE\xD0\x58\x40\x94\x8C\x11\xD0\xEB"
			"\x77\x39\x5A\xA3\xD5\xD0\xD3\xC3\x68\xE1\x75\xAA\xC0\x44\xEA\xD8\xDD\x13\x3F\xF9"
			"\x7D\x21\x14\x34\xA5\x87\x43\xA4\x0A\x96\x77\x00\xCC\xCA\xB1\xDA\xC4\x39\xE0\x66"
			"\x37\x05\x6E\xAC\xF2\xE6\xC6\xC5\x4F\x79\xD3\xE5\x6A\x3D\x36\x3F";

		fail = !!memcmp(result, expected, 2048/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA512/256/888 (C0UNT=1, E=32, N=16, A=32, P=32)\n";
	}

	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
