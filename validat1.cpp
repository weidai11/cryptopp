// validat1.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "pubkey.h"
#include "gfpcrypt.h"
#include "eccrypto.h"
#include "filters.h"
#include "files.h"
#include "hex.h"
#include "base32.h"
#include "base64.h"
#include "modes.h"
#include "cbcmac.h"
#include "dmac.h"
#include "idea.h"
#include "des.h"
#include "rc2.h"
#include "arc4.h"
#include "rc5.h"
#include "blowfish.h"
#include "3way.h"
#include "safer.h"
#include "gost.h"
#include "shark.h"
#include "cast.h"
#include "square.h"
#include "seal.h"
#include "rc6.h"
#include "mars.h"
#include "aes.h"
#include "cpu.h"
#include "rng.h"
#include "rijndael.h"
#include "twofish.h"
#include "serpent.h"
#include "skipjack.h"
#include "shacal2.h"
#include "camellia.h"
#include "osrng.h"
#include "drbg.h"
#include "rdrand.h"
#include "zdeflate.h"
#include "smartptr.h"
#include "channels.h"
#include "misc.h"

#include <time.h>
#include <memory>
#include <iostream>
#include <iomanip>

#include "validate.h"

// Aggressive stack checking with VS2005 SP1 and above.
#if (CRYPTOPP_MSC_VERSION >= 1410)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

bool ValidateAll(bool thorough)
{
	bool pass=TestSettings();
	pass=TestOS_RNG() && pass;
	pass=TestAutoSeeded() && pass;
	pass=TestAutoSeededX917() && pass;
	pass=TestNIST_DRBG() && pass;

#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
	pass=TestRDRAND() && pass;
	pass=TestRDSEED() && pass;
#endif

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_IMPORTS)
	// http://github.com/weidai11/cryptopp/issues/92
	pass=TestSecBlock() && pass;
	// http://github.com/weidai11/cryptopp/issues/336
	pass=TestIntegerBitops() && pass;
	// http://github.com/weidai11/cryptopp/issues/64
	pass=TestPolynomialMod2() && pass;
	// http://github.com/weidai11/cryptopp/issues/242
	pass=TestHuffmanCodes() && pass;
	// http://github.com/weidai11/cryptopp/issues/346
	pass=TestASN1Parse() && pass;
#endif

	pass=ValidateCRC32() && pass;
	pass=ValidateCRC32C() && pass;
	pass=ValidateAdler32() && pass;
	pass=ValidateMD2() && pass;
	pass=ValidateMD5() && pass;
	pass=ValidateSHA() && pass;

	pass=RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/keccak.txt") && pass;
	pass=RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/sha3_fips_202.txt") && pass;

	pass=ValidateTiger() && pass;
	pass=ValidateRIPEMD() && pass;
	pass=ValidatePanama() && pass;
	pass=ValidateWhirlpool() && pass;

	pass=ValidateBLAKE2s() && pass;
	pass=ValidateBLAKE2b() && pass;
	pass=ValidatePoly1305() && pass;
	pass=ValidateSipHash() && pass;

	pass=ValidateHMAC() && pass;
	pass=ValidateTTMAC() && pass;

	pass=ValidatePBKDF() && pass;
	pass=ValidateHKDF() && pass;

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
	pass=ValidateCamellia() && pass;
	pass=ValidateSalsa() && pass;
	pass=ValidateSosemanuk() && pass;
	pass=ValidateVMAC() && pass;
	pass=ValidateCCM() && pass;
	pass=ValidateGCM() && pass;
	pass=ValidateCMAC() && pass;
	pass=RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/eax.txt") && pass;
	pass=RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/seed.txt") && pass;

	pass=ValidateBBS() && pass;
	pass=ValidateDH() && pass;
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
//	pass=ValidateBlumGoldwasser() && pass;
	pass=ValidateECP() && pass;
	pass=ValidateEC2N() && pass;
	pass=ValidateECDSA() && pass;
	pass=ValidateECGDSA() && pass;
	pass=ValidateESIGN() && pass;

	if (pass)
		cout << "\nAll tests passed!\n";
	else
		cout << "\nOops!  Not all tests passed.\n";

	return pass;
}

bool TestSettings()
{
	bool pass = true;

	cout << "\nTesting Settings...\n\n";

	word32 w;
	const byte s[] = "\x01\x02\x03\x04";

#if (CRYPTOPP_MSC_VERSION >= 1400)
	std::copy(s, s+4,
		stdext::make_checked_array_iterator(reinterpret_cast<byte*>(&w), sizeof(w)));
#else
	std::copy(s, s+4, reinterpret_cast<byte*>(&w));
#endif

	if (w == 0x04030201L)
	{
#ifdef IS_LITTLE_ENDIAN
		cout << "passed:  ";
#else
		cout << "FAILED:  ";
		pass = false;
#endif
		cout << "Your machine is little endian.\n";
	}
	else if (w == 0x01020304L)
	{
#ifndef IS_LITTLE_ENDIAN
		cout << "passed:  ";
#else
		cout << "FAILED:  ";
		pass = false;
#endif
		cout << "Your machine is big endian.\n";
	}
	else
	{
		cout << "FAILED:  Your machine is neither big endian nor little endian.\n";
		pass = false;
	}

#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	// Don't assert the alignment of testvals. That's what this test is for.
	byte testvals[10] = {1,2,2,3,3,3,3,2,2,1};
	if (*(word32 *)(void *)(testvals+3) == 0x03030303 && *(word64 *)(void *)(testvals+1) == W64LIT(0x0202030303030202))
		cout << "passed:  Your machine allows unaligned data access.\n";
	else
	{
		cout << "FAILED:  Unaligned data access gave incorrect results.\n";
		pass = false;
	}
#else
	cout << "passed:  CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS is not defined. Will restrict to aligned data access.\n";
#endif

	if (sizeof(byte) == 1)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(byte) == " << sizeof(byte) << endl;

	if (sizeof(word16) == 2)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word16) == " << sizeof(word16) << endl;

	if (sizeof(word32) == 4)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word32) == " << sizeof(word32) << endl;

	if (sizeof(word64) == 8)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word64) == " << sizeof(word64) << endl;

#ifdef CRYPTOPP_WORD128_AVAILABLE
	if (sizeof(word128) == 16)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word128) == " << sizeof(word128) << endl;
#endif

	if (sizeof(word) == 2*sizeof(hword)
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
		&& sizeof(dword) == 2*sizeof(word)
#endif
		)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(hword) == " << sizeof(hword) << ", sizeof(word) == " << sizeof(word);
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
	cout << ", sizeof(dword) == " << sizeof(dword);
#endif
	cout << endl;

#ifdef CRYPTOPP_CPUID_AVAILABLE
	bool hasMMX = HasMMX();
	bool hasISSE = HasISSE();
	bool hasSSE2 = HasSSE2();
	bool hasSSSE3 = HasSSSE3();
	bool hasSSE4 = HasSSE4();
	bool isP4 = IsP4();
	int cacheLineSize = GetCacheLineSize();

	if ((isP4 && (!hasMMX || !hasSSE2)) || (hasSSE2 && !hasMMX) || (cacheLineSize < 16 || cacheLineSize > 256 || !IsPowerOf2(cacheLineSize)))
	{
		cout << "FAILED:  ";
		pass = false;
	}
	else
		cout << "passed:  ";

	cout << "hasMMX == " << hasMMX << ", hasISSE == " << hasISSE << ", hasSSE2 == " << hasSSE2 << ", hasSSSE3 == " << hasSSSE3 << ", hasSSE4 == " << hasSSE4;
	cout << ", hasAESNI == " << HasAESNI() << ", hasCLMUL == " << HasCLMUL() << ", hasRDRAND == " << HasRDRAND() << ", hasRDSEED == " << HasRDSEED();
	cout << ", hasSHA == " << HasSHA() << ", isP4 == " << isP4 << ", cacheLineSize == " << cacheLineSize << endl;

#elif (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64)
	bool hasNEON = HasNEON();
	bool hasPMULL = HasPMULL();
	bool hasCRC32 = HasCRC32();
	bool hasAES = HasAES();
	bool hasSHA1 = HasSHA1();
	bool hasSHA2 = HasSHA2();

	cout << "passed:  ";
	cout << "hasNEON == " << hasNEON << ", hasPMULL == " << hasPMULL << ", hasCRC32 == " << hasCRC32 << ", hasAES == " << hasAES << ", hasSHA1 == " << hasSHA1 << ", hasSHA2 == " << hasSHA2 << endl;
#endif

	if (!pass)
	{
		cout << "Some critical setting in config.h is in error.  Please fix it and recompile." << endl;
		abort();
	}
	return pass;
}

bool TestOS_RNG()
{
	bool pass = true;

	member_ptr<RandomNumberGenerator> rng;

#ifdef BLOCKING_RNG_AVAILABLE
	try {rng.reset(new BlockingRng);}
	catch (OS_RNG_Err &) {}
#endif

	if (rng.get())
	{
		cout << "\nTesting operating system provided blocking random number generator...\n\n";

		MeterFilter meter(new Redirector(TheBitBucket()));
		RandomNumberSource test(*rng, UINT_MAX, false, new Deflator(new Redirector(meter)));
		unsigned long total=0, length=0;
		time_t t = time(NULL), t1 = 0;
		CRYPTOPP_UNUSED(length);

		// check that it doesn't take too long to generate a reasonable amount of randomness
		while (total < 16 && (t1 < 10 || total*8 > (unsigned long)t1))
		{
			test.Pump(1);
			total += 1;
			t1 = time(NULL) - t;
		}

		if (total < 16)
		{
			cout << "FAILED:";
			pass = false;
		}
		else
			cout << "passed:";
		cout << "  it took " << long(t1) << " seconds to generate " << total << " bytes" << endl;

#if 0	// disable this part. it's causing an unpredictable pause during the validation testing
		if (t1 < 2)
		{
			// that was fast, are we really blocking?
			// first exhaust the extropy reserve
			t = time(NULL);
			while (time(NULL) - t < 2)
			{
				test.Pump(1);
				total += 1;
			}

			// if it generates too many bytes in a certain amount of time,
			// something's probably wrong
			t = time(NULL);
			while (time(NULL) - t < 2)
			{
				test.Pump(1);
				total += 1;
				length += 1;
			}
			if (length > 1024)
			{
				cout << "FAILED:";
				pass = false;
			}
			else
				cout << "passed:";
			cout << "  it generated " << length << " bytes in " << long(time(NULL) - t) << " seconds" << endl;
		}
#endif

		test.AttachedTransformation()->MessageEnd();

		if (meter.GetTotalBytes() < total)
		{
			cout << "FAILED:";
			pass = false;
		}
		else
			cout << "passed:";
		cout << "  " << total << " generated bytes compressed to " << meter.GetTotalBytes() << " bytes by DEFLATE" << endl;
	}
	else
		cout << "\nNo operating system provided blocking random number generator, skipping test." << endl;

	rng.reset(NULL);
#ifdef NONBLOCKING_RNG_AVAILABLE
	try {rng.reset(new NonblockingRng);}
	catch (OS_RNG_Err &) {}
#endif

	if (rng.get())
	{
		cout << "\nTesting operating system provided nonblocking random number generator...\n\n";

		MeterFilter meter(new Redirector(TheBitBucket()));
		RandomNumberSource test(*rng, 100000, true, new Deflator(new Redirector(meter)));

		if (meter.GetTotalBytes() < 100000)
		{
			cout << "FAILED:";
			pass = false;
		}
		else
			cout << "passed:";
		cout << "  100000 generated bytes compressed to " << meter.GetTotalBytes() << " bytes by DEFLATE" << endl;
	}
	else
		cout << "\nNo operating system provided nonblocking random number generator, skipping test." << endl;

	return pass;
}

#if defined(NO_OS_DEPENDENCE) || !defined(OS_RNG_AVAILABLE)
bool TestAutoSeeded()
{
	return true;
}
bool TestAutoSeededX917()
{
	return true;
}
#else
bool TestAutoSeeded()
{
	// This tests Auto-Seeding and GenerateIntoBufferedTransformation.
	cout << "\nTesting AutoSeeded generator...\n\n";

	AutoSeededRandomPool prng;
	static const unsigned int ENTROPY_SIZE = 32;
	bool generate = true, discard = true, incorporate = false;

	MeterFilter meter(new Redirector(TheBitBucket()));
	RandomNumberSource test(prng, 100000, true, new Deflator(new Redirector(meter)));

	if (meter.GetTotalBytes() < 100000)
	{
		cout << "FAILED:";
		generate = false;
	}
	else
		cout << "passed:";
	cout << "  100000 generated bytes compressed to " << meter.GetTotalBytes() << " bytes by DEFLATE" << endl;

	try
	{
		prng.DiscardBytes(100000);
	}
	catch(const Exception&)
	{
		discard = false;
	}

	if (!discard)
		cout << "FAILED:";
	else
		cout << "passed:";
	cout << "  discarded 10000 bytes" << endl;

	try
	{
		if(prng.CanIncorporateEntropy())
		{
			SecByteBlock entropy(ENTROPY_SIZE);
			OS_GenerateRandomBlock(false, entropy, entropy.SizeInBytes());

			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());

			incorporate = true;
		}
	}
	catch(const Exception& /*ex*/)
	{
	}

	if (!incorporate)
		cout << "FAILED:";
	else
		cout << "passed:";
	cout << "  IncorporateEntropy with " << 4*ENTROPY_SIZE << " bytes" << endl;

	return generate && discard && incorporate;
}

bool TestAutoSeededX917()
{
	// This tests Auto-Seeding and GenerateIntoBufferedTransformation.
	cout << "\nTesting AutoSeeded X917 generator...\n\n";

	AutoSeededX917RNG<AES> prng;
	static const unsigned int ENTROPY_SIZE = 32;
	bool generate = true, discard = true, incorporate = false;

	MeterFilter meter(new Redirector(TheBitBucket()));
	RandomNumberSource test(prng, 100000, true, new Deflator(new Redirector(meter)));

	if (meter.GetTotalBytes() < 100000)
	{
		cout << "FAILED:";
		generate = false;
	}
	else
		cout << "passed:";
	cout << "  100000 generated bytes compressed to " << meter.GetTotalBytes() << " bytes by DEFLATE" << endl;

	try
	{
		prng.DiscardBytes(100000);
	}
	catch(const Exception&)
	{
		discard = false;
	}

	if (!discard)
		cout << "FAILED:";
	else
		cout << "passed:";
	cout << "  discarded 10000 bytes" << endl;

	try
	{
		if(prng.CanIncorporateEntropy())
		{
			SecByteBlock entropy(ENTROPY_SIZE);
			OS_GenerateRandomBlock(false, entropy, entropy.SizeInBytes());

			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());
			prng.IncorporateEntropy(entropy, entropy.SizeInBytes());

			incorporate = true;
		}
	}
	catch(const Exception& /*ex*/)
	{
	}

	if (!incorporate)
		cout << "FAILED:";
	else
		cout << "passed:";
	cout << "  IncorporateEntropy with " << 4*ENTROPY_SIZE << " bytes" << endl;

	return generate && discard && incorporate;
}
#endif // NO_OS_DEPENDENCE

#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
bool TestRDRAND()
{
	// Testing on 6th generation i7 shows RDRAND needs less than 8 retries for 10K bytes.
	RDRAND rdrand;
	bool entropy = true, compress = true, discard = true;
	static const unsigned int SIZE = 10000;

	if (HasRDRAND())
	{
		cout << "\nTesting RDRAND generator...\n\n";

		MeterFilter meter(new Redirector(TheBitBucket()));
		Deflator deflator(new Redirector(meter));
		MaurerRandomnessTest maurer;

		ChannelSwitch chsw;
		chsw.AddDefaultRoute(deflator);
		chsw.AddDefaultRoute(maurer);

		RandomNumberSource rns(rdrand, SIZE, true, new Redirector(chsw));
		deflator.Flush(true);

		CRYPTOPP_ASSERT(0 == maurer.BytesNeeded());
		const double mv = maurer.GetTestValue();
		if (mv < 0.98f)
		{
			cout << "FAILED:";
			entropy = false;
		}
		else
			cout << "passed:";

		// Coverity finding, also see http://stackoverflow.com/a/34509163/608639.
		StreamState ss(cout);
		cout << std::setiosflags(std::ios::fixed) << std::setprecision(6);
		cout << "  Maurer Randomness Test returned value " << mv << endl;

		if (meter.GetTotalBytes() < SIZE)
		{
			cout << "FAILED:";
			compress = false;
		}
		else
			cout << "passed:";
		cout << "  " << SIZE << " generated bytes compressed to " << meter.GetTotalBytes() << " bytes by DEFLATE\n";

		try
		{
			rdrand.DiscardBytes(SIZE);
		}
		catch(const Exception&)
		{
			discard = false;
		}

		if (!discard)
			cout << "FAILED:";
		else
			cout << "passed:";
		cout << "  discarded " << SIZE << " bytes\n";
	}
	else
		cout << "\nRDRAND generator not available, skipping test.\n";

	// Squash code coverage warnings on unused functions
	(void)rdrand.AlgorithmName();
	(void)rdrand.CanIncorporateEntropy();
	rdrand.SetRetries(rdrand.GetRetries());
	rdrand.IncorporateEntropy(NULL, 0);

	if (!(entropy && compress && discard))
		cout.flush();

	return entropy && compress && discard;
}
#endif

#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
bool TestRDSEED()
{
	// Testing on 5th generation i5 shows RDSEED needs about 128 retries for 10K bytes
	//  on 64-bit/amd64 VM, and it needs more for an 32-bit/i686 VM.
	RDSEED rdseed(256);
	bool entropy = true, compress = true, discard = true;
	static const unsigned int SIZE = 10000;

	if (HasRDSEED())
	{
		cout << "\nTesting RDSEED generator...\n\n";

		MeterFilter meter(new Redirector(TheBitBucket()));
		Deflator deflator(new Redirector(meter));
		MaurerRandomnessTest maurer;

		ChannelSwitch chsw;
		chsw.AddDefaultRoute(deflator);
		chsw.AddDefaultRoute(maurer);

		RandomNumberSource rns(rdseed, SIZE, true, new Redirector(chsw));
		deflator.Flush(true);

		CRYPTOPP_ASSERT(0 == maurer.BytesNeeded());
		const double mv = maurer.GetTestValue();
		if (mv < 0.98f)
		{
			cout << "FAILED:";
			entropy = false;
		}
		else
			cout << "passed:";

		// Coverity finding, also see http://stackoverflow.com/a/34509163/608639.
		StreamState ss(cout);
		cout << std::setiosflags(std::ios::fixed) << std::setprecision(6);
		cout << "  Maurer Randomness Test returned value " << mv << endl;

		if (meter.GetTotalBytes() < SIZE)
		{
			cout << "FAILED:";
			compress = false;
		}
		else
			cout << "passed:";
		cout << "  " << SIZE << " generated bytes compressed to " << meter.GetTotalBytes() << " bytes by DEFLATE\n";

		try
		{
			rdseed.DiscardBytes(SIZE);
		}
		catch(const Exception&)
		{
			discard = false;
		}

		if (!discard)
			cout << "FAILED:";
		else
			cout << "passed:";
		cout << "  discarded " << SIZE << " bytes\n";
	}
	else
		cout << "\nRDSEED generator not available, skipping test.\n";

	// Squash code coverage warnings on unused functions
	(void)rdseed.AlgorithmName();
	(void)rdseed.CanIncorporateEntropy();
	rdseed.SetRetries(rdseed.GetRetries());
	rdseed.IncorporateEntropy(NULL, 0);

	if (!(entropy && compress && discard))
		cout.flush();

	return entropy && compress && discard;
}
#endif

bool TestNIST_DRBG()
{
	cout << "\nTesting NIST DRBG generators...\n\n";
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (COUNT=0, E=16, N=8)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (COUNT=1, E=16, N=8)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=0, E=16, N=8, A=16)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=1, E=16, N=8, A=16)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=0, E=16, N=8, A=0, P=16)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=1, E=16, N=8, A=0, P=16)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=0, E=16, N=8, A=16, P=16)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA1/128/440 (C0UNT=1, E=16, N=8, A=16, P=16)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA256/128/440 (C0UNT=0, E=32, N=16, A=32, P=32)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA256/128/440 (C0UNT=1, E=32, N=16, A=32, P=32)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA512/256/888 (C0UNT=0, E=32, N=16, A=32, P=32)" << endl;
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

		cout << (fail ? "FAILED   " : "passed   ") << "Hash_DRBG SHA512/256/888 (C0UNT=1, E=32, N=16, A=32, P=32)" << endl;
	}

	return pass;
}

class CipherFactory
{
public:
	virtual unsigned int BlockSize() const =0;
	virtual unsigned int KeyLength() const =0;

	virtual BlockTransformation* NewEncryption(const byte *keyStr) const =0;
	virtual BlockTransformation* NewDecryption(const byte *keyStr) const =0;
};

template <class E, class D> class FixedRoundsCipherFactory : public CipherFactory
{
public:
	FixedRoundsCipherFactory(unsigned int keylen=0) : m_keylen(keylen?keylen:E::DEFAULT_KEYLENGTH) {}
	unsigned int BlockSize() const {return E::BLOCKSIZE;}
	unsigned int KeyLength() const {return m_keylen;}

	BlockTransformation* NewEncryption(const byte *keyStr) const
		{return new E(keyStr, m_keylen);}
	BlockTransformation* NewDecryption(const byte *keyStr) const
		{return new D(keyStr, m_keylen);}

	unsigned int m_keylen;
};

template <class E, class D> class VariableRoundsCipherFactory : public CipherFactory
{
public:
	VariableRoundsCipherFactory(unsigned int keylen=0, unsigned int rounds=0)
		: m_keylen(keylen ? keylen : E::DEFAULT_KEYLENGTH), m_rounds(rounds ? rounds : E::DEFAULT_ROUNDS) {}
	unsigned int BlockSize() const {return E::BLOCKSIZE;}
	unsigned int KeyLength() const {return m_keylen;}

	BlockTransformation* NewEncryption(const byte *keyStr) const
		{return new E(keyStr, m_keylen, m_rounds);}
	BlockTransformation* NewDecryption(const byte *keyStr) const
		{return new D(keyStr, m_keylen, m_rounds);}

	unsigned int m_keylen, m_rounds;
};

bool BlockTransformationTest(const CipherFactory &cg, BufferedTransformation &valdata, unsigned int tuples = 0xffff)
{
	HexEncoder output(new FileSink(cout));
	SecByteBlock plain(cg.BlockSize()), cipher(cg.BlockSize()), out(cg.BlockSize()), outplain(cg.BlockSize());
	SecByteBlock key(cg.KeyLength());
	bool pass=true, fail;

	while (valdata.MaxRetrievable() && tuples--)
	{
		valdata.Get(key, cg.KeyLength());
		valdata.Get(plain, cg.BlockSize());
		valdata.Get(cipher, cg.BlockSize());

		member_ptr<BlockTransformation> transE(cg.NewEncryption(key));
		transE->ProcessBlock(plain, out);
		fail = memcmp(out, cipher, cg.BlockSize()) != 0;

		member_ptr<BlockTransformation> transD(cg.NewDecryption(key));
		transD->ProcessBlock(out, outplain);
		fail=fail || memcmp(outplain, plain, cg.BlockSize());

		pass = pass && !fail;

		cout << (fail ? "FAILED   " : "passed   ");
		output.Put(key, cg.KeyLength());
		cout << "   ";
		output.Put(outplain, cg.BlockSize());
		cout << "   ";
		output.Put(out, cg.BlockSize());
		cout << endl;
	}
	return pass;
}

class FilterTester : public Unflushable<Sink>
{
public:
	FilterTester(const byte *validOutput, size_t outputLen)
		: validOutput(validOutput), outputLen(outputLen), counter(0), fail(false) {}
	void PutByte(byte inByte)
	{
		if (counter >= outputLen || validOutput[counter] != inByte)
		{
			std::cerr << "incorrect output " << counter << ", " << (word16)validOutput[counter] << ", " << (word16)inByte << "\n";
			fail = true;
			CRYPTOPP_ASSERT(false);
		}
		counter++;
	}
	size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking)
	{
		CRYPTOPP_UNUSED(messageEnd), CRYPTOPP_UNUSED(blocking);

		while (length--)
			FilterTester::PutByte(*inString++);

		if (messageEnd)
			if (counter != outputLen)
			{
				fail = true;
				CRYPTOPP_ASSERT(false);
			}

		return 0;
	}
	bool GetResult()
	{
		return !fail;
	}

	const byte *validOutput;
	size_t outputLen, counter;
	bool fail;
};

bool TestFilter(BufferedTransformation &bt, const byte *in, size_t inLen, const byte *out, size_t outLen)
{
	FilterTester *ft;
	bt.Attach(ft = new FilterTester(out, outLen));

	while (inLen)
	{
		size_t randomLen = GlobalRNG().GenerateWord32(0, (word32)inLen);
		bt.Put(in, randomLen);
		in += randomLen;
		inLen -= randomLen;
	}
	bt.MessageEnd();
	return ft->GetResult();
}

bool ValidateDES()
{
	cout << "\nDES validation suite running...\n\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/descert.dat", true, new HexDecoder);
	bool pass = BlockTransformationTest(FixedRoundsCipherFactory<DESEncryption, DESDecryption>(), valdata);

	cout << "\nTesting EDE2, EDE3, and XEX3 variants...\n\n";

	FileSource valdata1(CRYPTOPP_DATA_DIR "TestData/3desval.dat", true, new HexDecoder);
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_EDE2_Encryption, DES_EDE2_Decryption>(), valdata1, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_EDE3_Encryption, DES_EDE3_Decryption>(), valdata1, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_XEX3_Encryption, DES_XEX3_Decryption>(), valdata1, 1) && pass;

	return pass;
}

bool TestModeIV(SymmetricCipher &e, SymmetricCipher &d)
{
	SecByteBlock lastIV, iv(e.IVSize());
	StreamTransformationFilter filter(e, new StreamTransformationFilter(d));

	// vector_ptr<byte> due to Enterprise Analysis finding on the stack based array.
	vector_ptr<byte> plaintext(20480);

	for (unsigned int i=1; i<20480; i*=2)
	{
		e.GetNextIV(GlobalRNG(), iv);
		if (iv == lastIV)
			return false;
		else
			lastIV = iv;

		e.Resynchronize(iv);
		d.Resynchronize(iv);

		unsigned int length = STDMAX(GlobalRNG().GenerateWord32(0, i), (word32)e.MinLastBlockSize());
		GlobalRNG().GenerateBlock(plaintext, length);

		if (!TestFilter(filter, plaintext, length, plaintext, length))
			return false;
	}

	return true;
}

bool ValidateCipherModes()
{
	cout << "\nTesting DES modes...\n\n";
	const byte key[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	const byte iv[] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};
	const byte plain[] = {	// "Now is the time for all " without tailing 0
		0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
		0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
		0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20};
	DESEncryption desE(key);
	DESDecryption desD(key);
	bool pass=true, fail;

	{
		// from FIPS 81
		const byte encrypted[] = {
			0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15,
			0x6a, 0x27, 0x17, 0x87, 0xab, 0x88, 0x83, 0xf9,
			0x89, 0x3d, 0x51, 0xec, 0x4b, 0x56, 0x3b, 0x53};

		ECB_Mode_ExternalCipher::Encryption modeE(desE);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULL, StreamTransformationFilter::NO_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "ECB encryption" << endl;

		ECB_Mode_ExternalCipher::Decryption modeD(desD);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULL, StreamTransformationFilter::NO_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "ECB decryption" << endl;
	}
	{
		// from FIPS 81
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C,
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F,
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULL, StreamTransformationFilter::NO_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with no padding" << endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULL, StreamTransformationFilter::NO_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with no padding" << endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC mode IV generation" << endl;
	}
	{
		// generated with Crypto++, matches FIPS 81
		// but has extra 8 bytes as result of padding
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C,
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F,
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6,
			0x62, 0xC1, 0x6A, 0x27, 0xE4, 0xFC, 0xF2, 0x77};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with PKCS #7 padding" << endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with PKCS #7 padding" << endl;
	}
	{
		// generated with Crypto++ 5.2, matches FIPS 81
		// but has extra 8 bytes as result of padding
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C,
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F,
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6,
			0xcf, 0xb7, 0xc7, 0x64, 0x0e, 0x7c, 0xd9, 0xa7};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULL, StreamTransformationFilter::ONE_AND_ZEROS_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with one-and-zeros padding" << endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULL, StreamTransformationFilter::ONE_AND_ZEROS_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with one-and-zeros padding" << endl;
	}
	{
		const byte plain_1[] = {'a', 0, 0, 0, 0, 0, 0, 0};
		// generated with Crypto++
		const byte encrypted[] = {
			0x9B, 0x47, 0x57, 0x59, 0xD6, 0x9C, 0xF6, 0xD0};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULL, StreamTransformationFilter::ZEROS_PADDING).Ref(),
			plain_1, 1, encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with zeros padding" << endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULL, StreamTransformationFilter::ZEROS_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain_1, sizeof(plain_1));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with zeros padding" << endl;
	}
	{
		// generated with Crypto++, matches FIPS 81
		// but with last two blocks swapped as result of CTS
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C,
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6,
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F};

		CBC_CTS_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with ciphertext stealing (CTS)" << endl;

		CBC_CTS_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with ciphertext stealing (CTS)" << endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC CTS IV generation" << endl;
	}
	{
		// generated with Crypto++
		const byte decryptionIV[] = {0x4D, 0xD0, 0xAC, 0x8F, 0x47, 0xCF, 0x79, 0xCE};
		const byte encrypted[] = {0x12, 0x34, 0x56};

		byte stolenIV[8];

		CBC_CTS_Mode_ExternalCipher::Encryption modeE(desE, iv);
		modeE.SetStolenIV(stolenIV);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, 3, encrypted, sizeof(encrypted));
		fail = memcmp(stolenIV, decryptionIV, 8) != 0 || fail;
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with ciphertext and IV stealing" << endl;

		CBC_CTS_Mode_ExternalCipher::Decryption modeD(desD, stolenIV);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, 3);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with ciphertext and IV stealing" << endl;
	}
	{
		const byte encrypted[] = {	// from FIPS 81
			0xF3,0x09,0x62,0x49,0xC7,0xF4,0x6E,0x51,
			0xA6,0x9E,0x83,0x9B,0x1A,0x92,0xF7,0x84,
			0x03,0x46,0x71,0x33,0x89,0x8E,0xA6,0x22};

		CFB_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CFB encryption" << endl;

		CFB_Mode_ExternalCipher::Decryption modeD(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CFB decryption" << endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CFB mode IV generation" << endl;
	}
	{
		const byte plain_2[] = {	// "Now is the." without tailing 0
			0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,0x68,0x65};
		const byte encrypted[] = {	// from FIPS 81
			0xf3,0x1f,0xda,0x07,0x01,0x14,0x62,0xee,0x18,0x7f};

		CFB_Mode_ExternalCipher::Encryption modeE(desE, iv, 1);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain_2, sizeof(plain_2), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CFB (8-bit feedback) encryption" << endl;

		CFB_Mode_ExternalCipher::Decryption modeD(desE, iv, 1);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain_2, sizeof(plain_2));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CFB (8-bit feedback) decryption" << endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CFB (8-bit feedback) IV generation" << endl;
	}
	{
		const byte encrypted[] = {	// from Eric Young's libdes
			0xf3,0x09,0x62,0x49,0xc7,0xf4,0x6e,0x51,
			0x35,0xf2,0x4a,0x24,0x2e,0xeb,0x3d,0x3f,
			0x3d,0x6d,0x5b,0xe3,0x25,0x5a,0xf8,0xc3};

		OFB_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "OFB encryption" << endl;

		OFB_Mode_ExternalCipher::Decryption modeD(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "OFB decryption" << endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "OFB IV generation" << endl;
	}
	{
		const byte encrypted[] = {	// generated with Crypto++
			0xF3, 0x09, 0x62, 0x49, 0xC7, 0xF4, 0x6E, 0x51,
			0x16, 0x3A, 0x8C, 0xA0, 0xFF, 0xC9, 0x4C, 0x27,
			0xFA, 0x2F, 0x80, 0xF4, 0x80, 0xB8, 0x6F, 0x75};

		CTR_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "Counter Mode encryption" << endl;

		CTR_Mode_ExternalCipher::Decryption modeD(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "Counter Mode decryption" << endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "Counter Mode IV generation" << endl;
	}
	{
		const byte plain_3[] = {	// "7654321 Now is the time for "
			0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20,
			0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
			0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
			0x66, 0x6f, 0x72, 0x20};
		const byte mac1[] = {	// from FIPS 113
			0xf1, 0xd3, 0x0f, 0x68, 0x49, 0x31, 0x2c, 0xa4};
		const byte mac2[] = {	// generated with Crypto++
			0x35, 0x80, 0xC5, 0xC4, 0x6B, 0x81, 0x24, 0xE2};

		CBC_MAC<DES> cbcmac(key);
		HashFilter cbcmacFilter(cbcmac);
		fail = !TestFilter(cbcmacFilter, plain_3, sizeof(plain_3), mac1, sizeof(mac1));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC MAC" << endl;

		DMAC<DES> dmac(key);
		HashFilter dmacFilter(dmac);
		fail = !TestFilter(dmacFilter, plain_3, sizeof(plain_3), mac2, sizeof(mac2));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "DMAC" << endl;
	}
	{
		CTR_Mode<AES>::Encryption modeE(plain, 16, plain);
		CTR_Mode<AES>::Decryption modeD(plain, 16, plain);
		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "AES CTR Mode" << endl;
	}
	{
		OFB_Mode<AES>::Encryption modeE(plain, 16, plain);
		OFB_Mode<AES>::Decryption modeD(plain, 16, plain);
		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "AES OFB Mode" << endl;
	}
	{
		CFB_Mode<AES>::Encryption modeE(plain, 16, plain);
		CFB_Mode<AES>::Decryption modeD(plain, 16, plain);
		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "AES CFB Mode" << endl;
	}
	{
		CBC_Mode<AES>::Encryption modeE(plain, 16, plain);
		CBC_Mode<AES>::Decryption modeD(plain, 16, plain);
		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "AES CBC Mode" << endl;
	}

	return pass;
}

bool ValidateIDEA()
{
	cout << "\nIDEA validation suite running...\n\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/ideaval.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<IDEAEncryption, IDEADecryption>(), valdata);
}

bool ValidateSAFER()
{
	cout << "\nSAFER validation suite running...\n\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/saferval.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_K_Encryption, SAFER_K_Decryption>(8,6), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_K_Encryption, SAFER_K_Decryption>(16,12), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_SK_Encryption, SAFER_SK_Decryption>(8,6), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_SK_Encryption, SAFER_SK_Decryption>(16,10), valdata, 4) && pass;
	return pass;
}

bool ValidateRC2()
{
	cout << "\nRC2 validation suite running...\n\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/rc2val.dat", true, new HexDecoder);
	HexEncoder output(new FileSink(cout));
	SecByteBlock plain(RC2Encryption::BLOCKSIZE), cipher(RC2Encryption::BLOCKSIZE), out(RC2Encryption::BLOCKSIZE), outplain(RC2Encryption::BLOCKSIZE);
	SecByteBlock key(128);
	bool pass=true, fail;

	while (valdata.MaxRetrievable())
	{
		byte keyLen, effectiveLen;

		valdata.Get(keyLen);
		valdata.Get(effectiveLen);
		valdata.Get(key, keyLen);
		valdata.Get(plain, RC2Encryption::BLOCKSIZE);
		valdata.Get(cipher, RC2Encryption::BLOCKSIZE);

		member_ptr<BlockTransformation> transE(new RC2Encryption(key, keyLen, effectiveLen));
		transE->ProcessBlock(plain, out);
		fail = memcmp(out, cipher, RC2Encryption::BLOCKSIZE) != 0;

		member_ptr<BlockTransformation> transD(new RC2Decryption(key, keyLen, effectiveLen));
		transD->ProcessBlock(out, outplain);
		fail=fail || memcmp(outplain, plain, RC2Encryption::BLOCKSIZE);

		pass = pass && !fail;

		cout << (fail ? "FAILED   " : "passed   ");
		output.Put(key, keyLen);
		cout << "   ";
		output.Put(outplain, RC2Encryption::BLOCKSIZE);
		cout << "   ";
		output.Put(out, RC2Encryption::BLOCKSIZE);
		cout << endl;
	}
	return pass;
}

bool ValidateARC4()
{
	unsigned char Key0[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
	unsigned char Input0[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	unsigned char Output0[] = {0x75,0xb7,0x87,0x80,0x99,0xe0,0xc5,0x96};

	unsigned char Key1[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	unsigned char Input1[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char Output1[]={0x74,0x94,0xc2,0xe7,0x10,0x4b,0x08,0x79};

	unsigned char Key2[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char Input2[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char Output2[]={0xde,0x18,0x89,0x41,0xa3,0x37,0x5d,0x3a};

	unsigned char Key3[]={0xef,0x01,0x23,0x45};
	unsigned char Input3[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char Output3[]={0xd6,0xa1,0x41,0xa7,0xec,0x3c,0x38,0xdf,0xbd,0x61};

	unsigned char Key4[]={ 0x01,0x23,0x45,0x67,0x89,0xab, 0xcd,0xef };
	unsigned char Input4[] =
	{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01};
	unsigned char Output4[]= {
	0x75,0x95,0xc3,0xe6,0x11,0x4a,0x09,0x78,0x0c,0x4a,0xd4,
	0x52,0x33,0x8e,0x1f,0xfd,0x9a,0x1b,0xe9,0x49,0x8f,
	0x81,0x3d,0x76,0x53,0x34,0x49,0xb6,0x77,0x8d,0xca,
	0xd8,0xc7,0x8a,0x8d,0x2b,0xa9,0xac,0x66,0x08,0x5d,
	0x0e,0x53,0xd5,0x9c,0x26,0xc2,0xd1,0xc4,0x90,0xc1,
	0xeb,0xbe,0x0c,0xe6,0x6d,0x1b,0x6b,0x1b,0x13,0xb6,
	0xb9,0x19,0xb8,0x47,0xc2,0x5a,0x91,0x44,0x7a,0x95,
	0xe7,0x5e,0x4e,0xf1,0x67,0x79,0xcd,0xe8,0xbf,0x0a,
	0x95,0x85,0x0e,0x32,0xaf,0x96,0x89,0x44,0x4f,0xd3,
	0x77,0x10,0x8f,0x98,0xfd,0xcb,0xd4,0xe7,0x26,0x56,
	0x75,0x00,0x99,0x0b,0xcc,0x7e,0x0c,0xa3,0xc4,0xaa,
	0xa3,0x04,0xa3,0x87,0xd2,0x0f,0x3b,0x8f,0xbb,0xcd,
	0x42,0xa1,0xbd,0x31,0x1d,0x7a,0x43,0x03,0xdd,0xa5,
	0xab,0x07,0x88,0x96,0xae,0x80,0xc1,0x8b,0x0a,0xf6,
	0x6d,0xff,0x31,0x96,0x16,0xeb,0x78,0x4e,0x49,0x5a,
	0xd2,0xce,0x90,0xd7,0xf7,0x72,0xa8,0x17,0x47,0xb6,
	0x5f,0x62,0x09,0x3b,0x1e,0x0d,0xb9,0xe5,0xba,0x53,
	0x2f,0xaf,0xec,0x47,0x50,0x83,0x23,0xe6,0x71,0x32,
	0x7d,0xf9,0x44,0x44,0x32,0xcb,0x73,0x67,0xce,0xc8,
	0x2f,0x5d,0x44,0xc0,0xd0,0x0b,0x67,0xd6,0x50,0xa0,
	0x75,0xcd,0x4b,0x70,0xde,0xdd,0x77,0xeb,0x9b,0x10,
	0x23,0x1b,0x6b,0x5b,0x74,0x13,0x47,0x39,0x6d,0x62,
	0x89,0x74,0x21,0xd4,0x3d,0xf9,0xb4,0x2e,0x44,0x6e,
	0x35,0x8e,0x9c,0x11,0xa9,0xb2,0x18,0x4e,0xcb,0xef,
	0x0c,0xd8,0xe7,0xa8,0x77,0xef,0x96,0x8f,0x13,0x90,
	0xec,0x9b,0x3d,0x35,0xa5,0x58,0x5c,0xb0,0x09,0x29,
	0x0e,0x2f,0xcd,0xe7,0xb5,0xec,0x66,0xd9,0x08,0x4b,
	0xe4,0x40,0x55,0xa6,0x19,0xd9,0xdd,0x7f,0xc3,0x16,
	0x6f,0x94,0x87,0xf7,0xcb,0x27,0x29,0x12,0x42,0x64,
	0x45,0x99,0x85,0x14,0xc1,0x5d,0x53,0xa1,0x8c,0x86,
	0x4c,0xe3,0xa2,0xb7,0x55,0x57,0x93,0x98,0x81,0x26,
	0x52,0x0e,0xac,0xf2,0xe3,0x06,0x6e,0x23,0x0c,0x91,
	0xbe,0xe4,0xdd,0x53,0x04,0xf5,0xfd,0x04,0x05,0xb3,
	0x5b,0xd9,0x9c,0x73,0x13,0x5d,0x3d,0x9b,0xc3,0x35,
	0xee,0x04,0x9e,0xf6,0x9b,0x38,0x67,0xbf,0x2d,0x7b,
	0xd1,0xea,0xa5,0x95,0xd8,0xbf,0xc0,0x06,0x6f,0xf8,
	0xd3,0x15,0x09,0xeb,0x0c,0x6c,0xaa,0x00,0x6c,0x80,
	0x7a,0x62,0x3e,0xf8,0x4c,0x3d,0x33,0xc1,0x95,0xd2,
	0x3e,0xe3,0x20,0xc4,0x0d,0xe0,0x55,0x81,0x57,0xc8,
	0x22,0xd4,0xb8,0xc5,0x69,0xd8,0x49,0xae,0xd5,0x9d,
	0x4e,0x0f,0xd7,0xf3,0x79,0x58,0x6b,0x4b,0x7f,0xf6,
	0x84,0xed,0x6a,0x18,0x9f,0x74,0x86,0xd4,0x9b,0x9c,
	0x4b,0xad,0x9b,0xa2,0x4b,0x96,0xab,0xf9,0x24,0x37,
	0x2c,0x8a,0x8f,0xff,0xb1,0x0d,0x55,0x35,0x49,0x00,
	0xa7,0x7a,0x3d,0xb5,0xf2,0x05,0xe1,0xb9,0x9f,0xcd,
	0x86,0x60,0x86,0x3a,0x15,0x9a,0xd4,0xab,0xe4,0x0f,
	0xa4,0x89,0x34,0x16,0x3d,0xdd,0xe5,0x42,0xa6,0x58,
	0x55,0x40,0xfd,0x68,0x3c,0xbf,0xd8,0xc0,0x0f,0x12,
	0x12,0x9a,0x28,0x4d,0xea,0xcc,0x4c,0xde,0xfe,0x58,
	0xbe,0x71,0x37,0x54,0x1c,0x04,0x71,0x26,0xc8,0xd4,
	0x9e,0x27,0x55,0xab,0x18,0x1a,0xb7,0xe9,0x40,0xb0,
	0xc0};

	member_ptr<Weak::ARC4> arc4;
	bool pass=true, fail;
	unsigned int i;

	cout << "\nARC4 validation suite running...\n\n";

	arc4.reset(new Weak::ARC4(Key0, sizeof(Key0)));
	arc4->ProcessString(Input0, sizeof(Input0));
	fail = memcmp(Input0, Output0, sizeof(Input0)) != 0;
	cout << (fail ? "FAILED" : "passed") << "    Test 0" << endl;
	pass = pass && !fail;

	arc4.reset(new Weak::ARC4(Key1, sizeof(Key1)));
	arc4->ProcessString(Key1, Input1, sizeof(Key1));
	fail = memcmp(Output1, Key1, sizeof(Key1)) != 0;
	cout << (fail ? "FAILED" : "passed") << "    Test 1" << endl;
	pass = pass && !fail;

	arc4.reset(new Weak::ARC4(Key2, sizeof(Key2)));
	for (i=0, fail=false; i<sizeof(Input2); i++)
		if (arc4->ProcessByte(Input2[i]) != Output2[i])
			fail = true;
	cout << (fail ? "FAILED" : "passed") << "    Test 2" << endl;
	pass = pass && !fail;

	arc4.reset(new Weak::ARC4(Key3, sizeof(Key3)));
	for (i=0, fail=false; i<sizeof(Input3); i++)
		if (arc4->ProcessByte(Input3[i]) != Output3[i])
			fail = true;
	cout << (fail ? "FAILED" : "passed") << "    Test 3" << endl;
	pass = pass && !fail;

	arc4.reset(new Weak::ARC4(Key4, sizeof(Key4)));
	for (i=0, fail=false; i<sizeof(Input4); i++)
		if (arc4->ProcessByte(Input4[i]) != Output4[i])
			fail = true;
	cout << (fail ? "FAILED" : "passed") << "    Test 4" << endl;
	pass = pass && !fail;

	return pass;
}

bool ValidateRC5()
{
	cout << "\nRC5 validation suite running...\n\n";
	bool pass1 = true, pass2 = true;

	RC5Encryption enc;  // 0 to 2040-bits (255-bytes)
	pass1 = RC5Encryption::DEFAULT_KEYLENGTH ==  16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(0) == 0 && pass1;
	pass1 = enc.StaticGetValidKeyLength(254) == 254 && pass1;
	pass1 = enc.StaticGetValidKeyLength(255) == 255 && pass1;
	pass1 = enc.StaticGetValidKeyLength(256) == 255 && pass1;
	pass1 = enc.StaticGetValidKeyLength(0) == enc.MinKeyLength() && pass1;
	pass1 = enc.StaticGetValidKeyLength(SIZE_MAX) == enc.MaxKeyLength() && pass1;

	RC5Decryption dec;
	pass2 = RC5Decryption::DEFAULT_KEYLENGTH ==  16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(0) == 0 && pass2;
	pass2 = dec.StaticGetValidKeyLength(254) == 254 && pass2;
	pass2 = dec.StaticGetValidKeyLength(255) == 255 && pass2;
	pass2 = dec.StaticGetValidKeyLength(256) == 255 && pass2;
	pass2 = dec.StaticGetValidKeyLength(0) == dec.MinKeyLength() && pass2;
	pass2 = dec.StaticGetValidKeyLength(SIZE_MAX) == dec.MaxKeyLength() && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/rc5val.dat", true, new HexDecoder);
	return BlockTransformationTest(VariableRoundsCipherFactory<RC5Encryption, RC5Decryption>(16, 12), valdata) && pass1 && pass2;
}

bool ValidateRC6()
{
	cout << "\nRC6 validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	RC6Encryption enc;
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(24) == 24 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(128) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(0) == enc.MinKeyLength() && pass1;
	pass1 = enc.StaticGetValidKeyLength(SIZE_MAX) == enc.MaxKeyLength() && pass1;

	RC6Decryption dec;
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(24) == 24 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(128) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(0) == dec.MinKeyLength() && pass2;
	pass2 = dec.StaticGetValidKeyLength(SIZE_MAX) == dec.MaxKeyLength() && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/rc6val.dat", true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(16), valdata, 2) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(24), valdata, 2) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(32), valdata, 2) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateMARS()
{
	cout << "\nMARS validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	MARSEncryption enc;
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(24) == 24 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 56 && pass1;
	pass1 = enc.StaticGetValidKeyLength(128) == 56 && pass1;
	pass1 = enc.StaticGetValidKeyLength(0) == enc.MinKeyLength() && pass1;
	pass1 = enc.StaticGetValidKeyLength(SIZE_MAX) == enc.MaxKeyLength() && pass1;

	MARSDecryption dec;
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(24) == 24 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 56 && pass2;
	pass2 = dec.StaticGetValidKeyLength(128) == 56 && pass2;
	pass2 = dec.StaticGetValidKeyLength(0) == dec.MinKeyLength() && pass2;
	pass2 = dec.StaticGetValidKeyLength(SIZE_MAX) == dec.MaxKeyLength() && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/marsval.dat", true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(16), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(24), valdata, 3) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(32), valdata, 2) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateRijndael()
{
	cout << "\nRijndael (AES) validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	RijndaelEncryption enc;
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(24) == 24 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(128) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(0) == enc.MinKeyLength() && pass1;
	pass1 = enc.StaticGetValidKeyLength(SIZE_MAX) == enc.MaxKeyLength() && pass1;

	RijndaelDecryption dec;
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(24) == 24 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(128) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(0) == dec.MinKeyLength() && pass2;
	pass2 = dec.StaticGetValidKeyLength(SIZE_MAX) == dec.MaxKeyLength() && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/rijndael.dat", true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(16), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(24), valdata, 3) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(32), valdata, 2) && pass3;
	pass3 = RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/aes.txt") && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateTwofish()
{
	cout << "\nTwofish validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	TwofishEncryption enc;
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(24) == 24 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(128) == 32 && pass1;

	TwofishDecryption dec;
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(24) == 24 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(128) == 32 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/twofishv.dat", true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(16), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(24), valdata, 3) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(32), valdata, 2) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateSerpent()
{
	cout << "\nSerpent validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	SerpentEncryption enc;
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(24) == 24 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(128) == 32 && pass1;

	SerpentDecryption dec;
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(24) == 24 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(128) == 32 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/serpentv.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(16), valdata, 5) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(24), valdata, 4) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(32), valdata, 3) && pass;
	return pass1 && pass2 && pass3;
}

bool ValidateBlowfish()
{
	cout << "\nBlowfish validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true, fail;

	BlowfishEncryption enc1;	// 32 to 448-bits (4 to 56-bytes)
	pass1 = enc1.StaticGetValidKeyLength(3) == 4 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(4) == 4 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(5) == 5 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(8) == 8 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(24) == 24 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(56) == 56 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(57) == 56 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(60) == 56 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(64) == 56 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(128) == 56 && pass1;

	BlowfishDecryption dec1; // 32 to 448-bits (4 to 56-bytes)
	pass2 = dec1.StaticGetValidKeyLength(3) == 4 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(4) == 4 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(5) == 5 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(8) == 8 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(24) == 24 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(56) == 56 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(57) == 56 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(60) == 56 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(64) == 56 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(128) == 56 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	HexEncoder output(new FileSink(cout));
	const char *key[]={"abcdefghijklmnopqrstuvwxyz", "Who is John Galt?"};
	byte *plain[]={(byte *)"BLOWFISH", (byte *)"\xfe\xdc\xba\x98\x76\x54\x32\x10"};
	byte *cipher[]={(byte *)"\x32\x4e\xd0\xfe\xf4\x13\xa2\x03", (byte *)"\xcc\x91\x73\x2b\x80\x22\xf6\x84"};
	byte out[8], outplain[8];

	for (int i=0; i<2; i++)
	{
		ECB_Mode<Blowfish>::Encryption enc2((byte *)key[i], strlen(key[i]));
		enc2.ProcessData(out, plain[i], 8);
		fail = memcmp(out, cipher[i], 8) != 0;

		ECB_Mode<Blowfish>::Decryption dec2((byte *)key[i], strlen(key[i]));
		dec2.ProcessData(outplain, cipher[i], 8);
		fail = fail || memcmp(outplain, plain[i], 8);
		pass3 = pass3 && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << '\"' << key[i] << '\"';
		for (int j=0; j<(signed int)(30-strlen(key[i])); j++)
			cout << ' ';
		output.Put(outplain, 8);
		cout << "  ";
		output.Put(out, 8);
		cout << endl;
	}
	return pass1 && pass2 && pass3;
}

bool ValidateThreeWay()
{
	cout << "\n3-WAY validation suite running...\n\n";
	bool pass1 = true, pass2 = true;

	ThreeWayEncryption enc;  // 96-bit only
	pass1 = ThreeWayEncryption::KEYLENGTH ==  12 && pass1;
	pass1 = enc.StaticGetValidKeyLength(8) == 12 && pass1;
	pass1 = enc.StaticGetValidKeyLength(12) == 12 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 12 && pass1;

	ThreeWayDecryption dec;  // 96-bit only
	pass2 = ThreeWayDecryption::KEYLENGTH ==  12 && pass2;
	pass2 = dec.StaticGetValidKeyLength(8) == 12 && pass2;
	pass2 = dec.StaticGetValidKeyLength(12) == 12 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 12 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/3wayval.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<ThreeWayEncryption, ThreeWayDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateGOST()
{
	cout << "\nGOST validation suite running...\n\n";
	bool pass1 = true, pass2 = true;

	GOSTEncryption enc;  // 256-bit only
	pass1 = GOSTEncryption::KEYLENGTH ==  32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(24) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(40) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 32 && pass1;

	GOSTDecryption dec;  // 256-bit only
	pass2 = GOSTDecryption::KEYLENGTH ==  32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(24) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(40) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 32 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/gostval.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<GOSTEncryption, GOSTDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateSHARK()
{
	cout << "\nSHARK validation suite running...\n\n";
	bool pass1 = true, pass2 = true;

	SHARKEncryption enc;  // 128-bit only
	pass1 = SHARKEncryption::KEYLENGTH ==  16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(15) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(17) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 16 && pass1;

	SHARKDecryption dec;  // 128-bit only
	pass2 = SHARKDecryption::KEYLENGTH ==  16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(15) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(17) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 16 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/sharkval.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SHARKEncryption, SHARKDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateCAST()
{
	cout << "\nCAST-128 validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	CAST128Encryption enc1;  // 40 to 128-bits (5 to 16-bytes)
	pass1 = CAST128Encryption::DEFAULT_KEYLENGTH ==  16 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(4) == 5 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(5) == 5 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(15) == 15 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc1.StaticGetValidKeyLength(17) == 16 && pass1;

	CAST128Decryption dec1;  // 40 to 128-bits (5 to 16-bytes)
	pass2 = CAST128Decryption::DEFAULT_KEYLENGTH ==  16 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(4) == 5 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(5) == 5 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(15) == 15 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec1.StaticGetValidKeyLength(17) == 16 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource val128(CRYPTOPP_DATA_DIR "TestData/cast128v.dat", true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(16), val128, 1) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(10), val128, 1) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(5), val128, 1) && pass3;

	cout << "\nCAST-256 validation suite running...\n\n";
	bool pass4 = true, pass5 = true, pass6 = true;

	CAST256Encryption enc2;  // 128, 160, 192, 224, or 256-bits (16 to 32-bytes, step 4)
	pass1 = CAST128Encryption::DEFAULT_KEYLENGTH ==  16 && pass1;
	pass4 = enc2.StaticGetValidKeyLength(15) == 16 && pass4;
	pass4 = enc2.StaticGetValidKeyLength(16) == 16 && pass4;
	pass4 = enc2.StaticGetValidKeyLength(17) == 20 && pass4;
	pass4 = enc2.StaticGetValidKeyLength(20) == 20 && pass4;
	pass4 = enc2.StaticGetValidKeyLength(24) == 24 && pass4;
	pass4 = enc2.StaticGetValidKeyLength(28) == 28 && pass4;
	pass4 = enc2.StaticGetValidKeyLength(31) == 32 && pass4;
	pass4 = enc2.StaticGetValidKeyLength(32) == 32 && pass4;
	pass4 = enc2.StaticGetValidKeyLength(33) == 32 && pass4;

	CAST256Decryption dec2;  // 128, 160, 192, 224, or 256-bits (16 to 32-bytes, step 4)
	pass2 = CAST256Decryption::DEFAULT_KEYLENGTH ==  16 && pass2;
	pass5 = dec2.StaticGetValidKeyLength(15) == 16 && pass5;
	pass5 = dec2.StaticGetValidKeyLength(16) == 16 && pass5;
	pass5 = dec2.StaticGetValidKeyLength(17) == 20 && pass5;
	pass5 = dec2.StaticGetValidKeyLength(20) == 20 && pass5;
	pass5 = dec2.StaticGetValidKeyLength(24) == 24 && pass5;
	pass5 = dec2.StaticGetValidKeyLength(28) == 28 && pass5;
	pass5 = dec2.StaticGetValidKeyLength(31) == 32 && pass5;
	pass5 = dec2.StaticGetValidKeyLength(32) == 32 && pass5;
	pass5 = dec2.StaticGetValidKeyLength(33) == 32 && pass5;
	cout << (pass4 && pass5 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource val256(CRYPTOPP_DATA_DIR "TestData/cast256v.dat", true, new HexDecoder);
	pass6 = BlockTransformationTest(FixedRoundsCipherFactory<CAST256Encryption, CAST256Decryption>(16), val256, 1) && pass6;
	pass6 = BlockTransformationTest(FixedRoundsCipherFactory<CAST256Encryption, CAST256Decryption>(24), val256, 1) && pass6;
	pass6 = BlockTransformationTest(FixedRoundsCipherFactory<CAST256Encryption, CAST256Decryption>(32), val256, 1) && pass6;

	return pass1 && pass2 && pass3 && pass4 && pass5 && pass6;
}

bool ValidateSquare()
{
	cout << "\nSquare validation suite running...\n\n";
	bool pass1 = true, pass2 = true;

	SquareEncryption enc;  // 128-bits only
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(15) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(17) == 16 && pass1;

	SquareDecryption dec;  // 128-bits only
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(15) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(17) == 16 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/squareva.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SquareEncryption, SquareDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateSKIPJACK()
{
	cout << "\nSKIPJACK validation suite running...\n\n";
	bool pass1 = true, pass2 = true;

	SKIPJACKEncryption enc;  // 80-bits only
	pass1 = enc.StaticGetValidKeyLength(8) == 10 && pass1;
	pass1 = enc.StaticGetValidKeyLength(9) == 10 && pass1;
	pass1 = enc.StaticGetValidKeyLength(10) == 10 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 10 && pass1;

	SKIPJACKDecryption dec;  // 80-bits only
	pass2 = dec.StaticGetValidKeyLength(8) == 10 && pass2;
	pass2 = dec.StaticGetValidKeyLength(9) == 10 && pass2;
	pass2 = dec.StaticGetValidKeyLength(10) == 10 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 10 && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/skipjack.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SKIPJACKEncryption, SKIPJACKDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateSEAL()
{
	static const byte input[] = {0x37,0xa0,0x05,0x95,0x9b,0x84,0xc4,0x9c,0xa4,0xbe,0x1e,0x05,0x06,0x73,0x53,0x0f,0x5f,0xb0,0x97,0xfd,0xf6,0xa1,0x3f,0xbd,0x6c,0x2c,0xde,0xcd,0x81,0xfd,0xee,0x7c};
	static const byte key[] = {0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0};
	static const byte iv[] = {0x01, 0x35, 0x77, 0xaf};
	byte output[32];

	cout << "\nSEAL validation suite running...\n\n";

	SEAL<>::Encryption seal(key, sizeof(key), iv);
	unsigned int size = sizeof(input);
	bool pass = true;

	memset(output, 1, size);
	seal.ProcessString(output, input, size);
	for (unsigned int i=0; i<size; i++)
		if (output[i] != 0)
			pass = false;

	seal.Seek(1);
	output[1] = seal.ProcessByte(output[1]);
	seal.ProcessString(output+2, size-2);
	pass = pass && memcmp(output+1, input+1, size-1) == 0;

	cout << (pass ? "passed" : "FAILED") << endl;
	return pass;
}

bool ValidateBaseCode()
{
	bool pass = true, fail;
	byte data[255];
	for (unsigned int i=0; i<255; i++)
		data[i] = byte(i);
	static const char hexEncoded[] =
"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"
"28292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
"505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F7071727374757677"
"78797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"
"C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFE";
	static const char base32Encoded[] =
"AAASEA2EAWDAQCAJBIFS2DIQB6IBCESVCSKTNF22DEPBYHA7D2RUAIJCENUCKJTHFAWUWK3NFWZC8NBT"
"GI3VIPJYG66DUQT5HS8V6R4AIFBEGTCFI3DWSUKKJPGE4VURKBIXEW4WKXMFQYC3MJPX2ZK8M7SGC2VD"
"NTUYN35IPFXGY5DPP3ZZA6MUQP4HK7VZRB6ZW856RX9H9AEBSKB2JBNGS8EIVCWMTUG27D6SUGJJHFEX"
"U4M3TGN4VQQJ5HW9WCS4FI7EWYVKRKFJXKX43MPQX82MDNXVYU45PP72ZG7MZRF7Z496BSQC2RCNMTYH"
"3DE6XU8N3ZHN9WGT4MJ7JXQY49NPVYY55VQ77Z9A6HTQH3HF65V8T4RK7RYQ55ZR8D29F69W8Z5RR8H3"
"9M7939R8";
	const char *base64AndHexEncoded =
"41414543417751464267634943516F4C4441304F4478415245684D554652595847426B6147787764"
"486838674953496A4A43556D4A7967704B6973734C5334764D4445794D7A51310A4E6A63344F546F"
"375044302B50304242516B4E4552555A4853456C4B5330784E546B395155564A5456465657563168"
"5A576C746358563566594746695932526C5A6D646F615770720A6247317562334278636E4E306458"
"5A3365486C3665337839666E2B4167594B44684957476834694A696F754D6A5936506B4A47536B35"
"53566C7065596D5A71626E4A32656E3643680A6F714F6B7061616E714B6D717136797472712B7773"
"624B7A744C573274376935757275387662362F774D484377385446787366497963724C7A4D334F7A"
"39445230745055316462580A324E6E6132397A6433742F6734654C6A354F586D352B6A7036757673"
"3765377638504879382F5431397666342B6672372F50332B0A";

	cout << "\nBase64, base32 and hex coding validation suite running...\n\n";

	fail = !TestFilter(HexEncoder().Ref(), data, 255, (const byte *)hexEncoded, strlen(hexEncoded));
	cout << (fail ? "FAILED    " : "passed    ");
	cout << "Hex Encoding\n";
	pass = pass && !fail;

	fail = !TestFilter(HexDecoder().Ref(), (const byte *)hexEncoded, strlen(hexEncoded), data, 255);
	cout << (fail ? "FAILED    " : "passed    ");
	cout << "Hex Decoding\n";
	pass = pass && !fail;

	fail = !TestFilter(Base32Encoder().Ref(), data, 255, (const byte *)base32Encoded, strlen(base32Encoded));
	cout << (fail ? "FAILED    " : "passed    ");
	cout << "Base32 Encoding\n";
	pass = pass && !fail;

	fail = !TestFilter(Base32Decoder().Ref(), (const byte *)base32Encoded, strlen(base32Encoded), data, 255);
	cout << (fail ? "FAILED    " : "passed    ");
	cout << "Base32 Decoding\n";
	pass = pass && !fail;

	fail = !TestFilter(Base64Encoder(new HexEncoder).Ref(), data, 255, (const byte *)base64AndHexEncoded, strlen(base64AndHexEncoded));
	cout << (fail ? "FAILED    " : "passed    ");
	cout << "Base64 Encoding\n";
	pass = pass && !fail;

	fail = !TestFilter(HexDecoder(new Base64Decoder).Ref(), (const byte *)base64AndHexEncoded, strlen(base64AndHexEncoded), data, 255);
	cout << (fail ? "FAILED    " : "passed    ");
	cout << "Base64 Decoding\n";
	pass = pass && !fail;

	return pass;
}

bool ValidateSHACAL2()
{
	cout << "\nSHACAL-2 validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	SHACAL2Encryption enc;  // 128 to 512-bits (16 to 64-bytes)
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(15) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 64 && pass1;
	pass1 = enc.StaticGetValidKeyLength(65) == 64 && pass1;
	pass1 = enc.StaticGetValidKeyLength(128) == 64 && pass1;
	pass1 = enc.StaticGetValidKeyLength(0) == enc.MinKeyLength() && pass1;
	pass1 = enc.StaticGetValidKeyLength(SIZE_MAX) == enc.MaxKeyLength() && pass1;

	SHACAL2Decryption dec;  // 128 to 512-bits (16 to 64-bytes)
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(15) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 64 && pass2;
	pass2 = dec.StaticGetValidKeyLength(65) == 64 && pass2;
	pass2 = dec.StaticGetValidKeyLength(128) == 64 && pass2;
	pass2 = dec.StaticGetValidKeyLength(0) == dec.MinKeyLength() && pass2;
	pass2 = dec.StaticGetValidKeyLength(SIZE_MAX) == dec.MaxKeyLength() && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/shacal2v.dat", true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<SHACAL2Encryption, SHACAL2Decryption>(16), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<SHACAL2Encryption, SHACAL2Decryption>(64), valdata, 10) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateCamellia()
{
	cout << "\nCamellia validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	CamelliaEncryption enc;
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(24) == 24 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(128) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(0) == enc.MinKeyLength() && pass1;
	pass1 = enc.StaticGetValidKeyLength(SIZE_MAX) == enc.MaxKeyLength() && pass1;

	CamelliaDecryption dec;
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(24) == 24 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(128) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(0) == dec.MinKeyLength() && pass2;
	pass2 = dec.StaticGetValidKeyLength(SIZE_MAX) == dec.MaxKeyLength() && pass2;
	cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(CRYPTOPP_DATA_DIR "TestData/camellia.dat", true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CamelliaEncryption, CamelliaDecryption>(16), valdata, 15) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CamelliaEncryption, CamelliaDecryption>(24), valdata, 15) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CamelliaEncryption, CamelliaDecryption>(32), valdata, 15) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateSalsa()
{
	cout << "\nSalsa validation suite running...\n";

	return RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/salsa.txt");
}

bool ValidateSosemanuk()
{
	cout << "\nSosemanuk validation suite running...\n";
	return RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/sosemanuk.txt");
}

bool ValidateVMAC()
{
	cout << "\nVMAC validation suite running...\n";
	return RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/vmac.txt");
}

bool ValidateCCM()
{
	cout << "\nAES/CCM validation suite running...\n";
	return RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/ccm.txt");
}

bool ValidateGCM()
{
	cout << "\nAES/GCM validation suite running...\n";
	cout << "\n2K tables:";
	bool pass = RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/gcm.txt", MakeParameters(Name::TableSize(), (int)2048));
	cout << "\n64K tables:";
	return RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/gcm.txt", MakeParameters(Name::TableSize(), (int)64*1024)) && pass;
}

bool ValidateCMAC()
{
	cout << "\nCMAC validation suite running...\n";
	return RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/cmac.txt");
}
