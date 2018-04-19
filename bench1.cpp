// bench1.cpp - originally written and placed in the public domain by Wei Dai
//              CryptoPP::Test namespace added by JW in February 2017

#include "cryptlib.h"
#include "bench.h"
#include "validate.h"

#include "aes.h"
#include "kalyna.h"
#include "threefish.h"
#include "blumshub.h"
#include "files.h"
#include "filters.h"
#include "hex.h"
#include "modes.h"
#include "factory.h"
#include "smartptr.h"
#include "cpu.h"
#include "drbg.h"
#include "rdrand.h"
#include "padlkrng.h"
#include "stdcpp.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4355)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

#ifdef CLOCKS_PER_SEC
const double CLOCK_TICKS_PER_SECOND = (double)CLOCKS_PER_SEC;
#elif defined(CLK_TCK)
const double CLOCK_TICKS_PER_SECOND = (double)CLK_TCK;
#else
const double CLOCK_TICKS_PER_SECOND = 1000000.0;
#endif

const byte defaultKey[] = "0123456789" // 168 + NULL
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"00000000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000000";

double g_allocatedTime = 0.0, g_hertz = 0.0, g_logTotal = 0.0;
unsigned int g_logCount = 0;
time_t g_testBegin, g_testEnd;

void OutputResultBytes(const char *name, double length, double timeTaken)
{
	// Coverity finding, also see http://stackoverflow.com/a/34509163/608639.
	StreamState ss(std::cout);

	// Coverity finding
	if (length < 0.000001f) length = 0.000001f;
	if (timeTaken < 0.000001f) timeTaken = 0.000001f;

	double mbs = length / timeTaken / (1024*1024);
	std::cout << "\n<TR><TD>" << name;
	std::cout << std::setiosflags(std::ios::fixed);
	std::cout << "<TD>" << std::setprecision(0) << std::setiosflags(std::ios::fixed) << mbs;
	if (g_hertz > 1.0f)
	{
		const double cpb = timeTaken * g_hertz / length;
		if (cpb < 24.0f)
			std::cout << "<TD>" << std::setprecision(2) << std::setiosflags(std::ios::fixed) << cpb;
		else
			std::cout << "<TD>" << std::setprecision(1) << std::setiosflags(std::ios::fixed) << cpb;
	}
	g_logTotal += log(mbs);
	g_logCount++;
}

void OutputResultKeying(double iterations, double timeTaken)
{
	// Coverity finding, also see http://stackoverflow.com/a/34509163/608639.
	StreamState ss(std::cout);

	// Coverity finding
	if (iterations < 0.000001f) iterations = 0.000001f;
	if (timeTaken < 0.000001f) timeTaken = 0.000001f;

	std::cout << "<TD>" << std::setprecision(3) << std::setiosflags(std::ios::fixed) << (1000*1000*timeTaken/iterations);

	// Coverity finding
	if (g_hertz > 1.0f)
		std::cout << "<TD>" << std::setprecision(0) << std::setiosflags(std::ios::fixed) << timeTaken * g_hertz / iterations;
}

void OutputResultOperations(const char *name, const char *operation, bool pc, unsigned long iterations, double timeTaken)
{
	// Coverity finding, also see http://stackoverflow.com/a/34509163/608639.
	StreamState ss(std::cout);

	// Coverity finding
	if (!iterations) iterations++;
	if (timeTaken < 0.000001f) timeTaken = 0.000001f;

	std::cout << "\n<TR><TD>" << name << " " << operation << (pc ? " with precomputation" : "");
	std::cout << "<TD>" << std::setprecision(2) << std::setiosflags(std::ios::fixed) << (1000*timeTaken/iterations);

	// Coverity finding
	if (g_hertz > 1.0f)
	{
		const double t = timeTaken * g_hertz / iterations / 1000000;
		std::cout << "<TD>" << std::setprecision(2) << std::setiosflags(std::ios::fixed) << t;
	}

	g_logTotal += log(iterations/timeTaken);
	g_logCount++;
}

/*
void BenchMark(const char *name, BlockTransformation &cipher, double timeTotal)
{
	const int BUF_SIZE = RoundUpToMultipleOf(2048U, cipher.OptimalNumberOfParallelBlocks() * cipher.BlockSize());
	AlignedSecByteBlock buf(BUF_SIZE);
	buf.SetMark(16);

	const int nBlocks = BUF_SIZE / cipher.BlockSize();
	unsigned long i=0, blocks=1;
	double timeTaken;

	clock_t start = ::clock();
	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			cipher.ProcessAndXorMultipleBlocks(buf, NULLPTR, buf, nBlocks);
		timeTaken = double(::clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}
*/

void BenchMark(const char *name, StreamTransformation &cipher, double timeTotal)
{
	const int BUF_SIZE=RoundUpToMultipleOf(2048U, cipher.OptimalBlockSize());
	AlignedSecByteBlock buf(BUF_SIZE);
	Test::GlobalRNG().GenerateBlock(buf, BUF_SIZE);
	buf.SetMark(16);

	unsigned long i=0, blocks=1;
	double timeTaken;

	clock_t start = ::clock();
	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			cipher.ProcessString(buf, BUF_SIZE);
		timeTaken = double(::clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

void BenchMark(const char *name, AuthenticatedSymmetricCipher &cipher, double timeTotal)
{
	if (cipher.NeedsPrespecifiedDataLengths())
		cipher.SpecifyDataLengths(0, cipher.MaxMessageLength(), 0);

	BenchMark(name, static_cast<StreamTransformation &>(cipher), timeTotal);
}

void BenchMark(const char *name, HashTransformation &ht, double timeTotal)
{
	const int BUF_SIZE=2048U;
	AlignedSecByteBlock buf(BUF_SIZE);
	Test::GlobalRNG().GenerateBlock(buf, BUF_SIZE);
	buf.SetMark(16);

	unsigned long i=0, blocks=1;
	double timeTaken;

	clock_t start = ::clock();
	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			ht.Update(buf, BUF_SIZE);
		timeTaken = double(::clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

void BenchMark(const char *name, BufferedTransformation &bt, double timeTotal)
{
	const int BUF_SIZE=2048U;
	AlignedSecByteBlock buf(BUF_SIZE);
	Test::GlobalRNG().GenerateBlock(buf, BUF_SIZE);
	buf.SetMark(16);

	unsigned long i=0, blocks=1;
	double timeTaken;

	clock_t start = ::clock();
	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			bt.Put(buf, BUF_SIZE);
		timeTaken = double(::clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

void BenchMark(const char *name, RandomNumberGenerator &rng, double timeTotal)
{
	const int BUF_SIZE = 2048U;
	AlignedSecByteBlock buf(BUF_SIZE);
	Test::GlobalRNG().GenerateBlock(buf, BUF_SIZE);
	buf.SetMark(16);

	SymmetricCipher * cipher = dynamic_cast<SymmetricCipher*>(&rng);
	if (cipher != NULLPTR)
	{
		const size_t size = cipher->DefaultKeyLength();
		if (cipher->IsResynchronizable())
			cipher->SetKeyWithIV(buf, size, buf+size);
		else
			cipher->SetKey(buf, size);
	}

	unsigned long long blocks = 1;
	double timeTaken;

	clock_t start = ::clock();
	do
	{
		rng.GenerateBlock(buf, buf.size());
		blocks++;
		timeTaken = double(::clock() - start) / CLOCK_TICKS_PER_SECOND;
	} while (timeTaken < timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

// Hack, but we probably need a KeyedRandomNumberGenerator interface
//  and a few methods to generalize keying a RNG. X917RNG, Hash_DRBG,
//  HMAC_DRBG, AES/CFB RNG and a few others could use it. "A few others"
//  includes BLAKE2, ChaCha and Poly1305 when used as a RNG.
void BenchMark(const char *name, NIST_DRBG &rng, double timeTotal)
{
	const int BUF_SIZE = 2048U;
	AlignedSecByteBlock buf(BUF_SIZE);
	Test::GlobalRNG().GenerateBlock(buf, BUF_SIZE);
	buf.SetMark(16);

	rng.IncorporateEntropy(buf, rng.MinEntropyLength());
	unsigned long long blocks = 1;
	double timeTaken;

	clock_t start = ::clock();
	do
	{
		rng.GenerateBlock(buf, buf.size());
		blocks++;
		timeTaken = double(::clock() - start) / CLOCK_TICKS_PER_SECOND;
	} while (timeTaken < timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

void BenchMarkKeying(SimpleKeyingInterface &c, size_t keyLength, const NameValuePairs &params)
{
	unsigned long iterations = 0;
	double timeTaken;

	clock_t start = ::clock();
	do
	{
		for (unsigned int i=0; i<1024; i++)
			c.SetKey(defaultKey, keyLength, params);
		timeTaken = double(::clock() - start) / CLOCK_TICKS_PER_SECOND;
		iterations += 1024;
	}
	while (timeTaken < g_allocatedTime);

	OutputResultKeying(iterations, timeTaken);
}

template <class T_FactoryOutput, class T_Interface>
void BenchMarkByName2(const char *factoryName, size_t keyLength = 0, const char *displayName=NULLPTR, const NameValuePairs &params = g_nullNameValuePairs)
{
	std::string name(factoryName ? factoryName : "");
	member_ptr<T_FactoryOutput> obj(ObjectFactoryRegistry<T_FactoryOutput>::Registry().CreateObject(name.c_str()));

	if (!keyLength)
		keyLength = obj->DefaultKeyLength();

	if (displayName)
		name = displayName;
	else if (keyLength)
		name += " (" + IntToString(keyLength * 8) + "-bit key)";

	const int blockSize = params.GetIntValueWithDefault(Name::BlockSize(), 0);
	obj->SetKey(defaultKey, keyLength, CombinedNameValuePairs(params, MakeParameters(Name::IV(), ConstByteArrayParameter(defaultKey, blockSize ? blockSize : obj->IVSize()), false)));
	BenchMark(name.c_str(), *static_cast<T_Interface *>(obj.get()), g_allocatedTime);
	BenchMarkKeying(*obj, keyLength, CombinedNameValuePairs(params, MakeParameters(Name::IV(), ConstByteArrayParameter(defaultKey, blockSize ? blockSize : obj->IVSize()), false)));
}

template <class T_FactoryOutput>
void BenchMarkByName(const char *factoryName, size_t keyLength = 0, const char *displayName=NULLPTR, const NameValuePairs &params = g_nullNameValuePairs)
{
	CRYPTOPP_UNUSED(params);
	BenchMarkByName2<T_FactoryOutput, T_FactoryOutput>(factoryName, keyLength, displayName, params);
}

template <class T>
void BenchMarkByNameKeyLess(const char *factoryName, const char *displayName=NULLPTR, const NameValuePairs &params = g_nullNameValuePairs)
{
	CRYPTOPP_UNUSED(params);
	std::string name = factoryName;
	if (displayName)
		name = displayName;

	member_ptr<T> obj(ObjectFactoryRegistry<T>::Registry().CreateObject(factoryName));
	BenchMark(name.c_str(), *obj, g_allocatedTime);
}

void AddHtmlHeader()
{
	// HTML5
	std::cout << "<!DOCTYPE HTML>";
	std::cout << "\n<HTML lang=\"en\">";

	std::cout << "\n<HEAD>";
	std::cout << "\n<META charset=\"UTF-8\">";
	std::cout << "\n<TITLE>Speed Comparison of Popular Crypto Algorithms</TITLE>";
	std::cout << "\n<STYLE>\n  table {border-collapse: collapse;}";
	std::cout << "\n  table, th, td, tr {border: 1px solid black;}\n</STYLE>";
	std::cout << "\n</HEAD>";

	std::cout << "\n<BODY>";

	std::cout << "\n<H1><A href=\"http://www.cryptopp.com\">Crypto++</A> " << CRYPTOPP_VERSION / 100;
	std::cout << '.' << (CRYPTOPP_VERSION % 100) / 10 << '.' << CRYPTOPP_VERSION % 10 << " Benchmarks</H1>";

	std::cout << "\n<P>Here are speed benchmarks for some commonly used cryptographic algorithms.</P>";

	if (g_hertz > 1.0f)
		std::cout << "\n<P>CPU frequency of the test platform is " << g_hertz << " Hz.</P>";
	else
		std::cout << "\n<P>CPU frequency of the test platform was not provided.</P>" << std::endl;
}

void AddHtmlFooter()
{
	std::cout << "\n</BODY>";
	std::cout << "\n</HTML>" << std::endl;
}

void BenchmarkWithCommand(int argc, const char* const argv[])
{
	std::string command(argv[1]);
	float runningTime(argc >= 3 ? Test::StringToValue<float, true>(argv[2]) : 1.0f);
	float cpuFreq(argc >= 4 ? Test::StringToValue<float, true>(argv[3])*float(1e9) : 0.0f);
	std::string algoName(argc >= 5 ? argv[4] : "");

	if (command == "b")  // All benchmarks
		Benchmark(Test::All, runningTime, cpuFreq);
	else if (command == "b3")  // Public key algorithms
		Test::Benchmark(Test::PublicKey, runningTime, cpuFreq);
	else if (command == "b2")  // Shared key algorithms
		Test::Benchmark(Test::SharedKey, runningTime, cpuFreq);
	else if (command == "b1")  // Unkeyed algorithms
		Test::Benchmark(Test::Unkeyed, runningTime, cpuFreq);
}

void Benchmark(Test::TestClass suites, double t, double hertz)
{
	g_allocatedTime = t;
	g_hertz = hertz;

	AddHtmlHeader();

	g_testBegin = ::time(NULLPTR);

	if (static_cast<int>(suites) == 0 || static_cast<int>(suites) > TestLast)
		suites = Test::All;

	// Unkeyed algorithms
	if (suites & Test::Unkeyed)
	{
		std::cout << "\n<BR>";
		Benchmark1(t, hertz);
	}

	// Shared key algorithms
	if (suites & Test::SharedKey)
	{
		std::cout << "\n<BR>";
		Benchmark2(t, hertz);
	}

	// Public key algorithms
	if (suites & Test::PublicKey)
	{
		std::cout << "\n<BR>";
		Benchmark3(t, hertz);
	}

	g_testEnd = ::time(NULLPTR);

	{
		StreamState state(std::cout);
		std::cout << "\n<P>Throughput Geometric Average: " << std::setiosflags(std::ios::fixed);
		std::cout << std::exp(g_logTotal/(g_logCount > 0.0f ? g_logCount : 1.0f)) << std::endl;
	}

	std::cout << "\n<P>Test started at " << TimeToString(g_testBegin);
	std::cout << "\n<BR>Test ended at " << TimeToString(g_testEnd);
	std::cout << std::endl;

	AddHtmlFooter();
}

void Benchmark1(double t, double hertz)
{
	g_allocatedTime = t;
	g_hertz = hertz;

	const char *cpb;
	if (g_hertz > 1.0f)
		cpb = "<TH>Cycles Per Byte";
	else
		cpb = "";

	std::cout << "\n<TABLE>";

	std::cout << "\n<COLGROUP><COL style=\"text-align: left;\"><COL style=\"text-align: right;\">";
	std::cout << "<COL style=\"text-align: right;\">";
	std::cout << "\n<THEAD style=\"background: #F0F0F0\">";
	std::cout << "\n<TR><TH>Algorithm<TH>MiB/Second" << cpb;

	std::cout << "\n<TBODY style=\"background: white;\">";
	{
#ifdef NONBLOCKING_RNG_AVAILABLE
		BenchMarkByNameKeyLess<RandomNumberGenerator>("NonblockingRng");
#endif
#ifdef OS_RNG_AVAILABLE
		BenchMarkByNameKeyLess<RandomNumberGenerator>("AutoSeededRandomPool");
		BenchMarkByNameKeyLess<RandomNumberGenerator>("AutoSeededX917RNG(AES)");
#endif
		BenchMarkByNameKeyLess<RandomNumberGenerator>("MT19937");
#if (CRYPTOPP_BOOL_X86)
		if (HasPadlockRNG())
			BenchMarkByNameKeyLess<RandomNumberGenerator>("PadlockRNG");
#endif
#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
		if (HasRDRAND())
			BenchMarkByNameKeyLess<RandomNumberGenerator>("RDRAND");
		if (HasRDSEED())
			BenchMarkByNameKeyLess<RandomNumberGenerator>("RDSEED");
#endif
		BenchMarkByNameKeyLess<RandomNumberGenerator>("AES/OFB RNG");
		BenchMarkByNameKeyLess<NIST_DRBG>("Hash_DRBG(SHA1)");
		BenchMarkByNameKeyLess<NIST_DRBG>("Hash_DRBG(SHA256)");
		BenchMarkByNameKeyLess<NIST_DRBG>("HMAC_DRBG(SHA1)");
		BenchMarkByNameKeyLess<NIST_DRBG>("HMAC_DRBG(SHA256)");
	}

	std::cout << "\n<TBODY style=\"background: yellow;\">";
	{
		BenchMarkByNameKeyLess<HashTransformation>("CRC32");
		BenchMarkByNameKeyLess<HashTransformation>("CRC32C");
		BenchMarkByNameKeyLess<HashTransformation>("Adler32");
		BenchMarkByNameKeyLess<HashTransformation>("MD5");
		BenchMarkByNameKeyLess<HashTransformation>("SHA-1");
		BenchMarkByNameKeyLess<HashTransformation>("SHA-256");
		BenchMarkByNameKeyLess<HashTransformation>("SHA-512");
		BenchMarkByNameKeyLess<HashTransformation>("SHA3-224");
		BenchMarkByNameKeyLess<HashTransformation>("SHA3-256");
		BenchMarkByNameKeyLess<HashTransformation>("SHA3-384");
		BenchMarkByNameKeyLess<HashTransformation>("SHA3-512");
		BenchMarkByNameKeyLess<HashTransformation>("Keccak-224");
		BenchMarkByNameKeyLess<HashTransformation>("Keccak-256");
		BenchMarkByNameKeyLess<HashTransformation>("Keccak-384");
		BenchMarkByNameKeyLess<HashTransformation>("Keccak-512");
		BenchMarkByNameKeyLess<HashTransformation>("Tiger");
		BenchMarkByNameKeyLess<HashTransformation>("Whirlpool");
		BenchMarkByNameKeyLess<HashTransformation>("RIPEMD-160");
		BenchMarkByNameKeyLess<HashTransformation>("RIPEMD-320");
		BenchMarkByNameKeyLess<HashTransformation>("RIPEMD-128");
		BenchMarkByNameKeyLess<HashTransformation>("RIPEMD-256");
		BenchMarkByNameKeyLess<HashTransformation>("SM3");
		BenchMarkByNameKeyLess<HashTransformation>("BLAKE2s");
		BenchMarkByNameKeyLess<HashTransformation>("BLAKE2b");
	}

	std::cout << "\n</TABLE>" << std::endl;
}

void Benchmark2(double t, double hertz)
{
	g_allocatedTime = t;
	g_hertz = hertz;

	const char *cpb, *cpk;
	if (g_hertz > 1.0f)
	{
		cpb = "<TH>Cycles Per Byte";
		cpk = "<TH>Cycles to<BR>Setup Key and IV";
	}
	else
	{
		cpb = cpk = "";
	}

	std::cout << "\n<TABLE>";
	std::cout << "\n<COLGROUP><COL style=\"text-align: left;\"><COL style=\"text-align: right;\"><COL style=";
	std::cout << "\"text-align: right;\"><COL style=\"text-align: right;\"><COL style=\"text-align: right;\">";
	std::cout << "\n<THEAD style=\"background: #F0F0F0\">";
	std::cout << "\n<TR><TH>Algorithm<TH>MiB/Second" << cpb;
	std::cout << "<TH>Microseconds to<BR>Setup Key and IV" << cpk;

	std::cout << "\n<TBODY style=\"background: white;\">";
	{
#if CRYPTOPP_AESNI_AVAILABLE
		if (HasCLMUL())
			BenchMarkByName2<AuthenticatedSymmetricCipher, MessageAuthenticationCode>("AES/GCM", 0, "GMAC(AES)");
		else
#elif CRYPTOPP_ARM_PMULL_AVAILABLE
		if (HasPMULL())
			BenchMarkByName2<AuthenticatedSymmetricCipher, MessageAuthenticationCode>("AES/GCM", 0, "GMAC(AES)");
		else
#endif
		{
			BenchMarkByName2<AuthenticatedSymmetricCipher, MessageAuthenticationCode>("AES/GCM", 0, "GMAC(AES) (2K tables)", MakeParameters(Name::TableSize(), 2048));
			BenchMarkByName2<AuthenticatedSymmetricCipher, MessageAuthenticationCode>("AES/GCM", 0, "GMAC(AES) (64K tables)", MakeParameters(Name::TableSize(), 64 * 1024));
		}

		BenchMarkByName<MessageAuthenticationCode>("VMAC(AES)-64");
		BenchMarkByName<MessageAuthenticationCode>("VMAC(AES)-128");
		BenchMarkByName<MessageAuthenticationCode>("HMAC(SHA-1)");
		BenchMarkByName<MessageAuthenticationCode>("HMAC(SHA-256)");
		BenchMarkByName<MessageAuthenticationCode>("Two-Track-MAC");
		BenchMarkByName<MessageAuthenticationCode>("CMAC(AES)");
		BenchMarkByName<MessageAuthenticationCode>("DMAC(AES)");
		BenchMarkByName<MessageAuthenticationCode>("Poly1305(AES)");
		BenchMarkByName<MessageAuthenticationCode>("BLAKE2s");
		BenchMarkByName<MessageAuthenticationCode>("BLAKE2b");
		BenchMarkByName<MessageAuthenticationCode>("SipHash-2-4");
		BenchMarkByName<MessageAuthenticationCode>("SipHash-4-8");
	}

	std::cout << "\n<TBODY style=\"background: yellow;\">";
	{
		BenchMarkByName<SymmetricCipher>("Panama-LE");
		BenchMarkByName<SymmetricCipher>("Panama-BE");
		BenchMarkByName<SymmetricCipher>("Salsa20");
		BenchMarkByName<SymmetricCipher>("Salsa20", 0, "Salsa20/12", MakeParameters(Name::Rounds(), 12));
		BenchMarkByName<SymmetricCipher>("Salsa20", 0, "Salsa20/8", MakeParameters(Name::Rounds(), 8));
		BenchMarkByName<SymmetricCipher>("ChaCha20");
		BenchMarkByName<SymmetricCipher>("ChaCha12");
		BenchMarkByName<SymmetricCipher>("ChaCha8");
		BenchMarkByName<SymmetricCipher>("Sosemanuk");
		BenchMarkByName<SymmetricCipher>("MARC4");
		BenchMarkByName<SymmetricCipher>("SEAL-3.0-LE");
		BenchMarkByName<SymmetricCipher>("WAKE-OFB-LE");
	}

	std::cout << "\n<TBODY style=\"background: white;\">";
	{
		BenchMarkByName<SymmetricCipher>("AES/CTR", 16);
		BenchMarkByName<SymmetricCipher>("AES/CTR", 24);
		BenchMarkByName<SymmetricCipher>("AES/CTR", 32);
		BenchMarkByName<SymmetricCipher>("AES/CBC", 16);
		BenchMarkByName<SymmetricCipher>("AES/CBC", 24);
		BenchMarkByName<SymmetricCipher>("AES/CBC", 32);
		BenchMarkByName<SymmetricCipher>("AES/OFB", 16);
		BenchMarkByName<SymmetricCipher>("AES/CFB", 16);
		BenchMarkByName<SymmetricCipher>("AES/ECB", 16);
		BenchMarkByName<SymmetricCipher>("ARIA/CTR", 16);
		BenchMarkByName<SymmetricCipher>("ARIA/CTR", 32);
		BenchMarkByName<SymmetricCipher>("Camellia/CTR", 16);
		BenchMarkByName<SymmetricCipher>("Camellia/CTR", 32);
		BenchMarkByName<SymmetricCipher>("Twofish/CTR");
		BenchMarkByName<SymmetricCipher>("Threefish-256(256)/CTR", 32);
		BenchMarkByName<SymmetricCipher>("Threefish-512(512)/CTR", 64);
		BenchMarkByName<SymmetricCipher>("Threefish-1024(1024)/CTR", 128);
		BenchMarkByName<SymmetricCipher>("Serpent/CTR");
		BenchMarkByName<SymmetricCipher>("CAST-128/CTR");
		BenchMarkByName<SymmetricCipher>("CAST-256/CTR");
		BenchMarkByName<SymmetricCipher>("RC6/CTR");
		BenchMarkByName<SymmetricCipher>("MARS/CTR");
		BenchMarkByName<SymmetricCipher>("SHACAL-2/CTR", 16);
		BenchMarkByName<SymmetricCipher>("SHACAL-2/CTR", 64);
		BenchMarkByName<SymmetricCipher>("DES/CTR");
		BenchMarkByName<SymmetricCipher>("DES-XEX3/CTR");
		BenchMarkByName<SymmetricCipher>("DES-EDE3/CTR");
		BenchMarkByName<SymmetricCipher>("IDEA/CTR");
		BenchMarkByName<SymmetricCipher>("RC5/CTR", 0, "RC5 (r=16)");
		BenchMarkByName<SymmetricCipher>("Blowfish/CTR");
		BenchMarkByName<SymmetricCipher>("TEA/CTR");
		BenchMarkByName<SymmetricCipher>("XTEA/CTR");
		BenchMarkByName<SymmetricCipher>("SKIPJACK/CTR");
		BenchMarkByName<SymmetricCipher>("SEED/CTR", 0, "SEED/CTR (1/2 K table)");
		BenchMarkByName<SymmetricCipher>("SM4/CTR");

		BenchMarkByName<SymmetricCipher>("Kalyna-128/CTR", 16, "Kalyna-128(128)/CTR (128-bit key)");
		BenchMarkByName<SymmetricCipher>("Kalyna-128/CTR", 32, "Kalyna-128(256)/CTR (256-bit key)");
		BenchMarkByName<SymmetricCipher>("Kalyna-256/CTR", 32, "Kalyna-256(256)/CTR (256-bit key)");
		BenchMarkByName<SymmetricCipher>("Kalyna-256/CTR", 64, "Kalyna-256(512)/CTR (512-bit key)");
		BenchMarkByName<SymmetricCipher>("Kalyna-512/CTR", 64, "Kalyna-512(512)/CTR (512-bit key)");

		BenchMarkByName<SymmetricCipher>("SIMON-64/CTR", 12, "SIMON-64(96)/CTR (96-bit key)");
		BenchMarkByName<SymmetricCipher>("SIMON-64/CTR", 16, "SIMON-64(128)/CTR (128-bit key)");
		BenchMarkByName<SymmetricCipher>("SIMON-128/CTR", 16, "SIMON-128(128)/CTR (128-bit key)");
		BenchMarkByName<SymmetricCipher>("SIMON-128/CTR", 24, "SIMON-128(192)/CTR (192-bit key)");
		BenchMarkByName<SymmetricCipher>("SIMON-128/CTR", 32, "SIMON-128(256)/CTR (256-bit key)");

		BenchMarkByName<SymmetricCipher>("SPECK-64/CTR", 12, "SPECK-64(96)/CTR (96-bit key)");
		BenchMarkByName<SymmetricCipher>("SPECK-64/CTR", 16, "SPECK-64(128)/CTR (128-bit key)");
		BenchMarkByName<SymmetricCipher>("SPECK-128/CTR", 16, "SPECK-128(128)/CTR (128-bit key)");
		BenchMarkByName<SymmetricCipher>("SPECK-128/CTR", 24, "SPECK-128(192)/CTR (192-bit key)");
		BenchMarkByName<SymmetricCipher>("SPECK-128/CTR", 32, "SPECK-128(256)/CTR (256-bit key)");
	}

	std::cout << "\n<TBODY style=\"background: yellow;\">";
	{
#if CRYPTOPP_AESNI_AVAILABLE
		if (HasCLMUL())
			BenchMarkByName2<AuthenticatedSymmetricCipher, AuthenticatedSymmetricCipher>("AES/GCM", 0, "AES/GCM");
		else
#elif CRYPTOPP_ARM_PMULL_AVAILABLE
		if (HasPMULL())
			BenchMarkByName2<AuthenticatedSymmetricCipher, AuthenticatedSymmetricCipher>("AES/GCM", 0, "AES/GCM");
		else
#endif
		{
			BenchMarkByName2<AuthenticatedSymmetricCipher, AuthenticatedSymmetricCipher>("AES/GCM", 0, "AES/GCM (2K tables)", MakeParameters(Name::TableSize(), 2048));
			BenchMarkByName2<AuthenticatedSymmetricCipher, AuthenticatedSymmetricCipher>("AES/GCM", 0, "AES/GCM (64K tables)", MakeParameters(Name::TableSize(), 64 * 1024));
		}
		BenchMarkByName2<AuthenticatedSymmetricCipher, AuthenticatedSymmetricCipher>("AES/CCM");
		BenchMarkByName2<AuthenticatedSymmetricCipher, AuthenticatedSymmetricCipher>("AES/EAX");
	}

	std::cout << "\n</TABLE>" << std::endl;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
