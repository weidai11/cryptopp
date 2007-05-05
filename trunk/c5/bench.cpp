// bench.cpp - written and placed in the public domain by Wei Dai

#define _CRT_SECURE_NO_DEPRECATE

#include "bench.h"
#include "crc.h"
#include "adler32.h"
#include "idea.h"
#include "des.h"
#include "rc5.h"
#include "blowfish.h"
#include "wake.h"
#include "cast.h"
#include "seal.h"
#include "rc6.h"
#include "mars.h"
#include "twofish.h"
#include "serpent.h"
#include "skipjack.h"
#include "cbcmac.h"
#include "dmac.h"
#include "aes.h"
#include "blumshub.h"
#include "rng.h"
#include "files.h"
#include "hex.h"
#include "modes.h"
#include "factory.h"

#include <time.h>
#include <math.h>
#include <iostream>
#include <iomanip>

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

#ifdef CLOCKS_PER_SEC
const double CLOCK_TICKS_PER_SECOND = (double)CLOCKS_PER_SEC;
#elif defined(CLK_TCK)
const double CLOCK_TICKS_PER_SECOND = (double)CLK_TCK;
#else
const double CLOCK_TICKS_PER_SECOND = 1000000.0;
#endif

double logtotal = 0, g_allocatedTime, g_hertz;
unsigned int logcount = 0;

static const byte *const key=(byte *)"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

void OutputResultBytes(const char *name, double length, double timeTaken)
{
	double mbs = length / timeTaken / (1024*1024);
	cout << "\n<TR><TH>" << name;
//	cout << "<TD>" << setprecision(3) << length / (1024*1024);
	cout << setiosflags(ios::fixed);
//	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << setprecision(0) << setiosflags(ios::fixed) << mbs;
	if (g_hertz)
		cout << "<TD>" << setprecision(1) << setiosflags(ios::fixed) << timeTaken * g_hertz / length;
	cout << resetiosflags(ios::fixed);
	logtotal += log(mbs);
	logcount++;
}

void OutputResultKeying(double iterations, double timeTaken)
{
	cout << "<TD>" << setprecision(3) << setiosflags(ios::fixed) << (1000*1000*timeTaken/iterations);
	if (g_hertz)
		cout << "<TD>" << setprecision(0) << setiosflags(ios::fixed) << timeTaken * g_hertz / iterations;
}

void OutputResultOperations(const char *name, const char *operation, bool pc, unsigned long iterations, double timeTaken)
{
	cout << "\n<TR><TH>" << name << " " << operation << (pc ? " with precomputation" : "");
//	cout << "<TD>" << iterations;
//	cout << setiosflags(ios::fixed);
//	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << setprecision(2) << setiosflags(ios::fixed) << (1000*timeTaken/iterations);
	if (g_hertz)
		cout << "<TD>" << setprecision(2) << setiosflags(ios::fixed) << timeTaken * g_hertz / iterations / 1000000;
	cout << resetiosflags(ios::fixed);

	logtotal += log(iterations/timeTaken);
	logcount++;
}

void BenchMark(const char *name, BlockTransformation &cipher, double timeTotal)
{
	const int BUF_SIZE = RoundUpToMultipleOf(2048U, cipher.OptimalNumberOfParallelBlocks() * cipher.BlockSize());
	AlignedSecByteBlock buf(BUF_SIZE);
	const int nBlocks = BUF_SIZE / cipher.BlockSize();
	clock_t start = clock();

	unsigned long i=0, blocks=1;
	double timeTaken;
	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			cipher.ProcessAndXorMultipleBlocks(buf, NULL, buf, nBlocks);
		timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

void BenchMark(const char *name, StreamTransformation &cipher, double timeTotal)
{
	const int BUF_SIZE=RoundUpToMultipleOf(2048U, cipher.OptimalBlockSize());
	AlignedSecByteBlock buf(BUF_SIZE);
	clock_t start = clock();

	unsigned long i=0, blocks=1;
	double timeTaken;
	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			cipher.ProcessString(buf, BUF_SIZE);
		timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

void BenchMark(const char *name, HashTransformation &ht, double timeTotal)
{
	const int BUF_SIZE=2048U;
	AlignedSecByteBlock buf(BUF_SIZE);
	LC_RNG rng((word32)time(NULL));
	rng.GenerateBlock(buf, BUF_SIZE);
	clock_t start = clock();

	unsigned long i=0, blocks=1;
	double timeTaken;
	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			ht.Update(buf, BUF_SIZE);
		timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

void BenchMark(const char *name, BufferedTransformation &bt, double timeTotal)
{
	const int BUF_SIZE=2048U;
	AlignedSecByteBlock buf(BUF_SIZE);
	LC_RNG rng((word32)time(NULL));
	rng.GenerateBlock(buf, BUF_SIZE);
	clock_t start = clock();

	unsigned long i=0, blocks=1;
	double timeTaken;
	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			bt.Put(buf, BUF_SIZE);
		timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	OutputResultBytes(name, double(blocks) * BUF_SIZE, timeTaken);
}

void BenchMarkKeying(SimpleKeyingInterface &c, size_t keyLength, const NameValuePairs &params)
{
	unsigned long iterations = 0;
	clock_t start = clock();
	double timeTaken;
	do
	{
		for (unsigned int i=0; i<1024; i++)
			c.SetKey(key, keyLength, params);
		timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND;
		iterations += 1024;
	}
	while (timeTaken < g_allocatedTime);

	OutputResultKeying(iterations, timeTaken);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkKeyed(const char *name, double timeTotal, const NameValuePairs &params = g_nullNameValuePairs, T *x=NULL)
{
	T c;
	c.SetKey(key, c.DefaultKeyLength(), CombinedNameValuePairs(params, MakeParameters(Name::IV(), key, false)));
	BenchMark(name, c, timeTotal);
	BenchMarkKeying(c, c.DefaultKeyLength(), CombinedNameValuePairs(params, MakeParameters(Name::IV(), key, false)));
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkKeyedVariable(const char *name, double timeTotal, unsigned int keyLength, const NameValuePairs &params = g_nullNameValuePairs, T *x=NULL)
{
	T c;
	c.SetKey(key, keyLength, CombinedNameValuePairs(params, MakeParameters(Name::IV(), key, false)));
	BenchMark(name, c, timeTotal);
	BenchMarkKeying(c, keyLength, CombinedNameValuePairs(params, MakeParameters(Name::IV(), key, false)));
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkKeyless(const char *name, double timeTotal, T *x=NULL)
{
	T c;
	BenchMark(name, c, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkByName(const char *factoryName, size_t keyLength = 0, const char *displayName=NULL, const NameValuePairs &params = g_nullNameValuePairs, T *x=NULL)
{
	std::string name = factoryName;
	if (displayName)
		name = displayName;
	else if (keyLength)
		name += " (" + IntToString(keyLength * 8) + "-bit key)";

	std::auto_ptr<T> obj(ObjectFactoryRegistry<T>::Registry().CreateObject(factoryName));
	if (!keyLength)
		keyLength = obj->DefaultKeyLength();
	obj->SetKey(key, keyLength, CombinedNameValuePairs(params, MakeParameters(Name::IV(), key, false)));
	BenchMark(name.c_str(), *obj, g_allocatedTime);
	BenchMarkKeying(*obj, keyLength, CombinedNameValuePairs(params, MakeParameters(Name::IV(), key, false)));
}

template <class T>
void BenchMarkByNameKeyLess(const char *factoryName, const char *displayName=NULL, const NameValuePairs &params = g_nullNameValuePairs, T *x=NULL)
{
	std::string name = factoryName;
	if (displayName)
		name = displayName;

	std::auto_ptr<T> obj(ObjectFactoryRegistry<T>::Registry().CreateObject(factoryName));
	BenchMark(name.c_str(), *obj, g_allocatedTime);
}

void BenchmarkAll(double t, double hertz)
{
#if 1
	logtotal = 0;
	logcount = 0;
	g_allocatedTime = t;
	g_hertz = hertz;

	const char *cpb, *cpk;
	if (g_hertz)
	{
		cpb = "<TH>Cycles Per Byte";
		cpk = "<TH>Cycles to<br>Setup Key and IV";
		cout << "CPU frequency of the test platform is " << g_hertz << " Hz.\n";
	}
	else
	{
		cpb = cpk = "";
		cout << "CPU frequency of the test platform was not provided.\n";
	}

	cout << "<TABLE border=1><COLGROUP><COL align=left><COL align=right><COL align=right><COL align=right><COL align=right>" << endl;
	cout << "<THEAD><TR><TH>Algorithm<TH>MiB/Second" << cpb << "<TH>Microseconds to<br>Setup Key and IV" << cpk << endl;

	cout << "\n<TBODY style=\"background: white\">";
	BenchMarkByName<MessageAuthenticationCode>("VMAC(AES)-64");
	BenchMarkByName<MessageAuthenticationCode>("VMAC(AES)-128");
	BenchMarkByName<MessageAuthenticationCode>("HMAC(SHA-1)");
	BenchMarkByName<MessageAuthenticationCode>("Two-Track-MAC");
	BenchMarkKeyed<CBC_MAC<AES> >("CBC-MAC/AES", t);
	BenchMarkKeyed<DMAC<AES> >("DMAC/AES", t);

	cout << "\n<TBODY style=\"background: yellow\">";
	BenchMarkKeyless<CRC32>("CRC-32", t);
	BenchMarkKeyless<Adler32>("Adler-32", t);
	BenchMarkByNameKeyLess<HashTransformation>("MD5");
	BenchMarkByNameKeyLess<HashTransformation>("SHA-1");
	BenchMarkByNameKeyLess<HashTransformation>("SHA-256");
#ifdef WORD64_AVAILABLE
	BenchMarkByNameKeyLess<HashTransformation>("SHA-512");
	BenchMarkByNameKeyLess<HashTransformation>("Tiger");
	BenchMarkByNameKeyLess<HashTransformation>("Whirlpool");
#endif
	BenchMarkByNameKeyLess<HashTransformation>("RIPEMD-160");
	BenchMarkByNameKeyLess<HashTransformation>("RIPEMD-320");
	BenchMarkByNameKeyLess<HashTransformation>("RIPEMD-128");
	BenchMarkByNameKeyLess<HashTransformation>("RIPEMD-256");

	cout << "\n<TBODY style=\"background: white\">";
	BenchMarkByName<SymmetricCipher>("Panama-LE");
	BenchMarkByName<SymmetricCipher>("Panama-BE");
	BenchMarkByName<SymmetricCipher>("Salsa20");
	BenchMarkByName<SymmetricCipher>("Salsa20", 0, "Salsa20/12", MakeParameters(Name::Rounds(), 12));
	BenchMarkByName<SymmetricCipher>("Salsa20", 0, "Salsa20/8", MakeParameters(Name::Rounds(), 8));
	BenchMarkByName<SymmetricCipher>("Sosemanuk");
	BenchMarkByName<SymmetricCipher>("MARC4");
	BenchMarkKeyed<SEAL<BigEndian>::Encryption>("SEAL-3.0-BE", t);
	BenchMarkKeyed<SEAL<LittleEndian>::Encryption>("SEAL-3.0-LE", t);
	BenchMarkKeyed<WAKE_OFB<BigEndian>::Encryption>("WAKE-OFB-BE", t);
	BenchMarkKeyed<WAKE_OFB<LittleEndian>::Encryption>("WAKE-OFB-LE", t);

	cout << "\n<TBODY style=\"background: yellow\">";
	BenchMarkByName<SymmetricCipher>("AES/ECB", 16);
	BenchMarkByName<SymmetricCipher>("AES/ECB", 24);
	BenchMarkByName<SymmetricCipher>("AES/ECB", 32);
	BenchMarkByName<SymmetricCipher>("AES/CTR", 16);
	BenchMarkByName<SymmetricCipher>("AES/OFB", 16);
	BenchMarkByName<SymmetricCipher>("AES/CFB", 16);
	BenchMarkByName<SymmetricCipher>("AES/CBC", 16);
	BenchMarkByName<SymmetricCipher>("Camellia/ECB", 16);
	BenchMarkByName<SymmetricCipher>("Camellia/ECB", 32);
	BenchMarkKeyed<Twofish::Encryption>("Twofish", t);
	BenchMarkKeyed<Serpent::Encryption>("Serpent", t);
	BenchMarkKeyed<CAST256::Encryption>("CAST-256", t);
	BenchMarkKeyed<RC6::Encryption>("RC6", t);
	BenchMarkKeyed<MARS::Encryption>("MARS", t);
	BenchMarkByName<SymmetricCipher>("SHACAL-2/ECB", 16);
	BenchMarkByName<SymmetricCipher>("SHACAL-2/ECB", 64);
	BenchMarkKeyed<DES::Encryption>("DES", t);
	BenchMarkKeyed<DES_XEX3::Encryption>("DES-XEX3", t);
	BenchMarkKeyed<DES_EDE3::Encryption>("DES-EDE3", t);
	BenchMarkKeyed<IDEA::Encryption>("IDEA", t);
	BenchMarkKeyed<RC5::Encryption>("RC5 (r=16)", t);
	BenchMarkKeyed<Blowfish::Encryption>("Blowfish", t);
	BenchMarkByName<SymmetricCipher>("TEA/ECB");
	BenchMarkByName<SymmetricCipher>("XTEA/ECB");
	BenchMarkKeyed<CAST128::Encryption>("CAST-128", t);
	BenchMarkKeyed<SKIPJACK::Encryption>("SKIPJACK", t);
	cout << "</TABLE>" << endl;

	BenchmarkAll2(t, hertz);

	cout << "Throughput Geometric Average: " << setiosflags(ios::fixed) << exp(logtotal/logcount) << endl;

	time_t endTime = time(NULL);
	cout << "\nTest ended at " << asctime(localtime(&endTime));
#endif
}
