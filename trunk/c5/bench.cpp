// bench.cpp - written and placed in the public domain by Wei Dai

#define _CRT_SECURE_NO_DEPRECATE

#include "bench.h"
#include "crc.h"
#include "adler32.h"
#include "md2.h"
#include "md5.h"
#include "md5mac.h"
#include "sha.h"
#include "haval.h"
#include "tiger.h"
#include "ripemd.h"
#include "panama.h"
#include "whrlpool.h"
#include "idea.h"
#include "des.h"
#include "rc2.h"
#include "arc4.h"
#include "rc5.h"
#include "blowfish.h"
#include "wake.h"
#include "3way.h"
#include "safer.h"
#include "gost.h"
#include "shark.h"
#include "cast.h"
#include "square.h"
#include "skipjack.h"
#include "seal.h"
#include "rc6.h"
#include "mars.h"
#include "rijndael.h"
#include "twofish.h"
#include "serpent.h"
#include "shacal2.h"
#include "camellia.h"
#include "hmac.h"
#include "xormac.h"
#include "cbcmac.h"
#include "dmac.h"
#include "ttmac.h"
#include "blumshub.h"
#include "rng.h"
#include "files.h"
#include "hex.h"
#include "modes.h"
#include "mdc.h"
#include "lubyrack.h"
#include "tea.h"
#include "salsa.h"

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

double logtotal = 0;
unsigned int logcount = 0;

static const byte *const key=(byte *)"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

void OutputResultBytes(const char *name, double length, double timeTaken)
{
	double mbs = length / timeTaken / (1024*1024);
	cout << "<TR><TH>" << name;
	cout << "<TD>" << setprecision(3) << length / (1024*1024);
	cout << setiosflags(ios::fixed);
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << setprecision(3) << mbs << endl;
	cout << resetiosflags(ios::fixed);
	logtotal += log(mbs);
	logcount++;
}

void OutputResultOperations(const char *name, const char *operation, bool pc, unsigned long iterations, double timeTaken)
{
	cout << "<TR><TH>" << name << " " << operation << (pc ? " with precomputation" : "");
	cout << "<TD>" << iterations;
	cout << setiosflags(ios::fixed);
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << setprecision(2) << (1000*timeTaken/iterations) << endl;
	cout << resetiosflags(ios::fixed);

	logtotal += log(iterations/timeTaken);
	logcount++;
}

void BenchMark(const char *name, BlockTransformation &cipher, double timeTotal)
{
	const int BUF_SIZE = RoundDownToMultipleOf(1024U, cipher.OptimalNumberOfParallelBlocks() * cipher.BlockSize());
	SecByteBlock buf(BUF_SIZE);
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
	const int BUF_SIZE=1024;
	SecByteBlock buf(BUF_SIZE);
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
	const int BUF_SIZE=1024;
	SecByteBlock buf(BUF_SIZE);
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
	const int BUF_SIZE=1024;
	SecByteBlock buf(BUF_SIZE);
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

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkKeyed(const char *name, double timeTotal, const NameValuePairs &params = g_nullNameValuePairs, T *x=NULL)
{
	T c;
	c.SetKey(key, c.DefaultKeyLength(), CombinedNameValuePairs(params, MakeParameters(Name::IV(), key, false)));
	BenchMark(name, c, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkKeyedVariable(const char *name, double timeTotal, unsigned int keyLength, const NameValuePairs &params = g_nullNameValuePairs, T *x=NULL)
{
	T c;
	c.SetKey(key, keyLength, CombinedNameValuePairs(params, MakeParameters(Name::IV(), key, false)));
	BenchMark(name, c, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkKeyless(const char *name, double timeTotal, T *x=NULL)
{
	T c;
	BenchMark(name, c, timeTotal);
}

void BenchmarkAll(double t)
{
#if 1
	logtotal = 0;
	logcount = 0;

	cout << "<TABLE border=1><COLGROUP><COL align=left><COL align=right><COL align=right><COL align=right>" << endl;
	cout << "<THEAD><TR><TH>Algorithm<TH>Megabytes(2^20 bytes) Processed<TH>Time Taken<TH>MB/Second\n<TBODY>" << endl;

	BenchMarkKeyless<CRC32>("CRC-32", t);
	BenchMarkKeyless<Adler32>("Adler-32", t);
	BenchMarkKeyless<MD2>("MD2", t);
	BenchMarkKeyless<MD5>("MD5", t);
	BenchMarkKeyless<SHA>("SHA-1", t);
	BenchMarkKeyless<SHA256>("SHA-256", t);
#ifdef WORD64_AVAILABLE
	BenchMarkKeyless<SHA512>("SHA-512", t);
#endif
	BenchMarkKeyless<HAVAL3>("HAVAL (pass=3)", t);
	BenchMarkKeyless<HAVAL4>("HAVAL (pass=4)", t);
	BenchMarkKeyless<HAVAL5>("HAVAL (pass=5)", t);
#ifdef WORD64_AVAILABLE
	BenchMarkKeyless<Tiger>("Tiger", t);
#endif
	BenchMarkKeyless<RIPEMD160>("RIPE-MD160", t);
	BenchMarkKeyless<RIPEMD320>("RIPE-MD320", t);
	BenchMarkKeyless<RIPEMD128>("RIPE-MD128", t);
	BenchMarkKeyless<RIPEMD256>("RIPE-MD256", t);
	BenchMarkKeyless<PanamaHash<LittleEndian> >("Panama Hash (little endian)", t);
	BenchMarkKeyless<PanamaHash<BigEndian> >("Panama Hash (big endian)", t);
#ifdef WORD64_AVAILABLE
	BenchMarkKeyless<Whirlpool>("Whirlpool", t);
#endif
	BenchMarkKeyed<MDC<MD5>::Encryption>("MDC/MD5", t);
	BenchMarkKeyed<LR<MD5>::Encryption>("Luby-Rackoff/MD5", t);
	BenchMarkKeyed<DES::Encryption>("DES", t);
	BenchMarkKeyed<DES_XEX3::Encryption>("DES-XEX3", t);
	BenchMarkKeyed<DES_EDE3::Encryption>("DES-EDE3", t);
	BenchMarkKeyed<IDEA::Encryption>("IDEA", t);
	BenchMarkKeyed<RC2::Encryption>("RC2", t);
	BenchMarkKeyed<RC5::Encryption>("RC5 (r=16)", t);
	BenchMarkKeyed<Blowfish::Encryption>("Blowfish", t);
	BenchMarkKeyed<ThreeWayDecryption>("3-WAY", t);
	BenchMarkKeyed<TEA::Encryption>("TEA", t);
	BenchMarkKeyedVariable<SAFER_SK::Encryption>("SAFER (r=8)", t, 8);
	BenchMarkKeyed<GOST::Encryption>("GOST", t);
#ifdef WORD64_AVAILABLE
	BenchMarkKeyed<SHARK::Encryption>("SHARK (r=6)", t);
#endif
	BenchMarkKeyed<CAST128::Encryption>("CAST-128", t);
	BenchMarkKeyed<CAST256::Encryption>("CAST-256", t);
	BenchMarkKeyed<Square::Encryption>("Square", t);
	BenchMarkKeyed<SKIPJACK::Encryption>("SKIPJACK", t);
	BenchMarkKeyed<RC6::Encryption>("RC6", t);
	BenchMarkKeyed<MARS::Encryption>("MARS", t);
	BenchMarkKeyedVariable<Rijndael::Encryption>("Rijndael (128-bit key)", t, 16);
	BenchMarkKeyedVariable<Rijndael::Encryption>("Rijndael (192-bit key)", t, 24);
	BenchMarkKeyedVariable<Rijndael::Encryption>("Rijndael (256-bit key)", t, 32);
	BenchMarkKeyedVariable<CTR_Mode<Rijndael>::Encryption>("Rijndael (128) CTR", t, 16);
	BenchMarkKeyedVariable<OFB_Mode<Rijndael>::Encryption>("Rijndael (128) OFB", t, 16);
	BenchMarkKeyedVariable<CFB_Mode<Rijndael>::Encryption>("Rijndael (128) CFB", t, 16);
	BenchMarkKeyedVariable<CBC_Mode<Rijndael>::Encryption>("Rijndael (128) CBC", t, 16);
	BenchMarkKeyed<Twofish::Encryption>("Twofish", t);
	BenchMarkKeyed<Serpent::Encryption>("Serpent", t);
	BenchMarkKeyed<ARC4>("ARC4", t);
	BenchMarkKeyed<SEAL<BigEndian>::Encryption>("SEAL-3.0-BE", t);
	BenchMarkKeyed<SEAL<LittleEndian>::Encryption>("SEAL-3.0-LE", t);
	BenchMarkKeyed<WAKE_CFB<BigEndian>::Encryption>("WAKE-CFB-BE", t);
	BenchMarkKeyed<WAKE_CFB<LittleEndian>::Encryption>("WAKE-CFB-LE", t);
	BenchMarkKeyed<WAKE_OFB<BigEndian>::Encryption>("WAKE-OFB-BE", t);
	BenchMarkKeyed<WAKE_OFB<LittleEndian>::Encryption>("WAKE-OFB-LE", t);
	BenchMarkKeyed<PanamaCipher<LittleEndian>::Encryption>("Panama Cipher (little endian)", t);
	BenchMarkKeyed<PanamaCipher<BigEndian>::Encryption>("Panama Cipher (big endian)", t);
	BenchMarkKeyedVariable<SHACAL2::Encryption>("SHACAL-2 (128-bit key)", t, 16);
	BenchMarkKeyedVariable<SHACAL2::Encryption>("SHACAL-2 (512-bit key)", t, 64);
#ifdef WORD64_AVAILABLE
	BenchMarkKeyedVariable<Camellia::Encryption>("Camellia (128-bit key)", t, 16);
	BenchMarkKeyedVariable<Camellia::Encryption>("Camellia (256-bit key)", t, 32);
#endif
	BenchMarkKeyed<Salsa20::Encryption>("Salsa20", t);
	BenchMarkKeyed<Salsa20::Encryption>("Salsa20/12", t, MakeParameters(Name::Rounds(), 12));
	BenchMarkKeyed<Salsa20::Encryption>("Salsa20/8", t, MakeParameters(Name::Rounds(), 8));

	BenchMarkKeyed<MD5MAC>("MD5-MAC", t);
	BenchMarkKeyed<XMACC<MD5> >("XMACC/MD5", t);
	BenchMarkKeyed<HMAC<MD5> >("HMAC/MD5", t);
	BenchMarkKeyed<TTMAC>("Two-Track-MAC", t);
	BenchMarkKeyed<CBC_MAC<Rijndael> >("CBC-MAC/Rijndael", t);
	BenchMarkKeyed<DMAC<Rijndael> >("DMAC/Rijndael", t);

	{
		Integer p("CB6C,B8CE,6351,164F,5D0C,0C9E,9E31,E231,CF4E,D551,CBD0,E671,5D6A,7B06,D8DF,C4A7h");
		Integer q("FD2A,8594,A132,20CC,4E6D,DE77,3AAA,CF15,CD9E,E447,8592,FF46,CC77,87BE,9876,A2AFh");
		Integer s("63239752671357255800299643604761065219897634268887145610573595874544114193025997412441121667211431");
		BlumBlumShub c(p, q, s);
		BenchMark("BlumBlumShub 512", c, t);
	}
	{
		Integer p("FD2A,8594,A132,20CC,4E6D,DE77,3AAA,CF15,CD9E,E447,8592,FF46,CC77,87BE,9876,9E2C,"
				  "8572,64C3,4CF4,188A,44D4,2130,1135,7982,6FF6,EDD3,26F0,5FAA,BAF4,A81E,7ADC,B80Bh");
		Integer q("C8B9,5797,B349,6BA3,FD72,F2C0,A796,8A65,EE0F,B4BA,272F,4FEE,4DB1,06D5,ECEB,7142,"
				  "E8A8,E5A8,6BF9,A32F,BA37,BACC,8A75,8A6B,2DCE,D6EC,B515,980A,4BB1,08FB,6F2C,2383h");
		Integer s("3578,8F00,2965,71A4,4382,699F,45FD,3922,8238,241B,CEBA,0543,3443,E8D9,12FB,AC46,"
				  "7EC4,8505,EC9E,7EE8,5A23,9B2A,B615,D0C4,9448,F23A,ADEE,E850,1A7A,CA30,0B5B,A408,"
				  "D936,21BA,844E,BDD6,7848,3D1E,9137,CC87,DAA5,773B,D45A,C8BB,5392,1393,108B,6992,"
				  "74E3,C5E2,C235,A321,0111,3BA4,BAB4,1A2F,17EE,C371,DE67,01C9,0F3D,907A,B252,9BDDh");
		BlumBlumShub c(p, q, s);
		BenchMark("BlumBlumShub 1024", c, t);
	}
	{
		Integer p("EB56,978A,7BA7,B5D9,1383,4611,94F5,4766,FCEF,CF41,958A,FC41,43D0,839F,C56B,B568,"
				  "4ED3,9E5A,BABB,5ACE,8B11,CEBC,88A2,7C12,FFEE,E6E8,CF0A,E231,5BC2,DEDE,80B7,32F6,"
				  "340E,D8A6,B7DE,C779,7EE5,0E16,9C88,FC9F,2A0E,EE6C,7D47,C5F2,6B06,EB8C,F1C8,2E67,"
				  "5B82,8C28,4FB8,542F,2874,C355,CEEE,7A54,1B06,A8AB,8B66,6A5C,9DB2,72B8,74F3,7BC7h");
		Integer q("EB6B,3645,4591,8343,7331,7CAC,B02E,4BB9,DEF5,8EDC,1772,DB9B,9571,5FAB,1CDD,4FB1,"
				  "7B9A,07CD,E715,D448,F552,CBBD,D387,C037,DE70,6661,F360,D0E8,D42E,292A,9321,DDCB,"
				  "0BF9,C514,BFAC,3F2C,C06E,DF64,A9B8,50D6,AC4F,B9E4,014B,5624,2B40,A0D4,5D0B,6DD4,"
				  "0989,D00E,0268,99AB,21DB,0BB4,DB38,84DA,594F,575F,95AC,1B70,45E4,96C8,C6AD,CE67h");
		Integer s("C75A,8A0D,E231,295F,C08A,1716,8611,D5EC,E9EF,B565,90EC,58C0,57D0,DA7D,C6E6,DB00,"
				  "2282,1CA7,EA31,D64E,768C,0B19,8563,36DF,2226,F4EC,74A4,2844,2E8D,37E8,53DC,0172,"
				  "5F56,8CF9,B444,CA02,78B3,17AF,7C78,D320,16AE,AC3D,B97F,7259,1B8F,9C84,6A16,B878,"
				  "0595,70BB,9C52,18B5,9100,9C1F,E85A,4035,06F3,5F38,7462,F01D,0462,BFBC,A4CD,4A45,"
				  "3A77,E7F8,DED1,D6EF,CEF7,0937,CD3F,3AF1,4F88,932D,6D4B,002C,3735,304C,C5D3,B88A,"
				  "B57B,24B6,5346,9B46,5153,B7ED,B216,C181,B1C6,C52E,CD2B,E0AA,B1BB,0A93,C92E,4F79,"
				  "4931,E303,7C8F,A408,8ACF,56CD,6EC0,76A2,5015,6BA4,4C50,C44D,53B9,E168,5F84,B381,"
				  "2514,10B2,00E5,B4D1,4156,A2FE,0BF6,6F33,0A1B,91C6,31B8,1C90,02F1,FB1F,C494,8B65h");
		BlumBlumShub c(p, q, s);
		BenchMark("BlumBlumShub 2048", c, t);
	}
	cout << "</TABLE>" << endl;

	BenchmarkAll2(t);

	cout << "Throughput Geometric Average: " << setiosflags(ios::fixed) << exp(logtotal/logcount) << endl;

	time_t endTime = time(NULL);
	cout << "\nTest ended at " << asctime(localtime(&endTime));
#endif
}
