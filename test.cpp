// test.cpp - originally written and placed in the public domain by Wei Dai
//            CryptoPP::Test namespace added by JW in February 2017
//            scoped_main added to CryptoPP::Test namespace by JW in July 2017
//            Also see http://github.com/weidai11/cryptopp/issues/447

#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "dll.h"
#include "cryptlib.h"
#include "aes.h"
#include "filters.h"
#include "md5.h"
#include "ripemd.h"
#include "rng.h"
#include "gzip.h"
#include "default.h"
#include "randpool.h"
#include "ida.h"
#include "base64.h"
#include "factory.h"
#include "whrlpool.h"
#include "tiger.h"
#include "smartptr.h"
#include "pkcspad.h"
#include "stdcpp.h"
#include "osrng.h"
#include "ossig.h"
#include "trap.h"

#include "validate.h"
#include "bench.h"

#include <iostream>
#include <sstream>
#include <locale>
#include <ctime>

#ifdef CRYPTOPP_WIN32_AVAILABLE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#if defined(CRYPTOPP_UNIX_AVAILABLE) || defined(CRYPTOPP_BSD_AVAILABLE)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define UNIX_PATH_FAMILY 1
#endif

#if defined(CRYPTOPP_OSX_AVAILABLE)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#define UNIX_PATH_FAMILY 1
#endif

#if (_MSC_VER >= 1000)
#include <crtdbg.h>		// for the debug heap
#endif

#if defined(__MWERKS__) && defined(macintosh)
#include <console.h>
#endif

#ifdef _OPENMP
# include <omp.h>
#endif

#ifdef __BORLANDC__
#pragma comment(lib, "cryptlib_bds.lib")
#endif

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

// If CRYPTOPP_USE_AES_GENERATOR is 1 then AES/OFB based is used.
// Otherwise the OS random number generator is used.
#define CRYPTOPP_USE_AES_GENERATOR 1

// Global namespace, provided by other source files
void FIPS140_SampleApplication();
void RegisterFactories(CryptoPP::Test::TestClass suites);
int (*AdhocTest)(int argc, char *argv[]) = NULLPTR;

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

const int MAX_PHRASE_LENGTH=250;
std::string g_argvPathHint="";

void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed);
std::string RSAEncryptString(const char *pubFilename, const char *seed, const char *message);
std::string RSADecryptString(const char *privFilename, const char *ciphertext);
void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename);
bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename);

void DigestFile(const char *file);
void HmacFile(const char *hexKey, const char *file);

void AES_CTR_Encrypt(const char *hexKey, const char *hexIV, const char *infile, const char *outfile);

std::string EncryptString(const char *plaintext, const char *passPhrase);
std::string DecryptString(const char *ciphertext, const char *passPhrase);

void EncryptFile(const char *in, const char *out, const char *passPhrase);
void DecryptFile(const char *in, const char *out, const char *passPhrase);

void SecretShareFile(int threshold, int nShares, const char *filename, const char *seed);
void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames);

void InformationDisperseFile(int threshold, int nShares, const char *filename);
void InformationRecoverFile(int threshold, const char *outFilename, char *const *inFilenames);

void GzipFile(const char *in, const char *out, int deflate_level);
void GunzipFile(const char *in, const char *out);

void Base64Encode(const char *infile, const char *outfile);
void Base64Decode(const char *infile, const char *outfile);
void HexEncode(const char *infile, const char *outfile);
void HexDecode(const char *infile, const char *outfile);

void FIPS140_GenerateRandomFiles();

bool Validate(int, bool, const char *);
void SetArgvPathHint(const char* argv0, std::string& pathHint);

ANONYMOUS_NAMESPACE_BEGIN
#if (CRYPTOPP_USE_AES_GENERATOR)
OFB_Mode<AES>::Encryption s_globalRNG;
#else
NonblockingRng s_globalRNG;
#endif
NAMESPACE_END

RandomNumberGenerator & GlobalRNG()
{
	return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
}

// Global seed used for the self tests
std::string s_globalSeed;
void PrintSeedAndThreads();

// See misc.h and trap.h for comments and usage
#if defined(CRYPTOPP_DEBUG) && defined(UNIX_SIGNALS_AVAILABLE)
static const SignalHandler<SIGTRAP, false> s_dummyHandler;
// static const DebugTrapHandler s_dummyHandler;
#endif

int scoped_main(int argc, char *argv[])
{
#ifdef _CRTDBG_LEAK_CHECK_DF
	// Turn on leak-checking
	int tempflag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
	tempflag |= _CRTDBG_LEAK_CHECK_DF;
	_CrtSetDbgFlag( tempflag );
#endif

#ifdef _SUNPRO_CC
	// No need for thread safety for the test program
	cout.set_safe_flag(stream_MT::unsafe_object);
	cin.set_safe_flag(stream_MT::unsafe_object);
#endif

	// A hint to help locate TestData/ and TestVectors/ after install.
	SetArgvPathHint(argv[0], g_argvPathHint);

	try
	{
		RegisterFactories(All);

		// Some editors have problems with the '\0' character when redirecting output.
		s_globalSeed = IntToString(time(NULLPTR));
		s_globalSeed.resize(16, ' ');

#if (CRYPTOPP_USE_AES_GENERATOR)
		// Fetch the SymmetricCipher interface, not the RandomNumberGenerator
		//  interface, to key the underlying cipher. If CRYPTOPP_USE_AES_GENERATOR is 1
		//  then AES/OFB based is used. Otherwise the OS random number generator is used.
		SymmetricCipher& cipher = dynamic_cast<SymmetricCipher&>(GlobalRNG());
		cipher.SetKeyWithIV((byte *)s_globalSeed.data(), 16, (byte *)s_globalSeed.data());
#endif

		std::string command, executableName, macFilename;

		if (argc < 2)
			command = 'h';
		else
			command = argv[1];

		if (command == "g")
		{
			char thisSeed[1024], privFilename[128], pubFilename[128];
			unsigned int keyLength;

			std::cout << "Key length in bits: ";
			std::cin >> keyLength;

			std::cout << "\nSave private key to file: ";
			std::cin >> privFilename;

			std::cout << "\nSave public key to file: ";
			std::cin >> pubFilename;

			std::cout << "\nRandom Seed: ";
			std::ws(std::cin);
			std::cin.getline(thisSeed, 1024);

			GenerateRSAKey(keyLength, privFilename, pubFilename, thisSeed);
		}
		else if (command == "rs")
			RSASignFile(argv[2], argv[3], argv[4]);
		else if (command == "rv")
		{
			bool verified = RSAVerifyFile(argv[2], argv[3], argv[4]);
			std::cout << (verified ? "valid signature" : "invalid signature") << std::endl;
		}
		else if (command == "r")
		{
			char privFilename[128], pubFilename[128];
			char thisSeed[1024], message[1024];

			std::cout << "Private key file: ";
			std::cin >> privFilename;

			std::cout << "\nPublic key file: ";
			std::cin >> pubFilename;

			std::cout << "\nRandom Seed: ";
			std::ws(std::cin);
			std::cin.getline(thisSeed, 1024);

			std::cout << "\nMessage: ";
			std::cin.getline(message, 1024);

			std::string ciphertext = RSAEncryptString(pubFilename, thisSeed, message);
			std::cout << "\nCiphertext: " << ciphertext << std::endl;

			std::string decrypted = RSADecryptString(privFilename, ciphertext.c_str());
			std::cout << "\nDecrypted: " << decrypted << std::endl;
		}
		else if (command == "mt")
		{
			MaurerRandomnessTest mt;
			FileStore fs(argv[2]);
			fs.TransferAllTo(mt);
			std::cout << "Maurer Test Value: " << mt.GetTestValue() << std::endl;
		}
		else if (command == "mac_dll")
		{
			std::string fname(argv[2] ? argv[2] : "");

			// sanity check on file size
			std::fstream dllFile(fname.c_str(), std::ios::in | std::ios::out | std::ios::binary);
			if (!dllFile.good())
			{
				std::cerr << "Failed to open file \"" << fname << "\"\n";
				return 1;
			}

			std::ifstream::pos_type fileEnd = dllFile.seekg(0, std::ios_base::end).tellg();
			if (fileEnd > 20*1000*1000)
			{
				std::cerr << "Input file " << fname << " is too large";
				std::cerr << "(size is " << fileEnd << ").\n";
				return 1;
			}

			// read file into memory
			unsigned int fileSize = (unsigned int)fileEnd;
			SecByteBlock buf(fileSize);
			dllFile.seekg(0, std::ios_base::beg);
			dllFile.read((char *)buf.begin(), fileSize);

			// find positions of relevant sections in the file, based on version 8 of documentation from http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
			word32 coffPos = *(word16 *)(void *)(buf+0x3c);
			word32 optionalHeaderPos = coffPos + 24;
			word16 optionalHeaderMagic = *(word16 *)(void *)(buf+optionalHeaderPos);
			if (optionalHeaderMagic != 0x10b && optionalHeaderMagic != 0x20b)
			{
				std::cerr << "Target file is not a PE32 or PE32+ image.\n";
				return 3;
			}
			word32 checksumPos = optionalHeaderPos + 64;
			word32 certificateTableDirectoryPos = optionalHeaderPos + (optionalHeaderMagic == 0x10b ? 128 : 144);
			word32 certificateTablePos = *(word32 *)(void *)(buf+certificateTableDirectoryPos);
			word32 certificateTableSize = *(word32 *)(void *)(buf+certificateTableDirectoryPos+4);
			if (certificateTableSize != 0)
				std::cerr << "Warning: certificate table (IMAGE_DIRECTORY_ENTRY_SECURITY) of target image is not empty.\n";

			// find where to place computed MAC
			byte mac[] = CRYPTOPP_DUMMY_DLL_MAC;
			byte *found = std::search(buf.begin(), buf.end(), mac+0, mac+sizeof(mac));
			if (found == buf.end())
			{
				std::cerr << "MAC placeholder not found. The MAC may already be placed.\n";
				return 2;
			}
			word32 macPos = (unsigned int)(found-buf.begin());

			// compute MAC
			member_ptr<MessageAuthenticationCode> pMac(NewIntegrityCheckingMAC());
			CRYPTOPP_ASSERT(pMac->DigestSize() == sizeof(mac));
			MeterFilter f(new HashFilter(*pMac, new ArraySink(mac, sizeof(mac))));
			f.AddRangeToSkip(0, checksumPos, 4);
			f.AddRangeToSkip(0, certificateTableDirectoryPos, 8);
			f.AddRangeToSkip(0, macPos, sizeof(mac));
			f.AddRangeToSkip(0, certificateTablePos, certificateTableSize);
			f.PutMessageEnd(buf.begin(), buf.size());

			// Encode MAC
			std::string hexMac;
			HexEncoder encoder;
			encoder.Put(mac, sizeof(mac)), encoder.MessageEnd();
			hexMac.resize(static_cast<size_t>(encoder.MaxRetrievable()));
			encoder.Get(reinterpret_cast<byte*>(&hexMac[0]), hexMac.size());

			// Report MAC and location
			std::cout << "Placing MAC " << hexMac << " in " << fname << " at file offset " << macPos;
			std::cout << " (0x" << std::hex << macPos << std::dec << ").\n";

			// place MAC
			dllFile.seekg(macPos, std::ios_base::beg);
			dllFile.write((char *)mac, sizeof(mac));
		}
		else if (command == "m")
			DigestFile(argv[2]);
		else if (command == "tv")
		{
			// TestDataFile() adds CRYPTOPP_DATA_DIR as required
			std::string fname = (argv[2] ? argv[2] : "all");
			if (fname.find(".txt") == std::string::npos)
				fname += ".txt";
			if (fname.find("TestVectors") == std::string::npos)
				fname = "TestVectors/" + fname;

			PrintSeedAndThreads();
			return !RunTestDataFile(fname.c_str());
		}
		else if (command == "t")
		{
			// VC60 workaround: use char array instead of std::string to workaround MSVC's getline bug
			char passPhrase[MAX_PHRASE_LENGTH], plaintext[1024];

			std::cout << "Passphrase: ";
			std::cin.getline(passPhrase, MAX_PHRASE_LENGTH);

			std::cout << "\nPlaintext: ";
			std::cin.getline(plaintext, sizeof(plaintext));

			std::string ciphertext = EncryptString(plaintext, passPhrase);
			std::cout << "\nCiphertext: " << ciphertext << std::endl;

			std::string decrypted = DecryptString(ciphertext.c_str(), passPhrase);
			std::cout << "\nDecrypted: " << decrypted << std::endl;

			return 0;
		}
		else if (command == "e64")
			Base64Encode(argv[2], argv[3]);
		else if (command == "d64")
			Base64Decode(argv[2], argv[3]);
		else if (command == "e16")
			HexEncode(argv[2], argv[3]);
		else if (command == "d16")
			HexDecode(argv[2], argv[3]);
		else if (command == "e" || command == "d")
		{
			char passPhrase[MAX_PHRASE_LENGTH];
			std::cout << "Passphrase: ";
			std::cin.getline(passPhrase, MAX_PHRASE_LENGTH);
			if (command == "e")
				EncryptFile(argv[2], argv[3], passPhrase);
			else
				DecryptFile(argv[2], argv[3], passPhrase);
		}
		else if (command == "ss")
		{
			char thisSeed[1024];
			std::cout << "\nRandom Seed: ";
			std::ws(std::cin);
			std::cin.getline(thisSeed, sizeof(thisSeed));
			SecretShareFile(StringToValue<int, true>(argv[2]), StringToValue<int, true>(argv[3]), argv[4], thisSeed);
		}
		else if (command == "sr")
			SecretRecoverFile(argc-3, argv[2], argv+3);
		else if (command == "id")
			InformationDisperseFile(StringToValue<int, true>(argv[2]), StringToValue<int, true>(argv[3]), argv[4]);
		else if (command == "ir")
			InformationRecoverFile(argc-3, argv[2], argv+3);
		else if (command == "v" || command == "vv")
			return !Validate(argc>2 ? StringToValue<int, true>(argv[2]) : 0, argv[1][1] == 'v', argc>3 ? argv[3] : NULLPTR);
		else if (command.substr(0,1) == "b") // "b", "b1", "b2", ...
			BenchmarkWithCommand(argc, argv);
		else if (command == "z")
			GzipFile(argv[3], argv[4], argv[2][0]-'0');
		else if (command == "u")
			GunzipFile(argv[2], argv[3]);
		else if (command == "fips")
			FIPS140_SampleApplication();
		else if (command == "fips-rand")
			FIPS140_GenerateRandomFiles();
		else if (command == "a")
		{
			if (AdhocTest)
				return (*AdhocTest)(argc, argv);
			else
			{
				std::cerr << "AdhocTest not defined.\n";
				return 1;
			}
		}
		else if (command == "hmac")
			HmacFile(argv[2], argv[3]);
		else if (command == "ae")
			AES_CTR_Encrypt(argv[2], argv[3], argv[4], argv[5]);
		else if (command == "h")
		{
			FileSource usage(DataDir("TestData/usage.dat").c_str(), true, new FileSink(std::cout));
			return 1;
		}
		else if (command == "V")
		{
			std::cout << CRYPTOPP_VERSION / 100 << '.' << (CRYPTOPP_VERSION % 100) / 10 << '.' << CRYPTOPP_VERSION % 10 << std::endl;
		}
		else
		{
			std::cerr << "Unrecognized command. Run \"cryptest h\" to obtain usage information.\n";
			return 1;
		}
		return 0;
	}
	catch(const Exception &e)
	{
		std::cout << "\nException caught: " << e.what() << std::endl;
		return -1;
	}
	catch(const std::exception &e)
	{
		std::cout << "\nstd::exception caught: " << e.what() << std::endl;
		return -2;
	}
} // main()

void SetArgvPathHint(const char* argv0, std::string& pathHint)
{
# if (PATH_MAX > 0)  // Posix
	size_t path_max = (size_t)PATH_MAX;
#elif (MAX_PATH > 0)  // Microsoft
	size_t path_max = (size_t)MAX_PATH;
#else
	size_t path_max = 260;
#endif

	// OS X and Solaris provide a larger path using pathconf than MAX_PATH.
	// Also see https://stackoverflow.com/a/33249023/608639 for FreeBSD.
#if defined(_PC_PATH_MAX)
	long ret = pathconf(argv0, _PC_PATH_MAX);
	const size_t old_path_max = path_max;
	if (SafeConvert(ret, path_max) == false)
		path_max = old_path_max;
#endif

	const size_t argLen = std::strlen(argv0);
	if (argLen >= path_max)
		return; // Can't use realpath safely
	pathHint = std::string(argv0, argLen);

#if defined(AT_EXECFN)
	if (getauxval(AT_EXECFN))
		pathHint = getauxval(AT_EXECFN);
#elif defined(_MSC_VER)
	char* pgmptr = NULLPTR;
	errno_t err = _get_pgmptr(&pgmptr);
	if (err == 0 && pgmptr != NULLPTR)
		pathHint = pgmptr;
#elif defined(CRYPTOPP_OSX_AVAILABLE)
	std::string t(path_max, (char)0);
	unsigned int len = (unsigned int)t.size();
	if (_NSGetExecutablePath(&t[0], &len) == 0)
	{
		t.resize(len);
		std::swap(pathHint, t);
	}
#elif defined(sun) || defined(__sun)
	if (getexecname())
		pathHint = getexecname();
#endif

#if (_POSIX_C_SOURCE >= 200809L) || (_XOPEN_SOURCE >= 700)
	char* resolved = realpath (pathHint.c_str(), NULLPTR);
	if (resolved != NULLPTR)
	{
		pathHint = resolved;
		std::free(resolved);
	}
#elif defined(UNIX_PATH_FAMILY)
	std::string resolved(path_max, (char)0);
	char* r = realpath (pathHint.c_str(), &resolved[0]);
	if (r != NULLPTR)
	{
		resolved.resize(std::strlen(&resolved[0]));
		std::swap(pathHint, resolved);
	}
#endif

#if defined(UNIX_PATH_FAMILY)
	// Is it possible for realpath to fail?
	struct stat buf; int x;
	x = lstat(pathHint.c_str(), &buf);
	if (x != 0 || S_ISLNK(buf.st_mode))
		pathHint.clear();
#endif

	// Trim the executable name, leave the path with a slash.
	std::string::size_type pos = pathHint.find_last_of("\\/");
	if (pos != std::string::npos)
		pathHint.erase(pos+1);
}

void FIPS140_GenerateRandomFiles()
{
#ifdef OS_RNG_AVAILABLE
	DefaultAutoSeededRNG rng;
	RandomNumberStore store(rng, ULONG_MAX);

	for (unsigned int i=0; i<100000; i++)
		store.TransferTo(FileSink((IntToString(i) + ".rnd").c_str()).Ref(), 20000);
#else
	std::cout << "OS provided RNG not available.\n";
	exit(-1);
#endif
}

void PrintSeedAndThreads()
{
	std::cout << "Using seed: " << s_globalSeed << std::endl;

#ifdef _OPENMP
	int tc = 0;
	#pragma omp parallel
	{
		tc = omp_get_num_threads();
	}

	std::cout << "OpenMP version " << (int)_OPENMP << ", ";
	std::cout << tc << (tc == 1 ? " thread" : " threads") << std::endl;
#endif
}

SecByteBlock HexDecodeString(const char *hex)
{
	StringSource ss(hex, true, new HexDecoder);
	SecByteBlock result((size_t)ss.MaxRetrievable());
	ss.Get(result, result.size());
	return result;
}

void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{
	// DEREncode() changed to Save() at Issue 569.
	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.AccessMaterial().Save(privFile);
	privFile.MessageEnd();

	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.AccessMaterial().Save(pubFile);
	pubFile.MessageEnd();
}

std::string RSAEncryptString(const char *pubFilename, const char *seed, const char *message)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor pub(pubFile);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	std::string result;
	StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
	return result;
}

std::string RSADecryptString(const char *privFilename, const char *ciphertext)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile);

	std::string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
	return result;
}

void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSASS<PKCS1v15, SHA1>::Signer priv(privFile);
	FileSource f(messageFilename, true, new SignerFilter(GlobalRNG(), priv, new HexEncoder(new FileSink(signatureFilename))));
}

bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSASS<PKCS1v15, SHA1>::Verifier pub(pubFile);

	FileSource signatureFile(signatureFilename, true, new HexDecoder);
	if (signatureFile.MaxRetrievable() != pub.SignatureLength())
		return false;
	SecByteBlock signature(pub.SignatureLength());
	signatureFile.Get(signature, signature.size());

	SignatureVerificationFilter *verifierFilter = new SignatureVerificationFilter(pub);
	verifierFilter->Put(signature, pub.SignatureLength());
	FileSource f(messageFilename, true, verifierFilter);

	return verifierFilter->GetLastResult();
}

void DigestFile(const char *filename)
{
	SHA1 sha;
	RIPEMD160 ripemd;
	SHA256 sha256;
	Tiger tiger;
	SHA512 sha512;
	Whirlpool whirlpool;

	vector_member_ptrs<HashFilter> filters(6);
	filters[0].reset(new HashFilter(sha));
	filters[1].reset(new HashFilter(ripemd));
	filters[2].reset(new HashFilter(tiger));
	filters[3].reset(new HashFilter(sha256));
	filters[4].reset(new HashFilter(sha512));
	filters[5].reset(new HashFilter(whirlpool));

	member_ptr<ChannelSwitch> channelSwitch(new ChannelSwitch);
	size_t i;
	for (i=0; i<filters.size(); i++)
		channelSwitch->AddDefaultRoute(*filters[i]);
	FileSource(filename, true, channelSwitch.release());

	HexEncoder encoder(new FileSink(std::cout), false);
	for (i=0; i<filters.size(); i++)
	{
		std::cout << filters[i]->AlgorithmName() << ": ";
		filters[i]->TransferTo(encoder);
		std::cout << "\n";
	}
}

void HmacFile(const char *hexKey, const char *file)
{
	member_ptr<MessageAuthenticationCode> mac;
	if (strcmp(hexKey, "selftest") == 0)
	{
		std::cerr << "Computing HMAC/SHA1 value for self test.\n";
		mac.reset(NewIntegrityCheckingMAC());
	}
	else
	{
		std::string decodedKey;
		StringSource(hexKey, true, new HexDecoder(new StringSink(decodedKey)));
		mac.reset(new HMAC<SHA1>((const byte *)decodedKey.data(), decodedKey.size()));
	}
	FileSource(file, true, new HashFilter(*mac, new HexEncoder(new FileSink(std::cout))));
}

void AES_CTR_Encrypt(const char *hexKey, const char *hexIV, const char *infile, const char *outfile)
{
	SecByteBlock key = HexDecodeString(hexKey);
	SecByteBlock iv = HexDecodeString(hexIV);
	CTR_Mode<AES>::Encryption aes(key, key.size(), iv);
	FileSource(infile, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
}

std::string EncryptString(const char *instr, const char *passPhrase)
{
	std::string outstr;

	DefaultEncryptorWithMAC encryptor(passPhrase, new HexEncoder(new StringSink(outstr)));
	encryptor.Put((byte *)instr, strlen(instr));
	encryptor.MessageEnd();

	return outstr;
}

std::string DecryptString(const char *instr, const char *passPhrase)
{
	std::string outstr;

	HexDecoder decryptor(new DefaultDecryptorWithMAC(passPhrase, new StringSink(outstr)));
	decryptor.Put((byte *)instr, strlen(instr));
	decryptor.MessageEnd();

	return outstr;
}

void EncryptFile(const char *in, const char *out, const char *passPhrase)
{
	FileSource f(in, true, new DefaultEncryptorWithMAC(passPhrase, new FileSink(out)));
}

void DecryptFile(const char *in, const char *out, const char *passPhrase)
{
	FileSource f(in, true, new DefaultDecryptorWithMAC(passPhrase, new FileSink(out)));
}

void SecretShareFile(int threshold, int nShares, const char *filename, const char *seed)
{
	CRYPTOPP_ASSERT(nShares >= 1 && nShares<=1000);
	if (nShares < 1 || nShares > 1000)
		throw InvalidArgument("SecretShareFile: " + IntToString(nShares) + " is not in range [1, 1000]");

	RandomPool rng;
	rng.IncorporateEntropy((byte *)seed, strlen(seed));

	ChannelSwitch *channelSwitch = NULLPTR;
	FileSource source(filename, false, new SecretSharing(rng, threshold, nShares, channelSwitch = new ChannelSwitch));

	// Be careful of the type of Sink used. An ArraySink will stop writing data once the array
	//    is full. Also see http://groups.google.com/forum/#!topic/cryptopp-users/XEKKLCEFH3Y.
	vector_member_ptrs<FileSink> fileSinks(nShares);
	std::string channel;
	for (int i=0; i<nShares; i++)
	{
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new FileSink((std::string(filename)+extension).c_str()));

		channel = WordToString<word32>(i);
		fileSinks[i]->Put((const byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
	}

	source.PumpAll();
}

void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
	CRYPTOPP_ASSERT(threshold >= 1 && threshold <=1000);
	if (threshold < 1 || threshold > 1000)
		throw InvalidArgument("SecretRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

	SecretRecovery recovery(threshold, new FileSink(outFilename));

	vector_member_ptrs<FileSource> fileSources(threshold);
	SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		fileSources[i].reset(new FileSource(inFilenames[i], false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
	}

	while (fileSources[0]->Pump(256))
		for (i=1; i<threshold; i++)
			fileSources[i]->Pump(256);

	for (i=0; i<threshold; i++)
		fileSources[i]->PumpAll();
}

void InformationDisperseFile(int threshold, int nShares, const char *filename)
{
	CRYPTOPP_ASSERT(threshold >= 1 && threshold <=1000);
	if (threshold < 1 || threshold > 1000)
		throw InvalidArgument("InformationDisperseFile: " + IntToString(nShares) + " is not in range [1, 1000]");

	ChannelSwitch *channelSwitch = NULLPTR;
	FileSource source(filename, false, new InformationDispersal(threshold, nShares, channelSwitch = new ChannelSwitch));

	// Be careful of the type of Sink used. An ArraySink will stop writing data once the array
	//    is full. Also see http://groups.google.com/forum/#!topic/cryptopp-users/XEKKLCEFH3Y.
	vector_member_ptrs<FileSink> fileSinks(nShares);
	std::string channel;
	for (int i=0; i<nShares; i++)
	{
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new FileSink((std::string(filename)+extension).c_str()));

		channel = WordToString<word32>(i);
		fileSinks[i]->Put((const byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
	}

	source.PumpAll();
}

void InformationRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
	CRYPTOPP_ASSERT(threshold<=1000);
	if (threshold < 1 || threshold > 1000)
		throw InvalidArgument("InformationRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

	InformationRecovery recovery(threshold, new FileSink(outFilename));

	vector_member_ptrs<FileSource> fileSources(threshold);
	SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		fileSources[i].reset(new FileSource(inFilenames[i], false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
	}

	while (fileSources[0]->Pump(256))
		for (i=1; i<threshold; i++)
			fileSources[i]->Pump(256);

	for (i=0; i<threshold; i++)
		fileSources[i]->PumpAll();
}

void GzipFile(const char *in, const char *out, int deflate_level)
{
//	FileSource(in, true, new Gzip(new FileSink(out), deflate_level));

	// use a filter graph to compare decompressed data with original
	//
	// Source ----> Gzip ------> Sink
	//    \           |
	//	    \       Gunzip
	//		  \       |
	//		    \     v
	//		      > ComparisonFilter

	EqualityComparisonFilter comparison;

	Gunzip gunzip(new ChannelSwitch(comparison, "0"));
	gunzip.SetAutoSignalPropagation(0);

	FileSink sink(out);

	ChannelSwitch *cs;
	Gzip gzip(cs = new ChannelSwitch(sink), deflate_level);
	cs->AddDefaultRoute(gunzip);

	cs = new ChannelSwitch(gzip);
	cs->AddDefaultRoute(comparison, "1");
	FileSource source(in, true, cs);

	comparison.ChannelMessageSeriesEnd("0");
	comparison.ChannelMessageSeriesEnd("1");
}

void GunzipFile(const char *in, const char *out)
{
	FileSource(in, true, new Gunzip(new FileSink(out)));
}

void Base64Encode(const char *in, const char *out)
{
	FileSource(in, true, new Base64Encoder(new FileSink(out)));
}

void Base64Decode(const char *in, const char *out)
{
	FileSource(in, true, new Base64Decoder(new FileSink(out)));
}

void HexEncode(const char *in, const char *out)
{
	FileSource(in, true, new HexEncoder(new FileSink(out)));
}

void HexDecode(const char *in, const char *out)
{
	FileSource(in, true, new HexDecoder(new FileSink(out)));
}

bool Validate(int alg, bool thorough, const char *seedInput)
{
	bool result;

	// Some editors have problems with the '\0' character when redirecting output.
	//   seedInput is argv[3] when issuing 'cryptest.exe v all <seed>'
	if (seedInput != NULLPTR)
	{
		s_globalSeed = seedInput;
		s_globalSeed.resize(16, ' ');
	}

#if (CRYPTOPP_USE_AES_GENERATOR)
		// Fetch the OFB_Mode<AES> interface, not the RandomNumberGenerator
		//  interface, to key the underlying cipher. If CRYPTOPP_USE_AES_GENERATOR is 1
		//  then AES/OFB based is used. Otherwise the OS random number generator is used.
		SymmetricCipher& cipher = dynamic_cast<SymmetricCipher&>(GlobalRNG());
		cipher.SetKeyWithIV((byte *)s_globalSeed.data(), 16, (byte *)s_globalSeed.data());
#endif

	g_testBegin = ::time(NULLPTR);
	PrintSeedAndThreads();

	// TODO: we need to group these tests like benchmarks...
	switch (alg)
	{
	case 0: result = ValidateAll(thorough); break;
	case 1: result = TestSettings(); break;
	case 2: result = TestOS_RNG(); break;
//	case 3: result = TestSecRandom(); break;
	case 4: result = ValidateMD5(); break;
	case 5: result = ValidateSHA(); break;
	case 6: result = ValidateDES(); break;
	case 7: result = ValidateIDEA(); break;
	case 8: result = ValidateARC4(); break;
	case 9: result = ValidateRC5(); break;
	case 10: result = ValidateBlowfish(); break;
//	case 11: result = ValidateDiamond2(); break;
	case 12: result = ValidateThreeWay(); break;
	case 13: result = ValidateBBS(); break;
	case 14: result = ValidateDH(); break;
	case 15: result = ValidateX25519(); break;
	case 16: result = ValidateRSA(); break;
	case 17: result = ValidateElGamal(); break;
	case 18: result = ValidateDSA(thorough); break;
//	case 18: result = ValidateHAVAL(); break;
	case 19: result = ValidateSAFER(); break;
	case 20: result = ValidateLUC(); break;
	case 21: result = ValidateRabin(); break;
//	case 22: result = ValidateBlumGoldwasser(); break;
	case 23: result = ValidateECP(); break;
	case 24: result = ValidateEC2N(); break;
//	case 25: result = ValidateMD5MAC(); break;
	case 26: result = ValidateGOST(); break;
	case 27: result = ValidateTiger(); break;
	case 28: result = ValidateRIPEMD(); break;
	case 29: result = ValidateHMAC(); break;
//	case 30: result = ValidateXMACC(); break;
	case 31: result = ValidateSHARK(); break;
	case 32: result = ValidateLUC_DH(); break;
	case 33: result = ValidateLUC_DL(); break;
	case 34: result = ValidateSEAL(); break;
	case 35: result = ValidateCAST(); break;
	case 36: result = ValidateSquare(); break;
	case 37: result = ValidateRC2(); break;
	case 38: result = ValidateRC6(); break;
	case 39: result = ValidateMARS(); break;
	case 40: result = ValidateRW(); break;
	case 41: result = ValidateMD2(); break;
	case 42: result = ValidateNR(); break;
	case 43: result = ValidateMQV(); break;
	case 44: result = ValidateRijndael(); break;
	case 45: result = ValidateTwofish(); break;
	case 46: result = ValidateSerpent(); break;
	case 47: result = ValidateCipherModes(); break;
	case 48: result = ValidateCRC32(); break;
	case 49: result = ValidateCRC32C(); break;
	case 50: result = ValidateECDSA(); break;
	case 51: result = ValidateECGDSA(thorough); break;
	case 52: result = ValidateXTR_DH(); break;
	case 53: result = ValidateSKIPJACK(); break;
	case 54: result = ValidateSHA2(); break;
	case 55: result = ValidatePanama(); break;
	case 56: result = ValidateAdler32(); break;
	case 57: result = ValidateMD4(); break;
	case 58: result = ValidatePBKDF(); break;
	case 59: result = ValidateHKDF(); break;
	case 60: result = ValidateScrypt(); break;
	case 61: result = ValidateESIGN(); break;
	case 62: result = ValidateDLIES(); break;
	case 63: result = ValidateBaseCode(); break;
	case 64: result = ValidateSHACAL2(); break;
	case 65: result = ValidateARIA(); break;
	case 66: result = ValidateCamellia(); break;
	case 67: result = ValidateWhirlpool(); break;
	case 68: result = ValidateTTMAC(); break;
	case 70: result = ValidateSalsa(); break;
	case 71: result = ValidateChaCha(); break;
	case 72: result = ValidateChaChaTLS(); break;
	case 73: result = ValidateSosemanuk(); break;
	case 74: result = ValidateRabbit(); break;
	case 75: result = ValidateHC128(); break;
	case 76: result = ValidateHC256(); break;
	case 80: result = ValidateVMAC(); break;
	case 81: result = ValidateCCM(); break;
	case 82: result = ValidateGCM(); break;
	case 83: result = ValidateCMAC(); break;
	case 84: result = ValidateSM3(); break;
	case 85: result = ValidateBLAKE2s(); break;
	case 86: result = ValidateBLAKE2b(); break;
	case 87: result = ValidatePoly1305(); break;
	case 88: result = ValidateSipHash(); break;
	case 89: result = ValidateHashDRBG(); break;
	case 90: result = ValidateHmacDRBG(); break;
	case 91: result = ValidateNaCl(); break;
	case 100: result = ValidateCHAM(); break;
	case 101: result = ValidateSIMECK(); break;
	case 102: result = ValidateSIMON(); break;
	case 103: result = ValidateSPECK(); break;

	case 110: result = ValidateSHA3(); break;
	case 111: result = ValidateSHAKE(); break;
	case 112: result = ValidateSHAKE_XOF(); break;

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
	// http://github.com/weidai11/cryptopp/issues/92
	case 9999: result = TestSecBlock(); break;
	// http://github.com/weidai11/cryptopp/issues/64
	case 9998: result = TestPolynomialMod2(); break;
	// http://github.com/weidai11/cryptopp/issues/336
	case 9997: result = TestIntegerBitops(); break;
	// http://github.com/weidai11/cryptopp/issues/602
	case 9996: result = TestIntegerOps(); break;
	// http://github.com/weidai11/cryptopp/issues/360
	case 9995: result = TestRounding(); break;
	// http://github.com/weidai11/cryptopp/issues/242
	case 9994: result = TestHuffmanCodes(); break;
	// http://github.com/weidai11/cryptopp/issues/346
	case 9993: result = TestASN1Parse(); break;
	// http://github.com/weidai11/cryptopp/issues/242
	case 9992: result = TestX25519(); break;
	// http://github.com/weidai11/cryptopp/issues/346
	case 9991: result = TestEd25519(); break;
# if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
	case 9990: result = TestAltivecOps(); break;
# endif
#endif

	default: return false;
	}

	g_testEnd = ::time(NULLPTR);

	std::cout << "\nSeed used was " << s_globalSeed;
	std::cout << "\nTest started at " << TimeToString(g_testBegin);
	std::cout << "\nTest ended at " << TimeToString(g_testEnd) << std::endl;

	return result;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP

// Microsoft puts a byte in global namespace. Combined with
// a 'using namespace CryptoPP', it causes compile failures.
// Also see http://github.com/weidai11/cryptopp/issues/442
// and http://github.com/weidai11/cryptopp/issues/447.
int CRYPTOPP_API main(int argc, char *argv[])
{
	return CryptoPP::Test::scoped_main(argc, argv);
}
