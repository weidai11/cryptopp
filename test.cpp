// test.cpp - written and placed in the public domain by Wei Dai

#define _CRT_SECURE_NO_DEPRECATE
#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "dll.h"
#include "md5.h"
#include "ripemd.h"
#include "rng.h"
#include "gzip.h"
#include "default.h"
#include "randpool.h"
#include "ida.h"
#include "base64.h"
#include "socketft.h"
#include "wait.h"
#include "factory.h"
#include "whrlpool.h"
#include "tiger.h"

#include "validate.h"
#include "bench.h"

// CRYPTOPP_ASSERT, includes <signal.h> for BSD, Linux and Unix
#include "trap.h"

#include <iostream>
#include <time.h>

#ifdef CRYPTOPP_WIN32_AVAILABLE
#include <windows.h>
#endif

#if defined(USE_BERKELEY_STYLE_SOCKETS) && !defined(macintosh)
#include <netinet/in.h>
#include <netinet/tcp.h>
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
# pragma comment(lib, "cryptlib_bds.lib")
# pragma comment(lib, "ws2_32.lib")
#endif

USING_NAMESPACE(CryptoPP)

const int MAX_PHRASE_LENGTH=250;

void RegisterFactories();

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

void ForwardTcpPort(const char *sourcePort, const char *destinationHost, const char *destinationPort);

void FIPS140_SampleApplication();
void FIPS140_GenerateRandomFiles();

bool Validate(int, bool, const char *);

#if defined(CRYPTOPP_DEBUG) && (defined(CRYPTOPP_BSD_AVAILABLE) || defined(CRYPTOPP_UNIX_AVAILABLE))
// Add a SIGTRAP handler for BSD, Linux, Unix; used by CRYPTOPP_ASSERT.
struct DebugTrapHandler
{
	explicit DebugTrapHandler()
	{
		// http://pubs.opengroup.org/onlinepubs/007908799/xsh/sigaction.html
		struct sigaction old_handler, new_handler;
		memset(&old_handler, 0x00, sizeof(old_handler));
		memset(&new_handler, 0x00, sizeof(new_handler));

		do
		{
			int ret = 0;

			ret = sigaction (SIGTRAP, NULL, &old_handler);
			if (ret != 0) break; // Failed

			// Don't step on another's handler (like a debugger)
			if (old_handler.sa_handler != NULL) break;

			// Set up the structure to specify the null action.
			new_handler.sa_handler = &DebugTrapHandler::NullHandler;
			new_handler.sa_flags = 0;

			ret = sigemptyset (&new_handler.sa_mask);
			if (ret != 0) break; // Failed

			// Install it.
			ret = sigaction (SIGTRAP, &new_handler, NULL);
			if (ret != 0) break; // Failed

		} while(0);
	}

	static void NullHandler(int /*unused*/) { }
};

#if __GNUC__
// Specify a relatively low priority to make sure we run before other CTORs
// http://gcc.gnu.org/onlinedocs/gcc/C_002b_002b-Attributes.html#C_002b_002b-Attributes
static const DebugTrapHandler g_dummyHandler __attribute__ ((init_priority (110)));
#else
static const DebugTrapHandler g_dummyHandler;
#endif // __GNUC__
#endif // CRYPTOPP_UNIX_AVAILABLE and not NDEBUG

RandomNumberGenerator & GlobalRNG()
{
	static OFB_Mode<AES>::Encryption s_globalRNG;
	return s_globalRNG;
}

int (*AdhocTest)(int argc, char *argv[]) = NULL;

int CRYPTOPP_API main(int argc, char *argv[])
{
#ifdef _CRTDBG_LEAK_CHECK_DF
	// Turn on leak-checking
	int tempflag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
	tempflag |= _CRTDBG_LEAK_CHECK_DF;
	_CrtSetDbgFlag( tempflag );
#endif

#if defined(__MWERKS__) && defined(macintosh)
	argc = ccommand(&argv);
#endif

	CRYPTOPP_UNUSED(argc), CRYPTOPP_UNUSED(argv);

	try
	{
		RegisterFactories();

		std::string seed = IntToString(time(NULL));
		seed.resize(16);

		OFB_Mode<AES>::Encryption& prng = dynamic_cast<OFB_Mode<AES>::Encryption&>(GlobalRNG());
		prng.SetKeyWithIV((byte *)seed.data(), 16, (byte *)seed.data());

		std::string command, executableName, macFilename;

		if (argc < 2)
			command = 'h';
		else
			command = argv[1];

		if (command == "g")
		{
			char seed[1024], privFilename[128], pubFilename[128];
			unsigned int keyLength;

			std::cout << "Key length in bits: ";
			std::cin >> keyLength;

			std::cout << "\nSave private key to file: ";
			std::cin >> privFilename;

			std::cout << "\nSave public key to file: ";
			std::cin >> pubFilename;

			std::cout << "\nRandom Seed: ";
			ws(std::cin);
			std::cin.getline(seed, 1024);

			GenerateRSAKey(keyLength, privFilename, pubFilename, seed);
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
			char seed[1024], message[1024];

			std::cout << "Private key file: ";
			std::cin >> privFilename;

			std::cout << "\nPublic key file: ";
			std::cin >> pubFilename;

			std::cout << "\nRandom Seed: ";
			ws(std::cin);
			std::cin.getline(seed, 1024);

			std::cout << "\nMessage: ";
			std::cin.getline(message, 1024);

			std::string ciphertext = RSAEncryptString(pubFilename, seed, message);
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
			// sanity check on file size
			std::fstream dllFile(argv[2], std::ios::in | std::ios::out | std::ios::binary);
			std::ifstream::pos_type fileEnd = dllFile.seekg(0, std::ios_base::end).tellg();
			if (fileEnd > 20*1000*1000)
			{
				std::cerr << "Input file too large (more than 20 MB).\n";
				return 1;
			}

			// read file into memory
			unsigned int fileSize = (unsigned int)fileEnd;
			SecByteBlock buf(fileSize);
			dllFile.seekg(0, std::ios_base::beg);
			dllFile.read((char *)buf.begin(), fileSize);

			// find positions of relevant sections in the file, based on version 8 of documentation from http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
			word32 coffPos = *(word16 *)(buf+0x3c);
			word32 optionalHeaderPos = coffPos + 24;
			word16 optionalHeaderMagic = *(word16 *)(buf+optionalHeaderPos);
			if (optionalHeaderMagic != 0x10b && optionalHeaderMagic != 0x20b)
			{
				std::cerr << "Target file is not a PE32 or PE32+ image.\n";
				return 3;
			}
			word32 checksumPos = optionalHeaderPos + 64;
			word32 certificateTableDirectoryPos = optionalHeaderPos + (optionalHeaderMagic == 0x10b ? 128 : 144);
			word32 certificateTablePos = *(word32 *)(buf+certificateTableDirectoryPos);
			word32 certificateTableSize = *(word32 *)(buf+certificateTableDirectoryPos+4);
			if (certificateTableSize != 0)
				std::cerr << "Warning: certificate table (IMAGE_DIRECTORY_ENTRY_SECURITY) of target image is not empty.\n";

			// find where to place computed MAC
			byte mac[] = CRYPTOPP_DUMMY_DLL_MAC;
			byte *found = std::search(buf.begin(), buf.end(), mac+0, mac+sizeof(mac));
			if (found == buf.end())
			{
				std::cerr << "MAC placeholder not found. Possibly the actual MAC was already placed.\n";
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

			// place MAC
			std::cout << "Placing MAC in file " << argv[2] << ", location " << macPos << ".\n";
			dllFile.seekg(macPos, std::ios_base::beg);
			dllFile.write((char *)mac, sizeof(mac));
		}
		else if (command == "m")
			DigestFile(argv[2]);
		else if (command == "tv")
		{
			std::string fname = (argc >= 3 ? argv[2] : "all");
			if (fname.find(".txt") == std::string::npos)
				fname = "TestVectors/" + fname + ".txt";
			return !RunTestDataFile(fname.c_str());
		}
		else if (command == "t")
		{
			// VC60 workaround: use char array instead of std::string to workaround MSVC's getline bug
			char passPhrase[MAX_PHRASE_LENGTH], plaintext[1024];

			std::cout << "Passphrase: ";
			std::cin.getline(passPhrase, MAX_PHRASE_LENGTH);

			std::cout << "\nPlaintext: ";
			std::cin.getline(plaintext, 1024);

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
			char seed[1024];
			std::cout << "\nRandom Seed: ";
			ws(std::cin);
			std::cin.getline(seed, 1024);
			SecretShareFile(atoi(argv[2]), atoi(argv[3]), argv[4], seed);
		}
		else if (command == "sr")
			SecretRecoverFile(argc-3, argv[2], argv+3);
		else if (command == "id")
			InformationDisperseFile(atoi(argv[2]), atoi(argv[3]), argv[4]);
		else if (command == "ir")
			InformationRecoverFile(argc-3, argv[2], argv+3);
		else if (command == "v" || command == "vv")
			return !Validate(argc>2 ? atoi(argv[2]) : 0, argv[1][1] == 'v', argc>3 ? argv[3] : NULL);
		else if (command == "b")
			BenchmarkAll(argc<3 ? 1 : atof(argv[2]), argc<4 ? 0 : atof(argv[3])*1e9);
		else if (command == "b2")
			BenchmarkAll2(argc<3 ? 1 : atof(argv[2]), argc<4 ? 0 : atof(argv[3])*1e9);
		else if (command == "z")
			GzipFile(argv[3], argv[4], argv[2][0]-'0');
		else if (command == "u")
			GunzipFile(argv[2], argv[3]);
		else if (command == "fips")
			FIPS140_SampleApplication();
		else if (command == "fips-rand")
			FIPS140_GenerateRandomFiles();
		else if (command == "ft")
			ForwardTcpPort(argv[2], argv[3], argv[4]);
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
			FileSource usage("TestData/usage.dat", true, new FileSink(std::cout));
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
	catch(CryptoPP::Exception &e)
	{
		std::cout << "\nCryptoPP::Exception caught: " << e.what() << std::endl;
		return -1;
	}
	catch(std::exception &e)
	{
		std::cout << "\nstd::exception caught: " << e.what() << std::endl;
		return -2;
	}
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

SecByteBlock HexDecodeString(const char *hex)
{
	StringSource ss(hex, true, new HexDecoder);
	SecByteBlock result((size_t)ss.MaxRetrievable());
	ss.Get(result, result.size());
	return result;
}

void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{
	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);
	privFile.MessageEnd();

	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
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
	RSASS<PKCS1v15, SHA>::Signer priv(privFile);
	FileSource f(messageFilename, true, new SignerFilter(GlobalRNG(), priv, new HexEncoder(new FileSink(signatureFilename))));
}

bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSASS<PKCS1v15, SHA>::Verifier pub(pubFile);

	FileSource signatureFile(signatureFilename, true, new HexDecoder);
	if (signatureFile.MaxRetrievable() != pub.SignatureLength())
		return false;
	SecByteBlock signature(pub.SignatureLength());
	signatureFile.Get(signature, signature.size());

	VerifierFilter *verifierFilter = new VerifierFilter(pub);
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

	using CryptoPP::auto_ptr;
	auto_ptr<ChannelSwitch> channelSwitch(new ChannelSwitch);

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
	CRYPTOPP_ASSERT(nShares<=1000);

	RandomPool rng;
	rng.IncorporateEntropy((byte *)seed, strlen(seed));

	ChannelSwitch *channelSwitch;
	FileSource source(filename, false, new SecretSharing(rng, threshold, nShares, channelSwitch = new ChannelSwitch));

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
		fileSinks[i]->Put((byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], DefaultChannel());
	}

	source.PumpAll();
}

void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
	CRYPTOPP_ASSERT(threshold<=1000);

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
	CRYPTOPP_ASSERT(nShares<=1000);

	ChannelSwitch *channelSwitch;
	FileSource source(filename, false, new InformationDispersal(threshold, nShares, channelSwitch = new ChannelSwitch));

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
		fileSinks[i]->Put((byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], DefaultChannel());
	}

	source.PumpAll();
}

void InformationRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
	CRYPTOPP_ASSERT(threshold<=1000);

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
	// Source --------> Gzip --------> Sink
	//    \              |
	//	    \          Gunzip
	//		  \          |
	//		    \        v
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

void ForwardTcpPort(const char *sourcePortName, const char *destinationHost, const char *destinationPortName)
{
#ifdef SOCKETS_AVAILABLE
	SocketsInitializer sockInit;

	Socket sockListen, sockSource, sockDestination;

	int sourcePort = Socket::PortNameToNumber(sourcePortName);
	int destinationPort = Socket::PortNameToNumber(destinationPortName);

	sockListen.Create();
	sockListen.Bind(sourcePort);
	setsockopt(sockListen, IPPROTO_TCP, TCP_NODELAY, "\x01", 1);

	std::cout << "Listing on port " << sourcePort << ".\n";
	sockListen.Listen();

	sockListen.Accept(sockSource);
	std::cout << "Connection accepted on port " << sourcePort << ".\n";
	sockListen.CloseSocket();

	std::cout << "Making connection to " << destinationHost << ", port " << destinationPort << ".\n";
	sockDestination.Create();
	sockDestination.Connect(destinationHost, destinationPort);

	std::cout << "Connection made to " << destinationHost << ", starting to forward.\n";

	SocketSource out(sockSource, false, new SocketSink(sockDestination));
	SocketSource in(sockDestination, false, new SocketSink(sockSource));

	WaitObjectContainer waitObjects;

	while (!(in.SourceExhausted() && out.SourceExhausted()))
	{
		waitObjects.Clear();

		out.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - out", NULL));
		in.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - in", NULL));

		waitObjects.Wait(INFINITE_TIME);

		if (!out.SourceExhausted())
		{
			std::cout << "o" << std::flush;
			out.PumpAll2(false);
			if (out.SourceExhausted())
				std::cout << "EOF received on source socket.\n";
		}

		if (!in.SourceExhausted())
		{
			std::cout << "i" << std::flush;
			in.PumpAll2(false);
			if (in.SourceExhausted())
				std::cout << "EOF received on destination socket.\n";
		}
	}
#else
	std::cout << "Socket support was not enabled at compile time.\n";
	exit(-1);
#endif
}

bool Validate(int alg, bool thorough, const char *seedInput)
{
	bool result;

	std::string seed = seedInput ? std::string(seedInput) : IntToString(time(NULL));
	seed.resize(16);

	std::cout << "Using seed: " << seed << std::endl;
	
	OFB_Mode<AES>::Encryption& prng = dynamic_cast<OFB_Mode<AES>::Encryption&>(GlobalRNG());
	prng.SetKeyWithIV((byte *)seed.data(), 16, (byte *)seed.data());

#ifdef _OPENMP
	int tc = 0;
	#pragma omp parallel
	{
		tc = omp_get_num_threads();
	}

	std::cout << "Using " << tc << " OMP " << (tc == 1 ? "thread" : "threads") << std::endl;
#endif

	std::cout << std::endl;

	switch (alg)
	{
		case 0: result = ValidateAll(thorough); break;
		case 1: result = TestSettings(); break;
		case 70: result = TestRotate(); break;
		case 71: result = TestConversion(); break;
		case 2: result = TestOS_RNG(); break;
		case 3: result = ValidateMD5(); break;
		case 4: result = ValidateSHA(); break;
		case 5: result = ValidateDES(); break;
		case 6: result = ValidateIDEA(); break;
		case 7: result = ValidateARC4(); break;
		case 8: result = ValidateRC5(); break;
		case 9: result = ValidateBlowfish(); break;
		//	case 10: result = ValidateDiamond2(); break;
		case 11: result = ValidateThreeWay(); break;
		case 12: result = ValidateBBS(); break;
		case 13: result = ValidateDH(); break;
		case 14: result = ValidateRSA(); break;
		case 15: result = ValidateElGamal(); break;
		case 16: result = ValidateDSA(thorough); break;
		//	case 17: result = ValidateHAVAL(); break;
		case 18: result = ValidateSAFER(); break;
		case 19: result = ValidateLUC(); break;
		case 20: result = ValidateRabin(); break;
		//	case 21: result = ValidateBlumGoldwasser(); break;
		case 22: result = ValidateECP(); break;
		case 23: result = ValidateEC2N(); break;
		//	case 24: result = ValidateMD5MAC(); break;
		case 25: result = ValidateGOST(); break;
		case 26: result = ValidateTiger(); break;
		case 27: result = ValidateRIPEMD(); break;
		case 28: result = ValidateHMAC(); break;
		//	case 29: result = ValidateXMACC(); break;
		case 30: result = ValidateSHARK(); break;
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
		case 49: result = ValidateECDSA(); break;
		case 50: result = ValidateXTR_DH(); break;
		case 51: result = ValidateSKIPJACK(); break;
		case 52: result = ValidateSHA2(); break;
		case 53: result = ValidatePanama(); break;
		case 54: result = ValidateAdler32(); break;
		case 55: result = ValidateMD4(); break;
		case 56: result = ValidatePBKDF(); break;
		case 57: result = ValidateESIGN(); break;
		case 58: result = ValidateDLIES(); break;
		case 59: result = ValidateBaseCode(); break;
		case 60: result = ValidateSHACAL2(); break;
		case 61: result = ValidateCamellia(); break;
		case 62: result = ValidateWhirlpool(); break;
		case 63: result = ValidateTTMAC(); break;
		case 64: result = ValidateSalsa(); break;
		case 65: result = ValidateSosemanuk(); break;
		case 66: result = ValidateVMAC(); break;
		case 67: result = ValidateCCM(); break;
		case 68: result = ValidateGCM(); break;
		case 69: result = ValidateCMAC(); break;
		case 72: result = ValidateHKDF(); break;
		default: return false;
	}

	time_t endTime = time(NULL);
	std::cout << "\nTest ended at " << asctime(localtime(&endTime));
	std::cout << "Seed used was: " << seed << std::endl;

	return result;
}
