// test.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "md5.h"
#include "sha.h"
#include "ripemd.h"
#include "files.h"
#include "rng.h"
#include "hex.h"
#include "gzip.h"
#include "default.h"
#include "rsa.h"
#include "randpool.h"
#include "ida.h"
#include "base64.h"
#include "socketft.h"
#include "dsa.h"
#include "rsa.h"
#include "osrng.h"
#include "wait.h"
#include "fips140.h"
#include "factory.h"

#include "validate.h"
#include "bench.h"

#include <iostream>
#include <time.h>

#ifdef CRYPTOPP_WIN32_AVAILABLE
#include <windows.h>
#endif

#if (_MSC_VER >= 1000)
#include <crtdbg.h>		// for the debug heap
#endif

#if defined(__MWERKS__) && defined(macintosh)
#include <console.h>
#endif

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

const int MAX_PHRASE_LENGTH=250;

void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed);
string RSAEncryptString(const char *pubFilename, const char *seed, const char *message);
string RSADecryptString(const char *privFilename, const char *ciphertext);
void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename);
bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename);

void DigestFile(const char *file);

string EncryptString(const char *plaintext, const char *passPhrase);
string DecryptString(const char *ciphertext, const char *passPhrase);

void EncryptFile(const char *in, const char *out, const char *passPhrase);
void DecryptFile(const char *in, const char *out, const char *passPhrase);

void SecretShareFile(int threshold, int nShares, const char *filename, const char *seed);
void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames);

void InformationDisperseFile(int threshold, int nShares, const char *filename);
void InformationRecoverFile(int threshold, const char *outFilename, char *const *inFilenames);

void GzipFile(const char *in, const char *out, int deflate_level);
void GunzipFile(const char *in, const char *out);

void Base64Encode(const char *in, const char *out);
void Base64Decode(const char *in, const char *out);
void HexEncode(const char *in, const char *out);
void HexDecode(const char *in, const char *out);

void ForwardTcpPort(const char *sourcePort, const char *destinationHost, const char *destinationPort);

void FIPS140_SampleApplication(const char *moduleFilename, const char *edcFilename);
void FIPS140_GenerateRandomFiles();

bool Validate(int, bool, const char *);

void RegisterFactories();
bool RunTestDataFile(const char *filename);

int (*AdhocTest)(int argc, char *argv[]) = NULL;

#ifdef __BCPLUSPLUS__
int cmain(int argc, char *argv[])
#elif defined(_MSC_VER)
int __cdecl main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
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

	try
	{
		std::string command, executableName, edcFilename;

		if (argc < 2)
			command = 'h';
		else
			command = argv[1];

		if (FIPS_140_2_ComplianceEnabled())
		{
			edcFilename = "edc.dat";

#ifdef CRYPTOPP_WIN32_AVAILABLE
			TCHAR filename[MAX_PATH];
			GetModuleFileName(GetModuleHandle(NULL), filename, sizeof(filename));
			executableName = filename;
			std::string::size_type pos = executableName.rfind('\\');
			if (pos != std::string::npos)
				edcFilename = executableName.substr(0, pos+1) + edcFilename;
#else
			executableName = argv[0];
#endif

			if (command.substr(0, 4) != "fips")
			{
				byte expectedModuleDigest[SHA1::DIGESTSIZE];
				FileSource(edcFilename.c_str(), true, new HexDecoder(new ArraySink(expectedModuleDigest, sizeof(expectedModuleDigest))));

				DoPowerUpSelfTest(executableName.c_str(), expectedModuleDigest);
			}
		}

		switch (command[0])
		{
		case 'g':
		  {
			char seed[1024], privFilename[128], pubFilename[128];
			unsigned int keyLength;

			cout << "Key length in bits: ";
			cin >> keyLength;

			cout << "\nSave private key to file: ";
			cin >> privFilename;

			cout << "\nSave public key to file: ";
			cin >> pubFilename;

			cout << "\nRandom Seed: ";
			ws(cin);
			cin.getline(seed, 1024);

			GenerateRSAKey(keyLength, privFilename, pubFilename, seed);
			return 0;
		  }
		case 'r':
		  {
			switch (argv[1][1])
			{
			case 's':
				RSASignFile(argv[2], argv[3], argv[4]);
				return 0;
			case 'v':
			  {
				bool verified = RSAVerifyFile(argv[2], argv[3], argv[4]);
				cout << (verified ? "valid signature" : "invalid signature") << endl;
				return 0;
			  }
			default:
			  {
				char privFilename[128], pubFilename[128];
				char seed[1024], message[1024];

				cout << "Private key file: ";
				cin >> privFilename;

				cout << "\nPublic key file: ";
				cin >> pubFilename;

				cout << "\nRandom Seed: ";
				ws(cin);
				cin.getline(seed, 1024);

				cout << "\nMessage: ";
				cin.getline(message, 1024);

				string ciphertext = RSAEncryptString(pubFilename, seed, message);
				cout << "\nCiphertext: " << ciphertext << endl;

				string decrypted = RSADecryptString(privFilename, ciphertext.c_str());
				cout << "\nDecrypted: " << decrypted << endl;

				return 0;
			  }
			}
		  }
		case 'm':
			if (command == "mt")
			{
				MaurerRandomnessTest mt;
				FileStore fs(argv[2]);
				fs.TransferAllTo(mt);
				cout << "Maurer Test Value: " << mt.GetTestValue() << endl;
			}
			else
				DigestFile(argv[2]);
			return 0;
		case 't':
		  {
			if (command == "tv")
			{
				return !RunTestDataFile(argv[2]);
			}
			// VC60 workaround: use char array instead of std::string to workaround MSVC's getline bug
			char passPhrase[MAX_PHRASE_LENGTH], plaintext[1024];

			cout << "Passphrase: ";
			cin.getline(passPhrase, MAX_PHRASE_LENGTH);

			cout << "\nPlaintext: ";
			cin.getline(plaintext, 1024);

			string ciphertext = EncryptString(plaintext, passPhrase);
			cout << "\nCiphertext: " << ciphertext << endl;

			string decrypted = DecryptString(ciphertext.c_str(), passPhrase);
			cout << "\nDecrypted: " << decrypted << endl;

			return 0;
		  }
		case 'e':
		case 'd':
			if (command == "e64")
				Base64Encode(argv[2], argv[3]);
			else if (command == "d64")
				Base64Decode(argv[2], argv[3]);
			else if (command == "e16")
				HexEncode(argv[2], argv[3]);
			else if (command == "d16")
				HexDecode(argv[2], argv[3]);
			else
			{
				char passPhrase[MAX_PHRASE_LENGTH];
				cout << "Passphrase: ";
				cin.getline(passPhrase, MAX_PHRASE_LENGTH);
				if (command == "e")
					EncryptFile(argv[2], argv[3], passPhrase);
				else
					DecryptFile(argv[2], argv[3], passPhrase);
			}
			return 0;
		case 's':
			if (argv[1][1] == 's')
			{
				char seed[1024];
				cout << "\nRandom Seed: ";
				ws(cin);
				cin.getline(seed, 1024);
				SecretShareFile(atoi(argv[2]), atoi(argv[3]), argv[4], seed);
			}
			else
				SecretRecoverFile(argc-3, argv[2], argv+3);
			return 0;
		case 'i':
			if (argv[1][1] == 'd')
				InformationDisperseFile(atoi(argv[2]), atoi(argv[3]), argv[4]);
			else
				InformationRecoverFile(argc-3, argv[2], argv+3);
			return 0;
		case 'v':
			return !Validate(argc>2 ? atoi(argv[2]) : 0, argv[1][1] == 'v', argc>3 ? argv[3] : NULL);
		case 'b':
			if (argc<3)
				BenchMarkAll();
			else
				BenchMarkAll((float)atof(argv[2]));
			return 0;
		case 'z':
			GzipFile(argv[3], argv[4], argv[2][0]-'0');
			return 0;
		case 'u':
			GunzipFile(argv[2], argv[3]);
			return 0;
		case 'f':
			if (command == "fips")
				FIPS140_SampleApplication(executableName.c_str(), edcFilename.c_str());
			else if (command == "fips-rand")
				FIPS140_GenerateRandomFiles();
			else if (command == "ft")
				ForwardTcpPort(argv[2], argv[3], argv[4]);
			return 0;
		case 'a':
			if (AdhocTest)
				return (*AdhocTest)(argc, argv);
			else
				return 0;
		default:
			FileSource usage("usage.dat", true, new FileSink(cout));
			return 1;
		}
	}
	catch(CryptoPP::Exception &e)
	{
		cout << "\nCryptoPP::Exception caught: " << e.what() << endl;
		return -1;
	}
	catch(std::exception &e)
	{
		cout << "\nstd::exception caught: " << e.what() << endl;
		return -2;
	}
}

void FIPS140_SampleApplication(const char *moduleFilename, const char *edcFilename)
{
	if (!FIPS_140_2_ComplianceEnabled())
	{
		cerr << "FIPS-140-2 compliance was turned off at compile time.\n";
		abort();
	}

	// try to use a crypto algorithm before doing a self test
	try
	{
		// trying to use a crypto algorithm before power-up self test will result in an exception
		DES::Encryption des;

		// should not be here
		cerr << "Use of DES before power-up test failed to cause an exception.\n";
		abort();
	}
	catch (SelfTestFailure &e)
	{
		cout << "0. Caught expected exception. Exception message follows: ";
		cout << e.what() << endl;
	}

	// simulate a power-up self test error
	SimulatePowerUpSelfTestFailure();
	try
	{
		// trying to use a crypto algorithm after power-up self test error will result in an exception
		DES::Encryption des;

		// should not be here
		cerr << "Use of DES failed to cause an exception after power-up self test error.\n";
		abort();
	}
	catch (SelfTestFailure &e)
	{
		cout << "1. Caught expected exception when simulating self test failure. Exception message follows: ";
		cout << e.what() << endl;
	}

	// clear the self test error state and do power-up self test
	byte expectedModuleDigest[SHA1::DIGESTSIZE];
	FileSource(edcFilename, true, new HexDecoder(new ArraySink(expectedModuleDigest, sizeof(expectedModuleDigest))));

	DoPowerUpSelfTest(moduleFilename, expectedModuleDigest);
	if (GetPowerUpSelfTestStatus() != POWER_UP_SELF_TEST_PASSED)
	{
		cerr << "Power-up self test failed.\n";
		abort();
	}
	cout << "2. Power-up self test passed.\n";

	// encrypt and decrypt
	const byte key[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	const byte iv[] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};
	const byte plaintext[] = {	// "Now is the time for all " without tailing 0
		0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
		0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
		0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20};
	byte ciphertext[24];
	byte decrypted[24];

	CBC_Mode<DES>::Encryption encryption_DES_CBC;
	encryption_DES_CBC.SetKeyWithIV(key, 8, iv);
	encryption_DES_CBC.ProcessString(ciphertext, plaintext, 24);

	CBC_Mode<DES>::Decryption decryption_DES_CBC;
	decryption_DES_CBC.SetKeyWithIV(key, 8, iv);
	decryption_DES_CBC.ProcessString(decrypted, ciphertext, 24);

	if (memcmp(plaintext, decrypted, 24) != 0)
	{
		cerr << "DES-CBC Encryption/decryption failed.\n";
		abort();
	}
	cout << "3. DES-CBC Encryption/decryption succeeded.\n";

	// hash
	const byte message[] = {'a', 'b', 'c'};
	const byte expectedDigest[] = {0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,0x9C,0xD0,0xD8,0x9D};
	byte digest[20];
	
	SHA1 sha;
	sha.Update(message, 3);
	sha.Final(digest);

	if (memcmp(digest, expectedDigest, 20) != 0)
	{
		cerr << "SHA-1 hash failed.\n";
		abort();
	}
	cout << "4. SHA-1 hash succeeded.\n";

	// create auto-seeded X9.17 RNG object, if available
#ifdef OS_RNG_AVAILABLE
	AutoSeededX917RNG<DES_EDE3> rng;
#else
	// this is used to allow this function to compile on platforms that don't have auto-seeded RNGs
	RandomNumberGenerator &rng(NullRNG());
#endif

	// generate DSA key
	DSA::PrivateKey dsaPrivateKey;
	dsaPrivateKey.GenerateRandomWithKeySize(rng, 1024);
	DSA::PublicKey dsaPublicKey;
	dsaPublicKey.AssignFrom(dsaPrivateKey);
	if (!dsaPrivateKey.Validate(rng, 3) || !dsaPublicKey.Validate(rng, 3))
	{
		cerr << "DSA key generation failed.\n";
		abort();
	}
	cout << "5. DSA key generation succeeded.\n";

	// encode DSA key
	std::string encodedDsaPublicKey, encodedDsaPrivateKey;
	dsaPublicKey.DEREncode(StringSink(encodedDsaPublicKey).Ref());
	dsaPrivateKey.DEREncode(StringSink(encodedDsaPrivateKey).Ref());

	// decode DSA key
	DSA::PrivateKey decodedDsaPrivateKey;
	decodedDsaPrivateKey.BERDecode(StringStore(encodedDsaPrivateKey).Ref());
	DSA::PublicKey decodedDsaPublicKey;
	decodedDsaPublicKey.BERDecode(StringStore(encodedDsaPublicKey).Ref());

	if (!decodedDsaPrivateKey.Validate(rng, 3) || !decodedDsaPublicKey.Validate(rng, 3))
	{
		cerr << "DSA key encode/decode failed.\n";
		abort();
	}
	cout << "6. DSA key encode/decode succeeded.\n";

	// sign and verify
	byte signature[40];
	DSA::Signer signer(dsaPrivateKey);
	assert(signer.SignatureLength() == 40);
	signer.SignMessage(rng, message, 3, signature);

	DSA::Verifier verifier(dsaPublicKey);
	if (!verifier.VerifyMessage(message, 3, signature, 40))
	{
		cerr << "DSA signature and verification failed.\n";
		abort();
	}
	cout << "7. DSA signature and verification succeeded.\n";


	// try to verify an invalid signature
	signature[0] ^= 1;
	if (verifier.VerifyMessage(message, 3, signature, 40))
	{
		cerr << "DSA signature verification failed to detect bad signature.\n";
		abort();
	}
	cout << "8. DSA signature verification successfully detected bad signature.\n";

	// try to use an invalid key length
	try
	{
		encryption_DES_CBC.SetKey(key, 5);

		// should not be here
		cerr << "DES implementation did not detect use of invalid key length.\n";
		abort();
	}
	catch (InvalidArgument &e)
	{
		cout << "9. Caught expected exception when using invalid key length. Exception message follows: ";
		cout << e.what() << endl;
	}

	cout << "\nFIPS 140-2 Sample Application completed normally.\n";
}

void FIPS140_GenerateRandomFiles()
{
#ifdef OS_RNG_AVAILABLE
	AutoSeededX917RNG<DES_EDE3> rng;
	RandomNumberStore store(rng, ULONG_MAX);

	for (unsigned int i=0; i<100000; i++)
		store.TransferTo(FileSink((IntToString(i) + ".rnd").c_str()).Ref(), 20000);
#else
	cout << "OS provided RNG not available.\n";
	exit(-1);
#endif
}

RandomPool & GlobalRNG()
{
	static RandomPool randomPool;
	return randomPool;
}

void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{
	RandomPool randPool;
	randPool.Put((byte *)seed, strlen(seed));

	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);
	privFile.MessageEnd();

	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
	pubFile.MessageEnd();
}

string RSAEncryptString(const char *pubFilename, const char *seed, const char *message)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor pub(pubFile);

	RandomPool randPool;
	randPool.Put((byte *)seed, strlen(seed));

	string result;
	StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
	return result;
}

string RSADecryptString(const char *privFilename, const char *ciphertext)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile);

	string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
	return result;
}

void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSASSA_PKCS1v15_SHA_Signer priv(privFile);
	FileSource f(messageFilename, true, new SignerFilter(GlobalRNG(), priv, new HexEncoder(new FileSink(signatureFilename))));
}

bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSASSA_PKCS1v15_SHA_Verifier pub(pubFile);

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
	MD5 md5;
	SHA sha;
	RIPEMD160 ripemd;
	SHA256 sha256;
	HashFilter md5Filter(md5), shaFilter(sha), ripemdFilter(ripemd), sha256Filter(sha256);

	auto_ptr<ChannelSwitch> channelSwitch(new ChannelSwitch);
	channelSwitch->AddDefaultRoute(md5Filter);
	channelSwitch->AddDefaultRoute(shaFilter);
	channelSwitch->AddDefaultRoute(ripemdFilter);
	channelSwitch->AddDefaultRoute(sha256Filter);
	FileSource(filename, true, channelSwitch.release());

	HexEncoder encoder(new FileSink(cout), false);
	cout << "\nMD5: ";
	md5Filter.TransferTo(encoder);
	cout << "\nSHA-1: ";
	shaFilter.TransferTo(encoder);
	cout << "\nRIPEMD-160: ";
	ripemdFilter.TransferTo(encoder);
	cout << "\nSHA-256: ";
	sha256Filter.TransferTo(encoder);
}

string EncryptString(const char *instr, const char *passPhrase)
{
	string outstr;

	DefaultEncryptorWithMAC encryptor(passPhrase, new HexEncoder(new StringSink(outstr)));
	encryptor.Put((byte *)instr, strlen(instr));
	encryptor.MessageEnd();

	return outstr;
}

string DecryptString(const char *instr, const char *passPhrase)
{
	string outstr;

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
	assert(nShares<=1000);

	RandomPool rng;
	rng.Put((byte *)seed, strlen(seed));

	ChannelSwitch *channelSwitch;
	FileSource source(filename, false, new SecretSharing(rng, threshold, nShares, channelSwitch = new ChannelSwitch));

	vector_member_ptrs<FileSink> fileSinks(nShares);
	string channel;
	for (int i=0; i<nShares; i++)
	{
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new FileSink((string(filename)+extension).c_str()));

		channel = WordToString<word32>(i);
		fileSinks[i]->Put((byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], BufferedTransformation::NULL_CHANNEL);
	}

	source.PumpAll();
}

void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
	assert(threshold<=1000);

	SecretRecovery recovery(threshold, new FileSink(outFilename));

	vector_member_ptrs<FileSource> fileSources(threshold);
	SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		fileSources[i].reset(new FileSource(inFilenames[i], false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new ChannelSwitch(recovery, string((char *)channel.begin(), 4)));
	}

	while (fileSources[0]->Pump(256))
		for (i=1; i<threshold; i++)
			fileSources[i]->Pump(256);

	for (i=0; i<threshold; i++)
		fileSources[i]->PumpAll();
}

void InformationDisperseFile(int threshold, int nShares, const char *filename)
{
	assert(nShares<=1000);

	ChannelSwitch *channelSwitch;
	FileSource source(filename, false, new InformationDispersal(threshold, nShares, channelSwitch = new ChannelSwitch));

	vector_member_ptrs<FileSink> fileSinks(nShares);
	string channel;
	for (int i=0; i<nShares; i++)
	{
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new FileSink((string(filename)+extension).c_str()));

		channel = WordToString<word32>(i);
		fileSinks[i]->Put((byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], BufferedTransformation::NULL_CHANNEL);
	}

	source.PumpAll();
}

void InformationRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
	assert(threshold<=1000);

	InformationRecovery recovery(threshold, new FileSink(outFilename));

	vector_member_ptrs<FileSource> fileSources(threshold);
	SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		fileSources[i].reset(new FileSource(inFilenames[i], false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new ChannelSwitch(recovery, string((char *)channel.begin(), 4)));
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

void ForwardTcpPort(const char *sourcePortName, const char *destinationHost, const char *destinationPortName)
{
#ifdef SOCKETS_AVAILABLE
	SocketsInitializer sockInit;

	Socket sockListen, sockSource, sockDestination;

	int sourcePort = Socket::PortNameToNumber(sourcePortName);
	int destinationPort = Socket::PortNameToNumber(destinationPortName);

	sockListen.Create();
	sockListen.Bind(sourcePort);

	cout << "Listing on port " << sourcePort << ".\n";
	sockListen.Listen();

	sockListen.Accept(sockSource);
	cout << "Connection accepted on port " << sourcePort << ".\n";
	sockListen.CloseSocket();

	cout << "Making connection to " << destinationHost << ", port " << destinationPort << ".\n";
	sockDestination.Create();
	sockDestination.Connect(destinationHost, destinationPort);

	cout << "Connection made to " << destinationHost << ", starting to forward.\n";

	SocketSource out(sockSource, false, new SocketSink(sockDestination));
	SocketSource in(sockDestination, false, new SocketSink(sockSource));

	WaitObjectContainer waitObjects;

	while (!(in.SourceExhausted() && out.SourceExhausted()))
	{
		waitObjects.Clear();

		out.GetWaitObjects(waitObjects);
		in.GetWaitObjects(waitObjects);

		waitObjects.Wait(INFINITE_TIME);

		if (!out.SourceExhausted())
		{
			cout << "o" << flush;
			out.PumpAll2(false);
			if (out.SourceExhausted())
				cout << "EOF received on source socket.\n";
		}

		if (!in.SourceExhausted())
		{
			cout << "i" << flush;
			in.PumpAll2(false);
			if (in.SourceExhausted())
				cout << "EOF received on destination socket.\n";
		}
	}
#else
	cout << "Socket support was not enabled at compile time.\n";
	exit(-1);
#endif
}

bool Validate(int alg, bool thorough, const char *seed)
{
	bool result;

	std::string timeSeed;
	if (!seed)
	{
		timeSeed = IntToString(time(NULL));
		seed = timeSeed.c_str();
	}

	cout << "Using seed: " << seed << endl << endl;
	GlobalRNG().Put((const byte *)seed, strlen(seed));

	switch (alg)
	{
	case 1: result = TestSettings(); break;
	case 2: result = TestOS_RNG(); break;
	case 3: result = ValidateMD5(); break;
	case 4: result = ValidateSHA(); break;
	case 5: result = ValidateDES(); break;
	case 6: result = ValidateIDEA(); break;
	case 7: result = ValidateARC4(); break;
	case 8: result = ValidateRC5(); break;
	case 9: result = ValidateBlowfish(); break;
	case 10: result = ValidateDiamond2(); break;
	case 11: result = ValidateThreeWay(); break;
	case 12: result = ValidateBBS(); break;
	case 13: result = ValidateDH(); break;
	case 14: result = ValidateRSA(); break;
	case 15: result = ValidateElGamal(); break;
	case 16: result = ValidateDSA(thorough); break;
	case 17: result = ValidateHAVAL(); break;
	case 18: result = ValidateSAFER(); break;
	case 19: result = ValidateLUC(); break;
	case 20: result = ValidateRabin(); break;
//	case 21: result = ValidateBlumGoldwasser(); break;
	case 22: result = ValidateECP(); break;
	case 23: result = ValidateEC2N(); break;
	case 24: result = ValidateMD5MAC(); break;
	case 25: result = ValidateGOST(); break;
	case 26: result = ValidateTiger(); break;
	case 27: result = ValidateRIPEMD(); break;
	case 28: result = ValidateHMAC(); break;
	case 29: result = ValidateXMACC(); break;
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
	default: result = ValidateAll(thorough); break;
	}

	time_t endTime = time(NULL);
	cout << "\nTest ended at " << asctime(localtime(&endTime));
	cout << "Seed used was: " << seed << endl;

	return result;
}
