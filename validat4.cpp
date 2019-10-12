// validat4.cpp - originally written and placed in the public domain by Wei Dai
//                CryptoPP::Test namespace added by JW in February 2017.
//                Source files split in July 2018 to expedite compiles.

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "cpu.h"
#include "validate.h"

#include "hex.h"
#include "base32.h"
#include "base64.h"

#include "rc2.h"
#include "aes.h"
#include "des.h"
#include "rc5.h"
#include "rc6.h"
#include "3way.h"
#include "aria.h"
#include "cast.h"
#include "mars.h"
#include "idea.h"
#include "gost.h"
#include "seal.h"
#include "seed.h"
#include "safer.h"
#include "shark.h"
#include "square.h"
#include "serpent.h"
#include "shacal2.h"
#include "twofish.h"
#include "blowfish.h"
#include "camellia.h"
#include "skipjack.h"

#include "arc4.h"
#include "salsa.h"
#include "chacha.h"
#include "rabbit.h"
#include "sosemanuk.h"

#include "modes.h"
#include "cmac.h"
#include "dmac.h"
#include "hmac.h"
#include "vmac.h"
#include "ttmac.h"

#include "drbg.h"

#include <iostream>
#include <iomanip>
#include <sstream>

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)


bool ValidateHmacDRBG()
{
	std::cout << "\nTesting NIST HMAC DRBGs...\n\n";
	bool pass=true, fail;

	// # CAVS 14.3
	// # DRBG800-90A information for "drbg_pr"
	// # Generated on Tue Apr 02 15:32:12 2013

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 0], [AdditionalInputLen = 0], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x79\x34\x9b\xbf\x7c\xdd\xa5\x79\x95\x57\x86\x66\x21\xc9\x13\x83";
		const byte entropy2[] = "\xc7\x21\x5b\x5b\x96\xc4\x8e\x9b\x33\x8c\x74\xe3\xe9\x9d\xfe\xdf";
		const byte nonce[] = "\x11\x46\x73\x3a\xbf\x8c\x35\xc8";

		HMAC_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8);
		drbg.IncorporateEntropy(entropy2, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(result, result.size());
		drbg.GenerateBlock(result, result.size());

		const byte expected[] = "\xc6\xa1\x6a\xb8\xd4\x20\x70\x6f\x0f\x34\xab\x7f\xec\x5a\xdc\xa9\xd8\xca\x3a\x13"
			"\x3e\x15\x9c\xa6\xac\x43\xc6\xf8\xa2\xbe\x22\x83\x4a\x4c\x0a\x0a\xff\xb1\x0d\x71"
			"\x94\xf1\xc1\xa5\xcf\x73\x22\xec\x1a\xe0\x96\x4e\xd4\xbf\x12\x27\x46\xe0\x87\xfd"
			"\xb5\xb3\xe9\x1b\x34\x93\xd5\xbb\x98\xfa\xed\x49\xe8\x5f\x13\x0f\xc8\xa4\x59\xb7";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "HMAC_DRBG SHA1/128/440 (COUNT=0, E=16, N=8)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 0], [AdditionalInputLen = 0], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\xee\x57\xfc\x23\x60\x0f\xb9\x02\x9a\x9e\xc6\xc8\x2e\x7b\x51\xe4";
		const byte entropy2[] = "\x84\x1d\x27\x6c\xa9\x51\x90\x61\xd9\x2d\x7d\xdf\xa6\x62\x8c\xa3";
		const byte nonce[] = "\x3e\x97\x21\xe4\x39\x3e\xf9\xad";

		HMAC_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8);
		drbg.IncorporateEntropy(entropy2, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(result, result.size());
		drbg.GenerateBlock(result, result.size());

		const byte expected[] = "\xee\x26\xa5\xc8\xef\x08\xa1\xca\x8f\x14\x15\x4d\x67\xc8\x8f\x5e\x7e\xd8\x21\x9d"
			"\x93\x1b\x98\x42\xac\x00\x39\xf2\x14\x55\x39\xf2\x14\x2b\x44\x11\x7a\x99\x8c\x22"
			"\xf5\x90\xf6\xc9\xb3\x8b\x46\x5b\x78\x3e\xcf\xf1\x3a\x77\x50\x20\x1f\x7e\xcf\x1b"
			"\x8a\xb3\x93\x60\x4c\x73\xb2\x38\x93\x36\x60\x9a\xf3\x44\x0c\xde\x43\x29\x8b\x84";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "HMAC_DRBG SHA1/128/440 (COUNT=1, E=16, N=8)\n";
	}

	// *****************************************************

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 0], [AdditionalInputLen = 16], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x7d\x70\x52\xa7\x76\xfd\x2f\xb3\xd7\x19\x1f\x73\x33\x04\xee\x8b";
		const byte entropy2[] = "\x49\x04\x7e\x87\x9d\x61\x09\x55\xee\xd9\x16\xe4\x06\x0e\x00\xc9";
		const byte nonce[] = "\xbe\x4a\x0c\xee\xdc\xa8\x02\x07";
		const byte additional1[] = "\xfd\x8b\xb3\x3a\xab\x2f\x6c\xdf\xbc\x54\x18\x11\x86\x1d\x51\x8d";
		const byte additional2[] = "\x99\xaf\xe3\x47\x54\x04\x61\xdd\xf6\xab\xeb\x49\x1e\x07\x15\xb4";
		const byte additional3[] = "\x02\xf7\x73\x48\x2d\xd7\xae\x66\xf7\x6e\x38\x15\x98\xa6\x4e\xf0";

		HMAC_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8);
		drbg.IncorporateEntropy(entropy2, 16, additional1, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(additional2, 16, result, result.size());
		drbg.GenerateBlock(additional3, 16, result, result.size());

		const byte expected[] = "\xa7\x36\x34\x38\x44\xfc\x92\x51\x13\x91\xdb\x0a\xdd\xd9\x06\x4d\xbe\xe2\x4c\x89"
			"\x76\xaa\x25\x9a\x9e\x3b\x63\x68\xaa\x6d\xe4\xc9\xbf\x3a\x0e\xff\xcd\xa9\xcb\x0e"
			"\x9d\xc3\x36\x52\xab\x58\xec\xb7\x65\x0e\xd8\x04\x67\xf7\x6a\x84\x9f\xb1\xcf\xc1"
			"\xed\x0a\x09\xf7\x15\x50\x86\x06\x4d\xb3\x24\xb1\xe1\x24\xf3\xfc\x9e\x61\x4f\xcb";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "HMAC_DRBG SHA1/128/440 (COUNT=0, E=16, N=8, A=16)\n";
	}

	{
		// [SHA-1], [PredictionResistance = False], [EntropyInputLen = 128], [NonceLen = 64]
		// [PersonalizationStringLen = 0], [AdditionalInputLen = 16], [ReturnedBitsLen = 640]
		const byte entropy1[] = "\x29\xc6\x2a\xfa\x3c\x52\x20\x8a\x3f\xde\xcb\x43\xfa\x61\x3f\x15";
		const byte entropy2[] = "\xbd\x87\xbe\x99\xd1\x84\x16\x54\x12\x31\x41\x40\xd4\x02\x71\x41";
		const byte nonce[] = "\x6c\x9e\xb5\x9a\xc3\xc2\xd4\x8b";
		const byte additional1[] = "\x43\x3d\xda\xf2\x59\xd1\x4b\xcf\x89\x76\x30\xcc\xaa\x27\x33\x8c";
		const byte additional2[] = "\x14\x11\x46\xd4\x04\xf2\x84\xc2\xd0\x2b\x6a\x10\x15\x6e\x33\x82";
		const byte additional3[] = "\xed\xc3\x43\xdb\xff\xe7\x1a\xb4\x11\x4a\xc3\x63\x9d\x44\x5b\x65";

		HMAC_DRBG<SHA1, 128/8, 440/8> drbg(entropy1, 16, nonce, 8);
		drbg.IncorporateEntropy(entropy2, 16, additional1, 16);

		SecByteBlock result(80);
		drbg.GenerateBlock(additional2, 16, result, result.size());
		drbg.GenerateBlock(additional3, 16, result, result.size());

		const byte expected[] = "\x8c\x73\x0f\x05\x26\x69\x4d\x5a\x9a\x45\xdb\xab\x05\x7a\x19\x75\x35\x7d\x65\xaf"
			"\xd3\xef\xf3\x03\x32\x0b\xd1\x40\x61\xf9\xad\x38\x75\x91\x02\xb6\xc6\x01\x16\xf6"
			"\xdb\x7a\x6e\x8e\x7a\xb9\x4c\x05\x50\x0b\x4d\x1e\x35\x7d\xf8\xe9\x57\xac\x89\x37"
			"\xb0\x5f\xb3\xd0\x80\xa0\xf9\x06\x74\xd4\x4d\xe1\xbd\x6f\x94\xd2\x95\xc4\x51\x9d";

		fail = !!memcmp(result, expected, 640/8);
		pass = !fail && pass;

		std::cout << (fail ? "FAILED   " : "passed   ") << "HMAC_DRBG SHA1/128/440 (COUNT=1, E=16, N=8, A=16)\n";
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
	FixedRoundsCipherFactory(unsigned int keylen=0) :
		m_keylen(keylen ? keylen : static_cast<unsigned int>(E::DEFAULT_KEYLENGTH)) {}

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
	VariableRoundsCipherFactory(unsigned int keylen=0, unsigned int rounds=0) :
		m_keylen(keylen ? keylen : static_cast<unsigned int>(E::DEFAULT_KEYLENGTH)),
		m_rounds(rounds ? rounds : static_cast<unsigned int>(E::DEFAULT_ROUNDS)) {}

	unsigned int BlockSize() const {return static_cast<unsigned int>(E::BLOCKSIZE);}
	unsigned int KeyLength() const {return m_keylen;}

	BlockTransformation* NewEncryption(const byte *keyStr) const
		{return new E(keyStr, m_keylen, m_rounds);}
	BlockTransformation* NewDecryption(const byte *keyStr) const
		{return new D(keyStr, m_keylen, m_rounds);}

	unsigned int m_keylen, m_rounds;
};

bool BlockTransformationTest(const CipherFactory &cg, BufferedTransformation &valdata, unsigned int tuples = 0xffff)
{
	HexEncoder output(new FileSink(std::cout));
	SecByteBlock plain(cg.BlockSize()), cipher(cg.BlockSize()), out(cg.BlockSize()), outplain(cg.BlockSize());
	SecByteBlock key(cg.KeyLength());
	bool pass=true, fail;

	while (valdata.MaxRetrievable() && tuples--)
	{
		(void)valdata.Get(key, cg.KeyLength());
		(void)valdata.Get(plain, cg.BlockSize());
		(void)valdata.Get(cipher, cg.BlockSize());

		member_ptr<BlockTransformation> transE(cg.NewEncryption(key));
		transE->ProcessBlock(plain, out);
		fail = memcmp(out, cipher, cg.BlockSize()) != 0;

		member_ptr<BlockTransformation> transD(cg.NewDecryption(key));
		transD->ProcessBlock(out, outplain);
		fail=fail || memcmp(outplain, plain, cg.BlockSize());

		pass = pass && !fail;

		std::cout << (fail ? "FAILED   " : "passed   ");
		output.Put(key, cg.KeyLength());
		std::cout << "   ";
		output.Put(outplain, cg.BlockSize());
		std::cout << "   ";
		output.Put(out, cg.BlockSize());
		std::cout << std::endl;
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
	std::cout << "\nDES validation suite running...\n\n";

	FileSource valdata(DataDir("TestData/descert.dat").c_str(), true, new HexDecoder);
	bool pass = BlockTransformationTest(FixedRoundsCipherFactory<DESEncryption, DESDecryption>(), valdata);

	std::cout << "\nTesting EDE2, EDE3, and XEX3 variants...\n\n";

	FileSource valdata1(DataDir("TestData/3desval.dat").c_str(), true, new HexDecoder);
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_EDE2_Encryption, DES_EDE2_Decryption>(), valdata1, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_EDE3_Encryption, DES_EDE3_Decryption>(), valdata1, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_XEX3_Encryption, DES_XEX3_Decryption>(), valdata1, 1) && pass;

	return pass;
}

bool TestModeIV(SymmetricCipher &e, SymmetricCipher &d)
{
	SecByteBlock lastIV, iv(e.IVSize());
	StreamTransformationFilter filter(e, new StreamTransformationFilter(d));

	// Enterprise Analysis finding on the stack based array
	const int BUF_SIZE=20480U;
	AlignedSecByteBlock plaintext(BUF_SIZE);

	for (unsigned int i=1; i<BUF_SIZE; i*=2)
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
	std::cout << "\nTesting DES modes...\n\n";
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
		fail = !TestFilter(StreamTransformationFilter(modeE, NULLPTR, StreamTransformationFilter::NO_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "ECB encryption" << std::endl;

		ECB_Mode_ExternalCipher::Decryption modeD(desD);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULLPTR, StreamTransformationFilter::NO_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "ECB decryption" << std::endl;
	}
	{
		// from FIPS 81
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C,
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F,
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULLPTR, StreamTransformationFilter::NO_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with no padding" << std::endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULLPTR, StreamTransformationFilter::NO_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with no padding" << std::endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC mode IV generation" << std::endl;
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
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with PKCS #7 padding" << std::endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with PKCS #7 padding" << std::endl;
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
		fail = !TestFilter(StreamTransformationFilter(modeE, NULLPTR, StreamTransformationFilter::ONE_AND_ZEROS_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with one-and-zeros padding" << std::endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULLPTR, StreamTransformationFilter::ONE_AND_ZEROS_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with one-and-zeros padding" << std::endl;
	}
	{
		const byte plain_1[] = {'a', 0, 0, 0, 0, 0, 0, 0};
		// generated with Crypto++
		const byte encrypted[] = {
			0x9B, 0x47, 0x57, 0x59, 0xD6, 0x9C, 0xF6, 0xD0};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULLPTR, StreamTransformationFilter::ZEROS_PADDING).Ref(),
			plain_1, 1, encrypted, sizeof(encrypted));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with zeros padding" << std::endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULLPTR, StreamTransformationFilter::ZEROS_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain_1, sizeof(plain_1));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with zeros padding" << std::endl;
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
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with ciphertext stealing (CTS)" << std::endl;

		CBC_CTS_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with ciphertext stealing (CTS)" << std::endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC CTS IV generation" << std::endl;
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
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with ciphertext and IV stealing" << std::endl;

		CBC_CTS_Mode_ExternalCipher::Decryption modeD(desD, stolenIV);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, 3);
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with ciphertext and IV stealing" << std::endl;
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
		std::cout << (fail ? "FAILED   " : "passed   ") << "CFB encryption" << std::endl;

		CFB_Mode_ExternalCipher::Decryption modeD(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CFB decryption" << std::endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CFB mode IV generation" << std::endl;
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
		std::cout << (fail ? "FAILED   " : "passed   ") << "CFB (8-bit feedback) encryption" << std::endl;

		CFB_Mode_ExternalCipher::Decryption modeD(desE, iv, 1);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain_2, sizeof(plain_2));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CFB (8-bit feedback) decryption" << std::endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "CFB (8-bit feedback) IV generation" << std::endl;
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
		std::cout << (fail ? "FAILED   " : "passed   ") << "OFB encryption" << std::endl;

		OFB_Mode_ExternalCipher::Decryption modeD(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "OFB decryption" << std::endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "OFB IV generation" << std::endl;
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
		std::cout << (fail ? "FAILED   " : "passed   ") << "Counter Mode encryption" << std::endl;

		CTR_Mode_ExternalCipher::Decryption modeD(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "Counter Mode decryption" << std::endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "Counter Mode IV generation" << std::endl;
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
		std::cout << (fail ? "FAILED   " : "passed   ") << "CBC MAC" << std::endl;

		DMAC<DES> dmac(key);
		HashFilter dmacFilter(dmac);
		fail = !TestFilter(dmacFilter, plain_3, sizeof(plain_3), mac2, sizeof(mac2));
		pass = pass && !fail;
		std::cout << (fail ? "FAILED   " : "passed   ") << "DMAC" << std::endl;
	}

	return pass;
}

bool ValidateIDEA()
{
	std::cout << "\nIDEA validation suite running...\n\n";

	FileSource valdata(DataDir("TestData/ideaval.dat").c_str(), true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<IDEAEncryption, IDEADecryption>(), valdata);
}

bool ValidateSAFER()
{
	std::cout << "\nSAFER validation suite running...\n\n";

	FileSource valdata(DataDir("TestData/saferval.dat").c_str(), true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_K_Encryption, SAFER_K_Decryption>(8,6), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_K_Encryption, SAFER_K_Decryption>(16,12), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_SK_Encryption, SAFER_SK_Decryption>(8,6), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_SK_Encryption, SAFER_SK_Decryption>(16,10), valdata, 4) && pass;
	return pass;
}

bool ValidateRC2()
{
	std::cout << "\nRC2 validation suite running...\n\n";

	FileSource valdata(DataDir("TestData/rc2val.dat").c_str(), true, new HexDecoder);
	HexEncoder output(new FileSink(std::cout));
	SecByteBlock plain(RC2Encryption::BLOCKSIZE), cipher(RC2Encryption::BLOCKSIZE), out(RC2Encryption::BLOCKSIZE), outplain(RC2Encryption::BLOCKSIZE);
	SecByteBlock key(128);
	bool pass=true, fail;

	while (valdata.MaxRetrievable())
	{
		byte keyLen, effectiveLen;

		(void)valdata.Get(keyLen);
		(void)valdata.Get(effectiveLen);
		(void)valdata.Get(key, keyLen);
		(void)valdata.Get(plain, RC2Encryption::BLOCKSIZE);
		(void)valdata.Get(cipher, RC2Encryption::BLOCKSIZE);

		member_ptr<BlockTransformation> transE(new RC2Encryption(key, keyLen, effectiveLen));
		transE->ProcessBlock(plain, out);
		fail = memcmp(out, cipher, RC2Encryption::BLOCKSIZE) != 0;

		member_ptr<BlockTransformation> transD(new RC2Decryption(key, keyLen, effectiveLen));
		transD->ProcessBlock(out, outplain);
		fail=fail || memcmp(outplain, plain, RC2Encryption::BLOCKSIZE);

		pass = pass && !fail;

		std::cout << (fail ? "FAILED   " : "passed   ");
		output.Put(key, keyLen);
		std::cout << "   ";
		output.Put(outplain, RC2Encryption::BLOCKSIZE);
		std::cout << "   ";
		output.Put(out, RC2Encryption::BLOCKSIZE);
		std::cout << std::endl;
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

	std::cout << "\nARC4 validation suite running...\n\n";

	arc4.reset(new Weak::ARC4(Key0, sizeof(Key0)));
	arc4->ProcessString(Input0, sizeof(Input0));
	fail = memcmp(Input0, Output0, sizeof(Input0)) != 0;
	std::cout << (fail ? "FAILED" : "passed") << "   Test 0" << std::endl;
	pass = pass && !fail;

	arc4.reset(new Weak::ARC4(Key1, sizeof(Key1)));
	arc4->ProcessString(Key1, Input1, sizeof(Key1));
	fail = memcmp(Output1, Key1, sizeof(Key1)) != 0;
	std::cout << (fail ? "FAILED" : "passed") << "   Test 1" << std::endl;
	pass = pass && !fail;

	arc4.reset(new Weak::ARC4(Key2, sizeof(Key2)));
	for (i=0, fail=false; i<sizeof(Input2); i++)
		if (arc4->ProcessByte(Input2[i]) != Output2[i])
			fail = true;
	std::cout << (fail ? "FAILED" : "passed") << "   Test 2" << std::endl;
	pass = pass && !fail;

	arc4.reset(new Weak::ARC4(Key3, sizeof(Key3)));
	for (i=0, fail=false; i<sizeof(Input3); i++)
		if (arc4->ProcessByte(Input3[i]) != Output3[i])
			fail = true;
	std::cout << (fail ? "FAILED" : "passed") << "   Test 3" << std::endl;
	pass = pass && !fail;

	arc4.reset(new Weak::ARC4(Key4, sizeof(Key4)));
	for (i=0, fail=false; i<sizeof(Input4); i++)
		if (arc4->ProcessByte(Input4[i]) != Output4[i])
			fail = true;
	std::cout << (fail ? "FAILED" : "passed") << "   Test 4" << std::endl;
	pass = pass && !fail;

	return pass;
}

bool ValidateRC5()
{
	std::cout << "\nRC5 validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/rc5val.dat").c_str(), true, new HexDecoder);
	return BlockTransformationTest(VariableRoundsCipherFactory<RC5Encryption, RC5Decryption>(16, 12), valdata) && pass1 && pass2;
}

bool ValidateRC6()
{
	std::cout << "\nRC6 validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/rc6val.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(16), valdata, 2) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(24), valdata, 2) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(32), valdata, 2) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateMARS()
{
	std::cout << "\nMARS validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/marsval.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(16), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(24), valdata, 3) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(32), valdata, 2) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateRijndael()
{
	std::cout << "\nRijndael (AES) validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/rijndael.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(16), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(24), valdata, 3) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(32), valdata, 2) && pass3;
	pass3 = RunTestDataFile("TestVectors/aes.txt") && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateTwofish()
{
	std::cout << "\nTwofish validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/twofishv.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(16), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(24), valdata, 3) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(32), valdata, 2) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateSerpent()
{
	std::cout << "\nSerpent validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/serpentv.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(16), valdata, 5) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(24), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(32), valdata, 3) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateBlowfish()
{
	std::cout << "\nBlowfish validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	HexEncoder output(new FileSink(std::cout));
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

		std::cout << (fail ? "FAILED   " : "passed   ");
		std::cout << '\"' << key[i] << '\"';
		for (int j=0; j<(signed int)(30-strlen(key[i])); j++)
			std::cout << ' ';
		output.Put(outplain, 8);
		std::cout << "  ";
		output.Put(out, 8);
		std::cout << std::endl;
	}
	return pass1 && pass2 && pass3;
}

bool ValidateThreeWay()
{
	std::cout << "\n3-WAY validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/3wayval.dat").c_str(), true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<ThreeWayEncryption, ThreeWayDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateGOST()
{
	std::cout << "\nGOST validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/gostval.dat").c_str(), true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<GOSTEncryption, GOSTDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateSHARK()
{
	std::cout << "\nSHARK validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/sharkval.dat").c_str(), true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SHARKEncryption, SHARKDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateCAST()
{
	std::cout << "\nCAST-128 validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource val128(DataDir("TestData/cast128v.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(16), val128, 1) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(10), val128, 1) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(5), val128, 1) && pass3;

	std::cout << "\nCAST-256 validation suite running...\n\n";
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
	std::cout << (pass4 && pass5 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource val256(DataDir("TestData/cast256v.dat").c_str(), true, new HexDecoder);
	pass6 = BlockTransformationTest(FixedRoundsCipherFactory<CAST256Encryption, CAST256Decryption>(16), val256, 1) && pass6;
	pass6 = BlockTransformationTest(FixedRoundsCipherFactory<CAST256Encryption, CAST256Decryption>(24), val256, 1) && pass6;
	pass6 = BlockTransformationTest(FixedRoundsCipherFactory<CAST256Encryption, CAST256Decryption>(32), val256, 1) && pass6;

	return pass1 && pass2 && pass3 && pass4 && pass5 && pass6;
}

bool ValidateSquare()
{
	std::cout << "\nSquare validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/squareva.dat").c_str(), true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SquareEncryption, SquareDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateSKIPJACK()
{
	std::cout << "\nSKIPJACK validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/skipjack.dat").c_str(), true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SKIPJACKEncryption, SKIPJACKDecryption>(), valdata) && pass1 && pass2;
}

bool ValidateSEAL()
{
	const byte input[] = {0x37,0xa0,0x05,0x95,0x9b,0x84,0xc4,0x9c,0xa4,0xbe,0x1e,0x05,0x06,0x73,0x53,0x0f,0x5f,0xb0,0x97,0xfd,0xf6,0xa1,0x3f,0xbd,0x6c,0x2c,0xde,0xcd,0x81,0xfd,0xee,0x7c};
	const byte key[] = {0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0};
	const byte iv[] = {0x01, 0x35, 0x77, 0xaf};
	byte output[32];

	std::cout << "\nSEAL validation suite running...\n\n";

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

	std::cout << (pass ? "passed" : "FAILED") << std::endl;
	return pass;
}

bool ValidateBaseCode()
{
	bool pass = true, fail;
	byte data[255];
	for (unsigned int i=0; i<255; i++)
		data[i] = byte(i);

	const char hexEncoded[] =
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"
		"28292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
		"505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F7071727374757677"
		"78797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"
		"C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFE";
	const char base32Encoded[] =
		"AAASEA2EAWDAQCAJBIFS2DIQB6IBCESVCSKTNF22DEPBYHA7D2RUAIJCENUCKJTHFAWUWK3NFWZC8NBT"
		"GI3VIPJYG66DUQT5HS8V6R4AIFBEGTCFI3DWSUKKJPGE4VURKBIXEW4WKXMFQYC3MJPX2ZK8M7SGC2VD"
		"NTUYN35IPFXGY5DPP3ZZA6MUQP4HK7VZRB6ZW856RX9H9AEBSKB2JBNGS8EIVCWMTUG27D6SUGJJHFEX"
		"U4M3TGN4VQQJ5HW9WCS4FI7EWYVKRKFJXKX43MPQX82MDNXVYU45PP72ZG7MZRF7Z496BSQC2RCNMTYH"
		"3DE6XU8N3ZHN9WGT4MJ7JXQY49NPVYY55VQ77Z9A6HTQH3HF65V8T4RK7RYQ55ZR8D29F69W8Z5RR8H3"
		"9M7939R8";
	const char base64AndHexEncoded[] =
		"41414543417751464267634943516F4C4441304F4478415245684D554652595847426B6147787764"
		"486838674953496A4A43556D4A7967704B6973734C5334764D4445794D7A51310A4E6A63344F546F"
		"375044302B50304242516B4E4552555A4853456C4B5330784E546B395155564A5456465657563168"
		"5A576C746358563566594746695932526C5A6D646F615770720A6247317562334278636E4E306458"
		"5A3365486C3665337839666E2B4167594B44684957476834694A696F754D6A5936506B4A47536B35"
		"53566C7065596D5A71626E4A32656E3643680A6F714F6B7061616E714B6D717136797472712B7773"
		"624B7A744C573274376935757275387662362F774D484377385446787366497963724C7A4D334F7A"
		"39445230745055316462580A324E6E6132397A6433742F6734654C6A354F586D352B6A7036757673"
		"3765377638504879382F5431397666342B6672372F50332B0A";
	const char base64URLAndHexEncoded[] =
		"41414543417751464267634943516F4C4441304F4478415245684D554652595847426B6147787764"
		"486838674953496A4A43556D4A7967704B6973734C5334764D4445794D7A51314E6A63344F546F37"
		"5044302D50304242516B4E4552555A4853456C4B5330784E546B395155564A54564656575631685A"
		"576C746358563566594746695932526C5A6D646F615770726247317562334278636E4E3064585A33"
		"65486C3665337839666E2D4167594B44684957476834694A696F754D6A5936506B4A47536B355356"
		"6C7065596D5A71626E4A32656E3643686F714F6B7061616E714B6D717136797472712D7773624B7A"
		"744C573274376935757275387662365F774D484377385446787366497963724C7A4D334F7A394452"
		"3074505531646258324E6E6132397A6433745F6734654C6A354F586D352D6A703675767337653776"
		"38504879385F5431397666342D6672375F50332D";

	std::cout << "\nBase64, Base64URL, Base32 and Base16 coding validation suite running...\n\n";

	fail = !TestFilter(HexEncoder().Ref(), data, 255, (const byte *)hexEncoded, strlen(hexEncoded));
	try {HexEncoder().IsolatedInitialize(g_nullNameValuePairs);}
	catch (const Exception&) {fail=true;}
	std::cout << (fail ? "FAILED:" : "passed:");
	std::cout << "  Hex Encoding\n";
	pass = pass && !fail;

	fail = !TestFilter(HexDecoder().Ref(), (const byte *)hexEncoded, strlen(hexEncoded), data, 255);
	try {HexDecoder().IsolatedInitialize(g_nullNameValuePairs);}
	catch (const Exception&) {fail=true;}
	std::cout << (fail ? "FAILED:" : "passed:");
	std::cout << "  Hex Decoding\n";
	pass = pass && !fail;

	fail = !TestFilter(Base32Encoder().Ref(), data, 255, (const byte *)base32Encoded, strlen(base32Encoded));
	try {Base32Encoder().IsolatedInitialize(g_nullNameValuePairs);}
	catch (const Exception&) {fail=true;}
	std::cout << (fail ? "FAILED:" : "passed:");
	std::cout << "  Base32 Encoding\n";
	pass = pass && !fail;

	fail = !TestFilter(Base32Decoder().Ref(), (const byte *)base32Encoded, strlen(base32Encoded), data, 255);
	try {Base32Decoder().IsolatedInitialize(g_nullNameValuePairs);}
	catch (const Exception&) {fail=true;}
	std::cout << (fail ? "FAILED:" : "passed:");
	std::cout << "  Base32 Decoding\n";
	pass = pass && !fail;

	fail = !TestFilter(Base64Encoder(new HexEncoder).Ref(), data, 255, (const byte *)base64AndHexEncoded, strlen(base64AndHexEncoded));
	try {Base64Encoder().IsolatedInitialize(g_nullNameValuePairs);}
	catch (const Exception&) {fail=true;}
	std::cout << (fail ? "FAILED:" : "passed:");
	std::cout << "  Base64 Encoding\n";
	pass = pass && !fail;

	fail = !TestFilter(HexDecoder(new Base64Decoder).Ref(), (const byte *)base64AndHexEncoded, strlen(base64AndHexEncoded), data, 255);
	try {Base64Decoder().IsolatedInitialize(g_nullNameValuePairs);}
	catch (const Exception&) {fail=true;}
	std::cout << (fail ? "FAILED:" : "passed:");
	std::cout << "  Base64 Decoding\n";
	pass = pass && !fail;

	fail = !TestFilter(Base64URLEncoder(new HexEncoder).Ref(), data, 255, (const byte *)base64URLAndHexEncoded, strlen(base64URLAndHexEncoded));
	try {Base64URLEncoder().IsolatedInitialize(g_nullNameValuePairs);}
	catch (const Exception&) {fail=true;}
	std::cout << (fail ? "FAILED:" : "passed:");
	std::cout << "  Base64 URL Encoding\n";
	pass = pass && !fail;

	fail = !TestFilter(HexDecoder(new Base64URLDecoder).Ref(), (const byte *)base64URLAndHexEncoded, strlen(base64URLAndHexEncoded), data, 255);
	try {Base64URLDecoder().IsolatedInitialize(g_nullNameValuePairs);}
	catch (const Exception&) {fail=true;}
	std::cout << (fail ? "FAILED:" : "passed:");
	std::cout << "  Base64 URL Decoding\n";
	pass = pass && !fail;

	return pass;
}

class MyEncoder : public SimpleProxyFilter
{
public:
	MyEncoder(BufferedTransformation *attachment = NULLPTR);
	void IsolatedInitialize(const NameValuePairs &params);
};

MyEncoder::MyEncoder(BufferedTransformation *attachment)
	: SimpleProxyFilter(new BaseN_Encoder(new Grouper), attachment)
{
	IsolatedInitialize(MakeParameters(Name::InsertLineBreaks(), true)(Name::MaxLineLength(), 72));
}

void MyEncoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	bool insertLineBreaks = parameters.GetValueWithDefault(Name::InsertLineBreaks(), true);
	int maxLineLength = parameters.GetIntValueWithDefault(Name::MaxLineLength(), 72);

	const byte padding = '=';
	const char *lineBreak = insertLineBreaks ? "\n" : "";

	char stars[64];
	memset(stars, '*', 64);

	m_filter->Initialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::EncodingLookupArray(), (const byte *)&stars[0], false)
			(Name::PaddingByte(), padding)
			(Name::GroupSize(), insertLineBreaks ? maxLineLength : 0)
			(Name::Separator(), ConstByteArrayParameter(lineBreak))
			(Name::Terminator(), ConstByteArrayParameter(lineBreak))
			(Name::Log2Base(), 6, true)));
}

class MyDecoder : public BaseN_Decoder
{
public:
	MyDecoder(BufferedTransformation *attachment = NULLPTR);
	void IsolatedInitialize(const NameValuePairs &params);
	static const int * CRYPTOPP_API GetDecodingLookupArray();
};

MyDecoder::MyDecoder(BufferedTransformation *attachment)
	: BaseN_Decoder(GetDecodingLookupArray(), 6, attachment)
{
}

void MyDecoder::IsolatedInitialize(const NameValuePairs &parameters)
{
	BaseN_Decoder::IsolatedInitialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::DecodingLookupArray(), GetDecodingLookupArray(), false)(Name::Log2Base(), 6, true)));
}

struct MyDecoderAlphabet
{
	MyDecoderAlphabet() {
		std::fill(tab, tab+COUNTOF(tab), '*');
	}
	byte tab[64];
};

struct MyDecoderArray
{
	MyDecoderArray() {
		std::fill(tab, tab+COUNTOF(tab), -1);
	}
	int tab[256];
};

const int * MyDecoder::GetDecodingLookupArray()
{
	static bool s_initialized = false;
	static MyDecoderAlphabet s_alpha;
	static MyDecoderArray s_array;

	MEMORY_BARRIER();
	if (!s_initialized)
	{
		InitializeDecodingLookupArray(s_array.tab, s_alpha.tab, COUNTOF(s_alpha.tab), false);
		s_initialized = true;
		MEMORY_BARRIER();
	}
	return s_array.tab;
}

bool ValidateEncoder()
{
	// The default encoder and decoder alphabet are bogus. They are a
	// string of '*'. To round trip a string both IsolatedInitialize
	// must be called and work correctly.
	std::cout << "\nCustom encoder validation running...\n\n";
	bool pass = true;

	int lookup[256];
	const char alphabet[64+1] =
		"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01234576789*";
	const char expected[] =
		"ILcBMSgriDicmKmTi2oENCsuJTufN0yWjL1HnS8xKdaiOkeZK3gKock1ktmlo1q4LlsNPrAyGrG0gjO2gzQ5FQ==";

	MyEncoder encoder;
	std::string str1;

	AlgorithmParameters eparams = MakeParameters(Name::EncodingLookupArray(),(const byte*)alphabet)
	                                            (Name::InsertLineBreaks(), false);
	encoder.IsolatedInitialize(eparams);

	encoder.Detach(new StringSink(str1));
	encoder.Put((const byte*) alphabet, 64);
	encoder.MessageEnd();

	MyDecoder decoder;
	std::string str2;

	MyDecoder::InitializeDecodingLookupArray(lookup, (const byte*) alphabet, 64, false);
	AlgorithmParameters dparams = MakeParameters(Name::DecodingLookupArray(),(const int*)lookup);
	decoder.IsolatedInitialize(dparams);

	decoder.Detach(new StringSink(str2));
	decoder.Put((const byte*) str1.data(), str1.size());
	decoder.MessageEnd();

	pass = (str1 == std::string(expected)) && pass;
	pass = (str2 == std::string(alphabet, 64)) && pass;

	std::cout << (pass ? "passed:" : "FAILED:");
	std::cout << "  Encode and decode\n";

	// Try forcing an empty message. This is the Monero bug
	// at https://github.com/weidai11/cryptopp/issues/562.
	{
		MyDecoder decoder2;
		SecByteBlock empty;

		AlgorithmParameters dparams2 = MakeParameters(Name::DecodingLookupArray(),(const int*)lookup);
		decoder2.IsolatedInitialize(dparams2);

		decoder2.Detach(new Redirector(TheBitBucket()));
		decoder2.Put(empty.BytePtr(), empty.SizeInBytes());
		decoder2.MessageEnd();

		// Tame the optimizer
		volatile lword size = decoder2.MaxRetrievable();
		lword shadow = size;
		CRYPTOPP_UNUSED(shadow);
	}

	std::cout << "passed:  0-length message\n";

	return pass;
}

bool ValidateSHACAL2()
{
	std::cout << "\nSHACAL-2 validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/shacal2v.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<SHACAL2Encryption, SHACAL2Decryption>(16), valdata, 4) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<SHACAL2Encryption, SHACAL2Decryption>(64), valdata, 10) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateARIA()
{
	std::cout << "\nARIA validation suite running...\n\n";
	bool pass1 = true, pass2 = true, pass3 = true;

	ARIAEncryption enc;
	pass1 = enc.StaticGetValidKeyLength(8) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(16) == 16 && pass1;
	pass1 = enc.StaticGetValidKeyLength(24) == 24 && pass1;
	pass1 = enc.StaticGetValidKeyLength(32) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(64) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(128) == 32 && pass1;
	pass1 = enc.StaticGetValidKeyLength(0) == enc.MinKeyLength() && pass1;
	pass1 = enc.StaticGetValidKeyLength(SIZE_MAX) == enc.MaxKeyLength() && pass1;

	ARIADecryption dec;
	pass2 = dec.StaticGetValidKeyLength(8) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(16) == 16 && pass2;
	pass2 = dec.StaticGetValidKeyLength(24) == 24 && pass2;
	pass2 = dec.StaticGetValidKeyLength(32) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(64) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(128) == 32 && pass2;
	pass2 = dec.StaticGetValidKeyLength(0) == dec.MinKeyLength() && pass2;
	pass2 = dec.StaticGetValidKeyLength(SIZE_MAX) == dec.MaxKeyLength() && pass2;
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/aria.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<ARIAEncryption, ARIADecryption>(16), valdata, 15) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<ARIAEncryption, ARIADecryption>(24), valdata, 15) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<ARIAEncryption, ARIADecryption>(32), valdata, 15) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateSIMECK()
{
	std::cout << "\nSIMECK validation suite running...\n";

	return RunTestDataFile("TestVectors/simeck.txt");
}

bool ValidateCHAM()
{
	std::cout << "\nCHAM validation suite running...\n";

	return RunTestDataFile("TestVectors/cham.txt");
}

bool ValidateHIGHT()
{
	std::cout << "\nHIGHT validation suite running...\n";

	return RunTestDataFile("TestVectors/hight.txt");
}

bool ValidateLEA()
{
	std::cout << "\nLEA validation suite running...\n";

	return RunTestDataFile("TestVectors/lea.txt");
}

bool ValidateSIMON()
{
	std::cout << "\nSIMON validation suite running...\n";

	return RunTestDataFile("TestVectors/simon.txt");
}

bool ValidateSPECK()
{
	std::cout << "\nSPECK validation suite running...\n";

	return RunTestDataFile("TestVectors/speck.txt");
}

bool ValidateCamellia()
{
	std::cout << "\nCamellia validation suite running...\n\n";
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
	std::cout << (pass1 && pass2 ? "passed:" : "FAILED:") << "  Algorithm key lengths\n";

	FileSource valdata(DataDir("TestData/camellia.dat").c_str(), true, new HexDecoder);
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CamelliaEncryption, CamelliaDecryption>(16), valdata, 15) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CamelliaEncryption, CamelliaDecryption>(24), valdata, 15) && pass3;
	pass3 = BlockTransformationTest(FixedRoundsCipherFactory<CamelliaEncryption, CamelliaDecryption>(32), valdata, 15) && pass3;
	return pass1 && pass2 && pass3;
}

bool ValidateSalsa()
{
	std::cout << "\nSalsa validation suite running...\n";

	return RunTestDataFile("TestVectors/salsa.txt");
}

bool ValidateChaCha()
{
	std::cout << "\nChaCha validation suite running...\n";

	return RunTestDataFile("TestVectors/chacha.txt");
}

bool ValidateChaChaTLS()
{
	std::cout << "\nChaCha-TLS validation suite running...\n";

	return RunTestDataFile("TestVectors/chacha_tls.txt");
}

bool ValidateSosemanuk()
{
	std::cout << "\nSosemanuk validation suite running...\n";
	return RunTestDataFile("TestVectors/sosemanuk.txt");
}

bool ValidateRabbit()
{
	std::cout << "\nRabbit validation suite running...\n";
	return RunTestDataFile("TestVectors/rabbit.txt");
}

bool ValidateHC128()
{
	std::cout << "\nHC-128 validation suite running...\n";
	return RunTestDataFile("TestVectors/hc128.txt");
}

bool ValidateHC256()
{
	std::cout << "\nHC-256 validation suite running...\n";
	return RunTestDataFile("TestVectors/hc256.txt");
}

bool ValidateVMAC()
{
	std::cout << "\nVMAC validation suite running...\n";
	return RunTestDataFile("TestVectors/vmac.txt");
}

bool ValidateCCM()
{
	std::cout << "\nAES/CCM validation suite running...\n";
	return RunTestDataFile("TestVectors/ccm.txt");
}

bool ValidateGCM()
{
	std::cout << "\nAES/GCM validation suite running...\n";
	std::cout << "\n2K tables:";
	bool pass = RunTestDataFile("TestVectors/gcm.txt", MakeParameters(Name::TableSize(), (int)2048));
	std::cout << "\n64K tables:";
	return RunTestDataFile("TestVectors/gcm.txt", MakeParameters(Name::TableSize(), (int)64*1024)) && pass;
}

bool ValidateXTS()
{
	std::cout << "\nAES/XTS validation suite running...\n";
	return RunTestDataFile("TestVectors/xts.txt");
}

bool ValidateCMAC()
{
	std::cout << "\nCMAC validation suite running...\n";
	return RunTestDataFile("TestVectors/cmac.txt");
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
