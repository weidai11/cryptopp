// validat2.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "pubkey.h"
#include "gfpcrypt.h"
#include "eccrypto.h"
#include "blumshub.h"
#include "filters.h"
#include "files.h"
#include "rsa.h"
#include "md2.h"
#include "elgamal.h"
#include "nr.h"
#include "dsa.h"
#include "dh.h"
#include "mqv.h"
#include "luc.h"
#include "xtrcrypt.h"
#include "rabin.h"
#include "rw.h"
#include "eccrypto.h"
#include "integer.h"
#include "gf2n.h"
#include "ecp.h"
#include "ec2n.h"
#include "asn.h"
#include "rng.h"
#include "hex.h"
#include "oids.h"
#include "esign.h"
#include "osrng.h"
#include "smartptr.h"

#include <iostream>
#include <sstream>
#include <iomanip>

#include "validate.h"

// Aggressive stack checking with VS2005 SP1 and above.
#if (CRYPTOPP_MSC_VERSION >= 1410)
# pragma strict_gs_check (on)
#endif

// Quiet deprecated warnings intended to benefit users.
#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4996)
#endif

#if CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

class FixedRNG : public RandomNumberGenerator
{
public:
	FixedRNG(BufferedTransformation &source) : m_source(source) {}

	void GenerateBlock(byte *output, size_t size)
	{
		m_source.Get(output, size);
	}

private:
	BufferedTransformation &m_source;
};

bool ValidateBBS()
{
	cout << "\nBlumBlumShub validation suite running...\n\n";

	Integer p("212004934506826557583707108431463840565872545889679278744389317666981496005411448865750399674653351");
	Integer q("100677295735404212434355574418077394581488455772477016953458064183204108039226017738610663984508231");
	Integer seed("63239752671357255800299643604761065219897634268887145610573595874544114193025997412441121667211431");
	BlumBlumShub bbs(p, q, seed);
	bool pass = true, fail;
	int j;

	static const byte output1[] = {
		0x49,0xEA,0x2C,0xFD,0xB0,0x10,0x64,0xA0,0xBB,0xB9,
		0x2A,0xF1,0x01,0xDA,0xC1,0x8A,0x94,0xF7,0xB7,0xCE};
	static const byte output2[] = {
		0x74,0x45,0x48,0xAE,0xAC,0xB7,0x0E,0xDF,0xAF,0xD7,
		0xD5,0x0E,0x8E,0x29,0x83,0x75,0x6B,0x27,0x46,0xA1};

	// Coverity finding, also see http://stackoverflow.com/a/34509163/608639.
	StreamState ss(cout);
	byte buf[20];

	bbs.GenerateBlock(buf, 20);
	fail = memcmp(output1, buf, 20) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<20;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	bbs.Seek(10);
	bbs.GenerateBlock(buf, 10);
	fail = memcmp(output1+10, buf, 10) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<10;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	bbs.Seek(1234567);
	bbs.GenerateBlock(buf, 20);
	fail = memcmp(output2, buf, 20) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<20;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	return pass;
}

bool SignatureValidate(PK_Signer &priv, PK_Verifier &pub, bool thorough = false)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "signature key validation\n";

	const byte *message = (byte *)"test message";
	const int messageLen = 12;

	SecByteBlock signature(priv.MaxSignatureLength());
	size_t signatureLength = priv.SignMessage(GlobalRNG(), message, messageLen, signature);
	fail = !pub.VerifyMessage(message, messageLen, signature, signatureLength);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "signature and verification\n";

	++signature[0];
	fail = pub.VerifyMessage(message, messageLen, signature, signatureLength);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "checking invalid signature" << endl;

	if (priv.MaxRecoverableLength() > 0)
	{
		signatureLength = priv.SignMessageWithRecovery(GlobalRNG(), message, messageLen, NULL, 0, signature);
		SecByteBlock recovered(priv.MaxRecoverableLengthFromSignatureLength(signatureLength));
		DecodingResult result = pub.RecoverMessage(recovered, NULL, 0, signature, signatureLength);
		fail = !(result.isValidCoding && result.messageLength == messageLen && memcmp(recovered, message, messageLen) == 0);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "signature and verification with recovery" << endl;

		++signature[0];
		result = pub.RecoverMessage(recovered, NULL, 0, signature, signatureLength);
		fail = result.isValidCoding;
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "recovery with invalid signature" << endl;
	}

	return pass;
}

bool CryptoSystemValidate(PK_Decryptor &priv, PK_Encryptor &pub, bool thorough = false)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "cryptosystem key validation\n";

	const byte *message = (byte *)"test message";
	const int messageLen = 12;
	SecByteBlock ciphertext(priv.CiphertextLength(messageLen));
	SecByteBlock plaintext(priv.MaxPlaintextLength(ciphertext.size()));

	pub.Encrypt(GlobalRNG(), message, messageLen, ciphertext);
	fail = priv.Decrypt(GlobalRNG(), ciphertext, priv.CiphertextLength(messageLen), plaintext) != DecodingResult(messageLen);
	fail = fail || memcmp(message, plaintext, messageLen);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "encryption and decryption\n";

	return pass;
}

bool SimpleKeyAgreementValidate(SimpleKeyAgreementDomain &d)
{
	if (d.GetCryptoParameters().Validate(GlobalRNG(), 3))
		cout << "passed    simple key agreement domain parameters validation" << endl;
	else
	{
		cout << "FAILED    simple key agreement domain parameters invalid" << endl;
		return false;
	}

	SecByteBlock priv1(d.PrivateKeyLength()), priv2(d.PrivateKeyLength());
	SecByteBlock pub1(d.PublicKeyLength()), pub2(d.PublicKeyLength());
	SecByteBlock val1(d.AgreedValueLength()), val2(d.AgreedValueLength());

	d.GenerateKeyPair(GlobalRNG(), priv1, pub1);
	d.GenerateKeyPair(GlobalRNG(), priv2, pub2);

	memset(val1.begin(), 0x10, val1.size());
	memset(val2.begin(), 0x11, val2.size());

	if (!(d.Agree(val1, priv1, pub2) && d.Agree(val2, priv2, pub1)))
	{
		cout << "FAILED    simple key agreement failed" << endl;
		return false;
	}

	if (memcmp(val1.begin(), val2.begin(), d.AgreedValueLength()))
	{
		cout << "FAILED    simple agreed values not equal" << endl;
		return false;
	}

	cout << "passed    simple key agreement" << endl;
	return true;
}

bool AuthenticatedKeyAgreementValidate(AuthenticatedKeyAgreementDomain &d)
{
	if (d.GetCryptoParameters().Validate(GlobalRNG(), 3))
		cout << "passed    authenticated key agreement domain parameters validation" << endl;
	else
	{
		cout << "FAILED    authenticated key agreement domain parameters invalid" << endl;
		return false;
	}

	SecByteBlock spriv1(d.StaticPrivateKeyLength()), spriv2(d.StaticPrivateKeyLength());
	SecByteBlock epriv1(d.EphemeralPrivateKeyLength()), epriv2(d.EphemeralPrivateKeyLength());
	SecByteBlock spub1(d.StaticPublicKeyLength()), spub2(d.StaticPublicKeyLength());
	SecByteBlock epub1(d.EphemeralPublicKeyLength()), epub2(d.EphemeralPublicKeyLength());
	SecByteBlock val1(d.AgreedValueLength()), val2(d.AgreedValueLength());

	d.GenerateStaticKeyPair(GlobalRNG(), spriv1, spub1);
	d.GenerateStaticKeyPair(GlobalRNG(), spriv2, spub2);
	d.GenerateEphemeralKeyPair(GlobalRNG(), epriv1, epub1);
	d.GenerateEphemeralKeyPair(GlobalRNG(), epriv2, epub2);

	memset(val1.begin(), 0x10, val1.size());
	memset(val2.begin(), 0x11, val2.size());

	if (!(d.Agree(val1, spriv1, epriv1, spub2, epub2) && d.Agree(val2, spriv2, epriv2, spub1, epub1)))
	{
		cout << "FAILED    authenticated key agreement failed" << endl;
		return false;
	}

	if (memcmp(val1.begin(), val2.begin(), d.AgreedValueLength()))
	{
		cout << "FAILED    authenticated agreed values not equal" << endl;
		return false;
	}

	cout << "passed    authenticated key agreement" << endl;
	return true;
}

bool ValidateRSA()
{
	cout << "\nRSA validation suite running...\n\n";

	byte out[100], outPlain[100];
	bool pass = true, fail;

	{
		const char *plain = "Everyone gets Friday off.";
		static const byte signature[] =
			"\x05\xfa\x6a\x81\x2f\xc7\xdf\x8b\xf4\xf2\x54\x25\x09\xe0\x3e\x84"
			"\x6e\x11\xb9\xc6\x20\xbe\x20\x09\xef\xb4\x40\xef\xbc\xc6\x69\x21"
			"\x69\x94\xac\x04\xf3\x41\xb5\x7d\x05\x20\x2d\x42\x8f\xb2\xa2\x7b"
			"\x5c\x77\xdf\xd9\xb1\x5b\xfc\x3d\x55\x93\x53\x50\x34\x10\xc1\xe1";

		FileSource keys(CRYPTOPP_DATA_DIR "TestData/rsa512a.dat", true, new HexDecoder);
		Weak::RSASSA_PKCS1v15_MD2_Signer rsaPriv(keys);
		Weak::RSASSA_PKCS1v15_MD2_Verifier rsaPub(rsaPriv);

		size_t signatureLength = rsaPriv.SignMessage(GlobalRNG(), (byte *)plain, strlen(plain), out);
		fail = memcmp(signature, out, 64) != 0;
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "signature check against test vector\n";

		fail = !rsaPub.VerifyMessage((byte *)plain, strlen(plain), out, signatureLength);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "verification check against test vector\n";

		out[10]++;
		fail = rsaPub.VerifyMessage((byte *)plain, strlen(plain), out, signatureLength);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "invalid signature verification\n";
	}
	{
		FileSource keys(CRYPTOPP_DATA_DIR "TestData/rsa1024.dat", true, new HexDecoder);
		RSAES_PKCS1v15_Decryptor rsaPriv(keys);
		RSAES_PKCS1v15_Encryptor rsaPub(rsaPriv);

		pass = CryptoSystemValidate(rsaPriv, rsaPub) && pass;
	}
	{
		RSAES<OAEP<SHA> >::Decryptor rsaPriv(GlobalRNG(), 512);
		RSAES<OAEP<SHA> >::Encryptor rsaPub(rsaPriv);

		pass = CryptoSystemValidate(rsaPriv, rsaPub) && pass;
	}
	{
		byte *plain = (byte *)
			"\x54\x85\x9b\x34\x2c\x49\xea\x2a";
		static const byte encrypted[] =
			"\x14\xbd\xdd\x28\xc9\x83\x35\x19\x23\x80\xe8\xe5\x49\xb1\x58\x2a"
			"\x8b\x40\xb4\x48\x6d\x03\xa6\xa5\x31\x1f\x1f\xd5\xf0\xa1\x80\xe4"
			"\x17\x53\x03\x29\xa9\x34\x90\x74\xb1\x52\x13\x54\x29\x08\x24\x52"
			"\x62\x51";
		static const byte oaepSeed[] =
			"\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2"
			"\xf0\x6c\xb5\x8f";
		ByteQueue bq;
		bq.Put(oaepSeed, 20);
		FixedRNG rng(bq);

		FileSource privFile(CRYPTOPP_DATA_DIR "TestData/rsa400pv.dat", true, new HexDecoder);
		FileSource pubFile(CRYPTOPP_DATA_DIR "TestData/rsa400pb.dat", true, new HexDecoder);
		RSAES_OAEP_SHA_Decryptor rsaPriv;
		rsaPriv.AccessKey().BERDecodePrivateKey(privFile, false, 0);
		RSAES_OAEP_SHA_Encryptor rsaPub(pubFile);

		memset(out, 0, 50);
		memset(outPlain, 0, 8);
		rsaPub.Encrypt(rng, plain, 8, out);
		DecodingResult result = rsaPriv.FixedLengthDecrypt(GlobalRNG(), encrypted, outPlain);
		fail = !result.isValidCoding || (result.messageLength!=8) || memcmp(out, encrypted, 50) || memcmp(plain, outPlain, 8);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "PKCS 2.0 encryption and decryption\n";
	}

	return pass;
}

bool ValidateDH()
{
	cout << "\nDH validation suite running...\n\n";

	FileSource f(CRYPTOPP_DATA_DIR "TestData/dh1024.dat", true, new HexDecoder());
	DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateMQV()
{
	cout << "\nMQV validation suite running...\n\n";

	FileSource f(CRYPTOPP_DATA_DIR "TestData/mqv1024.dat", true, new HexDecoder());
	MQV mqv(f);
	return AuthenticatedKeyAgreementValidate(mqv);
}

bool ValidateLUC_DH()
{
	cout << "\nLUC-DH validation suite running...\n\n";

	FileSource f(CRYPTOPP_DATA_DIR "TestData/lucd512.dat", true, new HexDecoder());
	LUC_DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateXTR_DH()
{
	cout << "\nXTR-DH validation suite running...\n\n";

	FileSource f(CRYPTOPP_DATA_DIR "TestData/xtrdh171.dat", true, new HexDecoder());
	XTR_DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateElGamal()
{
	cout << "\nElGamal validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc(CRYPTOPP_DATA_DIR "TestData/elgc1024.dat", true, new HexDecoder);
		ElGamalDecryptor privC(fc);
		ElGamalEncryptor pubC(privC);
		privC.AccessKey().Precompute();
		ByteQueue queue;
		privC.AccessKey().SavePrecomputation(queue);
		privC.AccessKey().LoadPrecomputation(queue);

		pass = CryptoSystemValidate(privC, pubC) && pass;
	}
	return pass;
}

bool ValidateDLIES()
{
	cout << "\nDLIES validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc(CRYPTOPP_DATA_DIR "TestData/dlie1024.dat", true, new HexDecoder);
		DLIES<>::Decryptor privC(fc);
		DLIES<>::Encryptor pubC(privC);
		pass = CryptoSystemValidate(privC, pubC) && pass;
	}
	{
		cout << "Generating new encryption key..." << endl;
		DLIES<>::GroupParameters gp;
		gp.GenerateRandomWithKeySize(GlobalRNG(), 128);
		DLIES<>::Decryptor decryptor;
		decryptor.AccessKey().GenerateRandom(GlobalRNG(), gp);
		DLIES<>::Encryptor encryptor(decryptor);

		pass = CryptoSystemValidate(decryptor, encryptor) && pass;
	}
	return pass;
}

bool ValidateNR()
{
	cout << "\nNR validation suite running...\n\n";
	bool pass = true;
	{
		FileSource f(CRYPTOPP_DATA_DIR "TestData/nr2048.dat", true, new HexDecoder);
		NR<SHA>::Signer privS(f);
		privS.AccessKey().Precompute();
		NR<SHA>::Verifier pubS(privS);

		pass = SignatureValidate(privS, pubS) && pass;
	}
	{
		cout << "Generating new signature key..." << endl;
		NR<SHA>::Signer privS(GlobalRNG(), 256);
		NR<SHA>::Verifier pubS(privS);

		pass = SignatureValidate(privS, pubS) && pass;
	}
	return pass;
}

bool ValidateDSA(bool thorough)
{
	cout << "\nDSA validation suite running...\n\n";

	bool pass = true;
	FileSource fs1(CRYPTOPP_DATA_DIR "TestData/dsa1024.dat", true, new HexDecoder());
	DSA::Signer priv(fs1);
	DSA::Verifier pub(priv);
	FileSource fs2(CRYPTOPP_DATA_DIR "TestData/dsa1024b.dat", true, new HexDecoder());
	DSA::Verifier pub1(fs2);
	assert(pub.GetKey() == pub1.GetKey());
	pass = SignatureValidate(priv, pub, thorough) && pass;
	pass = RunTestDataFile(CRYPTOPP_DATA_DIR "TestVectors/dsa.txt", g_nullNameValuePairs, thorough) && pass;

	return pass;
}

bool ValidateLUC()
{
	cout << "\nLUC validation suite running...\n\n";
	bool pass=true;

	{
		FileSource f(CRYPTOPP_DATA_DIR "TestData/luc1024.dat", true, new HexDecoder);
		LUCSSA_PKCS1v15_SHA_Signer priv(f);
		LUCSSA_PKCS1v15_SHA_Verifier pub(priv);
		pass = SignatureValidate(priv, pub) && pass;
	}
	{
		LUCES_OAEP_SHA_Decryptor priv(GlobalRNG(), 512);
		LUCES_OAEP_SHA_Encryptor pub(priv);
		pass = CryptoSystemValidate(priv, pub) && pass;
	}
	return pass;
}

bool ValidateLUC_DL()
{
	cout << "\nLUC-HMP validation suite running...\n\n";

	FileSource f(CRYPTOPP_DATA_DIR "TestData/lucs512.dat", true, new HexDecoder);
	LUC_HMP<SHA>::Signer privS(f);
	LUC_HMP<SHA>::Verifier pubS(privS);
	bool pass = SignatureValidate(privS, pubS);

	cout << "\nLUC-IES validation suite running...\n\n";

	FileSource fc(CRYPTOPP_DATA_DIR "TestData/lucc512.dat", true, new HexDecoder);
	LUC_IES<>::Decryptor privC(fc);
	LUC_IES<>::Encryptor pubC(privC);
	pass = CryptoSystemValidate(privC, pubC) && pass;

	return pass;
}

bool ValidateRabin()
{
	cout << "\nRabin validation suite running...\n\n";
	bool pass=true;

	{
		FileSource f(CRYPTOPP_DATA_DIR "TestData/rabi1024.dat", true, new HexDecoder);
		RabinSS<PSSR, SHA>::Signer priv(f);
		RabinSS<PSSR, SHA>::Verifier pub(priv);
		pass = SignatureValidate(priv, pub) && pass;
	}
	{
		RabinES<OAEP<SHA> >::Decryptor priv(GlobalRNG(), 512);
		RabinES<OAEP<SHA> >::Encryptor pub(priv);
		pass = CryptoSystemValidate(priv, pub) && pass;
	}
	return pass;
}

bool ValidateRW()
{
	cout << "\nRW validation suite running...\n\n";

	FileSource f(CRYPTOPP_DATA_DIR "TestData/rw1024.dat", true, new HexDecoder);
	RWSS<PSSR, SHA>::Signer priv(f);
	RWSS<PSSR, SHA>::Verifier pub(priv);

	return SignatureValidate(priv, pub);
}

/*
bool ValidateBlumGoldwasser()
{
	cout << "\nBlumGoldwasser validation suite running...\n\n";

	FileSource f(CRYPTOPP_DATA_DIR "TestData/blum512.dat", true, new HexDecoder);
	BlumGoldwasserPrivateKey priv(f);
	BlumGoldwasserPublicKey pub(priv);

	return CryptoSystemValidate(priv, pub);
}
*/

#if !defined(NDEBUG) && !defined(CRYPTOPP_IMPORTS)
// Issue 64: "PolynomialMod2::operator<<=", http://github.com/weidai11/cryptopp/issues/64
bool TestPolynomialMod2()
{
	bool pass1 = true, pass2 = true, pass3 = true;

	cout << "\nTesting PolynomialMod2 bit operations...\n\n";

	static const unsigned int start = 0;
	static const unsigned int stop = 4 * WORD_BITS + 1;

	for (unsigned int i=start; i < stop; i++)
	{
		PolynomialMod2 p(1);
		p <<= i;

		Integer n(Integer::One());
		n <<= i;

		std::ostringstream oss1;
		oss1 << p;

		std::string str1, str2;

		// str1 needs the commas removed used for grouping
		str1 = oss1.str();
		str1.erase(std::remove(str1.begin(), str1.end(), ','), str1.end());

		// str1 needs the trailing 'b' removed
		str1.erase(str1.end() - 1);

		// str2 is fine as-is
		str2 = IntToString(n, 2);

		pass1 &= (str1 == str2);
	}

	for (unsigned int i=start; i < stop; i++)
	{
		const word w((word)SIZE_MAX);

		PolynomialMod2 p(w);
		p <<= i;

		Integer n(Integer::POSITIVE, static_cast<lword>(w));
		n <<= i;

		std::ostringstream oss1;
		oss1 << p;

		std::string str1, str2;

		// str1 needs the commas removed used for grouping
		str1 = oss1.str();
		str1.erase(std::remove(str1.begin(), str1.end(), ','), str1.end());

		// str1 needs the trailing 'b' removed
		str1.erase(str1.end() - 1);

		// str2 is fine as-is
		str2 = IntToString(n, 2);

		pass2 &= (str1 == str2);
	}

	RandomNumberGenerator& prng = GlobalRNG();
	for (unsigned int i=start; i < stop; i++)
	{
		word w; 	// Cast to lword due to Visual Studio
		prng.GenerateBlock((byte*)&w, sizeof(w));

		PolynomialMod2 p(w);
		p <<= i;

		Integer n(Integer::POSITIVE, static_cast<lword>(w));
		n <<= i;

		std::ostringstream oss1;
		oss1 << p;

		std::string str1, str2;

		// str1 needs the commas removed used for grouping
		str1 = oss1.str();
		str1.erase(std::remove(str1.begin(), str1.end(), ','), str1.end());

		// str1 needs the trailing 'b' removed
		str1.erase(str1.end() - 1);

		// str2 is fine as-is
		str2 = IntToString(n, 2);

		if (str1 != str2)
		{
			cout << "  Oops..." << "\n";
			cout << "     random: " << std::hex << n << std::dec << "\n";
			cout << "     str1: " << str1 << "\n";
			cout << "     str2: " << str2 << "\n";
		}

		pass3 &= (str1 == str2);
	}

	cout << (!pass1 ? "FAILED" : "passed") << "    " << "1 shifted over range [" << dec << start << "," << stop << "]" << "\n";
	cout << (!pass2 ? "FAILED" : "passed") << "    " << "0x" << hex << word(SIZE_MAX) << dec << " shifted over range [" << start << "," << stop << "]" << "\n";
	cout << (!pass3 ? "FAILED" : "passed") << "    " << "random values shifted over range [" << dec << start << "," << stop << "]" << "\n";

	if (!(pass1 && pass2 && pass3))
		cout.flush();

	return pass1 && pass2 && pass3;
}
#endif

bool ValidateRFC6979() {
	cout << "RFC 6979 Validation Suite Starting" << endl;

	// RFC 6979 test suite private keys
	Integer prvkey_1024("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7h");
	Integer prvkey_2048("69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBCh");
	Integer prvkey_192p("6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4h");
	Integer prvkey_224p("F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1h");
	Integer prvkey_256p("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721h");
	Integer prvkey_384p("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5h");
	Integer prvkey_521p("00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538h");
	Integer prvkey_163k("09A4D6792295A7F730FC3F2B49CBC0F62E862272Fh");
	Integer prvkey_233k("103B2142BDC2A3C3B55080D09DF1808F79336DA2399F5CA7171D1BE9B0h");
	Integer prvkey_283k("06A0777356E87B89BA1ED3A3D845357BE332173C8F7A65BDC7DB4FAB3C4CC79ACC8194Eh");
	Integer prvkey_409k("29C16768F01D1B8A89FDA85E2EFD73A09558B92A178A2931F359E4D70AD853E569CDAF16DAA569758FB4E73089E4525D8BBFCFh");
	Integer prvkey_571k("0C16F58550D824ED7B95569D4445375D3A490BC7E0194C41A39DEB732C29396CDF1D66DE02DD1460A816606F3BEC0F32202C7BD18A32D87506466AA92032F1314ED7B19762B0D22h");
	Integer prvkey_163r("35318FC447D48D7E6BC93B48617DDDEDF26AA658Fh");
	Integer prvkey_233r("07ADC13DD5BF34D1DDEEB50B2CE23B5F5E6D18067306D60C5F6FF11E5D3h");
	Integer prvkey_283r("14510D4BC44F2D26F4553942C98073C1BD35545CEABB5CC138853C5158D2729EA408836h");
	Integer prvkey_409r("0494994CC325B08E7B4CE038BD9436F90B5E59A2C13C3140CD3AE07C04A01FC489F572CE0569A6DB7B8060393DE76330C624177h");
	Integer prvkey_571r("028A04857F24C1C082DF0D909C0E72F453F2E2340CCB071F0E389BCA2575DA19124198C57174929AD26E348CF63F78D28021EF5A9BF2D5CBEAF6B7CCB6C4DA824DD5C82CFB24E11h");

	// Python and/or Trezor ECDSA test suite private keys for secp256k1.
	Integer prvkey1_256k1("9d0219792467d7d37b4d43298a7d0c05h");
	Integer prvkey2_256k1("cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50h");
	Integer prvkey3_256k1("01h");
	Integer prvkey4_256k1("01h");
	Integer prvkey5_256k1("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140h");
	Integer prvkey6_256k1("f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181h");
	Integer prvkey7_256k1("e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2h");

	// RFC 6979 test suite curve orders
	Integer ord_1024("996F967F6C8E388D9E28D01E205FBA957A5698B1h"); // qlen = 160
	Integer ord_2048("F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1Fh"); // qlen = 256
	Integer ord_192p("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831h"); // qlen = 192
	Integer ord_224p("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3Dh"); // qlen = 224
	Integer ord_256p("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551h"); // qlen = 256
	Integer ord_384p("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973h"); // qlen = 384
	Integer ord_521p("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409h"); // qlen = 521
	Integer ord_163k("4000000000000000000020108A2E0CC0D99F8A5EFh"); // qlen = 163
	Integer ord_233k("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDFh"); // qlen = 232
	Integer ord_283k("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61h"); // qlen = 281
	Integer ord_409k("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCFh"); // qlen = 407
	Integer ord_571k("20000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001h"); // qlen = 570
	Integer ord_163r("40000000000000000000292FE77E70C12A4234C33h"); // qlen = 163
	Integer ord_233r("1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7h"); // qlen = 233
	Integer ord_283r("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307h"); // qlen = 282
	Integer ord_409r("10000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173h"); // qlen = 409
	Integer ord_571r("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47h"); // qlen = 570

        // Python and/or Trezor ECDSA curve orders.
	Integer ord_256k1("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141h"); // qlen = 256

	// RFC 6979 test suite k-value results
	Integer sha1res_sample_1024("7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5Bh");
	Integer sha1res_sample_2048("888FA6F7738A41BDC9846466ABDB8174C0338250AE50CE955CA16230F9CBD53Eh");
	Integer sha1res_sample_192p("37D7CA00D2C7B0E5E412AC03BD44BA837FDD5B28CD3B0021h");
	Integer sha1res_sample_224p("7EEFADD91110D8DE6C2C470831387C50D3357F7F4D477054B8B426BCh");
	Integer sha1res_sample_256p("882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4h");
	Integer sha1res_sample_384p("4471EF7518BB2C7C20F62EAE1C387AD0C5E8E470995DB4ACF694466E6AB096630F29E5938D25106C3C340045A2DB01A7h");
	Integer sha1res_sample_521p("089C071B419E1C2820962321787258469511958E80582E95D8378E0C2CCDB3CB42BEDE42F50E3FA3C71F5A76724281D31D9C89F0F91FC1BE4918DB1C03A5838D0F9h");
	Integer sha1res_sample_163k("09744429FA741D12DE2BE8316E35E84DB9E5DF1CDh");
	Integer sha1res_sample_233k("273179E3E12C69591AD3DD9C7CCE3985820E3913AB6696EB14486DDBCFh");
	Integer sha1res_sample_283k("0A96F788DECAF6C9DBE24DC75ABA6EAAE85E7AB003C8D4F83CB1540625B2993BF445692h");
	Integer sha1res_sample_409k("7866E5247F9A3556F983C86E81EDA696AC8489DB40A2862F278603982D304F08B2B6E1E7848534BEAF1330D37A1CF84C7994C1h");
	Integer sha1res_sample_571k("17F7E360B21BEAE4A757A19ACA77FB404D273F05719A86EAD9D7B3F4D5ED7B4630584BB153CF7DCD5A87CCA101BD7EA9ECA0CE5EE27CA985833560000BB52B6BBE068740A45B267h");
	Integer sha1res_sample_163r("0707A94C3D352E0A9FE49FB12F264992152A20004h");
	Integer sha1res_sample_233r("0A4E0B67A3A081C1B35D7BECEB5FE72A918B422B907145DB5416ED751CEh");
	Integer sha1res_sample_283r("277F389559667E8AE4B65DC056F8CE2872E1917E7CC59D17D485B0B98343206FBCCD441h");
	Integer sha1res_sample_409r("042D8A2B34402757EB2CCFDDC3E6E96A7ADD3FDA547FC10A0CB77CFC720B4F9E16EEAAA2A8CC4E4A4B5DBF7D8AC4EA491859E60h");
	Integer sha1res_sample_571r("2669FAFEF848AF67D437D4A151C3C5D3F9AA8BB66EDC35F090C9118F95BA0041B0993BE2EF55DAAF36B5B3A737C40DB1F6E3D93D97B8419AD6E1BB8A5D4A0E9B2E76832D4E7B862h");
	Integer sha224res_sample_1024("562097C06782D60C3037BA7BE104774344687649h");
	Integer sha224res_sample_2048("BC372967702082E1AA4FCE892209F71AE4AD25A6DFD869334E6F153BD0C4D806h");
	Integer sha224res_sample_192p("4381526B3FC1E7128F202E194505592F01D5FF4C5AF015D8h");
	Integer sha224res_sample_224p("C1D1F2F10881088301880506805FEB4825FE09ACB6816C36991AA06Dh");
	Integer sha224res_sample_256p("103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473h");
	Integer sha224res_sample_384p("A4E4D2F0E729EB786B31FC20AD5D849E304450E0AE8E3E341134A5C1AFA03CAB8083EE4E3C45B06A5899EA56C51B5879h");
	Integer sha224res_sample_521p("121415EC2CD7726330A61F7F3FA5DE14BE9436019C4DB8CB4041F3B54CF31BE0493EE3F427FB906393D895A19C9523F3A1D54BB8702BD4AA9C99DAB2597B92113F3h");
	Integer sha224res_sample_163k("323E7B28BFD64E6082F5B12110AA87BC0D6A6E159h");
	Integer sha224res_sample_233k("71626A309D9CD80AD0B975D757FE6BF4B84E49F8F34C780070D7746F19h");
	Integer sha224res_sample_283k("1B4C4E3B2F6B08B5991BD2BDDE277A7016DA527AD0AAE5BC61B64C5A0EE63E8B502EF61h");
	Integer sha224res_sample_409k("512340DB682C7B8EBE407BF1AA54194DFE85D49025FE0F632C9B8A06A996F2FCD0D73C752FB09D23DB8FBE50605DC25DF0745Ch");
	Integer sha224res_sample_571k("0B599D068A1A00498EE0B9AD6F388521F594BD3F234E47F7A1DB6490D7B57D60B0101B36F39CC22885F78641C69411279706F0989E6991E5D5B53619E43EFB397E25E0814EF02BCh");
	Integer sha224res_sample_163r("3B24C5E2C2D935314EABF57A6484289B291ADFE3Fh");
	Integer sha224res_sample_233r("0F2B1C1E80BEB58283AAA79857F7B83BDF724120D0913606FD07F7FFB2Ch");
	Integer sha224res_sample_283r("14CC8FCFEECD6B999B4DC6084EBB06FDED0B44D5C507802CC7A5E9ECF36E69DA6AE23C6h");
	Integer sha224res_sample_409r("0C933F1DC4C70838C2AD16564715ACAF545BCDD8DC203D25AF3EC63949C65CB2E68AC1F60CA7EACA2A823F4E240927AA82CEEC5h");
	Integer sha224res_sample_571r("2EAFAD4AC8644DEB29095BBAA88D19F31316434F1766AD4423E0B54DD2FE0C05E307758581B0DAED2902683BBC7C47B00E63E3E429BA54EA6BA3AEC33A94C9A24A6EF8E27B7677Ah");
	Integer sha256res_sample_1024("519BA0546D0C39202A7D34D7DFA5E760B318BCFBh");
	Integer sha256res_sample_2048("8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52h");
	Integer sha256res_sample_192p("32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496h");
	Integer sha256res_sample_224p("AD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDCh");
	Integer sha256res_sample_256p("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60h");
	Integer sha256res_sample_384p("180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E375572342863C899F9F2EDF9747A9B60h");
	Integer sha256res_sample_521p("0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C32575761793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E1A0h");
	Integer sha256res_sample_163k("23AF4074C90A02B3FE61D286D5C87F425E6BDD81Bh");
	Integer sha256res_sample_233k("73552F9CAC5774F74F485FA253871F2109A0C86040552EAA67DBA92DC9h");
	Integer sha256res_sample_283k("1CEB9E8E0DFF53CE687DEB81339ACA3C98E7A657D5A9499EF779F887A934408ECBE5A38h");
	Integer sha256res_sample_409k("782385F18BAF5A36A588637A76DFAB05739A14163BF723A4417B74BD1469D37AC9E8CCE6AEC8FF63F37B815AAF14A876EED962h");
	Integer sha256res_sample_571k("0F79D53E63D89FB87F4D9E6DC5949F5D9388BCFE9EBCB4C2F7CE497814CF40E845705F8F18DBF0F860DE0B1CC4A433EF74A5741F3202E958C082E0B76E16ECD5866AA0F5F3DF300h");
	Integer sha256res_sample_163r("3D7086A59E6981064A9CDB684653F3A81B6EC0F0Bh");
	Integer sha256res_sample_233r("034A53897B0BBDB484302E19BF3F9B34A2ABFED639D109A388DC52006B5h");
	Integer sha256res_sample_283r("38C9D662188982943E080B794A4CFB0732DBA37C6F40D5B8CFADED6FF31C5452BA3F877h");
	Integer sha256res_sample_409r("08EC42D13A3909A20C41BEBD2DFED8CACCE56C7A7D1251DF43F3E9E289DAE00E239F6960924AC451E125B784CB687C7F23283FDh");
	Integer sha256res_sample_571r("15C2C6B7D1A070274484774E558B69FDFA193BDB7A23F27C2CD24298CE1B22A6CC9B7FB8CABFD6CF7C6B1CF3251E5A1CDDD16FBFED28DE79935BB2C631B8B8EA9CC4BCC937E669Eh");
	Integer sha384res_sample_1024("95897CD7BBB944AA932DBC579C1C09EB6FCFC595h");
	Integer sha384res_sample_2048("C345D5AB3DA0A5BCB7EC8F8FB7A7E96069E03B206371EF7D83E39068EC564920h");
	Integer sha384res_sample_192p("4730005C4FCB01834C063A7B6760096DBE284B8252EF4311h");
	Integer sha384res_sample_224p("52B40F5A9D3D13040F494E83D3906C6079F29981035C7BD51E5CAC40h");
	Integer sha384res_sample_256p("09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4h");
	Integer sha384res_sample_384p("94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA95368623B8C4686915CF9h");
	Integer sha384res_sample_521p("1546A108BC23A15D6F21872F7DED661FA8431DDBD922D0DCDB77CC878C8553FFAD064C95A920A750AC9137E527390D2D92F153E66196966EA554D9ADFCB109C4211h");
	Integer sha384res_sample_163k("2132ABE0ED518487D3E4FA7FD24F8BED1F29CCFCEh");
	Integer sha384res_sample_233k("17D726A67539C609BD99E29AA3737EF247724B71455C3B6310034038C8h");
	Integer sha384res_sample_283k("1460A5C41745A5763A9D548AE62F2C3630BBED71B6AA549D7F829C22442A728C5D965DAh");
	Integer sha384res_sample_409k("4DA637CB2E5C90E486744E45A73935DD698D4597E736DA332A06EDA8B26D5ABC6153EC2ECE14981CF3E5E023F36FFA55EEA6D7h");
	Integer sha384res_sample_571k("0308253C022D25F8A9EBCD24459DD6596590BDEC7895618EEE8A2623A98D2A2B2E7594EE6B7AD3A39D70D68CB4ED01CB28E2129F8E2CC0CC8DC7780657E28BCD655F0BE9B7D35A2h");
	Integer sha384res_sample_163r("3B1E4443443486C7251A68EF184A936F05F8B17C7h");
	Integer sha384res_sample_233r("04D4670B28990BC92EEB49840B482A1FA03FE028D09F3D21F89C67ECA85h");
	Integer sha384res_sample_283r("21B7265DEBF90E6F988CFFDB62B121A02105226C652807CC324ED6FB119A287A72680ABh");
	Integer sha384res_sample_409r("0DA881BCE3BA851485879EF8AC585A63F1540B9198ECB8A1096D70CB25A104E2F8A96B108AE76CB49CF34491ABC70E9D2AAD450h");
	Integer sha384res_sample_571r("0FEF0B68CB49453A4C6ECBF1708DBEEFC885C57FDAFB88417AAEFA5B1C35017B4B498507937ADCE2F1D9EFFA5FE8F5AEB116B804FD182A6CF1518FDB62D53F60A0FF6EB707D856Bh");
	Integer sha512res_sample_1024("09ECE7CA27D0F5A4DD4E556C9DF1D21D28104F8Bh");
	Integer sha512res_sample_2048("5A12994431785485B3F5F067221517791B85A597B7A9436995C89ED0374668FCh");
	Integer sha512res_sample_192p("A2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1h");
	Integer sha512res_sample_224p("9DB103FFEDEDF9CFDBA05184F925400C1653B8501BAB89CEA0FBEC14h");
	Integer sha512res_sample_256p("5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5h");
	Integer sha512res_sample_384p("92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331A4E966532593A52980D0E3AAA5E10EC3h");
	Integer sha512res_sample_521p("1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3h");
	Integer sha512res_sample_163k("00BBCC2F39939388FDFE841892537EC7B1FF33AA3h");
	Integer sha512res_sample_233k("0E535C328774CDE546BE3AF5D7FCD263872F107E807435105BA2FDC166h");
	Integer sha512res_sample_283k("00F3B59FCB5C1A01A1A2A0019E98C244DFF61502D6E6B9C4E957EDDCEB258EF4DBEF04Ah");
	Integer sha512res_sample_409k("57055B293ECFDFE983CEF716166091E573275C53906A39EADC25C89C5EC8D7A7E5629FCFDFAD514E1348161C9A34EA1C42D58Ch");
	Integer sha512res_sample_571k("0C5EE7070AF55F84EBC43A0D481458CEDE1DCEBB57720A3C92F59B4941A044FECFF4F703940F3121773595E880333772ACF822F2449E17C64DA286BCD65711DD5DA44D7155BF004h");
	Integer sha512res_sample_163r("2EDF5CFCAC7553C17421FDF54AD1D2EF928A879D2h");
	Integer sha512res_sample_233r("0DE108AAADA760A14F42C057EF81C0A31AF6B82E8FBCA8DC86E443AB549h");
	Integer sha512res_sample_283r("20583259DC179D9DA8E5387E89BFF2A3090788CF1496BCABFE7D45BB120B0C811EB8980h");
	Integer sha512res_sample_409r("0750926FFAD7FF5DE85DF7960B3A4F9E3D38CF5A049BFC89739C48D42B34FBEE03D2C047025134CC3145B60AFD22A68DF0A7FB2h");
	Integer sha512res_sample_571r("3FF373833A06C791D7AD586AFA3990F6EF76999C35246C4AD0D519BFF180CA1880E11F2FB38B764854A0AE3BECDDB50F05AC4FCEE542F207C0A6229E2E19652F0E647B9C4882193h");
	Integer sha1res_test_1024("5C842DF4F9E344EE09F056838B42C7A17F4A6433h");
	Integer sha1res_test_2048("6EEA486F9D41A037B2C640BC5645694FF8FF4B98D066A25F76BE641CCB24BA4Fh");
	Integer sha1res_test_192p("D9CF9C3D3297D3260773A1DA7418DB5537AB8DD93DE7FA25h");
	Integer sha1res_test_224p("2519178F82C3F0E4F87ED5883A4E114E5B7A6E374043D8EFD329C253h");
	Integer sha1res_test_256p("8C9520267C55D6B980DF741E56B4ADEE114D84FBFA2E62137954164028632A2Eh");
	Integer sha1res_test_384p("66CC2C8F4D303FC962E5FF6A27BD79F84EC812DDAE58CF5243B64A4AD8094D47EC3727F3A3C186C15054492E30698497h");
	Integer sha1res_test_521p("0BB9F2BF4FE1038CCF4DABD7139A56F6FD8BB1386561BD3C6A4FC818B20DF5DDBA80795A947107A1AB9D12DAA615B1ADE4F7A9DC05E8E6311150F47F5C57CE8B222h");
	Integer sha1res_test_163k("14CAB9192F39C8A0EA8E81B4B87574228C99CD681h");
	Integer sha1res_test_233k("1D8BBF5CB6EFFA270A1CDC22C81E269F0CC16E27151E0A460BA9B51AFFh");
	Integer sha1res_test_283k("168B5F8C0881D4026C08AC5894A2239D219FA9F4DA0600ADAA56D5A1781AF81F08A726Eh");
	Integer sha1res_test_409k("545453D8DC05D220F9A12EF322D0B855E664C72835FABE8A41211453EB8A7CFF950D80773839D0043A46852DDA5A536E02291Fh");
	Integer sha1res_test_571k("1D056563469E933E4BE064585D84602D430983BFBFD6885A94BA484DF9A7AB031AD6AC090A433D8EEDC0A7643EA2A9BC3B6299E8ABA933B4C1F2652BB49DAEE833155C8F1319908h");
	Integer sha1res_test_163r("10024F5B324CBC8954BA6ADB320CD3AB9296983B4h");
	Integer sha1res_test_233r("0250C5C90A4E2A3F8849FEBA87F0D0AE630AB18CBABB84F4FFFB36CEAC0h");
	Integer sha1res_test_283r("0185C57A743D5BA06193CE2AA47B07EF3D6067E5AE1A6469BCD3FC510128BA564409D82h");
	Integer sha1res_test_409r("017E167EAB1850A3B38EE66BFE2270F2F6BFDAC5E2D227D47B20E75F0719161E6C74E9F23088F0C58B1E63BC6F185AD2EF4EAE6h");
	Integer sha1res_test_571r("019B506FD472675A7140E429AA5510DCDDC21004206EEC1B39B28A688A8FD324138F12503A4EFB64F934840DFBA2B4797CFC18B8BD0B31BBFF3CA66A4339E4EF9D771B15279D1DCh");
	Integer sha224res_test_1024("4598B8EFC1A53BC8AECD58D1ABBB0C0C71E67297h");
	Integer sha224res_test_2048("06BD4C05ED74719106223BE33F2D95DA6B3B541DAD7BFBD7AC508213B6DA6670h");
	Integer sha224res_test_192p("F5DC805F76EF851800700CCE82E7B98D8911B7D510059FBEh");
	Integer sha224res_test_224p("DF8B38D40DCA3E077D0AC520BF56B6D565134D9B5F2EAE0D34900524h");
	Integer sha224res_test_256p("669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7h");
	Integer sha224res_test_384p("18FA39DB95AA5F561F30FA3591DC59C0FA3653A80DAFFA0B48D1A4C6DFCBFF6E3D33BE4DC5EB8886A8ECD093F2935726h");
	Integer sha224res_test_521p("040D09FCF3C8A5F62CF4FB223CBBB2B9937F6B0577C27020A99602C25A01136987E452988781484EDBBCF1C47E554E7FC901BC3085E5206D9F619CFF07E73D6F706h");
	Integer sha224res_test_163k("091DD986F38EB936BE053DD6ACE3419D2642ADE8Dh");
	Integer sha224res_test_233k("67634D0ABA2C9BF7AE54846F26DCD166E7100654BCE6FDC96667631AA2h");
	Integer sha224res_test_283k("045E13EA645CE01D9B25EA38C8A8A170E04C83BB7F231EE3152209FE10EC8B2E565536Ch");
	Integer sha224res_test_409k("3C5352929D4EBE3CCE87A2DCE380F0D2B33C901E61ABC530DAF3506544AB0930AB9BFD553E51FCDA44F06CD2F49E17E07DB519h");
	Integer sha224res_test_571k("1DA875065B9D94DBE75C61848D69578BCC267935792624F9887B53C9AF9E43CABFC42E4C3F9A456BA89E717D24F1412F33CFD297A7A4D403B18B5438654C74D592D5022125E0C6Bh");
	Integer sha224res_test_163r("34F46DE59606D56C75406BFB459537A7CC280AA62h");
	Integer sha224res_test_233r("07BDB6A7FD080D9EC2FC84BFF9E3E15750789DC04290C84FED00E109BBDh");
	Integer sha224res_test_283r("2E5C1F00677A0E015EC3F799FA9E9A004309DBD784640EAAF5E1CE64D3045B9FE9C1FA1h");
	Integer sha224res_test_409r("01ADEB94C19951B460A146B8275D81638C07735B38A525D76023AAF26AA8A058590E1D5B1E78AB3C91608BDA67CFFBE6FC8A6CCh");
	Integer sha224res_test_571r("333C711F8C62F205F926593220233B06228285261D34026232F6F729620C6DE12220F282F4206D223226705608688B20B8BA86D8DFE54F07A37EC48F253283AC33C3F5102C8CC3Eh");
	Integer sha256res_test_1024("5A67592E8128E03A417B0484410FB72C0B630E1Ah");
	Integer sha256res_test_2048("1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7h");
	Integer sha256res_test_192p("5C4CE89CF56D9E7C77C8585339B006B97B5F0680B4306C6Ch");
	Integer sha256res_test_224p("FF86F57924DA248D6E44E8154EB69F0AE2AEBAEE9931D0B5A969F904h");
	Integer sha256res_test_256p("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0h");
	Integer sha256res_test_384p("0CFAC37587532347DC3389FDC98286BBA8C73807285B184C83E62E26C401C0FAA48DD070BA79921A3457ABFF2D630AD7h");
	Integer sha256res_test_521p("01DE74955EFAABC4C4F17F8E84D881D1310B5392D7700275F82F145C61E843841AF09035BF7A6210F5A431A6A9E81C9323354A9E69135D44EBD2FCAA7731B909258h");
	Integer sha256res_test_163k("193649CE51F0CFF0784CFC47628F4FA854A93F7A2h");
	Integer sha256res_test_233k("2CE5AEDC155ACC0DDC5E679EBACFD21308362E5EFC05C5E99B2557A8D7h");
	Integer sha256res_test_283k("0B585A7A68F51089691D6EDE2B43FC4451F66C10E65F134B963D4CBD4EB844B0E1469A6h");
	Integer sha256res_test_409k("251E32DEE10ED5EA4AD7370DF3EFF091E467D5531CA59DE3AA791763715E1169AB5E18C2A11CD473B0044FB45308E8542F2EB0h");
	Integer sha256res_test_571k("04DDD0707E81BB56EA2D1D45D7FAFDBDD56912CAE224086802FEA1018DB306C4FB8D93338DBF6841CE6C6AB1506E9A848D2C0463E0889268843DEE4ACB552CFFCB858784ED116B2h");
	Integer sha256res_test_163r("38145E3FFCA94E4DDACC20AD6E0997BD0E3B669D2h");
	Integer sha256res_test_233r("00376886E89013F7FF4B5214D56A30D49C99F53F211A3AFE01AA2BDE12Dh");
	Integer sha256res_test_283r("018A7D44F2B4341FEFE68F6BD8894960F97E08124AAB92C1FFBBE90450FCC9356C9AAA5h");
	Integer sha256res_test_409r("06EBA3D58D0E0DFC406D67FC72EF0C943624CF40019D1E48C3B54CCAB0594AFD5DEE30AEBAA22E693DBCFECAD1A85D774313DADh");
	Integer sha256res_test_571r("328E02CF07C7B5B6D3749D8302F1AE5BFAA8F239398459AF4A2C859C7727A8123A7FE9BE8B228413FC8DC0E9DE16AF3F8F43005107F9989A5D97A5C4455DA895E81336710A3FB2Ch");
	Integer sha384res_test_1024("220156B761F6CA5E6C9F1B9CF9C24BE25F98CD89h");
	Integer sha384res_test_2048("206E61F73DBE1B2DC8BE736B22B079E9DACD974DB00EEBBC5B64CAD39CF9F91Ch");
	Integer sha384res_test_192p("5AFEFB5D3393261B828DB6C91FBC68C230727B030C975693h");
	Integer sha384res_test_224p("7046742B839478C1B5BD31DB2E862AD868E1A45C863585B5F22BDC2Dh");
	Integer sha384res_test_256p("16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8h");
	Integer sha384res_test_384p("015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092ADA71F4A459BC0DA98ADB95837DB8312EAh");
	Integer sha384res_test_521p("1F1FC4A349A7DA9A9E116BFDD055DC08E78252FF8E23AC276AC88B1770AE0B5DCEB1ED14A4916B769A523CE1E90BA22846AF11DF8B300C38818F713DADD85DE0C88h");
	Integer sha384res_test_163k("37C73C6F8B404EC83DA17A6EBCA724B3FF1F7EEBAh");
	Integer sha384res_test_233k("1B4BD3903E74FD0B31E23F956C70062014DFEFEE21832032EA5352A055h");
	Integer sha384res_test_283k("1E88738E14482A09EE16A73D490A7FE8739DF500039538D5C4B6C8D6D7F208D6CA56760h");
	Integer sha384res_test_409k("11C540EA46C5038FE28BB66E2E9E9A04C9FE9567ADF33D56745953D44C1DC8B5B92922F53A174E431C0ED8267D919329F19014h");
	Integer sha384res_test_571k("0141B53DC6E569D8C0C0718A58A5714204502FDA146E7E2133E56D19E905B79413457437095DE13CF68B5CF5C54A1F2E198A55D974FC3E507AFC0ACF95ED391C93CC79E3B3FE37Ch");
	Integer sha384res_test_163r("375813210ECE9C4D7AB42DDC3C55F89189CF6DFFDh");
	Integer sha384res_test_233r("03726870DE75613C5E529E453F4D92631C03D08A7F63813E497D4CB3877h");
	Integer sha384res_test_283r("3C75397BA4CF1B931877076AF29F2E2F4231B117AB4B8E039F7F9704DE1BD3522F150B6h");
	Integer sha384res_test_409r("0A45B787DB44C06DEAB846511EEDBF7BFCFD3BD2C11D965C92FC195F67328F36A2DC83C0352885DAB96B55B02FCF49DCCB0E2DAh");
	Integer sha384res_test_571r("2A77E29EAD9E811A9FDA0284C14CDFA1D9F8FA712DA59D530A06CDE54187E250AD1D4FB5788161938B8DE049616399C5A56B0737C9564C9D4D845A4C6A7CDFCBFF0F01A82BE672Eh");
	Integer sha512res_test_1024("65D2C2EEB175E370F28C75BFCDC028D22C7DBE9Ch");
	Integer sha512res_test_2048("AFF1651E4CD6036D57AA8B2A05CCF1A9D5A40166340ECBBDC55BE10B568AA0AAh");
	Integer sha512res_test_192p("0758753A5254759C7CFBAD2E2D9B0792EEE44136C9480527h");
	Integer sha512res_test_224p("E39C2AA4EA6BE2306C72126D40ED77BF9739BB4D6EF2BBB1DCB6169Dh");
	Integer sha512res_test_256p("6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7Fh");
	Integer sha512res_test_384p("3780C4F67CB15518B6ACAE34C9F83568D2E12E47DEAB6C50A4E4EE5319D1E8CE0E2CC8A136036DC4B9C00E6888F66B6Ch");
	Integer sha512res_test_521p("16200813020EC986863BEDFC1B121F605C1215645018AEA1A7B215A564DE9EB1B38A67AA1128B80CE391C4FB71187654AAA3431027BFC7F395766CA988C964DC56Dh");
	Integer sha512res_test_163k("331AD98D3186F73967B1E0B120C80B1E22EFC2988h");
	Integer sha512res_test_233k("1775ED919CA491B5B014C5D5E86AF53578B5A7976378F192AF665CB705h");
	Integer sha512res_test_283k("00E5F24A223BD459653F682763C3BB322D4EE75DD89C63D4DC61518D543E76585076BBAh");
	Integer sha512res_test_409k("59527CE953BC09DF5E85155CAE7BB1D7F342265F41635545B06044F844ECB4FA6476E7D47420ADC8041E75460EC0A4EC760E95h");
	Integer sha512res_test_571k("14842F97F263587A164B215DD0F912C588A88DC4AB6AF4C530ADC1226F16E086D62C14435E6BFAB56F019886C88922D2321914EE41A8F746AAA2B964822E4AC6F40EE2492B66824h");
	Integer sha512res_test_163r("25AD8B393BC1E9363600FDA1A2AB6DF40079179A3h");
	Integer sha512res_test_233r("09CE5810F1AC68810B0DFFBB6BEEF2E0053BB937969AE7886F9D064A8C4h");
	Integer sha512res_test_283r("14E66B18441FA54C21E3492D0611D2B48E19DE3108D915FD5CA08E786327A2675F11074h");
	Integer sha512res_test_409r("0B90F8A0E757E81D4EA6891766729C96A6D01F9AEDC0D334932D1F81CC4E1973A4F01C33555FF08530A5098CADB6EDAE268ABB5h");
	Integer sha512res_test_571r("21CE6EE4A2C72C9F93BDB3B552F4A633B8C20C200F894F008643240184BE57BB282A1645E47FBBE131E899B4C61244EFC2486D88CDBD1DD4A65EBDD837019D02628D0DCD6ED8FB5h");

	// RFC 6979 test suite messages.
	string data1 = "sample";
	string data2 = "test";

	// Python ECDSA test suite data for secp256k1
	Integer sha256res1_256k1("8fa1f95d514760e498f28957b824ee6ec39ed64826ff4fecc2b5739ec45b91cdh");
	Integer sha256res2_256k1("2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3h");
	Integer sha256res3_256k1("8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15h");
	Integer sha256res4_256k1("38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3h");
	Integer sha256res5_256k1("33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90h");
	Integer sha256res6_256k1("525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1h");
	Integer sha256res7_256k1("1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3dh");

	// Python ECDSA test suite data for secp256k1.
	string data1_256k1 = "sample";
	string data2_256k1 = "sample";
	string data3_256k1 = "Satoshi Nakamoto";
	string data4_256k1 = "All those moments will be lost in time, like tears in rain. Time to die...";
	string data5_256k1 = "Satoshi Nakamoto";
	string data6_256k1 = "Alan Turing";
	string data7_256k1 = "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!";

	// DSA
	DSA2<SHA1, true>::Signer dsa_ds_sha1;
	DSA2<SHA224, true>::Signer dsa_ds_sha224;
	DSA2<SHA256, true>::Signer dsa_ds_sha256;
	DSA2<SHA384, true>::Signer dsa_ds_sha384;
	DSA2<SHA512, true>::Signer dsa_ds_sha512;

	// Technically, some of the tested curves use binary fields (EC2N), not
	// prime fields (ECP). k-value creation doesn't care about this. So, for
	// code simplicity, we'll just pretend all the curves use prime fields.
	ECDSA<ECP, SHA1, true>::Signer ds_sha1;
	ECDSA<ECP, SHA224, true>::Signer ds_sha224;
	ECDSA<ECP, SHA256, true>::Signer ds_sha256;
	ECDSA<ECP, SHA384, true>::Signer ds_sha384;
	ECDSA<ECP, SHA512, true>::Signer ds_sha512;

	//// TESTS DISABLED FOR NOW DUE TO CODE REFACTORING.
	// Unless otherwise noted, all tests are from RFC 6979.
	// DSA-1024
/*	Integer sha1calc_sample_1024 = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_1024,
	                                                  ord_1024.BitCount(),
	                                                  prvkey_1024);
	Integer sha1calc_test_1024 = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_1024,
	                                                ord_1024.BitCount(),
	                                                prvkey_1024);
	Integer sha224calc_sample_1024 = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_1024,
	                                                      ord_1024.BitCount(),
	                                                      prvkey_1024);
	Integer sha224calc_test_1024 = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_1024,
	                                                    ord_1024.BitCount(),
	                                                    prvkey_1024);
	Integer sha256calc_sample_1024 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_1024,
	                                                      ord_1024.BitCount(),
	                                                      prvkey_1024);
	Integer sha256calc_test_1024 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_1024,
	                                                    ord_1024.BitCount(),
	                                                    prvkey_1024);
	Integer sha384calc_sample_1024 = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_1024,
	                                                      ord_1024.BitCount(),
	                                                      prvkey_1024);
	Integer sha384calc_test_1024 = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_1024,
	                                                    ord_1024.BitCount(),
	                                                    prvkey_1024);
	Integer sha512calc_sample_1024 = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_1024,
	                                                      ord_1024.BitCount(),
	                                                      prvkey_1024);
	Integer sha512calc_test_1024 = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_1024,
	                                                    ord_1024.BitCount(),
	                                                    prvkey_1024);

	bool pass = (sha1calc_sample_1024 == sha1res_sample_1024);
	pass &= (sha1calc_test_1024 == sha1res_test_1024);
	pass &= (sha224calc_sample_1024 == sha224res_sample_1024);
	pass &= (sha224calc_test_1024 == sha224res_test_1024);
	pass &= (sha256calc_sample_1024 == sha256res_sample_1024);
	pass &= (sha256calc_test_1024 == sha256res_test_1024);
	pass &= (sha384calc_sample_1024 == sha384res_sample_1024);
	pass &= (sha384calc_test_1024 == sha384res_test_1024);
	pass &= (sha512calc_sample_1024 == sha512res_sample_1024);
	pass &= (sha512calc_test_1024 == sha512res_test_1024);
	cout << (pass ? "passed" : "FAILED") << "    DSA-1024" << endl;

	// DSA-2048
	Integer sha1calc_sample_2048 = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_2048,
	                                                  ord_2048.BitCount(),
	                                                  prvkey_2048);
	Integer sha1calc_test_2048 = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_2048,
	                                                ord_2048.BitCount(),
	                                                prvkey_2048);
	Integer sha224calc_sample_2048 = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_2048,
	                                                      ord_2048.BitCount(),
	                                                      prvkey_2048);
	Integer sha224calc_test_2048 = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_2048,
	                                                    ord_2048.BitCount(),
	                                                    prvkey_2048);
	Integer sha256calc_sample_2048 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_2048,
	                                                      ord_2048.BitCount(),
	                                                      prvkey_2048);
	Integer sha256calc_test_2048 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_2048,
	                                                    ord_2048.BitCount(),
	                                                    prvkey_2048);
	Integer sha384calc_sample_2048 = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_2048,
	                                                      ord_2048.BitCount(),
	                                                      prvkey_2048);
	Integer sha384calc_test_2048 = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_2048,
	                                                    ord_2048.BitCount(),
	                                                    prvkey_2048);
	Integer sha512calc_sample_2048 = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_2048,
	                                                      ord_2048.BitCount(),
	                                                      prvkey_2048);
	Integer sha512calc_test_2048 = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_2048,
	                                                    ord_2048.BitCount(),
	                                                    prvkey_2048);

	pass = (sha1calc_sample_2048 == sha1res_sample_2048);
	pass &= (sha1calc_test_2048 == sha1res_test_2048);
	pass &= (sha224calc_sample_2048 == sha224res_sample_2048);
	pass &= (sha224calc_test_2048 == sha224res_test_2048);
	pass &= (sha256calc_sample_2048 == sha256res_sample_2048);
	pass &= (sha256calc_test_2048 == sha256res_test_2048);
	pass &= (sha384calc_sample_2048 == sha384res_sample_2048);
	pass &= (sha384calc_test_2048 == sha384res_test_2048);
	pass &= (sha512calc_sample_2048 == sha512res_sample_2048);
	pass &= (sha512calc_test_2048 == sha512res_test_2048);
	cout << (pass ? "passed" : "FAILED") << "    DSA-2048" << endl;

	// secp192r1
	Integer sha1calc_sample_192p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_192p,
	                                                  ord_192p.BitCount(),
	                                                  prvkey_192p);
	Integer sha1calc_test_192p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_192p,
	                                                ord_192p.BitCount(),
	                                                prvkey_192p);
	Integer sha224calc_sample_192p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_192p,
	                                                      ord_192p.BitCount(),
	                                                      prvkey_192p);
	Integer sha224calc_test_192p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_192p,
	                                                    ord_192p.BitCount(),
	                                                    prvkey_192p);
	Integer sha256calc_sample_192p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_192p,
	                                                      ord_192p.BitCount(),
	                                                      prvkey_192p);
	Integer sha256calc_test_192p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_192p,
	                                                    ord_192p.BitCount(),
	                                                    prvkey_192p);
	Integer sha384calc_sample_192p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_192p,
	                                                      ord_192p.BitCount(),
	                                                      prvkey_192p);
	Integer sha384calc_test_192p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_192p,
	                                                    ord_192p.BitCount(),
	                                                    prvkey_192p);
	Integer sha512calc_sample_192p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_192p,
	                                                      ord_192p.BitCount(),
	                                                      prvkey_192p);
	Integer sha512calc_test_192p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_192p,
	                                                    ord_192p.BitCount(),
	                                                    prvkey_192p);

	pass = (sha1calc_sample_192p == sha1res_sample_192p);
	pass &= (sha1calc_test_192p == sha1res_test_192p);
	pass &= (sha224calc_sample_192p == sha224res_sample_192p);
	pass &= (sha224calc_test_192p == sha224res_test_192p);
	pass &= (sha256calc_sample_192p == sha256res_sample_192p);
	pass &= (sha256calc_test_192p == sha256res_test_192p);
	pass &= (sha384calc_sample_192p == sha384res_sample_192p);
	pass &= (sha384calc_test_192p == sha384res_test_192p);
	pass &= (sha512calc_sample_192p == sha512res_sample_192p);
	pass &= (sha512calc_test_192p == sha512res_test_192p);
	cout << (pass ? "passed" : "FAILED") << "    secp192r1" << endl;

	// secp224r1
	Integer sha1calc_sample_224p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_224p,
	                                                  ord_224p.BitCount(),
	                                                  prvkey_224p);
	Integer sha1calc_test_224p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_224p,
	                                                ord_224p.BitCount(),
	                                                prvkey_224p);
	Integer sha224calc_sample_224p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_224p,
	                                                      ord_224p.BitCount(),
	                                                      prvkey_224p);
	Integer sha224calc_test_224p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_224p,
	                                                    ord_224p.BitCount(),
	                                                    prvkey_224p);
	Integer sha256calc_sample_224p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_224p,
	                                                      ord_224p.BitCount(),
	                                                      prvkey_224p);
	Integer sha256calc_test_224p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_224p,
	                                                    ord_224p.BitCount(),
	                                                    prvkey_224p);
	Integer sha384calc_sample_224p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_224p,
	                                                      ord_224p.BitCount(),
	                                                      prvkey_224p);
	Integer sha384calc_test_224p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_224p,
	                                                    ord_224p.BitCount(),
	                                                    prvkey_224p);
	Integer sha512calc_sample_224p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_224p,
	                                                      ord_224p.BitCount(),
	                                                      prvkey_224p);
	Integer sha512calc_test_224p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_224p,
	                                                    ord_224p.BitCount(),
	                                                    prvkey_224p);

	pass = (sha1calc_sample_224p == sha1res_sample_224p);
	pass &= (sha1calc_test_224p == sha1res_test_224p);
	pass &= (sha224calc_sample_224p == sha224res_sample_224p);
	pass &= (sha224calc_test_224p == sha224res_test_224p);
	pass &= (sha256calc_sample_224p == sha256res_sample_224p);
	pass &= (sha256calc_test_224p == sha256res_test_224p);
	pass &= (sha384calc_sample_224p == sha384res_sample_224p);
	pass &= (sha384calc_test_224p == sha384res_test_224p);
	pass &= (sha512calc_sample_224p == sha512res_sample_224p);
	pass &= (sha512calc_test_224p == sha512res_test_224p);
	cout << (pass ? "passed" : "FAILED") << "    secp224r1" << endl;

	// secp256r1
	Integer sha1calc_sample_256p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_256p,
	                                                  ord_256p.BitCount(),
	                                                  prvkey_256p);
	Integer sha1calc_test_256p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_256p,
	                                                ord_256p.BitCount(),
	                                                prvkey_256p);
	Integer sha224calc_sample_256p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_256p,
	                                                      ord_256p.BitCount(),
	                                                      prvkey_256p);
	Integer sha224calc_test_256p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_256p,
	                                                    ord_256p.BitCount(),
	                                                    prvkey_256p);
	Integer sha256calc_sample_256p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_256p,
	                                                      ord_256p.BitCount(),
	                                                      prvkey_256p);
	Integer sha256calc_test_256p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_256p,
	                                                    ord_256p.BitCount(),
	                                                    prvkey_256p);
	Integer sha384calc_sample_256p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_256p,
	                                                      ord_256p.BitCount(),
	                                                      prvkey_256p);
	Integer sha384calc_test_256p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_256p,
	                                                    ord_256p.BitCount(),
	                                                    prvkey_256p);
	Integer sha512calc_sample_256p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_256p,
	                                                      ord_256p.BitCount(),
	                                                      prvkey_256p);
	Integer sha512calc_test_256p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_256p,
	                                                    ord_256p.BitCount(),
	                                                    prvkey_256p);

	pass = (sha1calc_sample_256p == sha1res_sample_256p);
	pass &= (sha1calc_test_256p == sha1res_test_256p);
	pass &= (sha224calc_sample_256p == sha224res_sample_256p);
	pass &= (sha224calc_test_256p == sha224res_test_256p);
	pass &= (sha256calc_sample_256p == sha256res_sample_256p);
	pass &= (sha256calc_test_256p == sha256res_test_256p);
	pass &= (sha384calc_sample_256p == sha384res_sample_256p);
	pass &= (sha384calc_test_256p == sha384res_test_256p);
	pass &= (sha512calc_sample_256p == sha512res_sample_256p);
	pass &= (sha512calc_test_256p == sha512res_test_256p);
	cout << (pass ? "passed" : "FAILED") << "    secp256r1" << endl;

	// secp384r1
	Integer sha1calc_sample_384p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_384p,
	                                                  ord_384p.BitCount(),
	                                                  prvkey_384p);
	Integer sha1calc_test_384p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_384p,
	                                                ord_384p.BitCount(),
	                                                prvkey_384p);
	Integer sha224calc_sample_384p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_384p,
	                                                      ord_384p.BitCount(),
	                                                      prvkey_384p);
	Integer sha224calc_test_384p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_384p,
	                                                    ord_384p.BitCount(),
	                                                    prvkey_384p);
	Integer sha256calc_sample_384p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_384p,
	                                                      ord_384p.BitCount(),
	                                                      prvkey_384p);
	Integer sha256calc_test_384p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_384p,
	                                                    ord_384p.BitCount(),
	                                                    prvkey_384p);
	Integer sha384calc_sample_384p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_384p,
	                                                      ord_384p.BitCount(),
	                                                      prvkey_384p);
	Integer sha384calc_test_384p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_384p,
	                                                    ord_384p.BitCount(),
	                                                    prvkey_384p);
	Integer sha512calc_sample_384p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_384p,
	                                                      ord_384p.BitCount(),
	                                                      prvkey_384p);
	Integer sha512calc_test_384p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_384p,
	                                                    ord_384p.BitCount(),
	                                                    prvkey_384p);

	pass = (sha1calc_sample_384p == sha1res_sample_384p);
	pass &= (sha1calc_test_384p == sha1res_test_384p);
	pass &= (sha224calc_sample_384p == sha224res_sample_384p);
	pass &= (sha224calc_test_384p == sha224res_test_384p);
	pass &= (sha256calc_sample_384p == sha256res_sample_384p);
	pass &= (sha256calc_test_384p == sha256res_test_384p);
	pass &= (sha384calc_sample_384p == sha384res_sample_384p);
	pass &= (sha384calc_test_384p == sha384res_test_384p);
	pass &= (sha512calc_sample_384p == sha512res_sample_384p);
	pass &= (sha512calc_test_384p == sha512res_test_384p);
	cout << (pass ? "passed" : "FAILED") << "    secp384r1" << endl;

	// secp521r1
	Integer sha1calc_sample_521p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_521p,
	                                                  ord_521p.BitCount(),
	                                                  prvkey_521p);
	Integer sha1calc_test_521p = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_521p,
	                                                ord_521p.BitCount(),
	                                                prvkey_521p);
	Integer sha224calc_sample_521p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_521p,
	                                                      ord_521p.BitCount(),
	                                                      prvkey_521p);
	Integer sha224calc_test_521p = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_521p,
	                                                    ord_521p.BitCount(),
	                                                    prvkey_521p);
	Integer sha256calc_sample_521p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_521p,
	                                                      ord_521p.BitCount(),
	                                                      prvkey_521p);
	Integer sha256calc_test_521p = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_521p,
	                                                    ord_521p.BitCount(),
	                                                    prvkey_521p);
	Integer sha384calc_sample_521p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_521p,
	                                                      ord_521p.BitCount(),
	                                                      prvkey_521p);
	Integer sha384calc_test_521p = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_521p,
	                                                    ord_521p.BitCount(),
	                                                    prvkey_521p);
	Integer sha512calc_sample_521p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_521p,
	                                                      ord_521p.BitCount(),
	                                                      prvkey_521p);
	Integer sha512calc_test_521p = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_521p,
	                                                    ord_521p.BitCount(),
	                                                    prvkey_521p);

	pass = (sha1calc_sample_521p == sha1res_sample_521p);
	pass &= (sha1calc_test_521p == sha1res_test_521p);
	pass &= (sha224calc_sample_521p == sha224res_sample_521p);
	pass &= (sha224calc_test_521p == sha224res_test_521p);
	pass &= (sha256calc_sample_521p == sha256res_sample_521p);
	pass &= (sha256calc_test_521p == sha256res_test_521p);
	pass &= (sha384calc_sample_521p == sha384res_sample_521p);
	pass &= (sha384calc_test_521p == sha384res_test_521p);
	pass &= (sha512calc_sample_521p == sha512res_sample_521p);
	pass &= (sha512calc_test_521p == sha512res_test_521p);
	cout << (pass ? "passed" : "FAILED") << "    secp521r1" << endl;

	// 163-bit Koblitz curve
	Integer sha1calc_sample_163k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_163k,
	                                                  ord_163k.BitCount(),
	                                                  prvkey_163k);
	Integer sha1calc_test_163k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_163k,
	                                                ord_163k.BitCount(),
	                                                prvkey_163k);
	Integer sha224calc_sample_163k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_163k,
	                                                      ord_163k.BitCount(),
	                                                      prvkey_163k);
	Integer sha224calc_test_163k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_163k,
	                                                    ord_163k.BitCount(),
	                                                    prvkey_163k);
	Integer sha256calc_sample_163k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_163k,
	                                                      ord_163k.BitCount(),
	                                                      prvkey_163k);
	Integer sha256calc_test_163k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_163k,
	                                                    ord_163k.BitCount(),
	                                                    prvkey_163k);
	Integer sha384calc_sample_163k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_163k,
	                                                      ord_163k.BitCount(),
	                                                      prvkey_163k);
	Integer sha384calc_test_163k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_163k,
	                                                    ord_163k.BitCount(),
	                                                    prvkey_163k);
	Integer sha512calc_sample_163k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_163k,
	                                                      ord_163k.BitCount(),
	                                                      prvkey_163k);
	Integer sha512calc_test_163k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_163k,
	                                                    ord_163k.BitCount(),
	                                                    prvkey_163k);

	pass = (sha1calc_sample_163k == sha1res_sample_163k);
	pass &= (sha1calc_test_163k == sha1res_test_163k);
	pass &= (sha224calc_sample_163k == sha224res_sample_163k);
	pass &= (sha224calc_test_163k == sha224res_test_163k);
	pass &= (sha256calc_sample_163k == sha256res_sample_163k);
	pass &= (sha256calc_test_163k == sha256res_test_163k);
	pass &= (sha384calc_sample_163k == sha384res_sample_163k);
	pass &= (sha384calc_test_163k == sha384res_test_163k);
	pass &= (sha512calc_sample_163k == sha512res_sample_163k);
	pass &= (sha512calc_test_163k == sha512res_test_163k);
	cout << (pass ? "passed" : "FAILED") << "    163-bit Koblitz" << endl;

	// 233-bit Koblitz curve
	Integer sha1calc_sample_233k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_233k,
	                                                  ord_233k.BitCount(),
	                                                  prvkey_233k);
	Integer sha1calc_test_233k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_233k,
	                                                ord_233k.BitCount(),
	                                                prvkey_233k);
	Integer sha224calc_sample_233k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_233k,
	                                                      ord_233k.BitCount(),
	                                                      prvkey_233k);
	Integer sha224calc_test_233k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_233k,
	                                                    ord_233k.BitCount(),
	                                                    prvkey_233k);
	Integer sha256calc_sample_233k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_233k,
	                                                      ord_233k.BitCount(),
	                                                      prvkey_233k);
	Integer sha256calc_test_233k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_233k,
	                                                    ord_233k.BitCount(),
	                                                    prvkey_233k);
	Integer sha384calc_sample_233k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_233k,
	                                                      ord_233k.BitCount(),
	                                                      prvkey_233k);
	Integer sha384calc_test_233k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_233k,
	                                                    ord_233k.BitCount(),
	                                                    prvkey_233k);
	Integer sha512calc_sample_233k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_233k,
	                                                      ord_233k.BitCount(),
	                                                      prvkey_233k);
	Integer sha512calc_test_233k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_233k,
	                                                    ord_233k.BitCount(),
	                                                    prvkey_233k);

	pass = (sha1calc_sample_233k == sha1res_sample_233k);
	pass &= (sha1calc_test_233k == sha1res_test_233k);
	pass &= (sha224calc_sample_233k == sha224res_sample_233k);
	pass &= (sha224calc_test_233k == sha224res_test_233k);
	pass &= (sha256calc_sample_233k == sha256res_sample_233k);
	pass &= (sha256calc_test_233k == sha256res_test_233k);
	pass &= (sha384calc_sample_233k == sha384res_sample_233k);
	pass &= (sha384calc_test_233k == sha384res_test_233k);
	pass &= (sha512calc_sample_233k == sha512res_sample_233k);
	pass &= (sha512calc_test_233k == sha512res_test_233k);
	cout << (pass ? "passed" : "FAILED") << "    233-bit Koblitz" << endl;

	// 283-bit Koblitz curve
	Integer sha1calc_sample_283k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_283k,
	                                                  ord_283k.BitCount(),
	                                                  prvkey_283k);
	Integer sha1calc_test_283k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_283k,
	                                                ord_283k.BitCount(),
	                                                prvkey_283k);
	Integer sha224calc_sample_283k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_283k,
	                                                      ord_283k.BitCount(),
	                                                      prvkey_283k);
	Integer sha224calc_test_283k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_283k,
	                                                    ord_283k.BitCount(),
	                                                    prvkey_283k);
	Integer sha256calc_sample_283k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_283k,
	                                                      ord_283k.BitCount(),
	                                                      prvkey_283k);
	Integer sha256calc_test_283k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_283k,
	                                                    ord_283k.BitCount(),
	                                                    prvkey_283k);
	Integer sha384calc_sample_283k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_283k,
	                                                      ord_283k.BitCount(),
	                                                      prvkey_283k);
	Integer sha384calc_test_283k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_283k,
	                                                    ord_283k.BitCount(),
	                                                    prvkey_283k);
	Integer sha512calc_sample_283k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_283k,
	                                                      ord_283k.BitCount(),
	                                                      prvkey_283k);
	Integer sha512calc_test_283k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_283k,
	                                                    ord_283k.BitCount(),
	                                                    prvkey_283k);

	pass = (sha1calc_sample_283k == sha1res_sample_283k);
	pass &= (sha1calc_test_283k == sha1res_test_283k);
	pass &= (sha224calc_sample_283k == sha224res_sample_283k);
	pass &= (sha224calc_test_283k == sha224res_test_283k);
	pass &= (sha256calc_sample_283k == sha256res_sample_283k);
	pass &= (sha256calc_test_283k == sha256res_test_283k);
	pass &= (sha384calc_sample_283k == sha384res_sample_283k);
	pass &= (sha384calc_test_283k == sha384res_test_283k);
	pass &= (sha512calc_sample_283k == sha512res_sample_283k);
	pass &= (sha512calc_test_283k == sha512res_test_283k);
	cout << (pass ? "passed" : "FAILED") << "    283-bit Koblitz" << endl;

	// 409-bit Koblitz curve
	Integer sha1calc_sample_409k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_409k,
	                                                  ord_409k.BitCount(),
	                                                  prvkey_409k);
	Integer sha1calc_test_409k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_409k,
	                                                ord_409k.BitCount(),
	                                                prvkey_409k);
	Integer sha224calc_sample_409k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_409k,
	                                                      ord_409k.BitCount(),
	                                                      prvkey_409k);
	Integer sha224calc_test_409k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_409k,
	                                                    ord_409k.BitCount(),
	                                                    prvkey_409k);
	Integer sha256calc_sample_409k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_409k,
	                                                      ord_409k.BitCount(),
	                                                      prvkey_409k);
	Integer sha256calc_test_409k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_409k,
	                                                    ord_409k.BitCount(),
	                                                    prvkey_409k);
	Integer sha384calc_sample_409k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_409k,
	                                                      ord_409k.BitCount(),
	                                                      prvkey_409k);
	Integer sha384calc_test_409k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_409k,
	                                                    ord_409k.BitCount(),
	                                                    prvkey_409k);
	Integer sha512calc_sample_409k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_409k,
	                                                      ord_409k.BitCount(),
	                                                      prvkey_409k);
	Integer sha512calc_test_409k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_409k,
	                                                    ord_409k.BitCount(),
	                                                    prvkey_409k);

	pass = (sha1calc_sample_409k == sha1res_sample_409k);
	pass &= (sha1calc_test_409k == sha1res_test_409k);
	pass &= (sha224calc_sample_409k == sha224res_sample_409k);
	pass &= (sha224calc_test_409k == sha224res_test_409k);
	pass &= (sha256calc_sample_409k == sha256res_sample_409k);
	pass &= (sha256calc_test_409k == sha256res_test_409k);
	pass &= (sha384calc_sample_409k == sha384res_sample_409k);
	pass &= (sha384calc_test_409k == sha384res_test_409k);
	pass &= (sha512calc_sample_409k == sha512res_sample_409k);
	pass &= (sha512calc_test_409k == sha512res_test_409k);
	cout << (pass ? "passed" : "FAILED") << "    409-bit Koblitz" << endl;

	// 571-bit Koblitz curve
	Integer sha1calc_sample_571k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_571k,
	                                                  ord_571k.BitCount(),
	                                                  prvkey_571k);
	Integer sha1calc_test_571k = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_571k,
	                                                ord_571k.BitCount(),
	                                                prvkey_571k);
	Integer sha224calc_sample_571k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_571k,
	                                                      ord_571k.BitCount(),
	                                                      prvkey_571k);
	Integer sha224calc_test_571k = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_571k,
	                                                    ord_571k.BitCount(),
	                                                    prvkey_571k);
	Integer sha256calc_sample_571k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_571k,
	                                                      ord_571k.BitCount(),
	                                                      prvkey_571k);
	Integer sha256calc_test_571k = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_571k,
	                                                    ord_571k.BitCount(),
	                                                    prvkey_571k);
	Integer sha384calc_sample_571k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_571k,
	                                                      ord_571k.BitCount(),
	                                                      prvkey_571k);
	Integer sha384calc_test_571k = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_571k,
	                                                    ord_571k.BitCount(),
	                                                    prvkey_571k);
	Integer sha512calc_sample_571k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_571k,
	                                                      ord_571k.BitCount(),
	                                                      prvkey_571k);
	Integer sha512calc_test_571k = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_571k,
	                                                    ord_571k.BitCount(),
	                                                    prvkey_571k);

	pass = (sha1calc_sample_571k == sha1res_sample_571k);
	pass &= (sha1calc_test_571k == sha1res_test_571k);
	pass &= (sha224calc_sample_571k == sha224res_sample_571k);
	pass &= (sha224calc_test_571k == sha224res_test_571k);
	pass &= (sha256calc_sample_571k == sha256res_sample_571k);
	pass &= (sha256calc_test_571k == sha256res_test_571k);
	pass &= (sha384calc_sample_571k == sha384res_sample_571k);
	pass &= (sha384calc_test_571k == sha384res_test_571k);
	pass &= (sha512calc_sample_571k == sha512res_sample_571k);
	pass &= (sha512calc_test_571k == sha512res_test_571k);
	cout << (pass ? "passed" : "FAILED") << "    571-bit Koblitz" << endl;

	// 163-bit pseudorandom curve
	Integer sha1calc_sample_163r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_163r,
	                                                  ord_163r.BitCount(),
	                                                  prvkey_163r);
	Integer sha1calc_test_163r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_163r,
	                                                ord_163r.BitCount(),
	                                                prvkey_163r);
	Integer sha224calc_sample_163r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_163r,
	                                                      ord_163r.BitCount(),
	                                                      prvkey_163r);
	Integer sha224calc_test_163r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_163r,
	                                                    ord_163r.BitCount(),
	                                                    prvkey_163r);
	Integer sha256calc_sample_163r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_163r,
	                                                      ord_163r.BitCount(),
	                                                      prvkey_163r);
	Integer sha256calc_test_163r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_163r,
	                                                    ord_163r.BitCount(),
	                                                    prvkey_163r);
	Integer sha384calc_sample_163r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_163r,
	                                                      ord_163r.BitCount(),
	                                                      prvkey_163r);
	Integer sha384calc_test_163r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_163r,
	                                                    ord_163r.BitCount(),
	                                                    prvkey_163r);
	Integer sha512calc_sample_163r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_163r,
	                                                      ord_163r.BitCount(),
	                                                      prvkey_163r);
	Integer sha512calc_test_163r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_163r,
	                                                    ord_163r.BitCount(),
	                                                    prvkey_163r);

	pass = (sha1calc_sample_163r == sha1res_sample_163r);
	pass &= (sha1calc_test_163r == sha1res_test_163r);
	pass &= (sha224calc_sample_163r == sha224res_sample_163r);
	pass &= (sha224calc_test_163r == sha224res_test_163r);
	pass &= (sha256calc_sample_163r == sha256res_sample_163r);
	pass &= (sha256calc_test_163r == sha256res_test_163r);
	pass &= (sha384calc_sample_163r == sha384res_sample_163r);
	pass &= (sha384calc_test_163r == sha384res_test_163r);
	pass &= (sha512calc_sample_163r == sha512res_sample_163r);
	pass &= (sha512calc_test_163r == sha512res_test_163r);
	cout << (pass ? "passed" : "FAILED") << "    163-bit pseudorandom" << endl;

	// 233-bit pseudorandom curve
	Integer sha1calc_sample_233r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_233r,
	                                                  ord_233r.BitCount(),
	                                                  prvkey_233r);
	Integer sha1calc_test_233r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_233r,
	                                                ord_233r.BitCount(),
	                                                prvkey_233r);
	Integer sha224calc_sample_233r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_233r,
	                                                      ord_233r.BitCount(),
	                                                      prvkey_233r);
	Integer sha224calc_test_233r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_233r,
	                                                    ord_233r.BitCount(),
	                                                    prvkey_233r);
	Integer sha256calc_sample_233r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_233r,
	                                                      ord_233r.BitCount(),
	                                                      prvkey_233r);
	Integer sha256calc_test_233r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_233r,
	                                                    ord_233r.BitCount(),
	                                                    prvkey_233r);
	Integer sha384calc_sample_233r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_233r,
	                                                      ord_233r.BitCount(),
	                                                      prvkey_233r);
	Integer sha384calc_test_233r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_233r,
	                                                    ord_233r.BitCount(),
	                                                    prvkey_233r);
	Integer sha512calc_sample_233r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_233r,
	                                                      ord_233r.BitCount(),
	                                                      prvkey_233r);
	Integer sha512calc_test_233r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_233r,
	                                                    ord_233r.BitCount(),
	                                                    prvkey_233r);

	pass = (sha1calc_sample_233r == sha1res_sample_233r);
	pass &= (sha1calc_test_233r == sha1res_test_233r);
	pass &= (sha224calc_sample_233r == sha224res_sample_233r);
	pass &= (sha224calc_test_233r == sha224res_test_233r);
	pass &= (sha256calc_sample_233r == sha256res_sample_233r);
	pass &= (sha256calc_test_233r == sha256res_test_233r);
	pass &= (sha384calc_sample_233r == sha384res_sample_233r);
	pass &= (sha384calc_test_233r == sha384res_test_233r);
	pass &= (sha512calc_sample_233r == sha512res_sample_233r);
	pass &= (sha512calc_test_233r == sha512res_test_233r);
	cout << (pass ? "passed" : "FAILED") << "    233-bit pseudorandom" << endl;

	// 283-bit pseudorandom curve
	Integer sha1calc_sample_283r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_283r,
	                                                  ord_283r.BitCount(),
	                                                  prvkey_283r);
	Integer sha1calc_test_283r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_283r,
	                                                ord_283r.BitCount(),
	                                                prvkey_283r);
	Integer sha224calc_sample_283r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_283r,
	                                                      ord_283r.BitCount(),
	                                                      prvkey_283r);
	Integer sha224calc_test_283r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_283r,
	                                                    ord_283r.BitCount(),
	                                                    prvkey_283r);
	Integer sha256calc_sample_283r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_283r,
	                                                      ord_283r.BitCount(),
	                                                      prvkey_283r);
	Integer sha256calc_test_283r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_283r,
	                                                    ord_283r.BitCount(),
	                                                    prvkey_283r);
	Integer sha384calc_sample_283r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_283r,
	                                                      ord_283r.BitCount(),
	                                                      prvkey_283r);
	Integer sha384calc_test_283r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_283r,
	                                                    ord_283r.BitCount(),
	                                                    prvkey_283r);
	Integer sha512calc_sample_283r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_283r,
	                                                      ord_283r.BitCount(),
	                                                      prvkey_283r);
	Integer sha512calc_test_283r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_283r,
	                                                    ord_283r.BitCount(),
	                                                    prvkey_283r);

	pass = (sha1calc_sample_283r == sha1res_sample_283r);
	pass &= (sha1calc_test_283r == sha1res_test_283r);
	pass &= (sha224calc_sample_283r == sha224res_sample_283r);
	pass &= (sha224calc_test_283r == sha224res_test_283r);
	pass &= (sha256calc_sample_283r == sha256res_sample_283r);
	pass &= (sha256calc_test_283r == sha256res_test_283r);
	pass &= (sha384calc_sample_283r == sha384res_sample_283r);
	pass &= (sha384calc_test_283r == sha384res_test_283r);
	pass &= (sha512calc_sample_283r == sha512res_sample_283r);
	pass &= (sha512calc_test_283r == sha512res_test_283r);
	cout << (pass ? "passed" : "FAILED") << "    283-bit pseudorandom" << endl;

	// 409-bit pseudorandom curve
	Integer sha1calc_sample_409r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_409r,
	                                                  ord_409r.BitCount(),
	                                                  prvkey_409r);
	Integer sha1calc_test_409r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_409r,
	                                                ord_409r.BitCount(),
	                                                prvkey_409r);
	Integer sha224calc_sample_409r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_409r,
	                                                      ord_409r.BitCount(),
	                                                      prvkey_409r);
	Integer sha224calc_test_409r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_409r,
	                                                    ord_409r.BitCount(),
	                                                    prvkey_409r);
	Integer sha256calc_sample_409r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_409r,
	                                                      ord_409r.BitCount(),
	                                                      prvkey_409r);
	Integer sha256calc_test_409r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_409r,
	                                                    ord_409r.BitCount(),
	                                                    prvkey_409r);
	Integer sha384calc_sample_409r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_409r,
	                                                      ord_409r.BitCount(),
	                                                      prvkey_409r);
	Integer sha384calc_test_409r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_409r,
	                                                    ord_409r.BitCount(),
	                                                    prvkey_409r);
	Integer sha512calc_sample_409r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_409r,
	                                                      ord_409r.BitCount(),
	                                                      prvkey_409r);
	Integer sha512calc_test_409r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_409r,
	                                                    ord_409r.BitCount(),
	                                                    prvkey_409r);

	pass = (sha1calc_sample_409r == sha1res_sample_409r);
	pass &= (sha1calc_test_409r == sha1res_test_409r);
	pass &= (sha224calc_sample_409r == sha224res_sample_409r);
	pass &= (sha224calc_test_409r == sha224res_test_409r);
	pass &= (sha256calc_sample_409r == sha256res_sample_409r);
	pass &= (sha256calc_test_409r == sha256res_test_409r);
	pass &= (sha384calc_sample_409r == sha384res_sample_409r);
	pass &= (sha384calc_test_409r == sha384res_test_409r);
	pass &= (sha512calc_sample_409r == sha512res_sample_409r);
	pass &= (sha512calc_test_409r == sha512res_test_409r);
	cout << (pass ? "passed" : "FAILED") << "    409-bit pseudorandom" << endl;

	// 571-bit pseudorandom curve
	Integer sha1calc_sample_571r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                  strlen(data1.c_str()),
	                                                  ord_571r,
	                                                  ord_571r.BitCount(),
	                                                  prvkey_571r);
	Integer sha1calc_test_571r = ds_sha1.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                strlen(data2.c_str()),
	                                                ord_571r,
	                                                ord_571r.BitCount(),
	                                                prvkey_571r);
	Integer sha224calc_sample_571r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_571r,
	                                                      ord_571r.BitCount(),
	                                                      prvkey_571r);
	Integer sha224calc_test_571r = ds_sha224.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_571r,
	                                                    ord_571r.BitCount(),
	                                                    prvkey_571r);
	Integer sha256calc_sample_571r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_571r,
	                                                      ord_571r.BitCount(),
	                                                      prvkey_571r);
	Integer sha256calc_test_571r = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_571r,
	                                                    ord_571r.BitCount(),
	                                                    prvkey_571r);
	Integer sha384calc_sample_571r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_571r,
	                                                      ord_571r.BitCount(),
	                                                      prvkey_571r);
	Integer sha384calc_test_571r = ds_sha384.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_571r,
	                                                    ord_571r.BitCount(),
	                                                    prvkey_571r);
	Integer sha512calc_sample_571r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data1.c_str()),
	                                                      strlen(data1.c_str()),
	                                                      ord_571r,
	                                                      ord_571r.BitCount(),
	                                                      prvkey_571r);
	Integer sha512calc_test_571r = ds_sha512.getDetKVal(reinterpret_cast<const unsigned char*>(data2.c_str()),
	                                                    strlen(data2.c_str()),
	                                                    ord_571r,
	                                                    ord_571r.BitCount(),
	                                                    prvkey_571r);

	pass = (sha1calc_sample_571r == sha1res_sample_571r);
	pass &= (sha1calc_test_571r == sha1res_test_571r);
	pass &= (sha224calc_sample_571r == sha224res_sample_571r);
	pass &= (sha224calc_test_571r == sha224res_test_571r);
	pass &= (sha256calc_sample_571r == sha256res_sample_571r);
	pass &= (sha256calc_test_571r == sha256res_test_571r);
	pass &= (sha384calc_sample_571r == sha384res_sample_571r);
	pass &= (sha384calc_test_571r == sha384res_test_571r);
	pass &= (sha512calc_sample_571r == sha512res_sample_571r);
	pass &= (sha512calc_test_571r == sha512res_test_571r);
	cout << (pass ? "passed" : "FAILED") << "    571-bit pseudorandom" << endl;
	cout << "RFC 6979 Validation Suite Completed" << endl;

	cout << "RFC 6979 Unofficial Validation Suite Started" << endl;
	// secp256k1  (Not part of RFC 6979 - Taken from Python test harnessses)
	Integer sha256calc1_256k1 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data1_256k1.c_str()),
	                                                 strlen(data1_256k1.c_str()),
	                                                 ord_256k1,
	                                                 ord_256k1.BitCount(),
	                                                 prvkey1_256k1);
	Integer sha256calc2_256k1 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data2_256k1.c_str()),
	                                                 strlen(data2_256k1.c_str()),
	                                                 ord_256k1,
	                                                 ord_256k1.BitCount(),
	                                                 prvkey2_256k1);
	Integer sha256calc3_256k1 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data3_256k1.c_str()),
	                                                 strlen(data3_256k1.c_str()),
	                                                 ord_256k1,
	                                                 ord_256k1.BitCount(),
	                                                 prvkey3_256k1);
	Integer sha256calc4_256k1 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data4_256k1.c_str()),
	                                                 strlen(data4_256k1.c_str()),
	                                                 ord_256k1,
	                                                 ord_256k1.BitCount(),
	                                                 prvkey4_256k1);
	Integer sha256calc5_256k1 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data5_256k1.c_str()),
	                                                 strlen(data5_256k1.c_str()),
	                                                 ord_256k1,
	                                                 ord_256k1.BitCount(),
	                                                 prvkey5_256k1);
	Integer sha256calc6_256k1 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data6_256k1.c_str()),
	                                                 strlen(data6_256k1.c_str()),
	                                                 ord_256k1,
	                                                 ord_256k1.BitCount(),
	                                                 prvkey6_256k1);
	Integer sha256calc7_256k1 = ds_sha256.getDetKVal(reinterpret_cast<const unsigned char*>(data7_256k1.c_str()),
	                                                 strlen(data7_256k1.c_str()),
	                                                 ord_256k1,
	                                                 ord_256k1.BitCount(),
	                                                 prvkey7_256k1);

	pass = (sha256calc1_256k1 == sha256res1_256k1);
	pass = (sha256calc2_256k1 == sha256res2_256k1);
	pass = (sha256calc3_256k1 == sha256res3_256k1);
	pass = (sha256calc4_256k1 == sha256res4_256k1);
	pass = (sha256calc5_256k1 == sha256res5_256k1);
	pass = (sha256calc6_256k1 == sha256res6_256k1);
	pass = (sha256calc7_256k1 == sha256res7_256k1);
	cout << (pass ? "passed" : "FAILED") << "    secp256k1" << endl;
	cout << "RFC 6979 Unofficial Validation Suite Completed" << endl;

	return pass;    
*/
	return true;
}

bool ValidateECP()
{
	cout << "\nECP validation suite running...\n\n";

	ECIES<ECP>::Decryptor cpriv(GlobalRNG(), ASN1::secp192r1());
	ECIES<ECP>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.GetKey().DEREncode(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.GetKey().DEREncode(bq);
	ECDSA<ECP, SHA>::Signer spriv(bq);
	ECDSA<ECP, SHA>::Verifier spub(bq);
	ECDH<ECP>::Domain ecdhc(ASN1::secp192r1());
	ECMQV<ECP>::Domain ecmqvc(ASN1::secp192r1());

	spriv.AccessKey().Precompute();
	ByteQueue queue;
	spriv.AccessKey().SavePrecomputation(queue);
	spriv.AccessKey().LoadPrecomputation(queue);

	bool pass = SignatureValidate(spriv, spub);
	cpub.AccessKey().Precompute();
	cpriv.AccessKey().Precompute();
	pass = CryptoSystemValidate(cpriv, cpub) && pass;
	pass = SimpleKeyAgreementValidate(ecdhc) && pass;
	pass = AuthenticatedKeyAgreementValidate(ecmqvc) && pass;

	cout << "Turning on point compression..." << endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	ecdhc.AccessGroupParameters().SetPointCompression(true);
	ecmqvc.AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;
	pass = SimpleKeyAgreementValidate(ecdhc) && pass;
	pass = AuthenticatedKeyAgreementValidate(ecmqvc) && pass;

	cout << "Testing SEC 2, NIST, and Brainpool recommended curves..." << endl;
	OID oid;
	while (!(oid = DL_GroupParameters_EC<ECP>::GetNextRecommendedParametersOID(oid)).m_values.empty())
	{
		DL_GroupParameters_EC<ECP> params(oid);
		bool fail = !params.Validate(GlobalRNG(), 2);
		cout << (fail ? "FAILED" : "passed") << "    " << dec << params.GetCurve().GetField().MaxElementBitLength() << " bits" << endl;
		pass = pass && !fail;
	}

	return pass;
}

bool ValidateEC2N()
{
	cout << "\nEC2N validation suite running...\n\n";

	ECIES<EC2N>::Decryptor cpriv(GlobalRNG(), ASN1::sect193r1());
	ECIES<EC2N>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.DEREncode(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.DEREncode(bq);
	ECDSA<EC2N, SHA>::Signer spriv(bq);
	ECDSA<EC2N, SHA>::Verifier spub(bq);
	ECDH<EC2N>::Domain ecdhc(ASN1::sect193r1());
	ECMQV<EC2N>::Domain ecmqvc(ASN1::sect193r1());

	spriv.AccessKey().Precompute();
	ByteQueue queue;
	spriv.AccessKey().SavePrecomputation(queue);
	spriv.AccessKey().LoadPrecomputation(queue);

	bool pass = SignatureValidate(spriv, spub);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;
	pass = SimpleKeyAgreementValidate(ecdhc) && pass;
	pass = AuthenticatedKeyAgreementValidate(ecmqvc) && pass;

	cout << "Turning on point compression..." << endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	ecdhc.AccessGroupParameters().SetPointCompression(true);
	ecmqvc.AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;
	pass = SimpleKeyAgreementValidate(ecdhc) && pass;
	pass = AuthenticatedKeyAgreementValidate(ecmqvc) && pass;

#if 0	// TODO: turn this back on when I make EC2N faster for pentanomial basis
	cout << "Testing SEC 2 recommended curves..." << endl;
	OID oid;
	while (!(oid = DL_GroupParameters_EC<EC2N>::GetNextRecommendedParametersOID(oid)).m_values.empty())
	{
		DL_GroupParameters_EC<EC2N> params(oid);
		bool fail = !params.Validate(GlobalRNG(), 2);
		cout << (fail ? "FAILED" : "passed") << "    " << params.GetCurve().GetField().MaxElementBitLength() << " bits" << endl;
		pass = pass && !fail;
	}
#endif

	return pass;
}

bool ValidateECDSA()
{
	cout << "\nECDSA validation suite running...\n\n";

	// from Sample Test Vectors for P1363
	GF2NT gf2n(191, 9, 0);
	byte a[]="\x28\x66\x53\x7B\x67\x67\x52\x63\x6A\x68\xF5\x65\x54\xE1\x26\x40\x27\x6B\x64\x9E\xF7\x52\x62\x67";
	byte b[]="\x2E\x45\xEF\x57\x1F\x00\x78\x6F\x67\xB0\x08\x1B\x94\x95\xA3\xD9\x54\x62\xF5\xDE\x0A\xA1\x85\xEC";
	EC2N ec(gf2n, PolynomialMod2(a,24), PolynomialMod2(b,24));

	EC2N::Point P;
	ec.DecodePoint(P, (byte *)"\x04\x36\xB3\xDA\xF8\xA2\x32\x06\xF9\xC4\xF2\x99\xD7\xB2\x1A\x9C\x36\x91\x37\xF2\xC8\x4A\xE1\xAA\x0D"
		"\x76\x5B\xE7\x34\x33\xB3\xF9\x5E\x33\x29\x32\xE7\x0E\xA2\x45\xCA\x24\x18\xEA\x0E\xF9\x80\x18\xFB", ec.EncodedPointSize());
	Integer n("40000000000000000000000004a20e90c39067c893bbb9a5H");
	Integer d("340562e1dda332f9d2aec168249b5696ee39d0ed4d03760fH");
	EC2N::Point Q(ec.Multiply(d, P));
	ECDSA<EC2N, SHA>::Signer priv(ec, P, n, d);
	ECDSA<EC2N, SHA>::Verifier pub(priv);

	Integer h("A9993E364706816ABA3E25717850C26C9CD0D89DH");
	Integer k("3eeace72b4919d991738d521879f787cb590aff8189d2b69H");
	static const byte sig[]="\x03\x8e\x5a\x11\xfb\x55\xe4\xc6\x54\x71\xdc\xd4\x99\x84\x52\xb1\xe0\x2d\x8a\xf7\x09\x9b\xb9\x30"
		"\x0c\x9a\x08\xc3\x44\x68\xc2\x44\xb4\xe5\xd6\xb2\x1b\x3c\x68\x36\x28\x07\x41\x60\x20\x32\x8b\x6e";
	Integer r(sig, 24);
	Integer s(sig+24, 24);

	Integer rOut, sOut;
	bool fail, pass=true;

	priv.RawSign(k, h, rOut, sOut);
	fail = (rOut != r) || (sOut != s);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "signature check against test vector\n";

	fail = !pub.VerifyMessage((byte *)"abc", 3, sig, sizeof(sig));
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "verification check against test vector\n";

	fail = pub.VerifyMessage((byte *)"xyz", 3, sig, sizeof(sig));
	pass = pass && !fail;

	pass = SignatureValidate(priv, pub) && pass;

	return pass;
}

bool ValidateESIGN()
{
	cout << "\nESIGN validation suite running...\n\n";

	bool pass = true, fail;

	static const char plain[] = "test";
	static const byte signature[] =
		"\xA3\xE3\x20\x65\xDE\xDA\xE7\xEC\x05\xC1\xBF\xCD\x25\x79\x7D\x99\xCD\xD5\x73\x9D\x9D\xF3\xA4\xAA\x9A\xA4\x5A\xC8\x23\x3D\x0D\x37\xFE\xBC\x76\x3F\xF1\x84\xF6\x59"
		"\x14\x91\x4F\x0C\x34\x1B\xAE\x9A\x5C\x2E\x2E\x38\x08\x78\x77\xCB\xDC\x3C\x7E\xA0\x34\x44\x5B\x0F\x67\xD9\x35\x2A\x79\x47\x1A\x52\x37\x71\xDB\x12\x67\xC1\xB6\xC6"
		"\x66\x73\xB3\x40\x2E\xD6\xF2\x1A\x84\x0A\xB6\x7B\x0F\xEB\x8B\x88\xAB\x33\xDD\xE4\x83\x21\x90\x63\x2D\x51\x2A\xB1\x6F\xAB\xA7\x5C\xFD\x77\x99\xF2\xE1\xEF\x67\x1A"
		"\x74\x02\x37\x0E\xED\x0A\x06\xAD\xF4\x15\x65\xB8\xE1\xD1\x45\xAE\x39\x19\xB4\xFF\x5D\xF1\x45\x7B\xE0\xFE\x72\xED\x11\x92\x8F\x61\x41\x4F\x02\x00\xF2\x76\x6F\x7C"
		"\x79\xA2\xE5\x52\x20\x5D\x97\x5E\xFE\x39\xAE\x21\x10\xFB\x35\xF4\x80\x81\x41\x13\xDD\xE8\x5F\xCA\x1E\x4F\xF8\x9B\xB2\x68\xFB\x28";

	FileSource keys(CRYPTOPP_DATA_DIR "TestData/esig1536.dat", true, new HexDecoder);
	ESIGN<SHA>::Signer signer(keys);
	ESIGN<SHA>::Verifier verifier(signer);

	fail = !SignatureValidate(signer, verifier);
	pass = pass && !fail;

	fail = !verifier.VerifyMessage((byte *)plain, strlen(plain), signature, verifier.SignatureLength());
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "verification check against test vector\n";

	cout << "Generating signature key from seed..." << endl;
	signer.AccessKey().GenerateRandom(GlobalRNG(), MakeParameters("Seed", ConstByteArrayParameter((const byte *)"test", 4))("KeySize", 3*512));
	verifier = signer;

	fail = !SignatureValidate(signer, verifier);
	pass = pass && !fail;

	return pass;
}
