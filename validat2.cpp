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
#include "hmqv.h"
#include "fhmqv.h"
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
#include "sha.h"
#include "ripemd.h"
#include "smartptr.h"

#include <iostream>
#include <sstream>
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

bool ValidateHMQV()
{
	std::cout << "\nHMQV validation suite running...\n\n";

	//ECHMQV< ECP >::Domain hmqvB(false /*server*/);
	ECHMQV256 hmqvB(false);
	FileSource f256(CRYPTOPP_DATA_DIR "TestData/hmqv256.dat", true, new HexDecoder());
	FileSource f384(CRYPTOPP_DATA_DIR "TestData/hmqv384.dat", true, new HexDecoder());
	FileSource f512(CRYPTOPP_DATA_DIR "TestData/hmqv512.dat", true, new HexDecoder());
	hmqvB.AccessGroupParameters().BERDecode(f256);

	std::cout << "HMQV with NIST P-256 and SHA-256:" << std::endl;

	if (hmqvB.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (server)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (server)" << std::endl;
		return false;
	}

	const OID oid = ASN1::secp256r1();
	ECHMQV< ECP >::Domain hmqvA(oid, true /*client*/);

	if (hmqvA.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (client)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (client)" << std::endl;
		return false;
	}

	SecByteBlock sprivA(hmqvA.StaticPrivateKeyLength()), sprivB(hmqvB.StaticPrivateKeyLength());
	SecByteBlock eprivA(hmqvA.EphemeralPrivateKeyLength()), eprivB(hmqvB.EphemeralPrivateKeyLength());
	SecByteBlock spubA(hmqvA.StaticPublicKeyLength()), spubB(hmqvB.StaticPublicKeyLength());
	SecByteBlock epubA(hmqvA.EphemeralPublicKeyLength()), epubB(hmqvB.EphemeralPublicKeyLength());
	SecByteBlock valA(hmqvA.AgreedValueLength()), valB(hmqvB.AgreedValueLength());

	hmqvA.GenerateStaticKeyPair(GlobalRNG(), sprivA, spubA);
	hmqvB.GenerateStaticKeyPair(GlobalRNG(), sprivB, spubB);
	hmqvA.GenerateEphemeralKeyPair(GlobalRNG(), eprivA, epubA);
	hmqvB.GenerateEphemeralKeyPair(GlobalRNG(), eprivB, epubB);

	memset(valA.begin(), 0x00, valA.size());
	memset(valB.begin(), 0x11, valB.size());

	if (!(hmqvA.Agree(valA, sprivA, eprivA, spubB, epubB) && hmqvB.Agree(valB, sprivB, eprivB, spubA, epubA)))
	{
		std::cout << "FAILED    authenticated key agreement failed" << std::endl;
		return false;
	}

	if (memcmp(valA.begin(), valB.begin(), hmqvA.AgreedValueLength()))
	{
		std::cout << "FAILED    authenticated agreed values not equal" << std::endl;
		return false;
	}

	std::cout << "passed    authenticated key agreement" << std::endl;

	// Now test HMQV with NIST P-384 curve and SHA384 hash
	std::cout << endl;
	std::cout << "HMQV with NIST P-384 and SHA-384:" << std::endl;

	ECHMQV384 hmqvB384(false);
	hmqvB384.AccessGroupParameters().BERDecode(f384);

	if (hmqvB384.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (server)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (server)" << std::endl;
		return false;
	}

	const OID oid384 = ASN1::secp384r1();
	ECHMQV384 hmqvA384(oid384, true /*client*/);

	if (hmqvA384.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (client)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (client)" << std::endl;
		return false;
	}

	SecByteBlock sprivA384(hmqvA384.StaticPrivateKeyLength()), sprivB384(hmqvB384.StaticPrivateKeyLength());
	SecByteBlock eprivA384(hmqvA384.EphemeralPrivateKeyLength()), eprivB384(hmqvB384.EphemeralPrivateKeyLength());
	SecByteBlock spubA384(hmqvA384.StaticPublicKeyLength()), spubB384(hmqvB384.StaticPublicKeyLength());
	SecByteBlock epubA384(hmqvA384.EphemeralPublicKeyLength()), epubB384(hmqvB384.EphemeralPublicKeyLength());
	SecByteBlock valA384(hmqvA384.AgreedValueLength()), valB384(hmqvB384.AgreedValueLength());

	hmqvA384.GenerateStaticKeyPair(GlobalRNG(), sprivA384, spubA384);
	hmqvB384.GenerateStaticKeyPair(GlobalRNG(), sprivB384, spubB384);
	hmqvA384.GenerateEphemeralKeyPair(GlobalRNG(), eprivA384, epubA384);
	hmqvB384.GenerateEphemeralKeyPair(GlobalRNG(), eprivB384, epubB384);

	memset(valA384.begin(), 0x00, valA384.size());
	memset(valB384.begin(), 0x11, valB384.size());

	if (!(hmqvA384.Agree(valA384, sprivA384, eprivA384, spubB384, epubB384) && hmqvB384.Agree(valB384, sprivB384, eprivB384, spubA384, epubA384)))
	{
		std::cout << "FAILED    authenticated key agreement failed" << std::endl;
		return false;
	}

	if (memcmp(valA384.begin(), valB384.begin(), hmqvA384.AgreedValueLength()))
	{
		std::cout << "FAILED    authenticated agreed values not equal" << std::endl;
		return false;
	}

	std::cout << "passed    authenticated key agreement" << std::endl;

	return true;
}

bool ValidateFHMQV()
{
	std::cout << "\nFHMQV validation suite running...\n\n";

	//ECFHMQV< ECP >::Domain fhmqvB(false /*server*/);
	ECFHMQV256 fhmqvB(false);
	FileSource f256(CRYPTOPP_DATA_DIR "TestData/fhmqv256.dat", true, new HexDecoder());
	FileSource f384(CRYPTOPP_DATA_DIR "TestData/fhmqv384.dat", true, new HexDecoder());
	FileSource f512(CRYPTOPP_DATA_DIR "TestData/fhmqv512.dat", true, new HexDecoder());
	fhmqvB.AccessGroupParameters().BERDecode(f256);

	std::cout << "FHMQV with NIST P-256 and SHA-256:" << std::endl;

	if (fhmqvB.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (server)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (server)" << std::endl;
		return false;
	}

	const OID oid = ASN1::secp256r1();
	ECFHMQV< ECP >::Domain fhmqvA(oid, true /*client*/);

	if (fhmqvA.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (client)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (client)" << std::endl;
		return false;
	}

	SecByteBlock sprivA(fhmqvA.StaticPrivateKeyLength()), sprivB(fhmqvB.StaticPrivateKeyLength());
	SecByteBlock eprivA(fhmqvA.EphemeralPrivateKeyLength()), eprivB(fhmqvB.EphemeralPrivateKeyLength());
	SecByteBlock spubA(fhmqvA.StaticPublicKeyLength()), spubB(fhmqvB.StaticPublicKeyLength());
	SecByteBlock epubA(fhmqvA.EphemeralPublicKeyLength()), epubB(fhmqvB.EphemeralPublicKeyLength());
	SecByteBlock valA(fhmqvA.AgreedValueLength()), valB(fhmqvB.AgreedValueLength());

	fhmqvA.GenerateStaticKeyPair(GlobalRNG(), sprivA, spubA);
	fhmqvB.GenerateStaticKeyPair(GlobalRNG(), sprivB, spubB);
	fhmqvA.GenerateEphemeralKeyPair(GlobalRNG(), eprivA, epubA);
	fhmqvB.GenerateEphemeralKeyPair(GlobalRNG(), eprivB, epubB);

	memset(valA.begin(), 0x00, valA.size());
	memset(valB.begin(), 0x11, valB.size());

	if (!(fhmqvA.Agree(valA, sprivA, eprivA, spubB, epubB) && fhmqvB.Agree(valB, sprivB, eprivB, spubA, epubA)))
	{
		std::cout << "FAILED    authenticated key agreement failed" << std::endl;
		return false;
	}

	if (memcmp(valA.begin(), valB.begin(), fhmqvA.AgreedValueLength()))
	{
		std::cout << "FAILED    authenticated agreed values not equal" << std::endl;
		return false;
	}

	std::cout << "passed    authenticated key agreement" << std::endl;

	// Now test FHMQV with NIST P-384 curve and SHA384 hash
	std::cout << endl;
	std::cout << "FHMQV with NIST P-384 and SHA-384:" << std::endl;

	ECHMQV384 fhmqvB384(false);
	fhmqvB384.AccessGroupParameters().BERDecode(f384);

	if (fhmqvB384.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (server)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (server)" << std::endl;
		return false;
	}

	const OID oid384 = ASN1::secp384r1();
	ECHMQV384 fhmqvA384(oid384, true /*client*/);

	if (fhmqvA384.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (client)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (client)" << std::endl;
		return false;
	}

	SecByteBlock sprivA384(fhmqvA384.StaticPrivateKeyLength()), sprivB384(fhmqvB384.StaticPrivateKeyLength());
	SecByteBlock eprivA384(fhmqvA384.EphemeralPrivateKeyLength()), eprivB384(fhmqvB384.EphemeralPrivateKeyLength());
	SecByteBlock spubA384(fhmqvA384.StaticPublicKeyLength()), spubB384(fhmqvB384.StaticPublicKeyLength());
	SecByteBlock epubA384(fhmqvA384.EphemeralPublicKeyLength()), epubB384(fhmqvB384.EphemeralPublicKeyLength());
	SecByteBlock valA384(fhmqvA384.AgreedValueLength()), valB384(fhmqvB384.AgreedValueLength());

	fhmqvA384.GenerateStaticKeyPair(GlobalRNG(), sprivA384, spubA384);
	fhmqvB384.GenerateStaticKeyPair(GlobalRNG(), sprivB384, spubB384);
	fhmqvA384.GenerateEphemeralKeyPair(GlobalRNG(), eprivA384, epubA384);
	fhmqvB384.GenerateEphemeralKeyPair(GlobalRNG(), eprivB384, epubB384);

	memset(valA384.begin(), 0x00, valA384.size());
	memset(valB384.begin(), 0x11, valB384.size());

	if (!(fhmqvA384.Agree(valA384, sprivA384, eprivA384, spubB384, epubB384) && fhmqvB384.Agree(valB384, sprivB384, eprivB384, spubA384, epubA384)))
	{
		std::cout << "FAILED    authenticated key agreement failed" << std::endl;
		return false;
	}

	if (memcmp(valA384.begin(), valB384.begin(), fhmqvA384.AgreedValueLength()))
	{
		std::cout << "FAILED    authenticated agreed values not equal" << std::endl;
		return false;
	}

	std::cout << "passed    authenticated key agreement" << std::endl;

	return true;
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
	CRYPTOPP_ASSERT(pub.GetKey() == pub1.GetKey());
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

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_IMPORTS)
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

	cout << (!pass1 ? "FAILED" : "passed") << ":  " << "1 shifted over range [" << dec << start << "," << stop << "]" << "\n";
	cout << (!pass2 ? "FAILED" : "passed") << ":  " << "0x" << hex << word(SIZE_MAX) << dec << " shifted over range [" << start << "," << stop << "]" << "\n";
	cout << (!pass3 ? "FAILED" : "passed") << ":  " << "random values shifted over range [" << dec << start << "," << stop << "]" << "\n";

	if (!(pass1 && pass2 && pass3))
		cout.flush();

	return pass1 && pass2 && pass3;
}
#endif

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

// from http://www.teletrust.de/fileadmin/files/oid/ecgdsa_final.pdf
bool ValidateECGDSA()
{
	cout << "\nECGDSA validation suite running...\n\n";

	bool fail, pass=true;

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function RIPEMD-160 (p. 10)
	{
		OID oid = ASN1::brainpoolP192r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 80F2425E 89B4F585 F27F3536 ED834D68 E3E492DE 08FE84B9");
		ECGDSA<ECP, RIPEMD160>::Signer signer(params, x);
		ECGDSA<ECP, RIPEMD160>::Verifier verifier(signer);

		Integer e("0x 00000000 577EF842 B32FDE45 79727FFF 02F7A280 74ADC4EF");
		Integer k("0x 22C17C2A 367DD85A B8A365ED 06F19C43 F9ED1834 9A9BC044");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 2D017BE7 F117FF99 4ED6FC63 CA5B4C7A 0430E9FA 095DAFC4");
		Integer sExp("0x C02B5CC5 C51D5411 060BF024 5049F824 839F671D 78A1BBF1");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function RIPEMD-160";
		const size_t len = strlen((char*)msg);

		byte signature[48];
		r.Encode(signature+0, 24);
		s.Encode(signature+24, 24);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP192r1 using RIPEMD-160\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function RIPEMD-160 (p. 13)
	{
		OID oid = ASN1::brainpoolP256r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 47B3A278 62DEF037 49ACF0D6 00E69F9B 851D01ED AEFA531F 4D168E78 7307F4D8");
		ECGDSA<ECP, RIPEMD160>::Signer signer(params, x);
		ECGDSA<ECP, RIPEMD160>::Verifier verifier(signer);

		Integer e("0x 00000000 00000000 00000000 577EF842 B32FDE45 79727FFF 02F7A280 74ADC4EF");
		Integer k("0x 908E3099 776261A4 558FF7A9 FA6DFFE0 CA6BB3F9 CB35C2E4 E1DC73FD 5E8C08A3");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 62CCD1D2 91E62F6A 4FFBD966 C66C85AA BA990BB6 AB0C087D BD54A456 CCC84E4C");
		Integer sExp("0x 9119719B 08EEA0D6 BC56E4D1 D37369BC F3768445 EF65CAE4 A37BF6D4 3BD01646");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function RIPEMD-160";
		const size_t len = strlen((char*)msg);

		byte signature[64];
		r.Encode(signature+0, 32);
		s.Encode(signature+32, 32);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP256r1 using RIPEMD-160\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function RIPEMD-160 (p. 16)
	{
		OID oid = ASN1::brainpoolP320r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 48683594 5A3A284F FC52629A D48D8F37 F4B2E993 9C52BC72 362A9961 40192AEF 7D2AAFF0 C73A51C5");
		ECGDSA<ECP, RIPEMD160>::Signer signer(params, x);
		ECGDSA<ECP, RIPEMD160>::Verifier verifier(signer);

		Integer e("0x 00000000 00000000 00000000 00000000 00000000 577EF842 B32FDE45 79727FFF 02F7A280 74ADC4EF");
		Integer k("0x C70BC00A 77AD7872 5D36CEEC 27D6F956 FB546EEF 6DC90E35 31452BD8 7ECE8A4A 7AD730AD C299D81B");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 3C925969 FAB22F7A E7B8CC5D 50CB0867 DFDB2CF4 FADA3D49 0DF75D72 F7563186 419494C9 8F9C82A6");
		Integer sExp("0x 06AB5250 B31A8E93 56194894 61733200 E4FD5C12 75C0AB37 E7E41149 5BAAE145 41DF6DE6 66B8CA56");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function RIPEMD-160";
		const size_t len = strlen((char*)msg);

		byte signature[80];
		r.Encode(signature+0, 40);
		s.Encode(signature+40, 40);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP320r1 using RIPEMD-160\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function SHA-1 (p. 19)
	{
		OID oid = ASN1::brainpoolP192r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 80F2425E 89B4F585 F27F3536 ED834D68 E3E492DE 08FE84B9");
		ECGDSA<ECP, SHA1>::Signer signer(params, x);
		ECGDSA<ECP, SHA1>::Verifier verifier(signer);

		Integer e("0x 00000000 CF00CD42 CAA80DDF 8DDEBDFD 32F2DA15 11B53F29");
		Integer k("0x 22C17C2A 367DD85A B8A365ED 06F19C43 F9ED1834 9A9BC044");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 2D017BE7 F117FF99 4ED6FC63 CA5B4C7A 0430E9FA 095DAFC4");
		Integer sExp("0x 18FD604E 5F00F55B 3585C052 8C319A2B 05B8F2DD EE9CF1A6");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function SHA-1";
		const size_t len = strlen((char*)msg);

		byte signature[48];
		r.Encode(signature+0, 24);
		s.Encode(signature+24, 24);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP192r1 using SHA-1\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function SHA-224 (p. 21)
	{
		OID oid = ASN1::brainpoolP256r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 47B3A278 62DEF037 49ACF0D6 00E69F9B 851D01ED AEFA531F 4D168E78 7307F4D8");
		ECGDSA<ECP, SHA224>::Signer signer(params, x);
		ECGDSA<ECP, SHA224>::Verifier verifier(signer);

		Integer e("0x 00000000 92AE8A0E 8D08EADE E9426378 714FF3E0 1957587D 2876FA70 D40E3144");
		Integer k("0x 908E3099 776261A4 558FF7A9 FA6DFFE0 CA6BB3F9 CB35C2E4 E1DC73FD 5E8C08A3");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 62CCD1D2 91E62F6A 4FFBD966 C66C85AA BA990BB6 AB0C087D BD54A456 CCC84E4C");
		Integer sExp("0x 6F029D92 1CBD2552 6EDCCF1C 45E3CBF7 B7A5D8D4 E005F0C4 1C49B052 DECB04EA");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function SHA-224";
		const size_t len = strlen((char*)msg);

		byte signature[64];
		r.Encode(signature+0, 32);
		s.Encode(signature+32, 32);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP256r1 using SHA-224\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function SHA-224 (p. 23)
	{
		OID oid = ASN1::brainpoolP320r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 48683594 5A3A284F FC52629A D48D8F37 F4B2E993 9C52BC72 362A9961 40192AEF 7D2AAFF0 C73A51C5");
		ECGDSA<ECP, SHA224>::Signer signer(params, x);
		ECGDSA<ECP, SHA224>::Verifier verifier(signer);

		Integer e("0x 00000000 00000000 00000000 92AE8A0E 8D08EADE E9426378 714FF3E0 1957587D 2876FA70 D40E3144");
		Integer k("0x C70BC00A 77AD7872 5D36CEEC 27D6F956 FB546EEF 6DC90E35 31452BD8 7ECE8A4A 7AD730AD C299D81B");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 3C925969 FAB22F7A E7B8CC5D 50CB0867 DFDB2CF4 FADA3D49 0DF75D72 F7563186 419494C9 8F9C82A6");
		Integer sExp("0x 6EA191CA 0D468AC3 E9568768 9338357C 7D0BACB3 F1D87E0D EC05F635 B7ADB842 75AA0086 60F812CF");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function SHA-224";
		const size_t len = strlen((char*)msg);

		byte signature[80];
		r.Encode(signature+0, 40);
		s.Encode(signature+40, 40);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP320r1 using SHA-224\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function SHA-224 (p. 27)
	{
		OID oid = ASN1::brainpoolP320r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 48683594 5A3A284F FC52629A D48D8F37 F4B2E993 9C52BC72 362A9961 40192AEF 7D2AAFF0 C73A51C5");
		ECGDSA<ECP, SHA256>::Signer signer(params, x);
		ECGDSA<ECP, SHA256>::Verifier verifier(signer);

		Integer e("0x 00000000 00000000 37ED8AA9 4AE667DB BB753330 E050EB8E 12195807 ECDC4FB1 0E0662B4 22C219D7");
		Integer k("0x C70BC00A 77AD7872 5D36CEEC 27D6F956 FB546EEF 6DC90E35 31452BD8 7ECE8A4A 7AD730AD C299D81B");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 3C925969 FAB22F7A E7B8CC5D 50CB0867 DFDB2CF4 FADA3D49 0DF75D72 F7563186 419494C9 8F9C82A6");
		Integer sExp("0x 24370797 A9D11717 BBBB2B76 2E08ECD0 7DD7E033 F544E47C BF3C6D16 FD90B51D CC2E4DD8 E6ECD8CD");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function SHA-256";
		const size_t len = strlen((char*)msg);

		byte signature[80];
		r.Encode(signature+0, 40);
		s.Encode(signature+40, 40);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP320r1 using SHA-256\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function SHA-384 (p. 34)
	{
		OID oid = ASN1::brainpoolP512r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 92006A98 8AF96D91 57AADCF8 62716962 7CE2ECC4 C58ECE5C 1A0A8642 11AB764C 04236FA0 160857A7 8E71CCAE 4D79D52E 5A69A457 8AF50658 1F598FA9 B4F7DA68");
		ECGDSA<ECP, SHA384>::Signer signer(params, x);
		ECGDSA<ECP, SHA384>::Verifier verifier(signer);

		Integer e("0x 00000000 00000000 00000000 00000000 68FEAB7D 8BF8A779 4466E447 5959946B 2136C084 A86090CA 8070C980 68B1250D 88213190 6B7E0CB8 475F9054 E9290C2E");
		Integer k("0x 6942B01D 5901BEC1 506BB874 9618E22E C0FCD7F3 5159D51E D53BA77A 78752128 A58232AD 8E0E021A FDE1477F F4C74FDF FE88AE2D 15D89B56 F6D73C03 77631D2B");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 0104918B 2B32B1A5 49BD43C3 0092953B 4164CA01 A1A97B5B 0756EA06 3AC16B41 B88A1BAB 4538CD7D 8466180B 3E3F5C86 46AC4A45 F564E9B6 8FEE72ED 00C7AC48");
		Integer sExp("0x 3D233E9F D9EB152E 889F4F7C F325B464 0894E5EA 44C51443 54305CD4 BF70D234 8257C2DB E06C5544 92CE9FDD 6861A565 77B53E5E E80E6062 31A4CF06 8FA1EC21");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function SHA-384";
		const size_t len = strlen((char*)msg);

		byte signature[128];
		r.Encode(signature+0, 64);
		s.Encode(signature+64, 64);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP512r1 using SHA-384\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	// 2.4.1 Examples of ECGDSA over GF(p) with the hash function SHA-512 (p. 38)
	{
		OID oid = ASN1::brainpoolP512r1();
		DL_GroupParameters_EC<ECP> params(oid);
		Integer x("0x 92006A98 8AF96D91 57AADCF8 62716962 7CE2ECC4 C58ECE5C 1A0A8642 11AB764C 04236FA0 160857A7 8E71CCAE 4D79D52E 5A69A457 8AF50658 1F598FA9 B4F7DA68");
		ECGDSA<ECP, SHA512>::Signer signer(params, x);
		ECGDSA<ECP, SHA512>::Verifier verifier(signer);

		Integer e("0x 1A95EF81 D213BD3B 8191E7FE 7F5BFD43 F51E3EE5 A4FD3D08 4A7C9BB5 411F4649 746AEBC6 623D4DEA 7E02DC5A 85E24AF2 96B5A555 AD470413 71E4BF64 380F3E34");
		Integer k("0x 6942B01D 5901BEC1 506BB874 9618E22E C0FCD7F3 5159D51E D53BA77A 78752128 A58232AD 8E0E021A FDE1477F F4C74FDF FE88AE2D 15D89B56 F6D73C03 77631D2B");

		Integer r, s;
		signer.RawSign(k, e, r, s);

		Integer rExp("0x 0104918B 2B32B1A5 49BD43C3 0092953B 4164CA01 A1A97B5B 0756EA06 3AC16B41 B88A1BAB 4538CD7D 8466180B 3E3F5C86 46AC4A45 F564E9B6 8FEE72ED 00C7AC48");
		Integer sExp("0x 17A011F8 DD7B5665 2B27AA6D 6E7BDF3C 7C23B5FA 32910FBA A107E627 0E1CA8A7 A263F661 8E6098A0 D6CD6BA1 C03544C5 425875EC B3418AF5 A3EE3F32 143E48D2");

		fail = (r != rExp) || (s != sExp);
		pass = pass && !fail;

		const byte msg[] = "Example of ECGDSA with the hash function SHA-512";
		const size_t len = strlen((char*)msg);

		byte signature[128];
		r.Encode(signature+0, 64);
		s.Encode(signature+64, 64);

		fail = !verifier.VerifyMessage(msg, len, signature, sizeof(signature));
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "brainpoolP512r1 using SHA-512\n";

		fail = !SignatureValidate(signer, verifier);
		pass = pass && !fail;
	}

	return pass;
}

bool ValidateESIGN()
{
	cout << "\nESIGN validation suite running...\n\n";

	bool pass = true, fail;

	static const char plain[] = "test";
	static const byte signature[] =
		"\xA3\xE3\x20\x65\xDE\xDA\xE7\xEC\x05\xC1\xBF\xCD\x25\x79\x7D\x99\xCD\xD5\x73\x9D\x9D\xF3\xA4\xAA\x9A\xA4\x5A\xC8\x23\x3D\x0D\x37"
		"\xFE\xBC\x76\x3F\xF1\x84\xF6\x59\x14\x91\x4F\x0C\x34\x1B\xAE\x9A\x5C\x2E\x2E\x38\x08\x78\x77\xCB\xDC\x3C\x7E\xA0\x34\x44\x5B\x0F"
		"\x67\xD9\x35\x2A\x79\x47\x1A\x52\x37\x71\xDB\x12\x67\xC1\xB6\xC6\x66\x73\xB3\x40\x2E\xD6\xF2\x1A\x84\x0A\xB6\x7B\x0F\xEB\x8B\x88"
		"\xAB\x33\xDD\xE4\x83\x21\x90\x63\x2D\x51\x2A\xB1\x6F\xAB\xA7\x5C\xFD\x77\x99\xF2\xE1\xEF\x67\x1A\x74\x02\x37\x0E\xED\x0A\x06\xAD"
		"\xF4\x15\x65\xB8\xE1\xD1\x45\xAE\x39\x19\xB4\xFF\x5D\xF1\x45\x7B\xE0\xFE\x72\xED\x11\x92\x8F\x61\x41\x4F\x02\x00\xF2\x76\x6F\x7C"
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
