// validat8.cpp - originally written and placed in the public domain by Wei Dai
//                CryptoPP::Test namespace added by JW in February 2017.
//                Source files split in July 2018 to expedite compiles.

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "cpu.h"
#include "validate.h"

#include "asn.h"
#include "oids.h"

#include "luc.h"
#include "rsa.h"
#include "xtr.h"
#include "rabin.h"
#include "pubkey.h"
#include "elgamal.h"
#include "xtrcrypt.h"
#include "eccrypto.h"

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

inline byte* C2B(char* ptr) {
    return reinterpret_cast<byte*>(ptr);
}

inline const byte* C2B(const char* ptr) {
    return reinterpret_cast<const byte*>(ptr);
}

bool ValidateRSA_Encrypt()
{
	// Must be large enough for RSA-3072 to test SHA3_256
	byte out[256], outPlain[128];
	bool pass = true, fail;

	{
		FileSource keys(DataDir("TestData/rsa1024.dat").c_str(), true, new HexDecoder);
		RSAES_PKCS1v15_Decryptor rsaPriv(keys);
		RSAES_PKCS1v15_Encryptor rsaPub(rsaPriv);

		pass = CryptoSystemValidate(rsaPriv, rsaPub) && pass;
	}
	{
		RSAES<OAEP<SHA1> >::Decryptor rsaPriv(GlobalRNG(), 512);
		RSAES<OAEP<SHA1> >::Encryptor rsaPub(rsaPriv);

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

		FileSource privFile(DataDir("TestData/rsa400pv.dat").c_str(), true, new HexDecoder);
		FileSource pubFile(DataDir("TestData/rsa400pb.dat").c_str(), true, new HexDecoder);
		RSAES_OAEP_SHA_Decryptor rsaPriv;
		rsaPriv.AccessKey().BERDecodePrivateKey(privFile, false, 0);
		RSAES_OAEP_SHA_Encryptor rsaPub(pubFile);

		memset(out, 0, 50);
		memset(outPlain, 0, 8);
		rsaPub.Encrypt(rng, plain, 8, out);
		DecodingResult result = rsaPriv.FixedLengthDecrypt(GlobalRNG(), encrypted, outPlain);
		fail = !result.isValidCoding || (result.messageLength!=8) || memcmp(out, encrypted, 50) || memcmp(plain, outPlain, 8);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "PKCS 2.0 encryption and decryption\n";
	}

	return pass;
}

bool ValidateLUC_Encrypt()
{
	FileSource f(DataDir("TestData/luc1024.dat").c_str(), true, new HexDecoder);
	LUCES_OAEP_SHA_Decryptor priv(GlobalRNG(), 512);
	LUCES_OAEP_SHA_Encryptor pub(priv);
	return CryptoSystemValidate(priv, pub);
}

bool ValidateLUC_DL_Encrypt()
{
	std::cout << "\nLUC-IES validation suite running...\n\n";

	FileSource fc(DataDir("TestData/lucc512.dat").c_str(), true, new HexDecoder);
	LUC_IES<>::Decryptor privC(fc);
	LUC_IES<>::Encryptor pubC(privC);
	return CryptoSystemValidate(privC, pubC);
}

bool ValidateRabin_Encrypt()
{
	FileSource f(DataDir("TestData/rabi1024.dat").c_str(), true, new HexDecoder);
	RabinES<OAEP<SHA1> >::Decryptor priv(f);
	RabinES<OAEP<SHA1> >::Encryptor pub(priv);
	return CryptoSystemValidate(priv, pub);
}

bool ValidateECP_Encrypt()
{
	ECIES<ECP>::Decryptor cpriv(GlobalRNG(), ASN1::secp192r1());
	ECIES<ECP>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.GetKey().DEREncode(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.GetKey().DEREncode(bq);

	cpub.AccessKey().Precompute();
	cpriv.AccessKey().Precompute();
	bool pass = CryptoSystemValidate(cpriv, cpub);

	std::cout << "Turning on point compression..." << std::endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;

	return pass;
}

// https://github.com/weidai11/cryptopp/issues/856
class NULLHash : public CryptoPP::IteratedHashWithStaticTransform
    <CryptoPP::word32, CryptoPP::BigEndian, 32, 0, NULLHash, 0>
{
public:
    static void InitState(HashWordType *state) {}
    static void Transform(CryptoPP::word32 *digest, const CryptoPP::word32 *data) {}
    static const char *StaticAlgorithmName() {return "NULL HASH";}
};

// https://github.com/weidai11/cryptopp/issues/856
template <class EC, class HASH = SHA1, class COFACTOR_OPTION = NoCofactorMultiplication, bool DHAES_MODE = true, bool LABEL_OCTETS = false>
struct ECIES_NULLDigest
	: public DL_ES<
		DL_Keys_EC<EC>,
		DL_KeyAgreementAlgorithm_DH<typename EC::Point, COFACTOR_OPTION>,
		DL_KeyDerivationAlgorithm_P1363<typename EC::Point, DHAES_MODE, P1363_KDF2<HASH> >,
		DL_EncryptionAlgorithm_Xor<HMAC<NULLHash>, DHAES_MODE, LABEL_OCTETS>,
		ECIES<EC> >
{
	// TODO: fix this after name is standardized
	CRYPTOPP_STATIC_CONSTEXPR const char* CRYPTOPP_API StaticAlgorithmName() {return "ECIES-NULLDigest";}
};

bool ValidateECP_NULLDigest_Encrypt()
{
	ECIES_NULLDigest<ECP>::Decryptor cpriv(GlobalRNG(), ASN1::secp256k1());
	ECIES_NULLDigest<ECP>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.GetKey().DEREncode(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.GetKey().DEREncode(bq);

	cpub.AccessKey().Precompute();
	cpriv.AccessKey().Precompute();
	bool pass = CryptoSystemValidate(cpriv, cpub);

	std::cout << "Turning on point compression..." << std::endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;

	return pass;
}

// Ensure interop with Crypto++ 5.6.4 and earlier
bool ValidateECP_Legacy_Encrypt()
{
	std::cout << "\nLegacy ECIES ECP validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc(DataDir("TestData/ecies_p160.dat").c_str(), true, new HexDecoder);
		ECIES<ECP,SHA1,NoCofactorMultiplication,false,true>::Decryptor privC(fc);
		ECIES<ECP,SHA1,NoCofactorMultiplication,false,true>::Encryptor pubC(privC);

		pass = CryptoSystemValidate(privC, pubC) && pass;

		// Test data generated by Crypto++ 5.6.2.
		// Also see https://github.com/weidai11/cryptopp/pull/857.
		const std::string plain = "Yoda said, Do or do not. There is no try.";
		const std::string cipher =
			"\x04\xF6\xC1\xB1\xFA\xAC\x8A\xD5\xD3\x96\xE7\x13\xAE\xBD\x0C\xCE"
			"\x15\xCF\x44\x54\x08\x63\xCC\xBF\x89\x4D\xD0\xB8\x38\xA1\x3A\xB2"
			"\x90\x75\x86\x82\x7F\x9D\x95\x26\xA5\x74\x13\x3A\x74\x63\x11\x71"
			"\x70\x4C\x01\xA4\x08\x04\x95\x69\x6A\x91\xF0\xC0\xA4\xBD\x1E\xAA"
			"\x59\x57\xB8\xA9\xD2\xF7\x7C\x98\xE3\xC5\xE3\xF4\x4F\xA7\x6E\x73"
			"\x83\xF3\x1E\x05\x73\xA4\xEE\x63\x55\xFD\x6D\x31\xBB\x9E\x36\x4C"
			"\x79\xD0\x76\xC0\x0D\xE9";

		std::string recover;
		recover.resize(privC.MaxPlaintextLength(cipher.size()));

		DecodingResult result = privC.Decrypt(GlobalRNG(), C2B(&cipher[0]), cipher.size(), C2B(&recover[0]));
		if (result.isValidCoding)
			recover.resize(result.messageLength);
		else
			recover.resize(0);

		pass = (plain == recover) && pass;
		std::cout << (pass ? "passed    " : "FAILED    ");
		std::cout << "decryption known answer\n";
	}
	return pass;
}

bool ValidateEC2N_Encrypt()
{
	// DEREncode() changed to Save() at Issue 569.
	ECIES<EC2N>::Decryptor cpriv(GlobalRNG(), ASN1::sect193r1());
	ECIES<EC2N>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.AccessMaterial().Save(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.AccessMaterial().Save(bq);
	bool pass = CryptoSystemValidate(cpriv, cpub);

	std::cout << "Turning on point compression..." << std::endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;

	return pass;
}

bool ValidateElGamal()
{
	std::cout << "\nElGamal validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc(DataDir("TestData/elgc1024.dat").c_str(), true, new HexDecoder);
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
	std::cout << "\nDLIES validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc(DataDir("TestData/dlie1024.dat").c_str(), true, new HexDecoder);
		DLIES<>::Decryptor privC(fc);
		DLIES<>::Encryptor pubC(privC);
		pass = CryptoSystemValidate(privC, pubC) && pass;
	}
	{
		std::cout << "Generating new encryption key..." << std::endl;
		DLIES<>::GroupParameters gp;
		gp.GenerateRandomWithKeySize(GlobalRNG(), 128);
		DLIES<>::Decryptor decryptor;
		decryptor.AccessKey().GenerateRandom(GlobalRNG(), gp);
		DLIES<>::Encryptor encryptor(decryptor);

		pass = CryptoSystemValidate(decryptor, encryptor) && pass;
	}
	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
