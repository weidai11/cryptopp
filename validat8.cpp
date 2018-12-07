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
