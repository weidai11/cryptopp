// bench2.cpp - written and placed in the public domain by Wei Dai

#include "bench.h"
#include "rng.h"
#include "files.h"
#include "hex.h"

#include "rsa.h"
#include "nr.h"
#include "dsa.h"
#include "luc.h"
#include "rabin.h"
#include "rw.h"
#include "eccrypto.h"
#include "ecp.h"
#include "ec2n.h"
#include "asn.h"
#include "dh.h"
#include "mqv.h"
#include "xtrcrypt.h"
#include "esign.h"

#include <time.h>
#include <math.h>
#include <iostream>
#include <iomanip>

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

void OutputResultOperations(const char *name, const char *operation, bool pc, unsigned long iterations, double timeTaken);

void BenchMarkEncryption(const char *name, PK_Encryptor &key, double timeTotal, bool pc=false)
{
	unsigned int len = 16;
	LC_RNG rng((word32)time(NULL));
	SecByteBlock plaintext(len), ciphertext(key.CiphertextLength(len));
	rng.GenerateBlock(plaintext, len);

	clock_t start = clock();
	unsigned int i;
	double timeTaken;
	for (timeTaken=(double)0, i=0; timeTaken < timeTotal; timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		key.Encrypt(rng, plaintext, len, ciphertext);

	OutputResultOperations(name, "Encryption", pc, i, timeTaken);

	if (!pc && key.GetMaterial().SupportsPrecomputation())
	{
		key.AccessMaterial().Precompute(16);
		BenchMarkEncryption(name, key, timeTotal, true);
	}
}

void BenchMarkDecryption(const char *name, PK_Decryptor &priv, PK_Encryptor &pub, double timeTotal)
{
	unsigned int len = 16;
	LC_RNG rng((word32)time(NULL));
	SecByteBlock ciphertext(pub.CiphertextLength(len));
	SecByteBlock plaintext(pub.MaxPlaintextLength(ciphertext.size()));
	rng.GenerateBlock(plaintext, len);
	pub.Encrypt(rng, plaintext, len, ciphertext);

	clock_t start = clock();
	unsigned int i;
	double timeTaken;
	for (timeTaken=(double)0, i=0; timeTaken < timeTotal; timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		priv.Decrypt(rng, ciphertext, ciphertext.size(), plaintext);

	OutputResultOperations(name, "Decryption", false, i, timeTaken);
}

void BenchMarkSigning(const char *name, PK_Signer &key, double timeTotal, bool pc=false)
{
	unsigned int len = 16;
	LC_RNG rng((word32)time(NULL));
	SecByteBlock message(len), signature(key.SignatureLength());
	rng.GenerateBlock(message, len);

	clock_t start = clock();
	unsigned int i;
	double timeTaken;
	for (timeTaken=(double)0, i=0; timeTaken < timeTotal; timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		key.SignMessage(rng, message, len, signature);

	OutputResultOperations(name, "Signature", pc, i, timeTaken);

	if (!pc && key.GetMaterial().SupportsPrecomputation())
	{
		key.AccessMaterial().Precompute(16);
		BenchMarkSigning(name, key, timeTotal, true);
	}
}

void BenchMarkVerification(const char *name, const PK_Signer &priv, PK_Verifier &pub, double timeTotal, bool pc=false)
{
	unsigned int len = 16;
	LC_RNG rng((word32)time(NULL));
	SecByteBlock message(len), signature(pub.SignatureLength());
	rng.GenerateBlock(message, len);
	priv.SignMessage(rng, message, len, signature);

	clock_t start = clock();
	unsigned int i;
	double timeTaken;
	for (timeTaken=(double)0, i=0; timeTaken < timeTotal; timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		pub.VerifyMessage(message, len, signature, signature.size());

	OutputResultOperations(name, "Verification", pc, i, timeTaken);

	if (!pc && pub.GetMaterial().SupportsPrecomputation())
	{
		pub.AccessMaterial().Precompute(16);
		BenchMarkVerification(name, priv, pub, timeTotal, true);
	}
}

void BenchMarkKeyGen(const char *name, SimpleKeyAgreementDomain &d, double timeTotal, bool pc=false)
{
	LC_RNG rng((word32)time(NULL));
	SecByteBlock priv(d.PrivateKeyLength()), pub(d.PublicKeyLength());

	clock_t start = clock();
	unsigned int i;
	double timeTaken;
	for (timeTaken=(double)0, i=0; timeTaken < timeTotal; timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		d.GenerateKeyPair(rng, priv, pub);

	OutputResultOperations(name, "Key-Pair Generation", pc, i, timeTaken);

	if (!pc && d.GetMaterial().SupportsPrecomputation())
	{
		d.AccessMaterial().Precompute(16);
		BenchMarkKeyGen(name, d, timeTotal, true);
	}
}

void BenchMarkKeyGen(const char *name, AuthenticatedKeyAgreementDomain &d, double timeTotal, bool pc=false)
{
	LC_RNG rng((word32)time(NULL));
	SecByteBlock priv(d.EphemeralPrivateKeyLength()), pub(d.EphemeralPublicKeyLength());

	clock_t start = clock();
	unsigned int i;
	double timeTaken;
	for (timeTaken=(double)0, i=0; timeTaken < timeTotal; timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		d.GenerateEphemeralKeyPair(rng, priv, pub);

	OutputResultOperations(name, "Key-Pair Generation", pc, i, timeTaken);

	if (!pc && d.GetMaterial().SupportsPrecomputation())
	{
		d.AccessMaterial().Precompute(16);
		BenchMarkKeyGen(name, d, timeTotal, true);
	}
}

void BenchMarkAgreement(const char *name, SimpleKeyAgreementDomain &d, double timeTotal, bool pc=false)
{
	LC_RNG rng((word32)time(NULL));
	SecByteBlock priv1(d.PrivateKeyLength()), priv2(d.PrivateKeyLength());
	SecByteBlock pub1(d.PublicKeyLength()), pub2(d.PublicKeyLength());
	d.GenerateKeyPair(rng, priv1, pub1);
	d.GenerateKeyPair(rng, priv2, pub2);
	SecByteBlock val(d.AgreedValueLength());

	clock_t start = clock();
	unsigned int i;
	double timeTaken;
	for (timeTaken=(double)0, i=0; timeTaken < timeTotal; timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND, i+=2)
	{
		d.Agree(val, priv1, pub2);
		d.Agree(val, priv2, pub1);
	}

	OutputResultOperations(name, "Key Agreement", pc, i, timeTaken);
}

void BenchMarkAgreement(const char *name, AuthenticatedKeyAgreementDomain &d, double timeTotal, bool pc=false)
{
	LC_RNG rng((word32)time(NULL));
	SecByteBlock spriv1(d.StaticPrivateKeyLength()), spriv2(d.StaticPrivateKeyLength());
	SecByteBlock epriv1(d.EphemeralPrivateKeyLength()), epriv2(d.EphemeralPrivateKeyLength());
	SecByteBlock spub1(d.StaticPublicKeyLength()), spub2(d.StaticPublicKeyLength());
	SecByteBlock epub1(d.EphemeralPublicKeyLength()), epub2(d.EphemeralPublicKeyLength());
	d.GenerateStaticKeyPair(rng, spriv1, spub1);
	d.GenerateStaticKeyPair(rng, spriv2, spub2);
	d.GenerateEphemeralKeyPair(rng, epriv1, epub1);
	d.GenerateEphemeralKeyPair(rng, epriv2, epub2);
	SecByteBlock val(d.AgreedValueLength());

	clock_t start = clock();
	unsigned int i;
	double timeTaken;
	for (timeTaken=(double)0, i=0; timeTaken < timeTotal; timeTaken = double(clock() - start) / CLOCK_TICKS_PER_SECOND, i+=2)
	{
		d.Agree(val, spriv1, epriv1, spub2, epub2);
		d.Agree(val, spriv2, epriv2, spub1, epub1);
	}

	OutputResultOperations(name, "Key Agreement", pc, i, timeTaken);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class SCHEME>
void BenchMarkCrypto(const char *filename, const char *name, double timeTotal, SCHEME *x=NULL)
{
	FileSource f(filename, true, new HexDecoder());
	typename SCHEME::Decryptor priv(f);
	typename SCHEME::Encryptor pub(priv);
	BenchMarkEncryption(name, pub, timeTotal);
	BenchMarkDecryption(name, priv, pub, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class SCHEME>
void BenchMarkSignature(const char *filename, const char *name, double timeTotal, SCHEME *x=NULL)
{
	FileSource f(filename, true, new HexDecoder());
	typename SCHEME::Signer priv(f);
	typename SCHEME::Verifier pub(priv);
	BenchMarkSigning(name, priv, timeTotal);
	BenchMarkVerification(name, priv, pub, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class D>
void BenchMarkKeyAgreement(const char *filename, const char *name, double timeTotal, D *x=NULL)
{
	FileSource f(filename, true, new HexDecoder());
	D d(f);
	BenchMarkKeyGen(name, d, timeTotal);
	BenchMarkAgreement(name, d, timeTotal);
}

void BenchmarkAll2(double t)
{
	cout << "<TABLE border=1><COLGROUP><COL align=left><COL align=right><COL align=right><COL align=right>" << endl;
	cout << "<THEAD><TR><TH>Operation<TH>Iterations<TH>Total Time<TH>Milliseconds/Operation" << endl;

	cout << "<TBODY style=\"background: yellow\">" << endl;
	BenchMarkCrypto<RSAES<OAEP<SHA> > >("rsa1024.dat", "RSA 1024", t);
	BenchMarkCrypto<RabinES<OAEP<SHA> > >("rabi1024.dat", "Rabin 1024", t);
	BenchMarkCrypto<LUCES<OAEP<SHA> > >("luc1024.dat", "LUC 1024", t);
	BenchMarkCrypto<DLIES<> >("dlie1024.dat", "DLIES 1024", t);
	BenchMarkCrypto<LUC_IES<> >("lucc512.dat", "LUCELG 512", t);

	cout << "<TBODY style=\"background: white\">" << endl;
	BenchMarkCrypto<RSAES<OAEP<SHA> > >("rsa2048.dat", "RSA 2048", t);
	BenchMarkCrypto<RabinES<OAEP<SHA> > >("rabi2048.dat", "Rabin 2048", t);
	BenchMarkCrypto<LUCES<OAEP<SHA> > >("luc2048.dat", "LUC 2048", t);
	BenchMarkCrypto<DLIES<> >("dlie2048.dat", "DLIES 2048", t);
	BenchMarkCrypto<LUC_IES<> >("lucc1024.dat", "LUCELG 1024", t);

	cout << "<TBODY style=\"background: yellow\">" << endl;
	BenchMarkSignature<RSASS<PSSR, SHA> >("rsa1024.dat", "RSA 1024", t);
	BenchMarkSignature<RabinSS<PSSR, SHA> >("rabi1024.dat", "Rabin 1024", t);
	BenchMarkSignature<RWSS<PSSR, SHA> >("rw1024.dat", "RW 1024", t);
	BenchMarkSignature<LUCSS<PSSR, SHA> >("luc1024.dat", "LUC 1024", t);
	BenchMarkSignature<NR<SHA> >("nr1024.dat", "NR 1024", t);
	BenchMarkSignature<DSA>("dsa1024.dat", "DSA 1024", t);
	BenchMarkSignature<LUC_HMP<SHA> >("lucs512.dat", "LUC-HMP 512", t);
	BenchMarkSignature<ESIGN<SHA> >("esig1023.dat", "ESIGN 1023", t);
	BenchMarkSignature<ESIGN<SHA> >("esig1536.dat", "ESIGN 1536", t);

	cout << "<TBODY style=\"background: white\">" << endl;
	BenchMarkSignature<RSASS<PSSR, SHA> >("rsa2048.dat", "RSA 2048", t);
	BenchMarkSignature<RabinSS<PSSR, SHA> >("rabi2048.dat", "Rabin 2048", t);
	BenchMarkSignature<RWSS<PSSR, SHA> >("rw2048.dat", "RW 2048", t);
	BenchMarkSignature<LUCSS<PSSR, SHA> >("luc2048.dat", "LUC 2048", t);
	BenchMarkSignature<NR<SHA> >("nr2048.dat", "NR 2048", t);
	BenchMarkSignature<LUC_HMP<SHA> >("lucs1024.dat", "LUC-HMP 1024", t);
	BenchMarkSignature<ESIGN<SHA> >("esig2046.dat", "ESIGN 2046", t);

	cout << "<TBODY style=\"background: yellow\">" << endl;
	BenchMarkKeyAgreement<XTR_DH>("xtrdh171.dat", "XTR-DH 171", t);
	BenchMarkKeyAgreement<XTR_DH>("xtrdh342.dat", "XTR-DH 342", t);
	BenchMarkKeyAgreement<DH>("dh1024.dat", "DH 1024", t);
	BenchMarkKeyAgreement<DH>("dh2048.dat", "DH 2048", t);
	BenchMarkKeyAgreement<LUC_DH>("lucd512.dat", "LUCDIF 512", t);
	BenchMarkKeyAgreement<LUC_DH>("lucd1024.dat", "LUCDIF 1024", t);
	BenchMarkKeyAgreement<MQV>("mqv1024.dat", "MQV 1024", t);
	BenchMarkKeyAgreement<MQV>("mqv2048.dat", "MQV 2048", t);

	cout << "<TBODY style=\"background: white\">" << endl;
	{
		Integer modulus("199999999999999999999999980586675243082581144187569");
		Integer a("659942,b7261b,249174,c86bd5,e2a65b,45fe07,37d110h");
		Integer b("3ece7d,09473d,666000,5baef5,d4e00e,30159d,2df49ah");
		Integer x("25dd61,4c0667,81abc0,fe6c84,fefaa3,858ca6,96d0e8h");
		Integer y("4e2477,05aab0,b3497f,d62b5e,78a531,446729,6c3fach");
		Integer r("100000000000000000000000000000000000000000000000151");
		Integer k(2);
		Integer d("76572944925670636209790912427415155085360939712345");

		ECP ec(modulus, a, b);
		ECP::Point P(x, y);
		P = ec.Multiply(k, P);
		ECP::Point Q(ec.Multiply(d, P));
		ECIES<ECP>::Decryptor cpriv(ec, P, r, d);
		ECIES<ECP>::Encryptor cpub(cpriv);
		ECDSA<ECP, SHA>::Signer spriv(cpriv);
		ECDSA<ECP, SHA>::Verifier spub(spriv);
		ECDH<ECP>::Domain ecdhc(ec, P, r, k);
		ECMQV<ECP>::Domain ecmqvc(ec, P, r, k);

		BenchMarkEncryption("ECIES over GF(p) 168", cpub, t);
		BenchMarkDecryption("ECIES over GF(p) 168", cpriv, cpub, t);
		BenchMarkSigning("ECNR over GF(p) 168", spriv, t);
		BenchMarkVerification("ECNR over GF(p) 168", spriv, spub, t);
		BenchMarkKeyGen("ECDHC over GF(p) 168", ecdhc, t);
		BenchMarkAgreement("ECDHC over GF(p) 168", ecdhc, t);
		BenchMarkKeyGen("ECMQVC over GF(p) 168", ecmqvc, t);
		BenchMarkAgreement("ECMQVC over GF(p) 168", ecmqvc, t);
	}

	cout << "<TBODY style=\"background: yellow\">" << endl;
	{
		Integer r("3805993847215893016155463826195386266397436443");
		Integer k(12);
		Integer d("2065729449256706362097909124274151550853609397");

		GF2NT gf2n(155, 62, 0);
		byte b[]={0x7, 0x33, 0x8f};
		EC2N ec(gf2n, PolynomialMod2::Zero(), PolynomialMod2(b,3));
		EC2N::Point P(0x7B, 0x1C8);
		P = ec.Multiply(k, P);
		EC2N::Point Q(ec.Multiply(d, P));
		ECIES<EC2N>::Decryptor cpriv(ec, P, r, d);
		ECIES<EC2N>::Encryptor cpub(cpriv);
		ECDSA<EC2N, SHA>::Signer spriv(cpriv);
		ECDSA<EC2N, SHA>::Verifier spub(spriv);
		ECDH<EC2N>::Domain ecdhc(ec, P, r, k);
		ECMQV<EC2N>::Domain ecmqvc(ec, P, r, k);

		BenchMarkEncryption("ECIES over GF(2^n) 155", cpub, t);
		BenchMarkDecryption("ECIES over GF(2^n) 155", cpriv, cpub, t);
		BenchMarkSigning("ECNR over GF(2^n) 155", spriv, t);
		BenchMarkVerification("ECNR over GF(2^n) 155", spriv, spub, t);
		BenchMarkKeyGen("ECDHC over GF(2^n) 155", ecdhc, t);
		BenchMarkAgreement("ECDHC over GF(2^n) 155", ecdhc, t);
		BenchMarkKeyGen("ECMQVC over GF(2^n) 155", ecmqvc, t);
		BenchMarkAgreement("ECMQVC over GF(2^n) 155", ecmqvc, t);
	}
	cout << "</TABLE>" << endl;
}
