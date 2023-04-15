// validat6.cpp - originally written and placed in the public domain by Wei Dai
//                CryptoPP::Test namespace added by JW in February 2017.
//                Source files split in July 2018 to expedite compiles.

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "cpu.h"
#include "validate.h"

#include "asn.h"
#include "oids.h"
#include "blumshub.h"
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

bool CryptoSystemValidate(PK_Decryptor &priv, PK_Encryptor &pub, bool thorough)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	pass = pass && !fail;

	std::cout << (fail ? "FAILED    " : "passed    ");
	std::cout << "cryptosystem key validation\n";

	const byte message[] = "test message";
	const int messageLen = 12;
	SecByteBlock ciphertext(priv.CiphertextLength(messageLen));
	SecByteBlock plaintext(priv.MaxPlaintextLength(ciphertext.size()));

	pub.Encrypt(GlobalRNG(), message, messageLen, ciphertext);
	fail = priv.Decrypt(GlobalRNG(), ciphertext, priv.CiphertextLength(messageLen), plaintext) != DecodingResult(messageLen);
	fail = fail || std::memcmp(message, plaintext, messageLen);
	pass = pass && !fail;

	std::cout << (fail ? "FAILED    " : "passed    ");
	std::cout << "encryption and decryption\n";

	return pass;
}

bool SimpleKeyAgreementValidate(SimpleKeyAgreementDomain &d)
{
	if (d.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    simple key agreement domain parameters validation" << std::endl;
	else
	{
		std::cout << "FAILED    simple key agreement domain parameters invalid" << std::endl;
		return false;
	}

	SecByteBlock priv1(d.PrivateKeyLength()), priv2(d.PrivateKeyLength());
	SecByteBlock pub1(d.PublicKeyLength()), pub2(d.PublicKeyLength());
	SecByteBlock val1(d.AgreedValueLength()), val2(d.AgreedValueLength());

	d.GenerateKeyPair(GlobalRNG(), priv1, pub1);
	d.GenerateKeyPair(GlobalRNG(), priv2, pub2);

	std::memset(val1.begin(), 0x10, val1.size());
	std::memset(val2.begin(), 0x11, val2.size());

	if (!(d.Agree(val1, priv1, pub2) && d.Agree(val2, priv2, pub1)))
	{
		std::cout << "FAILED    simple key agreement failed" << std::endl;
		return false;
	}

	if (std::memcmp(val1.begin(), val2.begin(), d.AgreedValueLength()))
	{
		std::cout << "FAILED    simple agreed values not equal" << std::endl;
		return false;
	}

	std::cout << "passed    simple key agreement" << std::endl;
	return true;
}

bool AuthenticatedKeyAgreementValidate(AuthenticatedKeyAgreementDomain &d)
{
	if (d.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid" << std::endl;
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

	std::memset(val1.begin(), 0x10, val1.size());
	std::memset(val2.begin(), 0x11, val2.size());

	if (d.Agree(val1, spriv1, epriv1, spub2, epub2) && d.Agree(val2, spriv2, epriv2, spub1, epub1))
	{
		std::cout << "passed    authenticated key agreement protocol execution" << std::endl;
	}
	else
	{
		std::cout << "FAILED    authenticated key agreement protocol execution" << std::endl;
		return false;
	}

	if (std::memcmp(val1.begin(), val2.begin(), d.AgreedValueLength()))
	{
		std::cout << "FAILED    authenticated agreed values not equal" << std::endl;
		return false;
	}

	std::cout << "passed    authenticated key agreement" << std::endl;
	return true;
}

bool AuthenticatedKeyAgreementWithRolesValidate(AuthenticatedKeyAgreementDomain &initiator, AuthenticatedKeyAgreementDomain &recipient)
{
	if (initiator.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (initiator)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (initiator)" << std::endl;
		return false;
	}

	if (recipient.GetCryptoParameters().Validate(GlobalRNG(), 3))
		std::cout << "passed    authenticated key agreement domain parameters validation (recipient)" << std::endl;
	else
	{
		std::cout << "FAILED    authenticated key agreement domain parameters invalid (recipient)" << std::endl;
		return false;
	}

	if (initiator.StaticPrivateKeyLength() != recipient.StaticPrivateKeyLength() ||
	    initiator.EphemeralPrivateKeyLength() != recipient.EphemeralPrivateKeyLength() ||
	    initiator.StaticPublicKeyLength() != recipient.StaticPublicKeyLength() ||
	    initiator.EphemeralPublicKeyLength() != recipient.EphemeralPublicKeyLength() ||
	    initiator.AgreedValueLength() != recipient.AgreedValueLength())
	{
		std::cout << "FAILED    authenticated key agreement domain parameter consistency" << std::endl;
		return false;
	}
	else
	{
		std::cout << "passed    authenticated key agreement domain parameter consistency" << std::endl;
	}

	SecByteBlock spriv1(initiator.StaticPrivateKeyLength()), spriv2(recipient.StaticPrivateKeyLength());
	SecByteBlock epriv1(initiator.EphemeralPrivateKeyLength()), epriv2(recipient.EphemeralPrivateKeyLength());
	SecByteBlock spub1(initiator.StaticPublicKeyLength()), spub2(recipient.StaticPublicKeyLength());
	SecByteBlock epub1(initiator.EphemeralPublicKeyLength()), epub2(recipient.EphemeralPublicKeyLength());
	SecByteBlock val1(initiator.AgreedValueLength()), val2(recipient.AgreedValueLength());

	initiator.GenerateStaticKeyPair(GlobalRNG(), spriv1, spub1);
	recipient.GenerateStaticKeyPair(GlobalRNG(), spriv2, spub2);
	initiator.GenerateEphemeralKeyPair(GlobalRNG(), epriv1, epub1);
	recipient.GenerateEphemeralKeyPair(GlobalRNG(), epriv2, epub2);

	std::memset(val1.begin(), 0x10, val1.size());
	std::memset(val2.begin(), 0x11, val2.size());

	if (initiator.Agree(val1, spriv1, epriv1, spub2, epub2) && recipient.Agree(val2, spriv2, epriv2, spub1, epub1))
	{
		std::cout << "passed    authenticated key agreement protocol execution" << std::endl;
	}
	else
	{
		std::cout << "FAILED    authenticated key agreement protocol execution" << std::endl;
		return false;
	}

	if (std::memcmp(val1.begin(), val2.begin(), initiator.AgreedValueLength()))
	{
		std::cout << "FAILED    authenticated agreed values not equal" << std::endl;
		return false;
	}

	std::cout << "passed    authenticated key agreement shared secret" << std::endl;
	return true;
}

bool SignatureValidate(PK_Signer &priv, PK_Verifier &pub, bool thorough)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	pass = pass && !fail;

	std::cout << (fail ? "FAILED    " : "passed    ");
	std::cout << "signature key validation\n";

	const byte message[] = "test message";
	const int messageLen = 12;

	SecByteBlock signature(priv.MaxSignatureLength());
	size_t signatureLength = priv.SignMessage(GlobalRNG(), message, messageLen, signature);
	fail = !pub.VerifyMessage(message, messageLen, signature, signatureLength);
	pass = pass && !fail;

	std::cout << (fail ? "FAILED    " : "passed    ");
	std::cout << "signature and verification\n";

	++signature[0];
	fail = pub.VerifyMessage(message, messageLen, signature, signatureLength);
	pass = pass && !fail;

	std::cout << (fail ? "FAILED    " : "passed    ");
	std::cout << "checking invalid signature" << std::endl;

	if (priv.MaxRecoverableLength() > 0)
	{
		signatureLength = priv.SignMessageWithRecovery(GlobalRNG(), message, messageLen, NULLPTR, 0, signature);
		SecByteBlock recovered(priv.MaxRecoverableLengthFromSignatureLength(signatureLength));
		DecodingResult result = pub.RecoverMessage(recovered, NULLPTR, 0, signature, signatureLength);
		fail = !(result.isValidCoding && result.messageLength == messageLen && std::memcmp(recovered, message, messageLen) == 0);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "signature and verification with recovery" << std::endl;

		++signature[0];
		result = pub.RecoverMessage(recovered, NULLPTR, 0, signature, signatureLength);
		fail = result.isValidCoding;
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "recovery with invalid signature" << std::endl;
	}

	return pass;
}

bool ValidateBBS()
{
	std::cout << "\nBlumBlumShub validation suite running...\n\n";

	Integer p("212004934506826557583707108431463840565872545889679278744389317666981496005411448865750399674653351");
	Integer q("100677295735404212434355574418077394581488455772477016953458064183204108039226017738610663984508231");
	Integer seed("63239752671357255800299643604761065219897634268887145610573595874544114193025997412441121667211431");
	BlumBlumShub bbs(p, q, seed);
	bool pass = true, fail;
	int j;

	const byte output1[] = {
		0x49,0xEA,0x2C,0xFD,0xB0,0x10,0x64,0xA0,0xBB,0xB9,
		0x2A,0xF1,0x01,0xDA,0xC1,0x8A,0x94,0xF7,0xB7,0xCE};
	const byte output2[] = {
		0x74,0x45,0x48,0xAE,0xAC,0xB7,0x0E,0xDF,0xAF,0xD7,
		0xD5,0x0E,0x8E,0x29,0x83,0x75,0x6B,0x27,0x46,0xA1};

	byte buf[20];
	std::ostringstream oss;

	bbs.GenerateBlock(buf, 20);
	fail = std::memcmp(output1, buf, 20) != 0;
	pass = pass && !fail;

	oss << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<20;j++)
		oss << std::setw(2) << std::setfill('0') << std::hex << (int)buf[j];
	oss << std::endl;

	bbs.Seek(10);
	bbs.GenerateBlock(buf, 10);
	fail = std::memcmp(output1+10, buf, 10) != 0;
	pass = pass && !fail;

	oss << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<10;j++)
		oss << std::setw(2) << std::setfill('0') << std::hex << (int)buf[j];
	oss << std::endl;

	bbs.Seek(1234567);
	bbs.GenerateBlock(buf, 20);
	fail = std::memcmp(output2, buf, 20) != 0;
	pass = pass && !fail;

	oss << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<20;j++)
		oss << std::setw(2) << std::setfill('0') << std::hex << (int)buf[j];
	oss << std::endl;

	std::cout << oss.str();
	return pass;
}

bool ValidateECP()
{
	// Remove word recommend. Some ECP curves may not be recommended depending
	// on whom you ask. ECP is more descriptive item in this case.
	std::cout << "\nTesting SEC 2, NIST and Brainpool ECP curves...\n\n";
	bool pass = true; OID oid;

	while (!(oid = DL_GroupParameters_EC<ECP>::GetNextRecommendedParametersOID(oid)).GetValues().empty())
	{
		DL_GroupParameters_EC<ECP> params(oid);
		pass = params.Validate(GlobalRNG(), 2);

		// Test addition of identity element
		DL_GroupParameters_EC<ECP>::Element e1;
		e1 = params.GetCurve().Add(e1, e1);
		pass = params.IsIdentity(e1) && pass;

		// Test doubling of identity element
		DL_GroupParameters_EC<ECP>::Element e2;
		e2 = params.GetCurve().Double(e2);
		pass = params.IsIdentity(e2) && pass;

		// Test multiplication of identity element
		DL_GroupParameters_EC<ECP>::Element e3;
		Integer two = Integer::Two();
		e3 = params.GetCurve().Multiply(two, e3);
		pass = params.IsIdentity(e3) && pass;

		std::cout << (pass ? "passed" : "FAILED") << "    " << std::dec << params.GetCurve().GetField().MaxElementBitLength() << " bits\n";
	}

	std::cout << "\nECP validation suite running...\n\n";
	return ValidateECP_Agreement() && ValidateECP_Encrypt() && ValidateECP_NULLDigest_Encrypt() && ValidateECP_Sign() && pass;
}

bool ValidateEC2N()
{
	// Remove word recommend. Binary curves may not be recommended depending
	// on whom you ask. EC2N is more descriptive item in this case.
	std::cout << "\nTesting SEC 2 EC2N curves...\n\n";
	bool pass = true; OID oid;

#if 1	// TODO: turn this back on when I make EC2N faster for pentanomial basis
	while (!(oid = DL_GroupParameters_EC<EC2N>::GetNextRecommendedParametersOID(oid)).GetValues().empty())
	{
		DL_GroupParameters_EC<EC2N> params(oid);
		pass = params.Validate(GlobalRNG(), 2);

		// Test addition of identity element
		DL_GroupParameters_EC<EC2N>::Element e1;
		e1 = params.GetCurve().Add(e1, e1);
		pass = params.IsIdentity(e1) && pass;

		// Test doubling of identity element
		DL_GroupParameters_EC<EC2N>::Element e2;
		e2 = params.GetCurve().Double(e2);
		pass = params.IsIdentity(e2) && pass;

		// Test multiplication of identity element
		DL_GroupParameters_EC<EC2N>::Element e3;
		Integer two = Integer::Two();
		e3 = params.GetCurve().Multiply(two, e3);
		pass = params.IsIdentity(e3) && pass;

		std::cout << (pass ? "passed" : "FAILED") << "    " << params.GetCurve().GetField().MaxElementBitLength() << " bits\n";
	}
#endif

	std::cout << "\nEC2N validation suite running...\n\n";
	return ValidateEC2N_Agreement() && ValidateEC2N_Encrypt() && ValidateEC2N_Sign() && pass;
}

bool ValidateRSA()
{
	std::cout << "\nRSA validation suite running...\n\n";
	return ValidateRSA_Encrypt() && ValidateRSA_Sign();
}

bool ValidateLUC()
{
	std::cout << "\nLUC validation suite running...\n\n";
	return ValidateLUC_Encrypt() && ValidateLUC_Sign();
}

bool ValidateLUC_DL()
{
	// Prologue printed in each function
	return ValidateLUC_DL_Encrypt() && ValidateLUC_DL_Sign();
}

bool ValidateRabin()
{
	std::cout << "\nRabin validation suite running...\n\n";
	return ValidateRabin_Encrypt() && ValidateRabin_Sign();
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
