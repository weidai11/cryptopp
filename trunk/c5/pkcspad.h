#ifndef CRYPTOPP_PKCSPAD_H
#define CRYPTOPP_PKCSPAD_H

#include "cryptlib.h"
#include "pubkey.h"

NAMESPACE_BEGIN(CryptoPP)

//! <a href="http://www.weidai.com/scan-mirror/ca.html#cem_PKCS1-1.5">EME-PKCS1-v1_5</a>
class PKCS_EncryptionPaddingScheme : public PK_EncryptionMessageEncodingMethod
{
public:
	static const char * StaticAlgorithmName() {return "EME-PKCS1-v1_5";}

	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const;
	void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const;
	DecodingResult Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const;
};

template <class H> struct PKCS_DigestDecoration
{
	static const byte decoration[];
	static const unsigned int length;
};

//! <a href="http://www.weidai.com/scan-mirror/sig.html#sem_PKCS1-1.5">EMSA-PKCS1-v1_5</a>
class PKCS1v15_SignatureMessageEncodingMethod : public PK_DeterministicSignatureMessageEncodingMethod
{
public:
	static const char * StaticAlgorithmName() {return "EMSA-PKCS1-v1_5";}

	void ComputeMessageRepresentative(RandomNumberGenerator &rng, 
		const byte *recoverableMessage, unsigned int recoverableMessageLength,
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const;

	struct HashIdentifierLookup
	{
		template <class H> struct HashIdentifierLookup2
		{
			static HashIdentifier Lookup()
			{
				return HashIdentifier(PKCS_DigestDecoration<H>::decoration, PKCS_DigestDecoration<H>::length);
			}
		};
	};
};

//! PKCS #1 version 1.5, for use with RSAES and RSASS
/*! The following hash functions are supported for signature: SHA, MD2, MD5, RIPEMD160, SHA256, SHA384, SHA512. */
struct PKCS1v15 : public SignatureStandard, public EncryptionStandard
{
	typedef PKCS_EncryptionPaddingScheme EncryptionMessageEncodingMethod;
	typedef PKCS1v15_SignatureMessageEncodingMethod SignatureMessageEncodingMethod;
};

// PKCS_DecoratedHashModule can be instantiated with the following
// classes as specified in PKCS#1 v2.0 and P1363a
class SHA;
class MD2;
class MD5;
class RIPEMD160;
class Tiger;
class SHA256;
class SHA384;
class SHA512;

NAMESPACE_END

#endif
