#ifndef CRYPTOPP_PKCSPAD_H
#define CRYPTOPP_PKCSPAD_H

#include "cryptlib.h"
#include "pubkey.h"

NAMESPACE_BEGIN(CryptoPP)

/// <a href="http://www.weidai.com/scan-mirror/ca.html#cem_PKCS1-1.5">EME-PKCS1-v1_5</a>
class PKCS_EncryptionPaddingScheme : public PK_PaddingAlgorithm
{
public:
	static const char * StaticAlgorithmName() {return "EME-PKCS1-v1_5";}

	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const;
	void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const;
	DecodingResult Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const;
};

/// <a href="http://www.weidai.com/scan-mirror/sig.html#sem_PKCS1-1.5">EMSA-PKCS1-v1_5</a>
class PKCS_SignaturePaddingScheme : public PK_PaddingAlgorithm
{
public:
	static const char * StaticAlgorithmName() {return "EMSA-PKCS1-v1_5";}

	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const;
	void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const;
	DecodingResult Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const;
};

/// <a href="http://www.weidai.com/scan-mirror/sig.html#sem_PKCS1-1.5">EMSA-PKCS1-v1_5</a>
template <class H>
class PKCS_DecoratedHashModule : public HashTransformationWithDefaultTruncation
{
public:
	static std::string StaticAlgorithmName() {return std::string("EMSA-PKCS1-v1_5(") + H::StaticAlgorithmName() + ")";}

	void Update(const byte *input, unsigned int length)
		{h.Update(input, length);}
	unsigned int DigestSize() const;
	void Final(byte *digest);
	void Restart() {h.Restart();}

private:
	H h;
};

//! PKCS #1 version 1.5, for use with RSAES and RSASSA
/*! The following hash functions are supported for signature: SHA, MD2, MD5, RIPEMD160, SHA256, SHA384, SHA512. */
struct PKCS1v15 : public SignatureStandard, public EncryptionStandard
{
	typedef PKCS_EncryptionPaddingScheme EncryptionPaddingAlgorithm;

	template <class H> struct SignaturePaddingAlgorithm {typedef PKCS_SignaturePaddingScheme type;};
	template <class H> struct DecoratedHashingAlgorithm {typedef PKCS_DecoratedHashModule<H> type;};
};

template<> struct CryptoStandardTraits<PKCS1v15> : public PKCS1v15 {};

template <class H> struct PKCS_DigestDecoration
{
	static const byte decoration[];
	static const unsigned int length;
};

// PKCS_DecoratedHashModule can be instantiated with the following
// classes as specified in PKCS#1 v2.0 and P1363a
class SHA;
class MD2;
class MD5;
class RIPEMD160;
class SHA256;
class SHA384;
class SHA512;

template <class H>
void PKCS_DecoratedHashModule<H>::Final(byte *digest)
{
	const unsigned int decorationLen = PKCS_DigestDecoration<H>::length;
	memcpy(digest, PKCS_DigestDecoration<H>::decoration, decorationLen);
	h.Final(digest+decorationLen);
}

template <class H>
unsigned int PKCS_DecoratedHashModule<H>::DigestSize() const
{
	return h.DigestSize() + PKCS_DigestDecoration<H>::length; // PKCS_DigestDecoration<H>::length;
}

NAMESPACE_END

#endif
