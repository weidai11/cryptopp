// elgamal.h - originally written and placed in the public domain by Wei Dai

/// \file elgamal.h
/// \brief Classes and functions for ElGamal key agreement and encryption schemes

#ifndef CRYPTOPP_ELGAMAL_H
#define CRYPTOPP_ELGAMAL_H

#include "cryptlib.h"
#include "modexppc.h"
#include "integer.h"
#include "gfpcrypt.h"
#include "pubkey.h"
#include "dsa.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief ElGamal key agreement and encryption schemes base class
/// \since Crypto++ 1.0
class CRYPTOPP_NO_VTABLE ElGamalBase : public DL_KeyAgreementAlgorithm_DH<Integer, NoCofactorMultiplication>,
					public DL_KeyDerivationAlgorithm<Integer>,
					public DL_SymmetricEncryptionAlgorithm
{
public:
	virtual ~ElGamalBase() {}

	void Derive(const DL_GroupParameters<Integer> &groupParams, byte *derivedKey, size_t derivedLength, const Integer &agreedElement, const Integer &ephemeralPublicKey, const NameValuePairs &derivationParams) const
	{
		CRYPTOPP_UNUSED(groupParams), CRYPTOPP_UNUSED(ephemeralPublicKey), CRYPTOPP_UNUSED(derivationParams);
		agreedElement.Encode(derivedKey, derivedLength);
	}

	size_t GetSymmetricKeyLength(size_t plainTextLength) const
	{
		CRYPTOPP_UNUSED(plainTextLength);
		return GetGroupParameters().GetModulus().ByteCount();
	}

	size_t GetSymmetricCiphertextLength(size_t plainTextLength) const
	{
		unsigned int len = GetGroupParameters().GetModulus().ByteCount();
		if (plainTextLength <= GetMaxSymmetricPlaintextLength(len))
			return len;
		else
			return 0;
	}

	size_t GetMaxSymmetricPlaintextLength(size_t cipherTextLength) const
	{
		unsigned int len = GetGroupParameters().GetModulus().ByteCount();
		if (cipherTextLength == len)
			return STDMIN(255U, len-3);
		else
			return 0;
	}

	void SymmetricEncrypt(RandomNumberGenerator &rng, const byte *key, const byte *plainText, size_t plainTextLength, byte *cipherText, const NameValuePairs &parameters) const
	{
		CRYPTOPP_UNUSED(parameters);
		const Integer &p = GetGroupParameters().GetModulus();
		unsigned int modulusLen = p.ByteCount();

		SecByteBlock block(modulusLen-1);
		rng.GenerateBlock(block, modulusLen-2-plainTextLength);
		memcpy(block+modulusLen-2-plainTextLength, plainText, plainTextLength);
		block[modulusLen-2] = (byte)plainTextLength;

		a_times_b_mod_c(Integer(key, modulusLen), Integer(block, modulusLen-1), p).Encode(cipherText, modulusLen);
	}

	DecodingResult SymmetricDecrypt(const byte *key, const byte *cipherText, size_t cipherTextLength, byte *plainText, const NameValuePairs &parameters) const
	{
		CRYPTOPP_UNUSED(parameters);
		const Integer &p = GetGroupParameters().GetModulus();
		unsigned int modulusLen = p.ByteCount();

		if (cipherTextLength != modulusLen)
			return DecodingResult();

		Integer m = a_times_b_mod_c(Integer(cipherText, modulusLen), Integer(key, modulusLen).InverseMod(p), p);

		m.Encode(plainText, 1);
		unsigned int plainTextLength = plainText[0];
		if (plainTextLength > GetMaxSymmetricPlaintextLength(modulusLen))
			return DecodingResult();
		m >>= 8;
		m.Encode(plainText, plainTextLength);
		return DecodingResult(plainTextLength);
	}

	virtual const DL_GroupParameters_GFP & GetGroupParameters() const =0;
};

/// \brief ElGamal key agreement and encryption schemes default implementation
/// \since Crypto++ 1.0
template <class BASE, class SCHEME_OPTIONS, class KEY>
class ElGamalObjectImpl : public DL_ObjectImplBase<BASE, SCHEME_OPTIONS, KEY>, public ElGamalBase
{
public:
	virtual ~ElGamalObjectImpl() {}

	size_t FixedMaxPlaintextLength() const {return this->MaxPlaintextLength(FixedCiphertextLength());}
	size_t FixedCiphertextLength() const {return this->CiphertextLength(0);}

	const DL_GroupParameters_GFP & GetGroupParameters() const {return this->GetKey().GetGroupParameters();}

	DecodingResult FixedLengthDecrypt(RandomNumberGenerator &rng, const byte *cipherText, byte *plainText) const
		{return Decrypt(rng, cipherText, FixedCiphertextLength(), plainText);}

protected:
	const DL_KeyAgreementAlgorithm<Integer> & GetKeyAgreementAlgorithm() const {return *this;}
	const DL_KeyDerivationAlgorithm<Integer> & GetKeyDerivationAlgorithm() const {return *this;}
	const DL_SymmetricEncryptionAlgorithm & GetSymmetricEncryptionAlgorithm() const {return *this;}
};

/// \brief ElGamal key agreement and encryption schemes keys
/// \details The ElGamalKeys class used DL_PrivateKey_GFP_OldFormat and DL_PublicKey_GFP_OldFormat
///   for the PrivateKey and PublicKey typedef from about Crypto++ 1.0 through Crypto++ 5.6.5.
///   At Crypto++ 6.0 the serialization format was cutover to standard PKCS8 and X509 encodings.
/// \sa <A HREF="https://github.com/weidai11/cryptopp/commit/a5a684d92986e8e2">Commit a5a684d92986e8e2</A>
struct ElGamalKeys
{
	typedef DL_CryptoKeys_GFP::GroupParameters GroupParameters;
	typedef DL_CryptoKeys_GFP::PrivateKey PrivateKey;
	typedef DL_CryptoKeys_GFP::PublicKey PublicKey;
};

/// \brief ElGamal encryption scheme with non-standard padding
/// \since Crypto++ 1.0
struct ElGamal
{
	typedef DL_CryptoSchemeOptions<ElGamal, ElGamalKeys, int, int, int> SchemeOptions;

	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "ElgamalEnc/Crypto++Padding";}

	typedef SchemeOptions::GroupParameters GroupParameters;
	/// implements PK_Encryptor interface
	typedef PK_FinalTemplate<ElGamalObjectImpl<DL_EncryptorBase<Integer>, SchemeOptions, SchemeOptions::PublicKey> > Encryptor;
	/// implements PK_Decryptor interface
	typedef PK_FinalTemplate<ElGamalObjectImpl<DL_DecryptorBase<Integer>, SchemeOptions, SchemeOptions::PrivateKey> > Decryptor;
};

typedef ElGamal::Encryptor ElGamalEncryptor;
typedef ElGamal::Decryptor ElGamalDecryptor;

NAMESPACE_END

#endif
