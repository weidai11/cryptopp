#ifndef CRYPTOPP_ELGAMAL_H
#define CRYPTOPP_ELGAMAL_H

#include "modexppc.h"
#include "dsa.h"

NAMESPACE_BEGIN(CryptoPP)

class ElGamalBase : public DL_KeyAgreementAlgorithm_DH<Integer, NoCofactorMultiplication>, 
					public DL_KeyDerivationAlgorithm<Integer>, 
					public DL_SymmetricEncryptionAlgorithm
{
public:
	void Derive(const DL_GroupParameters<Integer> &params, byte *derivedKey, unsigned int derivedLength, const Integer &agreedElement, const Integer &ephemeralPublicKey) const
	{
		agreedElement.Encode(derivedKey, derivedLength);
	}

	unsigned int GetSymmetricKeyLength(unsigned int plainTextLength) const
	{
		return GetGroupParameters().GetModulus().ByteCount();
	}

	unsigned int GetSymmetricCiphertextLength(unsigned int plainTextLength) const
	{
		unsigned int len = GetGroupParameters().GetModulus().ByteCount();
		if (plainTextLength <= GetMaxSymmetricPlaintextLength(len))
			return len;
		else
			return 0;
	}

	unsigned int GetMaxSymmetricPlaintextLength(unsigned int cipherTextLength) const
	{
		unsigned int len = GetGroupParameters().GetModulus().ByteCount();
		if (cipherTextLength == len)
			return STDMIN(255U, len-3);
		else
			return 0;
	}

	void SymmetricEncrypt(RandomNumberGenerator &rng, const byte *key, const byte *plainText, unsigned int plainTextLength, byte *cipherText) const
	{
		const Integer &p = GetGroupParameters().GetModulus();
		unsigned int modulusLen = p.ByteCount();

		SecByteBlock block(modulusLen-1);
		rng.GenerateBlock(block, modulusLen-2-plainTextLength);
		memcpy(block+modulusLen-2-plainTextLength, plainText, plainTextLength);
		block[modulusLen-2] = plainTextLength;

		a_times_b_mod_c(Integer(key, modulusLen), Integer(block, modulusLen-1), p).Encode(cipherText, modulusLen);
	}

	DecodingResult SymmetricDecrypt(const byte *key, const byte *cipherText, unsigned int cipherTextLength, byte *plainText) const
	{
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

template <class BASE, class SCHEME_OPTIONS, class KEY>
class ElGamalObjectImpl : public DL_ObjectImplBase<BASE, SCHEME_OPTIONS, KEY>, public ElGamalBase
{
public:
	unsigned int FixedMaxPlaintextLength() const {return MaxPlaintextLength(FixedCiphertextLength());}
	unsigned int FixedCiphertextLength() const {return CiphertextLength(0);}

	const DL_GroupParameters_GFP & GetGroupParameters() const {return GetKey().GetGroupParameters();}

	DecodingResult FixedLengthDecrypt(const byte *cipherText, byte *plainText) const
		{return Decrypt(cipherText, FixedCiphertextLength(), plainText);}

protected:
	const DL_KeyAgreementAlgorithm<Integer> & GetKeyAgreementAlgorithm() const {return *this;}
	const DL_KeyDerivationAlgorithm<Integer> & GetKeyDerivationAlgorithm() const {return *this;}
	const DL_SymmetricEncryptionAlgorithm & GetSymmetricEncryptionAlgorithm() const {return *this;}
};

struct ElGamalKeys
{
	typedef DL_CryptoKeys_GFP::GroupParameters GroupParameters;
	typedef DL_PrivateKey_GFP_OldFormat<DL_CryptoKeys_GFP::PrivateKey> PrivateKey;
	typedef DL_PublicKey_GFP_OldFormat<DL_CryptoKeys_GFP::PublicKey> PublicKey;
};

//! ElGamal encryption scheme with non-standard padding
struct ElGamal
{
	typedef DL_CryptoSchemeOptions<ElGamal, ElGamalKeys, int, int, int> SchemeOptions;

	static const char * StaticAlgorithmName() {return "ElgamalEnc/Crypto++Padding";}

	class EncryptorImpl : public ElGamalObjectImpl<DL_EncryptorBase<Integer, PK_FixedLengthEncryptor>,  SchemeOptions, SchemeOptions::PublicKey>, public PublicKeyCopier<SchemeOptions>
	{
	public:
		void CopyKeyInto(SchemeOptions::PublicKey &key) const
			{key = GetKey();}
	};

	class DecryptorImpl : public ElGamalObjectImpl<DL_DecryptorBase<Integer, PK_FixedLengthDecryptor>, SchemeOptions, SchemeOptions::PrivateKey>, public PrivateKeyCopier<SchemeOptions>
	{
	public:
		void CopyKeyInto(SchemeOptions::PublicKey &key) const
			{GetKey().MakePublicKey(key);}
		void CopyKeyInto(SchemeOptions::PrivateKey &key) const
			{key = GetKey();}
	};

	typedef SchemeOptions::GroupParameters GroupParameters;
	//! implements PK_Encryptor interface
	typedef PK_FinalTemplate<EncryptorImpl> Encryptor;
	//! implements PK_Decryptor interface
	typedef PK_FinalTemplate<DecryptorImpl> Decryptor;
};

typedef ElGamal::Encryptor ElGamalEncryptor;
typedef ElGamal::Decryptor ElGamalDecryptor;

NAMESPACE_END

#endif
