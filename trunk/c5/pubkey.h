// pubkey.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_PUBKEY_H
#define CRYPTOPP_PUBKEY_H

/** \file

	This file contains helper classes/functions for implementing public key algorithms.

	The class hierachies in this .h file tend to look like this:
<pre>
                  x1
                 / \
                y1  z1
                 |  |
            x2<y1>  x2<z1>
                 |  |
                y2  z2
                 |  |
            x3<y2>  x3<z2>
                 |  |
                y3  z3
</pre>
	- x1, y1, z1 are abstract interface classes defined in cryptlib.h
	- x2, y2, z2 are implementations of the interfaces using "abstract policies", which
	  are pure virtual functions that should return interfaces to interchangeable algorithms.
	  These classes have "Base" suffixes.
	- x3, y3, z3 hold actual algorithms and implement those virtual functions.
	  These classes have "Impl" suffixes.

	The "TF_" prefix means an implementation using trapdoor functions on integers.
	The "DL_" prefix means an implementation using group operations (in groups where discrete log is hard).
*/

#include "integer.h"
#include "filters.h"
#include "eprecomp.h"
#include "fips140.h"
#include "argnames.h"
#include <memory>

// VC60 workaround: this macro is defined in shlobj.h and conflicts with a template parameter used in this file
#undef INTERFACE

NAMESPACE_BEGIN(CryptoPP)

Integer NR_EncodeDigest(unsigned int modulusBits, const byte *digest, unsigned int digestLen);
Integer DSA_EncodeDigest(unsigned int modulusBits, const byte *digest, unsigned int digestLen);

template <typename STANDARD>
struct CryptoStandardTraits
{
	typedef typename STANDARD::EncryptionPaddingAlgorithm EncryptionPaddingAlgorithm;

	template <class H> class SignaturePaddingAlgorithm {};
	template <class H> class DecoratedHashingAlgorithm {};
};

// ********************************************************

//! .
class TrapdoorFunctionBounds
{
public:
	virtual ~TrapdoorFunctionBounds() {}

	virtual Integer PreimageBound() const =0;
	virtual Integer ImageBound() const =0;
	virtual Integer MaxPreimage() const {return --PreimageBound();}
	virtual Integer MaxImage() const {return --ImageBound();}
};

//! .
class RandomizedTrapdoorFunction : public TrapdoorFunctionBounds
{
public:
	virtual Integer ApplyRandomizedFunction(RandomNumberGenerator &rng, const Integer &x) const =0;
};

//! .
class TrapdoorFunction : public RandomizedTrapdoorFunction
{
public:
	Integer ApplyRandomizedFunction(RandomNumberGenerator &rng, const Integer &x) const
		{return ApplyFunction(x);}

	virtual Integer ApplyFunction(const Integer &x) const =0;
};

//! .
class RandomizedTrapdoorFunctionInverse
{
public:
	virtual ~RandomizedTrapdoorFunctionInverse() {}

	virtual Integer CalculateRandomizedInverse(RandomNumberGenerator &rng, const Integer &x) const =0;
};

//! .
class TrapdoorFunctionInverse : public RandomizedTrapdoorFunctionInverse
{
public:
	virtual ~TrapdoorFunctionInverse() {}

	Integer CalculateRandomizedInverse(RandomNumberGenerator &rng, const Integer &x) const
		{return CalculateInverse(x);}

	virtual Integer CalculateInverse(const Integer &x) const =0;
};

// ********************************************************

//! .
class PK_PaddingAlgorithm
{
public:
	virtual ~PK_PaddingAlgorithm() {}

	virtual unsigned int MaxUnpaddedLength(unsigned int paddedLength) const =0;

	virtual void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedBitLength) const =0;

	virtual DecodingResult Unpad(const byte *padded, unsigned int paddedBitLength, byte *raw) const =0;

	virtual bool IsReversible() const {return true;}
};

//! .
class PK_NonreversiblePaddingAlgorithm : public PK_PaddingAlgorithm
{
	DecodingResult Unpad(const byte *padded, unsigned int paddedBitLength, byte *raw) const {assert(false); return DecodingResult();}
	bool IsReversible() const {return false;}
};

// ********************************************************

//! .
template <class TFI>
class TF_Base
{
protected:
	unsigned int PaddedBlockByteLength() const {return BitsToBytes(PaddedBlockBitLength());}

	virtual const TrapdoorFunctionBounds & GetTrapdoorFunctionBounds() const =0;
	virtual const PK_PaddingAlgorithm & GetPaddingAlgorithm() const =0;
	virtual unsigned int PaddedBlockBitLength() const =0;

	typedef TFI TrapdoorFunctionInterface;
	virtual const TrapdoorFunctionInterface & GetTrapdoorFunctionInterface() const =0;
};

// ********************************************************

//! .
template <class INTERFACE, class BASE>
class TF_CryptoSystemBase : public INTERFACE, protected BASE
{
public:
	unsigned int FixedMaxPlaintextLength() const {return GetPaddingAlgorithm().MaxUnpaddedLength(PaddedBlockBitLength());}
	unsigned int FixedCiphertextLength() const {return GetTrapdoorFunctionBounds().MaxImage().ByteCount();}

protected:
	unsigned int PaddedBlockBitLength() const {return GetTrapdoorFunctionBounds().PreimageBound().BitCount()-1;}
};

//! .
class TF_DecryptorBase : public TF_CryptoSystemBase<PK_FixedLengthDecryptor, TF_Base<TrapdoorFunctionInverse> >
{
public:
	DecodingResult FixedLengthDecrypt(const byte *cipherText, byte *plainText) const;
};

//! .
class TF_EncryptorBase : public TF_CryptoSystemBase<PK_FixedLengthEncryptor, TF_Base<RandomizedTrapdoorFunction> >
{
public:
	void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText) const;
};

// ********************************************************

//! .
class DigestSignatureSystem
{
public:
	virtual unsigned int MaxDigestLength() const =0;
	virtual unsigned int DigestSignatureLength() const =0;
};

//! .
class DigestSigner : virtual public DigestSignatureSystem, public PrivateKeyAlgorithm
{
public:
	virtual void SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLen, byte *signature) const =0;
};

//! .
class DigestVerifier : virtual public DigestSignatureSystem, public PublicKeyAlgorithm
{
public:
	virtual bool VerifyDigest(const byte *digest, unsigned int digestLen, const byte *sig) const =0;
};

// ********************************************************

//! .
template <class INTERFACE, class BASE>
class TF_DigestSignatureSystemBase : public INTERFACE, protected BASE
{
public:
	unsigned int MaxDigestLength() const {return GetPaddingAlgorithm().MaxUnpaddedLength(PaddedBlockBitLength());}
	unsigned int DigestSignatureLength() const {return GetTrapdoorFunctionBounds().MaxPreimage().ByteCount();}

protected:
	unsigned int PaddedBlockBitLength() const {return GetTrapdoorFunctionBounds().ImageBound().BitCount()-1;}
};

//! .
class TF_DigestSignerBase : public TF_DigestSignatureSystemBase<DigestSigner, TF_Base<RandomizedTrapdoorFunctionInverse> >
{
public:
	void SignDigest(RandomNumberGenerator &rng, const byte *message, unsigned int messageLength, byte *signature) const;
};

//! .
class TF_DigestVerifierBase : public TF_DigestSignatureSystemBase<DigestVerifier, TF_Base<TrapdoorFunction> >
{
public:
	bool VerifyDigest(const byte *digest, unsigned int digestLen, const byte *sig) const;
};

// ********************************************************

//! .
template <class T1, class T2, class T3>
struct TF_SchemeOptions
{
	typedef T1 AlgorithmInfo;
	typedef T2 Keys;
	typedef typename Keys::PrivateKey PrivateKey;
	typedef typename Keys::PublicKey PublicKey;
	typedef T3 PaddingAlgorithm;
};

//! .
template <class KEYS>
class PublicKeyCopier
{
public:
	virtual void CopyKeyInto(typename KEYS::PublicKey &key) const =0;
};

//! .
template <class KEYS>
class PrivateKeyCopier
{
public:
	virtual void CopyKeyInto(typename KEYS::PublicKey &key) const =0;
	virtual void CopyKeyInto(typename KEYS::PrivateKey &key) const =0;
};

//! .
template <class BASE, class SCHEME_OPTIONS, class KEY>
class TF_ObjectImplBase : public AlgorithmImpl<BASE, typename SCHEME_OPTIONS::AlgorithmInfo>
{
public:
	typedef SCHEME_OPTIONS SchemeOptions;
	typedef KEY KeyClass;

	PublicKey & AccessPublicKey() {return AccessKey();}
	const PublicKey & GetPublicKey() const {return GetKey();}

	PrivateKey & AccessPrivateKey() {return AccessKey();}
	const PrivateKey & GetPrivateKey() const {return GetKey();}

	virtual const KeyClass & GetKey() const =0;
	virtual KeyClass & AccessKey() =0;

	const KeyClass & GetTrapdoorFunction() const {return GetKey();}

protected:
	const PK_PaddingAlgorithm & GetPaddingAlgorithm() const {static typename SCHEME_OPTIONS::PaddingAlgorithm paddingScheme; return paddingScheme;}
	const TrapdoorFunctionBounds & GetTrapdoorFunctionBounds() const {return GetKey();}
	const typename BASE::TrapdoorFunctionInterface & GetTrapdoorFunctionInterface() const {return GetKey();}
};

//! .
template <class BASE, class SCHEME_OPTIONS, class KEY>
class TF_ObjectImplExtRef : public TF_ObjectImplBase<BASE, SCHEME_OPTIONS, KEY>
{
public:
	TF_ObjectImplExtRef(const KEY *pKey = NULL) : m_pKey(pKey) {}
	void SetKeyPtr(const KEY *pKey) {m_pKey = pKey;}

	const KEY & GetKey() const {return *m_pKey;}
	KEY & AccessKey() {throw NotImplemented("TF_ObjectImplExtRef: cannot modify refererenced key");}

	void CopyKeyInto(typename SCHEME_OPTIONS::PrivateKey &key) const {assert(false);}
	void CopyKeyInto(typename SCHEME_OPTIONS::PublicKey &key) const {assert(false);}

private:
	const KEY * m_pKey;
};

//! .
template <class BASE, class SCHEME_OPTIONS, class KEY>
class TF_ObjectImpl : public TF_ObjectImplBase<BASE, SCHEME_OPTIONS, KEY>
{
public:
	const KEY & GetKey() const {return m_trapdoorFunction;}
	KEY & AccessKey() {return m_trapdoorFunction;}

private:
	KEY m_trapdoorFunction;
};

//! .
template <class BASE, class SCHEME_OPTIONS>
class TF_PublicObjectImpl : public TF_ObjectImpl<BASE, SCHEME_OPTIONS, typename SCHEME_OPTIONS::PublicKey>, public PublicKeyCopier<SCHEME_OPTIONS>
{
public:
	void CopyKeyInto(typename SCHEME_OPTIONS::PublicKey &key) const {key = GetKey();}
};

//! .
template <class BASE, class SCHEME_OPTIONS>
class TF_PrivateObjectImpl : public TF_ObjectImpl<BASE, SCHEME_OPTIONS, typename SCHEME_OPTIONS::PrivateKey>, public PrivateKeyCopier<SCHEME_OPTIONS>
{
public:
	void CopyKeyInto(typename SCHEME_OPTIONS::PrivateKey &key) const {key = GetKey();}
	void CopyKeyInto(typename SCHEME_OPTIONS::PublicKey &key) const {key = GetKey();}
};

//! .
template <class SCHEME_OPTIONS>
class TF_DecryptorImpl : public TF_PrivateObjectImpl<TF_DecryptorBase, SCHEME_OPTIONS>
{
};

//! .
template <class SCHEME_OPTIONS>
class TF_EncryptorImpl : public TF_PublicObjectImpl<TF_EncryptorBase, SCHEME_OPTIONS>
{
};

//! .
template <class SCHEME_OPTIONS>
class TF_DigestSignerImpl : public TF_PrivateObjectImpl<TF_DigestSignerBase, SCHEME_OPTIONS>
{
};

//! .
template <class SCHEME_OPTIONS>
class TF_DigestVerifierImpl : public TF_PublicObjectImpl<TF_DigestVerifierBase, SCHEME_OPTIONS>
{
};

// ********************************************************

//! .
template <class H>
class P1363_MGF1
{
public:
	static std::string StaticAlgorithmName() {return std::string("MGF1(") + H::StaticAlgorithmName() + ")";}
	static void GenerateAndMask(byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength);
};

template <class H>
void P1363_MGF1<H>::GenerateAndMask(byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength)
{
	H h;
	ArrayXorSink *sink;
	HashFilter filter(h, sink = new ArrayXorSink(output, outputLength));
	word32 counter = 0;
	while (sink->AvailableSize() > 0)
	{
		filter.Put(input, inputLength);
		filter.PutWord32(counter++);
		filter.MessageEnd();
	}
}

// ********************************************************

//! .
template <class H>
class P1363_KDF2
{
public:
	static void DeriveKey(byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength);
};

template <class H>
void P1363_KDF2<H>::DeriveKey(byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength)
{
	H h;
	ArraySink *sink;
	HashFilter filter(h, sink = new ArraySink(output, outputLength));
	word32 counter = 1;
	while (sink->AvailableSize() > 0)
	{
		filter.Put(input, inputLength);
		filter.PutWord32(counter++);
		filter.MessageEnd();
	}
}

// ********************************************************

//! .
template <class H, class INTERFACE, class DS_INTERFACE>
class PK_SignatureSchemeBase : public INTERFACE
{
public:
	unsigned int SignatureLength() const {return GetDigestSignatureSchemeInterface().DigestSignatureLength();}
	HashTransformation * NewMessageAccumulator() const {return new H;}

	virtual const DS_INTERFACE & GetDigestSignatureSchemeInterface() const =0;
};

//! .
template <class H>
class PK_SignerBase : public PK_SignatureSchemeBase<H, PK_Signer, DigestSigner>
{
public:
	void SignAndRestart(RandomNumberGenerator &rng, HashTransformation &messageAccumulator, byte *signature) const;
};

//! .
template <class H>
class PK_VerifierBase : public PK_SignatureSchemeBase<H, PK_Verifier, DigestVerifier>
{
public:
	bool VerifyAndRestart(HashTransformation &messageAccumulator, const byte *sig) const;
};

template <class H>
void PK_SignerBase<H>::SignAndRestart(RandomNumberGenerator &rng, HashTransformation &messageAccumulator, byte *signature) const
{
	if (messageAccumulator.DigestSize() > GetDigestSignatureSchemeInterface().MaxDigestLength())
		throw PK_Signer::KeyTooShort();
	SecByteBlock digest(messageAccumulator.DigestSize());
	messageAccumulator.Final(digest);
	GetDigestSignatureSchemeInterface().SignDigest(rng, digest, digest.size(), signature);
}

template <class H>
bool PK_VerifierBase<H>::VerifyAndRestart(HashTransformation &messageAccumulator, const byte *sig) const
{
	SecByteBlock digest(messageAccumulator.DigestSize());
	messageAccumulator.Final(digest);
	return GetDigestSignatureSchemeInterface().VerifyDigest(digest, digest.size(), sig);
}

//! .
template <class BASE, class DS>
class PK_SignatureSchemeImpl : public BASE
{
public:
	typedef typename DS::KeyClass KeyClass;

	// PublicKeyAlgorithm or PrivateKeyAlgorithm
	std::string AlgorithmName() const {return m_ds.AlgorithmName();}

	PrivateKey & AccessPrivateKey() {return m_ds.AccessPrivateKey();}
	const PrivateKey & GetPrivateKey() const {return m_ds.GetPrivateKey();}

	PublicKey & AccessPublicKey() {return m_ds.AccessPublicKey();}
	const PublicKey & GetPublicKey() const {return m_ds.GetPublicKey();}

	KeyClass & AccessKey() {return m_ds.AccessKey();}
	const KeyClass & GetKey() const {return m_ds.GetKey();}

	const KeyClass & GetTrapdoorFunction() const {return m_ds.GetTrapdoorFunction();}

	DS & AccessDigestSignatureScheme() {return m_ds;}
	const DS & GetDigestSignatureScheme() const {return m_ds;}

protected:
	DS m_ds;
};

//! .
template <class DS, class H>
class PK_SignerImpl : public PK_SignatureSchemeImpl<PK_SignerBase<H>, DS>, public PrivateKeyCopier<typename DS::SchemeOptions>
{
	const DigestSigner & GetDigestSignatureSchemeInterface() const {return m_ds;}
public:
	// PrivateKeyCopier
	void CopyKeyInto(typename DS::SchemeOptions::PublicKey &key) const
		{m_ds.CopyKeyInto(key);}
	void CopyKeyInto(typename DS::SchemeOptions::PrivateKey &key) const
		{m_ds.CopyKeyInto(key);}
};

//! .
template <class DS, class H>
class PK_VerifierImpl : public PK_SignatureSchemeImpl<PK_VerifierBase<H>, DS>, public PublicKeyCopier<typename DS::SchemeOptions>
{
	const DigestVerifier & GetDigestSignatureSchemeInterface() const {return m_ds;}
public:
	// PublicKeyCopier
	void CopyKeyInto(typename DS::SchemeOptions::PublicKey &key) const
		{m_ds.CopyKeyInto(key);}
};

// ********************************************************

//! .
class SignatureEncodingMethodWithRecovery : public HashTransformationWithDefaultTruncation
{
public:
	void Final(byte *digest) {}
	virtual void Encode(RandomNumberGenerator &rng, byte *representative) =0;
	virtual bool Verify(const byte *representative) =0;
	virtual DecodingResult Decode(byte *message) =0;
	virtual unsigned int MaximumRecoverableLength() const =0;
};

//! .
template <class H>
class SignatureSystemWithRecoveryBaseTemplate : virtual public PK_SignatureSchemeWithRecovery
{
public:
	unsigned int SignatureLength() const {return GetTrapdoorFunctionBounds().MaxPreimage().ByteCount();}
	HashTransformation * NewMessageAccumulator() const {return new H(PaddedBlockBitLength());}
	unsigned int MaximumRecoverableLength() const {return H::MaximumRecoverableLength(PaddedBlockBitLength());}
	bool AllowLeftoverMessage() const {return H::AllowLeftoverMessage();}

protected:
	unsigned int PaddedBlockByteLength() const {return BitsToBytes(PaddedBlockBitLength());}
	unsigned int PaddedBlockBitLength() const {return GetTrapdoorFunctionBounds().ImageBound().BitCount()-1;}

	virtual const TrapdoorFunctionBounds & GetTrapdoorFunctionBounds() const =0;
};

//! .
template <class TF, class H>
class SignerWithRecoveryTemplate : virtual public SignatureSystemWithRecoveryBaseTemplate<H>, virtual public PK_SignerWithRecovery, public TF
{
public:
	typedef TF KeyClass;

	const KeyClass & GetKey() const {return *this;}
	KeyClass & AccessKey() {return *this;}

	PrivateKey & AccessPrivateKey() {return *this;}

	SignerWithRecoveryTemplate() {}
	void SignAndRestart(RandomNumberGenerator &rng, HashTransformation &messageAccumulator, byte *signature) const;
	const TrapdoorFunctionBounds & GetTrapdoorFunctionBounds() const {return *this;}
};

//! .
template <class TF, class H>
class VerifierWithRecoveryTemplate : virtual public SignatureSystemWithRecoveryBaseTemplate<H>, virtual public PK_VerifierWithRecovery, public TF
{
public:
	typedef TF KeyClass;

	const KeyClass & GetKey() const {return *this;}
	KeyClass & AccessKey() {return *this;}

	PublicKey & AccessPublicKey() {return *this;}

	VerifierWithRecoveryTemplate() {}
	bool VerifyAndRestart(HashTransformation &messageAccumulator, const byte *sig) const;
	bool SignatureUpfrontForRecovery() const {return true;}
	HashTransformation * NewRecoveryAccumulator(const byte *signature) const;
	DecodingResult Recover(byte *recoveredMessage, HashTransformation *recoveryAccumulator, const byte *signature) const;
	const TrapdoorFunctionBounds & GetTrapdoorFunctionBounds() const {return *this;}
};

template <class TF, class H>
void SignerWithRecoveryTemplate<TF, H>::SignAndRestart(RandomNumberGenerator &rng, HashTransformation &messageAccumulator, byte *signature) const
{
	H &ma = static_cast<H&>(messageAccumulator);
	if (ma.MaximumRecoverableLength() == 0)
		throw KeyTooShort();
	SecByteBlock representative(PaddedBlockByteLength());
	ma.Encode(rng, representative);
	CalculateInverse(Integer(representative, representative.size())).Encode(signature, SignatureLength());
}

template <class TF, class H>
bool VerifierWithRecoveryTemplate<TF, H>::VerifyAndRestart(HashTransformation &messageAccumulator, const byte *signature) const
{
	SecByteBlock representative(PaddedBlockByteLength());
	ApplyFunction(Integer(signature, SignatureLength())).Encode(representative, representative.size());
	return messageAccumulator.Verify(representative);
}

template <class TF, class H>
HashTransformation * VerifierWithRecoveryTemplate<TF, H>::NewRecoveryAccumulator(const byte *signature) const
{
	SecByteBlock representative(PaddedBlockByteLength());
	ApplyFunction(Integer(signature, SignatureLength())).Encode(representative, representative.size());
	return new H(representative, PaddedBlockBitLength());
}

template <class TF, class H>
DecodingResult VerifierWithRecoveryTemplate<TF, H>::Recover(byte *recoveredMessage, HashTransformation *recoveryAccumulator, const byte *signature) const
{
	std::auto_ptr<H> ma(static_cast<H*>(recoveryAccumulator));
	return ma->Decode(recoveredMessage);
}

// ********************************************************

// to be thrown by DecodeElement and AgreeWithStaticPrivateKey
class DL_BadElement : public InvalidDataFormat
{
public:
	DL_BadElement() : InvalidDataFormat("CryptoPP: invalid group element") {}
};

//! .
template <class T>
class DL_GroupParameters : public CryptoParameters
{
	typedef DL_GroupParameters<T> ThisClass;
	
public:
	typedef T Element;

	DL_GroupParameters() : m_validationLevel(0) {}

	// CryptoMaterial
	bool Validate(RandomNumberGenerator &rng, unsigned int level) const
	{
		if (!GetBasePrecomputation().IsInitialized())
			return false;

		if (m_validationLevel > level)
			return true;

		bool pass = ValidateGroup(rng, level);
		pass = pass && ValidateElement(level, GetSubgroupGenerator(), &GetBasePrecomputation());

		m_validationLevel = pass ? level+1 : 0;

		return pass;
	}

	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		return GetValueHelper(this, name, valueType, pValue)
			CRYPTOPP_GET_FUNCTION_ENTRY(SubgroupOrder)
			CRYPTOPP_GET_FUNCTION_ENTRY(SubgroupGenerator)
			;
	}

	bool SupportsPrecomputation() const {return true;}

	void Precompute(unsigned int precomputationStorage=16)
	{
		AccessBasePrecomputation().Precompute(GetGroupPrecomputation(), GetSubgroupOrder().BitCount(), precomputationStorage);
	}

	void LoadPrecomputation(BufferedTransformation &storedPrecomputation)
	{
		AccessBasePrecomputation().Load(GetGroupPrecomputation(), storedPrecomputation);
		m_validationLevel = 0;
	}

	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const
	{
		GetBasePrecomputation().Save(GetGroupPrecomputation(), storedPrecomputation);
	}

	// non-inherited
	virtual const Element & GetSubgroupGenerator() const {return GetBasePrecomputation().GetBase(GetGroupPrecomputation());}
	virtual void SetSubgroupGenerator(const Element &base) {AccessBasePrecomputation().SetBase(GetGroupPrecomputation(), base);}
	virtual Element ExponentiateBase(const Integer &exponent) const
	{
		return GetBasePrecomputation().Exponentiate(GetGroupPrecomputation(), exponent);
	}
	virtual Element ExponentiateElement(const Element &base, const Integer &exponent) const
	{
		Element result;
		SimultaneousExponentiate(&result, base, &exponent, 1);
		return result;
	}

	virtual const DL_GroupPrecomputation<Element> & GetGroupPrecomputation() const =0;
	virtual const DL_FixedBasePrecomputation<Element> & GetBasePrecomputation() const =0;
	virtual DL_FixedBasePrecomputation<Element> & AccessBasePrecomputation() =0;
	virtual const Integer & GetSubgroupOrder() const =0;	// order of subgroup generated by base element
	virtual Integer GetMaxExponent() const =0;
	virtual Integer GetGroupOrder() const {return GetSubgroupOrder()*GetCofactor();}	// one of these two needs to be overriden
	virtual Integer GetCofactor() const {return GetGroupOrder()/GetSubgroupOrder();}
	virtual unsigned int GetEncodedElementSize(bool reversible) const =0;
	virtual void EncodeElement(bool reversible, const Element &element, byte *encoded) const =0;
	virtual Element DecodeElement(const byte *encoded, bool checkForGroupMembership) const =0;
	virtual Integer ConvertElementToInteger(const Element &element) const =0;
	virtual bool ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const =0;
	virtual bool ValidateElement(unsigned int level, const Element &element, const DL_FixedBasePrecomputation<Element> *precomp) const =0;
	virtual bool FastSubgroupCheckAvailable() const =0;
	virtual bool IsIdentity(const Element &element) const =0;
	virtual void SimultaneousExponentiate(Element *results, const Element &base, const Integer *exponents, unsigned int exponentsCount) const =0;

protected:
	void ParametersChanged() {m_validationLevel = 0;}

private:
	mutable unsigned int m_validationLevel;
};

//! .
template <class GROUP_PRECOMP, class BASE_PRECOMP = DL_FixedBasePrecomputationImpl<typename GROUP_PRECOMP::Element>, class BASE = DL_GroupParameters<typename GROUP_PRECOMP::Element> >
class DL_GroupParametersImpl : public BASE
{
public:
	typedef GROUP_PRECOMP GroupPrecomputation;
	typedef typename GROUP_PRECOMP::Element Element;
	typedef BASE_PRECOMP BasePrecomputation;
	
	const DL_GroupPrecomputation<Element> & GetGroupPrecomputation() const {return m_groupPrecomputation;}
	const DL_FixedBasePrecomputation<Element> & GetBasePrecomputation() const {return m_gpc;}
	DL_FixedBasePrecomputation<Element> & AccessBasePrecomputation() {return m_gpc;}

protected:
	GROUP_PRECOMP m_groupPrecomputation;
	BASE_PRECOMP m_gpc;
};

//! .
template <class T>
class DL_Key
{
public:
	virtual const DL_GroupParameters<T> & GetAbstractGroupParameters() const =0;
	virtual DL_GroupParameters<T> & AccessAbstractGroupParameters() =0;
};

//! .
template <class T>
class DL_PublicKey : public DL_Key<T>
{
	typedef DL_PublicKey<T> ThisClass;

public:
	typedef T Element;

	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		return GetAbstractGroupParameters().GetVoidValue(name, valueType, pValue)
			|| GetValueHelper(this, name, valueType, pValue)
				CRYPTOPP_GET_FUNCTION_ENTRY(PublicElement);
	}

	void AssignFrom(const NameValuePairs &source);
	
	// non-inherited
	virtual const Element & GetPublicElement() const {return GetPublicPrecomputation().GetBase(GetAbstractGroupParameters().GetGroupPrecomputation());}
	virtual void SetPublicElement(const Element &y) {AccessPublicPrecomputation().SetBase(GetAbstractGroupParameters().GetGroupPrecomputation(), y);}
	virtual Element ExponentiatePublicElement(const Integer &exponent) const
	{
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		return GetPublicPrecomputation().Exponentiate(params.GetGroupPrecomputation(), exponent);
	}
	virtual Element CascadeExponentiateBaseAndPublicElement(const Integer &baseExp, const Integer &publicExp) const
	{
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		return params.GetBasePrecomputation().CascadeExponentiate(params.GetGroupPrecomputation(), baseExp, GetPublicPrecomputation(), publicExp);
	}

	virtual const DL_FixedBasePrecomputation<T> & GetPublicPrecomputation() const =0;
	virtual DL_FixedBasePrecomputation<T> & AccessPublicPrecomputation() =0;
};

//! .
template <class T>
class DL_PrivateKey : public DL_Key<T>
{
	typedef DL_PrivateKey<T> ThisClass;

public:
	typedef T Element;

	void MakePublicKey(DL_PublicKey<T> &pub) const
	{
		pub.AccessAbstractGroupParameters().AssignFrom(GetAbstractGroupParameters());
		pub.SetPublicElement(GetAbstractGroupParameters().ExponentiateBase(GetPrivateExponent()));
	}

	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		return GetAbstractGroupParameters().GetVoidValue(name, valueType, pValue)
			|| GetValueHelper(this, name, valueType, pValue)
				CRYPTOPP_GET_FUNCTION_ENTRY(PrivateExponent);
	}

	void AssignFrom(const NameValuePairs &source)
	{
		AccessAbstractGroupParameters().AssignFrom(source);
		AssignFromHelper(this, source)
			CRYPTOPP_SET_FUNCTION_ENTRY(PrivateExponent);
	}

	virtual const Integer & GetPrivateExponent() const =0;
	virtual void SetPrivateExponent(const Integer &x) =0;
};

template <class T>
void DL_PublicKey<T>::AssignFrom(const NameValuePairs &source)
{
	DL_PrivateKey<T> *pPrivateKey = NULL;
	if (source.GetThisPointer(pPrivateKey))
		pPrivateKey->MakePublicKey(*this);
	else
	{
		AccessAbstractGroupParameters().AssignFrom(source);
		AssignFromHelper(this, source)
			CRYPTOPP_SET_FUNCTION_ENTRY(PublicElement);
	}
}

class OID;

//! .
template <class PK, class GP>
class DL_KeyImpl : public PK
{
public:
	typedef GP GroupParameters;

	OID GetAlgorithmID() const {return GetGroupParameters().GetAlgorithmID();}
//	void BERDecode(BufferedTransformation &bt)
//		{PK::BERDecode(bt);}
//	void DEREncode(BufferedTransformation &bt) const
//		{PK::DEREncode(bt);}
	bool BERDecodeAlgorithmParameters(BufferedTransformation &bt)
		{AccessGroupParameters().BERDecode(bt); return true;}
	bool DEREncodeAlgorithmParameters(BufferedTransformation &bt) const
		{GetGroupParameters().DEREncode(bt); return true;}

	const GP & GetGroupParameters() const {return m_groupParameters;}
	GP & AccessGroupParameters() {return m_groupParameters;}

private:
	GP m_groupParameters;
};

class X509PublicKey;
class PKCS8PrivateKey;

//! .
template <class GP>
class DL_PrivateKeyImpl : public DL_PrivateKey<CPP_TYPENAME GP::Element>, public DL_KeyImpl<PKCS8PrivateKey, GP>
{
public:
	typedef typename GP::Element Element;

	// GeneratableCryptoMaterial
	bool Validate(RandomNumberGenerator &rng, unsigned int level) const
	{
		bool pass = GetAbstractGroupParameters().Validate(rng, level);

		const Integer &q = GetAbstractGroupParameters().GetSubgroupOrder();
		const Integer &x = GetPrivateExponent();

		pass = pass && x.IsPositive() && x < q;
		if (level >= 1)
			pass = pass && Integer::Gcd(x, q) == Integer::One();
		return pass;
	}

	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		return GetValueHelper<DL_PrivateKey<Element> >(this, name, valueType, pValue).Assignable();
	}

	void AssignFrom(const NameValuePairs &source)
	{
		AssignFromHelper<DL_PrivateKey<Element> >(this, source);
	}

	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params)
	{
		if (!params.GetThisObject(AccessGroupParameters()))
			AccessGroupParameters().GenerateRandom(rng, params);
//		std::pair<const byte *, int> seed;
		Integer x(rng, Integer::One(), GetAbstractGroupParameters().GetMaxExponent());
//			Integer::ANY, Integer::Zero(), Integer::One(),
//			params.GetValue("DeterministicKeyGenerationSeed", seed) ? &seed : NULL);
		SetPrivateExponent(x);
	}

	bool SupportsPrecomputation() const {return true;}

	void Precompute(unsigned int precomputationStorage=16)
		{AccessAbstractGroupParameters().Precompute(precomputationStorage);}

	void LoadPrecomputation(BufferedTransformation &storedPrecomputation)
		{AccessAbstractGroupParameters().LoadPrecomputation(storedPrecomputation);}

	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const
		{GetAbstractGroupParameters().SavePrecomputation(storedPrecomputation);}

	// DL_Key
	const DL_GroupParameters<Element> & GetAbstractGroupParameters() const {return GetGroupParameters();}
	DL_GroupParameters<Element> & AccessAbstractGroupParameters() {return AccessGroupParameters();}

	// DL_PrivateKey
	const Integer & GetPrivateExponent() const {return m_x;}
	void SetPrivateExponent(const Integer &x) {m_x = x;}

	// PKCS8PrivateKey
	void BERDecodeKey(BufferedTransformation &bt)
		{m_x.BERDecode(bt);}
	void DEREncodeKey(BufferedTransformation &bt) const
		{m_x.DEREncode(bt);}

private:
	Integer m_x;
};

//! .
template <class BASE, class SIGNATURE_SCHEME>
class DL_PrivateKey_WithSignaturePairwiseConsistencyTest : public BASE
{
public:
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params)
	{
		BASE::GenerateRandom(rng, params);

		if (FIPS_140_2_ComplianceEnabled())
		{
			typename SIGNATURE_SCHEME::Signer signer(*this);
			typename SIGNATURE_SCHEME::Verifier verifier(signer);
			SignaturePairwiseConsistencyTest(signer, verifier);
		}
	}
};

//! .
template <class GP>
class DL_PublicKeyImpl : public DL_PublicKey<typename GP::Element>, public DL_KeyImpl<X509PublicKey, GP>
{
public:
	typedef typename GP::Element Element;

	// CryptoMaterial
	bool Validate(RandomNumberGenerator &rng, unsigned int level) const
	{
		bool pass = GetAbstractGroupParameters().Validate(rng, level);
		pass = pass && GetAbstractGroupParameters().ValidateElement(level, GetPublicElement(), &GetPublicPrecomputation());
		return pass;
	}

	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		return GetValueHelper<DL_PublicKey<Element> >(this, name, valueType, pValue).Assignable();
	}

	void AssignFrom(const NameValuePairs &source)
	{
		AssignFromHelper<DL_PublicKey<Element> >(this, source);
	}

	bool SupportsPrecomputation() const {return true;}

	void Precompute(unsigned int precomputationStorage=16)
	{
		AccessAbstractGroupParameters().Precompute(precomputationStorage);
		AccessPublicPrecomputation().Precompute(GetAbstractGroupParameters().GetGroupPrecomputation(), GetAbstractGroupParameters().GetSubgroupOrder().BitCount(), precomputationStorage);
	}

	void LoadPrecomputation(BufferedTransformation &storedPrecomputation)
	{
		AccessAbstractGroupParameters().LoadPrecomputation(storedPrecomputation);
		AccessPublicPrecomputation().Load(GetAbstractGroupParameters().GetGroupPrecomputation(), storedPrecomputation);
	}

	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const
	{
		GetAbstractGroupParameters().SavePrecomputation(storedPrecomputation);
		GetPublicPrecomputation().Save(GetAbstractGroupParameters().GetGroupPrecomputation(), storedPrecomputation);
	}

	// DL_Key
	const DL_GroupParameters<Element> & GetAbstractGroupParameters() const {return GetGroupParameters();}
	DL_GroupParameters<Element> & AccessAbstractGroupParameters() {return AccessGroupParameters();}

	// DL_PublicKey
	const DL_FixedBasePrecomputation<Element> & GetPublicPrecomputation() const {return m_ypc;}
	DL_FixedBasePrecomputation<Element> & AccessPublicPrecomputation() {return m_ypc;}

	// non-inherited
	bool operator==(const DL_PublicKeyImpl<GP> &rhs) const
		{return GetGroupParameters() == rhs.GetGroupParameters() && GetPublicElement() == rhs.GetPublicElement();}

private:
	typename GP::BasePrecomputation m_ypc;
};

//! .
template <class T>
class DL_ElgamalLikeSignatureAlgorithm
{
public:
	virtual Integer EncodeDigest(unsigned int modulusBits, const byte *digest, unsigned int digestLength) const =0;
	virtual bool Sign(const DL_GroupParameters<T> &params, const Integer &privateKey, const Integer &k, const Integer &e, Integer &r, Integer &s) const =0;
	virtual bool Verify(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &e, const Integer &r, const Integer &s) const =0;
	virtual unsigned int RLen(const DL_GroupParameters<T> &params) const
		{return params.GetSubgroupOrder().ByteCount();}
	virtual unsigned int SLen(const DL_GroupParameters<T> &params) const
		{return params.GetSubgroupOrder().ByteCount();}
};

//! .
template <class T>
class DL_KeyAgreementAlgorithm
{
public:
	typedef T Element;

	virtual Element AgreeWithEphemeralPrivateKey(const DL_GroupParameters<Element> &params, const DL_FixedBasePrecomputation<Element> &publicPrecomputation, const Integer &privateExponent) const =0;
	virtual Element AgreeWithStaticPrivateKey(const DL_GroupParameters<Element> &params, const Element &publicElement, bool validateOtherPublicKey, const Integer &privateExponent) const =0;
};

//! .
template <class T>
class DL_KeyDerivationAlgorithm
{
public:
	virtual void Derive(const DL_GroupParameters<T> &params, byte *derivedKey, unsigned int derivedLength, const T &agreedElement, const T &ephemeralPublicKey) const =0;
};

//! .
class DL_SymmetricEncryptionAlgorithm
{
public:
	virtual unsigned int GetSymmetricKeyLength(unsigned int plainTextLength) const =0;
	virtual unsigned int GetSymmetricCiphertextLength(unsigned int plainTextLength) const =0;
	virtual unsigned int GetMaxSymmetricPlaintextLength(unsigned int cipherTextLength) const =0;
	virtual void SymmetricEncrypt(RandomNumberGenerator &rng, const byte *key, const byte *plainText, unsigned int plainTextLength, byte *cipherText) const =0;
	virtual DecodingResult SymmetricDecrypt(const byte *key, const byte *cipherText, unsigned int cipherTextLength, byte *plainText) const =0;
};

//! .
template <class KI>
class DL_Base
{
protected:
	typedef KI KeyInterface;
	typedef typename KI::Element Element;

	const DL_GroupParameters<Element> & GetAbstractGroupParameters() const {return GetKeyInterface().GetAbstractGroupParameters();}
	DL_GroupParameters<Element> & AccessAbstractGroupParameters() {return AccessKeyInterface().AccessAbstractGroupParameters();}

	virtual KeyInterface & AccessKeyInterface() =0;
	virtual const KeyInterface & GetKeyInterface() const =0;
};

//! .
template <class INTERFACE, class KEY_INTERFACE>
class DL_DigestSignatureSystemBase : public INTERFACE, public DL_Base<KEY_INTERFACE>
{
public:
	unsigned int MaxDigestLength() const {return UINT_MAX;}
	unsigned int DigestSignatureLength() const
	{
		return GetSignatureAlgorithm().RLen(GetAbstractGroupParameters())
			+ GetSignatureAlgorithm().SLen(GetAbstractGroupParameters());
	}

protected:
	virtual const DL_ElgamalLikeSignatureAlgorithm<CPP_TYPENAME KEY_INTERFACE::Element> & GetSignatureAlgorithm() const =0;
};

//! .
template <class T>
class DL_DigestSignerBase : public DL_DigestSignatureSystemBase<DigestSigner, DL_PrivateKey<T> >
{
public:
	// for validation testing
	void RawSign(const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		const DL_PrivateKey<T> &key = GetKeyInterface();

		alg.Sign(params, key.GetPrivateExponent(), k, e, r, s);
	}

	void SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLength, byte *signature) const
	{
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		const DL_PrivateKey<T> &key = GetKeyInterface();

		GetMaterial().DoQuickSanityCheck();
		const Integer &q = params.GetSubgroupOrder();
		Integer e = alg.EncodeDigest(q.BitCount(), digest, digestLength);
		Integer k, r, s;

		do {k.Randomize(rng, 1, params.GetSubgroupOrder()-1);}
		while (!alg.Sign(params, key.GetPrivateExponent(), k, e, r, s));

		unsigned int rLen = alg.RLen(params);
		r.Encode(signature, rLen);
		s.Encode(signature+rLen, alg.SLen(params));
	}
};

//! .
template <class T>
class DL_DigestVerifierBase : public DL_DigestSignatureSystemBase<DigestVerifier, DL_PublicKey<T> >
{
public:
	bool VerifyDigest(const byte *digest, unsigned int digestLength, const byte *signature) const
	{
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		const DL_PublicKey<T> &key = GetKeyInterface();

		GetMaterial().DoQuickSanityCheck();
		const Integer &q = params.GetSubgroupOrder();
		Integer e = alg.EncodeDigest(q.BitCount(), digest, digestLength);
		unsigned int rLen = alg.RLen(params);
		Integer r(signature, rLen);
		Integer s(signature+rLen, alg.SLen(params));
		return alg.Verify(params, key, e, r, s);
	}
};

//! .
template <class PK, class KI>
class DL_CryptoSystemBase : public PK, public DL_Base<KI>
{
public:
	typedef typename DL_Base<KI>::Element Element;

	unsigned int MaxPlaintextLength(unsigned int cipherTextLength) const
	{
		unsigned int minLen = GetAbstractGroupParameters().GetEncodedElementSize(true);
		return cipherTextLength < minLen ? 0 : GetSymmetricEncryptionAlgorithm().GetMaxSymmetricPlaintextLength(cipherTextLength - minLen);
	}

	unsigned int CiphertextLength(unsigned int plainTextLength) const
	{
		unsigned int len = GetSymmetricEncryptionAlgorithm().GetSymmetricCiphertextLength(plainTextLength);
		return len == 0 ? 0 : GetAbstractGroupParameters().GetEncodedElementSize(true) + len;
	}

protected:
	virtual const DL_KeyAgreementAlgorithm<Element> & GetKeyAgreementAlgorithm() const =0;
	virtual const DL_KeyDerivationAlgorithm<Element> & GetKeyDerivationAlgorithm() const =0;
	virtual const DL_SymmetricEncryptionAlgorithm & GetSymmetricEncryptionAlgorithm() const =0;
};

//! .
template <class T, class PK = PK_Decryptor>
class DL_DecryptorBase : public DL_CryptoSystemBase<PK, DL_PrivateKey<T> >
{
public:
	typedef T Element;

	DecodingResult Decrypt(const byte *cipherText, unsigned int cipherTextLength, byte *plainText) const
	{
		try
		{
			const DL_KeyAgreementAlgorithm<T> &agreeAlg = GetKeyAgreementAlgorithm();
			const DL_KeyDerivationAlgorithm<T> &derivAlg = GetKeyDerivationAlgorithm();
			const DL_SymmetricEncryptionAlgorithm &encAlg = GetSymmetricEncryptionAlgorithm();
			const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
			const DL_PrivateKey<T> &key = GetKeyInterface();

			Element q = params.DecodeElement(cipherText, true);
			unsigned int elementSize = params.GetEncodedElementSize(true);
			cipherText += elementSize;
			cipherTextLength -= elementSize;

			Element z = agreeAlg.AgreeWithStaticPrivateKey(params, q, true, key.GetPrivateExponent());

			SecByteBlock derivedKey(encAlg.GetSymmetricKeyLength(encAlg.GetMaxSymmetricPlaintextLength(cipherTextLength)));
			derivAlg.Derive(params, derivedKey, derivedKey.size(), z, q);

			return encAlg.SymmetricDecrypt(derivedKey, cipherText, cipherTextLength, plainText);
		}
		catch (DL_BadElement &)
		{
			return DecodingResult();
		}
	}
};

//! .
template <class T, class PK = PK_Encryptor>
class DL_EncryptorBase : public DL_CryptoSystemBase<PK, DL_PublicKey<T> >
{
public:
	typedef T Element;

	void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText) const
	{
		const DL_KeyAgreementAlgorithm<T> &agreeAlg = GetKeyAgreementAlgorithm();
		const DL_KeyDerivationAlgorithm<T> &derivAlg = GetKeyDerivationAlgorithm();
		const DL_SymmetricEncryptionAlgorithm &encAlg = GetSymmetricEncryptionAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		const DL_PublicKey<T> &key = GetKeyInterface();

		Integer x(rng, Integer::One(), params.GetMaxExponent());
		Element q = params.ExponentiateBase(x);
		params.EncodeElement(true, q, cipherText);
		unsigned int elementSize = params.GetEncodedElementSize(true);
		cipherText += elementSize;

		Element z = agreeAlg.AgreeWithEphemeralPrivateKey(params, key.GetPublicPrecomputation(), x);

		SecByteBlock derivedKey(encAlg.GetSymmetricKeyLength(plainTextLength));
		derivAlg.Derive(params, derivedKey, derivedKey.size(), z, q);

		encAlg.SymmetricEncrypt(rng, derivedKey, plainText, plainTextLength, cipherText);
	}
};

//! .
template <class T1, class T2>
struct DL_SchemeOptionsBase
{
	typedef T1 AlgorithmInfo;
	typedef T2 GroupParameters;
	typedef typename GroupParameters::Element Element;
};

//! .
template <class T1, class T2>
struct DL_KeyedSchemeOptions : public DL_SchemeOptionsBase<T1, typename T2::PublicKey::GroupParameters>
{
	typedef T2 Keys;
	typedef typename Keys::PrivateKey PrivateKey;
	typedef typename Keys::PublicKey PublicKey;
};

//! .
template <class T1, class T2, class T3>
struct DL_SignatureSchemeOptions : public DL_KeyedSchemeOptions<T1, T2>
{
	typedef T3 SignatureAlgorithm;
};

//! .
template <class T1, class T2, class T3, class T4, class T5>
struct DL_CryptoSchemeOptions : public DL_KeyedSchemeOptions<T1, T2>
{
	typedef T3 KeyAgreementAlgorithm;
	typedef T4 KeyDerivationAlgorithm;
	typedef T5 SymmetricEncryptionAlgorithm;
};

//! .
template <class BASE, class SCHEME_OPTIONS, class KEY>
class DL_ObjectImplBase : public AlgorithmImpl<BASE, typename SCHEME_OPTIONS::AlgorithmInfo>
{
public:
	typedef SCHEME_OPTIONS SchemeOptions;
	typedef KEY KeyClass;
	typedef typename KeyClass::Element Element;

	PrivateKey & AccessPrivateKey() {return m_key;}
	PublicKey & AccessPublicKey() {return m_key;}

	// KeyAccessor
	const KeyClass & GetKey() const {return m_key;}
	KeyClass & AccessKey() {return m_key;}

protected:
	typename BASE::KeyInterface & AccessKeyInterface() {return m_key;}
	const typename BASE::KeyInterface & GetKeyInterface() const {return m_key;}

private:
	KeyClass m_key;
};

//! .
template <class BASE, class SCHEME_OPTIONS, class KEY>
class DL_ObjectImpl : public DL_ObjectImplBase<BASE, SCHEME_OPTIONS, KEY>
{
public:
	typedef typename KEY::Element Element;

protected:
	const DL_ElgamalLikeSignatureAlgorithm<Element> & GetSignatureAlgorithm() const
		{static typename SCHEME_OPTIONS::SignatureAlgorithm a; return a;}
	const DL_KeyAgreementAlgorithm<Element> & GetKeyAgreementAlgorithm() const
		{static typename SCHEME_OPTIONS::KeyAgreementAlgorithm a; return a;}
	const DL_KeyDerivationAlgorithm<Element> & GetKeyDerivationAlgorithm() const
		{static typename SCHEME_OPTIONS::KeyDerivationAlgorithm a; return a;}
	const DL_SymmetricEncryptionAlgorithm & GetSymmetricEncryptionAlgorithm() const
		{static typename SCHEME_OPTIONS::SymmetricEncryptionAlgorithm a; return a;}
};

//! .
template <class BASE, class SCHEME_OPTIONS>
class DL_PublicObjectImpl : public DL_ObjectImpl<BASE, SCHEME_OPTIONS, typename SCHEME_OPTIONS::PublicKey>, public PublicKeyCopier<SCHEME_OPTIONS>
{
public:
	void CopyKeyInto(typename SCHEME_OPTIONS::PublicKey &key) const
		{key = GetKey();}
};

//! .
template <class BASE, class SCHEME_OPTIONS>
class DL_PrivateObjectImpl : public DL_ObjectImpl<BASE, SCHEME_OPTIONS, typename SCHEME_OPTIONS::PrivateKey>, public PrivateKeyCopier<SCHEME_OPTIONS>
{
public:
	void CopyKeyInto(typename SCHEME_OPTIONS::PublicKey &key) const
		{GetKey().MakePublicKey(key);}
	void CopyKeyInto(typename SCHEME_OPTIONS::PrivateKey &key) const
		{key = GetKey();}
};

//! .
template <class SCHEME_OPTIONS>
class DL_DigestSignerImpl : public DL_PrivateObjectImpl<DL_DigestSignerBase<typename SCHEME_OPTIONS::Element>, SCHEME_OPTIONS>
{
};

//! .
template <class SCHEME_OPTIONS>
class DL_DigestVerifierImpl : public DL_PublicObjectImpl<DL_DigestVerifierBase<typename SCHEME_OPTIONS::Element>, SCHEME_OPTIONS>
{
};

//! .
template <class SCHEME_OPTIONS>
class DL_EncryptorImpl : public DL_PublicObjectImpl<DL_EncryptorBase<typename SCHEME_OPTIONS::Element>, SCHEME_OPTIONS>
{
};

//! .
template <class SCHEME_OPTIONS>
class DL_DecryptorImpl : public DL_PrivateObjectImpl<DL_DecryptorBase<typename SCHEME_OPTIONS::Element>, SCHEME_OPTIONS>
{
};

// ********************************************************

//! .
template <class T>
class DL_SimpleKeyAgreementDomainBase : public SimpleKeyAgreementDomain
{
public:
	typedef T Element;

	CryptoParameters & AccessCryptoParameters() {return AccessAbstractGroupParameters();}
	unsigned int AgreedValueLength() const {return GetAbstractGroupParameters().GetEncodedElementSize(false);}
	unsigned int PrivateKeyLength() const {return GetAbstractGroupParameters().GetSubgroupOrder().ByteCount();}
	unsigned int PublicKeyLength() const {return GetAbstractGroupParameters().GetEncodedElementSize(true);}

	void GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const
	{
		Integer x(rng, Integer::One(), GetAbstractGroupParameters().GetMaxExponent());
		x.Encode(privateKey, PrivateKeyLength());
	}

	void GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const
	{
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		Integer x(privateKey, PrivateKeyLength());
		Element y = params.ExponentiateBase(x);
		params.EncodeElement(true, y, publicKey);
	}
	
	bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const
	{
		try
		{
			const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
			Integer x(privateKey, PrivateKeyLength());
			Element w = params.DecodeElement(otherPublicKey, validateOtherPublicKey);

			Element z = GetKeyAgreementAlgorithm().AgreeWithStaticPrivateKey(
				GetAbstractGroupParameters(), w, validateOtherPublicKey, x);
			params.EncodeElement(false, z, agreedValue);
		}
		catch (DL_BadElement &)
		{
			return false;
		}
		return true;
	}

	const Element &GetGenerator() const {return GetAbstractGroupParameters().GetSubgroupGenerator();}

protected:
	virtual const DL_KeyAgreementAlgorithm<Element> & GetKeyAgreementAlgorithm() const =0;
	virtual DL_GroupParameters<Element> & AccessAbstractGroupParameters() =0;
	const DL_GroupParameters<Element> & GetAbstractGroupParameters() const {return const_cast<DL_SimpleKeyAgreementDomainBase<Element> *>(this)->AccessAbstractGroupParameters();}
};

enum CofactorMultiplicationOption {NO_COFACTOR_MULTIPLICTION, COMPATIBLE_COFACTOR_MULTIPLICTION, INCOMPATIBLE_COFACTOR_MULTIPLICTION};
typedef EnumToType<CofactorMultiplicationOption, NO_COFACTOR_MULTIPLICTION> NoCofactorMultiplication;
typedef EnumToType<CofactorMultiplicationOption, COMPATIBLE_COFACTOR_MULTIPLICTION> CompatibleCofactorMultiplication;
typedef EnumToType<CofactorMultiplicationOption, INCOMPATIBLE_COFACTOR_MULTIPLICTION> IncompatibleCofactorMultiplication;

//! DH key agreement algorithm
template <class ELEMENT, class COFACTOR_OPTION>
class DL_KeyAgreementAlgorithm_DH : public DL_KeyAgreementAlgorithm<ELEMENT>
{
public:
	typedef ELEMENT Element;

	static const char *StaticAlgorithmName()
		{return COFACTOR_OPTION::ToEnum() == NO_COFACTOR_MULTIPLICTION ? "DH" : "DHC";}

	Element AgreeWithEphemeralPrivateKey(const DL_GroupParameters<Element> &params, const DL_FixedBasePrecomputation<Element> &publicPrecomputation, const Integer &privateExponent) const
	{
		return publicPrecomputation.Exponentiate(params.GetGroupPrecomputation(), 
			COFACTOR_OPTION::ToEnum() == INCOMPATIBLE_COFACTOR_MULTIPLICTION ? privateExponent*params.GetCofactor() : privateExponent);
	}

	Element AgreeWithStaticPrivateKey(const DL_GroupParameters<Element> &params, const Element &publicElement, bool validateOtherPublicKey, const Integer &privateExponent) const
	{
		if (COFACTOR_OPTION::ToEnum() == COMPATIBLE_COFACTOR_MULTIPLICTION)
		{
			const Integer &k = params.GetCofactor();
			return params.ExponentiateElement(publicElement, 
				ModularArithmetic(params.GetSubgroupOrder()).Divide(privateExponent, k)*k);
		}
		else if (COFACTOR_OPTION::ToEnum() == INCOMPATIBLE_COFACTOR_MULTIPLICTION)
			return params.ExponentiateElement(publicElement, privateExponent*params.GetCofactor());
		else
		{
			assert(COFACTOR_OPTION::ToEnum() == NO_COFACTOR_MULTIPLICTION);

			if (!validateOtherPublicKey)
				return params.ExponentiateElement(publicElement, privateExponent);

			if (params.FastSubgroupCheckAvailable())
			{
				if (!params.ValidateElement(2, publicElement, NULL))
					throw DL_BadElement();
				return params.ExponentiateElement(publicElement, privateExponent);
			}
			else
			{
				const Integer e[2] = {params.GetSubgroupOrder(), privateExponent};
				Element r[2];
				params.SimultaneousExponentiate(r, publicElement, e, 2);
				if (!params.IsIdentity(r[0]))
					throw DL_BadElement();
				return r[1];
			}
		}
	}
};

// ********************************************************

//! A template implementing constructors for public key algorithm classes
template <class BASE>
class PK_FinalTemplate : public BASE
{
public:
	PK_FinalTemplate() {}

	PK_FinalTemplate(const Integer &v1)
		{AccessKey().Initialize(v1);}

	PK_FinalTemplate(const typename BASE::KeyClass &key)  {AccessKey().operator=(key);}

	template <class T>
	PK_FinalTemplate(const PublicKeyCopier<T> &key)
		{key.CopyKeyInto(AccessKey());}

	template <class T>
	PK_FinalTemplate(const PrivateKeyCopier<T> &key)
		{key.CopyKeyInto(AccessKey());}

	PK_FinalTemplate(BufferedTransformation &bt) {AccessKey().BERDecode(bt);}

#if (defined(_MSC_VER) && _MSC_VER < 1300)

	template <class T1, class T2>
	PK_FinalTemplate(T1 &v1, T2 &v2)
		{AccessKey().Initialize(v1, v2);}

	template <class T1, class T2, class T3>
	PK_FinalTemplate(T1 &v1, T2 &v2, T3 &v3)
		{AccessKey().Initialize(v1, v2, v3);}
	
	template <class T1, class T2, class T3, class T4>
	PK_FinalTemplate(T1 &v1, T2 &v2, T3 &v3, T4 &v4)
		{AccessKey().Initialize(v1, v2, v3, v4);}

	template <class T1, class T2, class T3, class T4, class T5>
	PK_FinalTemplate(T1 &v1, T2 &v2, T3 &v3, T4 &v4, T5 &v5)
		{AccessKey().Initialize(v1, v2, v3, v4, v5);}

	template <class T1, class T2, class T3, class T4, class T5, class T6>
	PK_FinalTemplate(T1 &v1, T2 &v2, T3 &v3, T4 &v4, T5 &v5, T6 &v6)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6);}

	template <class T1, class T2, class T3, class T4, class T5, class T6, class T7>
	PK_FinalTemplate(T1 &v1, T2 &v2, T3 &v3, T4 &v4, T5 &v5, T6 &v6, T7 &v7)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6, v7);}

	template <class T1, class T2, class T3, class T4, class T5, class T6, class T7, class T8>
	PK_FinalTemplate(T1 &v1, T2 &v2, T3 &v3, T4 &v4, T5 &v5, T6 &v6, T7 &v7, T8 &v8)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6, v7, v8);}

#else

	template <class T1, class T2>
	PK_FinalTemplate(const T1 &v1, const T2 &v2)
		{AccessKey().Initialize(v1, v2);}

	template <class T1, class T2, class T3>
	PK_FinalTemplate(const T1 &v1, const T2 &v2, const T3 &v3)
		{AccessKey().Initialize(v1, v2, v3);}
	
	template <class T1, class T2, class T3, class T4>
	PK_FinalTemplate(const T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4)
		{AccessKey().Initialize(v1, v2, v3, v4);}

	template <class T1, class T2, class T3, class T4, class T5>
	PK_FinalTemplate(const T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4, const T5 &v5)
		{AccessKey().Initialize(v1, v2, v3, v4, v5);}

	template <class T1, class T2, class T3, class T4, class T5, class T6>
	PK_FinalTemplate(const T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4, const T5 &v5, const T6 &v6)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6);}

	template <class T1, class T2, class T3, class T4, class T5, class T6, class T7>
	PK_FinalTemplate(const T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4, const T5 &v5, const T6 &v6, const T7 &v7)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6, v7);}

	template <class T1, class T2, class T3, class T4, class T5, class T6, class T7, class T8>
	PK_FinalTemplate(const T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4, const T5 &v5, const T6 &v6, const T7 &v7, const T8 &v8)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6, v7, v8);}

	template <class T1, class T2>
	PK_FinalTemplate(T1 &v1, const T2 &v2)
		{AccessKey().Initialize(v1, v2);}

	template <class T1, class T2, class T3>
	PK_FinalTemplate(T1 &v1, const T2 &v2, const T3 &v3)
		{AccessKey().Initialize(v1, v2, v3);}
	
	template <class T1, class T2, class T3, class T4>
	PK_FinalTemplate(T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4)
		{AccessKey().Initialize(v1, v2, v3, v4);}

	template <class T1, class T2, class T3, class T4, class T5>
	PK_FinalTemplate(T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4, const T5 &v5)
		{AccessKey().Initialize(v1, v2, v3, v4, v5);}

	template <class T1, class T2, class T3, class T4, class T5, class T6>
	PK_FinalTemplate(T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4, const T5 &v5, const T6 &v6)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6);}

	template <class T1, class T2, class T3, class T4, class T5, class T6, class T7>
	PK_FinalTemplate(T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4, const T5 &v5, const T6 &v6, const T7 &v7)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6, v7);}

	template <class T1, class T2, class T3, class T4, class T5, class T6, class T7, class T8>
	PK_FinalTemplate(T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4, const T5 &v5, const T6 &v6, const T7 &v7, const T8 &v8)
		{AccessKey().Initialize(v1, v2, v3, v4, v5, v6, v7, v8);}

#endif
};

//! Base class for public key encryption standard classes. These classes are used to select from variants of algorithms. Note that not all standards apply to all algorithms.
struct EncryptionStandard {};

//! Base class for public key signature standard classes. These classes are used to select from variants of algorithms. Note that not all standards apply to all algorithms.
struct SignatureStandard {};

template <class STANDARD, class KEYS, class ALG_INFO>
class TF_ES;

//! Trapdoor Function Based Encryption Scheme
template <class STANDARD, class KEYS, class ALG_INFO = TF_ES<STANDARD, KEYS, int> >
class TF_ES : public KEYS
{
	typedef typename STANDARD::EncryptionPaddingAlgorithm PaddingAlgorithm;

public:
	//! see EncryptionStandard for a list of standards
	typedef STANDARD Standard;
	typedef TF_SchemeOptions<ALG_INFO, KEYS, PaddingAlgorithm> SchemeOptions;

	static std::string StaticAlgorithmName() {return KEYS::StaticAlgorithmName() + "/" + PaddingAlgorithm::StaticAlgorithmName();}

	//! implements PK_Decryptor interface
	typedef PK_FinalTemplate<TF_DecryptorImpl<SchemeOptions> > Decryptor;
	//! implements PK_Encryptor interface
	typedef PK_FinalTemplate<TF_EncryptorImpl<SchemeOptions> > Encryptor;
};

template <class STANDARD, class H, class KEYS, class ALG_INFO>	// VC60 workaround: doesn't work if KEYS is first parameter
class TF_SSA;

//! Trapdoor Function Based Signature Scheme With Appendix
template <class STANDARD, class H, class KEYS, class ALG_INFO = TF_SSA<STANDARD, H, KEYS, int> >	// VC60 workaround: doesn't work if KEYS is first parameter
class TF_SSA : public KEYS
{
#ifdef __GNUC__
	// GCC3 workaround: can't do this typedef in one line
	typedef typename STANDARD::SignaturePaddingAlgorithm<H> Type1;
	typedef typename Type1::type PaddingAlgorithm;
	typedef typename STANDARD::DecoratedHashingAlgorithm<H> Type2;
public:
	typedef typename Type2::type DecoratedHashAlgorithm;
#else
	// VC60 workaround: using STANDARD directly causes internal compiler error
	typedef CryptoStandardTraits<STANDARD> Traits;
	typedef typename Traits::SignaturePaddingAlgorithm<H>::type PaddingAlgorithm;
public:
	typedef typename Traits::DecoratedHashingAlgorithm<H>::type DecoratedHashAlgorithm;
#endif

	//! see SignatureStandard for a list of standards
	typedef STANDARD Standard;
	typedef TF_SchemeOptions<ALG_INFO, KEYS, PaddingAlgorithm> SchemeOptions;

	static std::string StaticAlgorithmName() {return KEYS::StaticAlgorithmName() + "/" + PaddingAlgorithm::StaticAlgorithmName() + "(" + H::StaticAlgorithmName() + ")";}

	//! implements PK_Signer interface
	typedef PK_FinalTemplate<PK_SignerImpl<TF_DigestSignerImpl<SchemeOptions>, DecoratedHashAlgorithm> > Signer;
	//! implements PK_Verifier interface
	typedef PK_FinalTemplate<PK_VerifierImpl<TF_DigestVerifierImpl<SchemeOptions>, DecoratedHashAlgorithm> > Verifier;
};

template <class KEYS, class SA, class H, class ALG_INFO>
class DL_SSA;

//! Discrete Log Based Signature Scheme With Appendix
template <class KEYS, class SA, class H, class ALG_INFO = DL_SSA<KEYS, SA, H, int> >
class DL_SSA : public KEYS
{
	typedef DL_SignatureSchemeOptions<ALG_INFO, KEYS, SA> SchemeOptions;

public:
	static std::string StaticAlgorithmName() {return SA::StaticAlgorithmName() + std::string("/EMSA1(") + H::StaticAlgorithmName() + ")";}

	//! implements PK_Signer interface
	typedef PK_FinalTemplate<PK_SignerImpl<DL_DigestSignerImpl<SchemeOptions>, H> > Signer;
	//! implements PK_Verifier interface
	typedef PK_FinalTemplate<PK_VerifierImpl<DL_DigestVerifierImpl<SchemeOptions>, H> > Verifier;
};

//! Discrete Log Based Encryption Scheme
template <class KEYS, class AA, class DA, class EA, class ALG_INFO>
class DL_ES : public KEYS
{
	typedef DL_CryptoSchemeOptions<ALG_INFO, KEYS, AA, DA, EA> SchemeOptions;

public:
	//! implements PK_Decryptor interface
	typedef PK_FinalTemplate<DL_DecryptorImpl<SchemeOptions> > Decryptor;
	//! implements PK_Encryptor interface
	typedef PK_FinalTemplate<DL_EncryptorImpl<SchemeOptions> > Encryptor;
};

NAMESPACE_END

#endif
