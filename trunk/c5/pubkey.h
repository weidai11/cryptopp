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
	virtual bool IsRandomized() const {return true;}
};

//! .
class TrapdoorFunction : public RandomizedTrapdoorFunction
{
public:
	Integer ApplyRandomizedFunction(RandomNumberGenerator &rng, const Integer &x) const
		{return ApplyFunction(x);}
	bool IsRandomized() const {return false;}

	virtual Integer ApplyFunction(const Integer &x) const =0;
};

//! .
class RandomizedTrapdoorFunctionInverse
{
public:
	virtual ~RandomizedTrapdoorFunctionInverse() {}

	virtual Integer CalculateRandomizedInverse(RandomNumberGenerator &rng, const Integer &x) const =0;
	virtual bool IsRandomized() const {return true;}
};

//! .
class TrapdoorFunctionInverse : public RandomizedTrapdoorFunctionInverse
{
public:
	virtual ~TrapdoorFunctionInverse() {}

	Integer CalculateRandomizedInverse(RandomNumberGenerator &rng, const Integer &x) const
		{return CalculateInverse(rng, x);}
	bool IsRandomized() const {return false;}

	virtual Integer CalculateInverse(RandomNumberGenerator &rng, const Integer &x) const =0;
};

// ********************************************************

//! .
class PK_EncryptionMessageEncodingMethod
{
public:
	virtual ~PK_EncryptionMessageEncodingMethod() {}

	//! max size of unpadded message in bytes, given max size of padded message in bits (1 less than size of modulus)
	virtual unsigned int MaxUnpaddedLength(unsigned int paddedLength) const =0;

	virtual void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedBitLength) const =0;

	virtual DecodingResult Unpad(const byte *padded, unsigned int paddedBitLength, byte *raw) const =0;
};

// ********************************************************

//! .
template <class TFI, class MEI>
class TF_Base
{
protected:
	virtual const TrapdoorFunctionBounds & GetTrapdoorFunctionBounds() const =0;

	typedef TFI TrapdoorFunctionInterface;
	virtual const TrapdoorFunctionInterface & GetTrapdoorFunctionInterface() const =0;

	typedef MEI MessageEncodingInterface;
	virtual const MessageEncodingInterface & GetMessageEncodingInterface() const =0;
};

// ********************************************************

//! .
template <class INTERFACE, class BASE>
class TF_CryptoSystemBase : public INTERFACE, protected BASE
{
public:
	unsigned int FixedMaxPlaintextLength() const {return GetMessageEncodingInterface().MaxUnpaddedLength(PaddedBlockBitLength());}
	unsigned int FixedCiphertextLength() const {return GetTrapdoorFunctionBounds().MaxImage().ByteCount();}

protected:
	unsigned int PaddedBlockByteLength() const {return BitsToBytes(PaddedBlockBitLength());}
	unsigned int PaddedBlockBitLength() const {return GetTrapdoorFunctionBounds().PreimageBound().BitCount()-1;}
};

//! .
class TF_DecryptorBase : public TF_CryptoSystemBase<PK_FixedLengthDecryptor, TF_Base<TrapdoorFunctionInverse, PK_EncryptionMessageEncodingMethod> >
{
public:
	DecodingResult FixedLengthDecrypt(RandomNumberGenerator &rng, const byte *cipherText, byte *plainText) const;
};

//! .
class TF_EncryptorBase : public TF_CryptoSystemBase<PK_FixedLengthEncryptor, TF_Base<RandomizedTrapdoorFunction, PK_EncryptionMessageEncodingMethod> >
{
public:
	void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText) const;
};

// ********************************************************

typedef std::pair<const byte *, unsigned int> HashIdentifier;

//! .
class PK_SignatureMessageEncodingMethod
{
public:
	virtual ~PK_SignatureMessageEncodingMethod() {}

	virtual unsigned int MaxRecoverableLength(unsigned int representativeBitLength, unsigned int hashIdentifierLength, unsigned int digestLength) const
		{return 0;}

	bool IsProbabilistic() const 
		{return true;}
	bool AllowNonrecoverablePart() const
		{throw NotImplemented("PK_MessageEncodingMethod: this signature scheme does not support message recovery");}
	virtual bool RecoverablePartFirst() const
		{throw NotImplemented("PK_MessageEncodingMethod: this signature scheme does not support message recovery");}

	// for verification, DL
	virtual void ProcessSemisignature(HashTransformation &hash, const byte *semisignature, unsigned int semisignatureLength) const {}

	// for signature
	virtual void ProcessRecoverableMessage(HashTransformation &hash, 
		const byte *recoverableMessage, unsigned int recoverableMessageLength, 
		const byte *presignature, unsigned int presignatureLength,
		SecByteBlock &semisignature) const
	{
		if (RecoverablePartFirst())
			assert(!"ProcessRecoverableMessage() not implemented");
	}

	virtual void ComputeMessageRepresentative(RandomNumberGenerator &rng, 
		const byte *recoverableMessage, unsigned int recoverableMessageLength,
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const =0;

	virtual bool VerifyMessageRepresentative(
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const =0;

	virtual DecodingResult RecoverMessageFromRepresentative(	// for TF
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength,
		byte *recoveredMessage) const
		{throw NotImplemented("PK_MessageEncodingMethod: this signature scheme does not support message recovery");}

	virtual DecodingResult RecoverMessageFromSemisignature(		// for DL
		HashTransformation &hash, HashIdentifier hashIdentifier,
		const byte *presignature, unsigned int presignatureLength,
		const byte *semisignature, unsigned int semisignatureLength,
		byte *recoveredMessage) const
		{throw NotImplemented("PK_MessageEncodingMethod: this signature scheme does not support message recovery");}

	// VC60 workaround
	struct HashIdentifierLookup
	{
		template <class H> struct HashIdentifierLookup2
		{
			static HashIdentifier Lookup()
			{
				return HashIdentifier(NULL, 0);
			}
		};
	};
};

class PK_DeterministicSignatureMessageEncodingMethod : public PK_SignatureMessageEncodingMethod
{
public:
	bool VerifyMessageRepresentative(
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const;
};

class PK_RecoverableSignatureMessageEncodingMethod : public PK_SignatureMessageEncodingMethod
{
public:
	bool VerifyMessageRepresentative(
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const;
};

class DL_SignatureMessageEncodingMethod_DSA : public PK_DeterministicSignatureMessageEncodingMethod
{
public:
	void ComputeMessageRepresentative(RandomNumberGenerator &rng, 
		const byte *recoverableMessage, unsigned int recoverableMessageLength,
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const;
};

class DL_SignatureMessageEncodingMethod_NR : public PK_DeterministicSignatureMessageEncodingMethod
{
public:
	void ComputeMessageRepresentative(RandomNumberGenerator &rng, 
		const byte *recoverableMessage, unsigned int recoverableMessageLength,
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const;
};

class PK_MessageAccumulatorBase : public PK_MessageAccumulator
{
public:
	PK_MessageAccumulatorBase() : m_empty(true) {}

	virtual HashTransformation & AccessHash() =0;

	void Update(const byte *input, unsigned int length)
	{
		AccessHash().Update(input, length);
		m_empty = m_empty && length == 0;
	}

	SecByteBlock m_recoverableMessage, m_representative, m_presignature, m_semisignature;
	Integer m_k, m_s;
	bool m_empty;
};

template <class HASH_ALGORITHM>
class PK_MessageAccumulatorImpl : public PK_MessageAccumulatorBase, protected ObjectHolder<HASH_ALGORITHM>
{
public:
	HashTransformation & AccessHash() {return m_object;}
};

//! .
template <class INTERFACE, class BASE>
class TF_SignatureSchemeBase : public INTERFACE, protected BASE
{
public:
	unsigned int SignatureLength() const 
		{return GetTrapdoorFunctionBounds().MaxPreimage().ByteCount();}
	unsigned int MaxRecoverableLength() const 
		{return GetMessageEncodingInterface().MaxRecoverableLength(MessageRepresentativeBitLength(), GetHashIdentifier().second, GetDigestSize());}
	unsigned int MaxRecoverableLengthFromSignatureLength(unsigned int signatureLength) const
		{return MaxRecoverableLength();}

	bool IsProbabilistic() const 
		{return GetTrapdoorFunctionInterface().IsRandomized() || GetMessageEncodingInterface().IsProbabilistic();}
	bool AllowNonrecoverablePart() const 
		{return GetMessageEncodingInterface().AllowNonrecoverablePart();}
	bool RecoverablePartFirst() const 
		{return GetMessageEncodingInterface().RecoverablePartFirst();}

protected:
	unsigned int MessageRepresentativeLength() const {return BitsToBytes(MessageRepresentativeBitLength());}
	unsigned int MessageRepresentativeBitLength() const {return GetTrapdoorFunctionBounds().ImageBound().BitCount()-1;}
	virtual HashIdentifier GetHashIdentifier() const =0;
	virtual unsigned int GetDigestSize() const =0;
};

//! .
class TF_SignerBase : public TF_SignatureSchemeBase<PK_Signer, TF_Base<RandomizedTrapdoorFunctionInverse, PK_SignatureMessageEncodingMethod> >
{
public:
	void InputRecoverableMessage(PK_MessageAccumulator &messageAccumulator, const byte *recoverableMessage, unsigned int recoverableMessageLength) const;
	unsigned int SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart=true) const;
};

//! .
class TF_VerifierBase : public TF_SignatureSchemeBase<PK_Verifier, TF_Base<TrapdoorFunction, PK_SignatureMessageEncodingMethod> >
{
public:
	void InputSignature(PK_MessageAccumulator &messageAccumulator, const byte *signature, unsigned int signatureLength) const;
	bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const;
	DecodingResult RecoverAndRestart(byte *recoveredMessage, PK_MessageAccumulator &recoveryAccumulator) const;
};

// ********************************************************

//! .
template <class T1, class T2, class T3>
struct TF_CryptoSchemeOptions
{
	typedef T1 AlgorithmInfo;
	typedef T2 Keys;
	typedef typename Keys::PrivateKey PrivateKey;
	typedef typename Keys::PublicKey PublicKey;
	typedef T3 MessageEncodingMethod;
};

//! .
template <class T1, class T2, class T3, class T4>
struct TF_SignatureSchemeOptions : public TF_CryptoSchemeOptions<T1, T2, T3>
{
	typedef T4 HashFunction;
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
	const typename BASE::MessageEncodingInterface & GetMessageEncodingInterface() const 
		{static typename SCHEME_OPTIONS::MessageEncodingMethod messageEncodingMethod; return messageEncodingMethod;}
	const TrapdoorFunctionBounds & GetTrapdoorFunctionBounds() const 
		{return GetKey();}
	const typename BASE::TrapdoorFunctionInterface & GetTrapdoorFunctionInterface() const 
		{return GetKey();}

	// for signature scheme
	HashIdentifier GetHashIdentifier() const
	{
		typedef CPP_TYPENAME SchemeOptions::MessageEncodingMethod::HashIdentifierLookup::HashIdentifierLookup2<CPP_TYPENAME SchemeOptions::HashFunction> L;
		return L::Lookup();
	}
	unsigned int GetDigestSize() const
	{
		typedef CPP_TYPENAME SchemeOptions::HashFunction H;
		return H::DIGESTSIZE;
	}
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
class TF_SignerImpl : public TF_PrivateObjectImpl<TF_SignerBase, SCHEME_OPTIONS>
{
	PK_MessageAccumulator * NewSignatureAccumulator(RandomNumberGenerator &rng = NullRNG()) const
	{
		return new PK_MessageAccumulatorImpl<CPP_TYPENAME SCHEME_OPTIONS::HashFunction>;
	}
};

//! .
template <class SCHEME_OPTIONS>
class TF_VerifierImpl : public TF_PublicObjectImpl<TF_VerifierBase, SCHEME_OPTIONS>
{
	PK_MessageAccumulator * NewVerificationAccumulator() const
	{
		return new PK_MessageAccumulatorImpl<CPP_TYPENAME SCHEME_OPTIONS::HashFunction>;
	}
};

// ********************************************************

class MaskGeneratingFunction
{
public:
	virtual ~MaskGeneratingFunction() {}
	virtual void GenerateAndMask(HashTransformation &hash, byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength, bool mask = true) const =0;
};

void P1363_MGF1KDF2_Common(HashTransformation &hash, byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength, bool mask, unsigned int counterStart);

//! .
class P1363_MGF1 : public MaskGeneratingFunction
{
public:
	static const char * StaticAlgorithmName() {return "MGF1";}
#if 0
	// VC60 workaround: this function causes internal compiler error
	template <class H>
	static void GenerateAndMaskTemplate(byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength, H* dummy=NULL)
	{
		H h;
		P1363_MGF1KDF2_Common(h, output, outputLength, input, inputLength, mask, 0);
	}
#endif
	void GenerateAndMask(HashTransformation &hash, byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength, bool mask = true) const
	{
		P1363_MGF1KDF2_Common(hash, output, outputLength, input, inputLength, mask, 0);
	}
};

// ********************************************************

//! .
template <class H>
class P1363_KDF2
{
public:
	static void DeriveKey(byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength)
	{
		H h;
		P1363_MGF1KDF2_Common(h, output, outputLength, input, inputLength, false, 1);
	}
};

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
		return GetValueHelper(this, name, valueType, pValue, &GetAbstractGroupParameters())
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
		return GetValueHelper(this, name, valueType, pValue, &GetAbstractGroupParameters())
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
template <class PK, class GP, class O = OID>
class DL_KeyImpl : public PK
{
public:
	typedef GP GroupParameters;

	O GetAlgorithmID() const {return GetGroupParameters().GetAlgorithmID();}
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
			SignaturePairwiseConsistencyTest_FIPS_140_Only(signer, verifier);
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
//	virtual Integer EncodeDigest(unsigned int modulusBits, const byte *digest, unsigned int digestLength) const =0;
	virtual void Sign(const DL_GroupParameters<T> &params, const Integer &privateKey, const Integer &k, const Integer &e, Integer &r, Integer &s) const =0;
	virtual bool Verify(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &e, const Integer &r, const Integer &s) const =0;
	virtual Integer RecoverPresignature(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &r, const Integer &s) const
		{throw NotImplemented("DL_ElgamalLikeSignatureAlgorithm: this signature scheme does not support message recovery");}
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
class DL_SignatureSchemeBase : public INTERFACE, public DL_Base<KEY_INTERFACE>
{
public:
	unsigned int SignatureLength() const
	{
		return GetSignatureAlgorithm().RLen(GetAbstractGroupParameters())
			+ GetSignatureAlgorithm().SLen(GetAbstractGroupParameters());
	}
	unsigned int MaxRecoverableLength() const 
		{return GetMessageEncodingInterface().MaxRecoverableLength(0, GetHashIdentifier().second, GetDigestSize());}
	unsigned int MaxRecoverableLengthFromSignatureLength(unsigned int signatureLength) const
		{assert(false); return 0;}	// TODO

	bool IsProbabilistic() const 
		{return true;}
	bool AllowNonrecoverablePart() const 
		{return GetMessageEncodingInterface().AllowNonrecoverablePart();}
	bool RecoverablePartFirst() const 
		{return GetMessageEncodingInterface().RecoverablePartFirst();}

protected:
	unsigned int MessageRepresentativeLength() const {return BitsToBytes(MessageRepresentativeBitLength());}
	unsigned int MessageRepresentativeBitLength() const {return GetAbstractGroupParameters().GetSubgroupOrder().BitCount();}

	virtual const DL_ElgamalLikeSignatureAlgorithm<CPP_TYPENAME KEY_INTERFACE::Element> & GetSignatureAlgorithm() const =0;
	virtual const PK_SignatureMessageEncodingMethod & GetMessageEncodingInterface() const =0;
	virtual HashIdentifier GetHashIdentifier() const =0;
	virtual unsigned int GetDigestSize() const =0;
};

//! .
template <class T>
class DL_SignerBase : public DL_SignatureSchemeBase<PK_Signer, DL_PrivateKey<T> >
{
public:
	// for validation testing
	void RawSign(const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		const DL_PrivateKey<T> &key = GetKeyInterface();

		r = params.ConvertElementToInteger(params.ExponentiateBase(k));
		alg.Sign(params, key.GetPrivateExponent(), k, e, r, s);
	}

	void InputRecoverableMessage(PK_MessageAccumulator &messageAccumulator, const byte *recoverableMessage, unsigned int recoverableMessageLength) const
	{
		PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
		ma.m_recoverableMessage.Assign(recoverableMessage, recoverableMessageLength);
		GetMessageEncodingInterface().ProcessRecoverableMessage(ma.AccessHash(), 
			recoverableMessage, recoverableMessageLength, 
			ma.m_presignature, ma.m_presignature.size(),
			ma.m_semisignature);
	}

	unsigned int SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart) const
	{
		GetMaterial().DoQuickSanityCheck();

		PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		const DL_PrivateKey<T> &key = GetKeyInterface();

		SecByteBlock representative(MessageRepresentativeLength());
		GetMessageEncodingInterface().ComputeMessageRepresentative(
			rng, 
			ma.m_recoverableMessage, ma.m_recoverableMessage.size(), 
			ma.AccessHash(), GetHashIdentifier(), ma.m_empty, 
			representative, MessageRepresentativeBitLength());
		ma.m_empty = true;
		Integer e(representative, representative.size());

		Integer r;
		if (MaxRecoverableLength() > 0)
			r.Decode(ma.m_semisignature, ma.m_semisignature.size());
		else
			r.Decode(ma.m_presignature, ma.m_presignature.size());
		Integer s;
		alg.Sign(params, key.GetPrivateExponent(), ma.m_k, e, r, s);

		unsigned int rLen = alg.RLen(params);
		r.Encode(signature, rLen);
		s.Encode(signature+rLen, alg.SLen(params));

		if (restart)
			RestartMessageAccumulator(rng, ma);

		return SignatureLength();
	}

protected:
	void RestartMessageAccumulator(RandomNumberGenerator &rng, PK_MessageAccumulatorBase &ma) const
	{
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		ma.m_k.Randomize(rng, 1, params.GetSubgroupOrder()-1);
		ma.m_presignature.New(params.GetEncodedElementSize(false));
		params.ConvertElementToInteger(params.ExponentiateBase(ma.m_k)).Encode(ma.m_presignature, ma.m_presignature.size());
	}
};

//! .
template <class T>
class DL_VerifierBase : public DL_SignatureSchemeBase<PK_Verifier, DL_PublicKey<T> >
{
public:
	void InputSignature(PK_MessageAccumulator &messageAccumulator, const byte *signature, unsigned int signatureLength) const
	{
		PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();

		unsigned int rLen = alg.RLen(params);
		ma.m_semisignature.Assign(signature, rLen);
		ma.m_s.Decode(signature+rLen, alg.SLen(params));

		GetMessageEncodingInterface().ProcessSemisignature(ma.AccessHash(), ma.m_semisignature, ma.m_semisignature.size());
	}
	
	bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const
	{
		GetMaterial().DoQuickSanityCheck();

		PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		const DL_PublicKey<T> &key = GetKeyInterface();

		SecByteBlock representative(MessageRepresentativeLength());
		GetMessageEncodingInterface().ComputeMessageRepresentative(NullRNG(), ma.m_recoverableMessage, ma.m_recoverableMessage.size(), 
			ma.AccessHash(), GetHashIdentifier(), ma.m_empty,
			representative, MessageRepresentativeBitLength());
		ma.m_empty = true;
		Integer e(representative, representative.size());

		Integer r(ma.m_semisignature, ma.m_semisignature.size());
		return alg.Verify(params, key, e, r, ma.m_s);
	}

	DecodingResult RecoverAndRestart(byte *recoveredMessage, PK_MessageAccumulator &messageAccumulator) const
	{
		GetMaterial().DoQuickSanityCheck();

		PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
		const DL_ElgamalLikeSignatureAlgorithm<T> &alg = GetSignatureAlgorithm();
		const DL_GroupParameters<T> &params = GetAbstractGroupParameters();
		const DL_PublicKey<T> &key = GetKeyInterface();

		SecByteBlock representative(MessageRepresentativeLength());
		GetMessageEncodingInterface().ComputeMessageRepresentative(
			NullRNG(), 
			ma.m_recoverableMessage, ma.m_recoverableMessage.size(), 
			ma.AccessHash(), GetHashIdentifier(), ma.m_empty,
			representative, MessageRepresentativeBitLength());
		ma.m_empty = true;
		Integer e(representative, representative.size());

		ma.m_presignature.New(params.GetEncodedElementSize(false));
		Integer r(ma.m_semisignature, ma.m_semisignature.size());
		alg.RecoverPresignature(params, key, r, ma.m_s).Encode(ma.m_presignature, ma.m_presignature.size());

		return GetMessageEncodingInterface().RecoverMessageFromSemisignature(
			ma.AccessHash(), GetHashIdentifier(),
			ma.m_presignature, ma.m_presignature.size(),
			ma.m_semisignature, ma.m_semisignature.size(),
			recoveredMessage);
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

	DecodingResult Decrypt(RandomNumberGenerator &rng, const byte *cipherText, unsigned int cipherTextLength, byte *plainText) const
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
template <class T1, class T2, class T3, class T4, class T5>
struct DL_SignatureSchemeOptions : public DL_KeyedSchemeOptions<T1, T2>
{
	typedef T3 SignatureAlgorithm;
	typedef T4 MessageEncodingMethod;
	typedef T5 HashFunction;
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

	// for signature scheme
	HashIdentifier GetHashIdentifier() const
	{
		typedef CPP_TYPENAME SchemeOptions::MessageEncodingMethod::HashIdentifierLookup::HashIdentifierLookup2<CPP_TYPENAME SchemeOptions::HashFunction> L;
		return L::Lookup();
	}
	unsigned int GetDigestSize() const
	{
		typedef CPP_TYPENAME SchemeOptions::HashFunction H;
		return H::DIGESTSIZE;
	}

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
	HashIdentifier GetHashIdentifier() const
		{return HashIdentifier();}
	const PK_SignatureMessageEncodingMethod & GetMessageEncodingInterface() const 
		{static typename SCHEME_OPTIONS::MessageEncodingMethod a; return a;}
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
class DL_SignerImpl : public DL_PrivateObjectImpl<DL_SignerBase<typename SCHEME_OPTIONS::Element>, SCHEME_OPTIONS>
{
	PK_MessageAccumulator * NewSignatureAccumulator(RandomNumberGenerator &rng = NullRNG()) const
	{
		std::auto_ptr<PK_MessageAccumulatorBase> p(new PK_MessageAccumulatorImpl<CPP_TYPENAME SCHEME_OPTIONS::HashFunction>);
		RestartMessageAccumulator(rng, *p);
		return p.release();
	}
};

//! .
template <class SCHEME_OPTIONS>
class DL_VerifierImpl : public DL_PublicObjectImpl<DL_VerifierBase<typename SCHEME_OPTIONS::Element>, SCHEME_OPTIONS>
{
	PK_MessageAccumulator * NewVerificationAccumulator() const
	{
		return new PK_MessageAccumulatorImpl<CPP_TYPENAME SCHEME_OPTIONS::HashFunction>;
	}
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
	typedef typename STANDARD::EncryptionMessageEncodingMethod MessageEncodingMethod;

public:
	//! see EncryptionStandard for a list of standards
	typedef STANDARD Standard;
	typedef TF_CryptoSchemeOptions<ALG_INFO, KEYS, MessageEncodingMethod> SchemeOptions;

	static std::string StaticAlgorithmName() {return KEYS::StaticAlgorithmName() + "/" + MessageEncodingMethod::StaticAlgorithmName();}

	//! implements PK_Decryptor interface
	typedef PK_FinalTemplate<TF_DecryptorImpl<SchemeOptions> > Decryptor;
	//! implements PK_Encryptor interface
	typedef PK_FinalTemplate<TF_EncryptorImpl<SchemeOptions> > Encryptor;
};

template <class STANDARD, class H, class KEYS, class ALG_INFO>	// VC60 workaround: doesn't work if KEYS is first parameter
class TF_SS;

//! Trapdoor Function Based Signature Scheme
template <class STANDARD, class H, class KEYS, class ALG_INFO = TF_SS<STANDARD, H, KEYS, int> >	// VC60 workaround: doesn't work if KEYS is first parameter
class TF_SS : public KEYS
{
public:
	//! see SignatureStandard for a list of standards
	typedef STANDARD Standard;
	typedef typename Standard::SignatureMessageEncodingMethod MessageEncodingMethod;
	typedef TF_SignatureSchemeOptions<ALG_INFO, KEYS, MessageEncodingMethod, H> SchemeOptions;

	static std::string StaticAlgorithmName() {return KEYS::StaticAlgorithmName() + "/" + MessageEncodingMethod::StaticAlgorithmName() + "(" + H::StaticAlgorithmName() + ")";}

	//! implements PK_Signer interface
	typedef PK_FinalTemplate<TF_SignerImpl<SchemeOptions> > Signer;
	//! implements PK_Verifier interface
	typedef PK_FinalTemplate<TF_VerifierImpl<SchemeOptions> > Verifier;
};

template <class KEYS, class SA, class MEM, class H, class ALG_INFO>
class DL_SS;

//! Discrete Log Based Signature Scheme
template <class KEYS, class SA, class MEM, class H, class ALG_INFO = DL_SS<KEYS, SA, MEM, H, int> >
class DL_SS : public KEYS
{
	typedef DL_SignatureSchemeOptions<ALG_INFO, KEYS, SA, MEM, H> SchemeOptions;

public:
	static std::string StaticAlgorithmName() {return SA::StaticAlgorithmName() + std::string("/EMSA1(") + H::StaticAlgorithmName() + ")";}

	//! implements PK_Signer interface
	typedef PK_FinalTemplate<DL_SignerImpl<SchemeOptions> > Signer;
	//! implements PK_Verifier interface
	typedef PK_FinalTemplate<DL_VerifierImpl<SchemeOptions> > Verifier;
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
