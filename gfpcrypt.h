// gfpcrypt.h - written and placed in the public domain by Wei Dai

//! \file eccrypto.h
//! \brief Classes and functions for schemes based on Discrete Logs (DL) over GF(p)

#ifndef CRYPTOPP_GFPCRYPT_H
#define CRYPTOPP_GFPCRYPT_H

#include "config.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(push)
# pragma warning(disable: 4189)
#endif

#include "cryptlib.h"
#include "pubkey.h"
#include "integer.h"
#include "modexppc.h"
#include "algparam.h"
#include "smartptr.h"
#include "sha.h"
#include "asn.h"
#include "hmac.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

CRYPTOPP_DLL_TEMPLATE_CLASS DL_GroupParameters<Integer>;

//! \class DL_GroupParameters_IntegerBased
//! \brief Integer-based GroupParameters specialization
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE DL_GroupParameters_IntegerBased : public ASN1CryptoMaterial<DL_GroupParameters<Integer> >
{
	typedef DL_GroupParameters_IntegerBased ThisClass;

public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_IntegerBased() {}
#endif

	void Initialize(const DL_GroupParameters_IntegerBased &params)
		{Initialize(params.GetModulus(), params.GetSubgroupOrder(), params.GetSubgroupGenerator());}
	void Initialize(RandomNumberGenerator &rng, unsigned int pbits)
		{GenerateRandom(rng, MakeParameters("ModulusSize", (int)pbits));}
	void Initialize(const Integer &p, const Integer &g)
		{SetModulusAndSubgroupGenerator(p, g); SetSubgroupOrder(ComputeGroupOrder(p)/2);}
	void Initialize(const Integer &p, const Integer &q, const Integer &g)
		{SetModulusAndSubgroupGenerator(p, g); SetSubgroupOrder(q);}

	// ASN1Object interface
	void BERDecode(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	// GeneratibleCryptoMaterial interface
	/*! parameters: (ModulusSize, SubgroupOrderSize (optional)) */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);

	// DL_GroupParameters
	const Integer & GetSubgroupOrder() const {return m_q;}
	Integer GetGroupOrder() const {return GetFieldType() == 1 ? GetModulus()-Integer::One() : GetModulus()+Integer::One();}
	bool ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const;
	bool ValidateElement(unsigned int level, const Integer &element, const DL_FixedBasePrecomputation<Integer> *precomp) const;
	bool FastSubgroupCheckAvailable() const {return GetCofactor() == 2;}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	// Cygwin i386 crash at -O3; see .
	void EncodeElement(bool reversible, const Element &element, byte *encoded) const;
	unsigned int GetEncodedElementSize(bool reversible) const;
#else
	void EncodeElement(bool reversible, const Element &element, byte *encoded) const
		{CRYPTOPP_UNUSED(reversible); element.Encode(encoded, GetModulus().ByteCount());}
	unsigned int GetEncodedElementSize(bool reversible) const
		{CRYPTOPP_UNUSED(reversible); return GetModulus().ByteCount();}
#endif

	Integer DecodeElement(const byte *encoded, bool checkForGroupMembership) const;
	Integer ConvertElementToInteger(const Element &element) const
		{return element;}
	Integer GetMaxExponent() const;
	static std::string CRYPTOPP_API StaticAlgorithmNamePrefix() {return "";}

	OID GetAlgorithmID() const;

	virtual const Integer & GetModulus() const =0;
	virtual void SetModulusAndSubgroupGenerator(const Integer &p, const Integer &g) =0;

	void SetSubgroupOrder(const Integer &q)
		{m_q = q; ParametersChanged();}

protected:
	Integer ComputeGroupOrder(const Integer &modulus) const
		{return modulus-(GetFieldType() == 1 ? 1 : -1);}

	// GF(p) = 1, GF(p^2) = 2
	virtual int GetFieldType() const =0;
	virtual unsigned int GetDefaultSubgroupOrderSize(unsigned int modulusSize) const;

private:
	Integer m_q;
};

//! \class DL_GroupParameters_IntegerBasedImpl
//! \brief Integer-based GroupParameters default implementation
//! \tparam GROUP_PRECOMP group parameters precomputation specialization
//! \tparam BASE_PRECOMP base class precomputation specialization
template <class GROUP_PRECOMP, class BASE_PRECOMP = DL_FixedBasePrecomputationImpl<CPP_TYPENAME GROUP_PRECOMP::Element> >
class CRYPTOPP_NO_VTABLE DL_GroupParameters_IntegerBasedImpl : public DL_GroupParametersImpl<GROUP_PRECOMP, BASE_PRECOMP, DL_GroupParameters_IntegerBased>
{
	typedef DL_GroupParameters_IntegerBasedImpl<GROUP_PRECOMP, BASE_PRECOMP> ThisClass;

public:
	typedef typename GROUP_PRECOMP::Element Element;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_IntegerBasedImpl() {}
#endif

	// GeneratibleCryptoMaterial interface
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
		{return GetValueHelper<DL_GroupParameters_IntegerBased>(this, name, valueType, pValue).Assignable();}

	void AssignFrom(const NameValuePairs &source)
		{AssignFromHelper<DL_GroupParameters_IntegerBased>(this, source);}

	// DL_GroupParameters
	const DL_FixedBasePrecomputation<Element> & GetBasePrecomputation() const {return this->m_gpc;}
	DL_FixedBasePrecomputation<Element> & AccessBasePrecomputation() {return this->m_gpc;}

	// IntegerGroupParameters
	const Integer & GetModulus() const {return this->m_groupPrecomputation.GetModulus();}
    const Integer & GetGenerator() const {return this->m_gpc.GetBase(this->GetGroupPrecomputation());}

	void SetModulusAndSubgroupGenerator(const Integer &p, const Integer &g)		// these have to be set together
		{this->m_groupPrecomputation.SetModulus(p); this->m_gpc.SetBase(this->GetGroupPrecomputation(), g); this->ParametersChanged();}

	// non-inherited
	bool operator==(const DL_GroupParameters_IntegerBasedImpl<GROUP_PRECOMP, BASE_PRECOMP> &rhs) const
		{return GetModulus() == rhs.GetModulus() && GetGenerator() == rhs.GetGenerator() && this->GetSubgroupOrder() == rhs.GetSubgroupOrder();}
	bool operator!=(const DL_GroupParameters_IntegerBasedImpl<GROUP_PRECOMP, BASE_PRECOMP> &rhs) const
		{return !operator==(rhs);}
};

CRYPTOPP_DLL_TEMPLATE_CLASS DL_GroupParameters_IntegerBasedImpl<ModExpPrecomputation>;

//! \class DL_GroupParameters_GFP
//! \brief GF(p) group parameters
class CRYPTOPP_DLL DL_GroupParameters_GFP : public DL_GroupParameters_IntegerBasedImpl<ModExpPrecomputation>
{
public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_GFP() {}
#endif

	// DL_GroupParameters
	bool IsIdentity(const Integer &element) const {return element == Integer::One();}
	void SimultaneousExponentiate(Element *results, const Element &base, const Integer *exponents, unsigned int exponentsCount) const;

	// NameValuePairs interface
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		return GetValueHelper<DL_GroupParameters_IntegerBased>(this, name, valueType, pValue).Assignable();
	}

	// used by MQV
	Element MultiplyElements(const Element &a, const Element &b) const;
	Element CascadeExponentiate(const Element &element1, const Integer &exponent1, const Element &element2, const Integer &exponent2) const;

protected:
	int GetFieldType() const {return 1;}
};

//! \class DL_GroupParameters_GFP
//! \brief GF(p) group parameters that default to safe primes
class CRYPTOPP_DLL DL_GroupParameters_GFP_DefaultSafePrime : public DL_GroupParameters_GFP
{
public:
	typedef NoCofactorMultiplication DefaultCofactorOption;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_GFP_DefaultSafePrime() {}
#endif

protected:
	unsigned int GetDefaultSubgroupOrderSize(unsigned int modulusSize) const {return modulusSize-1;}
};

//! \class DL_Algorithm_GDSA
//! \brief GDSA algorithm
//! \tparam T FieldElement type or class
template <class T>
class DL_Algorithm_GDSA : public DL_ElgamalLikeSignatureAlgorithm<T>
{
public:
	CRYPTOPP_STATIC_CONSTEXPR char* const CRYPTOPP_API StaticAlgorithmName() {return "DSA-1363";}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_GDSA() {}
#endif

	void Sign(const DL_GroupParameters<T> &params, const Integer &x, const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		r %= q;
		Integer kInv = k.InverseMod(q);
		s = (kInv * (x*r + e)) % q;
		CRYPTOPP_ASSERT(!!r && !!s);
	}

	bool Verify(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &e, const Integer &r, const Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		if (r>=q || r<1 || s>=q || s<1)
			return false;

		Integer w = s.InverseMod(q);
		Integer u1 = (e * w) % q;
		Integer u2 = (r * w) % q;
		// verify r == (g^u1 * y^u2 mod p) mod q
		return r == params.ConvertElementToInteger(publicKey.CascadeExponentiateBaseAndPublicElement(u1, u2)) % q;
	}
};

CRYPTOPP_DLL_TEMPLATE_CLASS DL_Algorithm_GDSA<Integer>;

//! \class DL_Algorithm_NR
//! \brief NR algorithm
//! \tparam T FieldElement type or class
template <class T>
class DL_Algorithm_NR : public DL_ElgamalLikeSignatureAlgorithm<T>
{
public:
	CRYPTOPP_STATIC_CONSTEXPR char* const CRYPTOPP_API StaticAlgorithmName() {return "NR";}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_NR() {}
#endif

	void Sign(const DL_GroupParameters<T> &params, const Integer &x, const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		r = (r + e) % q;
		s = (k - x*r) % q;
		CRYPTOPP_ASSERT(!!r);
	}

	bool Verify(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &e, const Integer &r, const Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		if (r>=q || r<1 || s>=q)
			return false;

		// check r == (m_g^s * m_y^r + m) mod m_q
		return r == (params.ConvertElementToInteger(publicKey.CascadeExponentiateBaseAndPublicElement(s, r)) + e) % q;
	}
};

//! \class DL_PublicKey_GFP
//! \brief Discrete Log (DL) public key in GF(p) groups
//! \tparam GP GroupParameters derived class
//! \details DSA public key format is defined in 7.3.3 of RFC 2459. The	private key format is defined in 12.9 of PKCS #11 v2.10.
template <class GP>
class DL_PublicKey_GFP : public DL_PublicKeyImpl<GP>
{
public:
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PublicKey_GFP() {}
#endif

	void Initialize(const DL_GroupParameters_IntegerBased &params, const Integer &y)
		{this->AccessGroupParameters().Initialize(params); this->SetPublicElement(y);}
	void Initialize(const Integer &p, const Integer &g, const Integer &y)
		{this->AccessGroupParameters().Initialize(p, g); this->SetPublicElement(y);}
	void Initialize(const Integer &p, const Integer &q, const Integer &g, const Integer &y)
		{this->AccessGroupParameters().Initialize(p, q, g); this->SetPublicElement(y);}

	// X509PublicKey
	void BERDecodePublicKey(BufferedTransformation &bt, bool, size_t)
		{this->SetPublicElement(Integer(bt));}
	void DEREncodePublicKey(BufferedTransformation &bt) const
		{this->GetPublicElement().DEREncode(bt);}
};

//! \class DL_PrivateKey_GFP
//! \brief Discrete Log (DL) private key in GF(p) groups
//! \tparam GP GroupParameters derived class
template <class GP>
class DL_PrivateKey_GFP : public DL_PrivateKeyImpl<GP>
{
public:
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PrivateKey_GFP() {}
#endif

	void Initialize(RandomNumberGenerator &rng, unsigned int modulusBits)
		{this->GenerateRandomWithKeySize(rng, modulusBits);}
	void Initialize(RandomNumberGenerator &rng, const Integer &p, const Integer &g)
		{this->GenerateRandom(rng, MakeParameters("Modulus", p)("SubgroupGenerator", g));}
	void Initialize(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g)
		{this->GenerateRandom(rng, MakeParameters("Modulus", p)("SubgroupOrder", q)("SubgroupGenerator", g));}
	void Initialize(const DL_GroupParameters_IntegerBased &params, const Integer &x)
		{this->AccessGroupParameters().Initialize(params); this->SetPrivateExponent(x);}
	void Initialize(const Integer &p, const Integer &g, const Integer &x)
		{this->AccessGroupParameters().Initialize(p, g); this->SetPrivateExponent(x);}
	void Initialize(const Integer &p, const Integer &q, const Integer &g, const Integer &x)
		{this->AccessGroupParameters().Initialize(p, q, g); this->SetPrivateExponent(x);}
};

//! \class DL_SignatureKeys_GFP
//! \brief Discrete Log (DL) signing/verification keys in GF(p) groups
struct DL_SignatureKeys_GFP
{
	typedef DL_GroupParameters_GFP GroupParameters;
	typedef DL_PublicKey_GFP<GroupParameters> PublicKey;
	typedef DL_PrivateKey_GFP<GroupParameters> PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_SignatureKeys_GFP() {}
#endif
};

//! \class DL_CryptoKeys_GFP
//! \brief Discrete Log (DL) encryption/decryption keys in GF(p) groups
struct DL_CryptoKeys_GFP
{
	typedef DL_GroupParameters_GFP_DefaultSafePrime GroupParameters;
	typedef DL_PublicKey_GFP<GroupParameters> PublicKey;
	typedef DL_PrivateKey_GFP<GroupParameters> PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_CryptoKeys_GFP() {}
#endif
};

//! \class DL_PublicKey_GFP_OldFormat
//! \brief Discrete Log (DL) public key in GF(p) groups
//! \tparam BASE GroupParameters derived class
//! \deprecated This implementation uses a non-standard Crypto++ key format. New implementations
//!   should use DL_PublicKey_GFP and DL_PrivateKey_GFP
template <class BASE>
class DL_PublicKey_GFP_OldFormat : public BASE
{
public:
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PublicKey_GFP_OldFormat() {}
#endif

	void BERDecode(BufferedTransformation &bt)
	{
		BERSequenceDecoder seq(bt);
			Integer v1(seq);
			Integer v2(seq);
			Integer v3(seq);

			if (seq.EndReached())
			{
				this->AccessGroupParameters().Initialize(v1, v1/2, v2);
				this->SetPublicElement(v3);
			}
			else
			{
				Integer v4(seq);
				this->AccessGroupParameters().Initialize(v1, v2, v3);
				this->SetPublicElement(v4);
			}

		seq.MessageEnd();
	}

	void DEREncode(BufferedTransformation &bt) const
	{
		DERSequenceEncoder seq(bt);
			this->GetGroupParameters().GetModulus().DEREncode(seq);
			if (this->GetGroupParameters().GetCofactor() != 2)
				this->GetGroupParameters().GetSubgroupOrder().DEREncode(seq);
			this->GetGroupParameters().GetGenerator().DEREncode(seq);
			this->GetPublicElement().DEREncode(seq);
		seq.MessageEnd();
	}
};

//! \class DL_PrivateKey_GFP_OldFormat
//! \brief Discrete Log (DL) private key in GF(p) groups
//! \tparam BASE GroupParameters derived class
//! \deprecated This implementation uses a non-standard Crypto++ key format. New implementations
//!   should use DL_PublicKey_GFP and DL_PrivateKey_GFP
template <class BASE>
class DL_PrivateKey_GFP_OldFormat : public BASE
{
public:
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PrivateKey_GFP_OldFormat() {}
#endif

	void BERDecode(BufferedTransformation &bt)
	{
		BERSequenceDecoder seq(bt);
			Integer v1(seq);
			Integer v2(seq);
			Integer v3(seq);
			Integer v4(seq);

			if (seq.EndReached())
			{
				this->AccessGroupParameters().Initialize(v1, v1/2, v2);
				this->SetPrivateExponent(v4 % (v1/2));	// some old keys may have x >= q
			}
			else
			{
				Integer v5(seq);
				this->AccessGroupParameters().Initialize(v1, v2, v3);
				this->SetPrivateExponent(v5);
			}

		seq.MessageEnd();
	}

	void DEREncode(BufferedTransformation &bt) const
	{
		DERSequenceEncoder seq(bt);
			this->GetGroupParameters().GetModulus().DEREncode(seq);
			if (this->GetGroupParameters().GetCofactor() != 2)
				this->GetGroupParameters().GetSubgroupOrder().DEREncode(seq);
			this->GetGroupParameters().GetGenerator().DEREncode(seq);
			this->GetGroupParameters().ExponentiateBase(this->GetPrivateExponent()).DEREncode(seq);
			this->GetPrivateExponent().DEREncode(seq);
		seq.MessageEnd();
	}
};

//! \class GDSA
//! \brief DSA signature scheme
//! \tparam H HashTransformation derived class
//! \sa <a href="http://www.weidai.com/scan-mirror/sig.html#DSA-1363">DSA-1363</a>
//! \since Crypto++ 1.0 for DSA, Crypto++ 5.6.2 for DSA2
template <class H>
struct GDSA : public DL_SS<
	DL_SignatureKeys_GFP,
	DL_Algorithm_GDSA<Integer>,
	DL_SignatureMessageEncodingMethod_DSA,
	H>
{
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~GDSA() {}
#endif
};

//! \class NR
//! \brief NR signature scheme
//! \tparam H HashTransformation derived class
//! \sa <a href="http://www.weidai.com/scan-mirror/sig.html#NR">NR</a>
template <class H>
struct NR : public DL_SS<
	DL_SignatureKeys_GFP,
	DL_Algorithm_NR<Integer>,
	DL_SignatureMessageEncodingMethod_NR,
	H>
{
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~NR() {}
#endif
};

//! \class DL_GroupParameters_DSA
//! \brief DSA group parameters
//! \details These are GF(p) group parameters that are allowed by the DSA standard
//! \sa DL_Keys_DSA
class CRYPTOPP_DLL DL_GroupParameters_DSA : public DL_GroupParameters_GFP
{
public:
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_DSA() {}
#endif

	/*! also checks that the lengths of p and q are allowed by the DSA standard */
	bool ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const;
	/*! parameters: (ModulusSize), or (Modulus, SubgroupOrder, SubgroupGenerator) */
	/*! ModulusSize must be between DSA::MIN_PRIME_LENGTH and DSA::MAX_PRIME_LENGTH, and divisible by DSA::PRIME_LENGTH_MULTIPLE */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);

	static bool CRYPTOPP_API IsValidPrimeLength(unsigned int pbits)
		{return pbits >= MIN_PRIME_LENGTH && pbits <= MAX_PRIME_LENGTH && pbits % PRIME_LENGTH_MULTIPLE == 0;}

	enum {MIN_PRIME_LENGTH = 1024, MAX_PRIME_LENGTH = 3072, PRIME_LENGTH_MULTIPLE = 1024};
};

template <class H>
class DSA2;

//! \class DL_Keys_DSA
//! \brief DSA keys
//! \sa DL_GroupParameters_DSA
struct DL_Keys_DSA
{
	typedef DL_PublicKey_GFP<DL_GroupParameters_DSA> PublicKey;
	typedef DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_GFP<DL_GroupParameters_DSA>, DSA2<SHA> > PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Keys_DSA() {}
#endif
};

//! \class DSA2
//! \brief DSA signature scheme
//! \tparam H HashTransformation derived class
//! \details The class is named DSA2 instead of DSA for backwards compatibility because DSA was a non-template class.
//! \sa <a href="http://en.wikipedia.org/wiki/Digital_Signature_Algorithm">DSA</a>, as specified in FIPS 186-3
//! \since Crypto++ 1.0 for DSA, Crypto++ 5.6.2 for DSA2
template <class H>
class DSA2 : public DL_SS<
	DL_Keys_DSA,
	DL_Algorithm_GDSA<Integer>,
	DL_SignatureMessageEncodingMethod_DSA,
	H,
	DSA2<H> >
{
public:
	static std::string CRYPTOPP_API StaticAlgorithmName() {return "DSA/" + (std::string)H::StaticAlgorithmName();}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DSA2() {}
#endif

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	enum {MIN_PRIME_LENGTH = 1024, MAX_PRIME_LENGTH = 3072, PRIME_LENGTH_MULTIPLE = 1024};
#endif
};

//! DSA with SHA-1, typedef'd for backwards compatibility
typedef DSA2<SHA1> DSA;

CRYPTOPP_DLL_TEMPLATE_CLASS DL_PublicKey_GFP<DL_GroupParameters_DSA>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_GFP<DL_GroupParameters_DSA>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_GFP<DL_GroupParameters_DSA>, DSA2<SHA> >;

//! \class DL_EncryptionAlgorithm_Xor
//! \brief P1363 based XOR Encryption Method
//! \tparam MAC MessageAuthenticationCode derived class used for MAC computation
//! \tparam DHAES_MODE flag indicating DHAES mode
//! \tparam LABEL_OCTETS flag indicating the label is octet count
//! \details DL_EncryptionAlgorithm_Xor is based on an early P1363 draft, which itself appears to be based on an
//!   early Certicom SEC-1 draft (or an early SEC-1 draft was based on a P1363 draft). Crypto++ 4.2 used it in its Integrated
//!   Ecryption Schemes with <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=false</tt> and <tt>LABEL_OCTETS=true</tt>.
//! \details If you need this method for Crypto++ 4.2 compatibility, then use the ECIES template class with
//!   <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=false</tt> and <tt>LABEL_OCTETS=true</tt>.
//! \details If you need this method for Bouncy Castle 1.54 and Botan 1.11 compatibility, then use the ECIES template class with
//!   <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=ture</tt> and <tt>LABEL_OCTETS=false</tt>.
//! \details Bouncy Castle 1.54 and Botan 1.11 compatibility are the default template parameters.
//! \since Crypto++ 4.0
template <class MAC, bool DHAES_MODE, bool LABEL_OCTETS=false>
class DL_EncryptionAlgorithm_Xor : public DL_SymmetricEncryptionAlgorithm
{
public:
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_EncryptionAlgorithm_Xor() {}
#endif

	bool ParameterSupported(const char *name) const {return strcmp(name, Name::EncodingParameters()) == 0;}
	size_t GetSymmetricKeyLength(size_t plaintextLength) const
		{return plaintextLength + static_cast<size_t>(MAC::DIGESTSIZE);}
	size_t GetSymmetricCiphertextLength(size_t plaintextLength) const
		{return plaintextLength + static_cast<size_t>(MAC::DIGESTSIZE);}
	size_t GetMaxSymmetricPlaintextLength(size_t ciphertextLength) const
		{return SaturatingSubtract(ciphertextLength, static_cast<size_t>(MAC::DIGESTSIZE));}
	void SymmetricEncrypt(RandomNumberGenerator &rng, const byte *key, const byte *plaintext, size_t plaintextLength, byte *ciphertext, const NameValuePairs &parameters) const
	{
		CRYPTOPP_UNUSED(rng);
		const byte *cipherKey = NULL, *macKey = NULL;
		if (DHAES_MODE)
		{
			macKey = key;
			cipherKey = key + MAC::DEFAULT_KEYLENGTH;
		}
		else
		{
			cipherKey = key;
			macKey = key + plaintextLength;
		}

		ConstByteArrayParameter encodingParameters;
		parameters.GetValue(Name::EncodingParameters(), encodingParameters);

		if (plaintextLength)	// Coverity finding
			xorbuf(ciphertext, plaintext, cipherKey, plaintextLength);

		MAC mac(macKey);
		mac.Update(ciphertext, plaintextLength);
		mac.Update(encodingParameters.begin(), encodingParameters.size());
		if (DHAES_MODE)
		{
			byte L[8];
			PutWord(false, BIG_ENDIAN_ORDER, L, (LABEL_OCTETS ? word64(encodingParameters.size()) : 8 * word64(encodingParameters.size())));
			mac.Update(L, 8);
		}
		mac.Final(ciphertext + plaintextLength);
	}
	DecodingResult SymmetricDecrypt(const byte *key, const byte *ciphertext, size_t ciphertextLength, byte *plaintext, const NameValuePairs &parameters) const
	{
		size_t plaintextLength = GetMaxSymmetricPlaintextLength(ciphertextLength);
		const byte *cipherKey, *macKey;
		if (DHAES_MODE)
		{
			macKey = key;
			cipherKey = key + MAC::DEFAULT_KEYLENGTH;
		}
		else
		{
			cipherKey = key;
			macKey = key + plaintextLength;
		}

		ConstByteArrayParameter encodingParameters;
		parameters.GetValue(Name::EncodingParameters(), encodingParameters);

		MAC mac(macKey);
		mac.Update(ciphertext, plaintextLength);
		mac.Update(encodingParameters.begin(), encodingParameters.size());
		if (DHAES_MODE)
		{
			byte L[8];
			PutWord(false, BIG_ENDIAN_ORDER, L, (LABEL_OCTETS ? word64(encodingParameters.size()) : 8 * word64(encodingParameters.size())));
			mac.Update(L, 8);
		}
		if (!mac.Verify(ciphertext + plaintextLength))
			return DecodingResult();

		if (plaintextLength)	// Coverity finding
			xorbuf(plaintext, ciphertext, cipherKey, plaintextLength);

		return DecodingResult(plaintextLength);
	}
};

//! _
template <class T, bool DHAES_MODE, class KDF>
class DL_KeyDerivationAlgorithm_P1363 : public DL_KeyDerivationAlgorithm<T>
{
public:
	bool ParameterSupported(const char *name) const {return strcmp(name, Name::KeyDerivationParameters()) == 0;}
	void Derive(const DL_GroupParameters<T> &params, byte *derivedKey, size_t derivedLength, const T &agreedElement, const T &ephemeralPublicKey, const NameValuePairs &parameters) const
	{
		SecByteBlock agreedSecret;
		if (DHAES_MODE)
		{
			agreedSecret.New(params.GetEncodedElementSize(true) + params.GetEncodedElementSize(false));
			params.EncodeElement(true, ephemeralPublicKey, agreedSecret);
			params.EncodeElement(false, agreedElement, agreedSecret + params.GetEncodedElementSize(true));
		}
		else
		{
			agreedSecret.New(params.GetEncodedElementSize(false));
			params.EncodeElement(false, agreedElement, agreedSecret);
		}

		ConstByteArrayParameter derivationParameters;
		parameters.GetValue(Name::KeyDerivationParameters(), derivationParameters);
		KDF::DeriveKey(derivedKey, derivedLength, agreedSecret, agreedSecret.size(), derivationParameters.begin(), derivationParameters.size());
	}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_KeyDerivationAlgorithm_P1363() {}
#endif
};

//! \class DLIES
//! \brief Discrete Log Integrated Encryption Scheme
//! \tparam COFACTOR_OPTION \ref CofactorMultiplicationOption "cofactor multiplication option"
//! \tparam HASH HashTransformation derived class used for key drivation and MAC computation
//! \tparam DHAES_MODE flag indicating if the MAC includes addition context parameters such as the label
//! \tparam LABEL_OCTETS flag indicating if the label size is specified in octets or bits
//! \details DLIES is an Integer based Integrated Encryption Scheme (IES). The scheme combines a Key Encapsulation Method (KEM)
//!   with a Data Encapsulation Method (DEM) and a MAC tag. The scheme is
//!   <A HREF="http://en.wikipedia.org/wiki/ciphertext_indistinguishability">IND-CCA2</A>, which is a strong notion of security.
//!   You should prefer an Integrated Encryption Scheme over homegrown schemes.
//! \details The library's original implementation is based on an early P1363 draft, which itself appears to be based on an early Certicom
//!   SEC-1 draft (or an early SEC-1 draft was based on a P1363 draft). Crypto++ 4.2 used the early draft in its Integrated Ecryption
//!   Schemes with <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=false</tt> and <tt>LABEL_OCTETS=true</tt>.
//! \details If you desire an Integrated Encryption Scheme with Crypto++ 4.2 compatibility, then use the DLIES template class with
//!   <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=false</tt> and <tt>LABEL_OCTETS=true</tt>.
//! \details If you desire an Integrated Encryption Scheme with Bouncy Castle 1.54 and Botan 1.11 compatibility, then use the DLIES
//!   template class with <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=true</tt> and <tt>LABEL_OCTETS=false</tt>.
//! \details The default template parameters ensure compatibility with Bouncy Castle 1.54 and Botan 1.11. The combination of
//!   <tt>IncompatibleCofactorMultiplication</tt> and <tt>DHAES_MODE=true</tt> is recommended for best efficiency and security.
//!   SHA1 is used for compatibility reasons, but it can be changed if desired. SHA-256 or another hash will likely improve the
//!   security provided by the MAC. The hash is also used in the key derivation function as a PRF.
//! \details Below is an example of constructing a Crypto++ 4.2 compatible DLIES encryptor and decryptor.
//! <pre>
//!     AutoSeededRandomPool prng;
//!     DL_PrivateKey_GFP<DL_GroupParameters_GFP> key;
//!     key.Initialize(prng, 2048);
//!
//!     DLIES<SHA1,NoCofactorMultiplication,true,true>::Decryptor decryptor(key);
//!     DLIES<SHA1,NoCofactorMultiplication,true,true>::Encryptor encryptor(decryptor);
//! </pre>
//! \sa ECIES, <a href="http://www.weidai.com/scan-mirror/ca.html#DLIES">Discrete Log Integrated Encryption Scheme (DLIES)</a>,
//!   Martínez, Encinas, and Ávila's <A HREF="http://digital.csic.es/bitstream/10261/32671/1/V2-I2-P7-13.pdf">A Survey of the Elliptic
//!   Curve Integrated Encryption Schemes</A>
//! \since Crypto++ 4.0, Crypto++ 5.6.6 for Bouncy Castle and Botan compatibility
template <class HASH = SHA1, class COFACTOR_OPTION = NoCofactorMultiplication, bool DHAES_MODE = true, bool LABEL_OCTETS=false>
struct DLIES
	: public DL_ES<
		DL_CryptoKeys_GFP,
		DL_KeyAgreementAlgorithm_DH<Integer, COFACTOR_OPTION>,
		DL_KeyDerivationAlgorithm_P1363<Integer, DHAES_MODE, P1363_KDF2<HASH> >,
		DL_EncryptionAlgorithm_Xor<HMAC<HASH>, DHAES_MODE, LABEL_OCTETS>,
		DLIES<> >
{
	static std::string CRYPTOPP_API StaticAlgorithmName() {return "DLIES";}	// TODO: fix this after name is standardized

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DLIES() {}
#endif
};

NAMESPACE_END

#if CRYPTOPP_MSC_VERSION
# pragma warning(pop)
#endif

#endif
