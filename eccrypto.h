// eccrypto.h - written and placed in the public domain by Wei Dai

//! \file eccrypto.h
//! \brief Classes and functions for Elliptic Curves over prime and binary fields

#ifndef CRYPTOPP_ECCRYPTO_H
#define CRYPTOPP_ECCRYPTO_H

#include "config.h"
#include "cryptlib.h"
#include "pubkey.h"
#include "integer.h"
#include "asn.h"
#include "hmac.h"
#include "sha.h"
#include "gfpcrypt.h"
#include "dh.h"
#include "mqv.h"
#include "hmqv.h"
#include "fhmqv.h"
#include "ecp.h"
#include "ec2n.h"

NAMESPACE_BEGIN(CryptoPP)

//! \brief Elliptic Curve Parameters
//! \tparam EC elliptic curve field
//! \details This class corresponds to the ASN.1 sequence of the same name
//!   in ANSI X9.62 and SEC 1. EC is currently defined for ECP and EC2N.
template <class EC>
class DL_GroupParameters_EC : public DL_GroupParametersImpl<EcPrecomputation<EC> >
{
	typedef DL_GroupParameters_EC<EC> ThisClass;

public:
	typedef EC EllipticCurve;
	typedef typename EllipticCurve::Point Point;
	typedef Point Element;
	typedef IncompatibleCofactorMultiplication DefaultCofactorOption;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_EC() {}
#endif

	DL_GroupParameters_EC() : m_compress(false), m_encodeAsOID(true) {}
	DL_GroupParameters_EC(const OID &oid)
		: m_compress(false), m_encodeAsOID(true) {Initialize(oid);}
	DL_GroupParameters_EC(const EllipticCurve &ec, const Point &G, const Integer &n, const Integer &k = Integer::Zero())
		: m_compress(false), m_encodeAsOID(true) {Initialize(ec, G, n, k);}
	DL_GroupParameters_EC(BufferedTransformation &bt)
		: m_compress(false), m_encodeAsOID(true) {BERDecode(bt);}

	void Initialize(const EllipticCurve &ec, const Point &G, const Integer &n, const Integer &k = Integer::Zero())
	{
		this->m_groupPrecomputation.SetCurve(ec);
		this->SetSubgroupGenerator(G);
		m_n = n;
		m_k = k;
	}
	void Initialize(const OID &oid);

	// NameValuePairs
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);

	// GeneratibleCryptoMaterial interface
	//! this implementation doesn't actually generate a curve, it just initializes the parameters with existing values
	/*! parameters: (Curve, SubgroupGenerator, SubgroupOrder, Cofactor (optional)), or (GroupOID) */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);

	// DL_GroupParameters
	const DL_FixedBasePrecomputation<Element> & GetBasePrecomputation() const {return this->m_gpc;}
	DL_FixedBasePrecomputation<Element> & AccessBasePrecomputation() {return this->m_gpc;}
	const Integer & GetSubgroupOrder() const {return m_n;}
	Integer GetCofactor() const;
	bool ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const;
	bool ValidateElement(unsigned int level, const Element &element, const DL_FixedBasePrecomputation<Element> *precomp) const;
	bool FastSubgroupCheckAvailable() const {return false;}
	void EncodeElement(bool reversible, const Element &element, byte *encoded) const
	{
		if (reversible)
			GetCurve().EncodePoint(encoded, element, m_compress);
		else
			element.x.Encode(encoded, GetEncodedElementSize(false));
	}
	virtual unsigned int GetEncodedElementSize(bool reversible) const
	{
		if (reversible)
			return GetCurve().EncodedPointSize(m_compress);
		else
			return GetCurve().GetField().MaxElementByteLength();
	}
	Element DecodeElement(const byte *encoded, bool checkForGroupMembership) const
	{
		Point result;
		if (!GetCurve().DecodePoint(result, encoded, GetEncodedElementSize(true)))
			throw DL_BadElement();
		if (checkForGroupMembership && !ValidateElement(1, result, NULL))
			throw DL_BadElement();
		return result;
	}
	Integer ConvertElementToInteger(const Element &element) const;
	Integer GetMaxExponent() const {return GetSubgroupOrder()-1;}
	bool IsIdentity(const Element &element) const {return element.identity;}
	void SimultaneousExponentiate(Element *results, const Element &base, const Integer *exponents, unsigned int exponentsCount) const;
	static std::string CRYPTOPP_API StaticAlgorithmNamePrefix() {return "EC";}

	// ASN1Key
	OID GetAlgorithmID() const;

	// used by MQV
	Element MultiplyElements(const Element &a, const Element &b) const;
	Element CascadeExponentiate(const Element &element1, const Integer &exponent1, const Element &element2, const Integer &exponent2) const;

	// non-inherited

	// enumerate OIDs for recommended parameters, use OID() to get first one
	static OID CRYPTOPP_API GetNextRecommendedParametersOID(const OID &oid);

	void BERDecode(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	void SetPointCompression(bool compress) {m_compress = compress;}
	bool GetPointCompression() const {return m_compress;}

	void SetEncodeAsOID(bool encodeAsOID) {m_encodeAsOID = encodeAsOID;}
	bool GetEncodeAsOID() const {return m_encodeAsOID;}

	const EllipticCurve& GetCurve() const {return this->m_groupPrecomputation.GetCurve();}

	bool operator==(const ThisClass &rhs) const
		{return this->m_groupPrecomputation.GetCurve() == rhs.m_groupPrecomputation.GetCurve() && this->m_gpc.GetBase(this->m_groupPrecomputation) == rhs.m_gpc.GetBase(rhs.m_groupPrecomputation);}

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	const Point& GetBasePoint() const {return this->GetSubgroupGenerator();}
	const Integer& GetBasePointOrder() const {return this->GetSubgroupOrder();}
	void LoadRecommendedParameters(const OID &oid) {Initialize(oid);}
#endif

protected:
	unsigned int FieldElementLength() const {return GetCurve().GetField().MaxElementByteLength();}
	unsigned int ExponentLength() const {return m_n.ByteCount();}

	OID m_oid;			// set if parameters loaded from a recommended curve
	Integer m_n;		// order of base point
	mutable Integer m_k;		// cofactor
	mutable bool m_compress, m_encodeAsOID;		// presentation details
};

//! \class DL_PublicKey_EC
//! \brief Elliptic Curve Discrete Log (DL) public key
//! \tparam EC elliptic curve field
template <class EC>
class DL_PublicKey_EC : public DL_PublicKeyImpl<DL_GroupParameters_EC<EC> >
{
public:
	typedef typename EC::Point Element;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PublicKey_EC() {}
#endif

	void Initialize(const DL_GroupParameters_EC<EC> &params, const Element &Q)
		{this->AccessGroupParameters() = params; this->SetPublicElement(Q);}
	void Initialize(const EC &ec, const Element &G, const Integer &n, const Element &Q)
		{this->AccessGroupParameters().Initialize(ec, G, n); this->SetPublicElement(Q);}

	// X509PublicKey
	void BERDecodePublicKey(BufferedTransformation &bt, bool parametersPresent, size_t size);
	void DEREncodePublicKey(BufferedTransformation &bt) const;
};

//! \class DL_PrivateKey_EC
//! \brief Elliptic Curve Discrete Log (DL) private key
//! \tparam EC elliptic curve field
template <class EC>
class DL_PrivateKey_EC : public DL_PrivateKeyImpl<DL_GroupParameters_EC<EC> >
{
public:
	typedef typename EC::Point Element;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PrivateKey_EC() {}
#endif

	void Initialize(const DL_GroupParameters_EC<EC> &params, const Integer &x)
		{this->AccessGroupParameters() = params; this->SetPrivateExponent(x);}
	void Initialize(const EC &ec, const Element &G, const Integer &n, const Integer &x)
		{this->AccessGroupParameters().Initialize(ec, G, n); this->SetPrivateExponent(x);}
	void Initialize(RandomNumberGenerator &rng, const DL_GroupParameters_EC<EC> &params)
		{this->GenerateRandom(rng, params);}
	void Initialize(RandomNumberGenerator &rng, const EC &ec, const Element &G, const Integer &n)
		{this->GenerateRandom(rng, DL_GroupParameters_EC<EC>(ec, G, n));}

	// PKCS8PrivateKey
	void BERDecodePrivateKey(BufferedTransformation &bt, bool parametersPresent, size_t size);
	void DEREncodePrivateKey(BufferedTransformation &bt) const;
};

//! \class ECDH
//! \brief Elliptic Curve Diffie-Hellman
//! \tparam EC elliptic curve field
//! \tparam COFACTOR_OPTION \ref CofactorMultiplicationOption "cofactor multiplication option"
//! \sa <a href="http://www.weidai.com/scan-mirror/ka.html#ECDH">Elliptic Curve Diffie-Hellman, AKA ECDH</a>
template <class EC, class COFACTOR_OPTION = CPP_TYPENAME DL_GroupParameters_EC<EC>::DefaultCofactorOption>
struct ECDH
{
	typedef DH_Domain<DL_GroupParameters_EC<EC>, COFACTOR_OPTION> Domain;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~ECDH() {}
#endif
};

//! \class ECMQV
//! \brief Elliptic Curve Menezes-Qu-Vanstone
//! \tparam EC elliptic curve field
//! \tparam COFACTOR_OPTION \ref CofactorMultiplicationOption "cofactor multiplication option"
/// \sa <a href="http://www.weidai.com/scan-mirror/ka.html#ECMQV">Elliptic Curve Menezes-Qu-Vanstone, AKA ECMQV</a>
template <class EC, class COFACTOR_OPTION = CPP_TYPENAME DL_GroupParameters_EC<EC>::DefaultCofactorOption>
struct ECMQV
{
	typedef MQV_Domain<DL_GroupParameters_EC<EC>, COFACTOR_OPTION> Domain;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~ECMQV() {}
#endif
};

//! \class ECHMQV
//! \brief Hashed Elliptic Curve Menezes-Qu-Vanstone
//! \tparam EC elliptic curve field
//! \tparam COFACTOR_OPTION \ref CofactorMultiplicationOption "cofactor multiplication option"
//! \details This implementation follows Hugo Krawczyk's <a href="http://eprint.iacr.org/2005/176">HMQV: A High-Performance
//!   Secure Diffie-Hellman Protocol</a>. Note: this implements HMQV only. HMQV-C with Key Confirmation is not provided.
template <class EC, class COFACTOR_OPTION = CPP_TYPENAME DL_GroupParameters_EC<EC>::DefaultCofactorOption, class HASH = SHA256>
struct ECHMQV
{
	typedef HMQV_Domain<DL_GroupParameters_EC<EC>, COFACTOR_OPTION, HASH> Domain;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~ECHMQV() {}
#endif
};

typedef ECHMQV< ECP, DL_GroupParameters_EC< ECP >::DefaultCofactorOption,   SHA1 >::Domain ECHMQV160;
typedef ECHMQV< ECP, DL_GroupParameters_EC< ECP >::DefaultCofactorOption, SHA256 >::Domain ECHMQV256;
typedef ECHMQV< ECP, DL_GroupParameters_EC< ECP >::DefaultCofactorOption, SHA384 >::Domain ECHMQV384;
typedef ECHMQV< ECP, DL_GroupParameters_EC< ECP >::DefaultCofactorOption, SHA512 >::Domain ECHMQV512;

//! \class ECFHMQV
//! \brief Fully Hashed Elliptic Curve Menezes-Qu-Vanstone
//! \tparam EC elliptic curve field
//! \tparam COFACTOR_OPTION \ref CofactorMultiplicationOption "cofactor multiplication option"
//! \details This implementation follows Augustin P. Sarr and Philippe Elbaz–Vincent, and Jean–Claude Bajard's
//!   <a href="http://eprint.iacr.org/2009/408">A Secure and Efficient Authenticated Diffie-Hellman Protocol</a>.
//!   Note: this is FHMQV, Protocol 5, from page 11; and not FHMQV-C.
template <class EC, class COFACTOR_OPTION = CPP_TYPENAME DL_GroupParameters_EC<EC>::DefaultCofactorOption, class HASH = SHA256>
struct ECFHMQV
{
	typedef FHMQV_Domain<DL_GroupParameters_EC<EC>, COFACTOR_OPTION, HASH> Domain;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~ECFHMQV() {}
#endif
};

typedef ECFHMQV< ECP, DL_GroupParameters_EC< ECP >::DefaultCofactorOption,   SHA1 >::Domain ECFHMQV160;
typedef ECFHMQV< ECP, DL_GroupParameters_EC< ECP >::DefaultCofactorOption, SHA256 >::Domain ECFHMQV256;
typedef ECFHMQV< ECP, DL_GroupParameters_EC< ECP >::DefaultCofactorOption, SHA384 >::Domain ECFHMQV384;
typedef ECFHMQV< ECP, DL_GroupParameters_EC< ECP >::DefaultCofactorOption, SHA512 >::Domain ECFHMQV512;

//! \class DL_Keys_EC
//! \brief Elliptic Curve Discrete Log (DL) keys
//! \tparam EC elliptic curve field
template <class EC>
struct DL_Keys_EC
{
	typedef DL_PublicKey_EC<EC> PublicKey;
	typedef DL_PrivateKey_EC<EC> PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Keys_EC() {}
#endif
};

// Forward declaration; documented below
template <class EC, class H>
struct ECDSA;

//! \class DL_Keys_ECDSA
//! \brief Elliptic Curve DSA keys
//! \tparam EC elliptic curve field
template <class EC>
struct DL_Keys_ECDSA
{
	typedef DL_PublicKey_EC<EC> PublicKey;
	typedef DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_EC<EC>, ECDSA<EC, SHA256> > PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Keys_ECDSA() {}
#endif
};

//! \class DL_Algorithm_ECDSA
//! \brief Elliptic Curve DSA (ECDSA) signature algorithm
//! \tparam EC elliptic curve field
template <class EC>
class DL_Algorithm_ECDSA : public DL_Algorithm_GDSA<typename EC::Point>
{
public:
	CRYPTOPP_STATIC_CONSTEXPR char* const CRYPTOPP_API StaticAlgorithmName() {return "ECDSA";}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_ECDSA() {}
#endif
};

//! \class DL_Algorithm_ECNR
//! \brief Elliptic Curve NR (ECNR) signature algorithm
//! \tparam EC elliptic curve field
template <class EC>
class DL_Algorithm_ECNR : public DL_Algorithm_NR<typename EC::Point>
{
public:
	CRYPTOPP_STATIC_CONSTEXPR char* const CRYPTOPP_API StaticAlgorithmName() {return "ECNR";}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_ECNR() {}
#endif
};

//! \class ECDSA
//! \brief Elliptic Curve DSA (ECDSA) signature scheme
//! \tparam EC elliptic curve field
//! \tparam H HashTransformation derived class
//! \sa <a href="http://www.weidai.com/scan-mirror/sig.html#ECDSA">ECDSA</a>
template <class EC, class H>
struct ECDSA : public DL_SS<DL_Keys_ECDSA<EC>, DL_Algorithm_ECDSA<EC>, DL_SignatureMessageEncodingMethod_DSA, H>
{
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~ECDSA() {}
#endif
};

//! \class ECNR
//! \brief Elliptic Curve NR (ECNR) signature scheme
//! \tparam EC elliptic curve field
//! \tparam H HashTransformation derived class
template <class EC, class H = SHA>
struct ECNR : public DL_SS<DL_Keys_EC<EC>, DL_Algorithm_ECNR<EC>, DL_SignatureMessageEncodingMethod_NR, H>
{
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~ECNR() {}
#endif
};


//! \class ECIES
//! \brief Elliptic Curve Integrated Encryption Scheme
//! \tparam COFACTOR_OPTION \ref CofactorMultiplicationOption "cofactor multiplication option"
//! \tparam HASH HashTransformation derived class used for key drivation and MAC computation
//! \tparam DHAES_MODE flag indicating if the MAC includes additional context parameters such as <em>u·V</em>, <em>v·U</em> and label
//! \tparam LABEL_OCTETS flag indicating if the label size is specified in octets or bits
//! \details ECIES is an Elliptic Curve based Integrated Encryption Scheme (IES). The scheme combines a Key Encapsulation
//!   Method (KEM) with a Data Encapsulation Method (DEM) and a MAC tag. The scheme is
//!   <A HREF="http://en.wikipedia.org/wiki/ciphertext_indistinguishability">IND-CCA2</A>, which is a strong notion of security.
//!   You should prefer an Integrated Encryption Scheme over homegrown schemes.
//! \details The library's original implementation is based on an early P1363 draft, which itself appears to be based on an early Certicom
//!   SEC-1 draft (or an early SEC-1 draft was based on a P1363 draft). Crypto++ 4.2 used the early draft in its Integrated Ecryption
//!   Schemes with <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=false</tt> and <tt>LABEL_OCTETS=true</tt>.
//! \details If you desire an Integrated Encryption Scheme with Crypto++ 4.2 compatibility, then use the ECIES template class with
//!   <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=false</tt> and <tt>LABEL_OCTETS=true</tt>.
//! \details If you desire an Integrated Encryption Scheme with Bouncy Castle 1.54 and Botan 1.11 compatibility, then use the ECIES
//!   template class with <tt>NoCofactorMultiplication</tt>, <tt>DHAES_MODE=true</tt> and <tt>LABEL_OCTETS=false</tt>.
//! \details The default template parameters ensure compatibility with Bouncy Castle 1.54 and Botan 1.11. The combination of
//!   <tt>IncompatibleCofactorMultiplication</tt> and <tt>DHAES_MODE=true</tt> is recommended for best efficiency and security.
//!   SHA1 is used for compatibility reasons, but it can be changed if desired. SHA-256 or another hash will likely improve the
//!   security provided by the MAC. The hash is also used in the key derivation function as a PRF.
//! \details Below is an example of constructing a Crypto++ 4.2 compatible ECIES encryptor and decryptor.
//! <pre>
//!     AutoSeededRandomPool prng;
//!     DL_PrivateKey_EC<ECP> key;
//!     key.Initialize(prng, ASN1::secp160r1());
//!
//!     ECIES<ECP,SHA1,NoCofactorMultiplication,true,true>::Decryptor decryptor(key);
//!     ECIES<ECP,SHA1,NoCofactorMultiplication,true,true>::Encryptor encryptor(decryptor);
//! </pre>
//! \sa DLIES, <a href="http://www.weidai.com/scan-mirror/ca.html#ECIES">Elliptic Curve Integrated Encryption Scheme (ECIES)</a>,
//!   Martínez, Encinas, and Ávila's <A HREF="http://digital.csic.es/bitstream/10261/32671/1/V2-I2-P7-13.pdf">A Survey of the Elliptic
//!   Curve Integrated Encryption Schemes</A>
//! \since Crypto++ 4.0, Crypto++ 5.6.6 for Bouncy Castle and Botan compatibility
template <class EC, class HASH = SHA1, class COFACTOR_OPTION = NoCofactorMultiplication, bool DHAES_MODE = true, bool LABEL_OCTETS = false>
struct ECIES
	: public DL_ES<
		DL_Keys_EC<EC>,
		DL_KeyAgreementAlgorithm_DH<typename EC::Point, COFACTOR_OPTION>,
		DL_KeyDerivationAlgorithm_P1363<typename EC::Point, DHAES_MODE, P1363_KDF2<HASH> >,
		DL_EncryptionAlgorithm_Xor<HMAC<HASH>, DHAES_MODE, LABEL_OCTETS>,
		ECIES<EC> >
{
	static std::string CRYPTOPP_API StaticAlgorithmName() {return "ECIES";}	// TODO: fix this after name is standardized

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~ECIES() {}
#endif
};

NAMESPACE_END

#ifdef CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#include "eccrypto.cpp"
#endif

NAMESPACE_BEGIN(CryptoPP)

CRYPTOPP_DLL_TEMPLATE_CLASS DL_GroupParameters_EC<ECP>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_GroupParameters_EC<EC2N>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PublicKeyImpl<DL_GroupParameters_EC<ECP> >;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PublicKeyImpl<DL_GroupParameters_EC<EC2N> >;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PublicKey_EC<ECP>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PublicKey_EC<EC2N>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKeyImpl<DL_GroupParameters_EC<ECP> >;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKeyImpl<DL_GroupParameters_EC<EC2N> >;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_EC<ECP>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_EC<EC2N>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_Algorithm_GDSA<ECP::Point>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_Algorithm_GDSA<EC2N::Point>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_EC<ECP>, ECDSA<ECP, SHA256> >;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_EC<EC2N>, ECDSA<EC2N, SHA256> >;

NAMESPACE_END

#endif
