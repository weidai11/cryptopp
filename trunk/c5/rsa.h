#ifndef CRYPTOPP_RSA_H
#define CRYPTOPP_RSA_H

/** \file
	This file contains classes that implement the RSA
	ciphers and signature schemes as defined in PKCS #1 v2.0.
*/

#include "pkcspad.h"
#include "oaep.h"
#include "integer.h"
#include "asn.h"

NAMESPACE_BEGIN(CryptoPP)

//! .
class RSAFunction : public TrapdoorFunction, public X509PublicKey
{
	typedef RSAFunction ThisClass;

public:
	void Initialize(const Integer &n, const Integer &e)
		{m_n = n; m_e = e;}

	// X509PublicKey
	OID GetAlgorithmID() const;
	void BERDecodeKey(BufferedTransformation &bt);
	void DEREncodeKey(BufferedTransformation &bt) const;

	// CryptoMaterial
	bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);

	// TrapdoorFunction
	Integer ApplyFunction(const Integer &x) const;
	Integer PreimageBound() const {return m_n;}
	Integer ImageBound() const {return m_n;}

	// non-derived
	const Integer & GetModulus() const {return m_n;}
	const Integer & GetPublicExponent() const {return m_e;}

	void SetModulus(const Integer &n) {m_n = n;}
	void SetPublicExponent(const Integer &e) {m_e = e;}

protected:
	Integer m_n, m_e;
};

//! .
class InvertibleRSAFunction : public RSAFunction, public TrapdoorFunctionInverse, public PKCS8PrivateKey
{
	typedef InvertibleRSAFunction ThisClass;

public:
	void Initialize(RandomNumberGenerator &rng, unsigned int modulusBits, const Integer &e = 17);
	void Initialize(const Integer &n, const Integer &e, const Integer &d, const Integer &p, const Integer &q, const Integer &dp, const Integer &dq, const Integer &u)
		{m_n = n; m_e = e; m_d = d; m_p = p; m_q = q; m_dp = dp; m_dq = dq; m_u = u;}
	//! factor n given private exponent
	void Initialize(const Integer &n, const Integer &e, const Integer &d);

	// PKCS8PrivateKey
	void BERDecode(BufferedTransformation &bt)
		{PKCS8PrivateKey::BERDecode(bt);}
	void DEREncode(BufferedTransformation &bt) const
		{PKCS8PrivateKey::DEREncode(bt);}
	void BERDecodeKey(BufferedTransformation &bt);
	void DEREncodeKey(BufferedTransformation &bt) const;

	// TrapdoorFunctionInverse
	Integer CalculateInverse(RandomNumberGenerator &rng, const Integer &x) const;

	// GeneratableCryptoMaterial
	bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
	/*! parameters: (ModulusSize, PublicExponent (default 17)) */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);

	// non-derived interface
	const Integer& GetPrime1() const {return m_p;}
	const Integer& GetPrime2() const {return m_q;}
	const Integer& GetPrivateExponent() const {return m_d;}
	const Integer& GetModPrime1PrivateExponent() const {return m_dp;}
	const Integer& GetModPrime2PrivateExponent() const {return m_dq;}
	const Integer& GetMultiplicativeInverseOfPrime2ModPrime1() const {return m_u;}

	void SetPrime1(const Integer &p) {m_p = p;}
	void SetPrime2(const Integer &q) {m_q = q;}
	void SetPrivateExponent(const Integer &d) {m_d = d;}
	void SetModPrime1PrivateExponent(const Integer &dp) {m_dp = dp;}
	void SetModPrime2PrivateExponent(const Integer &dq) {m_dq = dq;}
	void SetMultiplicativeInverseOfPrime2ModPrime1(const Integer &u) {m_u = u;}

protected:
	virtual void DEREncodeOptionalAttributes(BufferedTransformation &bt) const {}
	virtual void BERDecodeOptionalAttributes(BufferedTransformation &bt) {}

	Integer m_d, m_p, m_q, m_dp, m_dq, m_u;
};

//! .
struct RSA
{
	static std::string StaticAlgorithmName() {return "RSA";}
	typedef RSAFunction PublicKey;
	typedef InvertibleRSAFunction PrivateKey;
};

//! <a href="http://www.weidai.com/scan-mirror/ca.html#RSA">RSA cryptosystem</a>
template <class STANDARD>
struct RSAES : public TF_ES<STANDARD, RSA>
{
};

//! <a href="http://www.weidai.com/scan-mirror/sig.html#RSA">RSA signature scheme with appendix</a>
/*! See documentation of PKCS1v15 for a list of hash functions that can be used with it. */
template <class STANDARD, class H>
struct RSASS : public TF_SS<STANDARD, H, RSA>
{
};

// The two RSA encryption schemes defined in PKCS #1 v2.0
typedef RSAES<PKCS1v15>::Decryptor RSAES_PKCS1v15_Decryptor;
typedef RSAES<PKCS1v15>::Encryptor RSAES_PKCS1v15_Encryptor;

typedef RSAES<OAEP<SHA> >::Decryptor RSAES_OAEP_SHA_Decryptor;
typedef RSAES<OAEP<SHA> >::Encryptor RSAES_OAEP_SHA_Encryptor;

// The three RSA signature schemes defined in PKCS #1 v2.0
typedef RSASS<PKCS1v15, SHA>::Signer RSASSA_PKCS1v15_SHA_Signer;
typedef RSASS<PKCS1v15, SHA>::Verifier RSASSA_PKCS1v15_SHA_Verifier;

typedef RSASS<PKCS1v15, MD2>::Signer RSASSA_PKCS1v15_MD2_Signer;
typedef RSASS<PKCS1v15, MD2>::Verifier RSASSA_PKCS1v15_MD2_Verifier;

typedef RSASS<PKCS1v15, MD5>::Signer RSASSA_PKCS1v15_MD5_Signer;
typedef RSASS<PKCS1v15, MD5>::Verifier RSASSA_PKCS1v15_MD5_Verifier;

NAMESPACE_END

#endif
