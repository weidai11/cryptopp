#ifndef CRYPTOPP_GFPCRYPT_H
#define CRYPTOPP_GFPCRYPT_H

/** \file
	Implementation of schemes based on DL over GF(p)
*/

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

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE DL_GroupParameters_IntegerBased : public ASN1CryptoMaterial<DL_GroupParameters<Integer> >
{
	typedef DL_GroupParameters_IntegerBased ThisClass;
	
public:
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
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_IntegerBased() {}
#endif

protected:
	Integer ComputeGroupOrder(const Integer &modulus) const
		{return modulus-(GetFieldType() == 1 ? 1 : -1);}

	// GF(p) = 1, GF(p^2) = 2
	virtual int GetFieldType() const =0;
	virtual unsigned int GetDefaultSubgroupOrderSize(unsigned int modulusSize) const;

private:
	Integer m_q;
};

//! _
template <class GROUP_PRECOMP, class BASE_PRECOMP = DL_FixedBasePrecomputationImpl<CPP_TYPENAME GROUP_PRECOMP::Element> >
class CRYPTOPP_NO_VTABLE DL_GroupParameters_IntegerBasedImpl : public DL_GroupParametersImpl<GROUP_PRECOMP, BASE_PRECOMP, DL_GroupParameters_IntegerBased>
{
	typedef DL_GroupParameters_IntegerBasedImpl<GROUP_PRECOMP, BASE_PRECOMP> ThisClass;

public:
	typedef typename GROUP_PRECOMP::Element Element;

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
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_IntegerBasedImpl() {}
#endif
};

CRYPTOPP_DLL_TEMPLATE_CLASS DL_GroupParameters_IntegerBasedImpl<ModExpPrecomputation>;

//! GF(p) group parameters
class CRYPTOPP_DLL DL_GroupParameters_GFP : public DL_GroupParameters_IntegerBasedImpl<ModExpPrecomputation>
{
public:
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
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_GFP() {}
#endif

protected:
	int GetFieldType() const {return 1;}
};

//! GF(p) group parameters that default to same primes
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

//! GDSA algorithm
template <class T, class H, bool useDetK>
class DL_Algorithm_GDSA : public DL_ElgamalLikeSignatureAlgorithm<T>
{
public:
	static const char * CRYPTOPP_API StaticAlgorithmName() {return "DSA-1363";}

	void Sign(const DL_GroupParameters<T> &params, const Integer &x, const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		r %= q;
		Integer kInv = k.InverseMod(q);
		s = (kInv * (x*r + e)) % q;
		assert(!!r && !!s);
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

	bool UseDeterministicK() const
	{ 
		return useDetK;
	}

	// Creates a k-value based on RFC 6979. Uses the message to hash and its size,
	// the curve order and its bit length, and a private key. Returns true to
	// indicate that the returned k-value is valid.
	const bool getDetKVal(const byte* hmsg, const size_t& hmsgSize,
	                      const Integer& cord, const size_t& cordBits,
	                      const Integer& pk, Integer& kVal) const
	{
		// After doing the initial setup, get the msg hash and work towards the final
		// k value, per the spec.
		SecByteBlock zeroByte(1);
		SecByteBlock oneByte(1);
		memset(zeroByte, '\x00', 1);
		memset(oneByte, '\x01', 1);

		size_t cordBytes = (cordBits + 7) / 8;
		SecByteBlock hkey(H::DIGESTSIZE);
		memset(hkey, '\x00', H::DIGESTSIZE);
		K.SetKey(hkey, hkey.size());
		SecByteBlock msgHash(K.DIGESTSIZE);
		SecByteBlock V(K.DIGESTSIZE);
		SecByteBlock prvKeyBlock = int2octets(pk, (const unsigned int)cordBytes);
		memset(V, '\x01', K.DIGESTSIZE);
		hashFunct.CalculateDigest(msgHash, hmsg, hmsgSize);

		SecByteBlock octetMsg = bits2octets(msgHash, cord, cordBits);
		SecByteBlock hmacInput1 = V + zeroByte + prvKeyBlock + octetMsg;
		K.CalculateDigest(hkey, hmacInput1, hmacInput1.size());

		K.SetKey(hkey, hkey.size());
		K.CalculateDigest(V, V, V.size());

		SecByteBlock hmacInput2 = V + oneByte + prvKeyBlock + octetMsg;
		K.CalculateDigest(hkey, hmacInput2, hmacInput2.size());

		K.SetKey(hkey, hkey.size());
		K.CalculateDigest(V, V, V.size());

		Integer retVal;
		for(bool done = false; done != true; )
		{
			SecByteBlock b2iData;
			for(size_t s = 0; s < cordBytes; s += hkey.size())
			{
				K.CalculateDigest(V, V, V.size());
				b2iData += V;
			}

			// Odds of failure are practically nil but we must play it safe.
			Integer b2i = bits2int(b2iData, (const unsigned int)cordBits);
			if(b2i >= Integer::One() && b2i < cord)
			{
				retVal = b2i;
				done = true;
			}
			else
			{
				SecByteBlock newHMACInput = V + zeroByte;
				K.CalculateDigest(hkey, newHMACInput, newHMACInput.size());

				K.SetKey(hkey, hkey.size());
				K.CalculateDigest(V, V, V.size());
			}
		}
		// Before running the k-val, hash & HMAC functs need to be cleared.
		// CalculateDigest() does this every time, though, so we're good.
		kVal = retVal;
		return true;
	}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_GDSA() {}
#endif

protected:
	// RFC 6979 support function. Takes a set of bits, takes the most significant
	// bytes (subject to a given bit limit), and turns them into an integer.
	Integer bits2int(const SecByteBlock& bits, const unsigned int& qlen) const
	{
		Integer retVal(bits, bits.size());
		if((retVal.ByteCount() * 8) > qlen)
		{
			retVal >>= ((retVal.ByteCount() * 8) - qlen);
		}
	
		return retVal;
	}

	// RFC 6979 support function. Takes an integer and converts it into bytes that
	// are the same length as an elliptic curve's order.
	SecByteBlock int2octets(const Integer& val, const unsigned int& rlenBytes) const
	{
		SecByteBlock octetBlock(val.ByteCount());
		val.Encode(octetBlock, val.ByteCount());
		SecByteBlock retVal = octetBlock;

		// The least significant bytes are the ones we need to preserve.
		if(octetBlock.size() > rlenBytes)
		{
			SecByteBlock octetBlock1(rlenBytes);
			size_t offset = octetBlock.size() - rlenBytes;
			memcpy(octetBlock1, octetBlock + offset, rlenBytes);
			retVal = octetBlock1;
		}
		else if(octetBlock.size() < rlenBytes)
		{
			SecByteBlock octetBlock2(rlenBytes);
			memset(octetBlock2, '\x00', rlenBytes);
			size_t offset = rlenBytes - octetBlock.size();
			memcpy(octetBlock2 + offset, octetBlock, rlenBytes - offset);
			retVal = octetBlock2;
		}

		return retVal;
	}

	// Turn a stream of bits into a set of bytes with the same length as an elliptic
	// curve's order.
	SecByteBlock bits2octets(const SecByteBlock& inData, const Integer& curveOrder,
	                        const size_t& curveOrderNumBits) const
	{
		Integer bintTemp = bits2int(inData, (const unsigned int)curveOrderNumBits);
		Integer bint = bintTemp - curveOrder;
		return int2octets(bint.IsNegative() ? bintTemp : bint,
		                  curveOrder.ByteCount());	
	}

	// Get() returns const ref
	const H& GetHash() const { return const_cast<const H&>(hashFunct); }
	const HMAC<H>& GetHMAC() const { return const_cast<const HMAC<H>&>(K); }
	// Access() returns non-const ref
	H& AccessHash() { return hashFunct; }
	HMAC<H>& AccessHMAC() { return K; }
private:
	mutable H hashFunct;
	mutable HMAC<H> K;
};

CRYPTOPP_DLL_TEMPLATE_CLASS DL_Algorithm_GDSA<Integer, SHA256, false>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_Algorithm_GDSA<Integer, SHA256, true>;

//! NR algorithm
template <class T>
class DL_Algorithm_NR : public DL_ElgamalLikeSignatureAlgorithm<T>
{
public:
	static const char * CRYPTOPP_API StaticAlgorithmName() {return "NR";}

	void Sign(const DL_GroupParameters<T> &params, const Integer &x, const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		r = (r + e) % q;
		s = (k - x*r) % q;
		assert(!!r);
	}

	bool Verify(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &e, const Integer &r, const Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		if (r>=q || r<1 || s>=q)
			return false;

		// check r == (m_g^s * m_y^r + m) mod m_q
		return r == (params.ConvertElementToInteger(publicKey.CascadeExponentiateBaseAndPublicElement(s, r)) + e) % q;
	}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_NR() {}
#endif
};

/*! DSA public key format is defined in 7.3.3 of RFC 2459. The
	private key format is defined in 12.9 of PKCS #11 v2.10. */
template <class GP>
class DL_PublicKey_GFP : public DL_PublicKeyImpl<GP>
{
public:
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
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PublicKey_GFP() {}
#endif
};

//! DL private key (in GF(p) groups)
template <class GP>
class DL_PrivateKey_GFP : public DL_PrivateKeyImpl<GP>
{
public:
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
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PrivateKey_GFP() {}
#endif
};

//! DL signing/verification keys (in GF(p) groups)
struct DL_SignatureKeys_GFP
{
	typedef DL_GroupParameters_GFP GroupParameters;
	typedef DL_PublicKey_GFP<GroupParameters> PublicKey;
	typedef DL_PrivateKey_GFP<GroupParameters> PrivateKey;
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_SignatureKeys_GFP() {}
#endif
};

//! DL encryption/decryption keys (in GF(p) groups)
struct DL_CryptoKeys_GFP
{
	typedef DL_GroupParameters_GFP_DefaultSafePrime GroupParameters;
	typedef DL_PublicKey_GFP<GroupParameters> PublicKey;
	typedef DL_PrivateKey_GFP<GroupParameters> PrivateKey;
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_CryptoKeys_GFP() {}
#endif
};

//! provided for backwards compatibility, this class uses the old non-standard Crypto++ key format
template <class BASE>
class DL_PublicKey_GFP_OldFormat : public BASE
{
public:
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
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PublicKey_GFP_OldFormat() {}
#endif
};

//! provided for backwards compatibility, this class uses the old non-standard Crypto++ key format
template <class BASE>
class DL_PrivateKey_GFP_OldFormat : public BASE
{
public:
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
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PrivateKey_GFP_OldFormat() {}
#endif
};

//! <a href="http://www.weidai.com/scan-mirror/sig.html#DSA-1363">DSA-1363</a>
template <class H, bool useDetK = false>
struct GDSA : public DL_SS<
	DL_SignatureKeys_GFP, 
	DL_Algorithm_GDSA<Integer, H, useDetK>, 
	DL_SignatureMessageEncodingMethod_DSA,
	H>
{
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~GDSA() {}
#endif
};

//! <a href="http://www.weidai.com/scan-mirror/sig.html#NR">NR</a>
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

//! DSA group parameters, these are GF(p) group parameters that are allowed by the DSA standard
class CRYPTOPP_DLL DL_GroupParameters_DSA : public DL_GroupParameters_GFP
{
public:
	/*! also checks that the lengths of p and q are allowed by the DSA standard */
	bool ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const;
	/*! parameters: (ModulusSize), or (Modulus, SubgroupOrder, SubgroupGenerator) */
	/*! ModulusSize must be between DSA::MIN_PRIME_LENGTH and DSA::MAX_PRIME_LENGTH, and divisible by DSA::PRIME_LENGTH_MULTIPLE */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);

	static bool CRYPTOPP_API IsValidPrimeLength(unsigned int pbits)
		{return pbits >= MIN_PRIME_LENGTH && pbits <= MAX_PRIME_LENGTH && pbits % PRIME_LENGTH_MULTIPLE == 0;}

	enum {MIN_PRIME_LENGTH = 1024, MAX_PRIME_LENGTH = 3072, PRIME_LENGTH_MULTIPLE = 1024};
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_DSA() {}
#endif
};

template <class H, bool useDetK = false>
class DSA2;

//! DSA keys
struct DL_Keys_DSA
{
	typedef DL_PublicKey_GFP<DL_GroupParameters_DSA> PublicKey;
	typedef DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_GFP<DL_GroupParameters_DSA>, DSA2<SHA> > PrivateKey;
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Keys_DSA() {}
#endif
};

//! <a href="http://en.wikipedia.org/wiki/Digital_Signature_Algorithm">DSA</a>, as specified in FIPS 186-3
// class named DSA2 instead of DSA for backwards compatibility (DSA was a non-template class)
template <class H, bool useDetK>
class DSA2 : public DL_SS<
	DL_Keys_DSA, 
	DL_Algorithm_GDSA<Integer, H, useDetK>, 
	DL_SignatureMessageEncodingMethod_DSA,
	H, 
	DSA2<H, useDetK> >
{
public:
	static std::string CRYPTOPP_API StaticAlgorithmName() {return "DSA/" + (std::string)H::StaticAlgorithmName();}

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	enum {MIN_PRIME_LENGTH = 1024, MAX_PRIME_LENGTH = 3072, PRIME_LENGTH_MULTIPLE = 1024};
#endif

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DSA2() {}
#endif
};

//! DSA with SHA-1, typedef'd for backwards compatibility
typedef DSA2<SHA> DSA;

CRYPTOPP_DLL_TEMPLATE_CLASS DL_PublicKey_GFP<DL_GroupParameters_DSA>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_GFP<DL_GroupParameters_DSA>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_GFP<DL_GroupParameters_DSA>, DSA2<SHA> >;

//! the XOR encryption method, for use with DL-based cryptosystems
template <class MAC, bool DHAES_MODE>
class DL_EncryptionAlgorithm_Xor : public DL_SymmetricEncryptionAlgorithm
{
public:
	bool ParameterSupported(const char *name) const {return strcmp(name, Name::EncodingParameters()) == 0;}
	size_t GetSymmetricKeyLength(size_t plaintextLength) const
		{return plaintextLength + MAC::DEFAULT_KEYLENGTH;}
	size_t GetSymmetricCiphertextLength(size_t plaintextLength) const
		{return plaintextLength + MAC::DIGESTSIZE;}
	size_t GetMaxSymmetricPlaintextLength(size_t ciphertextLength) const
		{return (unsigned int)SaturatingSubtract(ciphertextLength, (unsigned int)MAC::DIGESTSIZE);}
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
			byte L[8] = {0,0,0,0};
			PutWord(false, BIG_ENDIAN_ORDER, L+4, word32(encodingParameters.size()));
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
			byte L[8] = {0,0,0,0};
			PutWord(false, BIG_ENDIAN_ORDER, L+4, word32(encodingParameters.size()));
			mac.Update(L, 8);
		}
		if (!mac.Verify(ciphertext + plaintextLength))
			return DecodingResult();

		if (plaintextLength)	// Coverity finding
			xorbuf(plaintext, ciphertext, cipherKey, plaintextLength);

		return DecodingResult(plaintextLength);
	}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_EncryptionAlgorithm_Xor() {}
#endif
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

//! Discrete Log Integrated Encryption Scheme, AKA <a href="http://www.weidai.com/scan-mirror/ca.html#DLIES">DLIES</a>
template <class COFACTOR_OPTION = NoCofactorMultiplication, bool DHAES_MODE = true>
struct DLIES
	: public DL_ES<
		DL_CryptoKeys_GFP,
		DL_KeyAgreementAlgorithm_DH<Integer, COFACTOR_OPTION>,
		DL_KeyDerivationAlgorithm_P1363<Integer, DHAES_MODE, P1363_KDF2<SHA1> >,
		DL_EncryptionAlgorithm_Xor<HMAC<SHA1>, DHAES_MODE>,
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
