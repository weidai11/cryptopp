#ifndef CRYPTOPP_RABIN_H
#define CRYPTOPP_RABIN_H

/** \file
*/

#include "oaep.h"
#include "pssr.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

//! Rabin
class RabinFunction : public TrapdoorFunction, public PublicKey
{
	typedef RabinFunction ThisClass;

public:
	void Initialize(const Integer &n, const Integer &r, const Integer &s)
		{m_n = n; m_r = r; m_s = s;}

	void BERDecode(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	Integer ApplyFunction(const Integer &x) const;
	Integer PreimageBound() const {return m_n;}
	Integer ImageBound() const {return m_n;}

	bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);

	const Integer& GetModulus() const {return m_n;}
	const Integer& GetQuadraticResidueModPrime1() const {return m_r;}
	const Integer& GetQuadraticResidueModPrime2() const {return m_s;}

	void SetModulus(const Integer &n) {m_n = n;}
	void SetQuadraticResidueModPrime1(const Integer &r) {m_r = r;}
	void SetQuadraticResidueModPrime2(const Integer &s) {m_s = s;}

protected:
	Integer m_n, m_r, m_s;
};

//! Invertible Rabin
class InvertibleRabinFunction : public RabinFunction, public TrapdoorFunctionInverse, public PrivateKey
{
	typedef InvertibleRabinFunction ThisClass;

public:
	void Initialize(const Integer &n, const Integer &r, const Integer &s,
							const Integer &p, const Integer &q, const Integer &u)
		{m_n = n; m_r = r; m_s = s; m_p = p; m_q = q; m_u = u;}
	void Initialize(RandomNumberGenerator &rng, unsigned int keybits)
		{GenerateRandomWithKeySize(rng, keybits);}

	void BERDecode(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	Integer CalculateInverse(const Integer &x) const;

	bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);
	/*! parameters: (ModulusSize) */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);

	const Integer& GetPrime1() const {return m_p;}
	const Integer& GetPrime2() const {return m_q;}
	const Integer& GetMultiplicativeInverseOfPrime2ModPrime1() const {return m_u;}

	void SetPrime1(const Integer &p) {m_p = p;}
	void SetPrime2(const Integer &q) {m_q = q;}
	void SetMultiplicativeInverseOfPrime2ModPrime1(const Integer &u) {m_u = u;}

protected:
	Integer m_p, m_q, m_u;
};

//! .
struct Rabin
{
	static std::string StaticAlgorithmName() {return "Rabin-Crypto++Variant";}
	typedef RabinFunction PublicKey;
	typedef InvertibleRabinFunction PrivateKey;
};

//! .
template <class STANDARD>
struct RabinES : public TF_ES<STANDARD, Rabin>
{
};

//! .
template <class EM>
struct RabinSSR
{
	typedef PK_FinalTemplate<SignerWithRecoveryTemplate<InvertibleRabinFunction, EM> > Signer;
	typedef PK_FinalTemplate<VerifierWithRecoveryTemplate<RabinFunction, EM> > Verifier;
};

//! .
template <class H>
struct RabinPSSR : public RabinSSR<PSSR<H> >
{
};

class SHA;

// More typedefs for backwards compatibility

typedef RabinES<OAEP<SHA> >::Decryptor RabinDecryptor;
typedef RabinES<OAEP<SHA> >::Encryptor RabinEncryptor;

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
// simulate template typedef
#define RabinSignerWith(H) RabinPSSR<H>::Signer
#define RabinVerifierWith(H) RabinPSSR<H>::Verifier
#endif

NAMESPACE_END

#endif
