// drbg.h - written and placed in public domain by Jeffrey Walton.
//          Copyright assigned to Crypto++ project.

//! \file drbg.h
//! \brief Classes for NIST DRBGs from 800-90A Rev 1 (June 2015)
//! \sa <A HREF="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Recommendation
//!   for Random Number Generation Using Deterministic Random Bit Generators</A>
//! \since Crypto++ 5.7

#ifndef CRYPTOPP_NIST_DETERMINISTIC_RANDOM_BIT_GENERATORS_H
#define CRYPTOPP_NIST_DETERMINISTIC_RANDOM_BIT_GENERATORS_H

#include "cryptlib.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

class NIST_DRBG : public RandomNumberGenerator
{
public:
	virtual ~NIST_DRBG() {}

	// RandomNumberGenerator
	virtual bool CanIncorporateEntropy() const {return true;}
	// RandomNumberGenerator
	virtual void IncorporateEntropy(const byte *input, size_t length)=0;
	// RandomNumberGenerator NIST overload
	virtual void IncorporateEntropy(const byte *entropy, size_t entropyLength, const byte* additional, size_t additionaLength)=0;
	// RandomNumberGenerator
	virtual void GenerateBlock(byte *output, size_t size)=0;
	// RandomNumberGenerator NIST overload
	virtual void GenerateBlock(const byte* additional, size_t additionaLength, byte *output, size_t size)=0;

	virtual unsigned int GetSecurityStrength() const=0;
	virtual unsigned int GetSeedLength() const=0;
	virtual unsigned int GetMinEntropy() const=0;
	virtual unsigned int GetMaxEntropy() const=0;
	virtual unsigned int GetMaxRequest() const=0;
	virtual unsigned int GetMaxReseed() const=0;

protected:

	virtual void DRBG_Instantiate(const byte* entropy, size_t entropyLength,
		const byte* nonce, size_t nonceLength, const byte* persoanlization, size_t personalizationLength)=0;

	virtual void DRBG_Reseed(const byte* entropy, size_t entropyLength, const byte* additional, size_t additionaLength)=0;
};

//! \class Hash_DRBG
//! \tparam HASH NIST approved hash derived from HashTransformation
//! \tparam STRENGTH security strength, in bytes
//! \tparam SEEDLENGTH seed length, in bytes
//! \brief Classes for NIST DRBGs from 800-90A Rev 1 (June 2015)
//! \details The NIST Hash DRBG is instantiated with a number of parameters. Two of the parameters,
//!   Security Strength and Seed Length, depend on the hash and are specified as template parameters.
//!   The remaining parameters are included in the class. The parameters and their values are listed
//!   in NIST SP 800-90A Rev. 1, Table 2: Definitions for Hash-Based DRBG Mechanisms (p.38).
//! \sa <A HREF="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Recommendation
//!   for Random Number Generation Using Deterministic Random Bit Generators</A>
//! \since Crypto++ 5.7
template <typename HASH=SHA256, unsigned int STRENGTH=128/8, unsigned int SEEDLENGTH=440/8>
class Hash_DRBG : public NIST_DRBG
{
public:
	CRYPTOPP_CONSTANT(SECURITY_STRENGTH=STRENGTH)
	CRYPTOPP_CONSTANT(SEED_LENGTH=SEEDLENGTH)
	CRYPTOPP_CONSTANT(MINIMUM_ENTROPY=STRENGTH)

	Hash_DRBG(const byte* entropy, size_t entropyLength=STRENGTH, const byte* nonce=NULL,
		size_t nonceLength=0, const byte* persoanlization=NULL, size_t persoanlizationLength=0)
		: NIST_DRBG(), m_c(SEEDLENGTH), m_v(SEEDLENGTH)
	{
		DRBG_Instantiate(entropy, entropyLength, nonce, nonceLength, persoanlization, persoanlizationLength);
	}

	unsigned int GetSecurityStrength() const {return SECURITY_STRENGTH;}
	unsigned int GetSeedLength() const {return SEED_LENGTH;}
	unsigned int GetMinEntropy() const {return SECURITY_STRENGTH;}
	unsigned int GetMaxEntropy() const {return (unsigned int)STDMIN((word64)UINT_MAX, W64LIT(4294967296));}
	unsigned int GetMaxRequest() const {return 65536;} // 2^16 bytes per request
	unsigned int GetMaxReseed() const {return (unsigned int)STDMIN((word64)UINT_MAX, W64LIT(35184372088832));}

	void IncorporateEntropy(const byte *input, size_t length)
		{return DRBG_Reseed(input, length, NULL, 0);}

	void IncorporateEntropy(const byte *entropy, size_t entropyLength, const byte* additional, size_t additionaLength)
		{return DRBG_Reseed(entropy, entropyLength, additional, additionaLength);}

	void GenerateBlock(byte *output, size_t size)
		{return Hash_Generate(NULL, 0, output, size);}

	void GenerateBlock(const byte* additional, size_t additionaLength, byte *output, size_t size)
		{return Hash_Generate(additional, additionaLength, output, size);}

protected:
	// 10.3.1 Derivation Function Using a Hash Function (Hash_df) (p.58)
	void Hash_df(const byte* input1, size_t inlen1, const byte* input2, size_t inlen2,
		const byte* input3, size_t inlen3, const byte* input4, size_t inlen4, byte* output, size_t outlen)
	{
		HASH hash;
		byte counter = 1;
		word32 bits = ConditionalByteReverse(BIG_ENDIAN_ORDER, static_cast<word32>(outlen*8));

		size_t count;
		for (count=0; outlen; outlen -= count, output += count, counter++)
		{
			hash.Update(&counter, 1);
			hash.Update(reinterpret_cast<const byte*>(&bits), 4);

			if (input1 && inlen1)
				hash.Update(input1, inlen1);
			if (input2 && inlen2)
				hash.Update(input2, inlen2);
			if (input3 && inlen3)
				hash.Update(input3, inlen3);
			if (input4 && inlen4)
				hash.Update(input4, inlen4);

			count = STDMIN(outlen, (size_t)HASH::DIGESTSIZE);
			hash.TruncatedFinal(output, count);
		}
	}

	// 10.1.1.2 Instantiation of Hash_DRBG (p.48)
	void DRBG_Instantiate(const byte* entropy, size_t entropyLength, const byte* nonce, size_t nonceLength,
		const byte* persoanlization, size_t persoanlizationLength)
	{
		CRYPTOPP_ASSERT(entropyLength+nonceLength+persoanlizationLength >= GetMinEntropy());

		const byte zero = 0;
		SecByteBlock t1(SEEDLENGTH), t2(SEEDLENGTH);
		Hash_df(entropy, entropyLength, nonce, nonceLength, persoanlization, persoanlizationLength, NULL, 0, t1, t1.size());
		Hash_df(&zero, 1, t1, t1.size(), NULL, 0, NULL, 0, t2, t2.size());

		m_v.swap(t1); m_c.swap(t2);
		m_reseed = 1;
	}

	// 10.1.1.3 Reseeding a Hash_DRBG Instantiation (p.49)
	void DRBG_Reseed(const byte* entropy, size_t entropyLength, const byte* additional, size_t additionaLength)
	{
		const byte zero = 0, one = 1;
		SecByteBlock t1(SEEDLENGTH), t2(SEEDLENGTH);
		Hash_df(&one, 1, m_v, m_v.size(), entropy, entropyLength, additional, additionaLength, t1, t1.size());
		Hash_df(&zero, 1, t1, t1.size(), NULL, 0, NULL, 0, t2, t2.size());

		m_v.swap(t1); m_c.swap(t2);
		m_reseed = 1;
	}

	// 10.1.1.4 Generating Pseudorandom Bits Using Hash_DRBG (p.50)
	void Hash_Generate(const byte* additional, size_t additionaLength, byte *output, size_t size)
	{
		// Step 1
		if (static_cast<word64>(m_reseed) >= static_cast<word64>(GetMaxReseed()))
			throw Exception(Exception::OTHER_ERROR, "Reseed required");

		// Step 2
		if (additional && additionaLength)
		{
			HASH hash;
			const byte two = 2;
			SecByteBlock w(HASH::DIGESTSIZE);

			hash.Update(&two, 1);
			hash.Update(m_v, m_v.size());
			hash.Update(additional, additionaLength);
			hash.Final(w);

			CRYPTOPP_ASSERT(SEEDLENGTH >= HASH::DIGESTSIZE);
			int carry=0, i=SEEDLENGTH-1, j=HASH::DIGESTSIZE-1;
			while(i>=0 && j>=0)
			{
				carry = m_v[i] + w[j] + carry;
				m_v[i] = static_cast<byte>(carry);
				carry >>= 8; i--; j--;
			}
			while (carry && i>=0)
			{
				carry = m_v[i] + carry;
				m_v[i] = static_cast<byte>(carry);
				carry >>= 8; i--;
			}
		}

		// Step 3
		{
			HASH hash;
			SecByteBlock data(m_v);

			size_t count;
			for (count = 0; size; size -= count, output += count)
			{
				hash.Update(data, data.size());
				count = STDMIN(size, (size_t)HASH::DIGESTSIZE);
				hash.TruncatedFinal(output, count);

				IncrementCounterByOne(data, static_cast<unsigned int>(data.size()));
			}
		}

		// Steps 4-7
		{
			HASH hash;
			const byte three = 3;
			SecByteBlock h(HASH::DIGESTSIZE);

			hash.Update(&three, 1);
			hash.Update(m_v, m_v.size());
			hash.Final(h);

			CRYPTOPP_ASSERT(SEEDLENGTH >= HASH::DIGESTSIZE);
			CRYPTOPP_ASSERT(HASH::DIGESTSIZE >= sizeof(m_reseed));
			int carry=0, i=SEEDLENGTH-1, j=HASH::DIGESTSIZE-1, k=sizeof(m_reseed)-1;
			while(i>=0 && j>=0 && k>=0)
			{
				carry = m_v[i] + m_c[i] + h[j] + GetByte<word64>(BIG_ENDIAN_ORDER, m_reseed, k) + carry;
				m_v[i] = static_cast<byte>(carry);
				carry >>= 8; i--; j--; k--;
			}
			while(i>=0 && j>=0)
			{
				carry = m_v[i] + m_c[i] + h[j] + carry;
				m_v[i] = static_cast<byte>(carry);
				carry >>= 8; i--; j--;
			}
			while (i>=0)
			{
				carry = m_v[i] + m_c[i] + carry;
				m_v[i] = static_cast<byte>(carry);
				carry >>= 8; i--;
			}
		}

		m_reseed++;
	}

private:
	SecByteBlock m_c, m_v;
	word64 m_reseed;
};

NAMESPACE_END

#endif  // CRYPTOPP_NIST_DETERMINISTIC_RANDOM_BIT_GENERATORS_H
