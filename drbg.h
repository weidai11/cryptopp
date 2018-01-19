// drbg.h - written and placed in public domain by Jeffrey Walton.

/// \file drbg.h
/// \brief Classes for NIST DRBGs from SP 800-90A
/// \sa <A HREF="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Recommendation
///   for Random Number Generation Using Deterministic Random Bit Generators, Rev 1 (June 2015)</A>
/// \since Crypto++ 6.0

#ifndef CRYPTOPP_NIST_DRBG_H
#define CRYPTOPP_NIST_DRBG_H

#include "cryptlib.h"
#include "secblock.h"
#include "hmac.h"
#include "sha.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief Interface for NIST DRBGs from SP 800-90A
/// \details NIST_DRBG is the base class interface for NIST DRBGs from SP 800-90A Rev 1 (June 2015)
/// \sa <A HREF="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Recommendation
///   for Random Number Generation Using Deterministic Random Bit Generators, Rev 1 (June 2015)</A>
/// \since Crypto++ 6.0
class NIST_DRBG : public RandomNumberGenerator
{
public:
    /// \brief Exception thrown when a NIST DRBG encounters an error
    class Err : public Exception
    {
    public:
        explicit Err(const std::string &c, const std::string &m)
        : Exception(OTHER_ERROR, c + ": " + m) {}
    };

public:
    virtual ~NIST_DRBG() {}

    /// \brief Determines if a generator can accept additional entropy
    /// \return true
    /// \details All NIST_DRBG return true
    virtual bool CanIncorporateEntropy() const {return true;}

    /// \brief Update RNG state with additional unpredictable values
    /// \param input the entropy to add to the generator
    /// \param length the size of the input buffer
    /// \throws NIST_DRBG::Err if the generator is reseeded with insufficient entropy
    /// \details NIST instantiation and reseed requirements demand the generator is constructed
    ///   with at least <tt>MINIMUM_ENTROPY</tt> entropy. The byte array for <tt>input</tt> must
    ///   meet <A HREF ="http://csrc.nist.gov/publications/PubsSPs.html">NIST SP 800-90B or
    ///   SP 800-90C</A> requirements.
    virtual void IncorporateEntropy(const byte *input, size_t length)=0;

    /// \brief Update RNG state with additional unpredictable values
    /// \param entropy the entropy to add to the generator
    /// \param entropyLength the size of the input buffer
    /// \param additional additional input to add to the generator
    /// \param additionaLength the size of the additional input buffer
    /// \throws NIST_DRBG::Err if the generator is reseeded with insufficient entropy
    /// \details IncorporateEntropy() is an overload provided to match NIST requirements. NIST
    ///   instantiation and reseed requirements demand the generator is constructed with at least
    ///   <tt>MINIMUM_ENTROPY</tt> entropy. The byte array for <tt>entropy</tt> must meet
    ///   <A HREF ="http://csrc.nist.gov/publications/PubsSPs.html">NIST SP 800-90B or
    ///!  SP 800-90C</A> requirements.
    virtual void IncorporateEntropy(const byte *entropy, size_t entropyLength, const byte* additional, size_t additionaLength)=0;

    /// \brief Generate random array of bytes
    /// \param output the byte buffer
    /// \param size the length of the buffer, in bytes
    /// \throws NIST_DRBG::Err if a reseed is required
    /// \throws NIST_DRBG::Err if the size exceeds <tt>MAXIMUM_BYTES_PER_REQUEST</tt>
    virtual void GenerateBlock(byte *output, size_t size)=0;

    /// \brief Generate random array of bytes
    /// \param additional additional input to add to the generator
    /// \param additionaLength the size of the additional input buffer
    /// \param output the byte buffer
    /// \param size the length of the buffer, in bytes
    /// \throws NIST_DRBG::Err if a reseed is required
    /// \throws NIST_DRBG::Err if the size exceeds <tt>MAXIMUM_BYTES_PER_REQUEST</tt>
    /// \details GenerateBlock() is an overload provided to match NIST requirements. The byte
    ///   array for <tt>additional</tt> input is optional. If present the additional randomness
    ///   is mixed before generating the output bytes.
    virtual void GenerateBlock(const byte* additional, size_t additionaLength, byte *output, size_t size)=0;

    /// \brief Provides the security strength
    /// \returns The security strength of the generator, in bytes
    /// \details The equivalent class constant is <tt>SECURITY_STRENGTH</tt>
    virtual unsigned int SecurityStrength() const=0;

    /// \brief Provides the seed length
    /// \returns The seed size of the generator, in bytes
    /// \details The equivalent class constant is <tt>SEED_LENGTH</tt>. The size is
    ///   used to maintain internal state of <tt>V</tt> and <tt>C</tt>.
    virtual unsigned int SeedLength() const=0;

    /// \brief Provides the minimum entropy size
    /// \returns The minimum entropy size required by the generator, in bytes
    /// \details The equivalent class constant is <tt>MINIMUM_ENTROPY</tt>. All NIST DRBGs must
    ///   be instaniated with at least <tt>MINIMUM_ENTROPY</tt> bytes of entropy. The bytes must
    ///   meet <A HREF="http://csrc.nist.gov/publications/PubsSPs.html">NIST SP 800-90B or
    ///   SP 800-90C</A> requirements.
    virtual unsigned int MinEntropyLength() const=0;

    /// \brief Provides the maximum entropy size
    /// \returns The maximum entropy size that can be consumed by the generator, in bytes
    /// \details The equivalent class constant is <tt>MAXIMUM_ENTROPY</tt>. The bytes must
    ///   meet <A HREF="http://csrc.nist.gov/publications/PubsSPs.html">NIST SP 800-90B or
    ///   SP 800-90C</A> requirements. <tt>MAXIMUM_ENTROPY</tt> has been reduced from
    ///   2<sup>35</sup> to <tt>INT_MAX</tt> to fit the underlying C++ datatype.
    virtual unsigned int MaxEntropyLength() const=0;

    /// \brief Provides the minimum nonce size
    /// \returns The minimum nonce size recommended for the generator, in bytes
    /// \details The equivalent class constant is <tt>MINIMUM_NONCE</tt>. If a nonce is not
    ///   required then <tt>MINIMUM_NONCE</tt> is 0. <tt>Hash_DRBG</tt> does not require a
    ///   nonce, while <tt>HMAC_DRBG</tt> and <tt>CTR_DRBG</tt> require a nonce.
    virtual unsigned int MinNonceLength() const=0;

    /// \brief Provides the maximum nonce size
    /// \returns The maximum nonce that can be consumed by the generator, in bytes
    /// \details The equivalent class constant is <tt>MAXIMUM_NONCE</tt>. <tt>MAXIMUM_NONCE</tt>
    ///   has been reduced from 2<sup>35</sup> to <tt>INT_MAX</tt> to fit the underlying C++ datatype.
    ///   If a nonce is not required then <tt>MINIMUM_NONCE</tt> is 0. <tt>Hash_DRBG</tt> does not
    ///   require a nonce, while <tt>HMAC_DRBG</tt> and <tt>CTR_DRBG</tt> require a nonce.
    virtual unsigned int MaxNonceLength() const=0;

    /// \brief Provides the maximum size of a request to GenerateBlock
    /// \returns The the maximum size of a request to GenerateBlock(), in bytes
    /// \details The equivalent class constant is <tt>MAXIMUM_BYTES_PER_REQUEST</tt>
    virtual unsigned int MaxBytesPerRequest() const=0;

    /// \brief Provides the maximum number of requests before a reseed
    /// \returns The the maximum number of requests before a reseed, in bytes
    /// \details The equivalent class constant is <tt>MAXIMUM_REQUESTS_BEFORE_RESEED</tt>.
    ///   <tt>MAXIMUM_REQUESTS_BEFORE_RESEED</tt> has been reduced from 2<sup>48</sup> to <tt>INT_MAX</tt>
    ///   to fit the underlying C++ datatype.
    virtual unsigned int MaxRequestBeforeReseed() const=0;

protected:
    virtual void DRBG_Instantiate(const byte* entropy, size_t entropyLength,
        const byte* nonce, size_t nonceLength, const byte* personalization, size_t personalizationLength)=0;

    virtual void DRBG_Reseed(const byte* entropy, size_t entropyLength, const byte* additional, size_t additionaLength)=0;
};

// *************************************************************

/// \tparam HASH NIST approved hash derived from HashTransformation
/// \tparam STRENGTH security strength, in bytes
/// \tparam SEEDLENGTH seed length, in bytes
/// \brief Hash_DRBG from SP 800-90A Rev 1 (June 2015)
/// \details The NIST Hash DRBG is instantiated with a number of parameters. Two of the parameters,
///   Security Strength and Seed Length, depend on the hash and are specified as template parameters.
///   The remaining parameters are included in the class. The parameters and their values are listed
///   in NIST SP 800-90A Rev. 1, Table 2: Definitions for Hash-Based DRBG Mechanisms (p.38).
/// \details Some parameters have been reduce to fit C++ datatypes. For example, NIST allows upto
///   2<sup>48</sup> requests before a reseed. However, Hash_DRBG limits it to <tt>INT_MAX</tt> due
///   to the limited data range of an int.
/// \sa <A HREF="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Recommendation
///   for Random Number Generation Using Deterministic Random Bit Generators, Rev 1 (June 2015)</A>
/// \since Crypto++ 6.0
template <typename HASH=SHA256, unsigned int STRENGTH=128/8, unsigned int SEEDLENGTH=440/8>
class Hash_DRBG : public NIST_DRBG, public NotCopyable
{
public:
    CRYPTOPP_CONSTANT(SECURITY_STRENGTH=STRENGTH)
    CRYPTOPP_CONSTANT(SEED_LENGTH=SEEDLENGTH)
    CRYPTOPP_CONSTANT(MINIMUM_ENTROPY=STRENGTH)
    CRYPTOPP_CONSTANT(MINIMUM_NONCE=0)
    CRYPTOPP_CONSTANT(MINIMUM_ADDITIONAL=0)
    CRYPTOPP_CONSTANT(MINIMUM_PERSONALIZATION=0)
    CRYPTOPP_CONSTANT(MAXIMUM_ENTROPY=INT_MAX)
    CRYPTOPP_CONSTANT(MAXIMUM_NONCE=INT_MAX)
    CRYPTOPP_CONSTANT(MAXIMUM_ADDITIONAL=INT_MAX)
    CRYPTOPP_CONSTANT(MAXIMUM_PERSONALIZATION=INT_MAX)
    CRYPTOPP_CONSTANT(MAXIMUM_BYTES_PER_REQUEST=65536)
    CRYPTOPP_CONSTANT(MAXIMUM_REQUESTS_BEFORE_RESEED=INT_MAX)

    static std::string StaticAlgorithmName() { return std::string("Hash_DRBG(") + HASH::StaticAlgorithmName() + std::string(")"); }

    /// \brief Construct a Hash DRBG
    /// \param entropy the entropy to instantiate the generator
    /// \param entropyLength the size of the entropy buffer
    /// \param nonce additional input to instantiate the generator
    /// \param nonceLength the size of the nonce buffer
    /// \param personalization additional input to instantiate the generator
    /// \param personalizationLength the size of the personalization buffer
    /// \throws NIST_DRBG::Err if the generator is instantiated with insufficient entropy
    /// \details All NIST DRBGs must be instaniated with at least <tt>MINIMUM_ENTROPY</tt> bytes of entropy.
    ///   The byte array for <tt>entropy</tt> must meet <A HREF ="http://csrc.nist.gov/publications/PubsSPs.html">NIST
    ///   SP 800-90B or SP 800-90C</A> requirements.
    /// \details The <tt>nonce</tt> and <tt>personalization</tt> are optional byte arrays. If <tt>nonce</tt> is supplied,
    ///   then it should be at least <tt>MINIMUM_NONCE</tt> bytes of entropy.
    /// \details An example of instantiating a SHA256 generator is shown below.
    ///   The example provides more entropy than required for SHA256. The <tt>NonblockingRng</tt> meets the
    ///   requirements of <A HREF ="http://csrc.nist.gov/publications/PubsSPs.html">NIST SP 800-90B or SP 800-90C</A>.
    ///   RDRAND() and RDSEED() generators would work as well.
    /// <pre>
    ///    SecByteBlock entropy(48), result(128);
    ///    NonblockingRng prng;
    ///    RandomNumberSource rns(prng, entropy.size(), new ArraySink(entropy, entropy.size()));
    ///
    ///    Hash_DRBG<SHA256, 128/8, 440/8> drbg(entropy, 32, entropy+32, 16);
    ///    drbg.GenerateBlock(result, result.size());
    /// </pre>
    Hash_DRBG(const byte* entropy=NULLPTR, size_t entropyLength=STRENGTH, const byte* nonce=NULLPTR,
        size_t nonceLength=0, const byte* personalization=NULLPTR, size_t personalizationLength=0)
        : NIST_DRBG(), m_c(SEEDLENGTH), m_v(SEEDLENGTH), m_reseed(0)
    {
        if (entropy != NULLPTR && entropyLength != 0)
            DRBG_Instantiate(entropy, entropyLength, nonce, nonceLength, personalization, personalizationLength);
    }

    unsigned int SecurityStrength() const {return SECURITY_STRENGTH;}
    unsigned int SeedLength() const {return SEED_LENGTH;}
    unsigned int MinEntropyLength() const {return MINIMUM_ENTROPY;}
    unsigned int MaxEntropyLength() const {return MAXIMUM_ENTROPY;}
    unsigned int MinNonceLength() const {return MINIMUM_NONCE;}
    unsigned int MaxNonceLength() const {return MAXIMUM_NONCE;}
    unsigned int MaxBytesPerRequest() const {return MAXIMUM_BYTES_PER_REQUEST;}
    unsigned int MaxRequestBeforeReseed() const {return MAXIMUM_REQUESTS_BEFORE_RESEED;}

    void IncorporateEntropy(const byte *input, size_t length)
        {return DRBG_Reseed(input, length, NULLPTR, 0);}

    void IncorporateEntropy(const byte *entropy, size_t entropyLength, const byte* additional, size_t additionaLength)
        {return DRBG_Reseed(entropy, entropyLength, additional, additionaLength);}

    void GenerateBlock(byte *output, size_t size)
        {return Hash_Generate(NULLPTR, 0, output, size);}

    void GenerateBlock(const byte* additional, size_t additionaLength, byte *output, size_t size)
        {return Hash_Generate(additional, additionaLength, output, size);}

protected:
    // 10.1.1.2 Instantiation of Hash_DRBG (p.39)
    void DRBG_Instantiate(const byte* entropy, size_t entropyLength, const byte* nonce, size_t nonceLength,
        const byte* personalization, size_t personalizationLength);

    // 10.1.1.3 Reseeding a Hash_DRBG Instantiation (p.40)
    void DRBG_Reseed(const byte* entropy, size_t entropyLength, const byte* additional, size_t additionaLength);

    // 10.1.1.4 Generating Pseudorandom Bits Using Hash_DRBG (p.41)
    void Hash_Generate(const byte* additional, size_t additionaLength, byte *output, size_t size);

    // 10.3.1 Derivation Function Using a Hash Function (Hash_df) (p.49)
    void Hash_Update(const byte* input1, size_t inlen1, const byte* input2, size_t inlen2,
        const byte* input3, size_t inlen3, const byte* input4, size_t inlen4, byte* output, size_t outlen);

private:
    SecByteBlock m_c, m_v;
    word64 m_reseed;
};

// typedef Hash_DRBG<SHA1,   128/8, 440/8> Hash_SHA1_DRBG;
// typedef Hash_DRBG<SHA256, 128/8, 440/8> Hash_SHA256_DRBG;
// typedef Hash_DRBG<SHA384, 256/8, 888/8> Hash_SHA384_DRBG;
// typedef Hash_DRBG<SHA512, 256/8, 888/8> Hash_SHA512_DRBG;

// *************************************************************

/// \tparam HASH NIST approved hash derived from HashTransformation
/// \tparam STRENGTH security strength, in bytes
/// \tparam SEEDLENGTH seed length, in bytes
/// \brief HMAC_DRBG from SP 800-90A Rev 1 (June 2015)
/// \details The NIST HMAC DRBG is instantiated with a number of parameters. Two of the parameters,
///   Security Strength and Seed Length, depend on the hash and are specified as template parameters.
///   The remaining parameters are included in the class. The parameters and their values are listed
///   in NIST SP 800-90A Rev. 1, Table 2: Definitions for Hash-Based DRBG Mechanisms (p.38).
/// \details Some parameters have been reduce to fit C++ datatypes. For example, NIST allows upto 2<sup>48</sup> requests
///   before a reseed. However, HMAC_DRBG limits it to <tt>INT_MAX</tt> due to the limited data range of an int.
/// \sa <A HREF="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Recommendation
///   for Random Number Generation Using Deterministic Random Bit Generators, Rev 1 (June 2015)</A>
/// \since Crypto++ 6.0
template <typename HASH=SHA256, unsigned int STRENGTH=128/8, unsigned int SEEDLENGTH=440/8>
class HMAC_DRBG : public NIST_DRBG, public NotCopyable
{
public:
    CRYPTOPP_CONSTANT(SECURITY_STRENGTH=STRENGTH)
    CRYPTOPP_CONSTANT(SEED_LENGTH=SEEDLENGTH)
    CRYPTOPP_CONSTANT(MINIMUM_ENTROPY=STRENGTH)
    CRYPTOPP_CONSTANT(MINIMUM_NONCE=0)
    CRYPTOPP_CONSTANT(MINIMUM_ADDITIONAL=0)
    CRYPTOPP_CONSTANT(MINIMUM_PERSONALIZATION=0)
    CRYPTOPP_CONSTANT(MAXIMUM_ENTROPY=INT_MAX)
    CRYPTOPP_CONSTANT(MAXIMUM_NONCE=INT_MAX)
    CRYPTOPP_CONSTANT(MAXIMUM_ADDITIONAL=INT_MAX)
    CRYPTOPP_CONSTANT(MAXIMUM_PERSONALIZATION=INT_MAX)
    CRYPTOPP_CONSTANT(MAXIMUM_BYTES_PER_REQUEST=65536)
    CRYPTOPP_CONSTANT(MAXIMUM_REQUESTS_BEFORE_RESEED=INT_MAX)

    static std::string StaticAlgorithmName() { return std::string("HMAC_DRBG(") + HASH::StaticAlgorithmName() + std::string(")"); }

    /// \brief Construct a HMAC DRBG
    /// \param entropy the entropy to instantiate the generator
    /// \param entropyLength the size of the entropy buffer
    /// \param nonce additional input to instantiate the generator
    /// \param nonceLength the size of the nonce buffer
    /// \param personalization additional input to instantiate the generator
    /// \param personalizationLength the size of the personalization buffer
    /// \throws NIST_DRBG::Err if the generator is instantiated with insufficient entropy
    /// \details All NIST DRBGs must be instaniated with at least <tt>MINIMUM_ENTROPY</tt> bytes of entropy.
    ///   The byte array for <tt>entropy</tt> must meet <A HREF ="http://csrc.nist.gov/publications/PubsSPs.html">NIST
    ///   SP 800-90B or SP 800-90C</A> requirements.
    /// \details The <tt>nonce</tt> and <tt>personalization</tt> are optional byte arrays. If <tt>nonce</tt> is supplied,
    ///   then it should be at least <tt>MINIMUM_NONCE</tt> bytes of entropy.
    /// \details An example of instantiating a SHA256 generator is shown below.
    ///   The example provides more entropy than required for SHA256. The <tt>NonblockingRng</tt> meets the
    ///   requirements of <A HREF ="http://csrc.nist.gov/publications/PubsSPs.html">NIST SP 800-90B or SP 800-90C</A>.
    ///   RDRAND() and RDSEED() generators would work as well.
    /// <pre>
    ///    SecByteBlock entropy(48), result(128);
    ///    NonblockingRng prng;
    ///    RandomNumberSource rns(prng, entropy.size(), new ArraySink(entropy, entropy.size()));
    ///
    ///    HMAC_DRBG<SHA256, 128/8, 440/8> drbg(entropy, 32, entropy+32, 16);
    ///    drbg.GenerateBlock(result, result.size());
    /// </pre>
    HMAC_DRBG(const byte* entropy=NULLPTR, size_t entropyLength=STRENGTH, const byte* nonce=NULLPTR,
        size_t nonceLength=0, const byte* personalization=NULLPTR, size_t personalizationLength=0)
        : NIST_DRBG(), m_k(HASH::DIGESTSIZE), m_v(HASH::DIGESTSIZE), m_reseed(0)
    {
        if (entropy != NULLPTR && entropyLength != 0)
            DRBG_Instantiate(entropy, entropyLength, nonce, nonceLength, personalization, personalizationLength);
    }

    unsigned int SecurityStrength() const {return SECURITY_STRENGTH;}
    unsigned int SeedLength() const {return SEED_LENGTH;}
    unsigned int MinEntropyLength() const {return MINIMUM_ENTROPY;}
    unsigned int MaxEntropyLength() const {return MAXIMUM_ENTROPY;}
    unsigned int MinNonceLength() const {return MINIMUM_NONCE;}
    unsigned int MaxNonceLength() const {return MAXIMUM_NONCE;}
    unsigned int MaxBytesPerRequest() const {return MAXIMUM_BYTES_PER_REQUEST;}
    unsigned int MaxRequestBeforeReseed() const {return MAXIMUM_REQUESTS_BEFORE_RESEED;}

    void IncorporateEntropy(const byte *input, size_t length)
        {return DRBG_Reseed(input, length, NULLPTR, 0);}

    void IncorporateEntropy(const byte *entropy, size_t entropyLength, const byte* additional, size_t additionaLength)
        {return DRBG_Reseed(entropy, entropyLength, additional, additionaLength);}

    void GenerateBlock(byte *output, size_t size)
        {return HMAC_Generate(NULLPTR, 0, output, size);}

    void GenerateBlock(const byte* additional, size_t additionaLength, byte *output, size_t size)
        {return HMAC_Generate(additional, additionaLength, output, size);}

protected:
    // 10.1.2.3 Instantiation of HMAC_DRBG (p.45)
    void DRBG_Instantiate(const byte* entropy, size_t entropyLength, const byte* nonce, size_t nonceLength,
        const byte* personalization, size_t personalizationLength);

    // 10.1.2.4 Reseeding a HMAC_DRBG Instantiation (p.46)
    void DRBG_Reseed(const byte* entropy, size_t entropyLength, const byte* additional, size_t additionaLength);

    // 10.1.2.5 Generating Pseudorandom Bits Using HMAC_DRBG (p.46)
    void HMAC_Generate(const byte* additional, size_t additionaLength, byte *output, size_t size);

    // 10.1.2.2 Derivation Function Using a HMAC Function (HMAC_Update) (p.44)
    void HMAC_Update(const byte* input1, size_t inlen1, const byte* input2, size_t inlen2, const byte* input3, size_t inlen3);

private:
    SecByteBlock m_k, m_v;
    word64 m_reseed;
};

// typedef HMAC_DRBG<SHA1,   128/8, 440/8> HMAC_SHA1_DRBG;
// typedef HMAC_DRBG<SHA256, 128/8, 440/8> HMAC_SHA256_DRBG;
// typedef HMAC_DRBG<SHA384, 256/8, 888/8> HMAC_SHA384_DRBG;
// typedef HMAC_DRBG<SHA512, 256/8, 888/8> HMAC_SHA512_DRBG;

// *************************************************************

// 10.1.1.2 Instantiation of Hash_DRBG (p.39)
template <typename HASH, unsigned int STRENGTH, unsigned int SEEDLENGTH>
void Hash_DRBG<HASH, STRENGTH, SEEDLENGTH>::DRBG_Instantiate(const byte* entropy, size_t entropyLength, const byte* nonce, size_t nonceLength,
    const byte* personalization, size_t personalizationLength)
{
    //  SP 800-90A, 8.6.3: The entropy input shall have entropy that is equal to or greater than the security
    //  strength of the instantiation. Additional entropy may be provided in the nonce or the optional
    //  personalization string during instantiation, or in the additional input during reseeding and generation,
    //  but this is not required and does not increase the "official" security strength of the DRBG
    //  instantiation that is recorded in the internal state.
    CRYPTOPP_ASSERT(entropyLength >= MINIMUM_ENTROPY);
    if (entropyLength < MINIMUM_ENTROPY)
        throw NIST_DRBG::Err("Hash_DRBG", "Insufficient entropy during instantiate");

    // SP 800-90A, Section 9, says we should throw if we have too much entropy, too large a nonce,
    // or too large a persoanlization string. We warn in Debug builds, but do nothing in Release builds.
    CRYPTOPP_ASSERT(entropyLength <= MAXIMUM_ENTROPY);
    CRYPTOPP_ASSERT(nonceLength <= MAXIMUM_NONCE);
    CRYPTOPP_ASSERT(personalizationLength <= MAXIMUM_PERSONALIZATION);

    const byte zero = 0;
    SecByteBlock t1(SEEDLENGTH), t2(SEEDLENGTH);
    Hash_Update(entropy, entropyLength, nonce, nonceLength, personalization, personalizationLength, NULLPTR, 0, t1, t1.size());
    Hash_Update(&zero, 1, t1, t1.size(), NULLPTR, 0, NULLPTR, 0, t2, t2.size());

    m_v.swap(t1); m_c.swap(t2);
    m_reseed = 1;
}

// 10.1.1.3 Reseeding a Hash_DRBG Instantiation (p.40)
template <typename HASH, unsigned int STRENGTH, unsigned int SEEDLENGTH>
void Hash_DRBG<HASH, STRENGTH, SEEDLENGTH>::DRBG_Reseed(const byte* entropy, size_t entropyLength, const byte* additional, size_t additionaLength)
{
    //  SP 800-90A, 8.6.3: The entropy input shall have entropy that is equal to or greater than the security
    //  strength of the instantiation. Additional entropy may be provided in the nonce or the optional
    //  personalization string during instantiation, or in the additional input during reseeding and generation,
    //  but this is not required and does not increase the "official" security strength of the DRBG
    //  instantiation that is recorded in the internal state..
    CRYPTOPP_ASSERT(entropyLength >= MINIMUM_ENTROPY);
    if (entropyLength < MINIMUM_ENTROPY)
        throw NIST_DRBG::Err("Hash_DRBG", "Insufficient entropy during reseed");

    // SP 800-90A, Section 9, says we should throw if we have too much entropy, too large a nonce,
    // or too large a persoanlization string. We warn in Debug builds, but do nothing in Release builds.
    CRYPTOPP_ASSERT(entropyLength <= MAXIMUM_ENTROPY);
    CRYPTOPP_ASSERT(additionaLength <= MAXIMUM_ADDITIONAL);

    const byte zero = 0, one = 1;
    SecByteBlock t1(SEEDLENGTH), t2(SEEDLENGTH);
    Hash_Update(&one, 1, m_v, m_v.size(), entropy, entropyLength, additional, additionaLength, t1, t1.size());
    Hash_Update(&zero, 1, t1, t1.size(), NULLPTR, 0, NULLPTR, 0, t2, t2.size());

    m_v.swap(t1); m_c.swap(t2);
    m_reseed = 1;
}

// 10.1.1.4 Generating Pseudorandom Bits Using Hash_DRBG (p.41)
template <typename HASH, unsigned int STRENGTH, unsigned int SEEDLENGTH>
void Hash_DRBG<HASH, STRENGTH, SEEDLENGTH>::Hash_Generate(const byte* additional, size_t additionaLength, byte *output, size_t size)
{
    // Step 1
    if (static_cast<word64>(m_reseed) >= static_cast<word64>(MaxRequestBeforeReseed()))
        throw NIST_DRBG::Err("Hash_DRBG", "Reseed required");

    if (size > MaxBytesPerRequest())
        throw NIST_DRBG::Err("Hash_DRBG", "Request size exceeds limit");

    // SP 800-90A, Section 9, says we should throw if we have too much entropy, too large a nonce,
    // or too large a persoanlization string. We warn in Debug builds, but do nothing in Release builds.
    CRYPTOPP_ASSERT(additionaLength <= MAXIMUM_ADDITIONAL);

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
        int carry=0, j=HASH::DIGESTSIZE-1, i=SEEDLENGTH-1;
        while (j>=0)
        {
            carry = m_v[i] + w[j] + carry;
            m_v[i] = static_cast<byte>(carry);
            i--; j--; carry >>= 8;
        }
        while (i>=0)
        {
            carry = m_v[i] + carry;
            m_v[i] = static_cast<byte>(carry);
            i--; carry >>= 8;
        }
    }

    // Step 3
    {
        HASH hash;
        SecByteBlock data(m_v);

        while (size)
        {
            hash.Update(data, data.size());
            size_t count = STDMIN(size, (size_t)HASH::DIGESTSIZE);
            hash.TruncatedFinal(output, count);

            IncrementCounterByOne(data, static_cast<unsigned int>(data.size()));
            size -= count; output += count;
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
        int carry=0, k=sizeof(m_reseed)-1, j=HASH::DIGESTSIZE-1, i=SEEDLENGTH-1;

        // Using Integer class slows things down by about 8 cpb.
        // Using word128 and word64 benefits the first loop only by about 2 cpb.
#if defined(CRYPTOPP_WORD128_AVAILABLE)
        byte* p1 = m_v.begin()+SEEDLENGTH-8;
        byte* p2 = m_c.begin()+SEEDLENGTH-8;
        byte* p3 = h.begin()+HASH::DIGESTSIZE-8;

        const word64 w1 = GetWord<word64>(false, BIG_ENDIAN_ORDER, p1);
        const word64 w2 = GetWord<word64>(false, BIG_ENDIAN_ORDER, p2);
        const word64 w3 = GetWord<word64>(false, BIG_ENDIAN_ORDER, p3);
        const word64 w4 = m_reseed;

        word128 r = static_cast<word128>(w1) + w2 + w3 + w4;
        PutWord(false, BIG_ENDIAN_ORDER, p1, static_cast<word64>(r));
        i -= 8; j -= 8; k=0; carry = static_cast<int>(r >> 64);

        // The default implementation and a couple of others cause a crash in
        // VS2005, VS2008 and VS2105. This seems to work with all MS compilers.
#elif defined(CRYPTOPP_MSC_VERSION)
        byte* p1 = m_v.begin()+SEEDLENGTH-8;
        byte* p2 = m_c.begin()+SEEDLENGTH-8;
        byte* p3 = h.begin()+HASH::DIGESTSIZE-8;

        const word64 w1 = GetWord<word64>(false, BIG_ENDIAN_ORDER, p1);
        const word64 w2 = GetWord<word64>(false, BIG_ENDIAN_ORDER, p2);
        const word64 w3 = GetWord<word64>(false, BIG_ENDIAN_ORDER, p3);
        const word64 w4 = m_reseed;

        const word64 r1 = (w1 & 0xffffffff) + (w2 & 0xffffffff) + (w3 & 0xffffffff) + (w4 & 0xffffffff);
        carry = static_cast<int>(r1 >> 32);
        const word64 r2 = (w1 >> 32) + (w2 >> 32) + (w3 >> 32) + (w4 >> 32) + carry;
        carry = static_cast<int>(r2 >> 32);

        const word64 r = (r2 << 32) + (r1 & 0xffffffff);
        PutWord(false, BIG_ENDIAN_ORDER, p1, r);
        i -= 8; j -= 8; k=0;

        // Default implementation, but slower on some machines.
#else
        while (k>=0)
        {
            carry = m_v[i] + m_c[i] + h[j] + GetByte<word64>(BIG_ENDIAN_ORDER, m_reseed, k) + carry;
            m_v[i] = static_cast<byte>(carry);
            i--; j--; k--; carry >>= 8;
        }
#endif

        while (j>=0)
        {
            carry = m_v[i] + m_c[i] + h[j] + carry;
            m_v[i] = static_cast<byte>(carry);
            i--; j--; carry >>= 8;
        }

        while (i>=0)
        {
            carry = m_v[i] + m_c[i] + carry;
            m_v[i] = static_cast<byte>(carry);
            i--; carry >>= 8;
        }

        // CRYPTOPP_WORD128_AVAILABLE causes -Wunused-but-set-variable
        CRYPTOPP_UNUSED(k);
    }

    m_reseed++;
}

// 10.3.1 Derivation Function Using a Hash Function (Hash_df) (p.49)
template <typename HASH, unsigned int STRENGTH, unsigned int SEEDLENGTH>
void Hash_DRBG<HASH, STRENGTH, SEEDLENGTH>::Hash_Update(const byte* input1, size_t inlen1, const byte* input2, size_t inlen2,
    const byte* input3, size_t inlen3, const byte* input4, size_t inlen4, byte* output, size_t outlen)
{
    HASH hash;
    byte counter = 1;
    word32 bits = ConditionalByteReverse(BIG_ENDIAN_ORDER, static_cast<word32>(outlen*8));

    while (outlen)
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

        size_t count = STDMIN(outlen, (size_t)HASH::DIGESTSIZE);
        hash.TruncatedFinal(output, count);

        output += count; outlen -= count;
        counter++;
    }
}

// *************************************************************

// 10.1.2.3 Instantiation of HMAC_DRBG (p.45)
template <typename HASH, unsigned int STRENGTH, unsigned int SEEDLENGTH>
void HMAC_DRBG<HASH, STRENGTH, SEEDLENGTH>::DRBG_Instantiate(const byte* entropy, size_t entropyLength, const byte* nonce, size_t nonceLength,
    const byte* personalization, size_t personalizationLength)
{
    //  SP 800-90A, 8.6.3: The entropy input shall have entropy that is equal to or greater than the security
    //  strength of the instantiation. Additional entropy may be provided in the nonce or the optional
    //  personalization string during instantiation, or in the additional input during reseeding and generation,
    //  but this is not required and does not increase the "official" security strength of the DRBG
    //  instantiation that is recorded in the internal state.
    CRYPTOPP_ASSERT(entropyLength >= MINIMUM_ENTROPY);
    if (entropyLength < MINIMUM_ENTROPY)
        throw NIST_DRBG::Err("HMAC_DRBG", "Insufficient entropy during instantiate");

    // SP 800-90A, Section 9, says we should throw if we have too much entropy, too large a nonce,
    // or too large a persoanlization string. We warn in Debug builds, but do nothing in Release builds.
    CRYPTOPP_ASSERT(entropyLength <= MAXIMUM_ENTROPY);
    CRYPTOPP_ASSERT(nonceLength <= MAXIMUM_NONCE);
    CRYPTOPP_ASSERT(personalizationLength <= MAXIMUM_PERSONALIZATION);

    std::fill(m_k.begin(), m_k.begin()+m_k.size(), byte(0));
    std::fill(m_v.begin(), m_v.begin()+m_v.size(), byte(1));

    HMAC_Update(entropy, entropyLength, nonce, nonceLength, personalization, personalizationLength);
    m_reseed = 1;
}

// 10.1.2.4 Reseeding a HMAC_DRBG Instantiation (p.46)
template <typename HASH, unsigned int STRENGTH, unsigned int SEEDLENGTH>
void HMAC_DRBG<HASH, STRENGTH, SEEDLENGTH>::DRBG_Reseed(const byte* entropy, size_t entropyLength, const byte* additional, size_t additionaLength)
{
    //  SP 800-90A, 8.6.3: The entropy input shall have entropy that is equal to or greater than the security
    //  strength of the instantiation. Additional entropy may be provided in the nonce or the optional
    //  personalization string during instantiation, or in the additional input during reseeding and generation,
    //  but this is not required and does not increase the "official" security strength of the DRBG
    //  instantiation that is recorded in the internal state..
    CRYPTOPP_ASSERT(entropyLength >= MINIMUM_ENTROPY);
    if (entropyLength < MINIMUM_ENTROPY)
        throw NIST_DRBG::Err("HMAC_DRBG", "Insufficient entropy during reseed");

    // SP 800-90A, Section 9, says we should throw if we have too much entropy, too large a nonce,
    // or too large a persoanlization string. We warn in Debug builds, but do nothing in Release builds.
    CRYPTOPP_ASSERT(entropyLength <= MAXIMUM_ENTROPY);
    CRYPTOPP_ASSERT(additionaLength <= MAXIMUM_ADDITIONAL);

    HMAC_Update(entropy, entropyLength, additional, additionaLength, NULLPTR, 0);
    m_reseed = 1;
}

// 10.1.2.5 Generating Pseudorandom Bits Using HMAC_DRBG (p.46)
template <typename HASH, unsigned int STRENGTH, unsigned int SEEDLENGTH>
void HMAC_DRBG<HASH, STRENGTH, SEEDLENGTH>::HMAC_Generate(const byte* additional, size_t additionaLength, byte *output, size_t size)
{
    // Step 1
    if (static_cast<word64>(m_reseed) >= static_cast<word64>(MaxRequestBeforeReseed()))
        throw NIST_DRBG::Err("HMAC_DRBG", "Reseed required");

    if (size > MaxBytesPerRequest())
        throw NIST_DRBG::Err("HMAC_DRBG", "Request size exceeds limit");

    // SP 800-90A, Section 9, says we should throw if we have too much entropy, too large a nonce,
    // or too large a persoanlization string. We warn in Debug builds, but do nothing in Release builds.
    CRYPTOPP_ASSERT(additionaLength <= MAXIMUM_ADDITIONAL);

    // Step 2
    if (additional && additionaLength)
        HMAC_Update(additional, additionaLength, NULLPTR, 0, NULLPTR, 0);

    // Step 3
    HMAC<HASH> hmac;
    hmac.SetKey(m_k, m_k.size());

    while (size)
    {
        hmac.Update(m_v, m_v.size());
        hmac.TruncatedFinal(m_v, m_v.size());

        size_t count = STDMIN(size, (size_t)HASH::DIGESTSIZE);
        memcpy(output, m_v, count);

        size -= count; output += count;
    }

    HMAC_Update(additional, additionaLength, NULLPTR, 0, NULLPTR, 0);
    m_reseed++;
}

// 10.1.2.2 Derivation Function Using a HMAC Function (HMAC_Update) (p.44)
template <typename HASH, unsigned int STRENGTH, unsigned int SEEDLENGTH>
void HMAC_DRBG<HASH, STRENGTH, SEEDLENGTH>::HMAC_Update(const byte* input1, size_t inlen1, const byte* input2, size_t inlen2, const byte* input3, size_t inlen3)
{
    const byte zero = 0, one = 1;
    HMAC<HASH> hmac;

    // Step 1
    hmac.SetKey(m_k, m_k.size());
    hmac.Update(m_v, m_v.size());
    hmac.Update(&zero, 1);

    if (input1 && inlen1)
        hmac.Update(input1, inlen1);
    if (input2 && inlen2)
        hmac.Update(input2, inlen2);
    if (input3 && inlen3)
        hmac.Update(input3, inlen3);

    hmac.TruncatedFinal(m_k, m_k.size());

    // Step 2
    hmac.SetKey(m_k, m_k.size());
    hmac.Update(m_v, m_v.size());

    hmac.TruncatedFinal(m_v, m_v.size());

    // Step 3
    if ((inlen1 | inlen2 | inlen3) == 0)
        return;

    // Step 4
    hmac.SetKey(m_k, m_k.size());
    hmac.Update(m_v, m_v.size());
    hmac.Update(&one, 1);

    if (input1 && inlen1)
        hmac.Update(input1, inlen1);
    if (input2 && inlen2)
        hmac.Update(input2, inlen2);
    if (input3 && inlen3)
        hmac.Update(input3, inlen3);

    hmac.TruncatedFinal(m_k, m_k.size());

    // Step 5
    hmac.SetKey(m_k, m_k.size());
    hmac.Update(m_v, m_v.size());

    hmac.TruncatedFinal(m_v, m_v.size());
}

NAMESPACE_END

#endif  // CRYPTOPP_NIST_DRBG_H
