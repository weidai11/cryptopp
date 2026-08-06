// argon2.h - written and placed in public domain by Colin Brown.
//            Based on Argon2 designed by Alex Biryukov, Daniel Dinu,
//            Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves.
//            Reference implementation at http://github.com/P-H-C/phc-winner-argon2.

/// \file argon2.h
/// \brief Classes for Argon2 password based key derivation function
/// \details This implementation provides all three Argon2 variants (Argon2d, Argon2i, and Argon2id)
///   as specified in RFC 9106. Argon2 is a memory-hard password hashing and key derivation function
///   designed to resist GPU cracking attacks, side-channel attacks, and time-memory trade-offs.
/// \sa <A HREF="https://tools.ietf.org/html/rfc9106">RFC 9106, Argon2 Memory-Hard Function for
///   Password Hashing and Proof-of-Work Applications</A>,
///   <A HREF="https://github.com/P-H-C/phc-winner-argon2">PHC Argon2 Reference Implementation</A>
/// \since Crypto++ 8.8

#ifndef CRYPTOPP_ARGON2_H
#define CRYPTOPP_ARGON2_H

#include "cryptlib.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief Argon2 password based key derivation function
/// \details Argon2 is a memory-hard password hashing function designed to resist GPU cracking
///   attacks, side-channel attacks, and time-memory trade-offs. This implementation supports
///   all three variants:
///   - Argon2d: Data-dependent addressing for GPU resistance (suitable for cryptocurrencies)
///   - Argon2i: Data-independent addressing with side-channel resistance (suitable for password hashing)
///   - Argon2id: Hybrid approach combining Argon2i and Argon2d (recommended for most use cases)
/// \details The Crypto++ implementation uses OpenMP to accelerate the derivation when available.
/// \details RFC 9106 recommends Argon2id with t=1 and 2 GiB memory for most use cases, or t=3
///   and 64 MiB memory for memory-constrained environments.
/// \sa <A HREF="https://tools.ietf.org/html/rfc9106">RFC 9106, Argon2 Memory-Hard Function for
///   Password Hashing and Proof-of-Work Applications</A>
/// \since Crypto++ 8.8
class Argon2 : public KeyDerivationFunction
{
public:
    /// \brief Argon2 variant selection
    /// \details Argon2 supports three variants with different security properties
    enum Variant {
        /// \brief Argon2d - data-dependent addressing, resistant to GPU attacks
        /// \details Faster but vulnerable to side-channel attacks. Best for cryptocurrencies
        ///   and applications without side-channel threats.
        ARGON2D = 0,

        /// \brief Argon2i - data-independent addressing, resistant to side-channel attacks
        /// \details Slower than Argon2d but provides protection against timing attacks.
        ///   Suitable for password hashing where side-channel attacks are a concern.
        ARGON2I = 1,

        /// \brief Argon2id - hybrid of Argon2i and Argon2d (recommended)
        /// \details Uses Argon2i for the first half pass and Argon2d for the rest.
        ///   RFC 9106 recommends this variant for most use cases.
        ARGON2ID = 2
    };

    /// \brief Construct an Argon2 key derivation function
    /// \param variant the Argon2 variant to use (default: Argon2id)
    /// \details The default variant is Argon2id as recommended by RFC 9106
    Argon2(Variant variant = ARGON2ID);

    virtual ~Argon2() {}

    /// \brief Provides the static algorithm name for a variant
    /// \param variant the Argon2 variant
    /// \return the standard algorithm name ("Argon2d", "Argon2i", or "Argon2id")
    static std::string StaticAlgorithmName(Variant variant = ARGON2ID);

    /// \brief Provides the name of this algorithm
    /// \return the standard algorithm name
    /// \details The algorithm name depends on the variant set in the constructor
    std::string AlgorithmName() const;

    /// \brief Returns the maximum derived key length
    /// \return maximum derived key length, in bytes
    /// \details RFC 9106 allows up to 2^32-1 bytes, but this implementation is limited
    ///   by SIZE_MAX due to C++ datatypes
    size_t MaxDerivedKeyLength() const {
        return static_cast<size_t>(0)-1;
    }

    /// \brief Returns a valid key length for the derivation function
    /// \param keylength the size of the derived key, in bytes
    /// \return the valid key length, in bytes
    /// \details Argon2 supports any derived key length from 4 bytes to MaxDerivedKeyLength()
    size_t GetValidDerivedLength(size_t keylength) const;

    /// \brief Derive a key from a password
    /// \param derived the derived output buffer
    /// \param derivedLen the size of the derived buffer, in bytes (minimum 4)
    /// \param password the password input buffer
    /// \param passwordLen the size of the password buffer, in bytes
    /// \param params parameters including Salt, TimeCost, MemoryCost, Parallelism, Secret, AssociatedData
    /// \return the number of iterations performed
    /// \throw InvalidDerivedKeyLength if <tt>derivedLen</tt> is less than 4
    /// \throw InvalidArgument if parameters are invalid
    /// \details DeriveKey() provides a standard interface to derive a key from
    ///   a password and other parameters. Parameters are extracted from NameValuePairs:
    ///   - Salt: byte array (required)
    ///   - TimeCost: word32 (default 3)
    ///   - MemoryCost: word32 in kibibytes (default 65536 = 64 MiB)
    ///   - Parallelism: word32 (default 4)
    ///   - Secret: byte array (optional)
    ///   - AssociatedData: byte array (optional)
    size_t DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen,
        const NameValuePairs& params) const;

    /// \brief Derive a key from a password
    /// \param derived the derived output buffer
    /// \param derivedLen the size of the derived buffer, in bytes (minimum 4)
    /// \param password the password input buffer
    /// \param passwordLen the size of the password buffer, in bytes
    /// \param salt the salt input buffer
    /// \param saltLen the size of the salt buffer, in bytes (minimum 8)
    /// \param timeCost the time cost parameter (number of iterations, minimum 1)
    /// \param memoryCost the memory cost parameter in kibibytes (minimum 8*parallelism)
    /// \param parallelism the parallelism parameter (number of lanes, minimum 1)
    /// \param secret optional secret input buffer
    /// \param secretLen the size of the secret buffer, in bytes
    /// \param associatedData optional associated data input buffer
    /// \param associatedDataLen the size of the associated data buffer, in bytes
    /// \return the number of iterations performed (always returns timeCost)
    /// \throw InvalidDerivedKeyLength if <tt>derivedLen</tt> is less than 4
    /// \throw InvalidArgument if parameters are invalid
    /// \details DeriveKey() provides a more convenient interface with explicit parameters.
    /// \details RFC 9106 recommends:
    ///   - First choice: Argon2id with t=1, m=2097152 (2 GiB), p=4
    ///   - Second choice (memory-constrained): Argon2id with t=3, m=65536 (64 MiB), p=4
    /// \details This implementation defaults to the second recommendation for broader compatibility.
    /// \details The time cost ("t" in RFC 9106) is the number of passes over the memory.
    /// \details The memory cost ("m" in RFC 9106) is measured in kibibytes (1024 bytes).
    /// \details The parallelism ("p" in RFC 9106) determines the number of computational lanes.
    ///   Due to Microsoft's OpenMP 2.0 implementation, parallelism is limited to INT_MAX.
    size_t DeriveKey(byte *derived, size_t derivedLen,
        const byte *password, size_t passwordLen,
        const byte *salt, size_t saltLen,
        word32 timeCost=3, word32 memoryCost=65536, word32 parallelism=4,
        const byte *secret=NULLPTR, size_t secretLen=0,
        const byte *associatedData=NULLPTR, size_t associatedDataLen=0) const;

protected:
    /// \brief Default parameters
    enum {
        defaultTimeCost=3,          ///< Default time cost (iterations)
        defaultMemoryCost=65536,    ///< Default memory cost in KiB (64 MiB)
        defaultParallelism=4        ///< Default parallelism (lanes)
    };

    /// \brief Get the algorithm object
    /// \return reference to the algorithm
    const Algorithm & GetAlgorithm() const {
        return *this;
    }

    /// \brief Validate Argon2 parameters
    /// \param derivedLen the desired derived key length
    /// \param timeCost the time cost parameter
    /// \param memoryCost the memory cost parameter in kibibytes
    /// \param parallelism the parallelism parameter
    /// \throw InvalidArgument if parameters are invalid
    /// \details Performs comprehensive validation according to RFC 9106 requirements
    void ValidateParameters(size_t derivedLen, word32 timeCost, word32 memoryCost, word32 parallelism) const;

private:
    Variant m_variant;
};

NAMESPACE_END

#endif // CRYPTOPP_ARGON2_H
