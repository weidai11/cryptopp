// xed25519.h - written and placed in public domain by Jeffrey Walton
//              Crypto++ specific implementation wrapped around Andrew
//              Moon's public domain curve25519-donna. Also see
//              https://github.com/floodyberry/curve25519-donna.

// Typically the key agreement classes encapsulate their data more
// than x25519 does below. We made them a little more accessible
// due to crypto_box operations. Once the library cuts-in the
// crypto_box operations the x25519 class will be more restricted.

/// \file xed25519.h
/// \brief Classes for x25519 and ed25519 operations
/// \details This implementation integrates Andrew Moon's public domain
///   curve25519-donna.
/// \sa Andrew Moon's GitHub <A
///   HREF="https://github.com/floodyberry/curve25519-donna">curve25519-donna</A>
/// \since Crypto++ 8.0

#ifndef CRYPTOPP_XED25519_H
#define CRYPTOPP_XED25519_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

class Integer;

/// \brief x25519 with key validation
/// \since Crypto++ 8.0
class x25519 : public SimpleKeyAgreementDomain, public CryptoParameters
{
public:
    /// \brief Test if a key is clamped
    /// \param x private key
    static bool IsClamped(const byte x[32]);

    /// \brief Test if a key has small order
    /// \param y public key
    static bool IsSmallOrder(const byte y[32]);

    /// \brief Test if a key is clamped
    /// \param x private key
    static void ClampKey(byte x[32]);

    virtual ~x25519() {}

    /// \brief Create a x25519 object
    /// \param y public key
    /// \param x private key
    /// \details This constructor creates a x25519 object using existing parameters.
    /// \note The public key is not validated.
    x25519(const byte y[32], const byte x[32]);

    /// \brief Create a x25519 object
    /// \param x private key
    /// \details This constructor creates a x25519 object using existing parameters.
    ///   The public key is calculated from the private key.
    x25519(const byte x[32]);

    /// \brief Create a x25519 object
    /// \param y public key
    /// \param x private key
    /// \details This constructor creates a x25519 object using existing parameters.
    /// \note The public key is not validated.
    x25519(const Integer &y, const Integer &x);

    /// \brief Create a x25519 object
    /// \param x private key
    /// \details This constructor creates a x25519 object using existing parameters.
    ///   The public key is calculated from the private key.
    x25519(const Integer &x);

    /// \brief Create a x25519 object
    /// \param rng RandomNumberGenerator derived class
    /// \details This constructor creates a new x25519 using the random number generator.
    x25519(RandomNumberGenerator &rng);

    /// \brief Create a x25519 object
    /// \param params public and private key
    /// \details This constructor creates a x25519 object using existing parameters.
    ///   The <tt>params</tt> can be created with <tt>DEREncode</tt>.
    /// \note The public key is not validated.
    x25519(BufferedTransformation &params);

    /// \brief Decode a x25519 object
    /// \param params serialized object
    /// \details DEREncode() writes the public and private key as an ASN.1 structure.
    ///   The private key is written first as a <tt>BIT_STRING</tt>. The public key
    ///   is written second as an <tt>OCTET_STRING</tt>.
    void DEREncode(BufferedTransformation &params) const;

    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);
    CryptoParameters & AccessCryptoParameters() {return *this;}

    unsigned int AgreedValueLength() const {return 32;}
    unsigned int PrivateKeyLength() const {return 32;}
    unsigned int PublicKeyLength() const {return 32;}

    void GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const;
    void GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const;
    bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const;

private:
    FixedSizeSecBlock<byte, 32> m_sk, m_pk;
};

NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_XED25519_H
