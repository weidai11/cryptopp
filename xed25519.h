// xed25519.h - written and placed in public domain by Jeffrey Walton
//              Crypto++ specific implementation wrapped around Andrew
//              Moon's public domain curve25519-donna and ed25519-donna,
//              https://github.com/floodyberry/curve25519-donna and
//              https://github.com/floodyberry/ed25519-donna.

// Typically the key agreement classes encapsulate their data more
// than x25519 does below. We made them a little more accessible
// due to crypto_box operations. Once the library cuts-in the
// crypto_box operations the x25519 class will be more restricted.

/// \file xed25519.h
/// \brief Classes for x25519 and ed25519 operations
/// \details This implementation integrates Andrew Moon's public domain
///   curve25519-donna.
/// \sa Andrew Moon's x22519 GitHub <A
///   HREF="https://github.com/floodyberry/curve25519-donna">curve25519-donna</A>
///   and ed22519 GitHub <A
///   HREF="https://github.com/floodyberry/ed25519-donna">ed25519-donna</A>
/// \since Crypto++ 8.0

#ifndef CRYPTOPP_XED25519_H
#define CRYPTOPP_XED25519_H

#include "cryptlib.h"
#include "pubkey.h"
#include "oids.h"

// TODO: remove this header
#include "naclite.h"

NAMESPACE_BEGIN(CryptoPP)

class OID;
class Integer;
struct ed25519Signer;
struct ed25519Verifier;

// ******************** x25519 Agreement ************************* //

/// \brief x25519 with key validation
/// \since Crypto++ 8.0
class x25519 : public SimpleKeyAgreementDomain, public CryptoParameters
{
public:
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(SHARED_KEYLENGTH = 32)

    virtual ~x25519() {}

    /// \brief Create a x25519 object
    /// \param y public key
    /// \param x private key
    /// \details This constructor creates a x25519 object using existing parameters.
    /// \note The public key is not validated.
    x25519(const byte y[PUBLIC_KEYLENGTH], const byte x[SECRET_KEYLENGTH]);

    /// \brief Create a x25519 object
    /// \param x private key
    /// \details This constructor creates a x25519 object using existing parameters.
    ///   The public key is calculated from the private key.
    x25519(const byte x[SECRET_KEYLENGTH]);

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

    /// \brief Clamp a private key
    /// \param y public key
    /// \param x private key
    /// \details ClampKeys() clamps a private key and then regenerates the
    ///   public key from the private key.
    void ClampKeys(byte y[PUBLIC_KEYLENGTH], byte x[SECRET_KEYLENGTH]) const;

    /// \brief Test if a key is clamped
    /// \param x private key
    bool IsClamped(const byte x[SECRET_KEYLENGTH]) const;

    /// \brief Test if a key has small order
    /// \param y public key
    bool IsSmallOrder(const byte y[PUBLIC_KEYLENGTH]) const;

    /// \brief Decode a x25519 object
    /// \param params serialized object
    /// \details DEREncode() writes the public and private key as an ASN.1 structure.
    ///   The private key is written first as a <tt>BIT_STRING</tt>. The public key
    ///   is written second as an <tt>OCTET_STRING</tt>.
    void DEREncode(BufferedTransformation &params) const;

    // CryptoParameters
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);

    // CryptoParameters
    CryptoParameters & AccessCryptoParameters() {return *this;}

    // DL_PrivateKey
    void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params);

    // SimpleKeyAgreementDomain
    unsigned int AgreedValueLength() const {return SHARED_KEYLENGTH;}
    unsigned int PrivateKeyLength() const {return SECRET_KEYLENGTH;}
    unsigned int PublicKeyLength() const {return PUBLIC_KEYLENGTH;}

    // SimpleKeyAgreementDomain
    void GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const;
    void GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const;
    bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const;

protected:
    FixedSizeSecBlock<byte, SECRET_KEYLENGTH> m_sk;
    FixedSizeSecBlock<byte, PUBLIC_KEYLENGTH> m_pk;
};

// ****************** ed25519 Signatures *********************** //

struct ed25519_MessageAccumulator : public PK_MessageAccumulator
{
    CRYPTOPP_CONSTANT(RESERVE_SIZE=2048+64)

    ed25519_MessageAccumulator() {
        m_msg.reserve(RESERVE_SIZE);
    }

    ed25519_MessageAccumulator(RandomNumberGenerator &rng) {
        CRYPTOPP_UNUSED(rng); m_msg.reserve(RESERVE_SIZE);
    }

    void Update(const byte* msg, size_t len) {
        if (msg && len)
            m_msg.insert(m_msg.end(), msg, msg+len);
    }

    void Restart() {
        m_msg.clear();
    }

    const byte* begin() const {
        return &m_msg[0];
    }

    size_t size() const {
        return m_msg.size();
    }

protected:
    // TODO: Find an equivalent Crypto++ structure.
    std::vector<byte, AllocatorWithCleanup<byte> > m_msg;
};

/// \brief ed25519 signature algorithm
/// \since Crypto++ 8.0
struct ed25519Signer : public PK_Signer, public PKCS8PrivateKey
{
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = 64)

    virtual ~ed25519Signer() {}

    /// \brief Create a ed25519Signer object
    /// \param y public key
    /// \param x private key
    /// \details This constructor creates a ed25519Signer object using existing parameters.
    /// \note The public key is not validated.
    ed25519Signer(const byte y[PUBLIC_KEYLENGTH], const byte x[SECRET_KEYLENGTH]);

    /// \brief Create a ed25519Signer object
    /// \param x private key
    /// \details This constructor creates a ed25519Signer object using existing parameters.
    ///   The public key is calculated from the private key.
    ed25519Signer(const byte x[SECRET_KEYLENGTH]);

    /// \brief Create a ed25519Signer object
    /// \param y public key
    /// \param x private key
    /// \details This constructor creates a ed25519Signer object using existing parameters.
    /// \note The public key is not validated.
    ed25519Signer(const Integer &y, const Integer &x);

    /// \brief Create a ed25519Signer object
    /// \param x private key
    /// \details This constructor creates a ed25519Signer object using existing parameters.
    ///   The public key is calculated from the private key.
    ed25519Signer(const Integer &x);

    /// \brief Create a ed25519Signer object
    /// \param rng RandomNumberGenerator derived class
    /// \details This constructor creates a new ed25519Signer using the random number generator.
    ed25519Signer(RandomNumberGenerator &rng);

    /// \brief Create a ed25519Signer object
    /// \param params public and private key
    /// \details This constructor creates a ed25519Signer object using existing parameters.
    ///   The <tt>params</tt> can be created with <tt>DEREncode</tt>.
    /// \note The public key is not validated.
    ed25519Signer(BufferedTransformation &params);

    /// \brief Clamp a private key
    /// \param y public key
    /// \param x private key
    /// \details ClampKeys() clamps a private key and then regenerates the
    ///   public key from the private key.
    void ClampKeys(byte y[PUBLIC_KEYLENGTH], byte x[SECRET_KEYLENGTH]) const;

    /// \brief Test if a key is clamped
    /// \param x private key
    bool IsClamped(const byte x[SECRET_KEYLENGTH]) const;

    // CryptoMaterial
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);

    // DL_PrivateKey
    void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params);

    // DL_ObjectImplBase
    PrivateKey& AccessKey() { return *this; }
    PrivateKey& AccessPrivateKey() { return *this; }

    OID GetAlgorithmID() const {
        return ASN1::curve25519();
    }

    void BERDecodePrivateKey(BufferedTransformation &bt, bool parametersPresent, size_t size) {
        CRYPTOPP_UNUSED(bt); CRYPTOPP_UNUSED(parametersPresent);
        CRYPTOPP_UNUSED(size);
    }

    void DEREncodePrivateKey(BufferedTransformation &bt) const {
        CRYPTOPP_UNUSED(bt);
    }

    // DL_SignatureSchemeBase
    size_t SignatureLength() const { return SIGNATURE_LENGTH; }
    size_t MaxRecoverableLength() const { return 0; }
    size_t MaxRecoverableLengthFromSignatureLength(size_t signatureLength) const {
        CRYPTOPP_UNUSED(signatureLength); return 0;
    }

    bool IsProbabilistic() const { return false; }
    bool AllowNonrecoverablePart() const { return false; }
    bool RecoverablePartFirst() const { return false; }

    PK_MessageAccumulator* NewSignatureAccumulator(RandomNumberGenerator &rng) const {
        return new ed25519_MessageAccumulator(rng);
    }

    void InputRecoverableMessage(PK_MessageAccumulator &messageAccumulator, const byte *recoverableMessage, size_t recoverableMessageLength) const {
        CRYPTOPP_UNUSED(messageAccumulator); CRYPTOPP_UNUSED(recoverableMessage);
        CRYPTOPP_UNUSED(recoverableMessageLength);
        throw NotImplemented("ed25519Signer: this object does not support recoverable messages");
    }

    size_t SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart) const;

protected:
    friend ed25519Verifier;
    FixedSizeSecBlock<byte, SECRET_KEYLENGTH> m_sk;
    FixedSizeSecBlock<byte, PUBLIC_KEYLENGTH> m_pk;
};

/// \brief ed25519 signature verification algorithm
/// \since Crypto++ 8.0
struct ed25519Verifier : public PK_Verifier, public X509PublicKey
{
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = 64)

    virtual ~ed25519Verifier() {}

    /// \brief Create a ed25519Verifier object
    /// \param y public key
    /// \param x private key
    /// \details This constructor creates a ed25519Verifier object using existing parameters.
    /// \note The public key is not validated.
    ed25519Verifier(const byte y[PUBLIC_KEYLENGTH]);

    /// \brief Create a ed25519Verifier object
    /// \param y public key
    /// \param x private key
    /// \details This constructor creates a ed25519Verifier object using existing parameters.
    /// \note The public key is not validated.
    ed25519Verifier(const Integer &y);

    /// \brief Create a ed25519Verifier object
    /// \param params public and private key
    /// \details This constructor creates a ed25519Verifier object using existing parameters.
    ///   The <tt>params</tt> can be created with <tt>DEREncode</tt>.
    /// \note The public key is not validated.
    ed25519Verifier(BufferedTransformation &params);

    /// \brief Create a ed25519Verifier object
    /// \param params public and private key
    /// \details This constructor creates a ed25519Verifier object using existing parameters.
    ///   The <tt>params</tt> can be created with <tt>DEREncode</tt>.
    /// \note The public key is not validated.
    ed25519Verifier(const ed25519Signer& signer);

    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);

    // DL_ObjectImplBase
    PublicKey& AccessKey() { return *this; }
    PublicKey& AccessPublicKey() { return *this; }

    OID GetAlgorithmID() const {
        return ASN1::curve25519();
    }

     void BERDecodePublicKey(BufferedTransformation &bt, bool parametersPresent, size_t size) {
        CRYPTOPP_UNUSED(bt); CRYPTOPP_UNUSED(parametersPresent);
        CRYPTOPP_UNUSED(size);
    }

    void DEREncodePublicKey(BufferedTransformation &bt) const {
        CRYPTOPP_UNUSED(bt);
    }

    // DL_SignatureSchemeBase
    size_t SignatureLength() const { return SIGNATURE_LENGTH; }
    size_t MaxRecoverableLength() const { return 0; }
    size_t MaxRecoverableLengthFromSignatureLength(size_t signatureLength) const {
        CRYPTOPP_UNUSED(signatureLength); return 0;
    }

    bool IsProbabilistic() const { return false; }
    bool AllowNonrecoverablePart() const { return false; }
    bool RecoverablePartFirst() const { return false; }

    ed25519_MessageAccumulator* NewVerificationAccumulator() const {
        return new ed25519_MessageAccumulator;
    }

    void InputSignature(PK_MessageAccumulator &messageAccumulator, const byte *signature, size_t signatureLength) const {
        // TODO: verify signature is always inserted first...
        ed25519_MessageAccumulator& accum = static_cast<ed25519_MessageAccumulator&>(messageAccumulator);
        CRYPTOPP_ASSERT(accum.size() == 0);

        if (signature && signatureLength)
            accum.Update(signature, signatureLength);
    }

    bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const {

        ed25519_MessageAccumulator& accum = static_cast<ed25519_MessageAccumulator&>(messageAccumulator);
        SecByteBlock temp(SIGNATURE_LENGTH+accum.size());
        word64 tlen=temp.size();

        int ret = NaCl::crypto_sign_open(temp, &tlen, accum.begin(), accum.size(), m_pk);
        accum.Restart();

        return ret == 0;
    }

     DecodingResult RecoverAndRestart(byte *recoveredMessage, PK_MessageAccumulator &messageAccumulator) const {
        CRYPTOPP_UNUSED(recoveredMessage); CRYPTOPP_UNUSED(messageAccumulator);
        throw NotImplemented("ed25519Verifier: this object does not support recoverable messages");
    }

protected:
    FixedSizeSecBlock<byte, PUBLIC_KEYLENGTH> m_pk;
};

/// \brief ed25519 signature scheme
/// \since Crypto++ 8.0
struct ed25519
{
    typedef ed25519Signer Signer;
    typedef ed25519Verifier Verifier;
};

NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_XED25519_H
