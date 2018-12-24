// xed25519.h - written and placed in public domain by Jeffrey Walton
//              Crypto++ specific implementation wrapped around Andrew
//              Moon's public domain curve25519-donna and ed25519-donna,
//              https://github.com/floodyberry/curve25519-donna and
//              https://github.com/floodyberry/ed25519-donna.

// Typically the key agreement classes encapsulate their data more
// than x25519 does below. They are a little more accessible
// due to crypto_box operations.


/// \file xed25519.h
/// \brief Classes for x25519 and ed25519 operations
/// \details This implementation integrates Andrew Moon's public domain code
///   for curve25519-donna and ed25519-donna.
/// \details Moving keys into and out of the library proceeds as follows.
///   If an Integer class is accepted or returned, then the data is in big
///   endian format. That is, the MSB is at byte position 0, and the LSB
///   is at byte position 31. The Integer will work as expected, just like
///   an int or a long.
/// \details If a byte array is accepted, then the byte array is in little
///   endian format. That is, the LSB is at byte position 0, and the MSB is
///   at byte position 31. This follows the implementation where byte 0 is
///   clamed with 248. That is my_arr[0] &= 248 to mask the lower 3 bits.
/// \details PKCS8 and X509 keys encoded using ASN.1 follow little endian
///   arrays. The format is specified in <A HREF=
///   "https:///tools.ietf.org/html/draft-ietf-curdle-pkix">draft-ietf-curdle-pkix</A>.
/// \details If you have a little endian array and you want to wrap it in
///   an Integer using big endian then you can perform the following:
/// <pre>Integer x(my_arr, SECRET_KEYLENGTH, UNSIGNED, LITTLE_ENDIAN_ORDER);</pre>
/// \sa Andrew Moon's x22519 GitHub <A
///   HREF="https://github.com/floodyberry/curve25519-donna">curve25519-donna</A>,
///   ed22519 GitHub <A
///   HREF="https://github.com/floodyberry/ed25519-donna">ed25519-donna</A>, and
///   <A HREF="https:///tools.ietf.org/html/draft-ietf-curdle-pkix">draft-ietf-curdle-pkix</A>
/// \since Crypto++ 8.0

#ifndef CRYPTOPP_XED25519_H
#define CRYPTOPP_XED25519_H

#include "cryptlib.h"
#include "pubkey.h"
#include "oids.h"

NAMESPACE_BEGIN(CryptoPP)

class Integer;
struct ed25519Signer;
struct ed25519Verifier;

// ******************** x25519 Agreement ************************* //

/// \brief x25519 with key validation
/// \since Crypto++ 8.0
class x25519 : public SimpleKeyAgreementDomain, public CryptoParameters, public PKCS8PrivateKey
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

    /// \brief Create a x25519 object
    /// \param oid an object identifier
    /// \details This constructor creates a new x25519 using the specified OID. The public
    ///   and private points are uninitialized.
    x25519(const OID &oid);

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

    /// \Brief Get the Object Identifier
    /// \returns the Object Identifier
    /// \details The default OID is from RFC 8410 using id-X25519.
    ///   The default private key format is RFC 5208.
    OID GetAlgorithmID() const {
        return m_oid.Empty() ? ASN1::X25519() : m_oid;
    }

    /// \Brief Set the Object Identifier
    /// \param oid the new Object Identifier
    void SetAlgorithmID(const OID& oid) {
        m_oid = oid;
    }

    // CryptoParameters
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);

    // CryptoParameters
    CryptoParameters & AccessCryptoParameters() {return *this;}

    /// \brief DER encode ASN.1 object
    /// \param bt BufferedTransformation object
    /// \details Save() will write the OID associated with algorithm or scheme.
    ///   In the case of public and private keys, this function writes the
    ///   subjectPubicKeyInfo parts.
    /// \details The default OID is from RFC 8410 using id-X25519.
    ///   The default private key format is RFC 5208, which is the old format.
    ///   The old format provides the best interop, and keys will work
    ///   with OpenSSL.
    void Save(BufferedTransformation &bt) const {
        DEREncode(bt, 0);
    }

    /// \brief DER encode ASN.1 object
    /// \param bt BufferedTransformation object
    /// \param v0 flag indicating v0
    /// \details Save() will write the OID associated with algorithm or scheme.
    ///   In the case of public and private keys, this function writes the
    ///   subjectPubicKeyInfo parts.
    /// \details The default OID is from RFC 8410 using id-X25519.
    ///   The default private key format is RFC 5208.
    /// \details v0 means version 0 INTEGER is written. Version 0 means
    ///   RFC 5208 format, which is the old format. The old format provides
    ///   the best interop, and keys will work with OpenSSL. The the other
    ///   option is using version 1 INTEGER. Version 1 means RFC 5958 format,
    ///   which is the new format.
    void Save(BufferedTransformation &bt, bool v0) const {
        DEREncode(bt, v0 ? 0 : 1);
    }

    /// \brief BER decode ASN.1 object
    /// \param bt BufferedTransformation object
    void Load(BufferedTransformation &bt) {
        BERDecode(bt);
    }

    // PKCS8PrivateKey
    void BERDecode(BufferedTransformation &bt);
    void DEREncode(BufferedTransformation &bt) const { DEREncode(bt, 0); }
    void DEREncode(BufferedTransformation &bt, int version) const;
    void BERDecodePrivateKey(BufferedTransformation &bt, bool parametersPresent, size_t size);
    void DEREncodePrivateKey(BufferedTransformation &bt) const;

    // Hack because multiple OIDs are available
    void BERDecodeAndCheckAlgorithmID(BufferedTransformation& bt);

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
    OID m_oid;  // preferred OID
};

// ****************** ed25519 Signer *********************** //

struct ed25519_MessageAccumulator : public PK_MessageAccumulator
{
    CRYPTOPP_CONSTANT(RESERVE_SIZE=2048+64)
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH=64)

    ed25519_MessageAccumulator() {
        Restart();
    }

    ed25519_MessageAccumulator(RandomNumberGenerator &rng) {
        CRYPTOPP_UNUSED(rng); Restart();
    }

    void Update(const byte* msg, size_t len) {
        if (msg && len)
            m_msg.insert(m_msg.end(), msg, msg+len);
    }

    void Restart() {
        m_msg.reserve(RESERVE_SIZE);
        m_msg.resize(SIGNATURE_LENGTH);
    }

    byte* signature() {
        return &m_msg[0];
    }

    const byte* signature() const {
        return &m_msg[0];
    }

    const byte* data() const {
        return &m_msg[0]+SIGNATURE_LENGTH;
    }

    size_t size() const {
        return m_msg.size()-SIGNATURE_LENGTH;
    }

protected:
    // TODO: Find an equivalent Crypto++ structure.
    std::vector<byte, AllocatorWithCleanup<byte> > m_msg;
};

struct ed25519PrivateKey : public PKCS8PrivateKey
{
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = 64)

    // CryptoMaterial
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);

    // GroupParameters
    OID GetAlgorithmID() const {
        return m_oid.Empty() ? ASN1::Ed25519() : m_oid;
    }

    /// \brief DER encode ASN.1 object
    /// \param bt BufferedTransformation object
    /// \details Save() will write the OID associated with algorithm or scheme.
    ///   In the case of public and private keys, this function writes the
    ///   subjectPubicKeyInfo parts.
    /// \details The default OID is from RFC 8410 using id-X25519.
    ///   The default private key format is RFC 5208, which is the old format.
    ///   The old format provides the best interop, and keys will work
    ///   with OpenSSL.
    void Save(BufferedTransformation &bt) const {
        DEREncode(bt, 0);
    }

    /// \brief DER encode ASN.1 object
    /// \param bt BufferedTransformation object
    /// \param v0 flag indicating v0
    /// \details Save() will write the OID associated with algorithm or scheme.
    ///   In the case of public and private keys, this function writes the
    ///   subjectPubicKeyInfo parts.
    /// \details The default OID is from RFC 8410 using id-Ed25519.
    ///   The default private key format is RFC 5208.
    /// \details v0 means version 0 INTEGER is written. Version 0 means
    ///   RFC 5208 format, which is the old format. The old format provides
    ///   the best interop, and keys will work with OpenSSL. The the other
    ///   option is using version 1 INTEGER. Version 1 means RFC 5958 format,
    ///   which is the new format.
    void Save(BufferedTransformation &bt, bool v0) const {
        DEREncode(bt, v0 ? 0 : 1);
    }

    /// \brief BER decode ASN.1 object
    /// \param bt BufferedTransformation object
    void Load(BufferedTransformation &bt) {
        BERDecode(bt);
    }

    /// \brief Initializes a public key from this key
    /// \param pub reference to a public key
    void MakePublicKey(PublicKey &pub) const;

    // PKCS8PrivateKey
    void BERDecode(BufferedTransformation &bt);
    void DEREncode(BufferedTransformation &bt) const { DEREncode(bt, 0); }
    void DEREncode(BufferedTransformation &bt, int version) const;
    void BERDecodePrivateKey(BufferedTransformation &bt, bool parametersPresent, size_t size);
    void DEREncodePrivateKey(BufferedTransformation &bt) const;

    // Hack because multiple OIDs are available
    void BERDecodeAndCheckAlgorithmID(BufferedTransformation& bt);

    // PKCS8PrivateKey
    void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params);
    void SetPrivateExponent(const byte x[SECRET_KEYLENGTH]);
    void SetPrivateExponent(const Integer &x);
    const Integer& GetPrivateExponent() const;

    /// \brief Clamp a private key
    /// \param y public key
    /// \param x private key
    /// \details ClampKeys() clamps a private key and then regenerates the
    ///   public key from the private key.
    void ClampKeys(byte y[PUBLIC_KEYLENGTH], byte x[SECRET_KEYLENGTH]) const;

    /// \brief Test if a key is clamped
    /// \param x private key
    bool IsClamped(const byte x[SECRET_KEYLENGTH]) const;

    FixedSizeSecBlock<byte, SECRET_KEYLENGTH> m_sk;
    FixedSizeSecBlock<byte, PUBLIC_KEYLENGTH> m_pk;
    OID m_oid;  // preferred OID
    mutable Integer m_x;  // for DL_PrivateKey
};

/// \brief ed25519 signature algorithm
/// \since Crypto++ 8.0
struct ed25519Signer : public PK_Signer
{
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = 64)
    typedef Integer Element;

    virtual ~ed25519Signer() {}

    /// \brief Create a ed25519Signer object
    ed25519Signer() {}

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

    // DL_ObjectImplBase
    PrivateKey& AccessKey() { return m_key; }
    PrivateKey& AccessPrivateKey() { return m_key; }

    const PrivateKey& GetKey() const { return m_key; }
    const PrivateKey& GetPrivateKey() const { return m_key; }

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
    ed25519PrivateKey m_key;
};

// ****************** ed25519 Verifier *********************** //

struct ed25519PublicKey : public X509PublicKey
{
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = 32)
    typedef Integer Element;

    OID GetAlgorithmID() const {
        return m_oid.Empty() ? ASN1::Ed25519() : m_oid;
    }

    /// \brief DER encode ASN.1 object
    /// \param bt BufferedTransformation object
    /// \details Save() will write the OID associated with algorithm or scheme.
    ///   In the case of public and private keys, this function writes the
    ///   subjectPubicKeyInfo parts.
    /// \details The default OID is from RFC 8410 using id-X25519.
    ///   The default private key format is RFC 5208, which is the old format.
    ///   The old format provides the best interop, and keys will work
    ///   with OpenSSL.
    void Save(BufferedTransformation &bt) const {
        BEREncode(bt);
    }

    /// \brief BER decode ASN.1 object
    /// \param bt BufferedTransformation object
    void Load(BufferedTransformation &bt) {
        BERDecode(bt);
    }

    // X509PublicKey
    void BERDecode(BufferedTransformation &bt);
    void DEREncode(BufferedTransformation &bt) const;
    void BERDecodePublicKey(BufferedTransformation &bt, bool parametersPresent, size_t size);
    void DEREncodePublicKey(BufferedTransformation &bt) const;

    // Hack because multiple OIDs are available
    void BERDecodeAndCheckAlgorithmID(BufferedTransformation& bt);

    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);

    // DL_PublicKey
    void SetPublicElement(const byte y[PUBLIC_KEYLENGTH]);
    void SetPublicElement(const Element &y);
    const Element& GetPublicElement() const;

    FixedSizeSecBlock<byte, PUBLIC_KEYLENGTH> m_pk;
    OID m_oid;  // preferred OID
    mutable Integer m_y;  // for DL_PublicKey
};

/// \brief ed25519 signature verification algorithm
/// \since Crypto++ 8.0
struct ed25519Verifier : public PK_Verifier
{
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = 32)
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = 64)
    typedef Integer Element;

    virtual ~ed25519Verifier() {}

    /// \brief Create a ed25519Verifier object
    ed25519Verifier() {}

    /// \brief Create a ed25519Verifier object
    /// \param y public key
    /// \details This constructor creates a ed25519Verifier object using existing parameters.
    /// \note The public key is not validated.
    ed25519Verifier(const byte y[PUBLIC_KEYLENGTH]);

    /// \brief Create a ed25519Verifier object
    /// \param y public key
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
    /// \param signer ed25519 signer object
    /// \details This constructor creates a ed25519Verifier object using existing parameters.
    ///   The <tt>params</tt> can be created with <tt>DEREncode</tt>.
    /// \note The public key is not validated.
    ed25519Verifier(const ed25519Signer& signer);

    // DL_ObjectImplBase
    PublicKey& AccessKey() { return m_key; }
    PublicKey& AccessPublicKey() { return m_key; }

    const PublicKey& GetKey() const { return m_key; }
    const PublicKey& GetPublicKey() const { return m_key; }

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
        CRYPTOPP_ASSERT(signature != NULLPTR);
        CRYPTOPP_ASSERT(signatureLength == SIGNATURE_LENGTH);
        ed25519_MessageAccumulator& accum = static_cast<ed25519_MessageAccumulator&>(messageAccumulator);
        if (signature && signatureLength)
            std::memcpy(accum.signature(), signature, STDMIN((size_t)SIGNATURE_LENGTH, signatureLength));
    }

    bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const;

    DecodingResult RecoverAndRestart(byte *recoveredMessage, PK_MessageAccumulator &messageAccumulator) const {
        CRYPTOPP_UNUSED(recoveredMessage); CRYPTOPP_UNUSED(messageAccumulator);
        throw NotImplemented("ed25519Verifier: this object does not support recoverable messages");
    }

protected:
    ed25519PublicKey m_key;
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
