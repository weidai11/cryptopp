// xed25519.cpp - written and placed in public domain by Jeffrey Walton
//                Crypto++ specific implementation wrapped around Andrew
//                Moon's public domain curve25519-donna and ed25519-donna,
//                https://github.com/floodyberry/curve25519-donna and
//                https://github.com/floodyberry/ed25519-donna.

#include "pch.h"

#include "cryptlib.h"
#include "asn.h"
#include "integer.h"
#include "filters.h"
#include "stdcpp.h"

#include "xed25519.h"
#include "donna.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;

CRYPTOPP_ALIGN_DATA(16)
const byte blacklist[][32] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
      0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
    { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
      0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
    { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    { 0xcd, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
      0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x80 },
    { 0x4c, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
      0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7 },
    { 0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    { 0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    { 0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

bool HasSmallOrder(const byte y[32])
{
    // The magic 12 is the count of blaklisted points
    byte c[12] = { 0 };
    for (size_t j = 0; j < 32; j++) {
        for (size_t i = 0; i < COUNTOF(blacklist); i++) {
            c[i] |= y[j] ^ blacklist[i][j];
        }
    }

    unsigned int k = 0;
    for (size_t i = 0; i < COUNTOF(blacklist); i++) {
        k |= (c[i] - 1);
    }

    return (bool)((k >> 8) & 1);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

// ******************** x25519 Agreement ************************* //

x25519::x25519(const byte y[PUBLIC_KEYLENGTH], const byte x[SECRET_KEYLENGTH])
{
    std::memcpy(m_pk, y, PUBLIC_KEYLENGTH);
    std::memcpy(m_sk, x, SECRET_KEYLENGTH);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(const byte x[SECRET_KEYLENGTH])
{
    std::memcpy(m_sk, x, SECRET_KEYLENGTH);
    Donna::curve25519_mult(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(const Integer &y, const Integer &x)
{
    CRYPTOPP_ASSERT(y.MinEncodedSize() <= PUBLIC_KEYLENGTH);
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    y.Encode(m_pk, PUBLIC_KEYLENGTH); std::reverse(m_pk+0, m_pk+PUBLIC_KEYLENGTH);
    x.Encode(m_sk, SECRET_KEYLENGTH); std::reverse(m_sk+0, m_sk+SECRET_KEYLENGTH);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(const Integer &x)
{
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    x.Encode(m_sk, SECRET_KEYLENGTH);
    std::reverse(m_sk+0, m_sk+SECRET_KEYLENGTH);
    Donna::curve25519_mult(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(RandomNumberGenerator &rng)
{
    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    ClampKey(m_sk);
    SecretToPublicKey(m_pk, m_sk);
}

x25519::x25519(BufferedTransformation &params)
{
    Load(params);
}

void x25519::ClampKey(byte x[SECRET_KEYLENGTH]) const
{
    x[0] &= 248; x[31] &= 127; x[31] |= 64;
}

bool x25519::IsClamped(const byte x[SECRET_KEYLENGTH]) const
{
    return (x[0] & 248) == x[0] && (x[31] & 127) == x[31] && (x[31] | 64) == x[31];
}

bool x25519::IsSmallOrder(const byte y[PUBLIC_KEYLENGTH]) const
{
    return HasSmallOrder(y);
}

void x25519::SecretToPublicKey(byte y[PUBLIC_KEYLENGTH], const byte x[SECRET_KEYLENGTH]) const
{
    Donna::curve25519_mult(y, x);
}

void x25519::BERDecodeAndCheckAlgorithmID(BufferedTransformation &bt)
{
    // We have not yet determined the OID to use for this object.
    // We can't use OID's decoder because it throws BERDecodeError
    // if the OIDs do not match.
    OID oid(bt);

    // 1.3.6.1.4.1.3029.1.5.1/curvey25519 from Cryptlib used by OpenPGP.
    // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis
    if (!m_oid.Empty() && m_oid != oid)
        BERDecodeError();  // Only accept user specified OID
    else if (oid == ASN1::curve25519() || oid == ASN1::X25519() ||
        oid == OID(1)+3+6+1+4+1+3029+1+5)
        m_oid = oid;  // Accept any of the x25519 OIDs
    else
        BERDecodeError();
}

void x25519::BERDecode(BufferedTransformation &bt)
{
    // https://tools.ietf.org/html/rfc8410, section 7 and
    // https://www.cryptopp.com/wiki/curve25519_keys
    BERSequenceDecoder privateKeyInfo(bt);
        word32 version;
        BERDecodeUnsigned<word32>(privateKeyInfo, version, INTEGER, 0, 1);    // check version

        BERSequenceDecoder algorithm(privateKeyInfo);
            // GetAlgorithmID().BERDecodeAndCheck(algorithm);
            BERDecodeAndCheckAlgorithmID(algorithm);
        algorithm.MessageEnd();

        BERGeneralDecoder octetString(privateKeyInfo, OCTET_STRING);
            BERDecodePrivateKey(octetString, false, (size_t)privateKeyInfo.RemainingLength());
        octetString.MessageEnd();

        // publicKey [1] IMPLICIT PublicKey OPTIONAL
        bool generatePublicKey = true;
        if (privateKeyInfo.EndReached() == false /*version == 1?*/)
        {
            // Should we test this before decoding? In either case we
            // just throw a BERDecodeErr() when we can't parse it.
            BERGeneralDecoder publicKey(privateKeyInfo, CONTEXT_SPECIFIC | CONSTRUCTED | 1);
            SecByteBlock subjectPublicKey;
            unsigned int unusedBits;
            BERDecodeBitString(publicKey, subjectPublicKey, unusedBits);
                CRYPTOPP_ASSERT(unusedBits == 0);
                CRYPTOPP_ASSERT(subjectPublicKey.size() == PUBLIC_KEYLENGTH);
                if (subjectPublicKey.size() != PUBLIC_KEYLENGTH)
                    BERDecodeError();
                std::memcpy(m_pk.begin(), subjectPublicKey, PUBLIC_KEYLENGTH);
                generatePublicKey = false;
            publicKey.MessageEnd();
        }

    privateKeyInfo.MessageEnd();

    if (generatePublicKey)
        Donna::curve25519_mult(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

void x25519::DEREncode(BufferedTransformation &bt, int version) const
{
    // https://tools.ietf.org/html/rfc8410, section 7 and
    // https://www.cryptopp.com/wiki/curve25519_keys
    CRYPTOPP_ASSERT(version == 0 || version == 1);

    DERSequenceEncoder privateKeyInfo(bt);
        DEREncodeUnsigned<word32>(privateKeyInfo, version);

        DERSequenceEncoder algorithm(privateKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DERGeneralEncoder octetString(privateKeyInfo, OCTET_STRING);
            DEREncodePrivateKey(octetString);
        octetString.MessageEnd();

        if (version == 1)
        {
            DERGeneralEncoder publicKey(privateKeyInfo, CONTEXT_SPECIFIC | CONSTRUCTED | 1);
                DEREncodeBitString(publicKey, m_pk, PUBLIC_KEYLENGTH);
            publicKey.MessageEnd();
        }

    privateKeyInfo.MessageEnd();
}

void x25519::BERDecodePrivateKey(BufferedTransformation &bt, bool parametersPresent, size_t /*size*/)
{
    // https://tools.ietf.org/html/rfc8410 and
    // https://www.cryptopp.com/wiki/curve25519_keys

    BERGeneralDecoder privateKey(bt, OCTET_STRING);

        if (!privateKey.IsDefiniteLength())
            BERDecodeError();

        size_t size = privateKey.Get(m_sk, SECRET_KEYLENGTH);
        if (size != SECRET_KEYLENGTH)
            BERDecodeError();

        // We don't know how to decode them
        if (parametersPresent)
            BERDecodeError();

    privateKey.MessageEnd();
}

void x25519::DEREncodePrivateKey(BufferedTransformation &bt) const
{
    // https://tools.ietf.org/html/rfc8410
    DERGeneralEncoder privateKey(bt, OCTET_STRING);
        privateKey.Put(m_sk, SECRET_KEYLENGTH);
    privateKey.MessageEnd();
}

bool x25519::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);

    if (level >= 1 && IsClamped(m_sk) == false)
        return false;
    if (level >= 2 && IsSmallOrder(m_pk) == true)
        return false;
    if (level >= 3)
    {
        // Verify m_pk is pairwise consistent with m_sk
        SecByteBlock pk(PUBLIC_KEYLENGTH);
        SecretToPublicKey(pk, m_sk);

        if (VerifyBufsEqual(pk, m_pk, PUBLIC_KEYLENGTH) == false)
            return false;
    }

    return true;
}

bool x25519::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    if (std::strcmp(name, Name::PrivateExponent()) == 0 || std::strcmp(name, "SecretKey") == 0)
    {
        this->ThrowIfTypeMismatch(name, typeid(ConstByteArrayParameter), valueType);
        reinterpret_cast<ConstByteArrayParameter*>(pValue)->Assign(m_sk, SECRET_KEYLENGTH, false);
        return true;
    }

    if (std::strcmp(name, Name::PublicElement()) == 0)
    {
        this->ThrowIfTypeMismatch(name, typeid(ConstByteArrayParameter), valueType);
        reinterpret_cast<ConstByteArrayParameter*>(pValue)->Assign(m_pk, PUBLIC_KEYLENGTH, false);
        return true;
    }

    if (std::strcmp(name, Name::GroupOID()) == 0)
    {
        if (m_oid.Empty())
            return false;

        this->ThrowIfTypeMismatch(name, typeid(OID), valueType);
        *reinterpret_cast<OID *>(pValue) = m_oid;
        return true;
    }

    return false;
}

void x25519::AssignFrom(const NameValuePairs &source)
{
    ConstByteArrayParameter val;
    if (source.GetValue(Name::PrivateExponent(), val) || source.GetValue("SecretKey", val))
    {
        std::memcpy(m_sk, val.begin(), SECRET_KEYLENGTH);
    }

    if (source.GetValue(Name::PublicElement(), val))
    {
        std::memcpy(m_pk, val.begin(), PUBLIC_KEYLENGTH);
    }

    OID oid;
    if (source.GetValue(Name::GroupOID(), oid))
    {
        m_oid = oid;
    }

    bool derive = false;
    if (source.GetValue("DerivePublicKey", derive) && derive == true)
        SecretToPublicKey(m_pk, m_sk);
}

void x25519::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params)
{
    ConstByteArrayParameter seed;
    if (params.GetValue(Name::Seed(), seed) && rng.CanIncorporateEntropy())
        rng.IncorporateEntropy(seed.begin(), seed.size());

    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    ClampKey(m_sk);
    SecretToPublicKey(m_pk, m_sk);
}

void x25519::GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const
{
    rng.GenerateBlock(privateKey, SECRET_KEYLENGTH);
    ClampKey(privateKey);
}

void x25519::GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const
{
    CRYPTOPP_UNUSED(rng);
    SecretToPublicKey(publicKey, privateKey);
}

bool x25519::Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey) const
{
    CRYPTOPP_ASSERT(agreedValue != NULLPTR);
    CRYPTOPP_ASSERT(otherPublicKey != NULLPTR);

    if (validateOtherPublicKey && IsSmallOrder(otherPublicKey))
        return false;

    return Donna::curve25519_mult(agreedValue, privateKey, otherPublicKey) == 0;
}

// ******************** ed25519 Signer ************************* //

void ed25519PrivateKey::SecretToPublicKey(byte y[PUBLIC_KEYLENGTH], const byte x[SECRET_KEYLENGTH]) const
{
    int ret = Donna::ed25519_publickey(y, x);
    CRYPTOPP_ASSERT(ret == 0); CRYPTOPP_UNUSED(ret);
}

bool ed25519PrivateKey::IsSmallOrder(const byte y[PUBLIC_KEYLENGTH]) const
{
    return HasSmallOrder(y);
}

bool ed25519PrivateKey::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);

    if (level >= 1 && IsSmallOrder(m_pk) == true)
        return false;
    if (level >= 3)
    {
        // Verify m_pk is pairwise consistent with m_sk
        SecByteBlock pk(PUBLIC_KEYLENGTH);
        SecretToPublicKey(pk, m_sk);

        if (VerifyBufsEqual(pk, m_pk, PUBLIC_KEYLENGTH) == false)
            return false;
    }

    return true;
}

bool ed25519PrivateKey::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
     if (std::strcmp(name, Name::PrivateExponent()) == 0 || std::strcmp(name, "SecretKey") == 0)
     {
        this->ThrowIfTypeMismatch(name, typeid(ConstByteArrayParameter), valueType);
        reinterpret_cast<ConstByteArrayParameter*>(pValue)->Assign(m_sk, SECRET_KEYLENGTH, false);
        return true;
    }

    if (std::strcmp(name, Name::PublicElement()) == 0)
    {
        this->ThrowIfTypeMismatch(name, typeid(ConstByteArrayParameter), valueType);
        reinterpret_cast<ConstByteArrayParameter*>(pValue)->Assign(m_pk, PUBLIC_KEYLENGTH, false);
        return true;
    }

    if (std::strcmp(name, Name::GroupOID()) == 0)
    {
        if (m_oid.Empty())
            return false;

        this->ThrowIfTypeMismatch(name, typeid(OID), valueType);
        *reinterpret_cast<OID *>(pValue) = m_oid;
        return true;
    }

    return false;
}

void ed25519PrivateKey::AssignFrom(const NameValuePairs &source)
{
    ConstByteArrayParameter val;
    if (source.GetValue(Name::PrivateExponent(), val) || source.GetValue("SecretKey", val))
    {
        CRYPTOPP_ASSERT(val.size() == SECRET_KEYLENGTH);
        std::memcpy(m_sk, val.begin(), SECRET_KEYLENGTH);
    }
    if (source.GetValue(Name::PublicElement(), val))
    {
        CRYPTOPP_ASSERT(val.size() == PUBLIC_KEYLENGTH);
        std::memcpy(m_pk, val.begin(), PUBLIC_KEYLENGTH);
    }

    OID oid;
    if (source.GetValue(Name::GroupOID(), oid))
    {
        m_oid = oid;
    }

    bool derive = false;
    if (source.GetValue("DerivePublicKey", derive) && derive == true)
        SecretToPublicKey(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

void ed25519PrivateKey::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params=g_nullNameValuePairs)
{
    ConstByteArrayParameter seed;
    if (params.GetValue(Name::Seed(), seed) && rng.CanIncorporateEntropy())
        rng.IncorporateEntropy(seed.begin(), seed.size());

    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    int ret = Donna::ed25519_publickey(m_pk, m_sk);
    CRYPTOPP_ASSERT(ret == 0); CRYPTOPP_UNUSED(ret);
}

void ed25519PrivateKey::MakePublicKey (PublicKey &pub) const
{
    pub.AssignFrom(MakeParameters
        (Name::PublicElement(), ConstByteArrayParameter(m_pk.begin(), PUBLIC_KEYLENGTH))
        (Name::GroupOID(), GetAlgorithmID()));
}

void ed25519PrivateKey::BERDecodeAndCheckAlgorithmID(BufferedTransformation &bt)
{
    // We have not yet determined the OID to use for this object.
    // We can't use OID's decoder because it throws BERDecodeError
    // if the OIDs do not match.
    OID oid(bt);

    if (!m_oid.Empty() && m_oid != oid)
        BERDecodeError();  // Only accept user specified OID
    else if (oid == ASN1::curve25519() || oid == ASN1::Ed25519())
        m_oid = oid;  // Accept any of the ed25519PrivateKey OIDs
    else
        BERDecodeError();
}

void ed25519PrivateKey::BERDecode(BufferedTransformation &bt)
{
    // https://tools.ietf.org/html/rfc8410, section 7 and
    // https://www.cryptopp.com/wiki/curve25519_keys
    BERSequenceDecoder privateKeyInfo(bt);
        word32 version;
        BERDecodeUnsigned<word32>(privateKeyInfo, version, INTEGER, 0, 1);    // check version

        BERSequenceDecoder algorithm(privateKeyInfo);
            // GetAlgorithmID().BERDecodeAndCheck(algorithm);
            BERDecodeAndCheckAlgorithmID(algorithm);
        algorithm.MessageEnd();

        BERGeneralDecoder octetString(privateKeyInfo, OCTET_STRING);
            BERDecodePrivateKey(octetString, false, (size_t)privateKeyInfo.RemainingLength());
        octetString.MessageEnd();

        // publicKey [1] IMPLICIT PublicKey OPTIONAL
        bool generatePublicKey = true;
        if (privateKeyInfo.EndReached() == false /*version == 1?*/)
        {
            // Should we test this before decoding? In either case we
            // just throw a BERDecodeErr() when we can't parse it.
            BERGeneralDecoder publicKey(privateKeyInfo, CONTEXT_SPECIFIC | CONSTRUCTED | 1);
            SecByteBlock subjectPublicKey;
            unsigned int unusedBits;
            BERDecodeBitString(publicKey, subjectPublicKey, unusedBits);
                CRYPTOPP_ASSERT(unusedBits == 0);
                CRYPTOPP_ASSERT(subjectPublicKey.size() == PUBLIC_KEYLENGTH);
                if (subjectPublicKey.size() != PUBLIC_KEYLENGTH)
                    BERDecodeError();
                std::memcpy(m_pk.begin(), subjectPublicKey, PUBLIC_KEYLENGTH);
                generatePublicKey = false;
            publicKey.MessageEnd();
        }

    privateKeyInfo.MessageEnd();

    if (generatePublicKey)
        Donna::ed25519_publickey(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

void ed25519PrivateKey::DEREncode(BufferedTransformation &bt, int version) const
{
    // https://tools.ietf.org/html/rfc8410, section 7 and
    // https://www.cryptopp.com/wiki/curve25519_keys
    CRYPTOPP_ASSERT(version == 0 || version == 1);

    DERSequenceEncoder privateKeyInfo(bt);
        DEREncodeUnsigned<word32>(privateKeyInfo, version);

        DERSequenceEncoder algorithm(privateKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DERGeneralEncoder octetString(privateKeyInfo, OCTET_STRING);
            DEREncodePrivateKey(octetString);
        octetString.MessageEnd();

        if (version == 1)
        {
            DERGeneralEncoder publicKey(privateKeyInfo, CONTEXT_SPECIFIC | CONSTRUCTED | 1);
                DEREncodeBitString(publicKey, m_pk, PUBLIC_KEYLENGTH);
            publicKey.MessageEnd();
        }

    privateKeyInfo.MessageEnd();
}

void ed25519PrivateKey::BERDecodePrivateKey(BufferedTransformation &bt, bool parametersPresent, size_t /*size*/)
{
    // https://tools.ietf.org/html/rfc8410 and
    // https://www.cryptopp.com/wiki/curve25519_keys

    BERGeneralDecoder privateKey(bt, OCTET_STRING);

        if (!privateKey.IsDefiniteLength())
            BERDecodeError();

        size_t size = privateKey.Get(m_sk, SECRET_KEYLENGTH);
        if (size != SECRET_KEYLENGTH)
            BERDecodeError();

        // We don't know how to decode them
        if (parametersPresent)
            BERDecodeError();

    privateKey.MessageEnd();
}

void ed25519PrivateKey::DEREncodePrivateKey(BufferedTransformation &bt) const
{
    // https://tools.ietf.org/html/rfc8410
    DERGeneralEncoder privateKey(bt, OCTET_STRING);
        privateKey.Put(m_sk, SECRET_KEYLENGTH);
    privateKey.MessageEnd();
}

void ed25519PrivateKey::SetPrivateExponent (const byte x[SECRET_KEYLENGTH])
{
    AssignFrom(MakeParameters
        (Name::PrivateExponent(), ConstByteArrayParameter(x, SECRET_KEYLENGTH))
        ("DerivePublicKey", true));
}

void ed25519PrivateKey::SetPrivateExponent (const Integer &x)
{
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    SecByteBlock bx(SECRET_KEYLENGTH);
    x.Encode(bx, SECRET_KEYLENGTH); std::reverse(bx+0, bx+SECRET_KEYLENGTH);

    AssignFrom(MakeParameters
        (Name::PrivateExponent(), ConstByteArrayParameter(bx, SECRET_KEYLENGTH, false))
        ("DerivePublicKey", true));
}

const Integer& ed25519PrivateKey::GetPrivateExponent() const
{
    m_x = Integer(m_sk, SECRET_KEYLENGTH, Integer::UNSIGNED, LITTLE_ENDIAN_ORDER);
    return m_x;
}

////////////////////////

ed25519Signer::ed25519Signer(const byte y[PUBLIC_KEYLENGTH], const byte x[SECRET_KEYLENGTH])
{
    AccessPrivateKey().AssignFrom(MakeParameters
        (Name::PrivateExponent(), ConstByteArrayParameter(x, SECRET_KEYLENGTH, false))
        (Name::PublicElement(), ConstByteArrayParameter(y, PUBLIC_KEYLENGTH, false)));
}

ed25519Signer::ed25519Signer(const byte x[SECRET_KEYLENGTH])
{
    AccessPrivateKey().AssignFrom(MakeParameters
        (Name::PrivateExponent(), ConstByteArrayParameter(x, SECRET_KEYLENGTH, false))
        ("DerivePublicKey", true));
}

ed25519Signer::ed25519Signer(const Integer &y, const Integer &x)
{
    CRYPTOPP_ASSERT(y.MinEncodedSize() <= PUBLIC_KEYLENGTH);
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    SecByteBlock by(PUBLIC_KEYLENGTH), bx(SECRET_KEYLENGTH);
    y.Encode(by, PUBLIC_KEYLENGTH); std::reverse(by+0, by+PUBLIC_KEYLENGTH);
    x.Encode(bx, SECRET_KEYLENGTH); std::reverse(bx+0, bx+SECRET_KEYLENGTH);

    AccessPrivateKey().AssignFrom(MakeParameters
        (Name::PublicElement(), ConstByteArrayParameter(by, PUBLIC_KEYLENGTH, false))
        (Name::PrivateExponent(), ConstByteArrayParameter(bx, SECRET_KEYLENGTH, false)));
}

ed25519Signer::ed25519Signer(const Integer &x)
{
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    SecByteBlock bx(SECRET_KEYLENGTH);
    x.Encode(bx, SECRET_KEYLENGTH); std::reverse(bx+0, bx+SECRET_KEYLENGTH);

    AccessPrivateKey().AssignFrom(MakeParameters
        (Name::PrivateExponent(), ConstByteArrayParameter(bx, SECRET_KEYLENGTH, false))
        ("DerivePublicKey", true));
}

ed25519Signer::ed25519Signer(const PKCS8PrivateKey &key)
{
    // Load all fields from the other key
    ByteQueue queue;
    key.Save(queue);
    AccessPrivateKey().Load(queue);
}

ed25519Signer::ed25519Signer(RandomNumberGenerator &rng)
{
    AccessPrivateKey().GenerateRandom(rng);
}

ed25519Signer::ed25519Signer(BufferedTransformation &params)
{
    AccessPrivateKey().Load(params);
}

size_t ed25519Signer::SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart) const
{
    CRYPTOPP_ASSERT(signature != NULLPTR); CRYPTOPP_UNUSED(rng);

    ed25519_MessageAccumulator& accum = dynamic_cast<ed25519_MessageAccumulator&>(messageAccumulator);
    const ed25519PrivateKey& pk = dynamic_cast<const ed25519PrivateKey&>(GetPrivateKey());
    int ret = Donna::ed25519_sign(accum.data(), accum.size(), pk.GetPrivateKeyBytePtr(), pk.GetPublicKeyBytePtr(), signature);
    CRYPTOPP_ASSERT(ret == 0);

    if (restart)
        accum.Restart();

    return ret == 0 ? SIGNATURE_LENGTH : 0;
}

size_t ed25519Signer::SignStream (RandomNumberGenerator &rng, std::istream& stream, byte *signature) const
{
    CRYPTOPP_ASSERT(signature != NULLPTR); CRYPTOPP_UNUSED(rng);

    const ed25519PrivateKey& pk = dynamic_cast<const ed25519PrivateKey&>(GetPrivateKey());
    int ret = Donna::ed25519_sign(stream, pk.GetPrivateKeyBytePtr(), pk.GetPublicKeyBytePtr(), signature);
    CRYPTOPP_ASSERT(ret == 0);

    return ret == 0 ? SIGNATURE_LENGTH : 0;
}

// ******************** ed25519 Verifier ************************* //

bool ed25519PublicKey::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    if (std::strcmp(name, Name::PublicElement()) == 0)
    {
        this->ThrowIfTypeMismatch(name, typeid(ConstByteArrayParameter), valueType);
        reinterpret_cast<ConstByteArrayParameter*>(pValue)->Assign(m_pk, PUBLIC_KEYLENGTH, false);
        return true;
    }

    if (std::strcmp(name, Name::GroupOID()) == 0)
    {
        if (m_oid.Empty())
            return false;

        this->ThrowIfTypeMismatch(name, typeid(OID), valueType);
        *reinterpret_cast<OID *>(pValue) = m_oid;
        return true;
    }

    return false;
}

void ed25519PublicKey::AssignFrom(const NameValuePairs &source)
{
    ConstByteArrayParameter ba;
    if (source.GetValue(Name::PublicElement(), ba))
    {
        std::memcpy(m_pk, ba.begin(), PUBLIC_KEYLENGTH);
    }

    OID oid;
    if (source.GetValue(Name::GroupOID(), oid))
    {
        m_oid = oid;
    }
}

void ed25519PublicKey::BERDecodeAndCheckAlgorithmID(BufferedTransformation& bt)
{
    // We have not yet determined the OID to use for this object.
    // We can't use OID's decoder because it throws BERDecodeError
    // if the OIDs do not match.
    OID oid(bt);

    if (!m_oid.Empty() && m_oid != oid)
        BERDecodeError();  // Only accept user specified OID
    else if (oid == ASN1::curve25519() || oid == ASN1::Ed25519())
        m_oid = oid;  // Accept any of the ed25519PublicKey OIDs
    else
        BERDecodeError();
}

void ed25519PublicKey::BERDecode(BufferedTransformation &bt)
{
    BERSequenceDecoder publicKeyInfo(bt);

        BERSequenceDecoder algorithm(publicKeyInfo);
            // GetAlgorithmID().BERDecodeAndCheck(algorithm);
            BERDecodeAndCheckAlgorithmID(algorithm);
        algorithm.MessageEnd();

        BERDecodePublicKey(publicKeyInfo, false, (size_t)publicKeyInfo.RemainingLength());

    publicKeyInfo.MessageEnd();
}

void ed25519PublicKey::DEREncode(BufferedTransformation &bt) const
{
    DERSequenceEncoder publicKeyInfo(bt);

        DERSequenceEncoder algorithm(publicKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DEREncodePublicKey(publicKeyInfo);

    publicKeyInfo.MessageEnd();
}

void ed25519PublicKey::BERDecodePublicKey(BufferedTransformation &bt, bool parametersPresent, size_t /*size*/)
{
    // We don't know how to decode them
    if (parametersPresent)
        BERDecodeError();

    SecByteBlock subjectPublicKey;
    unsigned int unusedBits;
    BERDecodeBitString(bt, subjectPublicKey, unusedBits);

    CRYPTOPP_ASSERT(unusedBits == 0);
    CRYPTOPP_ASSERT(subjectPublicKey.size() == PUBLIC_KEYLENGTH);
    if (subjectPublicKey.size() != PUBLIC_KEYLENGTH)
        BERDecodeError();

    std::memcpy(m_pk.begin(), subjectPublicKey, PUBLIC_KEYLENGTH);
}

void ed25519PublicKey::DEREncodePublicKey(BufferedTransformation &bt) const
{
    DEREncodeBitString(bt, m_pk, PUBLIC_KEYLENGTH);
}

void ed25519PublicKey::SetPublicElement (const byte y[PUBLIC_KEYLENGTH])
{
    std::memcpy(m_pk, y, PUBLIC_KEYLENGTH);
}

void ed25519PublicKey::SetPublicElement (const Integer &y)
{
    CRYPTOPP_ASSERT(y.MinEncodedSize() <= PUBLIC_KEYLENGTH);

    SecByteBlock by(PUBLIC_KEYLENGTH);
    y.Encode(by, PUBLIC_KEYLENGTH); std::reverse(by+0, by+PUBLIC_KEYLENGTH);

    std::memcpy(m_pk, by, PUBLIC_KEYLENGTH);
}

const Integer& ed25519PublicKey::GetPublicElement() const
{
    m_y = Integer(m_pk, PUBLIC_KEYLENGTH, Integer::UNSIGNED, LITTLE_ENDIAN_ORDER);
    return m_y;
}

bool ed25519PublicKey::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng); CRYPTOPP_UNUSED(level);
    return true;
}

////////////////////////

ed25519Verifier::ed25519Verifier(const byte y[PUBLIC_KEYLENGTH])
{
    AccessPublicKey().AssignFrom(MakeParameters
        (Name::PublicElement(), ConstByteArrayParameter(y, PUBLIC_KEYLENGTH)));
}

ed25519Verifier::ed25519Verifier(const Integer &y)
{
    CRYPTOPP_ASSERT(y.MinEncodedSize() <= PUBLIC_KEYLENGTH);

    SecByteBlock by(PUBLIC_KEYLENGTH);
    y.Encode(by, PUBLIC_KEYLENGTH); std::reverse(by+0, by+PUBLIC_KEYLENGTH);

    AccessPublicKey().AssignFrom(MakeParameters
        (Name::PublicElement(), ConstByteArrayParameter(by, PUBLIC_KEYLENGTH, false)));
}

ed25519Verifier::ed25519Verifier(const X509PublicKey &key)
{
    // Load all fields from the other key
    ByteQueue queue;
    key.Save(queue);
    AccessPublicKey().Load(queue);
}

ed25519Verifier::ed25519Verifier(BufferedTransformation &params)
{
    AccessPublicKey().Load(params);
}

ed25519Verifier::ed25519Verifier(const ed25519Signer& signer)
{
    const ed25519PrivateKey& priv = dynamic_cast<const ed25519PrivateKey&>(signer.GetPrivateKey());
    priv.MakePublicKey(AccessPublicKey());
}

bool ed25519Verifier::VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const
{
    ed25519_MessageAccumulator& accum = static_cast<ed25519_MessageAccumulator&>(messageAccumulator);
    const ed25519PublicKey& pk = dynamic_cast<const ed25519PublicKey&>(GetPublicKey());
    int ret = Donna::ed25519_sign_open(accum.data(), accum.size(), pk.GetPublicKeyBytePtr(), accum.signature());
    accum.Restart();

    return ret == 0;
}

bool ed25519Verifier::VerifyStream(std::istream& stream, const byte *signature, size_t signatureLen) const
{
    CRYPTOPP_ASSERT(signatureLen == SIGNATURE_LENGTH);
    CRYPTOPP_UNUSED(signatureLen);

    const ed25519PublicKey& pk = static_cast<const ed25519PublicKey&>(GetPublicKey());
    int ret = Donna::ed25519_sign_open(stream, pk.GetPublicKeyBytePtr(), signature);

    return ret == 0;
}

NAMESPACE_END  // CryptoPP
