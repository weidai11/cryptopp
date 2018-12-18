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

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

// ******************** x25519 Agreement ************************* //

x25519::x25519(const byte y[PUBLIC_KEYLENGTH], const byte x[SECRET_KEYLENGTH])
{
    std::memcpy(m_pk, y, SECRET_KEYLENGTH);
    std::memcpy(m_sk, x, PUBLIC_KEYLENGTH);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(const byte x[SECRET_KEYLENGTH])
{
    std::memcpy(m_sk, x, SECRET_KEYLENGTH);
    ClampKeys(m_pk, m_sk);
}

x25519::x25519(const Integer &y, const Integer &x)
{
    CRYPTOPP_ASSERT(y.MinEncodedSize() <= PUBLIC_KEYLENGTH);
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    ArraySink ys(m_pk, PUBLIC_KEYLENGTH);
    y.Encode(ys, PUBLIC_KEYLENGTH);
    std::reverse(m_pk+0, m_pk+PUBLIC_KEYLENGTH);

    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);
    std::reverse(m_sk+0, m_sk+SECRET_KEYLENGTH);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(const Integer &x)
{
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);
    std::reverse(m_sk+0, m_sk+SECRET_KEYLENGTH);

    ClampKeys(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(RandomNumberGenerator &rng)
{
    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    m_sk[0] &= 248; m_sk[31] &= 127; m_sk[31] |= 64;
    Donna::curve25519_mult(m_pk, m_sk);
}

x25519::x25519(BufferedTransformation &params)
{
    // TODO: Fix the on-disk format once we determine what it is.
    BERSequenceDecoder seq(params);

      size_t read; byte unused;

      BERSequenceDecoder sk(seq, BIT_STRING);
      CRYPTOPP_ASSERT(sk.MaxRetrievable() >= SECRET_KEYLENGTH+1);

      read = sk.Get(unused);  // unused bits
      CRYPTOPP_ASSERT(read == 1 && unused == 0);

      read = sk.Get(m_sk, SECRET_KEYLENGTH);
      sk.MessageEnd();

      if (read != SECRET_KEYLENGTH)
          throw BERDecodeErr();

      if (seq.EndReached())
      {
          ClampKeys(m_pk, m_sk);
      }
      else
      {
          BERSequenceDecoder pk(seq, OCTET_STRING);
          CRYPTOPP_ASSERT(pk.MaxRetrievable() >= PUBLIC_KEYLENGTH);
          read = pk.Get(m_pk, PUBLIC_KEYLENGTH);
          pk.MessageEnd();

          if (read != PUBLIC_KEYLENGTH)
              throw BERDecodeErr();
      }

    seq.MessageEnd();

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

void x25519::ClampKeys(byte y[PUBLIC_KEYLENGTH], byte x[SECRET_KEYLENGTH]) const
{
    x[0] &= 248; x[31] &= 127; x[31] |= 64;
    Donna::curve25519_mult(y, x);
}

bool x25519::IsClamped(const byte x[SECRET_KEYLENGTH]) const
{
    return (x[0] & 248) == x[0] && (x[31] & 127) == x[31] && (x[31] | 64) == x[31];
}

bool x25519::IsSmallOrder(const byte y[PUBLIC_KEYLENGTH]) const
{
    // The magic 12 is the count of blaklisted points
    byte c[12] = { 0 };
    for (size_t j = 0; j < PUBLIC_KEYLENGTH; j++) {
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

void x25519::DEREncode(BufferedTransformation &params) const
{
    // TODO: Fix the on-disk format once we determine what it is.
    DERSequenceEncoder seq(params);

      DERSequenceEncoder sk(seq, BIT_STRING);
      sk.Put((byte)0);   // unused bits
      sk.Put(m_sk, SECRET_KEYLENGTH);
      sk.MessageEnd();

      DERSequenceEncoder pk(seq, OCTET_STRING);
      pk.Put(m_pk, PUBLIC_KEYLENGTH);
      pk.MessageEnd();

    seq.MessageEnd();
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

    return true;
}

bool x25519::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    if (valueType == typeid(ConstByteArrayParameter))
    {
        if (std::strcmp(name, "SecretKey") == 0 || std::strcmp(name, "PrivateExponent") == 0)
        {
            std::memcpy(pValue, m_sk, SECRET_KEYLENGTH);
            return true;
        }
        else if (std::strcmp(name, "PublicKey") == 0)
        {
            std::memcpy(pValue, m_pk, PUBLIC_KEYLENGTH);
            return true;
        }
    }

    return false;
}

void x25519::AssignFrom(const NameValuePairs &source)
{
    ConstByteArrayParameter val;
    if (source.GetValue("SecretKey", val) || source.GetValue("PrivateExponent", val))
    {
        std::memcpy(m_sk, val.begin(), SECRET_KEYLENGTH);
    }
    else if (source.GetValue("PublicKey", val))
    {
        std::memcpy(m_pk, val.begin(), PUBLIC_KEYLENGTH);
    }
}

void x25519::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params)
{
    ConstByteArrayParameter seed;
    if (params.GetValue("Seed", seed) && rng.CanIncorporateEntropy())
        rng.IncorporateEntropy(seed.begin(), seed.size());

    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    m_sk[0] &= 248; m_sk[31] &= 127; m_sk[31] |= 64;
    Donna::curve25519_mult(m_pk, m_sk);
}

void x25519::GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const
{
    rng.GenerateBlock(privateKey, SECRET_KEYLENGTH);
    privateKey[0] &= 248; privateKey[31] &= 127; privateKey[31] |= 64;
}

void x25519::GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const
{
    CRYPTOPP_UNUSED(rng);
    Donna::curve25519_mult(publicKey, privateKey);
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

ed25519Signer::ed25519Signer(const byte y[PUBLIC_KEYLENGTH], const byte x[SECRET_KEYLENGTH])
{
    std::memcpy(m_pk, y, PUBLIC_KEYLENGTH);
    std::memcpy(m_sk, x, SECRET_KEYLENGTH);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
}

ed25519Signer::ed25519Signer(const byte x[SECRET_KEYLENGTH])
{
    std::memcpy(m_sk, x, SECRET_KEYLENGTH);
    ClampKeys(m_pk, m_sk);
}

ed25519Signer::ed25519Signer(const Integer &y, const Integer &x)
{
    CRYPTOPP_ASSERT(y.MinEncodedSize() <= PUBLIC_KEYLENGTH);
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    ArraySink ys(m_pk, PUBLIC_KEYLENGTH);
    y.Encode(ys, PUBLIC_KEYLENGTH);
    std::reverse(m_pk+0, m_pk+PUBLIC_KEYLENGTH);

    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);
    std::reverse(m_sk+0, m_sk+SECRET_KEYLENGTH);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
}

ed25519Signer::ed25519Signer(const Integer &x)
{
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);
    std::reverse(m_sk+0, m_sk+SECRET_KEYLENGTH);

    ClampKeys(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
}

ed25519Signer::ed25519Signer(RandomNumberGenerator &rng)
{
    rng.GenerateBlock(m_sk, 32);
    m_sk[0] &= 248; m_sk[31] &= 127; m_sk[31] |= 64;

    int ret = Donna::ed25519_publickey(m_pk, m_sk);
    CRYPTOPP_ASSERT(ret == 0);
}

ed25519Signer::ed25519Signer(BufferedTransformation &params)
{
    // TODO: Fix the on-disk format once we determine what it is.
    BERSequenceDecoder seq(params);

      size_t read; byte unused;

      BERSequenceDecoder sk(seq, BIT_STRING);
      CRYPTOPP_ASSERT(sk.MaxRetrievable() >= SECRET_KEYLENGTH + 1);

      read = sk.Get(unused);  // unused bits
      CRYPTOPP_ASSERT(read == 1 && unused == 0);

      read = sk.Get(m_sk, SECRET_KEYLENGTH);
      sk.MessageEnd();

      if (read != SECRET_KEYLENGTH)
          throw BERDecodeErr();

      if (seq.EndReached())
      {
          ClampKeys(m_pk, m_sk);
      }
      else
      {
          BERSequenceDecoder pk(seq, OCTET_STRING);
          CRYPTOPP_ASSERT(pk.MaxRetrievable() >= PUBLIC_KEYLENGTH);
          read = pk.Get(m_pk, PUBLIC_KEYLENGTH);
          pk.MessageEnd();

          if (read != PUBLIC_KEYLENGTH)
              throw BERDecodeErr();
      }

    seq.MessageEnd();
}

void ed25519Signer::ClampKeys(byte y[PUBLIC_KEYLENGTH], byte x[SECRET_KEYLENGTH]) const
{
    x[0] &= 248; x[31] &= 127; x[31] |= 64;
    int ret = Donna::ed25519_publickey(y, x);
    CRYPTOPP_ASSERT(ret == 0);
}

bool ed25519Signer::IsClamped(const byte x[SECRET_KEYLENGTH]) const
{
    return (x[0] & 248) == x[0] && (x[31] & 127) == x[31] && (x[31] | 64) == x[31];
}

bool ed25519Signer::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng); CRYPTOPP_UNUSED(level);
    return true;
}

bool ed25519Signer::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    if (valueType == typeid(ConstByteArrayParameter))
    {
        if (std::strcmp(name, "SecretKey") == 0 || std::strcmp(name, "PrivateExponent") == 0)
        {
            std::memcpy(pValue, m_sk, SECRET_KEYLENGTH);
            return true;
        }
        else if (std::strcmp(name, "PublicKey") == 0)
        {
            std::memcpy(pValue, m_pk, PUBLIC_KEYLENGTH);
            return true;
        }
    }

    return false;
}

void ed25519Signer::AssignFrom(const NameValuePairs &source)
{
    ConstByteArrayParameter val;
    if (source.GetValue("SecretKey", val) || source.GetValue("PrivateExponent", val))
    {
        std::memcpy(m_sk, val.begin(), SECRET_KEYLENGTH);
    }
    else if (source.GetValue("PublicKey", val))
    {
        std::memcpy(m_pk, val.begin(), PUBLIC_KEYLENGTH);
    }
}

void ed25519Signer::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params)
{
    ConstByteArrayParameter seed;
    if (params.GetValue("Seed", seed) && rng.CanIncorporateEntropy())
        rng.IncorporateEntropy(seed.begin(), seed.size());

    rng.GenerateBlock(m_sk, 32);
    m_sk[0] &= 248; m_sk[31] &= 127; m_sk[31] |= 64;
    int ret = Donna::ed25519_publickey(m_pk, m_sk);
    CRYPTOPP_ASSERT(ret == 0);
}

void ed25519Signer::MakePublicKey (PublicKey &pub) const
{
    pub.AssignFrom(MakeParameters("PublicKey", ConstByteArrayParameter(m_pk.begin(), m_pk.size(), false)));
}

void ed25519Signer::SetPrivateExponent (const byte x[SECRET_KEYLENGTH])
{
    std::memcpy(m_sk, x, SECRET_KEYLENGTH);
}

void ed25519Signer::SetPrivateExponent (const Integer &x)
{
    CRYPTOPP_ASSERT(x.MinEncodedSize() <= SECRET_KEYLENGTH);

    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);
    std::reverse(m_sk+0, m_sk+SECRET_KEYLENGTH);

    ClampKeys(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
}

const Integer& ed25519Signer::GetPrivateExponent() const
{
    m_temp = Integer(m_sk, SECRET_KEYLENGTH, Integer::UNSIGNED, LITTLE_ENDIAN_ORDER);
    return m_temp;
}

size_t ed25519Signer::SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart) const {
    CRYPTOPP_ASSERT(signature != NULLPTR); CRYPTOPP_UNUSED(rng);

    ed25519_MessageAccumulator& accum = static_cast<ed25519_MessageAccumulator&>(messageAccumulator);
    int ret = Donna::ed25519_sign(accum.data(), accum.size(), m_sk, m_pk, signature);
    CRYPTOPP_ASSERT(ret == 0);

    if (restart)
        accum.Restart();

    return ret == 0 ? SIGNATURE_LENGTH : 0;
}

// ******************** ed25519 Verifier ************************* //

ed25519Verifier::ed25519Verifier(const byte y[PUBLIC_KEYLENGTH])
{
    std::memcpy(m_pk, y, PUBLIC_KEYLENGTH);
}

ed25519Verifier::ed25519Verifier(const Integer &y)
{
    CRYPTOPP_ASSERT(y.MinEncodedSize() <= PUBLIC_KEYLENGTH);

    ArraySink ys(m_pk, PUBLIC_KEYLENGTH);
    y.Encode(ys, PUBLIC_KEYLENGTH);
    std::reverse(m_pk+0, m_pk+PUBLIC_KEYLENGTH);
}

ed25519Verifier::ed25519Verifier(BufferedTransformation &params)
{
    // TODO: Fix the on-disk format once we determine what it is.
    BERSequenceDecoder seq(params);

      size_t read;
      BERSequenceDecoder pk(seq, OCTET_STRING);
      CRYPTOPP_ASSERT(pk.MaxRetrievable() >= PUBLIC_KEYLENGTH);
      read = pk.Get(m_pk, PUBLIC_KEYLENGTH);
      pk.MessageEnd();

      if (read != PUBLIC_KEYLENGTH)
          throw BERDecodeErr();

    seq.MessageEnd();
}

ed25519Verifier::ed25519Verifier(const ed25519Signer& signer)
{
    signer.MakePublicKey(AccessPublicKey());
}

bool ed25519Verifier::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng); CRYPTOPP_UNUSED(level);
    return true;
}

bool ed25519Verifier::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    if (valueType == typeid(ConstByteArrayParameter))
    {
        if (std::strcmp(name, "PublicKey") == 0)
        {
            std::memcpy(pValue, m_pk, PUBLIC_KEYLENGTH);
            return true;
        }
    }

    return false;
}

void ed25519Verifier::AssignFrom(const NameValuePairs &source)
{
    ConstByteArrayParameter val;
    if (source.GetValue("PublicKey", val))
    {
        std::memcpy(m_pk, val.begin(), PUBLIC_KEYLENGTH);
    }
}

void ed25519Verifier::SetPublicElement (const byte y[PUBLIC_KEYLENGTH])
{
    std::memcpy(m_pk, y, PUBLIC_KEYLENGTH);
}

void ed25519Verifier::SetPublicElement (const Integer &y)
{
    CRYPTOPP_ASSERT(y.MinEncodedSize() <= PUBLIC_KEYLENGTH);

    ArraySink ys(m_pk, PUBLIC_KEYLENGTH);
    y.Encode(ys, PUBLIC_KEYLENGTH);
    std::reverse(m_pk+0, m_pk+PUBLIC_KEYLENGTH);
}

const Integer& ed25519Verifier::GetPublicElement() const
{
    m_temp = Integer(m_pk, PUBLIC_KEYLENGTH, Integer::UNSIGNED, LITTLE_ENDIAN_ORDER);
    return m_temp;
}

bool ed25519Verifier::VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const {

    ed25519_MessageAccumulator& accum = static_cast<ed25519_MessageAccumulator&>(messageAccumulator);
    int ret = Donna::ed25519_sign_open(accum.data(), accum.size(), m_pk, accum.signature());
    accum.Restart();

    return ret == 0;
}

NAMESPACE_END  // CryptoPP
