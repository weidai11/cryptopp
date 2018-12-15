// xed25519.cpp - written and placed in public domain by Jeffrey Walton
//                Crypto++ specific implementation wrapped around Andrew
//                Moon's public domain curve25519-donna. Also see
//                https://github.com/floodyberry/curve25519-donna.

#include "pch.h"

#include "cryptlib.h"
#include "asn.h"
#include "integer.h"
#include "filters.h"

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
    Donna::curve25519_mult(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(const Integer &y, const Integer &x)
{
    ArraySink ys(m_pk, PUBLIC_KEYLENGTH);
    y.Encode(ys, PUBLIC_KEYLENGTH);

    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(const Integer &x)
{
    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);
    Donna::curve25519_mult(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

x25519::x25519(RandomNumberGenerator &rng)
{
    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    ClampKey(m_sk);
    Donna::curve25519_mult(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
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
          Donna::curve25519_mult(m_pk, m_sk);
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

void x25519::ClampKey(byte x[SECRET_KEYLENGTH]) const
{
    x[0] &= 248;
    x[31] &= 127;
    x[31] |= 64;
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
    // Avoid throwing parameter not used
    int unused;
    params.GetValue("KeySize", unused);

    ConstByteArrayParameter seed;
    if (params.GetValue("Seed", seed) && rng.CanIncorporateEntropy())
        rng.IncorporateEntropy(seed.begin(), seed.size());

    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    ClampKey(m_sk);
    (void)Donna::curve25519_mult(m_pk, m_sk);

    CRYPTOPP_ASSERT(IsClamped(m_sk) == true);
    CRYPTOPP_ASSERT(IsSmallOrder(m_pk) == false);
}

void x25519::GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const
{
    rng.GenerateBlock(privateKey, SECRET_KEYLENGTH);
    ClampKey(privateKey);
}

void x25519::GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const
{
    CRYPTOPP_UNUSED(rng);

    (void)Donna::curve25519_mult(publicKey, privateKey);
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
}

ed25519Signer::ed25519Signer(const byte x[SECRET_KEYLENGTH])
{
    std::memcpy(m_sk, x, SECRET_KEYLENGTH);
    Donna::curve25519_mult(m_pk, m_sk);
}

ed25519Signer::ed25519Signer(const Integer &y, const Integer &x)
{
    ArraySink ys(m_pk, PUBLIC_KEYLENGTH);
    y.Encode(ys, PUBLIC_KEYLENGTH);

    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);
}

ed25519Signer::ed25519Signer(const Integer &x)
{
    ArraySink xs(m_sk, SECRET_KEYLENGTH);
    x.Encode(xs, SECRET_KEYLENGTH);
    Donna::curve25519_mult(m_pk, m_sk);
}

ed25519Signer::ed25519Signer(RandomNumberGenerator &rng)
{
    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    Donna::curve25519_mult(m_pk, m_sk);
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
          Donna::curve25519_mult(m_pk, m_sk);
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

bool ed25519Signer::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    return true;
}

bool ed25519Signer::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    if (valueType == typeid(ConstByteArrayParameter))
    {
        if (std::strcmp(name, "SecretKey") == 0 || std::strcmp(name, "PrivateExponent") == 0)
        {
            std::memcpy(pValue, m_sk, 64);
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
    // Avoid throwing parameter not used
    int unused;
    params.GetValue("KeySize", unused);

    ConstByteArrayParameter seed;
    if (params.GetValue("Seed", seed) && rng.CanIncorporateEntropy())
        rng.IncorporateEntropy(seed.begin(), seed.size());

    rng.GenerateBlock(m_sk, SECRET_KEYLENGTH);
    (void)Donna::curve25519_mult(m_pk, m_sk);
}

// ******************** ed25519 Verifier ************************* //

ed25519Verifier::ed25519Verifier(const byte y[PUBLIC_KEYLENGTH])
{
    std::memcpy(m_pk, y, PUBLIC_KEYLENGTH);
}

ed25519Verifier::ed25519Verifier(const Integer &y)
{
    ArraySink ys(m_pk, PUBLIC_KEYLENGTH);
    y.Encode(ys, PUBLIC_KEYLENGTH);
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
    std::memcpy(m_pk, signer.m_pk, PUBLIC_KEYLENGTH);
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

NAMESPACE_END  // CryptoPP
