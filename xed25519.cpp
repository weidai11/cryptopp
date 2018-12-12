// xed25519_32.cpp - written and placed in public domain by Jeffrey Walton
//                   Crypto++ specific implementation wrapped around Adam
//                   Langley's curve25519-donna.

#include "pch.h"

#include "cryptlib.h"
#include "asn.h"
#include "integer.h"
#include "filters.h"

#include "xed25519.h"
#include "donna.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;

// See the comments for the code in tweetnacl.cpp
int is_small_order(const byte s[32])
{
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

  // The magic 12 is the count of blaklisted points
  byte c[12] = { 0 };
  for (size_t j = 0; j < 32; j++) {
    for (size_t i = 0; i < COUNTOF(blacklist); i++) {
      c[i] |= s[j] ^ blacklist[i][j];
    }
  }

  unsigned int k = 0;
  for (size_t i = 0; i < COUNTOF(blacklist); i++) {
    k |= (c[i] - 1);
  }

  return (int) ((k >> 8) & 1);
}

int is_clamped(const byte s[32])
{
  return (s[0] & 248) == s[0] && (s[31] & 127) == s[31] && (s[31] | 64) == s[31];
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

x25519::x25519(const byte y[32], const byte x[32])
{
    std::memcpy(m_pk, y, 32);
    std::memcpy(m_sk, x, 32);

    CRYPTOPP_ASSERT(is_clamped(m_sk) != 0);
    CRYPTOPP_ASSERT(is_small_order(m_pk) == 0);
}

x25519::x25519(const byte x[32])
{
    std::memcpy(m_sk, x, 32);
    GeneratePublicKey(NullRNG(), m_sk, m_pk);

    CRYPTOPP_ASSERT(is_clamped(m_sk) != 0);
    CRYPTOPP_ASSERT(is_small_order(m_pk) == 0);
}

x25519::x25519(const Integer &y, const Integer &x)
{
    ArraySink ys(m_pk, 32);
    y.Encode(ys, 32);

    ArraySink xs(m_sk, 32);
    x.Encode(xs, 32);

    CRYPTOPP_ASSERT(is_clamped(m_sk) != 0);
    CRYPTOPP_ASSERT(is_small_order(m_pk) == 0);
}

x25519::x25519(const Integer &x)
{
    ArraySink xs(m_sk, 32);
    x.Encode(xs, 32);
    GeneratePublicKey(NullRNG(), m_sk, m_pk);

    CRYPTOPP_ASSERT(is_clamped(m_sk) != 0);
    CRYPTOPP_ASSERT(is_small_order(m_pk) == 0);
}

x25519::x25519(RandomNumberGenerator &rng)
{
    GeneratePrivateKey(rng, m_sk);
    GeneratePublicKey(NullRNG(), m_sk, m_pk);

    CRYPTOPP_ASSERT(is_clamped(m_sk) != 0);
    CRYPTOPP_ASSERT(is_small_order(m_pk) == 0);
}

x25519::x25519(BufferedTransformation &params)
{
    // TODO: Fix the on-disk format once we determine what it is.
    BERSequenceDecoder seq(params);

      size_t read; byte unused;

      BERSequenceDecoder sk(seq, BIT_STRING);
      read = sk.Get(unused);  // unused bits
      CRYPTOPP_ASSERT(read == 1 && unused == 0);

      CRYPTOPP_ASSERT(sk.MaxRetrievable() >= 32);
      read = sk.Get(m_sk, 32);
      sk.MessageEnd();

      if (read != 32)
          throw BERDecodeErr();

      if (seq.EndReached())
      {
          GeneratePublicKey(NullRNG(), m_sk, m_pk);
      }
      else
      {
          BERSequenceDecoder pk(seq, OCTET_STRING);
          CRYPTOPP_ASSERT(pk.MaxRetrievable() >= 32);
          read = pk.Get(m_pk, 32);
          pk.MessageEnd();

          if (read != 32)
              throw BERDecodeErr();
      }

    seq.MessageEnd();

    CRYPTOPP_ASSERT(is_clamped(m_sk) != 0);
    CRYPTOPP_ASSERT(is_small_order(m_pk) == 0);
}

void x25519::DEREncode(BufferedTransformation &params) const
{
    // TODO: Fix the on-disk format once we determine what it is.
    DERSequenceEncoder seq(params);

      DERSequenceEncoder sk(seq, BIT_STRING);
      sk.Put((byte)0);   // unused bits
      sk.Put(m_sk, 32);
      sk.MessageEnd();

      DERSequenceEncoder pk(seq, OCTET_STRING);
      pk.Put(m_pk, 32);
      pk.MessageEnd();

    seq.MessageEnd();
}

bool x25519::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_ASSERT(is_clamped(m_sk) != 0);
    CRYPTOPP_ASSERT(is_small_order(m_pk) == 0);

    if (level >= 1 && is_clamped(m_sk) == 0)
        return false;
    if (level >= 2 && is_small_order(m_pk) != 0)
        return false;

    return true;
}

bool x25519::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    if (valueType == typeid(ConstByteArrayParameter))
    {
        if (std::strcmp(name, "SecretKey") == 0)
        {
            std::memcpy(pValue, m_sk, 32);
            return true;
        }
        else if (std::strcmp(name, "PublicKey") == 0)
        {
            std::memcpy(pValue, m_pk, 32);
            return true;
        }
    }

    return false;
}

void x25519::AssignFrom(const NameValuePairs &source)
{
    ConstByteArrayParameter val;
    if (source.GetValue("SecretKey", val))
    {
        std::memcpy(m_sk, val.begin(), 32);
    }
    else if (source.GetValue("PublicKey", val))
    {
        std::memcpy(m_pk, val.begin(), 32);
    }
}

void x25519::GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const
{
    rng.GenerateBlock(privateKey, 32);

    privateKey[0] &= 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;
}

void x25519::GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const
{
    CRYPTOPP_UNUSED(rng);

    const byte base[32] = {9};
    (void)Donna::curve25519(publicKey, privateKey, base);
}

bool x25519::Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey) const
{
    CRYPTOPP_ASSERT(agreedValue != NULLPTR);
    CRYPTOPP_ASSERT(otherPublicKey != NULLPTR);

    if (validateOtherPublicKey && is_small_order(otherPublicKey) != 0)
        return false;

    return Donna::curve25519(agreedValue, privateKey, otherPublicKey) == 0;
}

NAMESPACE_END  // CryptoPP
