// xed25519_32.cpp - written and placed in public domain by Jeffrey Walton
//                   Crypto++ specific implementation wrapped around Adam
//                   Langley's curve25519-donna.

#include "pch.h"

#include "cryptlib.h"
#include "asn.h"
#include "integer.h"
#include "filters.h"
#include "argnames.h"

#include "xed25519.h"
#include "donna.h"

NAMESPACE_BEGIN(CryptoPP)

x25519::x25519(const byte y[32], const byte x[32])
{
    std::memcpy(m_pk, y, 32);
    std::memcpy(m_sk, x, 32);
}

x25519::x25519(const Integer &y, const Integer &x)
{
    ArraySink ys(m_pk, 32);
    y.Encode(ys, 32);

    ArraySink xs(m_sk, 32);
    x.Encode(xs, 32);
}

x25519::x25519(RandomNumberGenerator &rng)
{
    GeneratePrivateKey(rng, m_sk);
    GeneratePublicKey(NullRNG(), m_sk, m_pk);
}

x25519::x25519(BufferedTransformation &params)
{
    // TODO: Fix the on-disk format once we know what it is.
    BERSequenceDecoder seq(params);

      BERGeneralDecoder x(seq, BIT_STRING);
      if (!x.IsDefiniteLength() || x.MaxRetrievable() < 32)
        BERDecodeError();
      x.Get(m_sk, 32);
      x.MessageEnd();

      BERGeneralDecoder y(seq, OCTET_STRING);
      if (!y.IsDefiniteLength() || y.MaxRetrievable() < 32)
        BERDecodeError();
      y.Get(m_pk, 32);
      y.MessageEnd();

    seq.MessageEnd();
}

void x25519::DEREncode(BufferedTransformation &params) const
{
    // TODO: Fix the on-disk format once we know what it is.
    DERSequenceEncoder seq(params);

      DERSequenceEncoder x(seq, BIT_STRING);
      x.Put(m_sk, 32);
      x.MessageEnd();

      DERSequenceEncoder y(seq, OCTET_STRING);
      y.Put(m_pk, 32);
      y.MessageEnd();

    seq.MessageEnd();
}

bool x25519::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);

    // TODO: add weak keys test
    return true;
}

bool x25519::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    //return GetValueHelper(this, name, valueType, pValue).Assignable()
    //    CRYPTOPP_GET_FUNCTION_ENTRY(SecretKey)
    //    CRYPTOPP_GET_FUNCTION_ENTRY(PublicKey)
    //    ;

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
    //AssignFromHelper(this, source)
    //    CRYPTOPP_SET_FUNCTION_ENTRY(SecretKey)
    //    CRYPTOPP_SET_FUNCTION_ENTRY(PublicKey)
    //    ;

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

    if (validateOtherPublicKey && Validate(NullRNG(), 3) == false)
        return false;

    return Donna::curve25519(agreedValue, privateKey, otherPublicKey) == 0;
}

NAMESPACE_END  // CryptoPP
