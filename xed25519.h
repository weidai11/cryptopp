// xed25519.h - written and placed in public domain by Jeffrey Walton
//              Crypto++ specific implementation wrapped around Adam
//              Langley's curve25519-donna.

#ifndef CRYPTOPP_XED25519_H
#define CRYPTOPP_XED25519_H

#include "cryptlib.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

class Integer;

/// \brief x25519 with key validation
class x25519 : public SimpleKeyAgreementDomain, public CryptoParameters
{
public:
    x25519(const byte y[32], const byte x[32]);
    x25519(const Integer &y, const Integer &x);
    x25519(RandomNumberGenerator &rng);
    x25519(BufferedTransformation &params);

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
