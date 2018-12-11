// xed25519.h - written and placed in public domain by Jeffrey Walton
//              Crypto++ specific implementation wrapped around Adam
//              Langley's curve25519-donna.

#ifndef CRYPTOPP_XED25519_H
#define CRYPTOPP_XED25519_H

#include "cryptlib.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

class x25519PrivateKey : public PrivateKey
{
public:
	bool Validate(RandomNumberGenerator &,unsigned int) const;

	void AssignFrom(const CryptoPP::NameValuePairs &);
	bool GetVoidValue(const char *,const type_info &,void *) const;

private:
	SecByteBlock m_priv;
};

class x25519PublicKey : public PublicKey
{
public:
	bool Validate(RandomNumberGenerator &,unsigned int) const;

	void AssignFrom(const CryptoPP::NameValuePairs &);
	bool GetVoidValue(const char *,const type_info &,void *) const;

private:
	SecByteBlock m_pub;
};

NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_XED25519_H
