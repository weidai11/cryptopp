// dh2.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "cryptlib.h"
#include "misc.h"
#include "dh2.h"

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
struct NullCryptoParameters : public CryptoParameters
{
	void AssignFrom(const NameValuePairs &source) {
	}
	bool Validate(RandomNumberGenerator &rng, unsigned int level) const {
		return false;
	}
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const {
		return false;
	}
};

struct NullSimpleKeyAgreementDomain : public TwoBases<NullCryptoParameters, SimpleKeyAgreementDomain>
{
	CryptoParameters & AccessCryptoParameters() {
		return *this;
	}
	unsigned int AgreedValueLength() const {
		return 1;
	}
	unsigned int PrivateKeyLength() const {
		return 1;
	}
	unsigned int PublicKeyLength() const {
		return 1;
	}
	void GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const {
	}
	void GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const {
	}
	bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const {
		return false;
	}
};

void DH2_TestInstantiations()
{
	NullSimpleKeyAgreementDomain dom;
	DH2 dh(dom);
}
#endif

bool DH2::Agree(byte *agreedValue,
		const byte *staticSecretKey, const byte *ephemeralSecretKey,
		const byte *staticOtherPublicKey, const byte *ephemeralOtherPublicKey,
		bool validateStaticOtherPublicKey) const
{
	return d1.Agree(agreedValue, staticSecretKey, staticOtherPublicKey, validateStaticOtherPublicKey)
		&& d2.Agree(agreedValue+d1.AgreedValueLength(), ephemeralSecretKey, ephemeralOtherPublicKey, true);
}

NAMESPACE_END
