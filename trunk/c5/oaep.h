#ifndef CRYPTOPP_OAEP_H
#define CRYPTOPP_OAEP_H

#include "pubkey.h"

NAMESPACE_BEGIN(CryptoPP)

extern byte OAEP_P_DEFAULT[];	// defined in misc.cpp

/// <a href="http://www.weidai.com/scan-mirror/ca.html#cem_OAEP-MGF1">EME-OAEP</a>, for use with RSAES
template <class H, class MGF=P1363_MGF1, byte *P=OAEP_P_DEFAULT, unsigned int PLen=0>
class OAEP : public PK_EncryptionMessageEncodingMethod, public EncryptionStandard
{
public:
	static std::string StaticAlgorithmName() {return std::string("OAEP-") + MGF::StaticAlgorithmName() + "(" + H::StaticAlgorithmName() + ")";}
	typedef OAEP<H, MGF, P, PLen> EncryptionMessageEncodingMethod;

	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const;
	void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const;
	DecodingResult Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const;
};

NAMESPACE_END

#endif
