// oaep.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "oaep.h"

#include <functional>

NAMESPACE_BEGIN(CryptoPP)

// ********************************************************

ANONYMOUS_NAMESPACE_BEGIN
	template <class H, byte *P, unsigned int PLen>
	struct PHashComputation
	{
		PHashComputation()	{H().CalculateDigest(pHash, P, PLen);}
		byte pHash[H::DIGESTSIZE];
	};

	template <class H, byte *P, unsigned int PLen>
	const byte *PHash()
	{
		static PHashComputation<H,P,PLen> pHash;
		return pHash.pHash;
	}
NAMESPACE_END

template <class H, class MGF, byte *P, unsigned int PLen>
unsigned int OAEP<H,MGF,P,PLen>::MaxUnpaddedLength(unsigned int paddedLength) const
{
	return paddedLength/8 > 1+2*H::DIGESTSIZE ? paddedLength/8-1-2*H::DIGESTSIZE : 0;
}

template <class H, class MGF, byte *P, unsigned int PLen>
void OAEP<H,MGF,P,PLen>::Pad(RandomNumberGenerator &rng, const byte *input, unsigned int inputLength, byte *oaepBlock, unsigned int oaepBlockLen) const
{
	assert (inputLength <= MaxUnpaddedLength(oaepBlockLen));

	// convert from bit length to byte length
	if (oaepBlockLen % 8 != 0)
	{
		oaepBlock[0] = 0;
		oaepBlock++;
	}
	oaepBlockLen /= 8;

	const unsigned int hLen = H::DIGESTSIZE;
	const unsigned int seedLen = hLen, dbLen = oaepBlockLen-seedLen;
	byte *const maskedSeed = oaepBlock;
	byte *const maskedDB = oaepBlock+seedLen;

	// DB = pHash || 00 ... || 01 || M
	memcpy(maskedDB, PHash<H,P,PLen>(), hLen);
	memset(maskedDB+hLen, 0, dbLen-hLen-inputLength-1);
	maskedDB[dbLen-inputLength-1] = 0x01;
	memcpy(maskedDB+dbLen-inputLength, input, inputLength);

	rng.GenerateBlock(maskedSeed, seedLen);
	H h;
	MGF mgf;
	mgf.GenerateAndMask(h, maskedDB, dbLen, maskedSeed, seedLen);
	mgf.GenerateAndMask(h, maskedSeed, seedLen, maskedDB, dbLen);
}

template <class H, class MGF, byte *P, unsigned int PLen>
DecodingResult OAEP<H,MGF,P,PLen>::Unpad(const byte *oaepBlock, unsigned int oaepBlockLen, byte *output) const
{
	bool invalid = false;

	// convert from bit length to byte length
	if (oaepBlockLen % 8 != 0)
	{
		invalid = (oaepBlock[0] != 0) || invalid;
		oaepBlock++;
	}
	oaepBlockLen /= 8;

	const unsigned int hLen = H::DIGESTSIZE;
	const unsigned int seedLen = hLen, dbLen = oaepBlockLen-seedLen;

	invalid = (oaepBlockLen < 2*hLen+1) || invalid;

	SecByteBlock t(oaepBlock, oaepBlockLen);
	byte *const maskedSeed = t;
	byte *const maskedDB = t+seedLen;

	H h;
	MGF mgf;
	mgf.GenerateAndMask(h, maskedSeed, seedLen, maskedDB, dbLen);
	mgf.GenerateAndMask(h, maskedDB, dbLen, maskedSeed, seedLen);

	// DB = pHash' || 00 ... || 01 || M

	byte *M = std::find(maskedDB+hLen, maskedDB+dbLen, 0x01);
	invalid = (M == maskedDB+dbLen) || invalid;
	invalid = (std::find_if(maskedDB+hLen, M, std::bind2nd(std::not_equal_to<byte>(), 0)) != M) || invalid;
	invalid = (memcmp(maskedDB, PHash<H,P,PLen>(), hLen) != 0) || invalid;

	if (invalid)
		return DecodingResult();

	M++;
	memcpy(output, M, maskedDB+dbLen-M);
	return DecodingResult(maskedDB+dbLen-M);
}

NAMESPACE_END
