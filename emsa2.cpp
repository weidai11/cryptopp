// emsa2.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "emsa2.h"

#ifndef CRYPTOPP_IMPORTS

NAMESPACE_BEGIN(CryptoPP)

// Inclusion based on DLL due to Clang, http://github.com/weidai11/cryptopp/issues/300
#ifndef CRYPTOPP_IS_DLL
template<> const byte EMSA2HashId<SHA1>::id = 0x33;
template<> const byte EMSA2HashId<SHA224>::id = 0x38;
template<> const byte EMSA2HashId<SHA256>::id = 0x34;
template<> const byte EMSA2HashId<SHA384>::id = 0x36;
template<> const byte EMSA2HashId<SHA512>::id = 0x35;
#endif

void EMSA2Pad::ComputeMessageRepresentative(RandomNumberGenerator& /*rng*/,
	const byte* recoverableMessage, size_t recoverableMessageLength,
	HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
	byte *representative, size_t representativeBitLength) const
{
	CRYPTOPP_UNUSED(recoverableMessage), CRYPTOPP_UNUSED(recoverableMessageLength), CRYPTOPP_UNUSED(representativeBitLength);
	CRYPTOPP_ASSERT(representativeBitLength >= MinRepresentativeBitLength(hashIdentifier.second, hash.DigestSize()));

	if (representativeBitLength % 8 != 7)
		throw PK_SignatureScheme::InvalidKeyLength("EMSA2: EMSA2 requires a key length that is a multiple of 8");

	size_t digestSize = hash.DigestSize();
	size_t representativeByteLength = BitsToBytes(representativeBitLength);

	representative[0] = messageEmpty ? 0x4b : 0x6b;
	std::memset(representative+1, 0xbb, representativeByteLength-digestSize-4);	// pad with 0xbb
	byte *afterP2 = representative+representativeByteLength-digestSize-3;
	afterP2[0] = 0xba;
	hash.Final(afterP2+1);
	representative[representativeByteLength-2] = *hashIdentifier.first;
	representative[representativeByteLength-1] = 0xcc;
}

NAMESPACE_END

#endif
