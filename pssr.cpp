// pssr.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "pssr.h"

NAMESPACE_BEGIN(CryptoPP)

template<> const byte EMSA2HashId<SHA>::id = 0x33;
template<> const byte EMSA2HashId<RIPEMD160>::id = 0x31;
template<> const byte EMSA2HashId<RIPEMD128>::id = 0x32;
template<> const byte EMSA2HashId<SHA256>::id = 0x34;
template<> const byte EMSA2HashId<SHA384>::id = 0x36;
template<> const byte EMSA2HashId<SHA512>::id = 0x35;
template<> const byte EMSA2HashId<Whirlpool>::id = 0x37;

unsigned int PSSR_MEM_Base::MaxRecoverableLength(unsigned int representativeBitLength, unsigned int hashIdentifierLength, unsigned int digestLength) const
{
	if (AllowRecovery())
	{
		unsigned int saltLen = SaltLen(digestLength);
		unsigned int minPadLen = MinPadLen(digestLength);
		return SaturatingSubtract(representativeBitLength, 8*(minPadLen + saltLen + digestLength + hashIdentifierLength) + 9) / 8;
	}
	return 0;
}

bool PSSR_MEM_Base::IsProbabilistic() const 
{
	return SaltLen(1) > 0;
}

bool PSSR_MEM_Base::AllowNonrecoverablePart() const
{
	return true;
}

bool PSSR_MEM_Base::RecoverablePartFirst() const
{
	return false;
}

void PSSR_MEM_Base::ComputeMessageRepresentative(RandomNumberGenerator &rng, 
	const byte *recoverableMessage, unsigned int recoverableMessageLength,
	HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
	byte *representative, unsigned int representativeBitLength) const
{
	const unsigned int u = hashIdentifier.second + 1;
	const unsigned int representativeByteLength = BitsToBytes(representativeBitLength);
	const unsigned int digestSize = hash.DigestSize();
	const unsigned int saltSize = SaltLen(digestSize);
	byte *const h = representative + representativeByteLength - u - digestSize;

	SecByteBlock digest(digestSize), salt(saltSize);
	hash.Final(digest);
	rng.GenerateBlock(salt, saltSize);

	// compute H = hash of M'
	byte c[8];
	UnalignedPutWord(BIG_ENDIAN_ORDER, c, (word32)SafeRightShift<29>(recoverableMessageLength));
	UnalignedPutWord(BIG_ENDIAN_ORDER, c+4, word32(recoverableMessageLength << 3));
	hash.Update(c, 8);
	hash.Update(recoverableMessage, recoverableMessageLength);
	hash.Update(digest, digestSize);
	hash.Update(salt, saltSize);
	hash.Final(h);

	// compute representative
	GetMGF().GenerateAndMask(hash, representative, representativeByteLength - u - digestSize, h, digestSize, false);
	byte *xorStart = representative + representativeByteLength - u - digestSize - salt.size() - recoverableMessageLength - 1;
	xorStart[0] ^= 1;
	xorbuf(xorStart + 1, recoverableMessage, recoverableMessageLength);
	xorbuf(xorStart + 1 + recoverableMessageLength, salt, salt.size());
	memcpy(representative + representativeByteLength - u, hashIdentifier.first, hashIdentifier.second);
	representative[representativeByteLength - 1] = hashIdentifier.second ? 0xcc : 0xbc;
	if (representativeBitLength % 8 != 0)
		representative[0] = (byte)Crop(representative[0], representativeBitLength % 8);
}

DecodingResult PSSR_MEM_Base::RecoverMessageFromRepresentative(
	HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
	byte *representative, unsigned int representativeBitLength,
	byte *recoverableMessage) const
{
	const unsigned int u = hashIdentifier.second + 1;
	const unsigned int representativeByteLength = BitsToBytes(representativeBitLength);
	const unsigned int digestSize = hash.DigestSize();
	const unsigned int saltSize = SaltLen(digestSize);
	const byte *const h = representative + representativeByteLength - u - digestSize;

	SecByteBlock digest(digestSize);
	hash.Final(digest);

	DecodingResult result(0);
	bool &valid = result.isValidCoding;
	unsigned int &recoverableMessageLength = result.messageLength;

	valid = (representative[representativeByteLength - 1] == (hashIdentifier.second ? 0xcc : 0xbc)) && valid;
	valid = (memcmp(representative + representativeByteLength - u, hashIdentifier.first, hashIdentifier.second) == 0) && valid;

	GetMGF().GenerateAndMask(hash, representative, representativeByteLength - u - digestSize, h, digestSize);
	if (representativeBitLength % 8 != 0)
		representative[0] = (byte)Crop(representative[0], representativeBitLength % 8);

	// extract salt and recoverableMessage from DB = 00 ... || 01 || M || salt
	byte *salt = representative + representativeByteLength - u - digestSize - saltSize;
	byte *M = std::find_if(representative, salt-1, std::bind2nd(std::not_equal_to<byte>(), 0));
	if (*M == 0x01 && (unsigned int)(M - representative - (representativeBitLength % 8 != 0)) >= MinPadLen(digestSize))
	{
		recoverableMessageLength = salt-M-1;
		memcpy(recoverableMessage, M+1, recoverableMessageLength);
	}
	else
		valid = false;

	// verify H = hash of M'
	byte c[8];
	UnalignedPutWord(BIG_ENDIAN_ORDER, c, (word32)SafeRightShift<29>(recoverableMessageLength));
	UnalignedPutWord(BIG_ENDIAN_ORDER, c+4, word32(recoverableMessageLength << 3));
	hash.Update(c, 8);
	hash.Update(recoverableMessage, recoverableMessageLength);
	hash.Update(digest, digestSize);
	hash.Update(salt, saltSize);
	valid = hash.Verify(h) && valid;

	if (!AllowRecovery() && valid && recoverableMessageLength != 0)
		{throw NotImplemented("PSSR_MEM: message recovery disabled");}
	
	return result;
}

NAMESPACE_END
