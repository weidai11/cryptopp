// pubkey.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "pubkey.h"

NAMESPACE_BEGIN(CryptoPP)

void TF_DigestSignerBase::SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLen, byte *signature) const
{
	assert(digestLen <= MaxDigestLength());

	SecByteBlock paddedBlock(PaddedBlockByteLength());
	GetPaddingAlgorithm().Pad(rng, digest, digestLen, paddedBlock, PaddedBlockBitLength());
	GetTrapdoorFunctionInterface().CalculateRandomizedInverse(rng, Integer(paddedBlock, paddedBlock.size())).Encode(signature, DigestSignatureLength());
}

bool TF_DigestVerifierBase::VerifyDigest(const byte *digest, unsigned int digestLen, const byte *signature) const
{
	SecByteBlock paddedBlock(PaddedBlockByteLength());
	Integer x = GetTrapdoorFunctionInterface().ApplyFunction(Integer(signature, DigestSignatureLength()));
	if (x.ByteCount() > paddedBlock.size())
		x = Integer::Zero();	// don't return false here to prevent timing attack
	x.Encode(paddedBlock, paddedBlock.size());
	if (GetPaddingAlgorithm().IsReversible())
	{
		SecByteBlock recoveredDigest(MaxDigestLength());
		DecodingResult result = GetPaddingAlgorithm().Unpad(paddedBlock, PaddedBlockBitLength(), recoveredDigest);
		return result == DecodingResult(digestLen) && memcmp(digest, recoveredDigest, digestLen) == 0;
	}
	else
	{
		SecByteBlock paddedBlock2(PaddedBlockByteLength());
		GetPaddingAlgorithm().Pad(NullRNG(), digest, digestLen, paddedBlock2, PaddedBlockBitLength());
		return paddedBlock == paddedBlock2;
	}
}

DecodingResult TF_DecryptorBase::FixedLengthDecrypt(const byte *cipherText, byte *plainText) const
{
	SecByteBlock paddedBlock(PaddedBlockByteLength());
	Integer x = GetTrapdoorFunctionInterface().CalculateInverse(Integer(cipherText, FixedCiphertextLength()));
	if (x.ByteCount() > paddedBlock.size())
		x = Integer::Zero();	// don't return false here to prevent timing attack
	x.Encode(paddedBlock, paddedBlock.size());
	return GetPaddingAlgorithm().Unpad(paddedBlock, PaddedBlockBitLength(), plainText);
}

void TF_EncryptorBase::Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText) const
{
	if (plainTextLength > FixedMaxPlaintextLength())
		throw InvalidArgument(AlgorithmName() + ": message too long for this public key");

	SecByteBlock paddedBlock(PaddedBlockByteLength());
	GetPaddingAlgorithm().Pad(rng, plainText, plainTextLength, paddedBlock, PaddedBlockBitLength());
	GetTrapdoorFunctionInterface().ApplyRandomizedFunction(rng, Integer(paddedBlock, paddedBlock.size())).Encode(cipherText, FixedCiphertextLength());
}

NAMESPACE_END
