// pubkey.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "pubkey.h"

NAMESPACE_BEGIN(CryptoPP)

void P1363_MGF1KDF2_Common(HashTransformation &hash, byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength, bool mask, unsigned int counterStart)
{
	ArraySink *sink;
	HashFilter filter(hash, sink = mask ? new ArrayXorSink(output, outputLength) : new ArraySink(output, outputLength));
	word32 counter = counterStart;
	while (sink->AvailableSize() > 0)
	{
		filter.Put(input, inputLength);
		filter.PutWord32(counter++);
		filter.MessageEnd();
	}
}

bool PK_DeterministicSignatureMessageEncodingMethod::VerifyMessageRepresentative(
	HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
	byte *representative, unsigned int representativeBitLength) const
{
	SecByteBlock computedRepresentative(BitsToBytes(representativeBitLength));
	ComputeMessageRepresentative(NullRNG(), NULL, 0, hash, hashIdentifier, messageEmpty, computedRepresentative, representativeBitLength);
	return memcmp(representative, computedRepresentative, computedRepresentative.size()) == 0;
}

bool PK_RecoverableSignatureMessageEncodingMethod::VerifyMessageRepresentative(
	HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
	byte *representative, unsigned int representativeBitLength) const
{
	SecByteBlock recoveredMessage(MaxRecoverableLength(representativeBitLength, hashIdentifier.second, hash.DigestSize()));
	DecodingResult result = RecoverMessageFromRepresentative(
		hash, hashIdentifier, messageEmpty, representative, representativeBitLength, recoveredMessage);
	return result.isValidCoding && result.messageLength == 0;
}

void TF_SignerBase::InputRecoverableMessage(PK_MessageAccumulator &messageAccumulator, const byte *recoverableMessage, unsigned int recoverableMessageLength) const
{
	PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
	const MessageEncodingInterface &mei = GetMessageEncodingInterface();
	unsigned int maxRecoverableLength = mei.MaxRecoverableLength(MessageRepresentativeBitLength(), GetHashIdentifier().second, ma.AccessHash().DigestSize());

	if (maxRecoverableLength == 0)
		{throw NotImplemented("TF_SignerBase: this algorithm does not support messsage recovery or the key is too short");}
	if (recoverableMessageLength > maxRecoverableLength)
		throw InvalidArgument("TF_SignerBase: the recoverable message part is too long for the given key and algorithm");

	ma.m_recoverableMessage.Assign(recoverableMessage, recoverableMessageLength);
	mei.ProcessRecoverableMessage(
		ma.AccessHash(), 
		recoverableMessage, recoverableMessageLength,
		NULL, 0, ma.m_semisignature);
}

unsigned int TF_SignerBase::SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart) const
{
	PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
	SecByteBlock representative(MessageRepresentativeLength());
	GetMessageEncodingInterface().ComputeMessageRepresentative(rng, 
		ma.m_recoverableMessage, ma.m_recoverableMessage.size(), 
		ma.AccessHash(), GetHashIdentifier(), ma.m_empty,
		representative, MessageRepresentativeBitLength());
	ma.m_empty = true;

	Integer r(representative, representative.size());
	unsigned int signatureLength = SignatureLength();
	GetTrapdoorFunctionInterface().CalculateRandomizedInverse(rng, r).Encode(signature, signatureLength);
	return signatureLength;
}

void TF_VerifierBase::InputSignature(PK_MessageAccumulator &messageAccumulator, const byte *signature, unsigned int signatureLength) const
{
	PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
	ma.m_representative.New(MessageRepresentativeLength());
	Integer x = GetTrapdoorFunctionInterface().ApplyFunction(Integer(signature, signatureLength));
	if (x.BitCount() > MessageRepresentativeBitLength())
		x = Integer::Zero();	// don't return false here to prevent timing attack
	x.Encode(ma.m_representative, ma.m_representative.size());
}

bool TF_VerifierBase::VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const
{
	PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
	bool result = GetMessageEncodingInterface().VerifyMessageRepresentative(
		ma.AccessHash(), GetHashIdentifier(), ma.m_empty, ma.m_representative, MessageRepresentativeBitLength());
	ma.m_empty = true;
	return result;
}

DecodingResult TF_VerifierBase::RecoverAndRestart(byte *recoveredMessage, PK_MessageAccumulator &messageAccumulator) const
{
	PK_MessageAccumulatorBase &ma = static_cast<PK_MessageAccumulatorBase &>(messageAccumulator);
	DecodingResult result = GetMessageEncodingInterface().RecoverMessageFromRepresentative(
		ma.AccessHash(), GetHashIdentifier(), ma.m_empty, ma.m_representative, MessageRepresentativeBitLength(), recoveredMessage);
	ma.m_empty = true;
	return result;
}

DecodingResult TF_DecryptorBase::FixedLengthDecrypt(RandomNumberGenerator &rng, const byte *cipherText, byte *plainText) const
{
	SecByteBlock paddedBlock(PaddedBlockByteLength());
	Integer x = GetTrapdoorFunctionInterface().CalculateInverse(rng, Integer(cipherText, FixedCiphertextLength()));
	if (x.ByteCount() > paddedBlock.size())
		x = Integer::Zero();	// don't return false here to prevent timing attack
	x.Encode(paddedBlock, paddedBlock.size());
	return GetMessageEncodingInterface().Unpad(paddedBlock, PaddedBlockBitLength(), plainText);
}

void TF_EncryptorBase::Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText) const
{
	if (plainTextLength > FixedMaxPlaintextLength())
		throw InvalidArgument(AlgorithmName() + ": message too long for this public key");

	SecByteBlock paddedBlock(PaddedBlockByteLength());
	GetMessageEncodingInterface().Pad(rng, plainText, plainTextLength, paddedBlock, PaddedBlockBitLength());
	GetTrapdoorFunctionInterface().ApplyRandomizedFunction(rng, Integer(paddedBlock, paddedBlock.size())).Encode(cipherText, FixedCiphertextLength());
}

NAMESPACE_END
