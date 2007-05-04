// cryptlib.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "cryptlib.h"
#include "misc.h"
#include "filters.h"
#include "algparam.h"
#include "fips140.h"
#include "argnames.h"
#include "fltrimpl.h"
#include "trdlocal.h"
#include "osrng.h"

#include <memory>

NAMESPACE_BEGIN(CryptoPP)

CRYPTOPP_COMPILE_ASSERT(sizeof(byte) == 1);
CRYPTOPP_COMPILE_ASSERT(sizeof(word16) == 2);
CRYPTOPP_COMPILE_ASSERT(sizeof(word32) == 4);
#ifdef WORD64_AVAILABLE
CRYPTOPP_COMPILE_ASSERT(sizeof(word64) == 8);
#endif
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
CRYPTOPP_COMPILE_ASSERT(sizeof(dword) == 2*sizeof(word));
#endif

const std::string BufferedTransformation::NULL_CHANNEL;
const NullNameValuePairs g_nullNameValuePairs;

BufferedTransformation & TheBitBucket()
{
	static BitBucket bitBucket;
	return bitBucket;
}

Algorithm::Algorithm(bool checkSelfTestStatus)
{
	if (checkSelfTestStatus && FIPS_140_2_ComplianceEnabled())
	{
		if (GetPowerUpSelfTestStatus() == POWER_UP_SELF_TEST_NOT_DONE && !PowerUpSelfTestInProgressOnThisThread())
			throw SelfTestFailure("Cryptographic algorithms are disabled before the power-up self tests are performed.");

		if (GetPowerUpSelfTestStatus() == POWER_UP_SELF_TEST_FAILED)
			throw SelfTestFailure("Cryptographic algorithms are disabled after a power-up self test failed.");
	}
}

void SimpleKeyingInterface::SetKey(const byte *key, size_t length, const NameValuePairs &params)
{
	this->ThrowIfInvalidKeyLength(length);
	this->UncheckedSetKey(key, (unsigned int)length, params);
}

void SimpleKeyingInterface::SetKeyWithRounds(const byte *key, size_t length, int rounds)
{
	SetKey(key, length, MakeParameters(Name::Rounds(), rounds));
}

void SimpleKeyingInterface::SetKeyWithIV(const byte *key, size_t length, const byte *iv)
{
	SetKey(key, length, MakeParameters(Name::IV(), iv));
}

void SimpleKeyingInterface::ThrowIfInvalidKeyLength(size_t length)
{
	if (!IsValidKeyLength(length))
		throw InvalidKeyLength(GetAlgorithm().AlgorithmName(), length);
}

void SimpleKeyingInterface::ThrowIfResynchronizable()
{
	if (IsResynchronizable())
		throw InvalidArgument(GetAlgorithm().AlgorithmName() + ": this object requires an IV");
}

void SimpleKeyingInterface::ThrowIfInvalidIV(const byte *iv)
{
	if (!iv && !(IVRequirement() == INTERNALLY_GENERATED_IV || IVRequirement() == UNIQUE_IV || !IsResynchronizable()))
		throw InvalidArgument(GetAlgorithm().AlgorithmName() + ": this object cannot use a null IV");
}

const byte * SimpleKeyingInterface::GetIVAndThrowIfInvalid(const NameValuePairs &params)
{
	const byte *iv;
	if (params.GetValue(Name::IV(), iv))
		ThrowIfInvalidIV(iv);
	else
		ThrowIfResynchronizable();
	return iv;
}

void SimpleKeyingInterface::GetNextIV(RandomNumberGenerator &rng, byte *IV)
{
	rng.GenerateBlock(IV, IVSize());
}

void BlockTransformation::ProcessAndXorMultipleBlocks(const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t numberOfBlocks) const
{
	unsigned int blockSize = BlockSize();
	while (numberOfBlocks--)
	{
		ProcessAndXorBlock(inBlocks, xorBlocks, outBlocks);
		inBlocks += blockSize;
		outBlocks += blockSize;
		if (xorBlocks)
			xorBlocks += blockSize;
	}
}

unsigned int BlockTransformation::BlockAlignment() const
{
	return GetAlignmentOf<word32>();
}

void StreamTransformation::ProcessLastBlock(byte *outString, const byte *inString, size_t length)
{
	assert(MinLastBlockSize() == 0);	// this function should be overriden otherwise

	if (length == MandatoryBlockSize())
		ProcessData(outString, inString, length);
	else if (length != 0)
		throw NotImplemented("StreamTransformation: this object does't support a special last block");
}

unsigned int RandomNumberGenerator::GenerateBit()
{
	return GenerateByte() & 1;
}

byte RandomNumberGenerator::GenerateByte()
{
	byte b;
	GenerateBlock(&b, 1);
	return b;
}

word32 RandomNumberGenerator::GenerateWord32(word32 min, word32 max)
{
	word32 range = max-min;
	const int maxBits = BitPrecision(range);

	word32 value;

	do
	{
		GenerateBlock((byte *)&value, sizeof(value));
		value = Crop(value, maxBits);
	} while (value > range);

	return value+min;
}

void RandomNumberGenerator::GenerateBlock(byte *output, size_t size)
{
	ArraySink s(output, size);
	GenerateIntoBufferedTransformation(s, BufferedTransformation::NULL_CHANNEL, size);
}

void RandomNumberGenerator::DiscardBytes(size_t n)
{
	GenerateIntoBufferedTransformation(TheBitBucket(), BufferedTransformation::NULL_CHANNEL, n);
}

void RandomNumberGenerator::GenerateIntoBufferedTransformation(BufferedTransformation &target, const std::string &channel, lword length)
{
	FixedSizeSecBlock<byte, 256> buffer;
	while (length)
	{
		size_t len = UnsignedMin(buffer.size(), length);
		GenerateBlock(buffer, len);
		target.ChannelPut(channel, buffer, len);
		length -= len;
	}
}

//! see NullRNG()
class ClassNullRNG : public RandomNumberGenerator
{
public:
	std::string AlgorithmName() const {return "NullRNG";}
	void GenerateBlock(byte *output, size_t size) {throw NotImplemented("NullRNG: NullRNG should only be passed to functions that don't need to generate random bytes");}
};

RandomNumberGenerator & NullRNG()
{
	static ClassNullRNG s_nullRNG;
	return s_nullRNG;
}

bool HashTransformation::TruncatedVerify(const byte *digestIn, size_t digestLength)
{
	ThrowIfInvalidTruncatedSize(digestLength);
	SecByteBlock digest(digestLength);
	TruncatedFinal(digest, digestLength);
	return memcmp(digest, digestIn, digestLength) == 0;
}

void HashTransformation::ThrowIfInvalidTruncatedSize(size_t size) const
{
	if (size > DigestSize())
		throw InvalidArgument("HashTransformation: can't truncate a " + IntToString(DigestSize()) + " byte digest to " + IntToString(size) + " bytes");
}

unsigned int BufferedTransformation::GetMaxWaitObjectCount() const
{
	const BufferedTransformation *t = AttachedTransformation();
	return t ? t->GetMaxWaitObjectCount() : 0;
}

void BufferedTransformation::GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack)
{
	BufferedTransformation *t = AttachedTransformation();
	if (t)
		t->GetWaitObjects(container, callStack);  // reduce clutter by not adding to stack here
}

void BufferedTransformation::Initialize(const NameValuePairs &parameters, int propagation)
{
	assert(!AttachedTransformation());
	IsolatedInitialize(parameters);
}

bool BufferedTransformation::Flush(bool hardFlush, int propagation, bool blocking)
{
	assert(!AttachedTransformation());
	return IsolatedFlush(hardFlush, blocking);
}

bool BufferedTransformation::MessageSeriesEnd(int propagation, bool blocking)
{
	assert(!AttachedTransformation());
	return IsolatedMessageSeriesEnd(blocking);
}

byte * BufferedTransformation::ChannelCreatePutSpace(const std::string &channel, size_t &size)
{
	if (channel.empty())
		return CreatePutSpace(size);
	else
		throw NoChannelSupport();
}

size_t BufferedTransformation::ChannelPut2(const std::string &channel, const byte *begin, size_t length, int messageEnd, bool blocking)
{
	if (channel.empty())
		return Put2(begin, length, messageEnd, blocking);
	else
		throw NoChannelSupport();
}

size_t BufferedTransformation::ChannelPutModifiable2(const std::string &channel, byte *begin, size_t length, int messageEnd, bool blocking)
{
	if (channel.empty())
		return PutModifiable2(begin, length, messageEnd, blocking);
	else
		return ChannelPut2(channel, begin, length, messageEnd, blocking);
}

bool BufferedTransformation::ChannelFlush(const std::string &channel, bool completeFlush, int propagation, bool blocking)
{
	if (channel.empty())
		return Flush(completeFlush, propagation, blocking);
	else
		throw NoChannelSupport();
}

bool BufferedTransformation::ChannelMessageSeriesEnd(const std::string &channel, int propagation, bool blocking)
{
	if (channel.empty())
		return MessageSeriesEnd(propagation, blocking);
	else
		throw NoChannelSupport();
}

lword BufferedTransformation::MaxRetrievable() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->MaxRetrievable();
	else
		return CopyTo(TheBitBucket());
}

bool BufferedTransformation::AnyRetrievable() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->AnyRetrievable();
	else
	{
		byte b;
		return Peek(b) != 0;
	}
}

size_t BufferedTransformation::Get(byte &outByte)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Get(outByte);
	else
		return Get(&outByte, 1);
}

size_t BufferedTransformation::Get(byte *outString, size_t getMax)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Get(outString, getMax);
	else
	{
		ArraySink arraySink(outString, getMax);
		return (size_t)TransferTo(arraySink, getMax);
	}
}

size_t BufferedTransformation::Peek(byte &outByte) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->Peek(outByte);
	else
		return Peek(&outByte, 1);
}

size_t BufferedTransformation::Peek(byte *outString, size_t peekMax) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->Peek(outString, peekMax);
	else
	{
		ArraySink arraySink(outString, peekMax);
		return (size_t)CopyTo(arraySink, peekMax);
	}
}

lword BufferedTransformation::Skip(lword skipMax)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Skip(skipMax);
	else
		return TransferTo(TheBitBucket(), skipMax);
}

lword BufferedTransformation::TotalBytesRetrievable() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->TotalBytesRetrievable();
	else
		return MaxRetrievable();
}

unsigned int BufferedTransformation::NumberOfMessages() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->NumberOfMessages();
	else
		return CopyMessagesTo(TheBitBucket());
}

bool BufferedTransformation::AnyMessages() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->AnyMessages();
	else
		return NumberOfMessages() != 0;
}

bool BufferedTransformation::GetNextMessage()
{
	if (AttachedTransformation())
		return AttachedTransformation()->GetNextMessage();
	else
	{
		assert(!AnyMessages());
		return false;
	}
}

unsigned int BufferedTransformation::SkipMessages(unsigned int count)
{
	if (AttachedTransformation())
		return AttachedTransformation()->SkipMessages(count);
	else
		return TransferMessagesTo(TheBitBucket(), count);
}

size_t BufferedTransformation::TransferMessagesTo2(BufferedTransformation &target, unsigned int &messageCount, const std::string &channel, bool blocking)
{
	if (AttachedTransformation())
		return AttachedTransformation()->TransferMessagesTo2(target, messageCount, channel, blocking);
	else
	{
		unsigned int maxMessages = messageCount;
		for (messageCount=0; messageCount < maxMessages && AnyMessages(); messageCount++)
		{
			size_t blockedBytes;
			lword transferredBytes;

			while (AnyRetrievable())
			{
				transferredBytes = LWORD_MAX;
				blockedBytes = TransferTo2(target, transferredBytes, channel, blocking);
				if (blockedBytes > 0)
					return blockedBytes;
			}

			if (target.ChannelMessageEnd(channel, GetAutoSignalPropagation(), blocking))
				return 1;

			bool result = GetNextMessage();
			assert(result);
		}
		return 0;
	}
}

unsigned int BufferedTransformation::CopyMessagesTo(BufferedTransformation &target, unsigned int count, const std::string &channel) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->CopyMessagesTo(target, count, channel);
	else
		return 0;
}

void BufferedTransformation::SkipAll()
{
	if (AttachedTransformation())
		AttachedTransformation()->SkipAll();
	else
	{
		while (SkipMessages()) {}
		while (Skip()) {}
	}
}

size_t BufferedTransformation::TransferAllTo2(BufferedTransformation &target, const std::string &channel, bool blocking)
{
	if (AttachedTransformation())
		return AttachedTransformation()->TransferAllTo2(target, channel, blocking);
	else
	{
		assert(!NumberOfMessageSeries());

		unsigned int messageCount;
		do
		{
			messageCount = UINT_MAX;
			size_t blockedBytes = TransferMessagesTo2(target, messageCount, channel, blocking);
			if (blockedBytes)
				return blockedBytes;
		}
		while (messageCount != 0);

		lword byteCount;
		do
		{
			byteCount = ULONG_MAX;
			size_t blockedBytes = TransferTo2(target, byteCount, channel, blocking);
			if (blockedBytes)
				return blockedBytes;
		}
		while (byteCount != 0);

		return 0;
	}
}

void BufferedTransformation::CopyAllTo(BufferedTransformation &target, const std::string &channel) const
{
	if (AttachedTransformation())
		AttachedTransformation()->CopyAllTo(target, channel);
	else
	{
		assert(!NumberOfMessageSeries());
		while (CopyMessagesTo(target, UINT_MAX, channel)) {}
	}
}

void BufferedTransformation::SetRetrievalChannel(const std::string &channel)
{
	if (AttachedTransformation())
		AttachedTransformation()->SetRetrievalChannel(channel);
}

size_t BufferedTransformation::ChannelPutWord16(const std::string &channel, word16 value, ByteOrder order, bool blocking)
{
	PutWord(false, order, m_buf, value);
	return ChannelPut(channel, m_buf, 2, blocking);
}

size_t BufferedTransformation::ChannelPutWord32(const std::string &channel, word32 value, ByteOrder order, bool blocking)
{
	PutWord(false, order, m_buf, value);
	return ChannelPut(channel, m_buf, 4, blocking);
}

size_t BufferedTransformation::PutWord16(word16 value, ByteOrder order, bool blocking)
{
	return ChannelPutWord16(NULL_CHANNEL, value, order, blocking);
}

size_t BufferedTransformation::PutWord32(word32 value, ByteOrder order, bool blocking)
{
	return ChannelPutWord32(NULL_CHANNEL, value, order, blocking);
}

size_t BufferedTransformation::PeekWord16(word16 &value, ByteOrder order) const
{
	byte buf[2] = {0, 0};
	size_t len = Peek(buf, 2);

	if (order)
		value = (buf[0] << 8) | buf[1];
	else
		value = (buf[1] << 8) | buf[0];

	return len;
}

size_t BufferedTransformation::PeekWord32(word32 &value, ByteOrder order) const
{
	byte buf[4] = {0, 0, 0, 0};
	size_t len = Peek(buf, 4);

	if (order)
		value = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf [3];
	else
		value = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf [0];

	return len;
}

size_t BufferedTransformation::GetWord16(word16 &value, ByteOrder order)
{
	return (size_t)Skip(PeekWord16(value, order));
}

size_t BufferedTransformation::GetWord32(word32 &value, ByteOrder order)
{
	return (size_t)Skip(PeekWord32(value, order));
}

void BufferedTransformation::Attach(BufferedTransformation *newOut)
{
	if (AttachedTransformation() && AttachedTransformation()->Attachable())
		AttachedTransformation()->Attach(newOut);
	else
		Detach(newOut);
}

void GeneratableCryptoMaterial::GenerateRandomWithKeySize(RandomNumberGenerator &rng, unsigned int keySize)
{
	GenerateRandom(rng, MakeParameters("KeySize", (int)keySize));
}

class PK_DefaultEncryptionFilter : public Unflushable<Filter>
{
public:
	PK_DefaultEncryptionFilter(RandomNumberGenerator &rng, const PK_Encryptor &encryptor, BufferedTransformation *attachment, const NameValuePairs &parameters)
		: m_rng(rng), m_encryptor(encryptor), m_parameters(parameters)
	{
		Detach(attachment);
	}

	size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking)
	{
		FILTER_BEGIN;
		m_plaintextQueue.Put(inString, length);

		if (messageEnd)
		{
			{
			size_t plaintextLength;
			if (!SafeConvert(m_plaintextQueue.CurrentSize(), plaintextLength))
				throw InvalidArgument("PK_DefaultEncryptionFilter: plaintext too long");
			size_t ciphertextLength = m_encryptor.CiphertextLength(plaintextLength);

			SecByteBlock plaintext(plaintextLength);
			m_plaintextQueue.Get(plaintext, plaintextLength);
			m_ciphertext.resize(ciphertextLength);
			m_encryptor.Encrypt(m_rng, plaintext, plaintextLength, m_ciphertext, m_parameters);
			}
			
			FILTER_OUTPUT(1, m_ciphertext, m_ciphertext.size(), messageEnd);
		}
		FILTER_END_NO_MESSAGE_END;
	}

	RandomNumberGenerator &m_rng;
	const PK_Encryptor &m_encryptor;
	const NameValuePairs &m_parameters;
	ByteQueue m_plaintextQueue;
	SecByteBlock m_ciphertext;
};

BufferedTransformation * PK_Encryptor::CreateEncryptionFilter(RandomNumberGenerator &rng, BufferedTransformation *attachment, const NameValuePairs &parameters) const
{
	return new PK_DefaultEncryptionFilter(rng, *this, attachment, parameters);
}

class PK_DefaultDecryptionFilter : public Unflushable<Filter>
{
public:
	PK_DefaultDecryptionFilter(RandomNumberGenerator &rng, const PK_Decryptor &decryptor, BufferedTransformation *attachment, const NameValuePairs &parameters)
		: m_rng(rng), m_decryptor(decryptor), m_parameters(parameters)
	{
		Detach(attachment);
	}

	size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking)
	{
		FILTER_BEGIN;
		m_ciphertextQueue.Put(inString, length);

		if (messageEnd)
		{
			{
			size_t ciphertextLength;
			if (!SafeConvert(m_ciphertextQueue.CurrentSize(), ciphertextLength))
				throw InvalidArgument("PK_DefaultDecryptionFilter: ciphertext too long");
			size_t maxPlaintextLength = m_decryptor.MaxPlaintextLength(ciphertextLength);

			SecByteBlock ciphertext(ciphertextLength);
			m_ciphertextQueue.Get(ciphertext, ciphertextLength);
			m_plaintext.resize(maxPlaintextLength);
			m_result = m_decryptor.Decrypt(m_rng, ciphertext, ciphertextLength, m_plaintext, m_parameters);
			if (!m_result.isValidCoding)
				throw InvalidCiphertext(m_decryptor.AlgorithmName() + ": invalid ciphertext");
			}

			FILTER_OUTPUT(1, m_plaintext, m_result.messageLength, messageEnd);
		}
		FILTER_END_NO_MESSAGE_END;
	}

	RandomNumberGenerator &m_rng;
	const PK_Decryptor &m_decryptor;
	const NameValuePairs &m_parameters;
	ByteQueue m_ciphertextQueue;
	SecByteBlock m_plaintext;
	DecodingResult m_result;
};

BufferedTransformation * PK_Decryptor::CreateDecryptionFilter(RandomNumberGenerator &rng, BufferedTransformation *attachment, const NameValuePairs &parameters) const
{
	return new PK_DefaultDecryptionFilter(rng, *this, attachment, parameters);
}

size_t PK_Signer::Sign(RandomNumberGenerator &rng, PK_MessageAccumulator *messageAccumulator, byte *signature) const
{
	std::auto_ptr<PK_MessageAccumulator> m(messageAccumulator);
	return SignAndRestart(rng, *m, signature, false);
}

size_t PK_Signer::SignMessage(RandomNumberGenerator &rng, const byte *message, size_t messageLen, byte *signature) const
{
	std::auto_ptr<PK_MessageAccumulator> m(NewSignatureAccumulator(rng));
	m->Update(message, messageLen);
	return SignAndRestart(rng, *m, signature, false);
}

size_t PK_Signer::SignMessageWithRecovery(RandomNumberGenerator &rng, const byte *recoverableMessage, size_t recoverableMessageLength, 
	const byte *nonrecoverableMessage, size_t nonrecoverableMessageLength, byte *signature) const
{
	std::auto_ptr<PK_MessageAccumulator> m(NewSignatureAccumulator(rng));
	InputRecoverableMessage(*m, recoverableMessage, recoverableMessageLength);
	m->Update(nonrecoverableMessage, nonrecoverableMessageLength);
	return SignAndRestart(rng, *m, signature, false);
}

bool PK_Verifier::Verify(PK_MessageAccumulator *messageAccumulator) const
{
	std::auto_ptr<PK_MessageAccumulator> m(messageAccumulator);
	return VerifyAndRestart(*m);
}

bool PK_Verifier::VerifyMessage(const byte *message, size_t messageLen, const byte *signature, size_t signatureLength) const
{
	std::auto_ptr<PK_MessageAccumulator> m(NewVerificationAccumulator());
	InputSignature(*m, signature, signatureLength);
	m->Update(message, messageLen);
	return VerifyAndRestart(*m);
}

DecodingResult PK_Verifier::Recover(byte *recoveredMessage, PK_MessageAccumulator *messageAccumulator) const
{
	std::auto_ptr<PK_MessageAccumulator> m(messageAccumulator);
	return RecoverAndRestart(recoveredMessage, *m);
}

DecodingResult PK_Verifier::RecoverMessage(byte *recoveredMessage, 
	const byte *nonrecoverableMessage, size_t nonrecoverableMessageLength, 
	const byte *signature, size_t signatureLength) const
{
	std::auto_ptr<PK_MessageAccumulator> m(NewVerificationAccumulator());
	InputSignature(*m, signature, signatureLength);
	m->Update(nonrecoverableMessage, nonrecoverableMessageLength);
	return RecoverAndRestart(recoveredMessage, *m);
}

void SimpleKeyAgreementDomain::GenerateKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const
{
	GeneratePrivateKey(rng, privateKey);
	GeneratePublicKey(rng, privateKey, publicKey);
}

void AuthenticatedKeyAgreementDomain::GenerateStaticKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const
{
	GenerateStaticPrivateKey(rng, privateKey);
	GenerateStaticPublicKey(rng, privateKey, publicKey);
}

void AuthenticatedKeyAgreementDomain::GenerateEphemeralKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const
{
	GenerateEphemeralPrivateKey(rng, privateKey);
	GenerateEphemeralPublicKey(rng, privateKey, publicKey);
}

NAMESPACE_END

#endif
