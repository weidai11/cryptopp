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

void SimpleKeyingInterface::SetKeyWithRounds(const byte *key, unsigned int length, int rounds)
{
	SetKey(key, length, MakeParameters(Name::Rounds(), rounds));
}

void SimpleKeyingInterface::SetKeyWithIV(const byte *key, unsigned int length, const byte *iv)
{
	SetKey(key, length, MakeParameters(Name::IV(), iv));
}

void SimpleKeyingInterface::ThrowIfInvalidKeyLength(const Algorithm &algorithm, unsigned int length)
{
	if (!IsValidKeyLength(length))
		throw InvalidKeyLength(algorithm.AlgorithmName(), length);
}

void SimpleKeyingInterface::ThrowIfResynchronizable()
{
	if (IsResynchronizable())
		throw InvalidArgument("SimpleKeyingInterface: this object requires an IV");
}

void SimpleKeyingInterface::ThrowIfInvalidIV(const byte *iv)
{
	if (!iv && !(IVRequirement() == INTERNALLY_GENERATED_IV || IVRequirement() == STRUCTURED_IV || !IsResynchronizable()))
		throw InvalidArgument("SimpleKeyingInterface: this object cannot use a null IV");
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

void BlockTransformation::ProcessAndXorMultipleBlocks(const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, unsigned int numberOfBlocks) const
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

void StreamTransformation::ProcessLastBlock(byte *outString, const byte *inString, unsigned int length)
{
	assert(MinLastBlockSize() == 0);	// this function should be overriden otherwise

	if (length == MandatoryBlockSize())
		ProcessData(outString, inString, length);
	else if (length != 0)
		throw NotImplemented("StreamTransformation: this object does't support a special last block");
}

unsigned int RandomNumberGenerator::GenerateBit()
{
	return Parity(GenerateByte());
}

void RandomNumberGenerator::GenerateBlock(byte *output, unsigned int size)
{
	while (size--)
		*output++ = GenerateByte();
}

word32 RandomNumberGenerator::GenerateWord32(word32 min, word32 max)
{
	word32 range = max-min;
	const int maxBytes = BytePrecision(range);
	const int maxBits = BitPrecision(range);

	word32 value;

	do
	{
		value = 0;
		for (int i=0; i<maxBytes; i++)
			value = (value << 8) | GenerateByte();

		value = Crop(value, maxBits);
	} while (value > range);

	return value+min;
}

void RandomNumberGenerator::DiscardBytes(unsigned int n)
{
	while (n--)
		GenerateByte();
}

//! see NullRNG()
class ClassNullRNG : public RandomNumberGenerator
{
public:
	std::string AlgorithmName() const {return "NullRNG";}
	byte GenerateByte() {throw NotImplemented("NullRNG: NullRNG should only be passed to functions that don't need to generate random bytes");}
};

RandomNumberGenerator & NullRNG()
{
	static ClassNullRNG s_nullRNG;
	return s_nullRNG;
}

bool HashTransformation::TruncatedVerify(const byte *digestIn, unsigned int digestLength)
{
	ThrowIfInvalidTruncatedSize(digestLength);
	SecByteBlock digest(digestLength);
	TruncatedFinal(digest, digestLength);
	return memcmp(digest, digestIn, digestLength) == 0;
}

void HashTransformation::ThrowIfInvalidTruncatedSize(unsigned int size) const
{
	if (size > DigestSize())
		throw InvalidArgument("HashTransformation: can't truncate a " + IntToString(DigestSize()) + " byte digest to " + IntToString(size) + " bytes");
}

unsigned int BufferedTransformation::GetMaxWaitObjectCount() const
{
	const BufferedTransformation *t = AttachedTransformation();
	return t ? t->GetMaxWaitObjectCount() : 0;
}

void BufferedTransformation::GetWaitObjects(WaitObjectContainer &container)
{
	BufferedTransformation *t = AttachedTransformation();
	if (t)
		t->GetWaitObjects(container);
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

byte * BufferedTransformation::ChannelCreatePutSpace(const std::string &channel, unsigned int &size)
{
	if (channel.empty())
		return CreatePutSpace(size);
	else
		throw NoChannelSupport();
}

unsigned int BufferedTransformation::ChannelPut2(const std::string &channel, const byte *begin, unsigned int length, int messageEnd, bool blocking)
{
	if (channel.empty())
		return Put2(begin, length, messageEnd, blocking);
	else
		throw NoChannelSupport();
}

unsigned int BufferedTransformation::ChannelPutModifiable2(const std::string &channel, byte *begin, unsigned int length, int messageEnd, bool blocking)
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

unsigned long BufferedTransformation::MaxRetrievable() const
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

unsigned int BufferedTransformation::Get(byte &outByte)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Get(outByte);
	else
		return Get(&outByte, 1);
}

unsigned int BufferedTransformation::Get(byte *outString, unsigned int getMax)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Get(outString, getMax);
	else
	{
		ArraySink arraySink(outString, getMax);
		return TransferTo(arraySink, getMax);
	}
}

unsigned int BufferedTransformation::Peek(byte &outByte) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->Peek(outByte);
	else
		return Peek(&outByte, 1);
}

unsigned int BufferedTransformation::Peek(byte *outString, unsigned int peekMax) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->Peek(outString, peekMax);
	else
	{
		ArraySink arraySink(outString, peekMax);
		return CopyTo(arraySink, peekMax);
	}
}

unsigned long BufferedTransformation::Skip(unsigned long skipMax)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Skip(skipMax);
	else
		return TransferTo(TheBitBucket(), skipMax);
}

unsigned long BufferedTransformation::TotalBytesRetrievable() const
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

unsigned int BufferedTransformation::TransferMessagesTo2(BufferedTransformation &target, unsigned int &messageCount, const std::string &channel, bool blocking)
{
	if (AttachedTransformation())
		return AttachedTransformation()->TransferMessagesTo2(target, messageCount, channel, blocking);
	else
	{
		unsigned int maxMessages = messageCount;
		for (messageCount=0; messageCount < maxMessages && AnyMessages(); messageCount++)
		{
			unsigned int blockedBytes;
			unsigned long transferredBytes;

			while (AnyRetrievable())
			{
				transferredBytes = ULONG_MAX;
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

unsigned int BufferedTransformation::TransferAllTo2(BufferedTransformation &target, const std::string &channel, bool blocking)
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
			unsigned int blockedBytes = TransferMessagesTo2(target, messageCount, channel, blocking);
			if (blockedBytes)
				return blockedBytes;
		}
		while (messageCount != 0);

		unsigned long byteCount;
		do
		{
			byteCount = ULONG_MAX;
			unsigned int blockedBytes = TransferTo2(target, byteCount, channel, blocking);
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

unsigned int BufferedTransformation::ChannelPutWord16(const std::string &channel, word16 value, ByteOrder order, bool blocking)
{
	FixedSizeSecBlock<byte, 2> buf;
	PutWord(false, order, buf, value);
	return ChannelPut(channel, buf, 2, blocking);
}

unsigned int BufferedTransformation::ChannelPutWord32(const std::string &channel, word32 value, ByteOrder order, bool blocking)
{
	FixedSizeSecBlock<byte, 4> buf;
	PutWord(false, order, buf, value);
	return ChannelPut(channel, buf, 4, blocking);
}

unsigned int BufferedTransformation::PutWord16(word16 value, ByteOrder order, bool blocking)
{
	return ChannelPutWord16(NULL_CHANNEL, value, order, blocking);
}

unsigned int BufferedTransformation::PutWord32(word32 value, ByteOrder order, bool blocking)
{
	return ChannelPutWord32(NULL_CHANNEL, value, order, blocking);
}

unsigned int BufferedTransformation::PeekWord16(word16 &value, ByteOrder order)
{
	byte buf[2] = {0, 0};
	unsigned int len = Peek(buf, 2);

	if (order)
		value = (buf[0] << 8) | buf[1];
	else
		value = (buf[1] << 8) | buf[0];

	return len;
}

unsigned int BufferedTransformation::PeekWord32(word32 &value, ByteOrder order)
{
	byte buf[4] = {0, 0, 0, 0};
	unsigned int len = Peek(buf, 4);

	if (order)
		value = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf [3];
	else
		value = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf [0];

	return len;
}

unsigned int BufferedTransformation::GetWord16(word16 &value, ByteOrder order)
{
	return Skip(PeekWord16(value, order));
}

unsigned int BufferedTransformation::GetWord32(word32 &value, ByteOrder order)
{
	return Skip(PeekWord32(value, order));
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

	unsigned int Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
	{
		FILTER_BEGIN;
		m_plaintextQueue.Put(inString, length);

		if (messageEnd)
		{
			{
			unsigned int plaintextLength = m_plaintextQueue.CurrentSize();
			unsigned int ciphertextLength = m_encryptor.CiphertextLength(plaintextLength);

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

	unsigned int Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
	{
		FILTER_BEGIN;
		m_ciphertextQueue.Put(inString, length);

		if (messageEnd)
		{
			{
			unsigned int ciphertextLength = m_ciphertextQueue.CurrentSize();
			unsigned int maxPlaintextLength = m_decryptor.MaxPlaintextLength(ciphertextLength);

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

unsigned int PK_Signer::Sign(RandomNumberGenerator &rng, PK_MessageAccumulator *messageAccumulator, byte *signature) const
{
	std::auto_ptr<PK_MessageAccumulator> m(messageAccumulator);
	return SignAndRestart(rng, *m, signature, false);
}

unsigned int PK_Signer::SignMessage(RandomNumberGenerator &rng, const byte *message, unsigned int messageLen, byte *signature) const
{
	std::auto_ptr<PK_MessageAccumulator> m(NewSignatureAccumulator(rng));
	m->Update(message, messageLen);
	return SignAndRestart(rng, *m, signature, false);
}

unsigned int PK_Signer::SignMessageWithRecovery(RandomNumberGenerator &rng, const byte *recoverableMessage, unsigned int recoverableMessageLength, 
	const byte *nonrecoverableMessage, unsigned int nonrecoverableMessageLength, byte *signature) const
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

bool PK_Verifier::VerifyMessage(const byte *message, unsigned int messageLen, const byte *signature, unsigned int signatureLength) const
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
	const byte *nonrecoverableMessage, unsigned int nonrecoverableMessageLength, 
	const byte *signature, unsigned int signatureLength) const
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
