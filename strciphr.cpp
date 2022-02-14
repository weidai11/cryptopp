// strciphr.cpp - originally written and placed in the public domain by Wei Dai

//     TODO: Figure out what is happening in ProcessData. The issue surfaced
//     for CFB_CipherTemplate<BASE>::ProcessData when we cut-in Cryptogams
//     AES ARMv7 asm. Then again in AdditiveCipherTemplate<S>::ProcessData
//     for CTR mode with HIGHT, which is a 64-bit block cipher. In both cases,
//     inString == outString leads to incorrect results. We think it relates
//     to aliasing violations because inString == outString.
//
//     Also see https://github.com/weidai11/cryptopp/issues/683,
//     https://github.com/weidai11/cryptopp/issues/1010 and
//     https://github.com/weidai11/cryptopp/issues/1088.

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "strciphr.h"

// Squash MS LNK4221 and libtool warnings
#ifndef CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
extern const char STRCIPHER_FNAME[] = __FILE__;
#endif

NAMESPACE_BEGIN(CryptoPP)

template <class S>
void AdditiveCipherTemplate<S>::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	PolicyInterface &policy = this->AccessPolicy();
	policy.CipherSetKey(params, key, length);
	m_leftOver = 0;
	unsigned int bufferByteSize = policy.CanOperateKeystream() ? GetBufferByteSize(policy) : RoundUpToMultipleOf(1024U, GetBufferByteSize(policy));
	m_buffer.New(bufferByteSize);

	if (this->IsResynchronizable())
	{
		size_t ivLength;
		const byte *iv = this->GetIVAndThrowIfInvalid(params, ivLength);
		policy.CipherResynchronize(m_buffer, iv, ivLength);
	}
}

template <class S>
void AdditiveCipherTemplate<S>::GenerateBlock(byte *outString, size_t length)
{
	if (m_leftOver > 0)
	{
		const size_t len = STDMIN(m_leftOver, length);
		std::memcpy(outString, PtrSub(KeystreamBufferEnd(), m_leftOver), len);

		length -= len; m_leftOver -= len;
		outString = PtrAdd(outString, len);
		if (!length) {return;}
	}

	PolicyInterface &policy = this->AccessPolicy();
	size_t bytesPerIteration = policy.GetBytesPerIteration();

	if (length >= bytesPerIteration)
	{
		const size_t iterations = length / bytesPerIteration;
		policy.WriteKeystream(outString, iterations);
		length -= iterations * bytesPerIteration;
		outString = PtrAdd(outString, iterations * bytesPerIteration);
	}

	if (length > 0)
	{
		size_t bufferByteSize = RoundUpToMultipleOf(length, bytesPerIteration);
		size_t bufferIterations = bufferByteSize / bytesPerIteration;

		policy.WriteKeystream(PtrSub(KeystreamBufferEnd(), bufferByteSize), bufferIterations);
		std::memcpy(outString, PtrSub(KeystreamBufferEnd(), bufferByteSize), length);
		m_leftOver = bufferByteSize - length;
	}
}

// TODO: Figure out what is happening in ProcessData. The issue surfaced
// for CFB_CipherTemplate<BASE>::ProcessData when we cut-in Cryptogams
// AES ARMv7 asm. Then again in AdditiveCipherTemplate<S>::ProcessData
// for CTR mode with HIGHT, which is a 64-bit block cipher. In both cases,
// inString == outString leads to incorrect results. We think it relates
// to aliasing violations because inString == outString.
//
// Also see https://github.com/weidai11/cryptopp/issues/683,
// https://github.com/weidai11/cryptopp/issues/1010 and
// https://github.com/weidai11/cryptopp/issues/1088.

template <class S>
void AdditiveCipherTemplate<S>::ProcessData(byte *outString, const byte *inString, size_t length)
{
	CRYPTOPP_ASSERT(outString); CRYPTOPP_ASSERT(inString);
	CRYPTOPP_ASSERT(length % this->MandatoryBlockSize() == 0);

	PolicyInterface &policy = this->AccessPolicy();
	size_t bytesPerIteration = policy.GetBytesPerIteration();

	if (m_leftOver > 0)
	{
		const size_t len = STDMIN(m_leftOver, length);
		xorbuf(outString, inString, PtrSub(KeystreamBufferEnd(), m_leftOver), len);

		inString = PtrAdd(inString, len);
		outString = PtrAdd(outString, len);
		length -= len; m_leftOver -= len;
	}

	if (!length) { return; }

	const word32 alignment = policy.GetAlignment();
	const bool inAligned = IsAlignedOn(inString, alignment);
	const bool outAligned = IsAlignedOn(outString, alignment);
	CRYPTOPP_UNUSED(inAligned); CRYPTOPP_UNUSED(outAligned);

	if (policy.CanOperateKeystream() && length >= bytesPerIteration)
	{
		const size_t iterations = length / bytesPerIteration;
		KeystreamOperationFlags flags = static_cast<KeystreamOperationFlags>(
			(inAligned ? EnumToInt(INPUT_ALIGNED) : 0) | (outAligned ? EnumToInt(OUTPUT_ALIGNED) : 0));
		KeystreamOperation operation = KeystreamOperation(flags);
		policy.OperateKeystream(operation, outString, inString, iterations);

		// Try to tame the optimizer. This is GH #683, #1010, and #1088.
		volatile byte* unused = const_cast<volatile byte*>(outString);
		CRYPTOPP_UNUSED(unused);

		inString = PtrAdd(inString, iterations * bytesPerIteration);
		outString = PtrAdd(outString, iterations * bytesPerIteration);
		length -= iterations * bytesPerIteration;
	}

	size_t bufferByteSize = m_buffer.size();
	size_t bufferIterations = bufferByteSize / bytesPerIteration;

	while (length >= bufferByteSize)
	{
		policy.WriteKeystream(m_buffer, bufferIterations);
		xorbuf(outString, inString, KeystreamBufferBegin(), bufferByteSize);

		inString = PtrAdd(inString, bufferByteSize);
		outString = PtrAdd(outString, bufferByteSize);
		length -= bufferByteSize;
	}

	if (length > 0)
	{
		bufferByteSize = RoundUpToMultipleOf(length, bytesPerIteration);
		bufferIterations = bufferByteSize / bytesPerIteration;

		policy.WriteKeystream(PtrSub(KeystreamBufferEnd(), bufferByteSize), bufferIterations);
		xorbuf(outString, inString, PtrSub(KeystreamBufferEnd(), bufferByteSize), length);

		m_leftOver = bufferByteSize - length;
	}
}

template <class S>
void AdditiveCipherTemplate<S>::Resynchronize(const byte *iv, int length)
{
	PolicyInterface &policy = this->AccessPolicy();
	m_leftOver = 0;
	m_buffer.New(GetBufferByteSize(policy));
	policy.CipherResynchronize(m_buffer, iv, this->ThrowIfInvalidIVLength(length));
}

template <class BASE>
void AdditiveCipherTemplate<BASE>::Seek(lword position)
{
	PolicyInterface &policy = this->AccessPolicy();
	unsigned int bytesPerIteration = policy.GetBytesPerIteration();

	policy.SeekToIteration(position / bytesPerIteration);
	position %= bytesPerIteration;

	if (position > 0)
	{
		policy.WriteKeystream(PtrSub(KeystreamBufferEnd(), bytesPerIteration), 1);
		m_leftOver = bytesPerIteration - static_cast<unsigned int>(position);
	}
	else
		m_leftOver = 0;
}

template <class BASE>
void CFB_CipherTemplate<BASE>::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	PolicyInterface &policy = this->AccessPolicy();
	policy.CipherSetKey(params, key, length);

	if (this->IsResynchronizable())
	{
		size_t ivLength;
		const byte *iv = this->GetIVAndThrowIfInvalid(params, ivLength);
		policy.CipherResynchronize(iv, ivLength);
	}

	m_leftOver = policy.GetBytesPerIteration();
}

template <class BASE>
void CFB_CipherTemplate<BASE>::Resynchronize(const byte *iv, int length)
{
	PolicyInterface &policy = this->AccessPolicy();
	policy.CipherResynchronize(iv, this->ThrowIfInvalidIVLength(length));
	m_leftOver = policy.GetBytesPerIteration();
}

// TODO: Figure out what is happening in ProcessData. The issue surfaced
// for CFB_CipherTemplate<BASE>::ProcessData when we cut-in Cryptogams
// AES ARMv7 asm. Then again in AdditiveCipherTemplate<S>::ProcessData
// for CTR mode with HIGHT, which is a 64-bit block cipher. In both cases,
// inString == outString leads to incorrect results. We think it relates
// to aliasing violations because inString == outString.
//
// Also see https://github.com/weidai11/cryptopp/issues/683,
// https://github.com/weidai11/cryptopp/issues/1010 and
// https://github.com/weidai11/cryptopp/issues/1088.

template <class BASE>
void CFB_CipherTemplate<BASE>::ProcessData(byte *outString, const byte *inString, size_t length)
{
	CRYPTOPP_ASSERT(outString); CRYPTOPP_ASSERT(inString);
	CRYPTOPP_ASSERT(length % this->MandatoryBlockSize() == 0);

	PolicyInterface &policy = this->AccessPolicy();
	unsigned int bytesPerIteration = policy.GetBytesPerIteration();
	byte *reg = policy.GetRegisterBegin();

	if (m_leftOver)
	{
		const size_t len = STDMIN(m_leftOver, length);
		CombineMessageAndShiftRegister(outString, PtrAdd(reg, bytesPerIteration - m_leftOver), inString, len);

		inString = PtrAdd(inString, len);
		outString = PtrAdd(outString, len);
		m_leftOver -= len; length -= len;
	}

	if (!length) { return; }

	const word32 alignment = policy.GetAlignment();
	const bool inAligned = IsAlignedOn(inString, alignment);
	const bool outAligned = IsAlignedOn(outString, alignment);
	CRYPTOPP_UNUSED(inAligned); CRYPTOPP_UNUSED(outAligned);

	if (policy.CanIterate() && length >= bytesPerIteration && outAligned)
	{
		CipherDir cipherDir = GetCipherDir(*this);
		policy.Iterate(outString, inString, cipherDir, length / bytesPerIteration);

		// Try to tame the optimizer. This is GH #683, #1010, and #1088.
		volatile byte* unused = const_cast<volatile byte*>(outString);
		CRYPTOPP_UNUSED(unused);

		const size_t remainder = length % bytesPerIteration;
		inString = PtrAdd(inString, length - remainder);
		outString = PtrAdd(outString, length - remainder);
		length = remainder;
	}

	while (length >= bytesPerIteration)
	{
		policy.TransformRegister();
		CombineMessageAndShiftRegister(outString, reg, inString, bytesPerIteration);

		inString = PtrAdd(inString, bytesPerIteration);
		outString = PtrAdd(outString, bytesPerIteration);
		length -= bytesPerIteration;
	}

	if (length > 0)
	{
		policy.TransformRegister();
		CombineMessageAndShiftRegister(outString, reg, inString, length);
		m_leftOver = bytesPerIteration - length;
	}
}

template <class BASE>
void CFB_EncryptionTemplate<BASE>::CombineMessageAndShiftRegister(byte *output, byte *reg, const byte *message, size_t length)
{
	xorbuf(reg, message, length);
	std::memcpy(output, reg, length);
}

template <class BASE>
void CFB_DecryptionTemplate<BASE>::CombineMessageAndShiftRegister(byte *output, byte *reg, const byte *message, size_t length)
{
	for (size_t i=0; i<length; i++)
	{
		byte b = message[i];
		output[i] = reg[i] ^ b;
		reg[i] = b;
	}
}

NAMESPACE_END

#endif
