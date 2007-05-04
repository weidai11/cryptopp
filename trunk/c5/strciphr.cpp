// strciphr.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

// prevent Sun's CC compiler from including this file automatically
#if !defined(__SUNPRO_CC) || defined(CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES)

#ifndef CRYPTOPP_IMPORTS

#include "strciphr.h"

NAMESPACE_BEGIN(CryptoPP)

template <class S>
void AdditiveCipherTemplate<S>::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	PolicyInterface &policy = this->AccessPolicy();
	policy.CipherSetKey(params, key, length);
	m_leftOver = 0;
	m_buffer.New(GetBufferByteSize(policy));

	if (this->IsResynchronizable())
		policy.CipherResynchronize(m_buffer, this->GetIVAndThrowIfInvalid(params));
}

template <class S>
void AdditiveCipherTemplate<S>::GenerateBlock(byte *outString, size_t length)
{
	if (m_leftOver > 0)
	{
		size_t len = STDMIN(m_leftOver, length);
		memcpy(outString, KeystreamBufferEnd()-m_leftOver, len);
		length -= len;
		m_leftOver -= len;
		outString += len;

		if (!length)
			return;
	}
	assert(m_leftOver == 0);

	PolicyInterface &policy = this->AccessPolicy();
	unsigned int bytesPerIteration = policy.GetBytesPerIteration();

	if (length >= bytesPerIteration)
	{
		size_t iterations = length / bytesPerIteration;
		policy.WriteKeystream(outString, iterations);
		outString += iterations * bytesPerIteration;
		length -= iterations * bytesPerIteration;

		if (!length)
			return;
	}

	unsigned int bufferByteSize = GetBufferByteSize(policy);
	unsigned int bufferIterations = policy.GetIterationsToBuffer();

	while (length >= bufferByteSize)
	{
		policy.WriteKeystream(m_buffer, bufferIterations);
		memcpy(outString, KeystreamBufferBegin(), bufferByteSize);
		length -= bufferByteSize;
		outString += bufferByteSize;
	}

	if (length > 0)
	{
		policy.WriteKeystream(m_buffer, bufferIterations);
		memcpy(outString, KeystreamBufferBegin(), length);
		m_leftOver = bytesPerIteration - length;
	}
}

template <class S>
void AdditiveCipherTemplate<S>::ProcessData(byte *outString, const byte *inString, size_t length)
{
	if (m_leftOver > 0)
	{
		size_t len = STDMIN(m_leftOver, length);
		xorbuf(outString, inString, KeystreamBufferEnd()-m_leftOver, len);
		length -= len;
		m_leftOver -= len;
		inString += len;
		outString += len;

		if (!length)
			return;
	}
	assert(m_leftOver == 0);

	PolicyInterface &policy = this->AccessPolicy();
	unsigned int bytesPerIteration = policy.GetBytesPerIteration();

	if (policy.CanOperateKeystream() && length >= bytesPerIteration)
	{
		size_t iterations = length / bytesPerIteration;
		unsigned int alignment = policy.GetAlignment();
		KeystreamOperation operation = KeystreamOperation((IsAlignedOn(inString, alignment) * 2) | (int)IsAlignedOn(outString, alignment));

		policy.OperateKeystream(operation, outString, inString, iterations);

		inString += iterations * bytesPerIteration;
		outString += iterations * bytesPerIteration;
		length -= iterations * bytesPerIteration;

		if (!length)
			return;
	}

	unsigned int bufferByteSize = GetBufferByteSize(policy);
	unsigned int bufferIterations = policy.GetIterationsToBuffer();

	while (length >= bufferByteSize)
	{
		policy.WriteKeystream(m_buffer, bufferIterations);
		xorbuf(outString, inString, KeystreamBufferBegin(), bufferByteSize);
		length -= bufferByteSize;
		inString += bufferByteSize;
		outString += bufferByteSize;
	}

	if (length > 0)
	{
		policy.WriteKeystream(m_buffer, bufferIterations);
		xorbuf(outString, inString, KeystreamBufferBegin(), length);
		m_leftOver = bytesPerIteration - length;
	}
}

template <class S>
void AdditiveCipherTemplate<S>::Resynchronize(const byte *iv)
{
	PolicyInterface &policy = this->AccessPolicy();
	m_leftOver = 0;
	m_buffer.New(GetBufferByteSize(policy));
	policy.CipherResynchronize(m_buffer, iv);
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
		policy.WriteKeystream(m_buffer, 1);
		m_leftOver = bytesPerIteration - (unsigned int)position;
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
		policy.CipherResynchronize(this->GetIVAndThrowIfInvalid(params));

	m_leftOver = policy.GetBytesPerIteration();
}

template <class BASE>
void CFB_CipherTemplate<BASE>::Resynchronize(const byte *iv)
{
	PolicyInterface &policy = this->AccessPolicy();
	policy.CipherResynchronize(iv);
	m_leftOver = policy.GetBytesPerIteration();
}

template <class BASE>
void CFB_CipherTemplate<BASE>::ProcessData(byte *outString, const byte *inString, size_t length)
{
	assert(length % this->MandatoryBlockSize() == 0);

	PolicyInterface &policy = this->AccessPolicy();
	unsigned int bytesPerIteration = policy.GetBytesPerIteration();
	unsigned int alignment = policy.GetAlignment();
	byte *reg = policy.GetRegisterBegin();

	if (m_leftOver)
	{
		size_t len = STDMIN(m_leftOver, length);
		CombineMessageAndShiftRegister(outString, reg + bytesPerIteration - m_leftOver, inString, len);
		m_leftOver -= len;
		length -= len;
		inString += len;
		outString += len;
	}

	if (!length)
		return;

	assert(m_leftOver == 0);

	if (policy.CanIterate() && length >= bytesPerIteration && IsAlignedOn(outString, alignment))
	{
		if (IsAlignedOn(inString, alignment))
			policy.Iterate(outString, inString, GetCipherDir(*this), length / bytesPerIteration);
		else
		{
			memcpy(outString, inString, length);
			policy.Iterate(outString, outString, GetCipherDir(*this), length / bytesPerIteration);
		}
		inString += length - length % bytesPerIteration;
		outString += length - length % bytesPerIteration;
		length %= bytesPerIteration;
	}

	while (length >= bytesPerIteration)
	{
		policy.TransformRegister();
		CombineMessageAndShiftRegister(outString, reg, inString, bytesPerIteration);
		length -= bytesPerIteration;
		inString += bytesPerIteration;
		outString += bytesPerIteration;
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
	memcpy(output, reg, length);
}

template <class BASE>
void CFB_DecryptionTemplate<BASE>::CombineMessageAndShiftRegister(byte *output, byte *reg, const byte *message, size_t length)
{
	for (unsigned int i=0; i<length; i++)
	{
		byte b = message[i];
		output[i] = reg[i] ^ b;
		reg[i] = b;
	}
}

NAMESPACE_END

#endif

#endif
