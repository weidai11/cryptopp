// strciphr.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "strciphr.h"

NAMESPACE_BEGIN(CryptoPP)

template <class S>
byte AdditiveCipherTemplate<S>::GenerateByte()
{
	PolicyInterface &policy = this->AccessPolicy();

	if (m_leftOver == 0)
	{
		policy.WriteKeystream(m_buffer, policy.GetIterationsToBuffer());
		m_leftOver = policy.GetBytesPerIteration();
	}

	return *(KeystreamBufferEnd()-m_leftOver--);
}

template <class S>
inline void AdditiveCipherTemplate<S>::ProcessData(byte *outString, const byte *inString, unsigned int length)
{
	if (m_leftOver > 0)
	{
		unsigned int len = STDMIN(m_leftOver, length);
		xorbuf(outString, inString, KeystreamBufferEnd()-m_leftOver, len);
		length -= len;
		m_leftOver -= len;
		inString += len;
		outString += len;
	}

	if (!length)
		return;

	assert(m_leftOver == 0);

	PolicyInterface &policy = this->AccessPolicy();
	unsigned int bytesPerIteration = policy.GetBytesPerIteration();
	unsigned int alignment = policy.GetAlignment();

	if (policy.CanOperateKeystream() && length >= bytesPerIteration && IsAlignedOn(outString, alignment))
	{
		if (IsAlignedOn(inString, alignment))
			policy.OperateKeystream(XOR_KEYSTREAM, outString, inString, length / bytesPerIteration);
		else
		{
			memcpy(outString, inString, length);
			policy.OperateKeystream(XOR_KEYSTREAM_INPLACE, outString, outString, length / bytesPerIteration);
		}
		inString += length - length % bytesPerIteration;
		outString += length - length % bytesPerIteration;
		length %= bytesPerIteration;

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
void CFB_CipherTemplate<BASE>::Resynchronize(const byte *iv)
{
	PolicyInterface &policy = this->AccessPolicy();
	policy.CipherResynchronize(iv);
	m_leftOver = policy.GetBytesPerIteration();
}

template <class BASE>
void CFB_CipherTemplate<BASE>::ProcessData(byte *outString, const byte *inString, unsigned int length)
{
	assert(length % this->MandatoryBlockSize() == 0);

	PolicyInterface &policy = this->AccessPolicy();
	unsigned int bytesPerIteration = policy.GetBytesPerIteration();
	unsigned int alignment = policy.GetAlignment();
	byte *reg = policy.GetRegisterBegin();

	if (m_leftOver)
	{
		unsigned int len = STDMIN(m_leftOver, length);
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
void CFB_EncryptionTemplate<BASE>::CombineMessageAndShiftRegister(byte *output, byte *reg, const byte *message, unsigned int length)
{
	xorbuf(reg, message, length);
	memcpy(output, reg, length);
}

template <class BASE>
void CFB_DecryptionTemplate<BASE>::CombineMessageAndShiftRegister(byte *output, byte *reg, const byte *message, unsigned int length)
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
