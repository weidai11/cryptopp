// modes.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "modes.h"

#ifndef NDEBUG
#include "des.h"
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifndef NDEBUG
void Modes_TestInstantiations()
{
	CFB_Mode<DES>::Encryption m0;
	CFB_Mode<DES>::Decryption m1;
	OFB_Mode<DES>::Encryption m2;
	CTR_Mode<DES>::Encryption m3;
	ECB_Mode<DES>::Encryption m4;
	CBC_Mode<DES>::Encryption m5;
}
#endif

void CipherModeBase::SetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	UncheckedSetKey(params, key, length, GetIVAndThrowIfInvalid(params));	// the underlying cipher will check the key length
}

void CipherModeBase::GetNextIV(byte *IV)
{
	if (!IsForwardTransformation())
		throw NotImplemented("CipherModeBase: GetNextIV() must be called on an encryption object");

	m_cipher->ProcessBlock(m_register);
	memcpy(IV, m_register, BlockSize());
}

void CTR_ModePolicy::SeekToIteration(lword iterationCount)
{
	int carry=0;
	for (int i=BlockSize()-1; i>=0; i--)
	{
		unsigned int sum = m_register[i] + byte(iterationCount) + carry;
		m_counterArray[i] = (byte) sum;
		carry = sum >> 8;
		iterationCount >>= 8;
	}
}

static inline void IncrementCounterByOne(byte *inout, unsigned int s)
{
	for (int i=s-1, carry=1; i>=0 && carry; i--)
		carry = !++inout[i];
}

static inline void IncrementCounterByOne(byte *output, const byte *input, unsigned int s)
{
	int i, carry;
	for (i=s-1, carry=1; i>=0 && carry; i--)
		carry = !(output[i] = input[i]+1);
	memcpy(output, input, i+1);
}

void CTR_ModePolicy::GetNextIV(byte *IV)
{
	IncrementCounterByOne(IV, m_counterArray, BlockSize());
}

inline void CTR_ModePolicy::ProcessMultipleBlocks(byte *output, const byte *input, unsigned int n)
{
	unsigned int s = BlockSize(), j = 0;
	for (unsigned int i=1; i<n; i++, j+=s)
		IncrementCounterByOne(m_counterArray + j + s, m_counterArray + j, s);
	m_cipher->ProcessAndXorMultipleBlocks(m_counterArray, input, output, n);
	IncrementCounterByOne(m_counterArray, m_counterArray + s*(n-1), s);
}

void CTR_ModePolicy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, unsigned int iterationCount)
{
	unsigned int maxBlocks = m_cipher->OptimalNumberOfParallelBlocks();
	if (maxBlocks == 1)
	{
		unsigned int sizeIncrement = BlockSize();
		while (iterationCount)
		{
			m_cipher->ProcessAndXorBlock(m_counterArray, input, output);
			IncrementCounterByOne(m_counterArray, sizeIncrement);
			output += sizeIncrement;
			input += sizeIncrement;
			iterationCount -= 1;
		}
	}
	else
	{
		unsigned int sizeIncrement = maxBlocks * BlockSize();
		while (iterationCount >= maxBlocks)
		{
			ProcessMultipleBlocks(output, input, maxBlocks);
			output += sizeIncrement;
			input += sizeIncrement;
			iterationCount -= maxBlocks;
		}
		if (iterationCount > 0)
			ProcessMultipleBlocks(output, input, iterationCount);
	}
}

void CTR_ModePolicy::CipherResynchronize(byte *keystreamBuffer, const byte *iv)
{
	unsigned int s = BlockSize();
	CopyOrZero(m_register, iv, s);
	m_counterArray.New(s * m_cipher->OptimalNumberOfParallelBlocks());
	CopyOrZero(m_counterArray, iv, s);
}

void BlockOrientedCipherModeBase::UncheckedSetKey(const NameValuePairs &params, const byte *key, unsigned int length, const byte *iv)
{
	m_cipher->SetKey(key, length, params);
	ResizeBuffers();
	if (IsResynchronizable())
		Resynchronize(iv);
}

void BlockOrientedCipherModeBase::ProcessData(byte *outString, const byte *inString, unsigned int length)
{
	unsigned int s = BlockSize();
	assert(length % s == 0);
	unsigned int alignment = m_cipher->BlockAlignment();
	bool inputAlignmentOk = !RequireAlignedInput() || IsAlignedOn(inString, alignment);

	if (IsAlignedOn(outString, alignment))
	{
		if (inputAlignmentOk)
			ProcessBlocks(outString, inString, length / s);
		else
		{
			memcpy(outString, inString, length);
			ProcessBlocks(outString, outString, length / s);
		}
	}
	else
	{
		while (length)
		{
			if (inputAlignmentOk)
				ProcessBlocks(m_buffer, inString, 1);
			else
			{
				memcpy(m_buffer, inString, s);
				ProcessBlocks(m_buffer, m_buffer, 1);
			}
			memcpy(outString, m_buffer, s);
			inString += s;
			outString += s;
			length -= s;
		}
	}
}

void CBC_Encryption::ProcessBlocks(byte *outString, const byte *inString, unsigned int numberOfBlocks)
{
	unsigned int blockSize = BlockSize();
	while (numberOfBlocks--)
	{
		xorbuf(m_register, inString, blockSize);
		m_cipher->ProcessBlock(m_register);
		memcpy(outString, m_register, blockSize);
		inString += blockSize;
		outString += blockSize;
	}
}

void CBC_CTS_Encryption::ProcessLastBlock(byte *outString, const byte *inString, unsigned int length)
{
	if (length <= BlockSize())
	{
		if (!m_stolenIV)
			throw InvalidArgument("CBC_Encryption: message is too short for ciphertext stealing");

		// steal from IV
		memcpy(outString, m_register, length);
		outString = m_stolenIV;
	}
	else
	{
		// steal from next to last block
		xorbuf(m_register, inString, BlockSize());
		m_cipher->ProcessBlock(m_register);
		inString += BlockSize();
		length -= BlockSize();
		memcpy(outString+BlockSize(), m_register, length);
	}

	// output last full ciphertext block
	xorbuf(m_register, inString, length);
	m_cipher->ProcessBlock(m_register);
	memcpy(outString, m_register, BlockSize());
}

void CBC_Decryption::ProcessBlocks(byte *outString, const byte *inString, unsigned int numberOfBlocks)
{
	unsigned int blockSize = BlockSize();
	while (numberOfBlocks--)
	{
		memcpy(m_temp, inString, blockSize);
		m_cipher->ProcessBlock(m_temp, outString);
		xorbuf(outString, m_register, blockSize);
		m_register.swap(m_temp);
		inString += blockSize;
		outString += blockSize;
	}
}

void CBC_CTS_Decryption::ProcessLastBlock(byte *outString, const byte *inString, unsigned int length)
{
	const byte *pn, *pn1;
	bool stealIV = length <= BlockSize();

	if (stealIV)
	{
		pn = inString;
		pn1 = m_register;
	}
	else
	{
		pn = inString + BlockSize();
		pn1 = inString;
		length -= BlockSize();
	}

	// decrypt last partial plaintext block
	memcpy(m_temp, pn1, BlockSize());
	m_cipher->ProcessBlock(m_temp);
	xorbuf(m_temp, pn, length);

	if (stealIV)
		memcpy(outString, m_temp, length);
	else
	{
		memcpy(outString+BlockSize(), m_temp, length);
		// decrypt next to last plaintext block
		memcpy(m_temp, pn, length);
		m_cipher->ProcessBlock(m_temp);
		xorbuf(outString, m_temp, m_register, BlockSize());
	}
}

NAMESPACE_END

#endif
