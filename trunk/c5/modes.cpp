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

void OFB_ModePolicy::WriteKeystream(byte *keystreamBuffer, size_t iterationCount)
{
	assert(m_cipher->IsForwardTransformation());	// OFB mode needs the "encrypt" direction of the underlying block cipher, even to decrypt
	unsigned int s = BlockSize();
	m_cipher->ProcessBlock(m_register, keystreamBuffer);
	if (iterationCount > 1)
		m_cipher->AdvancedProcessBlocks(keystreamBuffer, NULL, keystreamBuffer+s, s*(iterationCount-1), 0);
	memcpy(m_register, keystreamBuffer+s*(iterationCount-1), s);
}

void OFB_ModePolicy::CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length)
{
	CopyOrZero(m_register, iv, length);
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

void CTR_ModePolicy::IncrementCounterBy256()
{
	IncrementCounterByOne(m_counterArray, BlockSize()-1);
}

void CTR_ModePolicy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount)
{
	assert(m_cipher->IsForwardTransformation());	// CTR mode needs the "encrypt" direction of the underlying block cipher, even to decrypt
	unsigned int s = BlockSize();
	unsigned int inputIncrement = input ? s : 0;

	while (iterationCount)
	{
		byte lsb = m_counterArray[s-1];
		size_t blocks = UnsignedMin(iterationCount, 256U-lsb);
		m_cipher->AdvancedProcessBlocks(m_counterArray, input, output, blocks*s, BlockTransformation::BT_InBlockIsCounter);
		if ((m_counterArray[s-1] = lsb + (byte)blocks) == 0)
			IncrementCounterBy256();

		output += blocks*s;
		input += blocks*inputIncrement;
		iterationCount -= blocks;
	}
}

void CTR_ModePolicy::CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length)
{
	assert(length == BlockSize());
	CopyOrZero(m_register, iv, length);
	m_counterArray = m_register;
}

void BlockOrientedCipherModeBase::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	m_cipher->SetKey(key, length, params);
	ResizeBuffers();
	if (IsResynchronizable())
	{
		size_t ivLength;
		const byte *iv = GetIVAndThrowIfInvalid(params, ivLength);
		Resynchronize(iv, (int)ivLength);
	}
}

void ECB_OneWay::ProcessData(byte *outString, const byte *inString, size_t length)
{
	assert(length%BlockSize()==0);
	m_cipher->AdvancedProcessBlocks(inString, NULL, outString, length, 0);
}

void CBC_Encryption::ProcessData(byte *outString, const byte *inString, size_t length)
{
	if (!length)
		return;
	assert(length%BlockSize()==0);

	unsigned int blockSize = BlockSize();
	m_cipher->AdvancedProcessBlocks(inString, m_register, outString, blockSize, BlockTransformation::BT_XorInput);
	if (length > blockSize)
		m_cipher->AdvancedProcessBlocks(inString+blockSize, outString, outString+blockSize, length-blockSize, BlockTransformation::BT_XorInput);
	memcpy(m_register, outString + length - blockSize, blockSize);
}

void CBC_CTS_Encryption::ProcessLastBlock(byte *outString, const byte *inString, size_t length)
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

void CBC_Decryption::ProcessData(byte *outString, const byte *inString, size_t length)
{
	if (!length)
		return;
	assert(length%BlockSize()==0);

	unsigned int blockSize = BlockSize();
	memcpy(m_temp, inString+length-blockSize, blockSize);	// save copy now in case of in-place decryption
	if (length > blockSize)
		m_cipher->AdvancedProcessBlocks(inString+blockSize, inString, outString+blockSize, length-blockSize, BlockTransformation::BT_ReverseDirection);
	m_cipher->ProcessAndXorBlock(inString, m_register, outString);
	m_register.swap(m_temp);
}

void CBC_CTS_Decryption::ProcessLastBlock(byte *outString, const byte *inString, size_t length)
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
