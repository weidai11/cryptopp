// modes.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "modes.h"
#include "misc.h"

#if defined(CRYPTOPP_DEBUG)
#include "des.h"
#endif

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
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

void CipherModeBase::ResizeBuffers()
{
	m_register.New(m_cipher->BlockSize());
}

void CFB_ModePolicy::Iterate(byte *output, const byte *input, CipherDir dir, size_t iterationCount)
{
	CRYPTOPP_ASSERT(input);
	CRYPTOPP_ASSERT(output);
	CRYPTOPP_ASSERT(m_cipher->IsForwardTransformation());	// CFB mode needs the "encrypt" direction of the underlying block cipher, even to decrypt
	CRYPTOPP_ASSERT(m_feedbackSize == BlockSize());

	const unsigned int s = BlockSize();
	if (dir == ENCRYPTION)
	{
		m_cipher->ProcessAndXorBlock(m_register, input, output);
		if (iterationCount > 1)
			m_cipher->AdvancedProcessBlocks(output, input+s, output+s, (iterationCount-1)*s, 0);
		std::memcpy(m_register, output+(iterationCount-1)*s, s);
	}
	else
	{
		std::memcpy(m_temp, input+(iterationCount-1)*s, s);	// make copy first in case of in-place decryption
		if (iterationCount > 1)
			m_cipher->AdvancedProcessBlocks(input, input+s, output+s, (iterationCount-1)*s, BlockTransformation::BT_ReverseDirection);
		m_cipher->ProcessAndXorBlock(m_register, input, output);
		std::memcpy(m_register, m_temp, s);
	}
}

void CFB_ModePolicy::TransformRegister()
{
	CRYPTOPP_ASSERT(m_cipher->IsForwardTransformation());	// CFB mode needs the "encrypt" direction of the underlying block cipher, even to decrypt
	m_cipher->ProcessBlock(m_register, m_temp);
	unsigned int updateSize = BlockSize()-m_feedbackSize;
	memmove_s(m_register, m_register.size(), m_register+m_feedbackSize, updateSize);
	memcpy_s(m_register+updateSize, m_register.size()-updateSize, m_temp, m_feedbackSize);
}

void CFB_ModePolicy::CipherResynchronize(const byte *iv, size_t length)
{
	CRYPTOPP_ASSERT(length == BlockSize());
	CopyOrZero(m_register, m_register.size(), iv, length);
	TransformRegister();
}

void CFB_ModePolicy::SetFeedbackSize(unsigned int feedbackSize)
{
	if (feedbackSize > BlockSize())
		throw InvalidArgument("CFB_Mode: invalid feedback size");
	m_feedbackSize = feedbackSize ? feedbackSize : BlockSize();
}

void CFB_ModePolicy::ResizeBuffers()
{
	CipherModeBase::ResizeBuffers();
	m_temp.New(BlockSize());
}

void OFB_ModePolicy::WriteKeystream(byte *keystreamBuffer, size_t iterationCount)
{
	CRYPTOPP_ASSERT(m_cipher->IsForwardTransformation());	// OFB mode needs the "encrypt" direction of the underlying block cipher, even to decrypt
	const unsigned int s = BlockSize();
	m_cipher->ProcessBlock(m_register, keystreamBuffer);
	if (iterationCount > 1)
		m_cipher->AdvancedProcessBlocks(keystreamBuffer, NULLPTR, keystreamBuffer+s, s*(iterationCount-1), 0);
	std::memcpy(m_register, keystreamBuffer+s*(iterationCount-1), s);
}

void OFB_ModePolicy::CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length)
{
	CRYPTOPP_UNUSED(keystreamBuffer), CRYPTOPP_UNUSED(length);
	CRYPTOPP_ASSERT(length == BlockSize());

	CopyOrZero(m_register, m_register.size(), iv, length);
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

void CTR_ModePolicy::OperateKeystream(KeystreamOperation /*operation*/, byte *output, const byte *input, size_t iterationCount)
{
	// CTR mode needs the "encrypt" direction of the underlying block cipher, even to decrypt
	CRYPTOPP_ASSERT(m_cipher->IsForwardTransformation());
	const unsigned int s = BlockSize();
	const unsigned int inputIncrement = input ? s : 0;
	const unsigned int alignment = m_cipher->OptimalDataAlignment();

	while (iterationCount)
	{
		byte lsb = m_counterArray[s-1];
		const size_t blocks = UnsignedMin(iterationCount, 256U-lsb);
		const bool align = !IsAlignedOn(input, alignment) || !IsAlignedOn(output, alignment);

		if (align)
		{
			AlignedSecByteBlock i(input, blocks*s), o(blocks*s);
			m_cipher->AdvancedProcessBlocks(m_counterArray, i, o, blocks*s, BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_AllowParallel);
			std::memcpy(output, o, blocks*s);
		}
		else
		{
			m_cipher->AdvancedProcessBlocks(m_counterArray, input, output, blocks*s, BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_AllowParallel);
		}
		if ((m_counterArray[s-1] = lsb + (byte)blocks) == 0)
			IncrementCounterBy256();

		output += blocks*s;
		input += blocks*inputIncrement;
		iterationCount -= blocks;
	}
}

void CTR_ModePolicy::CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length)
{
	CRYPTOPP_UNUSED(keystreamBuffer), CRYPTOPP_UNUSED(length);
	CRYPTOPP_ASSERT(length == BlockSize());

	CopyOrZero(m_register, m_register.size(), iv, length);
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

void BlockOrientedCipherModeBase::ResizeBuffers()
{
	CipherModeBase::ResizeBuffers();
	m_buffer.New(BlockSize());
}

void ECB_OneWay::ProcessData(byte *outString, const byte *inString, size_t length)
{
	// If this fires you should align your buffers. There's a non-trival penalty for some processors
	CRYPTOPP_ASSERT(IsAlignedOn(inString, m_cipher->OptimalDataAlignment()));
	CRYPTOPP_ASSERT(IsAlignedOn(outString, m_cipher->OptimalDataAlignment()));
	CRYPTOPP_ASSERT(length%BlockSize()==0);

	const unsigned int blockSize = BlockSize();
	const unsigned int alignment = m_cipher->OptimalDataAlignment();
	bool align = !IsAlignedOn(inString, alignment) || !IsAlignedOn(outString, alignment);

	if (align)
	{
		AlignedSecByteBlock i(length), o(length);
		std::memcpy(i, inString, length);
		std::memcpy(o, outString+length-blockSize, blockSize);  // copy tail
		m_cipher->AdvancedProcessBlocks(i, NULLPTR, o, length, BlockTransformation::BT_AllowParallel);
		std::memcpy(outString, o, length);
	}
	else
	{
		m_cipher->AdvancedProcessBlocks(inString, NULLPTR, outString, length, BlockTransformation::BT_AllowParallel);
	}
}

void CBC_Encryption::ProcessData(byte *outString, const byte *inString, size_t length)
{
	// If this fires you should align your buffers. There's a non-trival penalty for some processors
	// CRYPTOPP_ASSERT(IsAlignedOn(inString, m_cipher->OptimalDataAlignment()));
	CRYPTOPP_ASSERT(IsAlignedOn(outString, m_cipher->OptimalDataAlignment()));
	CRYPTOPP_ASSERT(length%BlockSize()==0);

	if (!length)
		return;

	const unsigned int blockSize = BlockSize();
	const unsigned int alignment = m_cipher->OptimalDataAlignment();
	bool align = !IsAlignedOn(inString, alignment) || !IsAlignedOn(outString, alignment);

	if (align)
	{
		AlignedSecByteBlock i(length), o(length);
		std::memcpy(i, inString, length);
		std::memcpy(o, outString+length-blockSize, blockSize);  // copy tail

		m_cipher->AdvancedProcessBlocks(i, m_register, o, blockSize, BlockTransformation::BT_XorInput);
		if (length > blockSize)
			m_cipher->AdvancedProcessBlocks(i+blockSize, o, o+blockSize, length-blockSize, BlockTransformation::BT_XorInput);
		std::memcpy(m_register, o + length - blockSize, blockSize);
		std::memcpy(outString, o, length);
	}
	else
	{
		m_cipher->AdvancedProcessBlocks(inString, m_register, outString, blockSize, BlockTransformation::BT_XorInput);
		if (length > blockSize)
			m_cipher->AdvancedProcessBlocks(inString+blockSize, outString, outString+blockSize, length-blockSize, BlockTransformation::BT_XorInput);
		std::memcpy(m_register, outString + length - blockSize, blockSize);
	}
}

void CBC_CTS_Encryption::ProcessLastBlock(byte *outString, const byte *inString, size_t length)
{
	// If this fires you should align your buffers. There's a non-trival penalty for some processors
	CRYPTOPP_ASSERT(IsAlignedOn(inString, m_cipher->OptimalDataAlignment()));
	CRYPTOPP_ASSERT(IsAlignedOn(outString, m_cipher->OptimalDataAlignment()));

	if (length <= BlockSize())
	{
		if (!m_stolenIV)
			throw InvalidArgument("CBC_Encryption: message is too short for ciphertext stealing");

		// steal from IV
		std::memcpy(outString, m_register, length);
		outString = m_stolenIV;
	}
	else
	{
		// steal from next to last block
		xorbuf(m_register, inString, BlockSize());
		m_cipher->ProcessBlock(m_register);
		inString += BlockSize();
		length -= BlockSize();
		std::memcpy(outString+BlockSize(), m_register, length);
	}

	// output last full ciphertext block
	xorbuf(m_register, inString, length);
	m_cipher->ProcessBlock(m_register);
	std::memcpy(outString, m_register, BlockSize());
}

void CBC_Decryption::ResizeBuffers()
{
	BlockOrientedCipherModeBase::ResizeBuffers();
	m_temp.New(BlockSize());
}

void CBC_Decryption::ProcessData(byte *outString, const byte *inString, size_t length)
{
	// If this fires you should align your buffers. There's a non-trival penalty for some processors
	CRYPTOPP_ASSERT(IsAlignedOn(inString, m_cipher->OptimalDataAlignment()));
	CRYPTOPP_ASSERT(IsAlignedOn(outString, m_cipher->OptimalDataAlignment()));
	CRYPTOPP_ASSERT(length%BlockSize()==0);

	if (!length)
		return;

	const unsigned int blockSize = BlockSize();
	const unsigned int alignment = m_cipher->OptimalDataAlignment();
	bool align = !IsAlignedOn(inString, alignment) || !IsAlignedOn(outString, alignment);

	if (align)
	{
		AlignedSecByteBlock i(length), o(length);
		std::memcpy(i, inString, length);
		std::memcpy(o, outString+length-blockSize, blockSize);  // copy tail

		std::memcpy(m_temp, i+length-blockSize, blockSize);	// save copy now in case of in-place decryption
		if (length > blockSize)
			m_cipher->AdvancedProcessBlocks(i+blockSize, i, o+blockSize, length-blockSize, BlockTransformation::BT_ReverseDirection|BlockTransformation::BT_AllowParallel);
		m_cipher->ProcessAndXorBlock(i, m_register, o);
		m_register.swap(m_temp);
		std::memcpy(outString, o, length);
	}
	else
	{
		std::memcpy(m_temp, inString+length-blockSize, blockSize);	// save copy now in case of in-place decryption
		if (length > blockSize)
			m_cipher->AdvancedProcessBlocks(inString+blockSize, inString, outString+blockSize, length-blockSize, BlockTransformation::BT_ReverseDirection|BlockTransformation::BT_AllowParallel);
		m_cipher->ProcessAndXorBlock(inString, m_register, outString);
		m_register.swap(m_temp);
	}
}

void CBC_CTS_Decryption::ProcessLastBlock(byte *outString, const byte *inString, size_t length)
{
	// If this fires you should align your buffers. There's a non-trival penalty for some processors
	CRYPTOPP_ASSERT(IsAlignedOn(inString, m_cipher->OptimalDataAlignment()));
	CRYPTOPP_ASSERT(IsAlignedOn(outString, m_cipher->OptimalDataAlignment()));

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
	std::memcpy(m_temp, pn1, BlockSize());
	m_cipher->ProcessBlock(m_temp);
	xorbuf(m_temp, pn, length);

	if (stealIV)
		std::memcpy(outString, m_temp, length);
	else
	{
		std::memcpy(outString+BlockSize(), m_temp, length);
		// decrypt next to last plaintext block
		std::memcpy(m_temp, pn, length);
		m_cipher->ProcessBlock(m_temp);
		xorbuf(outString, m_temp, m_register, BlockSize());
	}
}

NAMESPACE_END

#endif
