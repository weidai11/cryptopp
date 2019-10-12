// cmac.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "cmac.h"
#include "misc.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::IsPowerOf2;

void MulU(byte *k, unsigned int len)
{
	byte carry = 0;
	for (int i=len-1; i>=1; i-=2)
	{
		byte carry2 = k[i] >> 7;
		k[i] += k[i] + carry;
		carry = k[i-1] >> 7;
		k[i-1] += k[i-1] + carry2;
	}

#ifndef CRYPTOPP_CMAC_WIDE_BLOCK_CIPHERS
	CRYPTOPP_ASSERT(len == 16);

	if (carry)
	{
		k[15] ^= 0x87;
		return;
	}
#else
	CRYPTOPP_ASSERT(IsPowerOf2(len));
	CRYPTOPP_ASSERT(len >= 8);
	CRYPTOPP_ASSERT(len <= 128);

	if (carry)
	{
		switch (len)
		{
		case 8:
			k[7] ^= 0x1b;
			break;
		case 16:
			k[15] ^= 0x87;
			break;
		case 32:
			// https://crypto.stackexchange.com/q/9815/10496
			// Polynomial x^256 + x^10 + x^5 + x^2 + 1
			k[30] ^= 4;
			k[31] ^= 0x25;
			break;
		case 64:
			// https://crypto.stackexchange.com/q/9815/10496
			// Polynomial x^512 + x^8 + x^5 + x^2 + 1
			k[62] ^= 1;
			k[63] ^= 0x25;
			break;
		case 128:
			// https://crypto.stackexchange.com/q/9815/10496
			// Polynomial x^1024 + x^19 + x^6 + x + 1
			k[125] ^= 8;
			k[126] ^= 0x00;
			k[127] ^= 0x43;
			break;
		default:
			CRYPTOPP_ASSERT(0);
		}
	}
#endif  // CRYPTOPP_CMAC_WIDE_BLOCK_CIPHERS
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void CMAC_Base::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	BlockCipher &cipher = AccessCipher();
	cipher.SetKey(key, length, params);

	unsigned int blockSize = cipher.BlockSize();
	m_reg.CleanNew(3*blockSize);
	m_counter = 0;

	cipher.ProcessBlock(m_reg, m_reg+blockSize);
	MulU(m_reg+blockSize, blockSize);
	memcpy(m_reg+2*blockSize, m_reg+blockSize, blockSize);
	MulU(m_reg+2*blockSize, blockSize);
}

void CMAC_Base::Update(const byte *input, size_t length)
{
	CRYPTOPP_ASSERT((input && length) || !(input || length));
	if (!length)
		return;

	BlockCipher &cipher = AccessCipher();
	unsigned int blockSize = cipher.BlockSize();

	if (m_counter > 0)
	{
		const unsigned int len = UnsignedMin(blockSize - m_counter, length);
		if (len)
		{
			xorbuf(m_reg+m_counter, input, len);
			length -= len;
			input += len;
			m_counter += len;
		}

		if (m_counter == blockSize && length > 0)
		{
			cipher.ProcessBlock(m_reg);
			m_counter = 0;
		}
	}

	if (length > blockSize)
	{
		CRYPTOPP_ASSERT(m_counter == 0);
		size_t leftOver = 1 + cipher.AdvancedProcessBlocks(m_reg, input, m_reg, length-1, BlockTransformation::BT_DontIncrementInOutPointers|BlockTransformation::BT_XorInput);
		input += (length - leftOver);
		length = leftOver;
	}

	if (length > 0)
	{
		CRYPTOPP_ASSERT(m_counter + length <= blockSize);
		xorbuf(m_reg+m_counter, input, length);
		m_counter += (unsigned int)length;
	}

	CRYPTOPP_ASSERT(m_counter > 0);
}

void CMAC_Base::TruncatedFinal(byte *mac, size_t size)
{
	ThrowIfInvalidTruncatedSize(size);

	BlockCipher &cipher = AccessCipher();
	unsigned int blockSize = cipher.BlockSize();

	if (m_counter < blockSize)
	{
		m_reg[m_counter] ^= 0x80;
		cipher.AdvancedProcessBlocks(m_reg, m_reg+2*blockSize, m_reg, blockSize, BlockTransformation::BT_DontIncrementInOutPointers|BlockTransformation::BT_XorInput);
	}
	else
		cipher.AdvancedProcessBlocks(m_reg, m_reg+blockSize, m_reg, blockSize, BlockTransformation::BT_DontIncrementInOutPointers|BlockTransformation::BT_XorInput);

	memcpy(mac, m_reg, size);

	m_counter = 0;
	memset(m_reg, 0, blockSize);
}

NAMESPACE_END

#endif
