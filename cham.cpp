// cham.cpp - written and placed in the public domain by Kim Sung Hee and Jeffrey Walton
//            Based on "CHAM: A Family of Lightweight Block Ciphers for Resource-Constrained Devices"
//            by Bonwook Koo, Dongyoung Roh, Hyeonjin Kim, Younghoon Jung, Dong-Geon Lee, and Daesung Kwon

#include "pch.h"
#include "config.h"

#include "cham.h"
#include "misc.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlConstant;

template <unsigned int W>
inline word64 Power()
{
	CRYPTOPP_ASSERT(W < sizeof(word64));
	return W64LIT(1) << W;
};

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void CHAM64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
	CRYPTOPP_UNUSED(params);
	CRYPTOPP_ASSERT(keyLength == 16);  // 128-bits

	m_key.New(keyLength);
	for (size_t i = 0; i < keyLength; i++)
	{
		// Fix me
		const size_t KW = 0;
		// Avoid the cast which violates punning and aliasing rules
		const byte* addr = userKey+i*sizeof(word16);
		// Extract k[i]. Under the hood a memcpy happens
		const word16 ki = GetWord<word16>(false, BIG_ENDIAN_ORDER, addr);

		m_key[i] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<8>(ki);
		m_key[(i + KW) ^ 1] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<11>(ki);
	}
}

void CHAM64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	std::memcpy(outBlock, inBlock, CHAM64::BLOCKSIZE);
	if (xorBlock)
		xorbuf(outBlock, xorBlock, CHAM64::BLOCKSIZE);
}

// If CHAM64::Enc::ProcessAndXorBlock and CHAM64::Dec::ProcessAndXorBlock
//   are the same code, then we can fold them into CHAM64::Base and supply
//   one CHAM64::Base::ProcessAndXorBlock.
void CHAM64::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	std::memcpy(outBlock, inBlock, CHAM64::BLOCKSIZE);
	if (xorBlock)
		xorbuf(outBlock, xorBlock, CHAM64::BLOCKSIZE);
}

void CHAM128::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
	CRYPTOPP_UNUSED(params);
	CRYPTOPP_ASSERT(keyLength == 16 || keyLength == 32);  // 128-bits or 256-bits
}

// If CHAM128::Enc::ProcessAndXorBlock and CHAM128::Dec::ProcessAndXorBlock
//   are the same code, then we can fold them into CHAM128::Base and supply
//   one CHAM128::Base::ProcessAndXorBlock.
void CHAM128::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	std::memcpy(outBlock, inBlock, CHAM128::BLOCKSIZE);
	if (xorBlock)
		xorbuf(outBlock, xorBlock, CHAM128::BLOCKSIZE);
}

void CHAM128::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	std::memcpy(outBlock, inBlock, CHAM128::BLOCKSIZE);
	if (xorBlock)
		xorbuf(outBlock, xorBlock, CHAM128::BLOCKSIZE);
}

NAMESPACE_END
