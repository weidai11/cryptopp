// cham.cpp - written and placed in the public domain by Kim Sung Hee and Jeffrey Walton
//            Based on "CHAM: A Family of Lightweight Block Ciphers for
//            Resource-Constrained Devices" by Bonwook Koo, Dongyoung Roh,
//            Hyeonjin Kim, Younghoon Jung, Dong-Geon Lee, and Daesung Kwon

#include "pch.h"
#include "config.h"

#include "cham.h"
#include "misc.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word16;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlConstant;

inline word16 CHAM64_Round(word16 x[2], const word16 k[4], unsigned int kw, unsigned int i)
{
	word16 t;
	if (i % 2 == 0) {
		t = static_cast<word16>(rotlConstant<8>((x[0] ^ i) +
				((rotlConstant<1>(x[1]) ^ k[i % (2 * kw)]) & 0xFFFF)));
	}
	else {
		t = static_cast<word16>(rotlConstant<1>((x[0] ^ i) +
				((rotlConstant<8>(x[1]) ^ k[i % (2 * kw)]) & 0xFFFF)));
	}
	return t;
}

inline word32 CHAM128_Round(word32 x[2], const word32 k[4], unsigned int kw, unsigned int i)
{
	word32 t;
	if (i % 2 == 0) {
		t = static_cast<word32>(rotlConstant<8>((x[0] ^ i) +
				((rotlConstant<1>(x[1]) ^ k[i % (2 * kw)]) & 0xFFFF)));
	}
	else {
		t = static_cast<word32>(rotlConstant<1>((x[0] ^ i) +
				((rotlConstant<8>(x[1]) ^ k[i % (2 * kw)]) & 0xFFFF)));
	}
	return t;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void CHAM64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
	CRYPTOPP_UNUSED(params);
	CRYPTOPP_ASSERT(keyLength == 16);  // 128-bits

	// Fix me... Is this correct?
	m_kw = keyLength/sizeof(word16);
	m_key.New(keyLength);

	for (size_t i = 0; i < m_kw; ++i)
	{
		// Avoid the cast which violates punning and aliasing rules
		const byte* addr = userKey+i*sizeof(word16);
		// Extract k[i]. Under the hood a memcpy happens
		const word16 ki = GetWord<word16>(false, BIG_ENDIAN_ORDER, addr);

		m_key[i] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<8>(ki);
		m_key[(i + m_kw) ^ 1] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<11>(ki);
	}
}

void CHAM64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	const unsigned int R = 80;
	for (size_t i = 0; i < 4; ++i)
	{
		m_x[0] = GetWord<word16>(false, BIG_ENDIAN_ORDER, inBlock);
		inBlock += sizeof(word16);
		m_x[1] = GetWord<word16>(false, BIG_ENDIAN_ORDER, inBlock);
		inBlock += sizeof(word16);

		const word16 t = CHAM64_Round(m_x, m_key, m_kw, i);

		m_x[0] = m_x[1];
		m_x[1] = m_x[2];
		m_x[2] = m_x[3];
		m_x[3] = t;
	}

	for (size_t i = 4; i < R; ++i)
	{
		const word16 t = CHAM64_Round(m_x, m_key, m_kw, i);

		m_x[0] = m_x[1];
		m_x[1] = m_x[2];
		m_x[2] = m_x[3];
		m_x[3] = t;
	}

	if (xorBlock)
		xorbuf(outBlock, inBlock, xorBlock, CHAM64::BLOCKSIZE);
	else
		std::memcpy(outBlock, m_x, CHAM64::BLOCKSIZE);
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

	// Fix me... Is this correct?
	m_kw = keyLength/sizeof(word32);
	m_key.New(keyLength);

	for (size_t i = 0; i < m_kw; ++i)
	{
		// Avoid the cast which violates punning and aliasing rules
		const byte* addr = userKey+i*sizeof(word32);
		// Extract k[i]. Under the hood a memcpy happens
		const word32 ki = GetWord<word32>(false, BIG_ENDIAN_ORDER, addr);

		m_key[i] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<8>(ki);
		m_key[(i + m_kw) ^ 1] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<11>(ki);
	}
}

// If CHAM128::Enc::ProcessAndXorBlock and CHAM128::Dec::ProcessAndXorBlock
//   are the same code, then we can fold them into CHAM128::Base and supply
//   one CHAM128::Base::ProcessAndXorBlock.
void CHAM128::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	const unsigned int R = 80;
	for (size_t i = 0; i < 4; ++i)
	{
		m_x[0] = GetWord<word32>(false, BIG_ENDIAN_ORDER, inBlock);
		inBlock += sizeof(word32);
		m_x[1] = GetWord<word32>(false, BIG_ENDIAN_ORDER, inBlock);
		inBlock += sizeof(word32);

		const word32 t = CHAM128_Round(m_x, m_key, m_kw, i);

		m_x[0] = m_x[1];
		m_x[1] = m_x[2];
		m_x[2] = m_x[3];
		m_x[3] = t;
	}

	for (size_t i = 4; i < R; ++i)
	{
		const word32 t = CHAM128_Round(m_x, m_key, m_kw, i);

		m_x[0] = m_x[1];
		m_x[1] = m_x[2];
		m_x[2] = m_x[3];
		m_x[3] = t;
	}

	if (xorBlock)
		xorbuf(outBlock, inBlock, xorBlock, CHAM128::BLOCKSIZE);
	else
		std::memcpy(outBlock, m_x, CHAM128::BLOCKSIZE);
}

void CHAM128::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	std::memcpy(outBlock, inBlock, CHAM128::BLOCKSIZE);
	if (xorBlock)
		xorbuf(outBlock, xorBlock, CHAM128::BLOCKSIZE);
}

NAMESPACE_END
