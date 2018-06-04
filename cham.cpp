// cham.cpp - written and placed in the public domain by Kim Sung Hee and Jeffrey Walton
//            Based on "CHAM: A Family of Lightweight Block Ciphers for
//            Resource-Constrained Devices" by Bonwook Koo, Dongyoung Roh,
//            Hyeonjin Kim, Younghoon Jung, Dong-Geon Lee, and Daesung Kwon

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
	std::memcpy(m_x.begin(), inBlock, CHAM64::BLOCKSIZE);

	const unsigned int R = 80;
	for (size_t i = 0; i < R; ++i)
	{
		word16 t;
		if (i % 2 == 0) {
			t = static_cast<word16>(rotlConstant<8>((m_x[0] ^ i) +
					((rotlConstant<1>(m_x[1]) ^ m_key[i % (2 * m_kw)]) & 0xFFFF)));
		}
		else {
			t = static_cast<word16>(rotlConstant<1>((m_x[0] ^ i) +
					((rotlConstant<8>(m_x[1]) ^ m_key[i % (2 * m_kw)]) & 0xFFFF)));
		}

		m_x[0] = m_x[1];
		m_x[1] = m_x[2];
		m_x[2] = m_x[3];
		m_x[3] = t;
	}

	std::memcpy(outBlock, m_x.begin(), CHAM64::BLOCKSIZE);

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
	std::memcpy(m_x.begin(), inBlock, CHAM128::BLOCKSIZE);

	const unsigned int R = 80;
	for (size_t i = 0; i < R; ++i)
	{
		word32 t;
		if (i % 2 == 0) {
			t = rotlConstant<8>((m_x[0] ^ i)+((rotlConstant<1>(m_x[1]) ^ m_key[i % (2 * m_kw)]) & 0xFFFFFFFF));
		}
		else {
			t = rotlConstant<1>((m_x[0] ^ i)+((rotlConstant<8>(m_x[1]) ^ m_key[i % (2 * m_kw)]) & 0xFFFFFFFF));
		}

		m_x[0] = m_x[1];
		m_x[1] = m_x[2];
		m_x[2] = m_x[3];
		m_x[3] = t;
	}

	std::memcpy(outBlock, m_x.begin(), CHAM128::BLOCKSIZE);

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
