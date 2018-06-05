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
using CryptoPP::rotlConstant;

template <unsigned int RR>
inline word16 CHAM64_Round(const word16 x[4], const word16 k[], unsigned int kw, unsigned int i)
{
	// RR is "round residue". The round function only cares about [0-3].
	CRYPTOPP_CONSTANT(IDX1 = (RR+0) % 4)
	CRYPTOPP_CONSTANT(IDX2 = (RR+1) % 4)
	CRYPTOPP_CONSTANT(R1 = RR % 2 ? 1 : 8)
	CRYPTOPP_CONSTANT(R2 = RR % 2 ? 8 : 1)

	return static_cast<word16>(rotlConstant<R2>((x[IDX1] ^ i) +
			((rotlConstant<R1>(x[IDX2]) ^ k[i % (2 * kw)]) & 0xFFFF)));
}

template <unsigned int RR>
inline word32 CHAM128_Round(const word32 x[4], const word32 k[], unsigned int kw, unsigned int i)
{
	// RR is "round residue". The round function only cares about [0-3].
	CRYPTOPP_CONSTANT(IDX1 = (RR+0) % 4)
	CRYPTOPP_CONSTANT(IDX2 = (RR+1) % 4)
	CRYPTOPP_CONSTANT(R1 = RR % 2 ? 1 : 8)
	CRYPTOPP_CONSTANT(R2 = RR % 2 ? 8 : 1)

	return static_cast<word32>(rotlConstant<R2>((x[IDX1] ^ i) +
			((rotlConstant<R1>(x[IDX2]) ^ k[i % (2 * kw)]) & 0xFFFFFFFF)));
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void CHAM64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
	CRYPTOPP_UNUSED(params);
	CRYPTOPP_ASSERT(keyLength == 16);  // 128-bits

	// Fix me... Is this correct?
	m_kw = keyLength/sizeof(word16);
	m_key.New(2*m_kw);

	for (size_t i = 0; i < m_kw; ++i)
	{
		// Extract k[i]. Under the hood a memcpy happens.
		// Can't do the cast. It will SIGBUS on ARM and SPARC.
		const word16 ki = GetWord<word16>(false, BIG_ENDIAN_ORDER, userKey);
		userKey += sizeof(word16);

		m_key[i] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<8>(ki);
		m_key[(i + m_kw) ^ 1] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<11>(ki);
	}
}

void CHAM64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	GetBlock<word16, BigEndian, false> iblock(inBlock);
	iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

	const unsigned int R = 80;
	// for (size_t i = 0; i < R; ++i)
	for (size_t i = 0; i < R; i+=4)
	{
#if 0
		const word16 t = CHAM64_Round(m_x, m_key, m_kw, i);
		m_x[0] = m_x[1];
		m_x[1] = m_x[2];
		m_x[2] = m_x[3];
		m_x[3] = t;
#endif
		m_x[0] = CHAM64_Round<0>(m_x, m_key, m_kw, i);
		m_x[1] = CHAM64_Round<1>(m_x, m_key, m_kw, i);
		m_x[2] = CHAM64_Round<2>(m_x, m_key, m_kw, i);
		m_x[3] = CHAM64_Round<3>(m_x, m_key, m_kw, i);
	}

	PutBlock<word16, BigEndian, false> oblock(xorBlock, outBlock);
	oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

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
	m_key.New(2*m_kw);

	for (size_t i = 0; i < m_kw; ++i)
	{
		// Extract k[i]. Under the hood a memcpy happens.
		// Can't do the cast. It will SIGBUS on ARM and SPARC.
		const word32 ki = GetWord<word32>(false, BIG_ENDIAN_ORDER, userKey);
		userKey += sizeof(word32);

		m_key[i] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<8>(ki);
		m_key[(i + m_kw) ^ 1] = ki ^ rotlConstant<1>(ki) ^ rotlConstant<11>(ki);
	}
}

void CHAM128::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	GetBlock<word32, BigEndian, false> iblock(inBlock);
	iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

	const unsigned int R = 80;
	// for (size_t i = 0; i < R; ++i)
	for (size_t i = 0; i < R; i+=4)
	{
#if 0
		const word32 t = CHAM128_Round(m_x, m_key, m_kw, i);
		m_x[0] = m_x[1];
		m_x[1] = m_x[2];
		m_x[2] = m_x[3];
		m_x[3] = t;
#endif
		m_x[0] = CHAM128_Round<0>(m_x, m_key, m_kw, i);
		m_x[1] = CHAM128_Round<1>(m_x, m_key, m_kw, i);
		m_x[2] = CHAM128_Round<2>(m_x, m_key, m_kw, i);
		m_x[3] = CHAM128_Round<3>(m_x, m_key, m_kw, i);
	}

	PutBlock<word32, BigEndian, false> oblock(xorBlock, outBlock);
	oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

void CHAM128::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	std::memcpy(outBlock, inBlock, CHAM128::BLOCKSIZE);
	if (xorBlock)
		xorbuf(outBlock, xorBlock, CHAM128::BLOCKSIZE);
}

NAMESPACE_END
