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
inline void CHAM64_Round(word16 x[4], const word16 k[], unsigned int i)
{
    // RR is "round residue". The round function only cares about [0-3].
    CRYPTOPP_CONSTANT(IDX1 = (RR+0) % 4)
    CRYPTOPP_CONSTANT(IDX2 = (RR+1) % 4)
    CRYPTOPP_CONSTANT(IDX4 = (RR+3) % 4)
    CRYPTOPP_CONSTANT(R1 = RR % 2 ? 1 : 8)
    CRYPTOPP_CONSTANT(R2 = RR % 2 ? 8 : 1)

    x[IDX4] = static_cast<word16>(rotlConstant<R2>((x[IDX1] ^ i) +
            ((rotlConstant<R1>(x[IDX2]) ^ k[i % 16]) & 0xFFFF)));
}

template <unsigned int RR, unsigned int KW>
inline void CHAM128_Round(word32 x[4], const word32 k[], unsigned int i)
{
    // RR is "round residue". The round function only cares about [0-3].
    CRYPTOPP_CONSTANT(IDX1 = (RR+0) % 4)
    CRYPTOPP_CONSTANT(IDX2 = (RR+1) % 4)
    CRYPTOPP_CONSTANT(IDX4 = (RR+3) % 4)
    CRYPTOPP_CONSTANT(R1 = RR % 2 ? 1 : 8)
    CRYPTOPP_CONSTANT(R2 = RR % 2 ? 8 : 1)

    x[IDX4] = static_cast<word32>(rotlConstant<R2>((x[IDX1] ^ i) +
            ((rotlConstant<R1>(x[IDX2]) ^ k[i % KW]) & 0xFFFFFFFF)));
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void CHAM64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    CRYPTOPP_ASSERT(keyLength == 16);  // 128-bits

    // Fix me... Is this correct?
    m_kw = keyLength/sizeof(word16);
    m_rk.New(2*m_kw);

    for (size_t i = 0; i < m_kw; ++i)
    {
        // Extract k[i]. Under the hood a memcpy happens.
        // Can't do the cast. It will SIGBUS on ARM and SPARC.
        const word16 rk = GetWord<word16>(false, BIG_ENDIAN_ORDER, userKey);
        userKey += sizeof(word16);

        m_rk[i] = rk ^ rotlConstant<1>(rk) ^ rotlConstant<8>(rk);
        m_rk[(i + m_kw) ^ 1] = rk ^ rotlConstant<1>(rk) ^ rotlConstant<11>(rk);
    }
}

void CHAM64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    GetBlock<word16, BigEndian, false> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    const unsigned int R = 80;
    for (size_t i = 0; i < R; i+=4)
    {
        CHAM64_Round<0>(m_x, m_rk, i+0);
        CHAM64_Round<1>(m_x, m_rk, i+1);
        CHAM64_Round<2>(m_x, m_rk, i+2);
        CHAM64_Round<3>(m_x, m_rk, i+3);
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
    m_rk.New(2*m_kw);

    for (size_t i = 0; i < m_kw; ++i)
    {
        // Extract k[i]. Under the hood a memcpy happens.
        // Can't do the cast. It will SIGBUS on ARM and SPARC.
        const word32 rk = GetWord<word32>(false, BIG_ENDIAN_ORDER, userKey);
        userKey += sizeof(word32);

        m_rk[i] = rk ^ rotlConstant<1>(rk) ^ rotlConstant<8>(rk);
        m_rk[(i + m_kw) ^ 1] = rk ^ rotlConstant<1>(rk) ^ rotlConstant<11>(rk);
    }
}

void CHAM128::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    GetBlock<word32, BigEndian, false> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    switch (m_kw)
    {
    case 4:  // 128-bit key
    {
        const unsigned int R = 80;
        for (size_t i = 0; i < R; i+=4)
        {
            CHAM128_Round<0, 8>(m_x, m_rk, i+0);
            CHAM128_Round<1, 8>(m_x, m_rk, i+1);
            CHAM128_Round<2, 8>(m_x, m_rk, i+2);
            CHAM128_Round<3, 8>(m_x, m_rk, i+3);
        }
        break;
    }
    case 8:  // 256-bit key
    {
        const unsigned int R = 96;
        for (size_t i = 0; i < R; i+=4)
        {
            CHAM128_Round<0, 16>(m_x, m_rk, i+0);
            CHAM128_Round<1, 16>(m_x, m_rk, i+1);
            CHAM128_Round<2, 16>(m_x, m_rk, i+2);
            CHAM128_Round<3, 16>(m_x, m_rk, i+3);
        }
        break;
    }
    default:
        CRYPTOPP_ASSERT(0);;
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
