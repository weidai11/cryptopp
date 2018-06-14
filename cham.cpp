// cham.cpp - written and placed in the public domain by Kim Sung Hee and Jeffrey Walton
//            Based on "CHAM: A Family of Lightweight Block Ciphers for
//            Resource-Constrained Devices" by Bonwook Koo, Dongyoung Roh,
//            Hyeonjin Kim, Younghoon Jung, Dong-Geon Lee, and Daesung Kwon

#include "pch.h"
#include "config.h"

#include "cham.h"
#include "misc.h"

//                 CHAM table of parameters
//  +-------------------------------------------------
//  +cipher          n      k      r     w      k/w
//  +-------------------------------------------------
//  +CHAM-64/128     64     128    80    16     8
//  +CHAM-128/128    128    128    80    32     4
//  +CHAM-128/256    128    256    96    32     8
//  +-------------------------------------------------

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::rotlConstant;
using CryptoPP::rotrConstant;

template <unsigned int RR, unsigned int KW, class T>
inline void CHAM_EncRound(T x[4], const T k[KW], unsigned int i)
{
    CRYPTOPP_CONSTANT(IDX0 = (RR+0) % 4)    // current
    CRYPTOPP_CONSTANT(IDX1 = (RR+1) % 4)    // current
    CRYPTOPP_CONSTANT(IDX3 = (RR+3+1) % 4)  // next
    CRYPTOPP_CONSTANT(R1 = (RR % 2 == 0) ? 1 : 8)
    CRYPTOPP_CONSTANT(R2 = (RR % 2 == 0) ? 8 : 1)

    // Follows conventions in the paper
    const T kk = static_cast<T>(k[i % KW]);
    const T aa = static_cast<T>(x[IDX0] ^ i);
    const T bb = rotlConstant<R1>(x[IDX1]) ^ kk;
    x[IDX3] = rotlConstant<R2>(static_cast<T>(aa + bb));
}

template <unsigned int RR, unsigned int KW, class T>
inline void CHAM_DecRound(T x[4], const T k[KW], unsigned int i)
{
    CRYPTOPP_CONSTANT(IDX0 = (RR+0) % 4)    // current
    CRYPTOPP_CONSTANT(IDX1 = (RR+1) % 4)    // current
    CRYPTOPP_CONSTANT(IDX3 = (RR+3+1) % 4)  // next
    CRYPTOPP_CONSTANT(R1 = (RR % 2 == 0) ? 1 : 8)
    CRYPTOPP_CONSTANT(R2 = (RR % 2 == 0) ? 8 : 1)

    // Follows conventions in the paper
    const T kk = static_cast<T>(k[i % KW]);
    const T aa = static_cast<T>(x[IDX3] ^ i);
    const T bb = rotlConstant<R1>(x[IDX1]) ^ kk;
    x[IDX0] = rotrConstant<R2>(static_cast<T>(aa - bb));
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void CHAM64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);

    m_kw = keyLength/sizeof(word16);
    m_rk.New(2*m_kw);

    for (size_t i = 0; i < m_kw; ++i, userKey += sizeof(word16))
    {
        // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
        const word16 rk = GetWord<word16>(false, BIG_ENDIAN_ORDER, userKey);
        m_rk[i] = rk ^ rotlConstant<1>(rk) ^ rotlConstant<8>(rk);
        m_rk[(i + m_kw) ^ 1] = rk ^ rotlConstant<1>(rk) ^ rotlConstant<11>(rk);
    }

    //for (size_t i = 0; i < m_rk.size(); ++i)
    //    printf("%04hx\n", m_rk[i]);
    //printf("\n");
}

void CHAM64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    GetBlock<word16, BigEndian, false> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    const unsigned int R = 80;
    for (int i = 0; i < R; i+=4)
    {
        CHAM_EncRound<0, 16>(m_x.begin(), m_rk.begin(), i+0);
        CHAM_EncRound<1, 16>(m_x.begin(), m_rk.begin(), i+1);
        CHAM_EncRound<2, 16>(m_x.begin(), m_rk.begin(), i+2);
        CHAM_EncRound<3, 16>(m_x.begin(), m_rk.begin(), i+3);
    }

    PutBlock<word16, BigEndian, false> oblock(xorBlock, outBlock);
    oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

void CHAM64::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // TODO: implement decryption. You may need to add another round function for decryption.
    GetBlock<word16, BigEndian, false> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    const unsigned int R = 80;
    for (int i = R-1; i >=0 ; i-=4)
    {
        CHAM_DecRound<3, 16>(m_x.begin(), m_rk.begin(), i-0);
        CHAM_DecRound<2, 16>(m_x.begin(), m_rk.begin(), i-1);
        CHAM_DecRound<1, 16>(m_x.begin(), m_rk.begin(), i-2);
        CHAM_DecRound<0, 16>(m_x.begin(), m_rk.begin(), i-3);
    }

    PutBlock<word16, BigEndian, false> oblock(xorBlock, outBlock);
    oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

void CHAM128::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);

    m_kw = keyLength/sizeof(word32);
    m_rk.New(2*m_kw);

    for (size_t i = 0; i < m_kw; ++i, userKey += sizeof(word32))
    {
        // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
        const word32 rk = GetWord<word32>(false, BIG_ENDIAN_ORDER, userKey);
        m_rk[i] = rk ^ rotlConstant<1>(rk) ^ rotlConstant<8>(rk);
        m_rk[(i + m_kw) ^ 1] = rk ^ rotlConstant<1>(rk) ^ rotlConstant<11>(rk);
    }

    //for (size_t i = 0; i < m_rk.size(); ++i)
    //    printf("%08x\n", m_rk[i]);
    //printf("\n");
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
        for (int i = 0; i < R; i+=4)
        {
            CHAM_EncRound<0, 8>(m_x.begin(), m_rk.begin(), i+0);
            CHAM_EncRound<1, 8>(m_x.begin(), m_rk.begin(), i+1);
            CHAM_EncRound<2, 8>(m_x.begin(), m_rk.begin(), i+2);
            CHAM_EncRound<3, 8>(m_x.begin(), m_rk.begin(), i+3);
        }
        break;
    }
    case 8:  // 256-bit key
    {
        const unsigned int R = 96;
        for (int i = 0; i < R; i+=4)
        {
            CHAM_EncRound<0, 16>(m_x.begin(), m_rk.begin(), i+0);
            CHAM_EncRound<1, 16>(m_x.begin(), m_rk.begin(), i+1);
            CHAM_EncRound<2, 16>(m_x.begin(), m_rk.begin(), i+2);
            CHAM_EncRound<3, 16>(m_x.begin(), m_rk.begin(), i+3);
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
    // TODO: implement decryption. You may need to add another round function for decryption.
    GetBlock<word32, BigEndian, false> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    switch (m_kw)
    {
    case 4:  // 128-bit key
    {
        const unsigned int R = 80;
        for (int i = R-1; i >= 0; i-=4)
        {
            CHAM_DecRound<3, 8>(m_x.begin(), m_rk.begin(), i-0);
            CHAM_DecRound<2, 8>(m_x.begin(), m_rk.begin(), i-1);
            CHAM_DecRound<1, 8>(m_x.begin(), m_rk.begin(), i-2);
            CHAM_DecRound<0, 8>(m_x.begin(), m_rk.begin(), i-3);
        }
        break;
    }
    case 8:  // 256-bit key
    {
        const unsigned int R = 96;
        for (int i = R-1; i >= 0; i-=4)
        {
            CHAM_DecRound<3, 16>(m_x.begin(), m_rk.begin(), i-0);
            CHAM_DecRound<2, 16>(m_x.begin(), m_rk.begin(), i-1);
            CHAM_DecRound<1, 16>(m_x.begin(), m_rk.begin(), i-2);
            CHAM_DecRound<0, 16>(m_x.begin(), m_rk.begin(), i-3);
        }
        break;
    }
    default:
        CRYPTOPP_ASSERT(0);;
    }

    PutBlock<word32, BigEndian, false> oblock(xorBlock, outBlock);
    oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

NAMESPACE_END
