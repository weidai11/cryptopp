// cham.cpp - written and placed in the public domain by Kim Sung Hee and Jeffrey Walton
//            Based on "CHAM: A Family of Lightweight Block Ciphers for
//            Resource-Constrained Devices" by Bonwook Koo, Dongyoung Roh,
//            Hyeonjin Kim, Younghoon Jung, Dong-Geon Lee, and Daesung Kwon

#include "pch.h"
#include "config.h"

#include "cham.h"
#include "misc.h"
#include "cpu.h"

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

/// \brief CHAM encryption round
/// \tparam RR the round number residue
/// \tparam KW the number of key words
/// \tparam T words type
/// \param x the state array
/// \param k the subkey table
/// \param i the round number
/// \details CHAM_EncRound applies the encryption round to the plain text.
///  RR is the "round residue" and it is used modulo 4. ProcessAndXorBlock
///  may provide a fully unrolled encryption transformation, or provide
///  a transformation that loops using multiples of 4 encryption rounds.
/// \details CHAM_EncRound calculates indexes into the x[] array based
///  on the round number residue. There is no need for the assignments
///  that shift values in preparations for the next round.
/// \details CHAM_EncRound depends on the round number. The actual round
///  being executed is passed through the parameter <tt>i</tt>. If
///  ProcessAndXorBlock fully unrolled the loop then the parameter
///  <tt>i</tt> would be unnecessary.
template <unsigned int RR, unsigned int KW, class T>
inline void CHAM_EncRound(T x[4], const T k[KW], unsigned int i)
{
    CRYPTOPP_CONSTANT(IDX0 = (RR+0) % 4);
    CRYPTOPP_CONSTANT(IDX1 = (RR+1) % 4);
    CRYPTOPP_CONSTANT(IDX3 = (RR+3+1) % 4);
    CRYPTOPP_CONSTANT(R1 = (RR % 2 == 0) ? 1 : 8);
    CRYPTOPP_CONSTANT(R2 = (RR % 2 == 0) ? 8 : 1);

    // Follows conventions in the ref impl
    const T kk = k[i % KW];
    const T aa = x[IDX0] ^ static_cast<T>(i);
    const T bb = rotlConstant<R1>(x[IDX1]) ^ kk;
    x[IDX3] = rotlConstant<R2>(static_cast<T>(aa + bb));
}

/// \brief CHAM decryption round
/// \tparam RR the round number residue
/// \tparam KW the number of key words
/// \tparam T words type
/// \param x the state array
/// \param k the subkey table
/// \param i the round number
/// \details CHAM_DecRound applies the decryption round to the cipher text.
///  RR is the "round residue" and it is used modulo 4. ProcessAndXorBlock
///  may provide a fully unrolled decryption transformation, or provide
///  a transformation that loops using multiples of 4 decryption rounds.
/// \details CHAM_DecRound calculates indexes into the x[] array based
///  on the round number residue. There is no need for the assignments
///  that shift values in preparations for the next round.
/// \details CHAM_DecRound depends on the round number. The actual round
///  being executed is passed through the parameter <tt>i</tt>. If
///  ProcessAndXorBlock fully unrolled the loop then the parameter
///  <tt>i</tt> would be unnecessary.
template <unsigned int RR, unsigned int KW, class T>
inline void CHAM_DecRound(T x[4], const T k[KW], unsigned int i)
{
    CRYPTOPP_CONSTANT(IDX0 = (RR+0) % 4);
    CRYPTOPP_CONSTANT(IDX1 = (RR+1) % 4);
    CRYPTOPP_CONSTANT(IDX3 = (RR+3+1) % 4);
    CRYPTOPP_CONSTANT(R1 = (RR % 2 == 0) ? 8 : 1);
    CRYPTOPP_CONSTANT(R2 = (RR % 2 == 0) ? 1 : 8);

    // Follows conventions in the ref impl
    const T kk = k[i % KW];
    const T aa = rotrConstant<R1>(x[IDX3]);
    const T bb = rotlConstant<R2>(x[IDX1]) ^ kk;
    x[IDX0] = static_cast<T>(aa - bb) ^ static_cast<T>(i);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if CRYPTOPP_CHAM_ADVANCED_PROCESS_BLOCKS
# if (CRYPTOPP_SSSE3_AVAILABLE)
extern size_t CHAM64_Enc_AdvancedProcessBlocks_SSSE3(const word16* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t CHAM64_Dec_AdvancedProcessBlocks_SSSE3(const word16* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t CHAM128_Enc_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t CHAM128_Dec_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
# endif  // CRYPTOPP_SSSE3_AVAILABLE
#endif  // CRYPTOPP_CHAM_ADVANCED_PROCESS_BLOCKS

std::string CHAM64::Base::AlgorithmProvider() const
{
#if (CRYPTOPP_CHAM_ADVANCED_PROCESS_BLOCKS)
# if defined(CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return "SSSE3";
# endif
#endif
    return "C++";
}

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
}

void CHAM64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word16, BigEndian> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    const int R = 80;
    for (int i = 0; i < R; i+=16)
    {
        CHAM_EncRound< 0, 16>(m_x.begin(), m_rk.begin(),  i+0);
        CHAM_EncRound< 1, 16>(m_x.begin(), m_rk.begin(),  i+1);
        CHAM_EncRound< 2, 16>(m_x.begin(), m_rk.begin(),  i+2);
        CHAM_EncRound< 3, 16>(m_x.begin(), m_rk.begin(),  i+3);
        CHAM_EncRound< 4, 16>(m_x.begin(), m_rk.begin(),  i+4);
        CHAM_EncRound< 5, 16>(m_x.begin(), m_rk.begin(),  i+5);
        CHAM_EncRound< 6, 16>(m_x.begin(), m_rk.begin(),  i+6);
        CHAM_EncRound< 7, 16>(m_x.begin(), m_rk.begin(),  i+7);
        CHAM_EncRound< 8, 16>(m_x.begin(), m_rk.begin(),  i+8);
        CHAM_EncRound< 9, 16>(m_x.begin(), m_rk.begin(),  i+9);
        CHAM_EncRound<10, 16>(m_x.begin(), m_rk.begin(), i+10);
        CHAM_EncRound<11, 16>(m_x.begin(), m_rk.begin(), i+11);
        CHAM_EncRound<12, 16>(m_x.begin(), m_rk.begin(), i+12);
        CHAM_EncRound<13, 16>(m_x.begin(), m_rk.begin(), i+13);
        CHAM_EncRound<14, 16>(m_x.begin(), m_rk.begin(), i+14);
        CHAM_EncRound<15, 16>(m_x.begin(), m_rk.begin(), i+15);
    }

    PutBlock<word16, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

void CHAM64::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word16, BigEndian> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    const int R = 80;
    for (int i = R-1; i >=0 ; i-=16)
    {
        CHAM_DecRound<15, 16>(m_x.begin(), m_rk.begin(),  i-0);
        CHAM_DecRound<14, 16>(m_x.begin(), m_rk.begin(),  i-1);
        CHAM_DecRound<13, 16>(m_x.begin(), m_rk.begin(),  i-2);
        CHAM_DecRound<12, 16>(m_x.begin(), m_rk.begin(),  i-3);
        CHAM_DecRound<11, 16>(m_x.begin(), m_rk.begin(),  i-4);
        CHAM_DecRound<10, 16>(m_x.begin(), m_rk.begin(),  i-5);
        CHAM_DecRound< 9, 16>(m_x.begin(), m_rk.begin(),  i-6);
        CHAM_DecRound< 8, 16>(m_x.begin(), m_rk.begin(),  i-7);
        CHAM_DecRound< 7, 16>(m_x.begin(), m_rk.begin(),  i-8);
        CHAM_DecRound< 6, 16>(m_x.begin(), m_rk.begin(),  i-9);
        CHAM_DecRound< 5, 16>(m_x.begin(), m_rk.begin(), i-10);
        CHAM_DecRound< 4, 16>(m_x.begin(), m_rk.begin(), i-11);
        CHAM_DecRound< 3, 16>(m_x.begin(), m_rk.begin(), i-12);
        CHAM_DecRound< 2, 16>(m_x.begin(), m_rk.begin(), i-13);
        CHAM_DecRound< 1, 16>(m_x.begin(), m_rk.begin(), i-14);
        CHAM_DecRound< 0, 16>(m_x.begin(), m_rk.begin(), i-15);
    }

    PutBlock<word16, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

std::string CHAM128::Base::AlgorithmProvider() const
{
#if defined(CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return "SSSE3";
#endif
    return "C++";
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
}

void CHAM128::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word32, BigEndian> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    switch (m_kw)
    {
    case 4:  // 128-bit key
    {
        const int R = 80;
        for (int i = 0; i < R; i+=8)
        {
            CHAM_EncRound<0, 8>(m_x.begin(), m_rk.begin(), i+0);
            CHAM_EncRound<1, 8>(m_x.begin(), m_rk.begin(), i+1);
            CHAM_EncRound<2, 8>(m_x.begin(), m_rk.begin(), i+2);
            CHAM_EncRound<3, 8>(m_x.begin(), m_rk.begin(), i+3);
            CHAM_EncRound<4, 8>(m_x.begin(), m_rk.begin(), i+4);
            CHAM_EncRound<5, 8>(m_x.begin(), m_rk.begin(), i+5);
            CHAM_EncRound<6, 8>(m_x.begin(), m_rk.begin(), i+6);
            CHAM_EncRound<7, 8>(m_x.begin(), m_rk.begin(), i+7);
        }
        break;
    }
    case 8:  // 256-bit key
    {
        const int R = 96;
        for (int i = 0; i < R; i+=16)
        {
            CHAM_EncRound< 0, 16>(m_x.begin(), m_rk.begin(),  i+0);
            CHAM_EncRound< 1, 16>(m_x.begin(), m_rk.begin(),  i+1);
            CHAM_EncRound< 2, 16>(m_x.begin(), m_rk.begin(),  i+2);
            CHAM_EncRound< 3, 16>(m_x.begin(), m_rk.begin(),  i+3);
            CHAM_EncRound< 4, 16>(m_x.begin(), m_rk.begin(),  i+4);
            CHAM_EncRound< 5, 16>(m_x.begin(), m_rk.begin(),  i+5);
            CHAM_EncRound< 6, 16>(m_x.begin(), m_rk.begin(),  i+6);
            CHAM_EncRound< 7, 16>(m_x.begin(), m_rk.begin(),  i+7);
            CHAM_EncRound< 8, 16>(m_x.begin(), m_rk.begin(),  i+8);
            CHAM_EncRound< 9, 16>(m_x.begin(), m_rk.begin(),  i+9);
            CHAM_EncRound<10, 16>(m_x.begin(), m_rk.begin(), i+10);
            CHAM_EncRound<11, 16>(m_x.begin(), m_rk.begin(), i+11);
            CHAM_EncRound<12, 16>(m_x.begin(), m_rk.begin(), i+12);
            CHAM_EncRound<13, 16>(m_x.begin(), m_rk.begin(), i+13);
            CHAM_EncRound<14, 16>(m_x.begin(), m_rk.begin(), i+14);
            CHAM_EncRound<15, 16>(m_x.begin(), m_rk.begin(), i+15);
        }
        break;
    }
    default:
        CRYPTOPP_ASSERT(0);
    }

    PutBlock<word32, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

void CHAM128::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word32, BigEndian> iblock(inBlock);
    iblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);

    switch (m_kw)
    {
    case 4:  // 128-bit key
    {
        const int R = 80;
        for (int i = R-1; i >= 0; i-=8)
        {
            CHAM_DecRound<7, 8>(m_x.begin(), m_rk.begin(), i-0);
            CHAM_DecRound<6, 8>(m_x.begin(), m_rk.begin(), i-1);
            CHAM_DecRound<5, 8>(m_x.begin(), m_rk.begin(), i-2);
            CHAM_DecRound<4, 8>(m_x.begin(), m_rk.begin(), i-3);
            CHAM_DecRound<3, 8>(m_x.begin(), m_rk.begin(), i-4);
            CHAM_DecRound<2, 8>(m_x.begin(), m_rk.begin(), i-5);
            CHAM_DecRound<1, 8>(m_x.begin(), m_rk.begin(), i-6);
            CHAM_DecRound<0, 8>(m_x.begin(), m_rk.begin(), i-7);
        }
        break;
    }
    case 8:  // 256-bit key
    {
        const int R = 96;
        for (int i = R-1; i >= 0; i-=16)
        {
            CHAM_DecRound<15, 16>(m_x.begin(), m_rk.begin(),  i-0);
            CHAM_DecRound<14, 16>(m_x.begin(), m_rk.begin(),  i-1);
            CHAM_DecRound<13, 16>(m_x.begin(), m_rk.begin(),  i-2);
            CHAM_DecRound<12, 16>(m_x.begin(), m_rk.begin(),  i-3);
            CHAM_DecRound<11, 16>(m_x.begin(), m_rk.begin(),  i-4);
            CHAM_DecRound<10, 16>(m_x.begin(), m_rk.begin(),  i-5);
            CHAM_DecRound< 9, 16>(m_x.begin(), m_rk.begin(),  i-6);
            CHAM_DecRound< 8, 16>(m_x.begin(), m_rk.begin(),  i-7);
            CHAM_DecRound< 7, 16>(m_x.begin(), m_rk.begin(),  i-8);
            CHAM_DecRound< 6, 16>(m_x.begin(), m_rk.begin(),  i-9);
            CHAM_DecRound< 5, 16>(m_x.begin(), m_rk.begin(), i-10);
            CHAM_DecRound< 4, 16>(m_x.begin(), m_rk.begin(), i-11);
            CHAM_DecRound< 3, 16>(m_x.begin(), m_rk.begin(), i-12);
            CHAM_DecRound< 2, 16>(m_x.begin(), m_rk.begin(), i-13);
            CHAM_DecRound< 1, 16>(m_x.begin(), m_rk.begin(), i-14);
            CHAM_DecRound< 0, 16>(m_x.begin(), m_rk.begin(), i-15);
        }
        break;
    }
    default:
        CRYPTOPP_ASSERT(0);
    }

    PutBlock<word32, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_x[0])(m_x[1])(m_x[2])(m_x[3]);
}

#if CRYPTOPP_CHAM_ADVANCED_PROCESS_BLOCKS
size_t CHAM64::Enc::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        return CHAM64_Enc_AdvancedProcessBlocks_SSSE3(m_rk, 80,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
# endif  // CRYPTOPP_SSSE3_AVAILABLE
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t CHAM64::Dec::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        return CHAM64_Dec_AdvancedProcessBlocks_SSSE3(m_rk, 80,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
# endif  // CRYPTOPP_SSSE3_AVAILABLE
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t CHAM128::Enc::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        const size_t rounds = (m_kw == 4 ? 80 : 96);
        return CHAM128_Enc_AdvancedProcessBlocks_SSSE3(m_rk, rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
# endif  // CRYPTOPP_SSSE3_AVAILABLE
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t CHAM128::Dec::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        const size_t rounds = (m_kw == 4 ? 80 : 96);
        return CHAM128_Dec_AdvancedProcessBlocks_SSSE3(m_rk, rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
# endif  // CRYPTOPP_SSSE3_AVAILABLE
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_CHAM_ADVANCED_PROCESS_BLOCKS

NAMESPACE_END
