// simeck.cpp - written and placed in the public domain by Kim Sung Hee and Jeffrey Walton
//              Based on "The Simeck Family of Lightweight Block Ciphers" by Gangqiang Yang,
//              Bo Zhu, Valentin Suder, Mark D. Aagaard, and Guang Gong

#include "pch.h"
#include "config.h"

#include "simeck.h"
#include "misc.h"
#include "cpu.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::rotlConstant;
using CryptoPP::rotrConstant;

/// \brief SIMECK encryption round
/// \tparam T word type
/// \param key the key for the round or iteration
/// \param left the first value
/// \param right the second value
/// \param temp a temporary workspace
/// \details SIMECK_Encryption serves as the key schedule, encryption and
///   decryption functions.
template <class T>
inline void SIMECK_Encryption(const T key, T& left, T& right, T& temp)
{
    temp = left;
    left = (left & rotlConstant<5>(left)) ^ rotlConstant<1>(left) ^ right ^ key;
    right = temp;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void SIMECK32::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    CRYPTOPP_UNUSED(keyLength);

    GetBlock<word16, BigEndian> kblock(userKey);
    kblock(m_t[3])(m_t[2])(m_t[1])(m_t[0]);

    word16 constant = 0xFFFC;
    word32 sequence = 0x9A42BB1F;
    for (unsigned int i = 0; i < ROUNDS; ++i)
    {
        m_rk[i] = m_t[0];

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;

        SIMECK_Encryption(static_cast<word16>(constant), m_t[1], m_t[0], m_t[4]);

        // rotate the LFSR of m_t
        m_t[4] = m_t[1];
        m_t[1] = m_t[2];
        m_t[2] = m_t[3];
        m_t[3] = m_t[4];
    }
}

void SIMECK32::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word16, BigEndian> iblock(inBlock);
    iblock(m_t[1])(m_t[0]);

    for (int idx = 0; idx < ROUNDS; ++idx)
        SIMECK_Encryption(m_rk[idx], m_t[1], m_t[0], m_t[4]);

    PutBlock<word16, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_t[1])(m_t[0]);
}

void SIMECK32::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word16, BigEndian> iblock(inBlock);
    iblock(m_t[0])(m_t[1]);

    for (int idx = ROUNDS - 1; idx >= 0; --idx)
        SIMECK_Encryption(m_rk[idx], m_t[1], m_t[0], m_t[4]);

    PutBlock<word16, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_t[0])(m_t[1]);
}

void SIMECK64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    CRYPTOPP_UNUSED(keyLength);

    GetBlock<word32, BigEndian> kblock(userKey);
    kblock(m_t[3])(m_t[2])(m_t[1])(m_t[0]);

    word64 constant = W64LIT(0xFFFFFFFC);
    word64 sequence = W64LIT(0x938BCA3083F);
    for (unsigned int i = 0; i < ROUNDS; ++i)
    {
        m_rk[i] = m_t[0];

        constant &= W64LIT(0xFFFFFFFC);
        constant |= sequence & 1;
        sequence >>= 1;

        SIMECK_Encryption(static_cast<word32>(constant), m_t[1], m_t[0], m_t[4]);

        // rotate the LFSR of m_t
        m_t[4] = m_t[1];
        m_t[1] = m_t[2];
        m_t[2] = m_t[3];
        m_t[3] = m_t[4];
    }
}

void SIMECK64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word32, BigEndian> iblock(inBlock);
    iblock(m_t[1])(m_t[0]);

    for (int idx = 0; idx < ROUNDS; ++idx)
        SIMECK_Encryption(m_rk[idx], m_t[1], m_t[0], m_t[4]);

    PutBlock<word32, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_t[1])(m_t[0]);
}

void SIMECK64::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word32, BigEndian> iblock(inBlock);
    iblock(m_t[0])(m_t[1]);

    for (int idx = ROUNDS - 1; idx >= 0; --idx)
        SIMECK_Encryption(m_rk[idx], m_t[1], m_t[0], m_t[4]);

    PutBlock<word32, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_t[0])(m_t[1]);
}

NAMESPACE_END
