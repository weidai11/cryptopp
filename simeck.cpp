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
template <class T>
inline void SIMECK_Encryption(const T key, T& left, T& right, T& temp)
{
    temp = left;
    left = (left & rotlConstant<5>(left)) ^ rotlConstant<1>(left) ^ right ^ key;
    right = temp;
}

/// \brief SIMECK decryption round
template <class T>
inline void SIMECK_Decryption(const T key, T& left, T& right, T& temp)
{
    temp = left;
    left = (left & rotlConstant<5>(left)) ^ rotlConstant<1>(left) ^ right ^ key;
    right = temp;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if CRYPTOPP_SIMECK_ADVANCED_PROCESS_BLOCKS
# if (CRYPTOPP_SSSE3_AVAILABLE)
extern size_t SIMECK32_Enc_AdvancedProcessBlocks_SSSE3(const word16* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SIMECK32_Dec_AdvancedProcessBlocks_SSSE3(const word16* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SIMECK64_Enc_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SIMECK64_Dec_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
# endif  // CRYPTOPP_SSSE3_AVAILABLE
#endif  // CRYPTOPP_SIMECK_ADVANCED_PROCESS_BLOCKS

void SIMECK32::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    CRYPTOPP_UNUSED(keyLength);

    GetBlock<word16, BigEndian> kblock(userKey);
    kblock(m_mk[3])(m_mk[2])(m_mk[1])(m_mk[0]);
}

#define temp m_t[2]

#define LROT16(x, r) (((x) << (r)) | ((x) >> (16 - (r))))

#define ROUND32(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT16((lft), 5)) ^ LROT16((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

void SIMECK32::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word16, BigEndian> iblock(inBlock);
    iblock(m_t[1])(m_t[0]);

    m_rk[0] = m_mk[0], m_rk[1] = m_mk[1];
    m_rk[2] = m_mk[2], m_rk[3] = m_mk[3];

    word16 constant = 0xFFFC;
    word32 sequence = 0x9A42BB1F;

    CRYPTOPP_CONSTANT(NUM_ROUNDS = 32);
    for (int idx = 0; idx < NUM_ROUNDS; ++idx)
    {
        SIMECK_Encryption(m_rk[0], m_t[1], m_t[0], temp);

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;

        SIMECK_Encryption(constant, m_rk[1], m_rk[0], temp);

        // rotate the LFSR of m_rk
        temp = m_rk[1];
        m_rk[1] = m_rk[2];
        m_rk[2] = m_rk[3];
        m_rk[3] = temp;
    }

    PutBlock<word16, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_t[1])(m_t[0]);
}

void SIMECK32::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word16, BigEndian> iblock(inBlock);
    iblock(m_t[1])(m_t[0]);

    // TODO

    PutBlock<word16, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_t[1])(m_t[0]);
}

void SIMECK64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    CRYPTOPP_UNUSED(keyLength);

    GetBlock<word32, BigEndian> kblock(userKey);
    kblock(m_mk[3])(m_mk[2])(m_mk[1])(m_mk[0]);
}

#define LROT32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

#define ROUND64(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT32((lft), 5)) ^ LROT32((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

void SIMECK64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word32, BigEndian> iblock(inBlock);
    iblock(m_t[1])(m_t[0]);

    m_rk[0] = m_mk[0], m_rk[1] = m_mk[1];
    m_rk[2] = m_mk[2], m_rk[3] = m_mk[3];

    word32 constant = 0xFFFFFFFC;
    word64 sequence = W64LIT(0x938BCA3083F);

    CRYPTOPP_CONSTANT(NUM_ROUNDS = 44);
    for (int idx = 0; idx < NUM_ROUNDS; ++idx)
    {
        SIMECK_Encryption(m_rk[0], m_t[1], m_t[0], temp);

        constant &= 0xFFFFFFFC;
        constant |= sequence & 1;
        sequence >>= 1;

        SIMECK_Encryption(constant, m_rk[1], m_rk[0], temp);

        // rotate the LFSR of m_rk
        temp = m_rk[1];
        m_rk[1] = m_rk[2];
        m_rk[2] = m_rk[3];
        m_rk[3] = temp;
    }

    PutBlock<word32, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_t[1])(m_t[0]);
}

void SIMECK64::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word32, BigEndian> iblock(inBlock);
    iblock(m_t[1])(m_t[0]);

    // TODO

    PutBlock<word32, BigEndian> oblock(xorBlock, outBlock);
    oblock(m_t[1])(m_t[0]);
}

#if CRYPTOPP_SIMECK_ADVANCED_PROCESS_BLOCKS
size_t SIMECK32::Enc::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        return SIMECK32_Enc_AdvancedProcessBlocks_SSSE3(m_rk, 80,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
# endif  // CRYPTOPP_SSSE3_AVAILABLE
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SIMECK32::Dec::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        return SIMECK32_Dec_AdvancedProcessBlocks_SSSE3(m_rk, 80,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
# endif  // CRYPTOPP_SSSE3_AVAILABLE
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SIMECK64::Enc::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        const size_t rounds = (m_kw == 4 ? 80 : 96);
        return SIMECK64_Enc_AdvancedProcessBlocks_SSSE3(m_rk, rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
# endif  // CRYPTOPP_SSSE3_AVAILABLE
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SIMECK64::Dec::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        const size_t rounds = (m_kw == 4 ? 80 : 96);
        return SIMECK64_Dec_AdvancedProcessBlocks_SSSE3(m_rk, rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
# endif  // CRYPTOPP_SSSE3_AVAILABLE
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_SIMECK_ADVANCED_PROCESS_BLOCKS

NAMESPACE_END
