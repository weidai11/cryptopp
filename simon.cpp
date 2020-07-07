// simon.h - written and placed in the public domain by Jeffrey Walton

#include "pch.h"
#include "config.h"

#include "simon.h"
#include "misc.h"
#include "cpu.h"

// Uncomment for benchmarking C++ against SSE or NEON.
// Do so in both simon.cpp and simon_simd.cpp.
// #undef CRYPTOPP_SSSE3_AVAILABLE
// #undef CRYPTOPP_SSE41_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlConstant;
using CryptoPP::rotrConstant;

/// \brief Round transformation helper
/// \tparam W word type
/// \param v value
template <class W>
inline W f(const W v)
{
    return (rotlConstant<1>(v) & rotlConstant<8>(v)) ^ rotlConstant<2>(v);
}

/// \brief Round transformation
/// \tparam W word type
/// \param x value
/// \param y value
/// \param k value
/// \param l value
template <class W>
inline void R2(W& x, W& y, const W k, const W l)
{
    y ^= f(x); y ^= k;
    x ^= f(y); x ^= l;
}

/// \brief Forward transformation
/// \tparam W word type
/// \tparam R number of rounds
/// \param c output array
/// \param p input array
/// \param k subkey array
template <class W, unsigned int R>
inline void SIMON_Encrypt(W c[2], const W p[2], const W k[R])
{
    c[0]=p[0]; c[1]=p[1];

    for (int i = 0; i < static_cast<int>(R-1); i += 2)
        R2(c[0], c[1], k[i], k[i + 1]);

    if (R & 1)
    {
        c[1] ^= f(c[0]); c[1] ^= k[R-1];
        W t = c[0]; c[0] = c[1]; c[1] = t;
    }
}

/// \brief Reverse transformation
/// \tparam W word type
/// \tparam R number of rounds
/// \param p output array
/// \param c input array
/// \param k subkey array
template <class W, unsigned int R>
inline void SIMON_Decrypt(W p[2], const W c[2], const W k[R])
{
    p[0]=c[0]; p[1]=c[1];
    unsigned int rounds = R;

    if (R & 1)
    {
        const W t = p[1]; p[1] = p[0]; p[0] = t;
        p[1] ^= k[R - 1]; p[1] ^= f(p[0]);
        rounds--;
    }

    for (int i = static_cast<int>(rounds - 2); i >= 0; i -= 2)
        R2(p[1], p[0], k[i + 1], k[i]);
}

/// \brief Subkey generation function
/// \details Used for SIMON-64 with 96-bit key and 42 rounds. A template was
///   not worthwhile because all instantiations would need specialization.
/// \param key empty subkey array
/// \param k user key array
inline void SIMON64_ExpandKey_3W(word32 key[42], const word32 k[3])
{
    const word32 c = 0xfffffffc;
    word64 z = W64LIT(0x7369f885192c0ef5);

    key[0] = k[2]; key[1] = k[1]; key[2] = k[0];
    for (size_t i = 3; i<42; ++i)
    {
        key[i] = static_cast<word32>(c ^ (z & 1) ^ key[i - 3] ^
            rotrConstant<3>(key[i - 1]) ^ rotrConstant<4>(key[i - 1]));
        z >>= 1;
    }
}

/// \brief Subkey generation function
/// \details Used for SIMON-64 with 128-bit key and 44 rounds. A template was
///   not worthwhile because all instantiations would need specialization.
/// \param key empty subkey array
/// \param k user key array
inline void SIMON64_ExpandKey_4W(word32 key[44], const word32 k[4])
{
    const word32 c = 0xfffffffc;
    word64 z = W64LIT(0xfc2ce51207a635db);

    key[0] = k[3]; key[1] = k[2]; key[2] = k[1]; key[3] = k[0];
    for (size_t i = 4; i<44; ++i)
    {
        key[i] = static_cast<word32>(c ^ (z & 1) ^ key[i - 4] ^
            rotrConstant<3>(key[i - 1]) ^ key[i - 3] ^ rotrConstant<4>(key[i - 1]) ^
            rotrConstant<1>(key[i - 3]));
        z >>= 1;
    }
}

/// \brief Subkey generation function
/// \details Used for SIMON-128 with 128-bit key and 68 rounds. A template was
///   not worthwhile because all instantiations would need specialization.
/// \param key empty subkey array
/// \param k user key array
inline void SIMON128_ExpandKey_2W(word64 key[68], const word64 k[2])
{
    const word64 c = W64LIT(0xfffffffffffffffc);
    word64 z = W64LIT(0x7369f885192c0ef5);

    key[0] = k[1]; key[1] = k[0];
    for (size_t i=2; i<66; ++i)
    {
        key[i] = c ^ (z & 1) ^ key[i - 2] ^ rotrConstant<3>(key[i - 1]) ^ rotrConstant<4>(key[i - 1]);
        z>>=1;
    }

    key[66] = c ^ 1 ^ key[64] ^ rotrConstant<3>(key[65]) ^ rotrConstant<4>(key[65]);
    key[67] = c^key[65] ^ rotrConstant<3>(key[66]) ^ rotrConstant<4>(key[66]);
}

/// \brief Subkey generation function
/// \details Used for SIMON-128 with 192-bit key and 69 rounds. A template was
///   not worthwhile because all instantiations would need specialization.
/// \param key empty subkey array
/// \param k user key array
inline void SIMON128_ExpandKey_3W(word64 key[69], const word64 k[3])
{
    const word64 c = W64LIT(0xfffffffffffffffc);
    word64 z = W64LIT(0xfc2ce51207a635db);

    key[0]=k[2]; key[1]=k[1]; key[2]=k[0];
    for (size_t i=3; i<67; ++i)
    {
        key[i] = c ^ (z & 1) ^ key[i - 3] ^ rotrConstant<3>(key[i - 1]) ^ rotrConstant<4>(key[i - 1]);
        z>>=1;
    }

    key[67] = c^key[64] ^ rotrConstant<3>(key[66]) ^ rotrConstant<4>(key[66]);
    key[68] = c ^ 1 ^ key[65] ^ rotrConstant<3>(key[67]) ^ rotrConstant<4>(key[67]);
}

/// \brief Subkey generation function
/// \details Used for SIMON-128 with 256-bit key and 72 rounds. A template was
///   not worthwhile because all instantiations would need specialization.
/// \param key empty subkey array
/// \param k user key array
inline void SIMON128_ExpandKey_4W(word64 key[72], const word64 k[4])
{
    const word64 c = W64LIT(0xfffffffffffffffc);
    word64 z = W64LIT(0xfdc94c3a046d678b);

    key[0]=k[3]; key[1]=k[2]; key[2]=k[1]; key[3]=k[0];
    for (size_t i=4; i<68; ++i)
    {
        key[i] = c ^ (z & 1) ^ key[i - 4] ^ rotrConstant<3>(key[i - 1]) ^ key[i - 3] ^ rotrConstant<4>(key[i - 1]) ^ rotrConstant<1>(key[i - 3]);
        z>>=1;
    }

    key[68] = c^key[64] ^ rotrConstant<3>(key[67]) ^ key[65] ^ rotrConstant<4>(key[67]) ^ rotrConstant<1>(key[65]);
    key[69] = c ^ 1 ^ key[65] ^ rotrConstant<3>(key[68]) ^ key[66] ^ rotrConstant<4>(key[68]) ^ rotrConstant<1>(key[66]);
    key[70] = c^key[66] ^ rotrConstant<3>(key[69]) ^ key[67] ^ rotrConstant<4>(key[69]) ^ rotrConstant<1>(key[67]);
    key[71] = c^key[67] ^ rotrConstant<3>(key[70]) ^ key[68] ^ rotrConstant<4>(key[70]) ^ rotrConstant<1>(key[68]);
}

ANONYMOUS_NAMESPACE_END

///////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
extern size_t SIMON128_Enc_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SIMON128_Dec_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
#endif

#if (CRYPTOPP_SSSE3_AVAILABLE)
extern size_t SIMON128_Enc_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SIMON128_Dec_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
#endif

#if (CRYPTOPP_ALTIVEC_AVAILABLE)
extern size_t SIMON128_Enc_AdvancedProcessBlocks_ALTIVEC(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SIMON128_Dec_AdvancedProcessBlocks_ALTIVEC(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
#endif

std::string SIMON64::Base::AlgorithmProvider() const
{
    return "C++";
}

unsigned int SIMON64::Base::OptimalDataAlignment() const
{
    return GetAlignmentOf<word32>();
}

void SIMON64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_ASSERT(keyLength == 12 || keyLength == 16);
    CRYPTOPP_UNUSED(params);

    // Building the key schedule table requires {3,4} words workspace.
    // Encrypting and decrypting requires 4 words workspace.
    m_kwords = keyLength/sizeof(word32);
    m_wspace.New(4U);

    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word32, LittleEndian> KeyBlock;
    KeyBlock kblk(userKey);

    switch (m_kwords)
    {
    case 3:
        m_rkeys.New((m_rounds = 42));
        kblk(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SIMON64_ExpandKey_3W(m_rkeys, m_wspace);
        break;
    case 4:
        m_rkeys.New((m_rounds = 44));
        kblk(m_wspace[3])(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SIMON64_ExpandKey_4W(m_rkeys, m_wspace);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }
}

void SIMON64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word32, LittleEndian> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[1])(m_wspace[0]);

    switch (m_rounds)
    {
    case 42:
        SIMON_Encrypt<word32, 42>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 44:
        SIMON_Encrypt<word32, 44>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

    // Do the endian gyrations from the paper and align pointers
    typedef PutBlock<word32, LittleEndian> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[3])(m_wspace[2]);
}

void SIMON64::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word32, LittleEndian> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[1])(m_wspace[0]);

    switch (m_rounds)
    {
    case 42:
        SIMON_Decrypt<word32, 42>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 44:
        SIMON_Decrypt<word32, 44>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

    // Do the endian gyrations from the paper and align pointers
    typedef PutBlock<word32, LittleEndian> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[3])(m_wspace[2]);
}

///////////////////////////////////////////////////////////

std::string SIMON128::Base::AlgorithmProvider() const
{
#if (CRYPTOPP_SIMON128_ADVANCED_PROCESS_BLOCKS)
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return "SSSE3";
# endif
# if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return "NEON";
# endif
# if (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return "Altivec";
# endif
#endif
    return "C++";
}

unsigned int SIMON128::Base::OptimalDataAlignment() const
{
#if (CRYPTOPP_SIMON128_ADVANCED_PROCESS_BLOCKS)
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return 16;  // load __m128i
# endif
# if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return 8;  // load uint64x2_t
# endif
# if (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return 16;  // load uint64x2_p
# endif
#endif
    return GetAlignmentOf<word64>();
}

void SIMON128::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_ASSERT(keyLength == 16 || keyLength == 24 || keyLength == 32);
    CRYPTOPP_UNUSED(params);

    // Building the key schedule table requires {2,3,4} words workspace.
    // Encrypting and decrypting requires 4 words workspace.
    m_kwords = keyLength/sizeof(word64);
    m_wspace.New(4U);

    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word64, LittleEndian> KeyBlock;
    KeyBlock kblk(userKey);

    switch (m_kwords)
    {
    case 2:
        m_rkeys.New((m_rounds = 68));
        kblk(m_wspace[1])(m_wspace[0]);
        SIMON128_ExpandKey_2W(m_rkeys, m_wspace);
        break;
    case 3:
        m_rkeys.New((m_rounds = 69));
        kblk(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SIMON128_ExpandKey_3W(m_rkeys, m_wspace);
        break;
    case 4:
        m_rkeys.New((m_rounds = 72));
        kblk(m_wspace[3])(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SIMON128_ExpandKey_4W(m_rkeys, m_wspace);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

#if CRYPTOPP_SIMON128_ADVANCED_PROCESS_BLOCKS

    // Pre-splat the round keys for Altivec forward transformation
#if CRYPTOPP_ALTIVEC_AVAILABLE
    if (IsForwardTransformation() && HasAltivec())
    {
        AlignedSecBlock presplat(m_rkeys.size()*2);
        for (size_t i=0, j=0; i<m_rkeys.size(); i++, j+=2)
            presplat[j+0] = presplat[j+1] = m_rkeys[i];
        m_rkeys.swap(presplat);
    }
#elif CRYPTOPP_SSSE3_AVAILABLE
    if (IsForwardTransformation() && HasSSSE3())
    {
        AlignedSecBlock presplat(m_rkeys.size()*2);
        for (size_t i=0, j=0; i<m_rkeys.size(); i++, j+=2)
            presplat[j+0] = presplat[j+1] = m_rkeys[i];
        m_rkeys.swap(presplat);
    }
#endif

#endif  // CRYPTOPP_SIMON128_ADVANCED_PROCESS_BLOCKS
}

void SIMON128::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word64, LittleEndian> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[1])(m_wspace[0]);

    switch (m_rounds)
    {
    case 68:
        SIMON_Encrypt<word64, 68>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 69:
        SIMON_Encrypt<word64, 69>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 72:
        SIMON_Encrypt<word64, 72>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

    // Do the endian gyrations from the paper and align pointers
    typedef PutBlock<word64, LittleEndian> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[3])(m_wspace[2]);
}

void SIMON128::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word64, LittleEndian> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[1])(m_wspace[0]);

    switch (m_rounds)
    {
    case 68:
        SIMON_Decrypt<word64, 68>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 69:
        SIMON_Decrypt<word64, 69>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 72:
        SIMON_Decrypt<word64, 72>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

    // Do the endian gyrations from the paper and align pointers
    typedef PutBlock<word64, LittleEndian> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[3])(m_wspace[2]);
}

#if (CRYPTOPP_SIMON128_ADVANCED_PROCESS_BLOCKS)
size_t SIMON128::Enc::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
#if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return SIMON128_Enc_AdvancedProcessBlocks_SSSE3(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return SIMON128_Enc_AdvancedProcessBlocks_NEON(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return SIMON128_Enc_AdvancedProcessBlocks_ALTIVEC(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SIMON128::Dec::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
#if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return SIMON128_Dec_AdvancedProcessBlocks_SSSE3(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return SIMON128_Dec_AdvancedProcessBlocks_NEON(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return SIMON128_Dec_AdvancedProcessBlocks_ALTIVEC(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_SIMON128_ADVANCED_PROCESS_BLOCKS

NAMESPACE_END
