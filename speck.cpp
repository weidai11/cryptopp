// speck.cpp - written and placed in the public domain by Jeffrey Walton

#include "pch.h"
#include "config.h"

#include "speck.h"
#include "misc.h"
#include "cpu.h"

// Uncomment for benchmarking C++ against SSE or NEON.
// Do so in both speck.cpp and speck_simd.cpp.
// #undef CRYPTOPP_SSSE3_AVAILABLE
// #undef CRYPTOPP_SSE41_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlConstant;
using CryptoPP::rotrConstant;

/// \brief Forward round transformation
/// \tparam W word type
/// \details TF83() is the forward round transformation using a=8 and b=3 rotations.
///   The initial test implementation provided template parameters, but they were
///   removed because SPECK32 using a=7 and b=2 was not on the road map. The
///   additional template parameters also made calling SPECK_Encrypt and SPECK_Decrypt
///   kind of messy.
template <class W>
inline void TF83(W& x, W& y, const W k)
{
    x = rotrConstant<8>(x);
    x += y; x ^= k;
    y = rotlConstant<3>(y);
    y ^= x;
}

/// \brief Reverse round transformation
/// \tparam W word type
/// \details TR83() is the reverse round transformation using a=8 and b=3 rotations.
///   The initial test implementation provided template parameters, but they were
///   removed because SPECK32 using a=7 and b=2 was not on the road map. The
///   additional template parameters also made calling SPECK_Encrypt and SPECK_Decrypt
///   kind of messy.
template <class W>
inline void TR83(W& x, W& y, const W k)
{
    y ^= x;
    y = rotrConstant<3>(y);
    x ^= k; x -= y;
    x = rotlConstant<8>(x);
}

/// \brief Forward transformation
/// \tparam W word type
/// \tparam R number of rounds
/// \param c output array
/// \param p input array
/// \param k subkey array
template <class W, unsigned int R>
inline void SPECK_Encrypt(W c[2], const W p[2], const W k[R])
{
    c[0]=p[0]; c[1]=p[1];

    // Don't unroll this loop. Things slow down.
    for (int i = 0; i < static_cast<int>(R); ++i)
        TF83(c[0], c[1], k[i]);
}

/// \brief Reverse transformation
/// \tparam W word type
/// \tparam R number of rounds
/// \param p output array
/// \param c input array
/// \param k subkey array
template <class W, unsigned int R>
inline void SPECK_Decrypt(W p[2], const W c[2], const W k[R])
{
    p[0]=c[0]; p[1]=c[1];

    // Don't unroll this loop. Things slow down.
    for (int i = static_cast<int>(R-1); i >= 0; --i)
        TR83(p[0], p[1], k[i]);
}

/// \brief Subkey generation function
/// \details Used when the user key consists of 2 words
/// \tparam W word type
/// \tparam R number of rounds
/// \param key empty subkey array
/// \param k user key array
template <class W, unsigned int R>
inline void SPECK_ExpandKey_2W(W key[R], const W k[2])
{
    CRYPTOPP_ASSERT(R==32);
    W i=0, B=k[0], A=k[1];

    while (i<R-1)
    {
        key[i]=A; TF83(B, A, i);
        i++;
    }
    key[R-1]=A;
}

/// \brief Subkey generation function
/// \details Used when the user key consists of 3 words
/// \tparam W word type
/// \tparam R number of rounds
/// \param key empty subkey array
/// \param k user key array
template <class W, unsigned int R>
inline void SPECK_ExpandKey_3W(W key[R], const W k[3])
{
    CRYPTOPP_ASSERT(R==33 || R==26);
    W i=0, C=k[0], B=k[1], A=k[2];

    unsigned int blocks = R/2;
    while (blocks--)
    {
        key[i+0]=A; TF83(B, A, i+0);
        key[i+1]=A; TF83(C, A, i+1);
        i+=2;
    }

    // The constexpr residue should allow the optimizer to remove unneeded statements
    if(R%2 == 1)
    {
        key[R-1]=A;
    }
}

/// \brief Subkey generation function
/// \details Used when the user key consists of 4 words
/// \tparam W word type
/// \tparam R number of rounds
/// \param key empty subkey array
/// \param k user key array
template <class W, unsigned int R>
inline void SPECK_ExpandKey_4W(W key[R], const W k[4])
{
    CRYPTOPP_ASSERT(R==34 || R==27);
    W i=0, D=k[0], C=k[1], B=k[2], A=k[3];

    unsigned int blocks = R/3;
    while (blocks--)
    {
        key[i+0]=A; TF83(B, A, i+0);
        key[i+1]=A; TF83(C, A, i+1);
        key[i+2]=A; TF83(D, A, i+2);
        i+=3;
    }

    // The constexpr residue should allow the optimizer to remove unneeded statements
    if(R%3 == 1)
    {
        key[R-1]=A;
    }
    else if(R%3 == 2)
    {
        key[R-2]=A; TF83(B, A, W(R-2));
        key[R-1]=A;
    }
}

ANONYMOUS_NAMESPACE_END

///////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
extern size_t SPECK128_Enc_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SPECK128_Dec_AdvancedProcessBlocks_NEON(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
#endif

#if (CRYPTOPP_SSE41_AVAILABLE)
extern size_t SPECK64_Enc_AdvancedProcessBlocks_SSE41(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SPECK64_Dec_AdvancedProcessBlocks_SSE41(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
#endif

#if (CRYPTOPP_SSSE3_AVAILABLE)
extern size_t SPECK128_Enc_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SPECK128_Dec_AdvancedProcessBlocks_SSSE3(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
#endif

#if (CRYPTOPP_ALTIVEC_AVAILABLE)
extern size_t SPECK128_Enc_AdvancedProcessBlocks_ALTIVEC(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t SPECK128_Dec_AdvancedProcessBlocks_ALTIVEC(const word64* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
#endif

std::string SPECK64::Base::AlgorithmProvider() const
{
    return "C++";
}

unsigned int SPECK64::Base::OptimalDataAlignment() const
{
    return GetAlignmentOf<word32>();
}

void SPECK64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
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
        m_rkeys.New((m_rounds = 26));
        kblk(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SPECK_ExpandKey_3W<word32, 26>(m_rkeys, m_wspace);
        break;
    case 4:
        m_rkeys.New((m_rounds = 27));
        kblk(m_wspace[3])(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SPECK_ExpandKey_4W<word32, 27>(m_rkeys, m_wspace);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }
}

void SPECK64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word32, LittleEndian> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[1])(m_wspace[0]);

    switch (m_rounds)
    {
    case 26:
        SPECK_Encrypt<word32, 26>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 27:
        SPECK_Encrypt<word32, 27>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

    // Do the endian gyrations from the paper and align pointers
    typedef PutBlock<word32, LittleEndian> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[3])(m_wspace[2]);
}

void SPECK64::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word32, LittleEndian> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[1])(m_wspace[0]);

    switch (m_rounds)
    {
    case 26:
        SPECK_Decrypt<word32, 26>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 27:
        SPECK_Decrypt<word32, 27>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

    // Do the endian gyrations from the paper and align pointers
    typedef PutBlock<word32, LittleEndian> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[3])(m_wspace[2]);
}

///////////////////////////////////////////////////////////

std::string SPECK128::Base::AlgorithmProvider() const
{
#if (CRYPTOPP_SPECK128_ADVANCED_PROCESS_BLOCKS)
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

unsigned int SPECK128::Base::OptimalDataAlignment() const
{
#if (CRYPTOPP_SPECK128_ADVANCED_PROCESS_BLOCKS)
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

void SPECK128::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
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
        m_rkeys.New((m_rounds = 32));
        kblk(m_wspace[1])(m_wspace[0]);
        SPECK_ExpandKey_2W<word64, 32>(m_rkeys, m_wspace);
        break;
    case 3:
        m_rkeys.New((m_rounds = 33));
        kblk(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SPECK_ExpandKey_3W<word64, 33>(m_rkeys, m_wspace);
        break;
    case 4:
        m_rkeys.New((m_rounds = 34));
        kblk(m_wspace[3])(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SPECK_ExpandKey_4W<word64, 34>(m_rkeys, m_wspace);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

#if CRYPTOPP_SPECK128_ADVANCED_PROCESS_BLOCKS

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

#endif  // CRYPTOPP_SPECK128_ADVANCED_PROCESS_BLOCKS
}

void SPECK128::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word64, LittleEndian> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[1])(m_wspace[0]);

    switch (m_rounds)
    {
    case 32:
        SPECK_Encrypt<word64, 32>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 33:
        SPECK_Encrypt<word64, 33>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 34:
        SPECK_Encrypt<word64, 34>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

    // Do the endian gyrations from the paper and align pointers
    typedef PutBlock<word64, LittleEndian> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[3])(m_wspace[2]);
}

void SPECK128::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do the endian gyrations from the paper and align pointers
    typedef GetBlock<word64, LittleEndian> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[1])(m_wspace[0]);

    switch (m_rounds)
    {
    case 32:
        SPECK_Decrypt<word64, 32>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 33:
        SPECK_Decrypt<word64, 33>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    case 34:
        SPECK_Decrypt<word64, 34>(m_wspace+2, m_wspace+0, m_rkeys);
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }

    // Do the endian gyrations from the paper and align pointers
    typedef PutBlock<word64, LittleEndian> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[3])(m_wspace[2]);
}

#if (CRYPTOPP_SPECK128_ADVANCED_PROCESS_BLOCKS)
size_t SPECK128::Enc::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
#if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return SPECK128_Enc_AdvancedProcessBlocks_SSSE3(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return SPECK128_Enc_AdvancedProcessBlocks_NEON(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return SPECK128_Enc_AdvancedProcessBlocks_ALTIVEC(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t SPECK128::Dec::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
#if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return SPECK128_Dec_AdvancedProcessBlocks_SSSE3(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return SPECK128_Dec_AdvancedProcessBlocks_NEON(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return SPECK128_Dec_AdvancedProcessBlocks_ALTIVEC(m_rkeys, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_SPECK128_ADVANCED_PROCESS_BLOCKS

NAMESPACE_END
