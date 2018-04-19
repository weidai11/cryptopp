// threefish.cpp - written and placed in the public domain by Jeffrey Walton
//                 Based on public domain code by Keru Kuro. Kuro's code is
//                 available at http://cppcrypto.sourceforge.net/.

#include "pch.h"
#include "config.h"

#include "threefish.h"
#include "misc.h"
#include "algparam.h"
#include "argnames.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlConstant;
using CryptoPP::rotrConstant;
using CryptoPP::rotlVariable;
using CryptoPP::rotrVariable;

template <unsigned int C0, unsigned int C1>
inline void G256(word64& G0, word64& G1, word64& G2, word64& G3)
{
    G0 += G1;
    G1 = rotlConstant<C0>(G1) ^ G0;
    G2 += G3;
    G3 = rotlConstant<C1>(G3) ^ G2;
}

template <unsigned int C0, unsigned int C1>
inline void IG256(word64& G0, word64& G1, word64& G2, word64& G3)
{
    G3 = rotrConstant<C1>(G3 ^ G2);
    G2 -= G3;
    G1 = rotrConstant<C0>(G1 ^ G0);
    G0 -= G1;
}

#define KS256(r) \
    G0 += m_rkey[(r + 1) % 5]; \
    G1 += m_rkey[(r + 2) % 5] + m_tweak[(r + 1) % 3]; \
    G2 += m_rkey[(r + 3) % 5] + m_tweak[(r + 2) % 3]; \
    G3 += m_rkey[(r + 4) % 5] + r + 1;

#define IKS256(r) \
    G0 -= m_rkey[(r + 1) % 5]; \
    G1 -= (m_rkey[(r + 2) % 5] + m_tweak[(r + 1) % 3]); \
    G2 -= (m_rkey[(r + 3) % 5] + m_tweak[(r + 2) % 3]); \
    G3 -= (m_rkey[(r + 4) % 5] + r + 1);

#define G256x8(r) \
    G256<14, 16>(G0, G1, G2, G3); \
    G256<52, 57>(G0, G3, G2, G1); \
    G256<23, 40>(G0, G1, G2, G3); \
    G256< 5, 37>(G0, G3, G2, G1); \
    KS256(r); \
    G256<25, 33>(G0, G1, G2, G3); \
    G256<46, 12>(G0, G3, G2, G1); \
    G256<58, 22>(G0, G1, G2, G3); \
    G256<32, 32>(G0, G3, G2, G1); \
    KS256(r + 1);

#define IG256x8(r) \
    IG256<32, 32>(G0, G3, G2, G1); \
    IG256<58, 22>(G0, G1, G2, G3); \
    IG256<46, 12>(G0, G3, G2, G1); \
    IG256<25, 33>(G0, G1, G2, G3); \
    IKS256(r); \
    IG256< 5, 37>(G0, G3, G2, G1); \
    IG256<23, 40>(G0, G1, G2, G3); \
    IG256<52, 57>(G0, G3, G2, G1); \
    IG256<14, 16>(G0, G1, G2, G3); \
    IKS256(r - 1);

///////////////////

template <unsigned int C0, unsigned int C1, unsigned int C2, unsigned int C3>
inline void G512(word64& G0, word64& G1, word64& G2, word64& G3, word64& G4, word64& G5, word64& G6, word64& G7)
{
    G0 += G1;
    G1 = rotlConstant<C0>(G1) ^ G0;
    G2 += G3;
    G3 = rotlConstant<C1>(G3) ^ G2;
    G4 += G5;
    G5 = rotlConstant<C2>(G5) ^ G4;
    G6 += G7;
    G7 = rotlConstant<C3>(G7) ^ G6;
}

template <unsigned int C0, unsigned int C1, unsigned int C2, unsigned int C3>
inline void IG512(word64& G0, word64& G1, word64& G2, word64& G3, word64& G4, word64& G5, word64& G6, word64& G7)
{
    G7 = rotrConstant<C3>(G7 ^ G6);
    G6 -= G7;
    G5 = rotrConstant<C2>(G5 ^ G4);
    G4 -= G5;
    G3 = rotrConstant<C1>(G3 ^ G2);
    G2 -= G3;
    G1 = rotrConstant<C0>(G1 ^ G0);
    G0 -= G1;
}

#define KS512(r) \
    G0 += m_rkey[(r + 1) % 9]; \
    G1 += m_rkey[(r + 2) % 9]; \
    G2 += m_rkey[(r + 3) % 9]; \
    G3 += m_rkey[(r + 4) % 9]; \
    G4 += m_rkey[(r + 5) % 9]; \
    G5 += m_rkey[(r + 6) % 9] + m_tweak[(r + 1) % 3]; \
    G6 += m_rkey[(r + 7) % 9] + m_tweak[(r + 2) % 3]; \
    G7 += m_rkey[(r + 8) % 9] + r + 1;

#define IKS512(r) \
    G0 -= m_rkey[(r + 1) % 9]; \
    G1 -= m_rkey[(r + 2) % 9]; \
    G2 -= m_rkey[(r + 3) % 9]; \
    G3 -= m_rkey[(r + 4) % 9]; \
    G4 -= m_rkey[(r + 5) % 9]; \
    G5 -= (m_rkey[(r + 6) % 9] + m_tweak[(r + 1) % 3]); \
    G6 -= (m_rkey[(r + 7) % 9] + m_tweak[(r + 2) % 3]); \
    G7 -= (m_rkey[(r + 8) % 9] + r + 1);

#define IG512x8(r) \
    IG512< 8, 35, 56, 22>(G6, G1, G0, G7, G2, G5, G4, G3); \
    IG512<25, 29, 39, 43>(G4, G1, G6, G3, G0, G5, G2, G7); \
    IG512<13, 50, 10, 17>(G2, G1, G4, G7, G6, G5, G0, G3); \
    IG512<39, 30, 34, 24>(G0, G1, G2, G3, G4, G5, G6, G7); \
    IKS512(r) \
    IG512<44,  9, 54, 56>(G6, G1, G0, G7, G2, G5, G4, G3); \
    IG512<17, 49, 36, 39>(G4, G1, G6, G3, G0, G5, G2, G7); \
    IG512<33, 27, 14, 42>(G2, G1, G4, G7, G6, G5, G0, G3); \
    IG512<46, 36, 19, 37>(G0, G1, G2, G3, G4, G5, G6, G7); \
    IKS512(r - 1)

#define G512x8(r) \
    G512<46, 36, 19, 37>(G0, G1, G2, G3, G4, G5, G6, G7); \
    G512<33, 27, 14, 42>(G2, G1, G4, G7, G6, G5, G0, G3); \
    G512<17, 49, 36, 39>(G4, G1, G6, G3, G0, G5, G2, G7); \
    G512<44,  9, 54, 56>(G6, G1, G0, G7, G2, G5, G4, G3); \
    KS512(r) \
    G512<39, 30, 34, 24>(G0, G1, G2, G3, G4, G5, G6, G7); \
    G512<13, 50, 10, 17>(G2, G1, G4, G7, G6, G5, G0, G3); \
    G512<25, 29, 39, 43>(G4, G1, G6, G3, G0, G5, G2, G7); \
    G512< 8, 35, 56, 22>(G6, G1, G0, G7, G2, G5, G4, G3); \
    KS512(r + 1)

///////////////////

template <unsigned int C0, unsigned int C1, unsigned int C2, unsigned int C3>
inline void G1024A(word64& G0, word64& G1, word64& G2, word64& G3,
        word64& G4, word64& G5, word64& G6, word64& G7)
{
    G0 += G1;
    G1 = rotlConstant<C0>(G1) ^ G0;
    G2 += G3;
    G3 = rotlConstant<C1>(G3) ^ G2;
    G4 += G5;
    G5 = rotlConstant<C2>(G5) ^ G4;
    G6 += G7;
    G7 = rotlConstant<C3>(G7) ^ G6;
}

template <unsigned int C4, unsigned int C5, unsigned int C6, unsigned int C7>
inline void G1024B(word64& G8, word64& G9, word64& G10, word64& G11,
        word64& G12, word64& G13, word64& G14, word64& G15)
{
    G8 += G9;
    G9 = rotlConstant<C4>(G9) ^ G8;
    G10 += G11;
    G11 = rotlConstant<C5>(G11) ^ G10;
    G12 += G13;
    G13 = rotlConstant<C6>(G13) ^ G12;
    G14 += G15;
    G15 = rotlConstant<C7>(G15) ^ G14;
}

template <unsigned int C0, unsigned int C1, unsigned int C2, unsigned int C3,
    unsigned int C4, unsigned int C5, unsigned int C6, unsigned int C7>
inline void G1024(word64& G0, word64& G1, word64& G2, word64& G3, word64& G4, word64& G5,
    word64& G6, word64& G7, word64& G8, word64& G9, word64& G10, word64& G11, word64& G12,
    word64& G13, word64& G14, word64& G15)
{
	// The extra gyrations promote inlining. Without it Threefish1024 looses 10 cpb.
	G1024A<C0, C1, C2, C3>(G0, G1,  G2,  G3,  G4,  G5,  G6,  G7);
	G1024B<C4, C5, C6, C7>(G8, G9, G10, G11, G12, G13, G14, G15);
}

template <unsigned int C4, unsigned int C5, unsigned int C6, unsigned int C7>
inline void IG1024A(word64& G8, word64& G9, word64& G10, word64& G11,
        word64& G12, word64& G13, word64& G14, word64& G15)
{
    G15 = rotrConstant<C7>(G15 ^ G14);
    G14 -= G15;
    G13 = rotrConstant<C6>(G13 ^ G12);
    G12 -= G13;
    G11 = rotrConstant<C5>(G11 ^ G10);
    G10 -= G11;
    G9 = rotrConstant<C4>(G9 ^ G8);
    G8 -= G9;
}

template <unsigned int C0, unsigned int C1, unsigned int C2, unsigned int C3>
inline void IG1024B(word64& G0, word64& G1, word64& G2, word64& G3,
        word64& G4, word64& G5, word64& G6, word64& G7)
{
    G7 = rotrConstant<C3>(G7 ^ G6);
    G6 -= G7;
    G5 = rotrConstant<C2>(G5 ^ G4);
    G4 -= G5;
    G3 = rotrConstant<C1>(G3 ^ G2);
    G2 -= G3;
    G1 = rotrConstant<C0>(G1 ^ G0);
    G0 -= G1;
}

template <unsigned int C0, unsigned int C1, unsigned int C2, unsigned int C3,
    unsigned int C4, unsigned int C5, unsigned int C6, unsigned int C7>
inline void IG1024(word64& G0, word64& G1, word64& G2, word64& G3, word64& G4, word64& G5,
    word64& G6, word64& G7, word64& G8, word64& G9, word64& G10, word64& G11, word64& G12,
    word64& G13, word64& G14, word64& G15)
{
	// The extra gyrations promote inlining. Without it Threefish1024 looses 10 cpb.
	IG1024A<C4, C5, C6, C7>(G8, G9, G10, G11, G12, G13, G14, G15);
	IG1024B<C0, C1, C2, C3>(G0, G1,  G2,  G3,  G4,  G5,  G6,  G7);
}

#define KS1024(r) \
    G0 += m_rkey[(r + 1) % 17]; \
    G1 += m_rkey[(r + 2) % 17]; \
    G2 += m_rkey[(r + 3) % 17]; \
    G3 += m_rkey[(r + 4) % 17]; \
    G4 += m_rkey[(r + 5) % 17]; \
    G5 += m_rkey[(r + 6) % 17]; \
    G6 += m_rkey[(r + 7) % 17]; \
    G7 += m_rkey[(r + 8) % 17]; \
    G8 += m_rkey[(r + 9) % 17]; \
    G9 += m_rkey[(r + 10) % 17]; \
    G10 += m_rkey[(r + 11) % 17]; \
    G11 += m_rkey[(r + 12) % 17]; \
    G12 += m_rkey[(r + 13) % 17]; \
    G13 += m_rkey[(r + 14) % 17] + m_tweak[(r + 1) % 3]; \
    G14 += m_rkey[(r + 15) % 17] + m_tweak[(r + 2) % 3]; \
    G15 += m_rkey[(r + 16) % 17] + r + 1;

#define IKS1024(r) \
    G0 -= m_rkey[(r + 1) % 17]; \
    G1 -= m_rkey[(r + 2) % 17]; \
    G2 -= m_rkey[(r + 3) % 17]; \
    G3 -= m_rkey[(r + 4) % 17]; \
    G4 -= m_rkey[(r + 5) % 17]; \
    G5 -= m_rkey[(r + 6) % 17]; \
    G6 -= m_rkey[(r + 7) % 17]; \
    G7 -= m_rkey[(r + 8) % 17]; \
    G8 -= m_rkey[(r + 9) % 17]; \
    G9 -= m_rkey[(r + 10) % 17]; \
    G10 -= m_rkey[(r + 11) % 17]; \
    G11 -= m_rkey[(r + 12) % 17]; \
    G12 -= m_rkey[(r + 13) % 17]; \
    G13 -= (m_rkey[(r + 14) % 17] + m_tweak[(r + 1) % 3]); \
    G14 -= (m_rkey[(r + 15) % 17] + m_tweak[(r + 2) % 3]); \
    G15 -= (m_rkey[(r + 16) % 17] + r + 1);

#define G1024x8(r) \
    G1024A<24, 13,  8, 47>(G0, G1, G2, G3, G4, G5, G6, G7); \
    G1024B< 8, 17, 22, 37>(G8, G9, G10, G11, G12, G13, G14, G15); \
    G1024A<38, 19, 10, 55>(G0, G9, G2, G13, G6, G11, G4, G15); \
    G1024B<49, 18, 23, 52>(G10, G7, G12, G3, G14, G5, G8, G1); \
    G1024A<33,  4, 51, 13>(G0, G7, G2, G5, G4, G3, G6, G1); \
    G1024B<34, 41, 59, 17>(G12, G15, G14, G13, G8, G11, G10, G9); \
    G1024A< 5, 20, 48, 41>(G0, G15, G2, G11, G6, G13, G4, G9); \
    G1024B<47, 28, 16, 25>(G14, G1, G8, G5, G10, G3, G12, G7); \
    KS1024(r); \
    G1024A<41,  9, 37, 31>(G0, G1, G2, G3, G4, G5, G6, G7); \
    G1024B<12, 47, 44, 30>(G8, G9, G10, G11, G12, G13, G14, G15); \
    G1024A<16, 34, 56, 51>(G0, G9, G2, G13, G6, G11, G4, G15); \
    G1024B< 4, 53, 42, 41>(G10, G7, G12, G3, G14, G5, G8, G1); \
    G1024A<31, 44, 47, 46>(G0, G7, G2, G5, G4, G3, G6, G1); \
    G1024B<19, 42, 44, 25>(G12, G15, G14, G13, G8, G11, G10, G9); \
    G1024A< 9, 48, 35, 52>(G0, G15, G2, G11, G6, G13, G4, G9); \
    G1024B<23, 31, 37, 20>(G14, G1, G8, G5, G10, G3, G12, G7); \
    KS1024(r + 1);

#define IG1024x8(r) \
    IG1024A< 9, 48, 35, 52>(G0, G15, G2, G11, G6, G13, G4, G9); \
    IG1024B<23, 31, 37, 20>(G14, G1, G8, G5, G10, G3, G12, G7); \
    IG1024A<31, 44, 47, 46>(G0, G7, G2, G5, G4, G3, G6, G1); \
    IG1024B<19, 42, 44, 25>(G12, G15, G14, G13, G8, G11, G10, G9); \
    IG1024A<16, 34, 56, 51>(G0, G9, G2, G13, G6, G11, G4, G15); \
    IG1024B< 4, 53, 42, 41>(G10, G7, G12, G3, G14, G5, G8, G1); \
    IG1024A<41,  9, 37, 31>(G0, G1, G2, G3, G4, G5, G6, G7); \
    IG1024B<12, 47, 44, 30>(G8, G9, G10, G11, G12, G13, G14, G15); \
    IKS1024(r); \
    IG1024A< 5, 20, 48, 41>(G0, G15, G2, G11, G6, G13, G4, G9); \
    IG1024B<47, 28, 16, 25>(G14, G1, G8, G5, G10, G3, G12, G7); \
    IG1024A<33,  4, 51, 13>(G0, G7, G2, G5, G4, G3, G6, G1); \
    IG1024B<34, 41, 59, 17>(G12, G15, G14, G13, G8, G11, G10, G9); \
    IG1024A<38, 19, 10, 55>(G0, G9, G2, G13, G6, G11, G4, G15); \
    IG1024B<49, 18, 23, 52>(G10, G7, G12, G3, G14, G5, G8, G1); \
    IG1024A<24, 13,  8, 47>(G0, G1, G2, G3, G4, G5, G6, G7); \
    IG1024B< 8, 17, 22, 37>(G8, G9, G10, G11, G12, G13, G14, G15); \
    IKS1024(r - 1);

ANONYMOUS_NAMESPACE_END

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

void Threefish256::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    // Blocksize is Keylength for Threefish
    CRYPTOPP_ASSERT(keyLength == KEYLENGTH);

    m_rkey.New(5);
    m_wspace.New(4);

    GetUserKey(LITTLE_ENDIAN_ORDER, m_rkey.begin(), 4, userKey, keyLength);
    m_rkey[4] = W64LIT(0x1BD11BDAA9FC1A22) ^ m_rkey[0] ^ m_rkey[1] ^ m_rkey[2] ^ m_rkey[3];

    SetTweak(params);
}

void Threefish256::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    word64 &G0=m_wspace[0], &G1=m_wspace[1], &G2=m_wspace[2], &G3=m_wspace[3];

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(G0)(G1)(G2)(G3);

    G0 += m_rkey[0]; G1 += m_rkey[1]; G2 += m_rkey[2];
    G3 += m_rkey[3]; G1 += m_tweak[0]; G2 += m_tweak[1];

    G256x8(0); G256x8(2); G256x8(4); G256x8(6); G256x8(8);
    G256x8(10); G256x8(12); G256x8(14); G256x8(16);

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(G0)(G1)(G2)(G3);
}

void Threefish256::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    word64 &G0=m_wspace[0], &G1=m_wspace[1], &G2=m_wspace[2], &G3=m_wspace[3];

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(G0)(G1)(G2)(G3);

    G0 -= m_rkey[3]; G1 -= m_rkey[4]; G2 -= m_rkey[0]; G3 -= m_rkey[1];
    G1 -= m_tweak[0]; G2 -= m_tweak[1]; G3 -= 18;

    IG256x8(16); IG256x8(14); IG256x8(12); IG256x8(10);
    IG256x8(8); IG256x8(6); IG256x8(4); IG256x8(2); IG256x8(0);

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(G0)(G1)(G2)(G3);
}

/////////////////////////////////////////////////////////////////

void Threefish512::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    // Blocksize is Keylength for Threefish
    CRYPTOPP_ASSERT(keyLength == KEYLENGTH);

    m_rkey.New(9);
    m_wspace.New(8);

    GetUserKey(LITTLE_ENDIAN_ORDER, m_rkey.begin(), 8, userKey, keyLength);
    m_rkey[8] = W64LIT(0x1BD11BDAA9FC1A22) ^ m_rkey[0] ^ m_rkey[1] ^ m_rkey[2] ^ m_rkey[3] ^
        m_rkey[4] ^ m_rkey[5] ^ m_rkey[6] ^ m_rkey[7];

    SetTweak(params);
}

void Threefish512::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    word64 &G0=m_wspace[0],   &G1=m_wspace[1],   &G2=m_wspace[2],   &G3=m_wspace[3];
    word64 &G4=m_wspace[4],   &G5=m_wspace[5],   &G6=m_wspace[6],   &G7=m_wspace[7];

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(G0)(G1)(G2)(G3)(G4)(G5)(G6)(G7);

    // 34 integer instructions total
    G0 += m_rkey[0]; G1 += m_rkey[1]; G2 += m_rkey[2]; G3 += m_rkey[3];
    G4 += m_rkey[4]; G5 += m_rkey[5]; G6 += m_rkey[6]; G7 += m_rkey[7];
    G5 += m_tweak[0]; G6 += m_tweak[1];

    G512x8(0); G512x8(2); G512x8(4); G512x8(6); G512x8(8);
    G512x8(10); G512x8(12); G512x8(14); G512x8(16);

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(G0)(G1)(G2)(G3)(G4)(G5)(G6)(G7);
}

void Threefish512::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    word64 &G0=m_wspace[0],   &G1=m_wspace[1],   &G2=m_wspace[2],   &G3=m_wspace[3];
    word64 &G4=m_wspace[4],   &G5=m_wspace[5],   &G6=m_wspace[6],   &G7=m_wspace[7];

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(G0)(G1)(G2)(G3)(G4)(G5)(G6)(G7);

    G0 -= m_rkey[0]; G1 -= m_rkey[1]; G2 -= m_rkey[2]; G3 -= m_rkey[3];
    G4 -= m_rkey[4]; G5 -= m_rkey[5]; G6 -= m_rkey[6]; G7 -= m_rkey[7];
    G5 -= m_tweak[0]; G6 -= m_tweak[1]; G7 -= 18;

    IG512x8(16); IG512x8(14); IG512x8(12); IG512x8(10);
    IG512x8(8); IG512x8(6); IG512x8(4); IG512x8(2); IG512x8(0);

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(G0)(G1)(G2)(G3)(G4)(G5)(G6)(G7);
}

/////////////////////////////////////////////////////////////////

void Threefish1024::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    // Blocksize is Keylength for Threefish
    CRYPTOPP_ASSERT(keyLength == KEYLENGTH);

    m_rkey.New(17);
    m_wspace.New(16);

    GetUserKey(LITTLE_ENDIAN_ORDER, m_rkey.begin(), 16, userKey, keyLength);
    m_rkey[16] = W64LIT(0x1BD11BDAA9FC1A22) ^ m_rkey[0] ^ m_rkey[1] ^ m_rkey[2] ^ m_rkey[3] ^ m_rkey[4] ^
        m_rkey[5] ^ m_rkey[6] ^ m_rkey[7] ^ m_rkey[8] ^ m_rkey[9] ^ m_rkey[10] ^ m_rkey[11] ^ m_rkey[12] ^
        m_rkey[13] ^ m_rkey[14] ^ m_rkey[15];

    SetTweak(params);
}

void Threefish1024::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    word64  &G0=m_wspace[0],   &G1=m_wspace[1],   &G2=m_wspace[2],   &G3=m_wspace[3];
    word64  &G4=m_wspace[4],   &G5=m_wspace[5],   &G6=m_wspace[6],   &G7=m_wspace[7];
    word64  &G8=m_wspace[8],   &G9=m_wspace[9],  &G10=m_wspace[10], &G11=m_wspace[11];
    word64 &G12=m_wspace[12], &G13=m_wspace[13], &G14=m_wspace[14], &G15=m_wspace[15];

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(G0)(G1)(G2)(G3)(G4)(G5)(G6)(G7)(G8)(G9)(G10)(G11)(G12)(G13)(G14)(G15);

    G0 += m_rkey[0]; G1 += m_rkey[1]; G2 += m_rkey[2]; G3 += m_rkey[3];
    G4 += m_rkey[4]; G5 += m_rkey[5]; G6 += m_rkey[6]; G7 += m_rkey[7];
    G8 += m_rkey[8]; G9 += m_rkey[9]; G10 += m_rkey[10]; G11 += m_rkey[11];
    G12 += m_rkey[12]; G13 += m_rkey[13]; G14 += m_rkey[14]; G15 += m_rkey[15];
    G13 += m_tweak[0]; G14 += m_tweak[1];

    G1024x8(0); G1024x8(2); G1024x8(4); G1024x8(6); G1024x8(8);
    G1024x8(10); G1024x8(12); G1024x8(14); G1024x8(16); G1024x8(18);

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(G0)(G1)(G2)(G3)(G4)(G5)(G6)(G7)(G8)(G9)(G10)(G11)(G12)(G13)(G14)(G15);
}

void Threefish1024::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    word64  &G0=m_wspace[0],   &G1=m_wspace[1],   &G2=m_wspace[2],   &G3=m_wspace[3];
    word64  &G4=m_wspace[4],   &G5=m_wspace[5],   &G6=m_wspace[6],   &G7=m_wspace[7];
    word64  &G8=m_wspace[8],   &G9=m_wspace[9],  &G10=m_wspace[10], &G11=m_wspace[11];
    word64 &G12=m_wspace[12], &G13=m_wspace[13], &G14=m_wspace[14], &G15=m_wspace[15];

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(G0)(G1)(G2)(G3)(G4)(G5)(G6)(G7)(G8)(G9)(G10)(G11)(G12)(G13)(G14)(G15);

    G0 -= m_rkey[3]; G1 -= m_rkey[4]; G2 -= m_rkey[5]; G3 -= m_rkey[6];
    G4 -= m_rkey[7]; G5 -= m_rkey[8]; G6 -= m_rkey[9]; G7 -= m_rkey[10];
    G8 -= m_rkey[11]; G9 -= m_rkey[12]; G10 -= m_rkey[13]; G11 -= m_rkey[14];
    G12 -= m_rkey[15]; G13 -= m_rkey[16]; G14 -= m_rkey[0]; G15 -= m_rkey[1];
    G13 -= m_tweak[2]; G14 -= m_tweak[0]; G15 -= 20;

    IG1024x8(18); IG1024x8(16); IG1024x8(14); IG1024x8(12); IG1024x8(10);
    IG1024x8(8); IG1024x8(6); IG1024x8(4); IG1024x8(2); IG1024x8(0);

    // Reverse bytes on BigEndian; align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(G0)(G1)(G2)(G3)(G4)(G5)(G6)(G7)(G8)(G9)(G10)(G11)(G12)(G13)(G14)(G15);
}

NAMESPACE_END
