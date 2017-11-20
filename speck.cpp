// speck.h - written and placed in the public domain by Jeffrey Walton

#include "pch.h"
#include "config.h"

#include "speck.h"
#include "misc.h"

// TODO
#include <iostream>

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlFixed;
using CryptoPP::rotrFixed;
using CryptoPP::rotlVariable;
using CryptoPP::rotrVariable;

//! \brief Forward round transformation
//! \tparam W word type
template <class W>
inline void TF83(W& x, W& y, const W& k)
{
    x = rotrFixed(x, 8);
    x += y; x ^= k;
    y = rotlFixed(y, 3);
    y ^= x;
}

//! \brief Reverse round transformation
//! \tparam W word type
template <class W>
inline void TR83(W& x, W& y, const W& k)
{
    y^=x;
    y=rotrFixed(y,3);
    x^=k; x-=y;
    x=rotlFixed(x,8);
}

//! \brief Forward transformation
//! \tparam W word type
//! \tparam R number of rounds
//! \param c output array
//! \param p input array
//! \param k subkey array
template <class W, unsigned int R>
inline void SPECK_Encrypt(W c[2], const W p[2], const W k[R])
{
    c[0]=p[0]; c[1]=p[1];

    // Don't unroll this loop. Things slow down.
    for(W i=0; static_cast<int>(i)<R; ++i)
        TF83(c[0], c[1], k[i]);
}

//! \brief Reverse transformation
//! \tparam W word type
//! \tparam R number of rounds
//! \param p output array
//! \param c input array
//! \param k subkey array
template <class W, unsigned int R>
inline void SPECK_Decrypt(W p[2], const W c[2], const W k[R])
{
    p[0]=c[0]; p[1]=c[1];

    // Don't unroll this loop. Things slow down.
    for(W i=R-1; static_cast<int>(i)>=0; --i)
        TR83(p[0], p[1], k[i]);
}

//! \brief Subkey generation function
//! \details Used when the user key consists of 2 words
//! \tparam W word type
//! \tparam R number of rounds
//! \param key empty subkey array
//! \param k user key array
template <class W, unsigned int R>
inline void SPECK_RoundKeys_2W(W key[R], const W k[2])
{
    CRYPTOPP_ASSERT(R==32);
    W i=0, B=k[1], A=k[0];

    while(i<R-1)
    {
        key[i]=A; TF83(B, A, i);
        i++;
    }
    key[R-1]=A;
}

//! \brief Subkey generation function
//! \details Used when the user key consists of 3 words
//! \tparam W word type
//! \tparam R number of rounds
//! \param key empty subkey array
//! \param k user key array
template <class W, unsigned int R>
inline void SPECK_RoundKeys_3W(W key[R], const W k[3])
{
    CRYPTOPP_ASSERT(R==33 || R==26);
    W i=0, C=k[2], B=k[1], A=k[0];

    unsigned int blocks = R/2;
    while(blocks--)
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

//! \brief Subkey generation function
//! \details Used when the user key consists of 4 words
//! \tparam W word type
//! \tparam R number of rounds
//! \param key empty subkey array
//! \param k user key array
template <class W, unsigned int R>
inline void SPECK_RoundKeys_4W(W key[R], const W k[4])
{
    CRYPTOPP_ASSERT(R==34 || R==27);
    W i=0, D=k[3], C=k[2], B=k[1], A=k[0];

    unsigned int blocks = R/3;
    while(blocks--)
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

NAMESPACE_BEGIN(CryptoPP)

void SPECK64::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_ASSERT(keyLength == 12 || keyLength == 16);

    // Building the key schedule table requires {3,4} words workspace.
    // Encrypting and decrypting requires 4 words workspace.
    m_kwords = keyLength/sizeof(word32);
    m_wspace.New(STDMAX(m_kwords,4U));

    // Avoid GetUserKey. SPECK does unusual things with key string and word ordering
    // {A,B} -> {B,A}, {A,B,C} -> {C,B,A}, etc.
    typedef GetBlock<word32, BigEndian, false> InBlock;
    InBlock iblk(userKey);

    switch (m_kwords)
    {
    case 3:
        m_rkey.New(26);
        iblk(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SPECK_RoundKeys_3W<word32, 26>(m_rkey, m_wspace);
        break;
    case 4:
        m_rkey.New(27);
        iblk(m_wspace[3])(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SPECK_RoundKeys_4W<word32, 27>(m_rkey, m_wspace);
        break;
    default:
        CRYPTOPP_ASSERT(0);;
    }
}

void SPECK64::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Reverse bytes on LittleEndian; align pointer on BigEndian
    typedef GetBlock<word32, BigEndian, false> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[0])(m_wspace[1]);

    switch (m_kwords)
    {
    case 3:
        SPECK_Encrypt<word32, 26>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    case 4:
        SPECK_Encrypt<word32, 27>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    default:
        CRYPTOPP_ASSERT(0);;
    }

    // Reverse bytes on LittleEndian; align pointer on BigEndian
    typedef PutBlock<word32, BigEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[2])(m_wspace[3]);
}

void SPECK64::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Reverse bytes on LittleEndian; align pointer on BigEndian
    typedef GetBlock<word32, BigEndian, false> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[0])(m_wspace[1]);

    switch (m_kwords)
    {
    case 3:
        SPECK_Decrypt<word32, 26>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    case 4:
        SPECK_Decrypt<word32, 27>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    default:
        CRYPTOPP_ASSERT(0);;
    }

    // Reverse bytes on LittleEndian; align pointer on BigEndian
    typedef PutBlock<word32, BigEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[2])(m_wspace[3]);
}

///////////////////////////////////////////////////////////

void SPECK128::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_ASSERT(keyLength == 16 || keyLength == 24 || keyLength == 32);

    // Building the key schedule table requires {2,3,4} words workspace.
    // Encrypting and decrypting requires 4 words workspace.
    m_kwords = keyLength/sizeof(word64);
    m_wspace.New(STDMAX(m_kwords,4U));

    // Avoid GetUserKey. SPECK does unusual things with key string and word ordering
    // {A,B} -> {B,A}, {A,B,C} -> {C,B,A}, etc.
    typedef GetBlock<word64, BigEndian, false> InBlock;
    InBlock iblk(userKey);

    switch (m_kwords)
    {
    case 2:
        m_rkey.New(32);
        iblk(m_wspace[1])(m_wspace[0]);
        SPECK_RoundKeys_2W<word64, 32>(m_rkey, m_wspace);
        break;
    case 3:
        m_rkey.New(33);
        iblk(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SPECK_RoundKeys_3W<word64, 33>(m_rkey, m_wspace);
        break;
    case 4:
        m_rkey.New(34);
        iblk(m_wspace[3])(m_wspace[2])(m_wspace[1])(m_wspace[0]);
        SPECK_RoundKeys_4W<word64, 34>(m_rkey, m_wspace);
        break;
    default:
        CRYPTOPP_ASSERT(0);;
    }
}

void SPECK128::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Reverse bytes on LittleEndian; align pointer on BigEndian
    typedef GetBlock<word64, BigEndian, false> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[0])(m_wspace[1]);

    switch (m_kwords)
    {
    case 2:
        SPECK_Encrypt<word64, 32>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    case 3:
        SPECK_Encrypt<word64, 33>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    case 4:
        SPECK_Encrypt<word64, 34>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    default:
        CRYPTOPP_ASSERT(0);;
    }

    // Reverse bytes on LittleEndian; align pointer on BigEndian
    typedef PutBlock<word64, BigEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[2])(m_wspace[3]);
}

void SPECK128::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Reverse bytes on LittleEndian; align pointer on BigEndian
    typedef GetBlock<word64, BigEndian, false> InBlock;
    InBlock iblk(inBlock); iblk(m_wspace[0])(m_wspace[1]);

    switch (m_kwords)
    {
    case 2:
        SPECK_Decrypt<word64, 32>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    case 3:
        SPECK_Decrypt<word64, 33>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    case 4:
        SPECK_Decrypt<word64, 34>(m_wspace+2, m_wspace+0, m_rkey);
        break;
    default:
        CRYPTOPP_ASSERT(0);;
    }

    // Reverse bytes on LittleEndian; align pointer on BigEndian
    typedef PutBlock<word64, BigEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock); oblk(m_wspace[2])(m_wspace[3]);
}

NAMESPACE_END
