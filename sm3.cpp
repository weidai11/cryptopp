// sm3.cpp - written and placed in the public domain by Jeffrey Walton and Han Lulu
//           Based on the specification provided by Sean Shen and Xiaodong Lee.
//           Based on code by Krzysztof Kwiatkowski and Jack Lloyd.
//           Also see https://tools.ietf.org/html/draft-shen-sm3-hash.

#include "pch.h"
#include "config.h"

#include "sm3.h"
#include "misc.h"
#include "cpu.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::rotlFixed;

using CryptoPP::SM3;
using CryptoPP::GetBlock;
using CryptoPP::BigEndian;

inline word32 P0(word32 X)
{
    return X ^ rotlFixed(X, 9) ^ rotlFixed(X, 17);
}

inline word32 FF1(word32 X, word32 Y, word32 Z)
{
    return (X & Y) | ((X | Y) & Z);
}

inline word32 GG1(word32 X, word32 Y, word32 Z)
{
    return ((Z ^ (X & (Y ^ Z))));
}

inline void R1(word32 A, word32& B, word32 C, word32& D, word32 E, word32& F,
        word32 G, word32& H, word32 TJ, word32 Wi, word32 Wj)
{
    const word32 A12 = rotlFixed(A, 12);
    const word32 SS1 = rotlFixed(A12 + E + TJ, 7);
    const word32 TT1 = (A ^ B ^ C) + D + (SS1 ^ A12) + Wj;
    const word32 TT2 = (E ^ F ^ G) + H + SS1 + Wi;

    B = rotlFixed(B, 9);
    D = TT1;
    F= rotlFixed(F, 19);
    H = P0(TT2);
}

inline void R2(word32 A, word32& B, word32 C, word32& D, word32 E, word32& F,
        word32 G, word32& H, word32 TJ, word32 Wi, word32 Wj)
{
    const word32 A12 = rotlFixed(A, 12);
    const word32 SS1 = rotlFixed(A12 + E + TJ, 7);
    const word32 TT1 = FF1(A, B, C) + D + (SS1 ^ A12) + Wj;
    const word32 TT2 = GG1(E, F, G) + H + SS1 + Wi;

    B = rotlFixed(B, 9);
    D = TT1;
    F = rotlFixed(F, 19);
    H = P0(TT2);
}

inline word32 P1(word32 X)
{
    return X ^ rotlFixed(X, 15) ^ rotlFixed(X, 23);
}

inline word32 SM3_E(word32 W0, word32 W7, word32 W13, word32 W3, word32 W10)
{
    return P1(W0 ^ W7 ^ rotlFixed(W13, 15)) ^ rotlFixed(W3, 7) ^ W10;
}

static size_t SM3_HashMultipleBlocks_CXX(word32 *state, const word32 *input, size_t length)
{
    CRYPTOPP_ASSERT(input);

    word32 A = state[0], B = state[1], C = state[2], D = state[3];
    word32 E = state[4], F = state[5], G = state[6], H = state[7];

    size_t blocks = length / SM3::BLOCKSIZE;
    for(size_t i = 0; i < blocks; ++i)
    {
        // Reverse bytes on LittleEndian; align pointer on BigEndian
        typedef GetBlock<word32, BigEndian, false> InBlock;
        InBlock iblk(input);

        word32 W00, W01, W02, W03, W04, W05, W06, W07, W08, W09, W10, W11, W12, W13, W14, W15;
        iblk(W00)(W01)(W02)(W03)(W04)(W05)(W06)(W07)(W08)(W09)(W10)(W11)(W12)(W13)(W14)(W15);

        R1(A, B, C, D, E, F, G, H, 0x79CC4519, W00, W00 ^ W04);
        W00 = SM3_E(W00, W07, W13, W03, W10);
        R1(D, A, B, C, H, E, F, G, 0xF3988A32, W01, W01 ^ W05);
        W01 = SM3_E(W01, W08, W14, W04, W11);
        R1(C, D, A, B, G, H, E, F, 0xE7311465, W02, W02 ^ W06);
        W02 = SM3_E(W02, W09, W15, W05, W12);
        R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W03, W03 ^ W07);
        W03 = SM3_E(W03, W10, W00, W06, W13);
        R1(A, B, C, D, E, F, G, H, 0x9CC45197, W04, W04 ^ W08);
        W04 = SM3_E(W04, W11, W01, W07, W14);
        R1(D, A, B, C, H, E, F, G, 0x3988A32F, W05, W05 ^ W09);
        W05 = SM3_E(W05, W12, W02, W08, W15);
        R1(C, D, A, B, G, H, E, F, 0x7311465E, W06, W06 ^ W10);
        W06 = SM3_E(W06, W13, W03, W09, W00);
        R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W07, W07 ^ W11);
        W07 = SM3_E(W07, W14, W04, W10, W01);
        R1(A, B, C, D, E, F, G, H, 0xCC451979, W08, W08 ^ W12);
        W08 = SM3_E(W08, W15, W05, W11, W02);
        R1(D, A, B, C, H, E, F, G, 0x988A32F3, W09, W09 ^ W13);
        W09 = SM3_E(W09, W00, W06, W12, W03);
        R1(C, D, A, B, G, H, E, F, 0x311465E7, W10, W10 ^ W14);
        W10 = SM3_E(W10, W01, W07, W13, W04);
        R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W11, W11 ^ W15);
        W11 = SM3_E(W11, W02, W08, W14, W05);
        R1(A, B, C, D, E, F, G, H, 0xC451979C, W12, W12 ^ W00);
        W12 = SM3_E(W12, W03, W09, W15, W06);
        R1(D, A, B, C, H, E, F, G, 0x88A32F39, W13, W13 ^ W01);
        W13 = SM3_E(W13, W04, W10, W00, W07);
        R1(C, D, A, B, G, H, E, F, 0x11465E73, W14, W14 ^ W02);
        W14 = SM3_E(W14, W05, W11, W01, W08);
        R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W15, W15 ^ W03);
        W15 = SM3_E(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
        W00 = SM3_E(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
        W01 = SM3_E(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
        W02 = SM3_E(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
        W03 = SM3_E(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
        W04 = SM3_E(W04, W11, W01, W07, W14);
        R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
        W05 = SM3_E(W05, W12, W02, W08, W15);
        R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
        W06 = SM3_E(W06, W13, W03, W09, W00);
        R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
        W07 = SM3_E(W07, W14, W04, W10, W01);
        R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
        W08 = SM3_E(W08, W15, W05, W11, W02);
        R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
        W09 = SM3_E(W09, W00, W06, W12, W03);
        R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
        W10 = SM3_E(W10, W01, W07, W13, W04);
        R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
        W11 = SM3_E(W11, W02, W08, W14, W05);
        R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
        W12 = SM3_E(W12, W03, W09, W15, W06);
        R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
        W13 = SM3_E(W13, W04, W10, W00, W07);
        R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
        W14 = SM3_E(W14, W05, W11, W01, W08);
        R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);
        W15 = SM3_E(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W00, W00 ^ W04);
        W00 = SM3_E(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W01, W01 ^ W05);
        W01 = SM3_E(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W02, W02 ^ W06);
        W02 = SM3_E(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W03, W03 ^ W07);
        W03 = SM3_E(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W04, W04 ^ W08);
        W04 = SM3_E(W04, W11, W01, W07, W14);
        R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W05, W05 ^ W09);
        W05 = SM3_E(W05, W12, W02, W08, W15);
        R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W06, W06 ^ W10);
        W06 = SM3_E(W06, W13, W03, W09, W00);
        R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W07, W07 ^ W11);
        W07 = SM3_E(W07, W14, W04, W10, W01);
        R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W08, W08 ^ W12);
        W08 = SM3_E(W08, W15, W05, W11, W02);
        R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W09, W09 ^ W13);
        W09 = SM3_E(W09, W00, W06, W12, W03);
        R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W10, W10 ^ W14);
        W10 = SM3_E(W10, W01, W07, W13, W04);
        R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W11, W11 ^ W15);
        W11 = SM3_E(W11, W02, W08, W14, W05);
        R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W12, W12 ^ W00);
        W12 = SM3_E(W12, W03, W09, W15, W06);
        R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W13, W13 ^ W01);
        W13 = SM3_E(W13, W04, W10, W00, W07);
        R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W14, W14 ^ W02);
        W14 = SM3_E(W14, W05, W11, W01, W08);
        R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W15, W15 ^ W03);
        W15 = SM3_E(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
        W00 = SM3_E(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
        W01 = SM3_E(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
        W02 = SM3_E(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
        W03 = SM3_E(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
        R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
        R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
        R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
        R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
        R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
        R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
        R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
        R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
        R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
        R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
        R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);

        A = (state[0] ^= A);
        B = (state[1] ^= B);
        C = (state[2] ^= C);
        D = (state[3] ^= D);
        E = (state[4] ^= E);
        F = (state[5] ^= F);
        G = (state[6] ^= G);
        H = (state[7] ^= H);

        input += SM3::BLOCKSIZE/sizeof(word32);
    }

    return length & (SM3::BLOCKSIZE-1);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void SM3::InitState(HashWordType *state)
{
    const word32 s[] = {
        0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
        0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU
    };

    std::memcpy(state, s, sizeof(s));
}

void SM3::Transform(word32 *state, const word32 *data)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);

    SM3_HashMultipleBlocks_CXX(state, data, SM3::BLOCKSIZE);
}

size_t SM3::HashMultipleBlocks(const HashWordType *input, size_t length)
{
    const size_t res = length & (SM3::BLOCKSIZE - 1);
    SM3_HashMultipleBlocks_CXX(m_state, input, length-res);
    return res;
}

NAMESPACE_END
