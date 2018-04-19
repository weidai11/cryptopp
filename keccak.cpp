// keccak.cpp - modified by Wei Dai from Ronny Van Keer's public domain sha3-simple.c
// all modifications here are placed in the public domain by Wei Dai

/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michael Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by Ronny Van Keer,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include "pch.h"
#include "keccak.h"

NAMESPACE_BEGIN(CryptoPP)

static const word64 KeccakF_RoundConstants[24] =
{
    W64LIT(0x0000000000000001), W64LIT(0x0000000000008082), W64LIT(0x800000000000808a),
    W64LIT(0x8000000080008000), W64LIT(0x000000000000808b), W64LIT(0x0000000080000001),
    W64LIT(0x8000000080008081), W64LIT(0x8000000000008009), W64LIT(0x000000000000008a),
    W64LIT(0x0000000000000088), W64LIT(0x0000000080008009), W64LIT(0x000000008000000a),
    W64LIT(0x000000008000808b), W64LIT(0x800000000000008b), W64LIT(0x8000000000008089),
    W64LIT(0x8000000000008003), W64LIT(0x8000000000008002), W64LIT(0x8000000000000080),
    W64LIT(0x000000000000800a), W64LIT(0x800000008000000a), W64LIT(0x8000000080008081),
    W64LIT(0x8000000000008080), W64LIT(0x0000000080000001), W64LIT(0x8000000080008008)
};

static void KeccakF1600(word64 *state)
{
    {
        word64 Aba, Abe, Abi, Abo, Abu;
        word64 Aga, Age, Agi, Ago, Agu;
        word64 Aka, Ake, Aki, Ako, Aku;
        word64 Ama, Ame, Ami, Amo, Amu;
        word64 Asa, Ase, Asi, Aso, Asu;
        word64 BCa, BCe, BCi, BCo, BCu;
        word64 Da, De, Di, Do, Du;
        word64 Eba, Ebe, Ebi, Ebo, Ebu;
        word64 Ega, Ege, Egi, Ego, Egu;
        word64 Eka, Eke, Eki, Eko, Eku;
        word64 Ema, Eme, Emi, Emo, Emu;
        word64 Esa, Ese, Esi, Eso, Esu;

        //copyFromState(A, state)
        typedef BlockGetAndPut<word64, LittleEndian, true, true> Block;
        Block::Get(state)(Aba)(Abe)(Abi)(Abo)(Abu)(Aga)(Age)(Agi)(Ago)(Agu)(Aka)(Ake)(Aki)(Ako)(Aku)(Ama)(Ame)(Ami)(Amo)(Amu)(Asa)(Ase)(Asi)(Aso)(Asu);

        for( unsigned int round = 0; round < 24; round += 2 )
        {
            //    prepareTheta
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;

            //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            Da = BCu^rotlConstant<1>(BCe);
            De = BCa^rotlConstant<1>(BCi);
            Di = BCe^rotlConstant<1>(BCo);
            Do = BCi^rotlConstant<1>(BCu);
            Du = BCo^rotlConstant<1>(BCa);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = rotlConstant<44>(Age);
            Aki ^= Di;
            BCi = rotlConstant<43>(Aki);
            Amo ^= Do;
            BCo = rotlConstant<21>(Amo);
            Asu ^= Du;
            BCu = rotlConstant<14>(Asu);
            Eba =   BCa ^((~BCe)&  BCi );
            Eba ^= (word64)KeccakF_RoundConstants[round];
            Ebe =   BCe ^((~BCi)&  BCo );
            Ebi =   BCi ^((~BCo)&  BCu );
            Ebo =   BCo ^((~BCu)&  BCa );
            Ebu =   BCu ^((~BCa)&  BCe );

            Abo ^= Do;
            BCa = rotlConstant<28>(Abo);
            Agu ^= Du;
            BCe = rotlConstant<20>(Agu);
            Aka ^= Da;
            BCi = rotlConstant<3>(Aka);
            Ame ^= De;
            BCo = rotlConstant<45>(Ame);
            Asi ^= Di;
            BCu = rotlConstant<61>(Asi);
            Ega =   BCa ^((~BCe)&  BCi );
            Ege =   BCe ^((~BCi)&  BCo );
            Egi =   BCi ^((~BCo)&  BCu );
            Ego =   BCo ^((~BCu)&  BCa );
            Egu =   BCu ^((~BCa)&  BCe );

            Abe ^= De;
            BCa = rotlConstant<1>(Abe);
            Agi ^= Di;
            BCe = rotlConstant<6>(Agi);
            Ako ^= Do;
            BCi = rotlConstant<25>(Ako);
            Amu ^= Du;
            BCo = rotlConstant<8>(Amu);
            Asa ^= Da;
            BCu = rotlConstant<18>(Asa);
            Eka =   BCa ^((~BCe)&  BCi );
            Eke =   BCe ^((~BCi)&  BCo );
            Eki =   BCi ^((~BCo)&  BCu );
            Eko =   BCo ^((~BCu)&  BCa );
            Eku =   BCu ^((~BCa)&  BCe );

            Abu ^= Du;
            BCa = rotlConstant<27>(Abu);
            Aga ^= Da;
            BCe = rotlConstant<36>(Aga);
            Ake ^= De;
            BCi = rotlConstant<10>(Ake);
            Ami ^= Di;
            BCo = rotlConstant<15>(Ami);
            Aso ^= Do;
            BCu = rotlConstant<56>(Aso);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = rotlConstant<62>(Abi);
            Ago ^= Do;
            BCe = rotlConstant<55>(Ago);
            Aku ^= Du;
            BCi = rotlConstant<39>(Aku);
            Ama ^= Da;
            BCo = rotlConstant<41>(Ama);
            Ase ^= De;
            BCu = rotlConstant<2>(Ase);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            //    prepareTheta
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu^rotlConstant<1>(BCe);
            De = BCa^rotlConstant<1>(BCi);
            Di = BCe^rotlConstant<1>(BCo);
            Do = BCi^rotlConstant<1>(BCu);
            Du = BCo^rotlConstant<1>(BCa);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = rotlConstant<44>(Ege);
            Eki ^= Di;
            BCi = rotlConstant<43>(Eki);
            Emo ^= Do;
            BCo = rotlConstant<21>(Emo);
            Esu ^= Du;
            BCu = rotlConstant<14>(Esu);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= (word64)KeccakF_RoundConstants[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = rotlConstant<28>(Ebo);
            Egu ^= Du;
            BCe = rotlConstant<20>(Egu);
            Eka ^= Da;
            BCi = rotlConstant<3>(Eka);
            Eme ^= De;
            BCo = rotlConstant<45>(Eme);
            Esi ^= Di;
            BCu = rotlConstant<61>(Esi);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = rotlConstant<1>(Ebe);
            Egi ^= Di;
            BCe = rotlConstant<6>(Egi);
            Eko ^= Do;
            BCi = rotlConstant<25>(Eko);
            Emu ^= Du;
            BCo = rotlConstant<8>(Emu);
            Esa ^= Da;
            BCu = rotlConstant<18>(Esa);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = rotlConstant<27>(Ebu);
            Ega ^= Da;
            BCe = rotlConstant<36>(Ega);
            Eke ^= De;
            BCi = rotlConstant<10>(Eke);
            Emi ^= Di;
            BCo = rotlConstant<15>(Emi);
            Eso ^= Do;
            BCu = rotlConstant<56>(Eso);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = rotlConstant<62>(Ebi);
            Ego ^= Do;
            BCe = rotlConstant<55>(Ego);
            Eku ^= Du;
            BCi = rotlConstant<39>(Eku);
            Ema ^= Da;
            BCo = rotlConstant<41>(Ema);
            Ese ^= De;
            BCu = rotlConstant<2>(Ese);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        //copyToState(state, A)
        Block::Put(NULLPTR, state)(Aba)(Abe)(Abi)(Abo)(Abu)(Aga)(Age)(Agi)(Ago)(Agu)(Aka)(Ake)(Aki)(Ako)(Aku)(Ama)(Ame)(Ami)(Amo)(Amu)(Asa)(Ase)(Asi)(Aso)(Asu);
    }
}

void Keccak::Update(const byte *input, size_t length)
{
    CRYPTOPP_ASSERT((input && length) || !(input || length));
    if (!length) { return; }

    size_t spaceLeft;
    while (length >= (spaceLeft = r() - m_counter))
    {
        if (spaceLeft)
            xorbuf(m_state.BytePtr() + m_counter, input, spaceLeft);
        KeccakF1600(m_state);
        input += spaceLeft;
        length -= spaceLeft;
        m_counter = 0;
    }

    if (length)
        xorbuf(m_state.BytePtr() + m_counter, input, length);
    m_counter += (unsigned int)length;
}

void Keccak::Restart()
{
    memset(m_state, 0, m_state.SizeInBytes());
    m_counter = 0;
}

void Keccak::TruncatedFinal(byte *hash, size_t size)
{
    ThrowIfInvalidTruncatedSize(size);

    m_state.BytePtr()[m_counter] ^= 1;
    m_state.BytePtr()[r()-1] ^= 0x80;
    KeccakF1600(m_state);
    memcpy(hash, m_state, size);
    Restart();
}

NAMESPACE_END
