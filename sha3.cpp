// sha3.cpp - modified by Wei Dai from Ronny Van Keer's public domain
//            Keccak-simple.c. All modifications here are placed in the
//            public domain by Wei Dai.
//            Keccack core function moved to keccakc.cpp in AUG 2018
//            by Jeffrey Walton. Separating the core file allows both
//            SHA3 and Keccack to share the core implementation.

/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michael Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include "pch.h"
#include "sha3.h"

NAMESPACE_BEGIN(CryptoPP)

// The Keccak core function
extern void KeccakF1600(word64 *state);

NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void SHA3::Update(const byte *input, size_t length)
{
    CRYPTOPP_ASSERT(!(input == NULLPTR && length != 0));
    if (length == 0) { return; }

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

void SHA3::Restart()
{
    memset(m_state, 0, m_state.SizeInBytes());
    m_counter = 0;
}

void SHA3::TruncatedFinal(byte *hash, size_t size)
{
    CRYPTOPP_ASSERT(hash != NULLPTR);
    ThrowIfInvalidTruncatedSize(size);

    m_state.BytePtr()[m_counter] ^= 0x06;
    m_state.BytePtr()[r()-1] ^= 0x80;
    KeccakF1600(m_state);
    std::memcpy(hash, m_state, size);
    Restart();
}

NAMESPACE_END
