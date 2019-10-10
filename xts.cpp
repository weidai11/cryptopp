// xts.cpp - written and placed in the public domain by Jeffrey Walton

#include "pch.h"

#include "xts.h"
#include "misc.h"
#include "modes.h"

#if defined(CRYPTOPP_DEBUG)
#include "rijndael.h"
#include "threefish.h"
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;

// Borrowed from CMAC, but little-endian representation
inline void GF_Multiply(byte *k, unsigned int len)
{
    byte Cin = 0, Cout;
    for (unsigned int j=0; j<len; j++)
    {
        Cout =  (k[j] >> 7) & 1;
        k[j] = ((k[j] << 1) + Cin) & 0xFF;
        Cin  =  Cout;
    }

#ifndef CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS
    CRYPTOPP_ASSERT(len == 16);

    if (Cout)
    {
        k[0] ^= 0x87;
        return;
    }
#else
    CRYPTOPP_ASSERT(IsPower2(len));
    CRYPTOPP_ASSERT(len >= 8);
    CRYPTOPP_ASSERT(len <= 128);

    // Special case the dominant case
    if (Cout && len == 16)
    {
        k[0] ^= 0x87;
        return;
    }

    if (Cout)
    {
        switch (len)
        {
        case 8:
        {
            const size_t LEIDX = 8-1;
            k[LEIDX-7] ^= 0x1b;
            break;
        }
        case 16:
        {
            const size_t LEIDX = 16-1;
            k[LEIDX-15] ^= 0x87;
            break;
        }
        case 32:
        {
            // https://crypto.stackexchange.com/q/9815/10496
            // Polynomial x^256 + x^10 + x^5 + x^2 + 1
            const size_t LEIDX = 32-1;
            k[LEIDX-30] ^= 4;
            k[LEIDX-31] ^= 0x25;
            break;
        }
        case 64:
        {
            // https://crypto.stackexchange.com/q/9815/10496
            // Polynomial x^512 + x^8 + x^5 + x^2 + 1
            const size_t LEIDX = 64-1;
            k[LEIDX-62] ^= 1;
            k[LEIDX-63] ^= 0x25;
            break;
        }
        case 128:
        {
            // https://crypto.stackexchange.com/q/9815/10496
            // Polynomial x^1024 + x^19 + x^6 + x + 1
            const size_t LEIDX = 128-1;
            k[LEIDX-125] ^= 8;
            k[LEIDX-126] ^= 0x00;
            k[LEIDX-127] ^= 0x43;
            break;
        }
        default:
            CRYPTOPP_ASSERT(0);
        }
    }
#endif  // CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS

}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
void Modes_TestInstantiations()
{
    XTS_Mode<AES>::Encryption m0;
    XTS_Mode<AES>::Decryption m1;
    XTS_Mode<AES>::Encryption m2;
    XTS_Mode<AES>::Decryption m3;

#ifdef CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS
    XTS_Mode<Threefish512>::Encryption m4;
    XTS_Mode<Threefish512>::Decryption m5;
#endif
}
#endif

#if 0
void XTS_ModeBase::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
    SetKey(key, length, params);
    ResizeBuffers();
    if (IsResynchronizable())
    {
        size_t ivLength;
        const byte *iv = GetIVAndThrowIfInvalid(params, ivLength);
        Resynchronize(iv, (int)ivLength);
    }
}
#endif

void XTS_ModeBase::SetKey(const byte *key, size_t length, const NameValuePairs &params)
{
    CRYPTOPP_ASSERT(length % 2 == 0);

    const size_t klen = length/2;
    AccessEncryptionCipher().SetKey(key+0, klen, params);
    AccessTweakCipher().SetKey(key+klen, klen, params);

    ResizeBuffers();

    size_t ivLength;
    const byte *iv = GetIVAndThrowIfInvalid(params, ivLength);
    Resynchronize(iv, (int)ivLength);
}

void XTS_ModeBase::ResizeBuffers()
{
    BlockOrientedCipherModeBase::ResizeBuffers();
    m_workspace.New(GetEncryptionCipher().BlockSize());
}

void XTS_ModeBase::ProcessData(byte *outString, const byte *inString, size_t length)
{
    const unsigned int blockSize = GetEncryptionCipher().BlockSize();

    // data unit is multiple of 16 bytes
    CRYPTOPP_ASSERT(length % blockSize == 0);

    // encrypt the tweak
    GetTweakCipher().ProcessBlock(m_register);

    // now encrypt the data unit, AES_BLK_BYTES at a time
    for (size_t i=0; i<length; i+=blockSize)
    {
        // merge the tweak into the input block
        for (size_t j=0; j<blockSize; j++)
            m_workspace[j] = inString[i+j] ^ m_register[j];

        // encrypt one block
        GetEncryptionCipher().ProcessBlock(m_workspace);

        // merge the tweak into the output block
        for (size_t j=0; j<blockSize; j++)
            outString[i+j] = m_workspace[j] ^ m_register[j];

        // Multiply T by alpha
        GF_Multiply(m_register, m_register.size());
    }
}

size_t XTS_ModeBase::ProcessLastBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
{
    // ensure output buffer is large enough
    CRYPTOPP_ASSERT(outLength >= inLength);

    const unsigned int blockSize = GetEncryptionCipher().BlockSize();
    size_t i, j;

    // need at least a full AES block
    CRYPTOPP_ASSERT(inLength >= BlockSize());

    // encrypt the tweak
    GetTweakCipher().ProcessBlock(m_register);

    // now encrypt the data unit, AES_BLK_BYTES at a time
    for (i=0; i+blockSize<=inLength; i+=blockSize)
    {
        // merge the tweak into the input block
        for (j=0; j<blockSize; j++)
            m_workspace[j] = inString[i+j] ^ m_register[j];

        // encrypt one block
        GetEncryptionCipher().ProcessBlock(m_workspace);

        // merge the tweak into the output block
        for (j=0; j<blockSize; j++)
            outString[i+j] = m_workspace[j] ^ m_register[j];

        // Multiply T by alpha
        GF_Multiply(m_register, m_register.size());
    }

    // is there a final partial block to handle?
    if (i < inLength)
    {
        for (j=0; i+j<inLength; j++)
        {
            // copy in the final plaintext bytes
            m_workspace[j] = inString[i+j] ^ m_register[j];
            // and copy out the final ciphertext bytes
            outString[i+j] = outString[i+j-blockSize];
        }

        // "steal" ciphertext to complete the block
        for (; j<blockSize; j++)
            m_workspace[j] = outString[i+j-blockSize] ^ m_register[j];

        // encrypt the final block
        GetEncryptionCipher().ProcessBlock(m_workspace);

        // merge the tweak into the output block
        for (j=0; j<blockSize; j++)
            outString[i+j-blockSize] = m_workspace[j] ^ m_register[j];
    }

    return inLength;
}

NAMESPACE_END
