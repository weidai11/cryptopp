// xts.cpp - written and placed in the public domain by Jeffrey Walton

#include "pch.h"

#include "xts.h"
#include "misc.h"
#include "modes.h"
#include "argnames.h"

#if defined(CRYPTOPP_DEBUG)
#include "aes.h"
#include "threefish.h"
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::GetWord;
using CryptoPP::PutWord;
using CryptoPP::IsPowerOf2;
using CryptoPP::BIG_ENDIAN_ORDER;
using CryptoPP::LITTLE_ENDIAN_ORDER;

// Borrowed from CMAC, but little-endian representation
inline void GF_Multiply(byte *k, unsigned int len)
{
#if defined(_LP64) || defined(__LP64__)
    word64 carry = 0, x;
    for (size_t i=0, idx=0; i<len/8; ++i, idx+=8)
    {
        x = GetWord<word64>(false, LITTLE_ENDIAN_ORDER, k+idx);
        word64 y = (x >> 63); x = (x << 1) + carry;
        PutWord<word64>(false, LITTLE_ENDIAN_ORDER, k+idx, x);
        carry = y;
    }
#else
    word32 carry = 0, x;
    for (size_t i=0, idx=0; i<len/4; ++i, idx+=4)
    {
        x = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, k+idx);
        word32 y = (x >> 31); x = (x << 1) + carry;
        PutWord<word32>(false, LITTLE_ENDIAN_ORDER, k+idx, x);
        carry = y;
    }
#endif

#if CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS

    CRYPTOPP_ASSERT(IsPowerOf2(len));
    CRYPTOPP_ASSERT(len >= 8);
    CRYPTOPP_ASSERT(len <= 128);

    // Special case the dominant case
    if (carry && len == 16)
    {
        k[0] ^= 0x87;
        return;
    }

    if (carry)
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
#else
    CRYPTOPP_ASSERT(len == 16);

    if (carry)
    {
        k[0] ^= 0x87;
        return;
    }
#endif  // CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS
}

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)

using CryptoPP::AES;
using CryptoPP::XTS_Mode;
using CryptoPP::Threefish512;

void Modes_TestInstantiations()
{
    XTS_Mode<AES>::Encryption m0;
    XTS_Mode<AES>::Decryption m1;
    XTS_Mode<AES>::Encryption m2;
    XTS_Mode<AES>::Decryption m3;

#if CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS
    XTS_Mode<Threefish512>::Encryption m4;
    XTS_Mode<Threefish512>::Decryption m5;
#endif
}
#endif

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

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

void XTS_ModeBase::Resynchronize(const byte *iv, int ivLength)
{
    BlockOrientedCipherModeBase::Resynchronize(iv, ivLength);
    GetTweakCipher().ProcessBlock(m_register);
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
    // GetTweakCipher().ProcessBlock(m_register);

    // now encrypt the data unit, AES_BLK_BYTES at a time
    for (size_t i=0; i<length; i+=blockSize)
    {
        // merge the tweak into the input block
        xorbuf(m_workspace, inString+i, m_register, blockSize);

        // encrypt one block
        GetEncryptionCipher().ProcessBlock(m_workspace);

        // merge the tweak into the output block
        xorbuf(outString+i, m_workspace, m_register, blockSize);

        // Multiply T by alpha
        GF_Multiply(m_register, m_register.size());
    }
}

size_t XTS_ModeBase::ProcessLastBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
{
    if (IsForwardTransformation())
        return ProcessLastPlainBlock(outString, outLength, inString, inLength);
    else
        return ProcessLastCipherBlock(outString, outLength, inString, inLength);
}

size_t XTS_ModeBase::ProcessLastPlainBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
{
    // ensure output buffer is large enough
    CRYPTOPP_ASSERT(outLength >= inLength);

    const unsigned int blockSize = GetEncryptionCipher().BlockSize();
    size_t i, j;

    // need at least a full AES block
    CRYPTOPP_ASSERT(inLength >= BlockSize());

    // encrypt the tweak
    // GetTweakCipher().ProcessBlock(m_register);

    // now encrypt the data unit, AES_BLK_BYTES at a time
    for (i=0; i+blockSize<=inLength; i+=blockSize)
    {
        // merge the tweak into the input block
        xorbuf(m_workspace, inString+i, m_register, blockSize);

        // encrypt one block
        GetEncryptionCipher().ProcessBlock(m_workspace);

        // merge the tweak into the output block
        xorbuf(outString+i, m_workspace, m_register, blockSize);

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
        xorbuf(outString+i-blockSize, m_workspace, m_register, blockSize);
    }

    return inLength;
}

size_t XTS_ModeBase::ProcessLastCipherBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
{
    // ensure output buffer is large enough
    CRYPTOPP_ASSERT(outLength >= inLength);

    const unsigned int blockSize = GetEncryptionCipher().BlockSize();
    size_t i, j;

    // need at least a full AES block
    CRYPTOPP_ASSERT(inLength >= BlockSize());

    // encrypt the tweak
    // GetTweakCipher().ProcessBlock(m_register);

    // now encrypt the data unit, AES_BLK_BYTES at a time
    for (i=0; i+blockSize<=inLength; i+=blockSize)
    {
        // merge the tweak into the input block
        xorbuf(m_workspace, inString+i, m_register, blockSize);

        // encrypt one block
        GetEncryptionCipher().ProcessBlock(m_workspace);

        // merge the tweak into the output block
        xorbuf(outString+i, m_workspace, m_register, blockSize);

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
        xorbuf(outString+i-blockSize, m_workspace, m_register, blockSize);
    }

    return inLength;
}

NAMESPACE_END
