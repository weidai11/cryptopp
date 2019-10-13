// xts.cpp - written and placed in the public domain by Jeffrey Walton

#include "pch.h"

#include "xts.h"
#include "misc.h"
#include "modes.h"

#if defined(CRYPTOPP_DEBUG)
# include "aes.h"
# include "threefish.h"
#endif

// 0.3 to 0.4 cpb profit
#if defined(__SSE2__) || defined(_M_X64)
# include <immintrin.h>
#endif

// C1189: error: This header is specific to ARM targets
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
# ifndef _M_ARM64
#  include <stdint.h>
#  include <arm_neon.h>
# endif
#endif

// Clang intrinsic casts
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

ANONYMOUS_NAMESPACE_BEGIN

using namespace CryptoPP;

// Aarch32, Aarch64, Altivec and X86_64 include SIMD as part of the
// base architecture. We can use the SIMD code below without an
// architecture option. No runtime tests are required. Unfortunately,
// we can't use it on Altivec because an architecture switch is required.
// The updated XorBuffer gains 0.3 to 1.5 cpb on the architectures for
// 16-byte block sizes. count must be a multiple of 16 since SIMD words
// are used.
inline void XorBuffer(byte *buf, const byte *mask, size_t count)
{
    CRYPTOPP_ASSERT(count >= 16 && (count % 16 == 0));
    CRYPTOPP_UNUSED(count);

#if defined(__SSE2__) || defined(_M_X64)
    #if (CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS)
    for (size_t i=0; i<count; i+=16)
        _mm_storeu_si128(M128_CAST(buf+i), _mm_xor_si128(
            _mm_loadu_si128(CONST_M128_CAST(mask+i)), _mm_loadu_si128(CONST_M128_CAST(buf+i))));
    #else
        _mm_storeu_si128(M128_CAST(buf), _mm_xor_si128(
            _mm_loadu_si128(CONST_M128_CAST(mask)), _mm_loadu_si128(CONST_M128_CAST(buf))));
    #endif

#elif defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
    #if (CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS)
    for (size_t i=0; i<count; i+=16)
        vst1q_u8(buf+i, veorq_u8(vld1q_u8(mask+i), vld1q_u8(buf+i)));
    #else
        vst1q_u8(buf, veorq_u8(vld1q_u8(mask), vld1q_u8(buf)));
    #endif

#else
    xorbuf(buf, mask, count);
#endif
}

// Aarch32, Aarch64, Altivec and X86_64 include SIMD as part of the
// base architecture. We can use the SIMD code below without an
// architecture option. No runtime tests are required. Unfortunately,
// we can't use it on Altivec because an architecture switch is required.
// The updated XorBuffer gains 0.3 to 1.5 cpb on the architectures for
// 16-byte block sizes. count must be a multiple of 16 since SIMD words
// are used.
inline void XorBuffer(byte *output, const byte *input, const byte *mask, size_t count)
{
    CRYPTOPP_ASSERT(count >= 16 && (count % 16 == 0));
    CRYPTOPP_UNUSED(count);

#if defined(__SSE2__) || defined(_M_X64)
    #if (CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS)
    for (size_t i=0; i<count; i+=16)
        _mm_storeu_si128(M128_CAST(output+i), _mm_xor_si128(
            _mm_loadu_si128(CONST_M128_CAST(input+i)), _mm_loadu_si128(CONST_M128_CAST(mask+i))));
    #else
        _mm_storeu_si128(M128_CAST(output), _mm_xor_si128(
            _mm_loadu_si128(CONST_M128_CAST(input)), _mm_loadu_si128(CONST_M128_CAST(mask))));
    #endif

#elif defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
    #if (CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS)
    for (size_t i=0; i<count; i+=16)
        vst1q_u8(output+i, veorq_u8(vld1q_u8(input+i), vld1q_u8(mask+i)));
    #else
        vst1q_u8(output, veorq_u8(vld1q_u8(input), vld1q_u8(mask)));
    #endif

#else
    xorbuf(output, input, mask, count);
#endif
}

// Borrowed from CMAC, but little-endian representation
inline void GF_Double(byte *k, unsigned int len)
{
#if defined(_M_X64) || defined(_M_ARM64) || defined(_LP64) || defined(__LP64__)
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
    CRYPTOPP_ASSERT(len >= 16);
    CRYPTOPP_ASSERT(len <= 128);

    if (carry)
    {
        switch (len)
        {
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

void XTS_ModeBase::ThrowIfInvalidKeyLength(size_t length)
{
    if (!AccessBlockCipher().IsValidKeyLength((length+1)/2))
        throw InvalidKeyLength(AlgorithmName(), length);
}

void XTS_ModeBase::SetKey(const byte *key, size_t length, const NameValuePairs &params)
{
    CRYPTOPP_ASSERT(length % 2 == 0);
    ThrowIfInvalidKeyLength(length);

#if (CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS == 0)
    CRYPTOPP_ASSERT(BlockSize() == 16);
    if (BlockSize() != 16)
        throw InvalidArgument(AlgorithmName() + ": block size of underlying block cipher is not 16");
#endif

    const size_t klen = length/2;
    AccessBlockCipher().SetKey(key+0, klen, params);
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

void XTS_ModeBase::Resynchronize(word64 sector, ByteOrder order)
{
    SecByteBlock iv(GetTweakCipher().BlockSize());
    PutWord<word64>(false, order, iv, sector);
    std::memset(iv+8, 0x00, iv.size()-8);

    BlockOrientedCipherModeBase::Resynchronize(iv, iv.size());
    GetTweakCipher().ProcessBlock(m_register);
}

void XTS_ModeBase::ResizeBuffers()
{
    BlockOrientedCipherModeBase::ResizeBuffers();
    m_workspace.New(GetBlockCipher().BlockSize());
}

void XTS_ModeBase::ProcessData(byte *outString, const byte *inString, size_t length)
{
    const unsigned int blockSize = GetBlockCipher().BlockSize();

    // data unit is multiple of 16 bytes
    CRYPTOPP_ASSERT(length % blockSize == 0);

    // now encrypt the data unit, AES_BLK_BYTES at a time
    for (size_t i=0; i<length; i+=blockSize)
    {
        // merge the tweak into the input block
        XorBuffer(m_workspace, inString+i, m_register, blockSize);

        // encrypt one block, merge the tweak into the output block
        GetBlockCipher().AdvancedProcessBlocks(m_workspace, m_register, outString+i, blockSize, 0);

        // Multiply T by alpha
        GF_Double(m_register, m_register.size());
    }
}

size_t XTS_ModeBase::ProcessLastBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
{
    // need at least a full AES block
    CRYPTOPP_ASSERT(inLength >= BlockSize());

    if (inLength < BlockSize())
        throw InvalidArgument("XTS: message is too short for ciphertext stealing");

    if (IsForwardTransformation())
        return ProcessLastPlainBlock(outString, outLength, inString, inLength);
    else
        return ProcessLastCipherBlock(outString, outLength, inString, inLength);
}

size_t XTS_ModeBase::ProcessLastPlainBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
{
    // ensure output buffer is large enough
    CRYPTOPP_ASSERT(outLength >= inLength);

    const unsigned int blockSize = GetBlockCipher().BlockSize();
    const unsigned int blocks = inLength / blockSize;
    const unsigned int tail = inLength % blockSize;
    outLength = inLength;

    if (tail == 0)
    {
        // Allow ProcessData to handle all the full blocks
        ProcessData(outString, inString, inLength);
        return inLength;
    }
    else if (blocks > 1)
    {
        // Allow ProcessData to handle full blocks except one
        const size_t head = (blocks-1)*blockSize;
        ProcessData(outString, inString, inLength-head);

        outString += head;
        inString  += head; inLength  -= head;
    }

    ///// handle the full block /////

    // merge the tweak into the input block
    XorBuffer(m_workspace, inString, m_register, blockSize);

    // encrypt one block, merge the tweak into the output block
    GetBlockCipher().AdvancedProcessBlocks(m_workspace, m_register, outString, blockSize, 0);

    // Multiply T by alpha
    GF_Double(m_register, m_register.size());

    ///// handle final partial block /////

    inString += blockSize;
    outString += blockSize;
    const size_t len = inLength-blockSize;

    // copy in the final plaintext bytes
    std::memcpy(m_workspace, inString, len);
    // and copy out the final ciphertext bytes
    std::memcpy(outString, outString-blockSize, len);
    // "steal" ciphertext to complete the block
    std::memcpy(m_workspace+len, outString-blockSize+len, blockSize-len);

    // merge the tweak into the input block
    XorBuffer(m_workspace, m_register, blockSize);

    // encrypt the final block, merge the tweak into the output block
    GetBlockCipher().AdvancedProcessBlocks(m_workspace, m_register, outString-blockSize, blockSize, 0);

    return outLength;
}

size_t XTS_ModeBase::ProcessLastCipherBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
{
    // ensure output buffer is large enough
    CRYPTOPP_ASSERT(outLength >= inLength);

    const unsigned int blockSize = GetBlockCipher().BlockSize();
    const unsigned int blocks = inLength / blockSize;
    const unsigned int tail = inLength % blockSize;
    outLength = inLength;

    if (tail == 0)
    {
        // Allow ProcessData to handle all the full blocks
        ProcessData(outString, inString, inLength);
        return inLength;
    }
    else if (blocks > 1)
    {
        // Allow ProcessData to handle full blocks except one
        const size_t head = (blocks-1)*blockSize;
        ProcessData(outString, inString, inLength-head);

        outString += head;
        inString  += head; inLength  -= head;
    }

    SecByteBlock poly1(m_register);
    SecByteBlock poly2(m_register);
    GF_Double(poly2, poly2.size());

    ///// handle final partial block /////

    inString += blockSize;
    outString += blockSize;
    const size_t len = inLength-blockSize;

    // merge the tweak into the input block
    XorBuffer(m_workspace, inString-blockSize, poly2, blockSize);

    // encrypt one block, merge the tweak into the output block
    GetBlockCipher().AdvancedProcessBlocks(m_workspace, poly2, m_workspace, blockSize, 0);

    // copy in the final plaintext bytes
    std::memcpy(outString-blockSize, inString, len);
    // and copy out the final ciphertext bytes
    std::memcpy(outString, m_workspace, len);
    // "steal" ciphertext to complete the block
    std::memcpy(outString-blockSize+len, m_workspace+len, blockSize-len);

    ///// handle the full previous block /////

    inString -= blockSize;
    outString -= blockSize;

    // merge the tweak into the output block
    XorBuffer(m_workspace, outString, poly1, blockSize);

    // encrypt one block, merge the tweak into the input block
    GetBlockCipher().AdvancedProcessBlocks(m_workspace, poly1, outString, blockSize, 0);

    return outLength;
}

NAMESPACE_END
