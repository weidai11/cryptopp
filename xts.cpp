// xts.cpp - written and placed in the public domain by Jeffrey Walton

// Aarch32, Aarch64, Altivec and X86_64 include SIMD as part of the
// base architecture. We can use the SIMD code below without an
// architecture option. No runtime tests are required. Unfortunately,
// we can't use it on Altivec because an architecture switch is required.
// The updated XorBuffer gains 0.3 to 1.5 cpb on the architectures for
// 16-byte block sizes.

#include "pch.h"

#include "xts.h"
#include "misc.h"
#include "modes.h"
#include "cpu.h"

#if defined(CRYPTOPP_DEBUG)
# include "aes.h"
# include "threefish.h"
#endif

// 0.3 to 0.4 cpb profit
#if defined(__SSE2__) || defined(_M_X64)
# include <emmintrin.h>
#endif

#if defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
# if (CRYPTOPP_ARM_NEON_HEADER) || (CRYPTOPP_ARM_ASIMD_AVAILABLE)
#  include <arm_neon.h>
# endif
#endif

#if defined(__ALTIVEC__)
# include "ppc_simd.h"
#endif

ANONYMOUS_NAMESPACE_BEGIN

using namespace CryptoPP;

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
#endif  // CRYPTOPP_DEBUG

inline void XorBuffer(byte *output, const byte *input, const byte *mask, size_t count)
{
    CRYPTOPP_ASSERT(count >= 16 && (count % 16 == 0));

#if defined(CRYPTOPP_DISABLE_ASM)
    xorbuf(output, input, mask, count);

#elif defined(__SSE2__) || defined(_M_X64)
    for (size_t i=0; i<count; i+=16)
        _mm_storeu_si128(M128_CAST(output+i),
            _mm_xor_si128(
                _mm_loadu_si128(CONST_M128_CAST(input+i)),
                _mm_loadu_si128(CONST_M128_CAST(mask+i))));

#elif defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
    for (size_t i=0; i<count; i+=16)
        vst1q_u8(output+i, veorq_u8(vld1q_u8(input+i), vld1q_u8(mask+i)));

#elif defined(__ALTIVEC__)
    for (size_t i=0; i<count; i+=16)
        VecStore(VecXor(VecLoad(input+i), VecLoad(mask+i)), output+i);

#else
    xorbuf(output, input, mask, count);
#endif
}

inline void XorBuffer(byte *buf, const byte *mask, size_t count)
{
    XorBuffer(buf, buf, mask, count);
}

// Borrowed from CMAC, but little-endian representation
inline void GF_Double(byte *out, const byte* in, unsigned int len)
{
#if defined(CRYPTOPP_WORD128_AVAILABLE)
    word128 carry = 0, x;
    for (size_t i=0, idx=0; i<len/16; ++i, idx+=16)
    {
        x = GetWord<word128>(false, LITTLE_ENDIAN_ORDER, in+idx);
        word128 y = (x >> 127); x = (x << 1) + carry;
        PutWord<word128>(false, LITTLE_ENDIAN_ORDER, out+idx, x);
        carry = y;
    }
#elif defined(_M_X64) || defined(_M_ARM64) || defined(_LP64) || defined(__LP64__)
    word64 carry = 0, x;
    for (size_t i=0, idx=0; i<len/8; ++i, idx+=8)
    {
        x = GetWord<word64>(false, LITTLE_ENDIAN_ORDER, in+idx);
        word64 y = (x >> 63); x = (x << 1) + carry;
        PutWord<word64>(false, LITTLE_ENDIAN_ORDER, out+idx, x);
        carry = y;
    }
#else
    word32 carry = 0, x;
    for (size_t i=0, idx=0; i<len/4; ++i, idx+=4)
    {
        x = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, in+idx);
        word32 y = (x >> 31); x = (x << 1) + carry;
        PutWord<word32>(false, LITTLE_ENDIAN_ORDER, out+idx, x);
        carry = y;
    }
#endif

#if CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS

    CRYPTOPP_ASSERT(IsPowerOf2(len));
    CRYPTOPP_ASSERT(len >= 16);
    CRYPTOPP_ASSERT(len <= 128);

    byte* k = out;
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

    byte* k = out;
    if (carry)
    {
        k[0] ^= 0x87;
        return;
    }
#endif  // CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS
}

inline void GF_Double(byte *inout, unsigned int len)
{
    GF_Double(inout, inout, len);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

void XTS_ModeBase::ThrowIfInvalidBlockSize(size_t length)
{
#if CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS
    CRYPTOPP_ASSERT(length >= 16 && length <= 128 && IsPowerOf2(length));
    if (length < 16 || length > 128 || !IsPowerOf2(length))
        throw InvalidArgument(AlgorithmName() + ": block size of underlying block cipher is not valid");
#else
    CRYPTOPP_ASSERT(length == 16);
    if (length != 16)
        throw InvalidArgument(AlgorithmName() + ": block size of underlying block cipher is not 16");
#endif
}

void XTS_ModeBase::ThrowIfInvalidKeyLength(size_t length)
{
    CRYPTOPP_ASSERT(length % 2 == 0);
    if (!GetBlockCipher().IsValidKeyLength((length+1)/2))
        throw InvalidKeyLength(AlgorithmName(), length);
}

void XTS_ModeBase::SetKey(const byte *key, size_t length, const NameValuePairs &params)
{
    ThrowIfInvalidKeyLength(length);
    ThrowIfInvalidBlockSize(BlockSize());

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
    std::memcpy(m_xregister, m_register, ivLength);
    GetTweakCipher().ProcessBlock(m_xregister);
}

void XTS_ModeBase::Resynchronize(word64 sector, ByteOrder order)
{
    SecByteBlock iv(GetTweakCipher().BlockSize());
    PutWord<word64>(false, order, iv, sector);
    std::memset(iv+8, 0x00, iv.size()-8);

    BlockOrientedCipherModeBase::Resynchronize(iv, (int)iv.size());
    std::memcpy(m_xregister, iv, iv.size());
    GetTweakCipher().ProcessBlock(m_xregister);
}

void XTS_ModeBase::ResizeBuffers()
{
    BlockOrientedCipherModeBase::ResizeBuffers();
    m_xworkspace.New(GetBlockCipher().BlockSize()*ParallelBlocks);
    m_xregister.New(GetBlockCipher().BlockSize()*ParallelBlocks);
}

// ProcessData runs either 12-4-1 blocks, 8-2-1 or 4-1 blocks. Which is
// selected depends on ParallelBlocks in the header file. 12-4-1 or 8-2-1
// can be used on Aarch64 and PowerPC. Intel should use 4-1 due to lack
// of registers. The unneeded code paths should be removed by optimizer.
// The extra gyrations save us 1.8 cpb on Aarch64 and 2.1 cpb on PowerPC.
void XTS_ModeBase::ProcessData(byte *outString, const byte *inString, size_t length)
{
    // data unit is multiple of 16 bytes
    CRYPTOPP_ASSERT(length % BlockSize() == 0);

    enum { lastParallelBlock = ParallelBlocks-1 };
    const unsigned int blockSize = GetBlockCipher().BlockSize();
    const size_t parallelSize = blockSize*ParallelBlocks;

    // encrypt the data unit, optimal size at a time
    while (length >= parallelSize)
    {
        // m_xregister[0] always points to the next tweak.
        GF_Double(m_xregister+1*blockSize, m_xregister+0*blockSize, blockSize);
        GF_Double(m_xregister+2*blockSize, m_xregister+1*blockSize, blockSize);
        GF_Double(m_xregister+3*blockSize, m_xregister+2*blockSize, blockSize);

        if (ParallelBlocks > 4)
        {
            GF_Double(m_xregister+4*blockSize, m_xregister+3*blockSize, blockSize);
            GF_Double(m_xregister+5*blockSize, m_xregister+4*blockSize, blockSize);
            GF_Double(m_xregister+6*blockSize, m_xregister+5*blockSize, blockSize);
            GF_Double(m_xregister+7*blockSize, m_xregister+6*blockSize, blockSize);
        }
        if (ParallelBlocks > 8)
        {
            GF_Double(m_xregister+8*blockSize, m_xregister+7*blockSize, blockSize);
            GF_Double(m_xregister+9*blockSize, m_xregister+8*blockSize, blockSize);
            GF_Double(m_xregister+10*blockSize, m_xregister+9*blockSize, blockSize);
            GF_Double(m_xregister+11*blockSize, m_xregister+10*blockSize, blockSize);
        }

        // merge the tweak into the input block
        XorBuffer(m_xworkspace, inString, m_xregister, parallelSize);

        // encrypt one block, merge the tweak into the output block
        GetBlockCipher().AdvancedProcessBlocks(m_xworkspace, m_xregister,
            outString, parallelSize, BlockTransformation::BT_AllowParallel);

        // m_xregister[0] always points to the next tweak.
        GF_Double(m_xregister+0, m_xregister+lastParallelBlock*blockSize, blockSize);

        inString += parallelSize;
        outString += parallelSize;
        length -= parallelSize;
    }

    // encrypt the data unit, 4 blocks at a time
    while (ParallelBlocks == 12 && length >= blockSize*4)
    {
        // m_xregister[0] always points to the next tweak.
        GF_Double(m_xregister+1*blockSize, m_xregister+0*blockSize, blockSize);
        GF_Double(m_xregister+2*blockSize, m_xregister+1*blockSize, blockSize);
        GF_Double(m_xregister+3*blockSize, m_xregister+2*blockSize, blockSize);

        // merge the tweak into the input block
        XorBuffer(m_xworkspace, inString, m_xregister, blockSize*4);

        // encrypt one block, merge the tweak into the output block
        GetBlockCipher().AdvancedProcessBlocks(m_xworkspace, m_xregister,
            outString, blockSize*4, BlockTransformation::BT_AllowParallel);

        // m_xregister[0] always points to the next tweak.
        GF_Double(m_xregister+0, m_xregister+3*blockSize, blockSize);

        inString += blockSize*4;
        outString += blockSize*4;
        length -= blockSize*4;
    }

    // encrypt the data unit, 2 blocks at a time
    while (ParallelBlocks == 8 && length >= blockSize*2)
    {
        // m_xregister[0] always points to the next tweak.
        GF_Double(m_xregister+1*blockSize, m_xregister+0*blockSize, blockSize);

        // merge the tweak into the input block
        XorBuffer(m_xworkspace, inString, m_xregister, blockSize*2);

        // encrypt one block, merge the tweak into the output block
        GetBlockCipher().AdvancedProcessBlocks(m_xworkspace, m_xregister,
            outString, blockSize*2, BlockTransformation::BT_AllowParallel);

        // m_xregister[0] always points to the next tweak.
        GF_Double(m_xregister+0, m_xregister+1*blockSize, blockSize);

        inString += blockSize*2;
        outString += blockSize*2;
        length -= blockSize*2;
    }

    // encrypt the data unit, blocksize at a time
    while (length)
    {
        // merge the tweak into the input block
        XorBuffer(m_xworkspace, inString, m_xregister, blockSize);

        // encrypt one block
        GetBlockCipher().ProcessBlock(m_xworkspace);

        // merge the tweak into the output block
        XorBuffer(outString, m_xworkspace, m_xregister, blockSize);

        // Multiply T by alpha
        GF_Double(m_xregister, blockSize);

        inString += blockSize;
        outString += blockSize;
        length -= blockSize;
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
    const size_t blocks = inLength / blockSize;
    const size_t tail = inLength % blockSize;
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
        inString  += head; inLength -= head;
    }

    ///// handle the full block /////

    // merge the tweak into the input block
    XorBuffer(m_xworkspace, inString, m_xregister, blockSize);

    // encrypt one block
    GetBlockCipher().ProcessBlock(m_xworkspace);

    // merge the tweak into the output block
    XorBuffer(outString, m_xworkspace, m_xregister, blockSize);

    // Multiply T by alpha
    GF_Double(m_xregister, blockSize);

    ///// handle final partial block /////

    inString += blockSize;
    outString += blockSize;
    const size_t len = inLength-blockSize;

    // copy in the final plaintext bytes
    std::memcpy(m_xworkspace, inString, len);
    // and copy out the final ciphertext bytes
    std::memcpy(outString, outString-blockSize, len);
    // "steal" ciphertext to complete the block
    std::memcpy(m_xworkspace+len, outString-blockSize+len, blockSize-len);

    // merge the tweak into the input block
    XorBuffer(m_xworkspace, m_xregister, blockSize);

    // encrypt one block
    GetBlockCipher().ProcessBlock(m_xworkspace);

    // merge the tweak into the previous output block
    XorBuffer(outString-blockSize, m_xworkspace, m_xregister, blockSize);

    return outLength;
}

size_t XTS_ModeBase::ProcessLastCipherBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
{
    // ensure output buffer is large enough
    CRYPTOPP_ASSERT(outLength >= inLength);

    const unsigned int blockSize = GetBlockCipher().BlockSize();
    const size_t blocks = inLength / blockSize;
    const size_t tail = inLength % blockSize;
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
        inString  += head; inLength -= head;
    }

    #define poly1 (m_xregister+0*blockSize)
    #define poly2 (m_xregister+1*blockSize)
    GF_Double(poly2, poly1, blockSize);

    ///// handle final partial block /////

    inString += blockSize;
    outString += blockSize;
    const size_t len = inLength-blockSize;

    // merge the tweak into the input block
    XorBuffer(m_xworkspace, inString-blockSize, poly2, blockSize);

    // encrypt one block
    GetBlockCipher().ProcessBlock(m_xworkspace);

    // merge the tweak into the output block
    XorBuffer(m_xworkspace, poly2, blockSize);

    // copy in the final plaintext bytes
    std::memcpy(outString-blockSize, inString, len);
    // and copy out the final ciphertext bytes
    std::memcpy(outString, m_xworkspace, len);
    // "steal" ciphertext to complete the block
    std::memcpy(outString-blockSize+len, m_xworkspace+len, blockSize-len);

    ///// handle the full previous block /////

    inString -= blockSize;
    outString -= blockSize;

    // merge the tweak into the input block
    XorBuffer(m_xworkspace, outString, poly1, blockSize);

    // encrypt one block
    GetBlockCipher().ProcessBlock(m_xworkspace);

    // merge the tweak into the output block
    XorBuffer(outString, m_xworkspace, poly1, blockSize);

    return outLength;
}

NAMESPACE_END
