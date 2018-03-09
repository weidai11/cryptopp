// adv-simd.h - written and placed in the public domain by Jeffrey Walton
//
//    The SIMD based implementations for ciphers that use SSE, NEON and Power7
//    have a commom pattern. Namely, they have a specialized implementation of
//    AdvancedProcessBlocks which processes multiple block using hardware
//    acceleration. After several implementations we noticed a lot of copy and
//    paste occuring. adv-simd.h provides a template to avoid the copy and paste.
//
//    There are 8 templates provided in this file. The number following the
//    function name is the block size of the cipher. The name following that
//    is the acceleration and arrangement. For example 4x1_SSE means Intel SSE
//    using two encrypt (or decrypt) functions: one that operates on 4 blocks,
//    and one that operates on 1 block.
//
//      * AdvancedProcessBlocks64_4x1_SSE
//      * AdvancedProcessBlocks128_4x1_SSE
//      * AdvancedProcessBlocks64_6x2_SSE
//      * AdvancedProcessBlocks128_6x2_SSE
//      * AdvancedProcessBlocks64_6x2_NEON
//      * AdvancedProcessBlocks128_6x2_NEON
//      * AdvancedProcessBlocks64_6x2_ALTIVEC
//      * AdvancedProcessBlocks128_6x2_ALTIVEC
//

#ifndef CRYPTOPP_ADVANCED_SIMD_TEMPLATES
#define CRYPTOPP_ADVANCED_SIMD_TEMPLATES

#include "config.h"
#include "misc.h"
#include "stdcpp.h"

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_SSSE3_AVAILABLE)
# include <emmintrin.h>
# include <pmmintrin.h>
# include <tmmintrin.h>
#endif

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include "ppc-simd.h"
#endif

// https://www.spinics.net/lists/gcchelp/msg47735.html and
// https://www.spinics.net/lists/gcchelp/msg47749.html
#if (CRYPTOPP_GCC_VERSION >= 40900)
# define GCC_NO_UBSAN __attribute__ ((no_sanitize_undefined))
#else
# define GCC_NO_UBSAN
#endif

// ************************ All block ciphers *********************** //

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::BlockTransformation;

CRYPTOPP_CONSTANT(BT_XorInput = BlockTransformation::BT_XorInput)
CRYPTOPP_CONSTANT(BT_AllowParallel = BlockTransformation::BT_AllowParallel)
CRYPTOPP_CONSTANT(BT_InBlockIsCounter = BlockTransformation::BT_InBlockIsCounter)
CRYPTOPP_CONSTANT(BT_ReverseDirection = BlockTransformation::BT_ReverseDirection)
CRYPTOPP_CONSTANT(BT_DontIncrementInOutPointers = BlockTransformation::BT_DontIncrementInOutPointers)

ANONYMOUS_NAMESPACE_END

// *************************** ARM NEON ************************** //

#if (CRYPTOPP_ARM_NEON_AVAILABLE)

NAMESPACE_BEGIN(CryptoPP)

template <typename F2, typename F6>
inline size_t AdvancedProcessBlocks64_6x2_NEON(F2 func2, F6 func6,
        const word32 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 8);

#if defined(CRYPTOPP_LITTLE_ENDIAN)
    const word32 s_zero32x4[]   = {0, 0, 0, 0};
    const word32 s_one32x4_1b[] = {0, 0, 0, 1<<24};
    const word32 s_one32x4_2b[] = {0, 2<<24, 0, 2<<24};
#else
    const word32 s_zero32x4[]   = {0, 0, 0, 0};
    const word32 s_one32x4_1b[] = {0, 0, 0, 1};
    const word32 s_one32x4_2b[] = {0, 2, 0, 2};
#endif

    const ptrdiff_t blockSize = 8;
    const ptrdiff_t neonBlockSize = 16;

    ptrdiff_t inIncrement = (flags & (BT_InBlockIsCounter|BT_DontIncrementInOutPointers)) ? 0 : neonBlockSize;
    ptrdiff_t xorIncrement = (xorBlocks != NULLPTR) ? neonBlockSize : 0;
    ptrdiff_t outIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : neonBlockSize;

    // Clang and Coverity are generating findings using xorBlocks as a flag.
    const bool xorInput = (xorBlocks != NULLPTR) && (flags & BT_XorInput);
    const bool xorOutput = (xorBlocks != NULLPTR) && !(flags & BT_XorInput);

    if (flags & BT_ReverseDirection)
    {
        inBlocks += static_cast<ptrdiff_t>(length) - neonBlockSize;
        xorBlocks += static_cast<ptrdiff_t>(length) - neonBlockSize;
        outBlocks += static_cast<ptrdiff_t>(length) - neonBlockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BT_AllowParallel)
    {
        while (length >= 6*neonBlockSize)
        {
            uint32x4_t block0, block1, block2, block3, block4, block5;
            if (flags & BT_InBlockIsCounter)
            {
                // For 64-bit block ciphers we need to load the CTR block, which is 8 bytes.
                // After the dup load we have two counters in the NEON word. Then we need
                // to increment the low ctr by 0 and the high ctr by 1.
                const uint8x8_t ctr = vld1_u8(inBlocks);
                block0 = vaddq_u32(vld1q_u32(s_one32x4_1b),
                    vreinterpretq_u32_u8(vcombine_u8(ctr,ctr)));

                // After initial increment of {0,1} remaining counters increment by {2,2}.
                const uint32x4_t be2 = vld1q_u32(s_one32x4_2b);
                block1 = vaddq_u32(be2, block0);
                block2 = vaddq_u32(be2, block1);
                block3 = vaddq_u32(be2, block2);
                block4 = vaddq_u32(be2, block3);
                block5 = vaddq_u32(be2, block4);

                vst1_u8(const_cast<byte*>(inBlocks), vget_low_u8(
                    vreinterpretq_u8_u32(vaddq_u32(be2, block5))));
            }
            else
            {
                block0 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block1 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block2 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block3 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block4 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block5 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = veorq_u32(block0, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u32(block1, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = veorq_u32(block2, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = veorq_u32(block3, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = veorq_u32(block4, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = veorq_u32(block5, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = veorq_u32(block0, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u32(block1, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = veorq_u32(block2, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = veorq_u32(block3, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = veorq_u32(block4, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = veorq_u32(block5, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            vst1q_u8(outBlocks, vreinterpretq_u8_u32(block0));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u32(block1));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u32(block2));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u32(block3));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u32(block4));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u32(block5));
            outBlocks += outIncrement;

            length -= 6*neonBlockSize;
        }

        while (length >= 2*neonBlockSize)
        {
            uint32x4_t block0, block1;
            if (flags & BT_InBlockIsCounter)
            {
                // For 64-bit block ciphers we need to load the CTR block, which is 8 bytes.
                // After the dup load we have two counters in the NEON word. Then we need
                // to increment the low ctr by 0 and the high ctr by 1.
                const uint8x8_t ctr = vld1_u8(inBlocks);
                block0 = vaddq_u32(vld1q_u32(s_one32x4_1b),
                    vreinterpretq_u32_u8(vcombine_u8(ctr,ctr)));

                // After initial increment of {0,1} remaining counters increment by {2,2}.
                const uint32x4_t be2 = vld1q_u32(s_one32x4_2b);
                block1 = vaddq_u32(be2, block0);

                vst1_u8(const_cast<byte*>(inBlocks), vget_low_u8(
                    vreinterpretq_u8_u32(vaddq_u32(be2, block1))));
            }
            else
            {
                block0 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block1 = vreinterpretq_u32_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = veorq_u32(block0, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u32(block1, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func2(block0, block1, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = veorq_u32(block0, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u32(block1, vreinterpretq_u32_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            vst1q_u8(outBlocks, vreinterpretq_u8_u32(block0));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u32(block1));
            outBlocks += outIncrement;

            length -= 2*neonBlockSize;
        }
    }

    if (length)
    {
        // Adjust to real block size
        if (flags & BT_ReverseDirection)
        {
            inIncrement += inIncrement ? blockSize : 0;
            xorIncrement += xorIncrement ? blockSize : 0;
            outIncrement += outIncrement ? blockSize : 0;
            inBlocks -= inIncrement;
            xorBlocks -= xorIncrement;
            outBlocks -= outIncrement;
        }
        else
        {
            inIncrement -= inIncrement ? blockSize : 0;
            xorIncrement -= xorIncrement ? blockSize : 0;
            outIncrement -= outIncrement ? blockSize : 0;
        }

        while (length >= blockSize)
        {
            uint32x4_t block, zero = vld1q_u32(s_zero32x4);

            const uint8x8_t v = vld1_u8(inBlocks);
            block = vreinterpretq_u32_u8(vcombine_u8(v,v));

            if (xorInput)
            {
                const uint8x8_t x = vld1_u8(xorBlocks);
                block = veorq_u32(block, vreinterpretq_u32_u8(vcombine_u8(x,x)));
            }

            if (flags & BT_InBlockIsCounter)
                const_cast<byte *>(inBlocks)[7]++;

            func2(block, zero, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                const uint8x8_t x = vld1_u8(xorBlocks);
                block = veorq_u32(block, vreinterpretq_u32_u8(vcombine_u8(x,x)));
            }

            vst1_u8(const_cast<byte*>(outBlocks),
                vget_low_u8(vreinterpretq_u8_u32(block)));

            inBlocks += inIncrement;
            outBlocks += outIncrement;
            xorBlocks += xorIncrement;
            length -= blockSize;
        }
    }

    return length;
}

template <typename F1, typename F6>
inline size_t AdvancedProcessBlocks128_NEON1x6(F1 func1, F6 func6,
            const word32 *subKeys, size_t rounds, const byte *inBlocks,
            const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 16);

#if defined(CRYPTOPP_LITTLE_ENDIAN)
    const word32 s_zero32x4[]   = {0, 0, 0, 0};
    const word32 s_one32x4[]    = {0, 0, 0, 1<<24};
#else
    const word32 s_zero32x4[]   = {0, 0, 0, 0};
    const word32 s_one32x4[]    = {0, 0, 0, 1};
#endif

    const ptrdiff_t blockSize = 16;
    // const ptrdiff_t neonBlockSize = 16;

    ptrdiff_t inIncrement = (flags & (BT_InBlockIsCounter|BT_DontIncrementInOutPointers)) ? 0 : blockSize;
    ptrdiff_t xorIncrement = (xorBlocks != NULLPTR) ? blockSize : 0;
    ptrdiff_t outIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : blockSize;

    // Clang and Coverity are generating findings using xorBlocks as a flag.
    const bool xorInput = (xorBlocks != NULLPTR) && (flags & BT_XorInput);
    const bool xorOutput = (xorBlocks != NULLPTR) && !(flags & BT_XorInput);

    if (flags & BT_ReverseDirection)
    {
        inBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        xorBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        outBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BT_AllowParallel)
    {
        while (length >= 6*blockSize)
        {
            uint64x2_t block0, block1, block2, block3, block4, block5;
            if (flags & BT_InBlockIsCounter)
            {
                const uint64x2_t be = vreinterpretq_u64_u32(vld1q_u32(s_one32x4));
                block0 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));

                block1 = vaddq_u64(block0, be);
                block2 = vaddq_u64(block1, be);
                block3 = vaddq_u64(block2, be);
                block4 = vaddq_u64(block3, be);
                block5 = vaddq_u64(block4, be);
                vst1q_u8(const_cast<byte*>(inBlocks),
                    vreinterpretq_u8_u64(vaddq_u64(block5, be)));
            }
            else
            {
                block0 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block1 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block2 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block3 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block4 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block5 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = veorq_u64(block2, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = veorq_u64(block3, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = veorq_u64(block4, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = veorq_u64(block5, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = veorq_u64(block2, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = veorq_u64(block3, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = veorq_u64(block4, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = veorq_u64(block5, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block0));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block1));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block2));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block3));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block4));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block5));
            outBlocks += outIncrement;

            length -= 6*blockSize;
        }
    }

    while (length >= blockSize)
    {
        uint64x2_t block;
        block = vreinterpretq_u64_u8(vld1q_u8(inBlocks));

        if (xorInput)
            block = veorq_u64(block, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));

        if (flags & BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func1(block, subKeys, static_cast<unsigned int>(rounds));

        if (xorOutput)
            block = veorq_u64(block, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));

        vst1q_u8(outBlocks, vreinterpretq_u8_u64(block));

        inBlocks += inIncrement;
        outBlocks += outIncrement;
        xorBlocks += xorIncrement;
        length -= blockSize;
    }

    return length;
}

template <typename F2, typename F6>
inline size_t AdvancedProcessBlocks128_6x2_NEON(F2 func2, F6 func6,
            const word64 *subKeys, size_t rounds, const byte *inBlocks,
            const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 16);

#if defined(CRYPTOPP_LITTLE_ENDIAN)
    const word32 s_one32x4[]    = {0, 0, 0, 1<<24};
#else
    const word32 s_one32x4[]    = {0, 0, 0, 1};
#endif

    const ptrdiff_t blockSize = 16;
    // const ptrdiff_t neonBlockSize = 16;

    ptrdiff_t inIncrement = (flags & (BT_InBlockIsCounter|BT_DontIncrementInOutPointers)) ? 0 : blockSize;
    ptrdiff_t xorIncrement = (xorBlocks != NULLPTR) ? blockSize : 0;
    ptrdiff_t outIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : blockSize;

    // Clang and Coverity are generating findings using xorBlocks as a flag.
    const bool xorInput = (xorBlocks != NULLPTR) && (flags & BT_XorInput);
    const bool xorOutput = (xorBlocks != NULLPTR) && !(flags & BT_XorInput);

    if (flags & BT_ReverseDirection)
    {
        inBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        xorBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        outBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BT_AllowParallel)
    {
        while (length >= 6*blockSize)
        {
            uint64x2_t block0, block1, block2, block3, block4, block5;
            if (flags & BT_InBlockIsCounter)
            {
                const uint64x2_t be = vreinterpretq_u64_u32(vld1q_u32(s_one32x4));
                block0 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));

                block1 = vaddq_u64(block0, be);
                block2 = vaddq_u64(block1, be);
                block3 = vaddq_u64(block2, be);
                block4 = vaddq_u64(block3, be);
                block5 = vaddq_u64(block4, be);
                vst1q_u8(const_cast<byte*>(inBlocks),
                    vreinterpretq_u8_u64(vaddq_u64(block5, be)));
            }
            else
            {
                block0 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block1 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block2 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block3 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block4 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block5 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = veorq_u64(block2, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = veorq_u64(block3, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = veorq_u64(block4, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = veorq_u64(block5, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = veorq_u64(block2, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = veorq_u64(block3, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = veorq_u64(block4, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = veorq_u64(block5, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block0));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block1));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block2));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block3));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block4));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block5));
            outBlocks += outIncrement;

            length -= 6*blockSize;
        }

        while (length >= 2*blockSize)
        {
            uint64x2_t block0, block1;
            if (flags & BT_InBlockIsCounter)
            {
                const uint64x2_t be = vreinterpretq_u64_u32(vld1q_u32(s_one32x4));
                block0 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                block1 = vaddq_u64(block0, be);

                vst1q_u8(const_cast<byte*>(inBlocks),
                    vreinterpretq_u8_u64(vaddq_u64(block1, be)));
            }
            else
            {
                block0 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
                block1 = vreinterpretq_u64_u8(vld1q_u8(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func2(block0, block1, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = veorq_u64(block0, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = veorq_u64(block1, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block0));
            outBlocks += outIncrement;
            vst1q_u8(outBlocks, vreinterpretq_u8_u64(block1));
            outBlocks += outIncrement;

            length -= 2*blockSize;
        }
    }

    while (length >= blockSize)
    {
        uint64x2_t block, zero = {0,0};
        block = vreinterpretq_u64_u8(vld1q_u8(inBlocks));

        if (xorInput)
            block = veorq_u64(block, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));

        if (flags & BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func2(block, zero, subKeys, static_cast<unsigned int>(rounds));

        if (xorOutput)
            block = veorq_u64(block, vreinterpretq_u64_u8(vld1q_u8(xorBlocks)));

        vst1q_u8(outBlocks, vreinterpretq_u8_u64(block));

        inBlocks += inIncrement;
        outBlocks += outIncrement;
        xorBlocks += xorIncrement;
        length -= blockSize;
    }

    return length;
}

NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

// *************************** Intel SSE ************************** //

#if defined(CRYPTOPP_SSSE3_AVAILABLE)

// Hack for SunCC, http://github.com/weidai11/cryptopp/issues/224
#if (__SUNPRO_CC >= 0x5130)
# define MAYBE_CONST
# define MAYBE_UNCONST_CAST(T, x) const_cast<MAYBE_CONST T>(x)
#else
# define MAYBE_CONST const
# define MAYBE_UNCONST_CAST(T, x) (x)
#endif

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#ifndef M128_CAST
# define M128_CAST(x) ((__m128i *)(void *)(x))
#endif
#ifndef CONST_M128_CAST
# define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))
#endif

// GCC double casts, https://www.spinics.net/lists/gcchelp/msg47735.html
#ifndef DOUBLE_CAST
# define DOUBLE_CAST(x) ((double *)(void *)(x))
#endif
#ifndef CONST_DOUBLE_CAST
# define CONST_DOUBLE_CAST(x) ((const double *)(const void *)(x))
#endif

NAMESPACE_BEGIN(CryptoPP)

template <typename F2, typename F6>
inline size_t GCC_NO_UBSAN AdvancedProcessBlocks64_6x2_SSE(F2 func2, F6 func6,
        const word32 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 8);

    CRYPTOPP_ALIGN_DATA(16)
    const word32 s_one32x4_1b[] = {0, 0, 0, 1<<24};
    CRYPTOPP_ALIGN_DATA(16)
    const word32 s_one32x4_2b[] = {0, 2<<24, 0, 2<<24};

    const ptrdiff_t blockSize = 8;
    const ptrdiff_t xmmBlockSize = 16;

    ptrdiff_t inIncrement = (flags & (BT_InBlockIsCounter|BT_DontIncrementInOutPointers)) ? 0 : xmmBlockSize;
    ptrdiff_t xorIncrement = (xorBlocks != NULLPTR) ? xmmBlockSize : 0;
    ptrdiff_t outIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : xmmBlockSize;

    // Clang and Coverity are generating findings using xorBlocks as a flag.
    const bool xorInput = (xorBlocks != NULLPTR) && (flags & BT_XorInput);
    const bool xorOutput = (xorBlocks != NULLPTR) && !(flags & BT_XorInput);

    if (flags & BT_ReverseDirection)
    {
        inBlocks += static_cast<ptrdiff_t>(length) - xmmBlockSize;
        xorBlocks += static_cast<ptrdiff_t>(length) - xmmBlockSize;
        outBlocks += static_cast<ptrdiff_t>(length) - xmmBlockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BT_AllowParallel)
    {
        while (length >= 6*xmmBlockSize)
        {
            __m128i block0, block1, block2, block3, block4, block5;
            if (flags & BT_InBlockIsCounter)
            {
                // For 64-bit block ciphers we need to load the CTR block, which is 8 bytes.
                // After the dup load we have two counters in the XMM word. Then we need
                // to increment the low ctr by 0 and the high ctr by 1.
                block0 = _mm_add_epi32(*CONST_M128_CAST(s_one32x4_1b), _mm_castpd_si128(
                    _mm_loaddup_pd(CONST_DOUBLE_CAST(inBlocks))));

                // After initial increment of {0,1} remaining counters increment by {2,2}.
                const __m128i be2 = *CONST_M128_CAST(s_one32x4_2b);
                block1 = _mm_add_epi32(be2, block0);
                block2 = _mm_add_epi32(be2, block1);
                block3 = _mm_add_epi32(be2, block2);
                block4 = _mm_add_epi32(be2, block3);
                block5 = _mm_add_epi32(be2, block4);

                // Store the next counter. UBsan false positive; mem_addr can be unaligned.
                _mm_store_sd(DOUBLE_CAST(inBlocks),
                    _mm_castsi128_pd(_mm_add_epi32(be2, block5)));
            }
            else
            {
                block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block2 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block3 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block4 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block5 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = _mm_xor_si128(block4, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = _mm_xor_si128(block5, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = _mm_xor_si128(block4, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = _mm_xor_si128(block5, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            _mm_storeu_si128(M128_CAST(outBlocks), block0);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block1);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block2);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block3);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block4);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block5);
            outBlocks += outIncrement;

            length -= 6*xmmBlockSize;
        }

        while (length >= 2*xmmBlockSize)
        {
            __m128i block0, block1;
            if (flags & BT_InBlockIsCounter)
            {
                // For 64-bit block ciphers we need to load the CTR block, which is 8 bytes.
                // After the dup load we have two counters in the XMM word. Then we need
                // to increment the low ctr by 0 and the high ctr by 1.
                block0 = _mm_add_epi32(*CONST_M128_CAST(s_one32x4_1b), _mm_castpd_si128(
                    _mm_loaddup_pd(CONST_DOUBLE_CAST(inBlocks))));

                // After initial increment of {0,1} remaining counters increment by {2,2}.
                const __m128i be2 = *CONST_M128_CAST(s_one32x4_2b);
                block1 = _mm_add_epi32(be2, block0);

                // Store the next counter. UBsan false positive; mem_addr can be unaligned.
                _mm_store_sd(DOUBLE_CAST(inBlocks),
                    _mm_castsi128_pd(_mm_add_epi64(be2, block1)));
            }
            else
            {
                block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func2(block0, block1, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            _mm_storeu_si128(M128_CAST(outBlocks), block0);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block1);
            outBlocks += outIncrement;

            length -= 2*xmmBlockSize;
        }
    }

    if (length)
    {
        // Adjust to real block size
        if (flags & BT_ReverseDirection)
        {
            inIncrement += inIncrement ? blockSize : 0;
            xorIncrement += xorIncrement ? blockSize : 0;
            outIncrement += outIncrement ? blockSize : 0;
            inBlocks -= inIncrement;
            xorBlocks -= xorIncrement;
            outBlocks -= outIncrement;
        }
        else
        {
            inIncrement -= inIncrement ? blockSize : 0;
            xorIncrement -= xorIncrement ? blockSize : 0;
            outIncrement -= outIncrement ? blockSize : 0;
        }

        while (length >= blockSize)
        {
            __m128i block, zero = _mm_setzero_si128();
            block = _mm_castpd_si128(
                // UBsan false positive; mem_addr can be unaligned.
                _mm_load_sd(CONST_DOUBLE_CAST(inBlocks)));

            if (xorInput)
            {
                block = _mm_xor_si128(block, _mm_castpd_si128(
                    // UBsan false positive; mem_addr can be unaligned.
                    _mm_load_sd(CONST_DOUBLE_CAST(xorBlocks))));
            }

            if (flags & BT_InBlockIsCounter)
                const_cast<byte *>(inBlocks)[7]++;

            func2(block, zero, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block = _mm_xor_si128(block, _mm_castpd_si128(
                    // UBsan false positive; mem_addr can be unaligned.
                    _mm_load_sd(CONST_DOUBLE_CAST(xorBlocks))));
            }

            // UBsan false positive; mem_addr can be unaligned.
            _mm_store_sd(DOUBLE_CAST(outBlocks), _mm_castsi128_pd(block));

            inBlocks += inIncrement;
            outBlocks += outIncrement;
            xorBlocks += xorIncrement;
            length -= blockSize;
        }
    }

    return length;
}

template <typename F2, typename F6>
inline size_t AdvancedProcessBlocks128_6x2_SSE(F2 func2, F6 func6,
        const word64 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 16);

    CRYPTOPP_ALIGN_DATA(16)
    const word32 s_one32x4[] = {0, 0, 0, 1<<24};

    const ptrdiff_t blockSize = 16;
    // const ptrdiff_t xmmBlockSize = 16;

    ptrdiff_t inIncrement = (flags & (BT_InBlockIsCounter|BT_DontIncrementInOutPointers)) ? 0 : blockSize;
    ptrdiff_t xorIncrement = (xorBlocks != NULLPTR) ? blockSize : 0;
    ptrdiff_t outIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : blockSize;

    // Clang and Coverity are generating findings using xorBlocks as a flag.
    const bool xorInput = (xorBlocks != NULLPTR) && (flags & BT_XorInput);
    const bool xorOutput = (xorBlocks != NULLPTR) && !(flags & BT_XorInput);

    if (flags & BT_ReverseDirection)
    {
        inBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        xorBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        outBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BT_AllowParallel)
    {
        while (length >= 6*blockSize)
        {
            __m128i block0, block1, block2, block3, block4, block5;
            if (flags & BT_InBlockIsCounter)
            {
                const __m128i be1 = *CONST_M128_CAST(s_one32x4);
                block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                block1 = _mm_add_epi32(block0, be1);
                block2 = _mm_add_epi32(block1, be1);
                block3 = _mm_add_epi32(block2, be1);
                block4 = _mm_add_epi32(block3, be1);
                block5 = _mm_add_epi32(block4, be1);
                _mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block5, be1));
            }
            else
            {
                block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block2 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block3 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block4 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block5 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = _mm_xor_si128(block4, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = _mm_xor_si128(block5, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block4 = _mm_xor_si128(block4, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block5 = _mm_xor_si128(block5, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            _mm_storeu_si128(M128_CAST(outBlocks), block0);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block1);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block2);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block3);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block4);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block5);
            outBlocks += outIncrement;

            length -= 6*blockSize;
        }

        while (length >= 2*blockSize)
        {
            __m128i block0, block1;
            if (flags & BT_InBlockIsCounter)
            {
                const __m128i be1 = *CONST_M128_CAST(s_one32x4);
                block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                block1 = _mm_add_epi32(block0, be1);
                _mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block1, be1));
            }
            else
            {
                block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func2(block0, block1, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            _mm_storeu_si128(M128_CAST(outBlocks), block0);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block1);
            outBlocks += outIncrement;

            length -= 2*blockSize;
        }
    }

    while (length >= blockSize)
    {
        __m128i block, zero = _mm_setzero_si128();
        block = _mm_loadu_si128(CONST_M128_CAST(inBlocks));

        if (xorInput)
            block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

        if (flags & BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func2(block, zero, subKeys, static_cast<unsigned int>(rounds));

        if (xorOutput)
            block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

        _mm_storeu_si128(M128_CAST(outBlocks), block);

        inBlocks += inIncrement;
        outBlocks += outIncrement;
        xorBlocks += xorIncrement;
        length -= blockSize;
    }

    return length;
}

template <typename F1, typename F4>
inline size_t AdvancedProcessBlocks128_4x1_SSE(F1 func1, F4 func4,
        MAYBE_CONST word32 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 16);

    CRYPTOPP_ALIGN_DATA(16)
    const word32 s_one32x4[] = {0, 0, 0, 1<<24};

    const ptrdiff_t blockSize = 16;
    // const ptrdiff_t xmmBlockSize = 16;

    ptrdiff_t inIncrement = (flags & (BT_InBlockIsCounter|BT_DontIncrementInOutPointers)) ? 0 : blockSize;
    ptrdiff_t xorIncrement = (xorBlocks != NULLPTR) ? blockSize : 0;
    ptrdiff_t outIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : blockSize;

    // Clang and Coverity are generating findings using xorBlocks as a flag.
    const bool xorInput = (xorBlocks != NULLPTR) && (flags & BT_XorInput);
    const bool xorOutput = (xorBlocks != NULLPTR) && !(flags & BT_XorInput);

    if (flags & BT_ReverseDirection)
    {
        inBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        xorBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        outBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BT_AllowParallel)
    {
        while (length >= 4*blockSize)
        {
            __m128i block0, block1, block2, block3;
            if (flags & BT_InBlockIsCounter)
            {
                const __m128i be1 = *CONST_M128_CAST(s_one32x4);
                block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                block1 = _mm_add_epi32(block0, be1);
                block2 = _mm_add_epi32(block1, be1);
                block3 = _mm_add_epi32(block2, be1);
                _mm_storeu_si128(M128_CAST(inBlocks), _mm_add_epi32(block3, be1));
            }
            else
            {
                block0 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block1 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block2 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
                block3 = _mm_loadu_si128(CONST_M128_CAST(inBlocks));
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            func4(block0, block1, block2, block3, subKeys, static_cast<unsigned int>(rounds));

            if (xorOutput)
            {
                block0 = _mm_xor_si128(block0, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block1 = _mm_xor_si128(block1, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block2 = _mm_xor_si128(block2, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
                block3 = _mm_xor_si128(block3, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));
                xorBlocks += xorIncrement;
            }

            _mm_storeu_si128(M128_CAST(outBlocks), block0);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block1);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block2);
            outBlocks += outIncrement;
            _mm_storeu_si128(M128_CAST(outBlocks), block3);
            outBlocks += outIncrement;

            length -= 4*blockSize;
        }
    }

    while (length >= blockSize)
    {
        __m128i block = _mm_loadu_si128(CONST_M128_CAST(inBlocks));

        if (xorInput)
            block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

        if (flags & BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func1(block, subKeys, static_cast<unsigned int>(rounds));

        if (xorOutput)
            block = _mm_xor_si128(block, _mm_loadu_si128(CONST_M128_CAST(xorBlocks)));

        _mm_storeu_si128(M128_CAST(outBlocks), block);

        inBlocks += inIncrement;
        outBlocks += outIncrement;
        xorBlocks += xorIncrement;
        length -= blockSize;
    }

    return length;
}

NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_SSSE3_AVAILABLE

// *********************** Altivec/Power 4 ********************** //

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)

NAMESPACE_BEGIN(CryptoPP)

template <typename F1, typename F6>
inline size_t AdvancedProcessBlocks128_6x1_ALTIVEC(F1 func1, F6 func6,
        const word32 *subKeys, size_t rounds, const byte *inBlocks,
        const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 16);

#if defined(CRYPTOPP_LITTLE_ENDIAN)
    const uint32x4_p s_one  = {1,0,0,0};
#else
    const uint32x4_p s_one = {0,0,0,1};
#endif

    const ptrdiff_t blockSize = 16;
    // const ptrdiff_t vexBlockSize = 16;

    ptrdiff_t inIncrement = (flags & (BT_InBlockIsCounter|BT_DontIncrementInOutPointers)) ? 0 : blockSize;
    ptrdiff_t xorIncrement = (xorBlocks != NULLPTR) ? blockSize : 0;
    ptrdiff_t outIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : blockSize;

    // Clang and Coverity are generating findings using xorBlocks as a flag.
    const bool xorInput = (xorBlocks != NULLPTR) && (flags & BT_XorInput);
    const bool xorOutput = (xorBlocks != NULLPTR) && !(flags & BT_XorInput);

    if (flags & BT_ReverseDirection)
    {
        inBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        xorBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        outBlocks += static_cast<ptrdiff_t>(length) - blockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BT_AllowParallel)
    {
        while (length >= 6*blockSize)
        {
            uint32x4_p block0, block1, block2, block3, block4, block5, temp;

            if (flags & BT_InBlockIsCounter)
            {
                block0 = VectorLoad(inBlocks);
                block1 = VectorAdd(block0, s_one);
                block2 = VectorAdd(block1, s_one);
                block3 = VectorAdd(block2, s_one);
                block4 = VectorAdd(block3, s_one);
                block5 = VectorAdd(block4, s_one);
                temp   = VectorAdd(block5, s_one);
                VectorStore(temp, const_cast<byte*>(inBlocks));
            }
            else
            {
                block0 = VectorLoad(inBlocks);
                inBlocks += inIncrement;
                block1 = VectorLoad(inBlocks);
                inBlocks += inIncrement;
                block2 = VectorLoad(inBlocks);
                inBlocks += inIncrement;
                block3 = VectorLoad(inBlocks);
                inBlocks += inIncrement;
                block4 = VectorLoad(inBlocks);
                inBlocks += inIncrement;
                block5 = VectorLoad(inBlocks);
                inBlocks += inIncrement;
            }

            if (xorInput)
            {
                block0 = VectorXor(block0, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block1 = VectorXor(block1, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block2 = VectorXor(block2, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block3 = VectorXor(block3, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block4 = VectorXor(block4, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block5 = VectorXor(block5, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, rounds);

            if (xorOutput)
            {
                block0 = VectorXor(block0, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block1 = VectorXor(block1, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block2 = VectorXor(block2, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block3 = VectorXor(block3, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block4 = VectorXor(block4, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
                block5 = VectorXor(block5, VectorLoad(xorBlocks));
                xorBlocks += xorIncrement;
            }

            VectorStore(block0, outBlocks);
            outBlocks += outIncrement;
            VectorStore(block1, outBlocks);
            outBlocks += outIncrement;
            VectorStore(block2, outBlocks);
            outBlocks += outIncrement;
            VectorStore(block3, outBlocks);
            outBlocks += outIncrement;
            VectorStore(block4, outBlocks);
            outBlocks += outIncrement;
            VectorStore(block5, outBlocks);
            outBlocks += outIncrement;

            length -= 6*blockSize;
        }
    }

    while (length >= blockSize)
    {
        uint32x4_p block = VectorLoad(inBlocks);

        if (xorInput)
            block = VectorXor(block, VectorLoad(xorBlocks));

        if (flags & BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func1(block, subKeys, rounds);

        if (xorOutput)
            block = VectorXor(block, VectorLoad(xorBlocks));

        VectorStore(block, outBlocks);

        inBlocks += inIncrement;
        outBlocks += outIncrement;
        xorBlocks += xorIncrement;
        length -= blockSize;
    }

    return length;
}

NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_ALTIVEC_AVAILABLE

#endif  // CRYPTOPP_ADVANCED_SIMD_TEMPLATES
