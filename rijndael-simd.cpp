// rijndael-simd.cpp - written and placed in the public domain by
//                     Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//                     AES-NI code originally written by Wei Dai.
//
//    This source file uses intrinsics and built-ins to gain access to
//    AES-NI, ARMv8a AES and Power8 AES instructions. A separate source
//    file is needed because additional CXXFLAGS are required to enable
//    the appropriate instructions sets in some build configurations.
//
//    ARMv8a AES code based on CriticalBlue code from Johannes Schneiders,
//    Skip Hovsmith and Barry O'Rourke for the mbedTLS project. Stepping
//    mbedTLS under a debugger was helped for us to determine problems
//    with our subkey generation and scheduling.
//
//    AltiVec and Power8 code based on http://github.com/noloader/AES-Intrinsics and
//    http://www.ibm.com/developerworks/library/se-power8-in-core-cryptography/
//    For Power8 do not remove the casts, even when const-ness is cast away. It causes
//    a 0.3 to 0.6 cpb drop in performance. The IBM documentation absolutely sucks.
//    Thanks to Andy Polyakov, Paul R and Trudeaun for answering questions and filling
//    the gaps in the IBM documentation.
//

#include "pch.h"
#include "config.h"
#include "misc.h"
#include "adv-simd.h"

// We set CRYPTOPP_ARM_AES_AVAILABLE based on compiler version.
// If the crypto is not available, then we have to disable it here.
#if !(defined(__ARM_FEATURE_CRYPTO) || defined(_MSC_VER))
# undef CRYPTOPP_ARM_AES_AVAILABLE
#endif

// We set CRYPTOPP_POWER8_CRYPTO_AVAILABLE based on compiler version.
// If the crypto is not available, then we have to disable it here.
#if !(defined(__CRYPTO) || defined(_ARCH_PWR8) || defined(_ARCH_PWR9))
# undef CRYPTOPP_POWER8_CRYPTO_AVAILABLE
# undef CRYPTOPP_POWER8_AES_AVAILABLE
#endif

#if (CRYPTOPP_AESNI_AVAILABLE)
# include <smmintrin.h>
# include <wmmintrin.h>
#endif

#if (CRYPTOPP_ARM_AES_AVAILABLE)
# include <arm_neon.h>
# if defined(CRYPTOPP_ARM_ACLE_AVAILABLE)
#  include <arm_acle.h>
# endif
#endif

#if defined(CRYPTOPP_POWER8_AES_AVAILABLE)
# include "ppc-simd.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

// Clang __m128i casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

NAMESPACE_BEGIN(CryptoPP)

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
extern "C" {
    typedef void (*SigHandler)(int);

    static jmp_buf s_jmpSIGILL;
    static void SigIllHandler(int)
    {
        longjmp(s_jmpSIGILL, 1);
    }
};
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARM64)
bool CPU_ProbeAES()
{
#if defined(CRYPTOPP_NO_CPU_FEATURE_PROBES)
    return false;
#elif (CRYPTOPP_ARM_AES_AVAILABLE)
# if defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    volatile bool result = true;
    __try
    {
        // AES encrypt and decrypt
        uint8x16_t data = vdupq_n_u8(0), key = vdupq_n_u8(0);
        uint8x16_t r1 = vaeseq_u8(data, key);
        uint8x16_t r2 = vaesdq_u8(data, key);
        r1 = vaesmcq_u8(r1);
        r2 = vaesimcq_u8(r2);

        result = !!(vgetq_lane_u8(r1,0) | vgetq_lane_u8(r2,7));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return result;
# else

    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
    volatile bool result = true;

    volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
    if (oldHandler == SIG_ERR)
        return false;

    volatile sigset_t oldMask;
    if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
        return false;

    if (setjmp(s_jmpSIGILL))
        result = false;
    else
    {
        uint8x16_t data = vdupq_n_u8(0), key = vdupq_n_u8(0);
        uint8x16_t r1 = vaeseq_u8(data, key);
        uint8x16_t r2 = vaesdq_u8(data, key);
        r1 = vaesmcq_u8(r1);
        r2 = vaesimcq_u8(r2);

        // Hack... GCC optimizes away the code and returns true
        result = !!(vgetq_lane_u8(r1,0) | vgetq_lane_u8(r2,7));
    }

    sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    signal(SIGILL, oldHandler);
    return result;
# endif
#else
    return false;
#endif  // CRYPTOPP_ARM_AES_AVAILABLE
}
#endif  // ARM32 or ARM64

// ***************************** ARMv8 ***************************** //

#if (CRYPTOPP_ARM_AES_AVAILABLE)

ANONYMOUS_NAMESPACE_BEGIN

static inline void ARMV8_Enc_Block(uint64x2_t &data, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(subkeys);
    const byte *keys = reinterpret_cast<const byte*>(subkeys);
    uint8x16_t block = vreinterpretq_u8_u64(data);

    // AES single round encryption
    block = vaeseq_u8(block, vld1q_u8(keys+0*16));
    // AES mix columns
    block = vaesmcq_u8(block);

    for (unsigned int i=1; i<rounds-1; i+=2)
    {
        // AES single round encryption
        block = vaeseq_u8(block, vld1q_u8(keys+i*16));
        // AES mix columns
        block = vaesmcq_u8(block);
        // AES single round encryption
        block = vaeseq_u8(block, vld1q_u8(keys+(i+1)*16));
        // AES mix columns
        block = vaesmcq_u8(block);
    }

    // AES single round encryption
    block = vaeseq_u8(block, vld1q_u8(keys+(rounds-1)*16));
    // Final Add (bitwise Xor)
    block = veorq_u8(block, vld1q_u8(keys+rounds*16));

    data = vreinterpretq_u64_u8(block);
}

static inline void ARMV8_Enc_6_Blocks(uint64x2_t &data0, uint64x2_t &data1,
    uint64x2_t &data2, uint64x2_t &data3, uint64x2_t &data4, uint64x2_t &data5,
    const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(subkeys);
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    uint8x16_t block0 = vreinterpretq_u8_u64(data0);
    uint8x16_t block1 = vreinterpretq_u8_u64(data1);
    uint8x16_t block2 = vreinterpretq_u8_u64(data2);
    uint8x16_t block3 = vreinterpretq_u8_u64(data3);
    uint8x16_t block4 = vreinterpretq_u8_u64(data4);
    uint8x16_t block5 = vreinterpretq_u8_u64(data5);

    uint8x16_t key;
    for (unsigned int i=0; i<rounds-1; ++i)
    {
        uint8x16_t key = vld1q_u8(keys+i*16);
        // AES single round encryption
        block0 = vaeseq_u8(block0, key);
        // AES mix columns
        block0 = vaesmcq_u8(block0);
        // AES single round encryption
        block1 = vaeseq_u8(block1, key);
        // AES mix columns
        block1 = vaesmcq_u8(block1);
        // AES single round encryption
        block2 = vaeseq_u8(block2, key);
        // AES mix columns
        block2 = vaesmcq_u8(block2);
        // AES single round encryption
        block3 = vaeseq_u8(block3, key);
        // AES mix columns
        block3 = vaesmcq_u8(block3);
        // AES single round encryption
        block4 = vaeseq_u8(block4, key);
        // AES mix columns
        block4 = vaesmcq_u8(block4);
        // AES single round encryption
        block5 = vaeseq_u8(block5, key);
        // AES mix columns
        block5 = vaesmcq_u8(block5);
    }

    // AES single round encryption
    key = vld1q_u8(keys+(rounds-1)*16);
    block0 = vaeseq_u8(block0, key);
    block1 = vaeseq_u8(block1, key);
    block2 = vaeseq_u8(block2, key);
    block3 = vaeseq_u8(block3, key);
    block4 = vaeseq_u8(block4, key);
    block5 = vaeseq_u8(block5, key);

    // Final Add (bitwise Xor)
    key = vld1q_u8(keys+rounds*16);
    data0 = vreinterpretq_u64_u8(veorq_u8(block0, key));
    data1 = vreinterpretq_u64_u8(veorq_u8(block1, key));
    data2 = vreinterpretq_u64_u8(veorq_u8(block2, key));
    data3 = vreinterpretq_u64_u8(veorq_u8(block3, key));
    data4 = vreinterpretq_u64_u8(veorq_u8(block4, key));
    data5 = vreinterpretq_u64_u8(veorq_u8(block5, key));
}

static inline void ARMV8_Dec_Block(uint64x2_t &data, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(subkeys);
    const byte *keys = reinterpret_cast<const byte*>(subkeys);
    uint8x16_t block = vreinterpretq_u8_u64(data);

    // AES single round decryption
    block = vaesdq_u8(block, vld1q_u8(keys+0*16));
    // AES inverse mix columns
    block = vaesimcq_u8(block);

    for (unsigned int i=1; i<rounds-1; i+=2)
    {
        // AES single round decryption
        block = vaesdq_u8(block, vld1q_u8(keys+i*16));
        // AES inverse mix columns
        block = vaesimcq_u8(block);
        // AES single round decryption
        block = vaesdq_u8(block, vld1q_u8(keys+(i+1)*16));
        // AES inverse mix columns
        block = vaesimcq_u8(block);
    }

    // AES single round decryption
    block = vaesdq_u8(block, vld1q_u8(keys+(rounds-1)*16));
    // Final Add (bitwise Xor)
    block = veorq_u8(block, vld1q_u8(keys+rounds*16));

    data = vreinterpretq_u64_u8(block);
}

static inline void ARMV8_Dec_6_Blocks(uint64x2_t &data0, uint64x2_t &data1,
    uint64x2_t &data2, uint64x2_t &data3, uint64x2_t &data4, uint64x2_t &data5,
    const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(subkeys);
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    uint8x16_t block0 = vreinterpretq_u8_u64(data0);
    uint8x16_t block1 = vreinterpretq_u8_u64(data1);
    uint8x16_t block2 = vreinterpretq_u8_u64(data2);
    uint8x16_t block3 = vreinterpretq_u8_u64(data3);
    uint8x16_t block4 = vreinterpretq_u8_u64(data4);
    uint8x16_t block5 = vreinterpretq_u8_u64(data5);

    uint8x16_t key;
    for (unsigned int i=0; i<rounds-1; ++i)
    {
        key = vld1q_u8(keys+i*16);
        // AES single round decryption
        block0 = vaesdq_u8(block0, key);
        // AES inverse mix columns
        block0 = vaesimcq_u8(block0);
        // AES single round decryption
        block1 = vaesdq_u8(block1, key);
        // AES inverse mix columns
        block1 = vaesimcq_u8(block1);
        // AES single round decryption
        block2 = vaesdq_u8(block2, key);
        // AES inverse mix columns
        block2 = vaesimcq_u8(block2);
        // AES single round decryption
        block3 = vaesdq_u8(block3, key);
        // AES inverse mix columns
        block3 = vaesimcq_u8(block3);
        // AES single round decryption
        block4 = vaesdq_u8(block4, key);
        // AES inverse mix columns
        block4 = vaesimcq_u8(block4);
        // AES single round decryption
        block5 = vaesdq_u8(block5, key);
        // AES inverse mix columns
        block5 = vaesimcq_u8(block5);
    }

    // AES single round decryption
    key = vld1q_u8(keys+(rounds-1)*16);
    block0 = vaesdq_u8(block0, key);
    block1 = vaesdq_u8(block1, key);
    block2 = vaesdq_u8(block2, key);
    block3 = vaesdq_u8(block3, key);
    block4 = vaesdq_u8(block4, key);
    block5 = vaesdq_u8(block5, key);

    // Final Add (bitwise Xor)
    key = vld1q_u8(keys+rounds*16);
    data0 = vreinterpretq_u64_u8(veorq_u8(block0, key));
    data1 = vreinterpretq_u64_u8(veorq_u8(block1, key));
    data2 = vreinterpretq_u64_u8(veorq_u8(block2, key));
    data3 = vreinterpretq_u64_u8(veorq_u8(block3, key));
    data4 = vreinterpretq_u64_u8(veorq_u8(block4, key));
    data5 = vreinterpretq_u64_u8(veorq_u8(block5, key));
}

ANONYMOUS_NAMESPACE_END

size_t Rijndael_Enc_AdvancedProcessBlocks_ARMV8(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_NEON1x6(ARMV8_Enc_Block, ARMV8_Enc_6_Blocks,
            subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_ARMV8(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_NEON1x6(ARMV8_Dec_Block, ARMV8_Dec_6_Blocks,
            subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

#endif  // CRYPTOPP_ARM_AES_AVAILABLE

// ***************************** AES-NI ***************************** //

#if (CRYPTOPP_AESNI_AVAILABLE)

ANONYMOUS_NAMESPACE_BEGIN

/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
CRYPTOPP_ALIGN_DATA(16)
const word32 s_rconLE[] = {
    0x01, 0x02, 0x04, 0x08,    0x10, 0x20, 0x40, 0x80,    0x1B, 0x36
};

static inline void AESNI_Enc_Block(__m128i &block, MAYBE_CONST word32 *subkeys, unsigned int rounds)
{
    const __m128i* skeys = reinterpret_cast<const __m128i*>(subkeys);

    block = _mm_xor_si128(block, skeys[0]);
    for (unsigned int i=1; i<rounds-1; i+=2)
    {
        block = _mm_aesenc_si128(block, skeys[i]);
        block = _mm_aesenc_si128(block, skeys[i+1]);
    }
    block = _mm_aesenc_si128(block, skeys[rounds-1]);
    block = _mm_aesenclast_si128(block, skeys[rounds]);
}

static inline void AESNI_Enc_4_Blocks(__m128i &block0, __m128i &block1, __m128i &block2, __m128i &block3,
                               MAYBE_CONST word32 *subkeys, unsigned int rounds)
{
    const __m128i* skeys = reinterpret_cast<const __m128i*>(subkeys);

    __m128i rk = skeys[0];
    block0 = _mm_xor_si128(block0, rk);
    block1 = _mm_xor_si128(block1, rk);
    block2 = _mm_xor_si128(block2, rk);
    block3 = _mm_xor_si128(block3, rk);
    for (unsigned int i=1; i<rounds; i++)
    {
        rk = skeys[i];
        block0 = _mm_aesenc_si128(block0, rk);
        block1 = _mm_aesenc_si128(block1, rk);
        block2 = _mm_aesenc_si128(block2, rk);
        block3 = _mm_aesenc_si128(block3, rk);
    }
    rk = skeys[rounds];
    block0 = _mm_aesenclast_si128(block0, rk);
    block1 = _mm_aesenclast_si128(block1, rk);
    block2 = _mm_aesenclast_si128(block2, rk);
    block3 = _mm_aesenclast_si128(block3, rk);
}

static inline void AESNI_Dec_Block(__m128i &block, MAYBE_CONST word32 *subkeys, unsigned int rounds)
{
    const __m128i* skeys = reinterpret_cast<const __m128i*>(subkeys);

    block = _mm_xor_si128(block, skeys[0]);
    for (unsigned int i=1; i<rounds-1; i+=2)
    {
        block = _mm_aesdec_si128(block, skeys[i]);
        block = _mm_aesdec_si128(block, skeys[i+1]);
    }
    block = _mm_aesdec_si128(block, skeys[rounds-1]);
    block = _mm_aesdeclast_si128(block, skeys[rounds]);
}

static inline void AESNI_Dec_4_Blocks(__m128i &block0, __m128i &block1, __m128i &block2, __m128i &block3,
                        MAYBE_CONST word32 *subkeys, unsigned int rounds)
{
    const __m128i* skeys = reinterpret_cast<const __m128i*>(subkeys);

    __m128i rk = skeys[0];
    block0 = _mm_xor_si128(block0, rk);
    block1 = _mm_xor_si128(block1, rk);
    block2 = _mm_xor_si128(block2, rk);
    block3 = _mm_xor_si128(block3, rk);
    for (unsigned int i=1; i<rounds; i++)
    {
        rk = skeys[i];
        block0 = _mm_aesdec_si128(block0, rk);
        block1 = _mm_aesdec_si128(block1, rk);
        block2 = _mm_aesdec_si128(block2, rk);
        block3 = _mm_aesdec_si128(block3, rk);
    }
    rk = skeys[rounds];
    block0 = _mm_aesdeclast_si128(block0, rk);
    block1 = _mm_aesdeclast_si128(block1, rk);
    block2 = _mm_aesdeclast_si128(block2, rk);
    block3 = _mm_aesdeclast_si128(block3, rk);
}

ANONYMOUS_NAMESPACE_END

void Rijndael_UncheckedSetKey_SSE4_AESNI(const byte *userKey, size_t keyLen, word32 *rk, unsigned int rounds)
{
    const word32 *rc = s_rconLE;

    __m128i temp = _mm_loadu_si128(M128_CAST(userKey+keyLen-16));
    std::memcpy(rk, userKey, keyLen);

    // keySize: m_key allocates 4*(rounds+1) word32's.
    const size_t keySize = 4*(rounds+1);
    const word32* end = rk + keySize;

    while (true)
    {
        rk[keyLen/4] = rk[0] ^ _mm_extract_epi32(_mm_aeskeygenassist_si128(temp, 0), 3) ^ *(rc++);
        rk[keyLen/4+1] = rk[1] ^ rk[keyLen/4];
        rk[keyLen/4+2] = rk[2] ^ rk[keyLen/4+1];
        rk[keyLen/4+3] = rk[3] ^ rk[keyLen/4+2];

        if (rk + keyLen/4 + 4 == end)
            break;

        if (keyLen == 24)
        {
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            temp = _mm_insert_epi32(temp, rk[11], 3);
        }
        else if (keyLen == 32)
        {
            temp = _mm_insert_epi32(temp, rk[11], 3);
            rk[12] = rk[ 4] ^ _mm_extract_epi32(_mm_aeskeygenassist_si128(temp, 0), 2);
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];
            temp = _mm_insert_epi32(temp, rk[15], 3);
        }
        else
        {
            temp = _mm_insert_epi32(temp, rk[7], 3);
        }

        rk += keyLen/4;
    }
}

void Rijndael_UncheckedSetKeyRev_AESNI(word32 *key, unsigned int rounds)
{
    unsigned int i, j;
    __m128i temp;

    vec_swap(*M128_CAST(key), *M128_CAST(key+4*rounds));

    for (i = 4, j = 4*rounds-4; i < j; i += 4, j -= 4)
    {
        temp = _mm_aesimc_si128(*M128_CAST(key+i));
        *M128_CAST(key+i) = _mm_aesimc_si128(*M128_CAST(key+j));
        *M128_CAST(key+j) = temp;
    }

    *M128_CAST(key+i) = _mm_aesimc_si128(*M128_CAST(key+i));
}

size_t Rijndael_Enc_AdvancedProcessBlocks_AESNI(const word32 *subKeys, size_t rounds,
        const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    // SunCC workaround
    MAYBE_CONST word32* sk = MAYBE_UNCONST_CAST(word32*, subKeys);
    MAYBE_CONST   byte* ib = MAYBE_UNCONST_CAST(byte*,  inBlocks);
    MAYBE_CONST   byte* xb = MAYBE_UNCONST_CAST(byte*, xorBlocks);

    return AdvancedProcessBlocks128_SSE1x4(AESNI_Enc_Block, AESNI_Enc_4_Blocks,
                sk, rounds, ib, xb, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_AESNI(const word32 *subKeys, size_t rounds,
        const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    MAYBE_CONST word32* sk = MAYBE_UNCONST_CAST(word32*, subKeys);
    MAYBE_CONST   byte* ib = MAYBE_UNCONST_CAST(byte*,  inBlocks);
    MAYBE_CONST   byte* xb = MAYBE_UNCONST_CAST(byte*, xorBlocks);

    return AdvancedProcessBlocks128_SSE1x4(AESNI_Dec_Block, AESNI_Dec_4_Blocks,
                sk, rounds, ib, xb, outBlocks, length, flags);
}

#endif  // CRYPTOPP_AESNI_AVAILABLE

// ***************************** Power 8 ***************************** //

#if (CRYPTOPP_POWER8_AES_AVAILABLE)

ANONYMOUS_NAMESPACE_BEGIN

/* Round constants */
static const uint32_t s_rcon[3][4] = {
#if defined(CRYPTOPP_LITTLE_ENDIAN)
    {0x01,0x01,0x01,0x01},   /*  1 */
    {0x1b,0x1b,0x1b,0x1b},   /*  9 */
    {0x36,0x36,0x36,0x36}    /* 10 */
#else
    {0x01000000,0x01000000,0x01000000,0x01000000},  /*  1 */
    {0x1b000000,0x1b000000,0x1b000000,0x1b000000},  /*  9 */
    {0x36000000,0x36000000,0x36000000,0x36000000}   /* 10 */
#endif
};

/* Permute mask */
static const uint32_t s_mask[4] = {
#if defined(CRYPTOPP_LITTLE_ENDIAN)
    0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d
#else
    0x0d0e0f0c,0x0d0e0f0c,0x0d0e0f0c,0x0d0e0f0c
#endif
};

static inline uint8x16_p
Rijndael_Subkey_POWER8(uint8x16_p r1, const uint8x16_p r4, const uint8x16_p r5)
{
    // Big endian: vec_sld(a, b, c)
    // Little endian: vec_sld(b, a, 16-c)

    const uint8x16_p r0 = {0};
    uint8x16_p r3, r6;

    r3 = VectorPermute(r1, r1, r5);     /* line  1 */
    r6 = VectorShiftLeft<12>(r0, r1);   /* line  2 */
    r3 = VectorEncryptLast(r3, r4);     /* line  3 */

    r1 = VectorXor(r1, r6);             /* line  4 */
    r6 = VectorShiftLeft<12>(r0, r1);   /* line  5 */
    r1 = VectorXor(r1, r6);             /* line  6 */
    r6 = VectorShiftLeft<12>(r0, r1);   /* line  7 */
    r1 = VectorXor(r1, r6);             /* line  8 */

    // Caller handles r4 (rcon) addition
    // r4 = VectorAdd(r4, r4);          /* line  9 */

    // r1 is ready for next round
    r1 = VectorXor(r1, r3);             /* line 10 */
    return r1;
}

static inline uint8_t*
IncrementPointerAndStore(const uint8x16_p& r, uint8_t* p)
{
    VectorStore(r, (p += 16));
    return p;
}

static inline void POWER8_Enc_Block(VectorType &block, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    VectorType k = VectorLoadKey(keys);
    block = VectorXor(block, k);

    for (size_t i=1; i<rounds-1; i+=2)
    {
        block = VectorEncrypt(block, VectorLoadKey(  i*16,   keys));
        block = VectorEncrypt(block, VectorLoadKey((i+1)*16, keys));
    }

    block = VectorEncrypt(block, VectorLoadKey((rounds-1)*16, keys));
    block = VectorEncryptLast(block, VectorLoadKey(rounds*16, keys));
}

static inline void POWER8_Enc_6_Blocks(VectorType &block0, VectorType &block1,
            VectorType &block2, VectorType &block3, VectorType &block4,
            VectorType &block5, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    VectorType k = VectorLoadKey(keys);
    block0 = VectorXor(block0, k);
    block1 = VectorXor(block1, k);
    block2 = VectorXor(block2, k);
    block3 = VectorXor(block3, k);
    block4 = VectorXor(block4, k);
    block5 = VectorXor(block5, k);

    for (size_t i=1; i<rounds; ++i)
    {
        k = VectorLoadKey(i*16, keys);
        block0 = VectorEncrypt(block0, k);
        block1 = VectorEncrypt(block1, k);
        block2 = VectorEncrypt(block2, k);
        block3 = VectorEncrypt(block3, k);
        block4 = VectorEncrypt(block4, k);
        block5 = VectorEncrypt(block5, k);
    }

    k = VectorLoadKey(rounds*16, keys);
    block0 = VectorEncryptLast(block0, k);
    block1 = VectorEncryptLast(block1, k);
    block2 = VectorEncryptLast(block2, k);
    block3 = VectorEncryptLast(block3, k);
    block4 = VectorEncryptLast(block4, k);
    block5 = VectorEncryptLast(block5, k);
}

static inline void POWER8_Dec_Block(VectorType &block, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    VectorType k = VectorLoadKey(rounds*16, keys);
    block = VectorXor(block, k);

    for (size_t i=rounds-1; i>1; i-=2)
    {
        block = VectorDecrypt(block, VectorLoadKey(  i*16,   keys));
        block = VectorDecrypt(block, VectorLoadKey((i-1)*16, keys));
    }

    block = VectorDecrypt(block, VectorLoadKey(16, keys));
    block = VectorDecryptLast(block, VectorLoadKey(0, keys));
}

static inline void POWER8_Dec_6_Blocks(VectorType &block0, VectorType &block1,
            VectorType &block2, VectorType &block3, VectorType &block4,
            VectorType &block5, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    VectorType k = VectorLoadKey(rounds*16, keys);
    block0 = VectorXor(block0, k);
    block1 = VectorXor(block1, k);
    block2 = VectorXor(block2, k);
    block3 = VectorXor(block3, k);
    block4 = VectorXor(block4, k);
    block5 = VectorXor(block5, k);

    for (size_t i=rounds-1; i>0; --i)
    {
        k = VectorLoadKey(i*16, keys);
        block0 = VectorDecrypt(block0, k);
        block1 = VectorDecrypt(block1, k);
        block2 = VectorDecrypt(block2, k);
        block3 = VectorDecrypt(block3, k);
        block4 = VectorDecrypt(block4, k);
        block5 = VectorDecrypt(block5, k);
    }

    k = VectorLoadKey(0, keys);
    block0 = VectorDecryptLast(block0, k);
    block1 = VectorDecryptLast(block1, k);
    block2 = VectorDecryptLast(block2, k);
    block3 = VectorDecryptLast(block3, k);
    block4 = VectorDecryptLast(block4, k);
    block5 = VectorDecryptLast(block5, k);
}

template <typename F1, typename F6>
size_t Rijndael_AdvancedProcessBlocks_POWER8(F1 func1, F6 func6, const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    CRYPTOPP_ASSERT(subKeys);
    CRYPTOPP_ASSERT(inBlocks);
    CRYPTOPP_ASSERT(outBlocks);
    CRYPTOPP_ASSERT(length >= 16);

    const size_t blockSize = 16;
    size_t inIncrement = (flags & (BlockTransformation::BT_InBlockIsCounter|BlockTransformation::BT_DontIncrementInOutPointers)) ? 0 : blockSize;
    size_t xorIncrement = xorBlocks ? blockSize : 0;
    size_t outIncrement = (flags & BlockTransformation::BT_DontIncrementInOutPointers) ? 0 : blockSize;

    if (flags & BlockTransformation::BT_ReverseDirection)
    {
        inBlocks += length - blockSize;
        xorBlocks += length - blockSize;
        outBlocks += length - blockSize;
        inIncrement = 0-inIncrement;
        xorIncrement = 0-xorIncrement;
        outIncrement = 0-outIncrement;
    }

    if (flags & BlockTransformation::BT_AllowParallel)
    {
        while (length >= 6*blockSize)
        {
#if defined(CRYPTOPP_LITTLE_ENDIAN)
            const VectorType one = (VectorType)((uint64x2_p){1,0});
#else
            const VectorType one = (VectorType)((uint64x2_p){0,1});
#endif

            VectorType block0, block1, block2, block3, block4, block5, temp;
            block0 = VectorLoad(inBlocks);

            if (flags & BlockTransformation::BT_InBlockIsCounter)
            {
                block1 = VectorAdd(block0, one);
                block2 = VectorAdd(block1, one);
                block3 = VectorAdd(block2, one);
                block4 = VectorAdd(block3, one);
                block5 = VectorAdd(block4, one);
                temp   = VectorAdd(block5, one);
                VectorStore(temp, const_cast<byte*>(inBlocks));
            }
            else
            {
                const int inc = static_cast<int>(inIncrement);
                block1 = VectorLoad(1*inc, inBlocks);
                block2 = VectorLoad(2*inc, inBlocks);
                block3 = VectorLoad(3*inc, inBlocks);
                block4 = VectorLoad(4*inc, inBlocks);
                block5 = VectorLoad(5*inc, inBlocks);
                inBlocks += 6*inc;
            }

            if (flags & BlockTransformation::BT_XorInput)
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = VectorXor(block0, VectorLoad(0*inc, xorBlocks));
                block1 = VectorXor(block1, VectorLoad(1*inc, xorBlocks));
                block2 = VectorXor(block2, VectorLoad(2*inc, xorBlocks));
                block3 = VectorXor(block3, VectorLoad(3*inc, xorBlocks));
                block4 = VectorXor(block4, VectorLoad(4*inc, xorBlocks));
                block5 = VectorXor(block5, VectorLoad(5*inc, xorBlocks));
                xorBlocks += 6*inc;
            }

            func6(block0, block1, block2, block3, block4, block5, subKeys, rounds);

            if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            {
                const int inc = static_cast<int>(xorIncrement);
                block0 = VectorXor(block0, VectorLoad(0*inc, xorBlocks));
                block1 = VectorXor(block1, VectorLoad(1*inc, xorBlocks));
                block2 = VectorXor(block2, VectorLoad(2*inc, xorBlocks));
                block3 = VectorXor(block3, VectorLoad(3*inc, xorBlocks));
                block4 = VectorXor(block4, VectorLoad(4*inc, xorBlocks));
                block5 = VectorXor(block5, VectorLoad(5*inc, xorBlocks));
                xorBlocks += 6*inc;
            }

            const int inc = static_cast<int>(outIncrement);
            VectorStore(block0, outBlocks+0*inc);
            VectorStore(block1, outBlocks+1*inc);
            VectorStore(block2, outBlocks+2*inc);
            VectorStore(block3, outBlocks+3*inc);
            VectorStore(block4, outBlocks+4*inc);
            VectorStore(block5, outBlocks+5*inc);

            outBlocks += 6*inc;
            length -= 6*blockSize;
        }
    }

    while (length >= blockSize)
    {
        VectorType block = VectorLoad(inBlocks);

        if (flags & BlockTransformation::BT_XorInput)
            block = VectorXor(block, VectorLoad(xorBlocks));

        if (flags & BlockTransformation::BT_InBlockIsCounter)
            const_cast<byte *>(inBlocks)[15]++;

        func1(block, subKeys, rounds);

        if (xorBlocks && !(flags & BlockTransformation::BT_XorInput))
            block = VectorXor(block, VectorLoad(xorBlocks));

        VectorStore(block, outBlocks);

        inBlocks += inIncrement;
        outBlocks += outIncrement;
        xorBlocks += xorIncrement;
        length -= blockSize;
    }

    return length;
}

ANONYMOUS_NAMESPACE_END

// We still need rcon and Se to fallback to C/C++ for AES-192 and AES-256.
// The IBM docs on AES sucks. Intel's docs on AESNI puts IBM to shame.
void Rijndael_UncheckedSetKey_POWER8(const byte* userKey, size_t keyLen, word32* rk,
                                     const word32* rc, const byte* Se)
{
    const size_t rounds = keyLen / 4 + 6;
    if (keyLen == 16)
    {
        std::memcpy(rk, userKey, keyLen);
        uint8_t* skptr = (uint8_t*)rk;

        uint8x16_p r1 = (uint8x16_p)VectorLoadKey(skptr);
        uint8x16_p r4 = (uint8x16_p)VectorLoadKey(s_rcon[0]);
        uint8x16_p r5 = (uint8x16_p)VectorLoadKey(s_mask);

#if defined(CRYPTOPP_LITTLE_ENDIAN)
        // Only the user key requires byte reversing.
        // The subkeys are stored in proper endianess.
        ReverseByteArrayLE(skptr);
#endif

        for (unsigned int i=0; i<rounds-2; ++i)
        {
            r1 = Rijndael_Subkey_POWER8(r1, r4, r5);
            r4 = vec_add(r4, r4);
            skptr = IncrementPointerAndStore(r1, skptr);
        }

        /* Round 9 using rcon=0x1b */
        r4 = (uint8x16_p)VectorLoadKey(s_rcon[1]);
        r1 = Rijndael_Subkey_POWER8(r1, r4, r5);
        skptr = IncrementPointerAndStore(r1, skptr);

        /* Round 10 using rcon=0x36 */
        r4 = (uint8x16_p)VectorLoadKey(s_rcon[2]);
        r1 = Rijndael_Subkey_POWER8(r1, r4, r5);
        skptr = IncrementPointerAndStore(r1, skptr);
    }
    else
    {
        GetUserKey(BIG_ENDIAN_ORDER, rk, keyLen/4, userKey, keyLen);
        word32 *rk_saved = rk, temp;

        // keySize: m_key allocates 4*(rounds+1) word32's.
        const size_t keySize = 4*(rounds+1);
        const word32* end = rk + keySize;

        while (true)
        {
            temp  = rk[keyLen/4-1];
            word32 x = (word32(Se[GETBYTE(temp, 2)]) << 24) ^ (word32(Se[GETBYTE(temp, 1)]) << 16) ^
                        (word32(Se[GETBYTE(temp, 0)]) << 8) ^ Se[GETBYTE(temp, 3)];
            rk[keyLen/4] = rk[0] ^ x ^ *(rc++);
            rk[keyLen/4+1] = rk[1] ^ rk[keyLen/4];
            rk[keyLen/4+2] = rk[2] ^ rk[keyLen/4+1];
            rk[keyLen/4+3] = rk[3] ^ rk[keyLen/4+2];

            if (rk + keyLen/4 + 4 == end)
                break;

            if (keyLen == 24)
            {
                rk[10] = rk[ 4] ^ rk[ 9];
                rk[11] = rk[ 5] ^ rk[10];
            }
            else if (keyLen == 32)
            {
                temp = rk[11];
                rk[12] = rk[ 4] ^ (word32(Se[GETBYTE(temp, 3)]) << 24) ^ (word32(Se[GETBYTE(temp, 2)]) << 16) ^ (word32(Se[GETBYTE(temp, 1)]) << 8) ^ Se[GETBYTE(temp, 0)];
                rk[13] = rk[ 5] ^ rk[12];
                rk[14] = rk[ 6] ^ rk[13];
                rk[15] = rk[ 7] ^ rk[14];
            }
            rk += keyLen/4;
        }

#if defined(CRYPTOPP_LITTLE_ENDIAN)
        rk = rk_saved;
        const uint8x16_p mask = ((uint8x16_p){12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3});
        const uint8x16_p zero = {0};

        unsigned int i=0;
        for (i=0; i<rounds; i+=2, rk+=8)
        {
            uint8x16_p d1 = vec_vsx_ld( 0, (uint8_t*)rk);
            uint8x16_p d2 = vec_vsx_ld(16, (uint8_t*)rk);
            d1 = vec_perm(d1, zero, mask);
            d2 = vec_perm(d2, zero, mask);
            vec_vsx_st(d1,  0, (uint8_t*)rk);
            vec_vsx_st(d2, 16, (uint8_t*)rk);
        }

        for ( ; i<rounds+1; i++, rk+=4)
            vec_vsx_st(vec_perm(vec_vsx_ld(0, (uint8_t*)rk), zero, mask), 0, (uint8_t*)rk);
#endif
    }
}

size_t Rijndael_Enc_AdvancedProcessBlocks_POWER8(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return Rijndael_AdvancedProcessBlocks_POWER8(POWER8_Enc_Block, POWER8_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_POWER8(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return Rijndael_AdvancedProcessBlocks_POWER8(POWER8_Dec_Block, POWER8_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

#endif  // CRYPTOPP_POWER8_AES_AVAILABLE
NAMESPACE_END
