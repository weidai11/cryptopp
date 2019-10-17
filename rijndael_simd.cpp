// rijndael_simd.cpp - written and placed in the public domain by
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
//    failed compiles and a 0.3 to 0.6 cpb drop in performance. The IBM documentation
//    absolutely sucks. Thanks to Andy Polyakov, Paul R and Trudeaun for answering
//    questions and filling the gaps in the IBM documentation.
//

#include "pch.h"
#include "config.h"
#include "misc.h"

#if (CRYPTOPP_AESNI_AVAILABLE)
# include "adv_simd.h"
# include <emmintrin.h>
# include <smmintrin.h>
# include <wmmintrin.h>
#endif

#if (CRYPTOPP_ARM_NEON_HEADER)
# include "adv_simd.h"
# include <arm_neon.h>
#endif

#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

#if defined(_M_ARM64)
# include "adv_simd.h"
#endif

#if defined(CRYPTOPP_POWER8_AES_AVAILABLE)
# include "adv_simd.h"
# include "ppc_simd.h"
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

// Clang intrinsic casts, http://bugs.llvm.org/show_bug.cgi?id=20670
#define M128_CAST(x) ((__m128i *)(void *)(x))
#define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))

// Squash MS LNK4221 and libtool warnings
extern const char RIJNDAEL_SIMD_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

// ************************* Feature Probes ************************* //

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
extern "C" {
    typedef void (*SigHandler)(int);

    static jmp_buf s_jmpSIGILL;
    static void SigIllHandler(int)
    {
        longjmp(s_jmpSIGILL, 1);
    }
}
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARMV8)
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
        key = vld1q_u8(keys+i*16);
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
    return AdvancedProcessBlocks128_6x1_NEON(ARMV8_Enc_Block, ARMV8_Enc_6_Blocks,
            subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_ARMV8(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_6x1_NEON(ARMV8_Dec_Block, ARMV8_Dec_6_Blocks,
            subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

#endif  // CRYPTOPP_ARM_AES_AVAILABLE

// ***************************** AES-NI ***************************** //

#if (CRYPTOPP_AESNI_AVAILABLE)

ANONYMOUS_NAMESPACE_BEGIN

/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
CRYPTOPP_ALIGN_DATA(16)
const word32 s_rconLE[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
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

void Rijndael_UncheckedSetKey_SSE4_AESNI(const byte *userKey, size_t keyLen, word32 *rk)
{
    const size_t rounds = keyLen / 4 + 6;
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

    return AdvancedProcessBlocks128_4x1_SSE(AESNI_Enc_Block, AESNI_Enc_4_Blocks,
                sk, rounds, ib, xb, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks_AESNI(const word32 *subKeys, size_t rounds,
        const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    MAYBE_CONST word32* sk = MAYBE_UNCONST_CAST(word32*, subKeys);
    MAYBE_CONST   byte* ib = MAYBE_UNCONST_CAST(byte*,  inBlocks);
    MAYBE_CONST   byte* xb = MAYBE_UNCONST_CAST(byte*, xorBlocks);

    return AdvancedProcessBlocks128_4x1_SSE(AESNI_Dec_Block, AESNI_Dec_4_Blocks,
                sk, rounds, ib, xb, outBlocks, length, flags);
}

#endif  // CRYPTOPP_AESNI_AVAILABLE

// ************************** Power 8 Crypto ************************** //

#if (CRYPTOPP_POWER8_AES_AVAILABLE)

ANONYMOUS_NAMESPACE_BEGIN

/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
CRYPTOPP_ALIGN_DATA(16)
static const uint32_t s_rconBE[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

static inline void POWER8_Enc_Block(uint32x4_p &block, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    uint32x4_p k = VecLoad(keys);
    block = VecXor(block, k);

    for (size_t i=1; i<rounds-1; i+=2)
    {
        block = VecEncrypt(block, VecLoad(  i*16,   keys));
        block = VecEncrypt(block, VecLoad((i+1)*16, keys));
    }

    block = VecEncrypt(block, VecLoad((rounds-1)*16, keys));
    block = VecEncryptLast(block, VecLoad(rounds*16, keys));
}

static inline void POWER8_Enc_6_Blocks(uint32x4_p &block0, uint32x4_p &block1,
            uint32x4_p &block2, uint32x4_p &block3, uint32x4_p &block4,
            uint32x4_p &block5, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    uint32x4_p k = VecLoad(keys);
    block0 = VecXor(block0, k);
    block1 = VecXor(block1, k);
    block2 = VecXor(block2, k);
    block3 = VecXor(block3, k);
    block4 = VecXor(block4, k);
    block5 = VecXor(block5, k);

    for (size_t i=1; i<rounds; ++i)
    {
        k = VecLoad(i*16, keys);
        block0 = VecEncrypt(block0, k);
        block1 = VecEncrypt(block1, k);
        block2 = VecEncrypt(block2, k);
        block3 = VecEncrypt(block3, k);
        block4 = VecEncrypt(block4, k);
        block5 = VecEncrypt(block5, k);
    }

    k = VecLoad(rounds*16, keys);
    block0 = VecEncryptLast(block0, k);
    block1 = VecEncryptLast(block1, k);
    block2 = VecEncryptLast(block2, k);
    block3 = VecEncryptLast(block3, k);
    block4 = VecEncryptLast(block4, k);
    block5 = VecEncryptLast(block5, k);
}

static inline void POWER8_Dec_Block(uint32x4_p &block, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    uint32x4_p k = VecLoad(rounds*16, keys);
    block = VecXor(block, k);

    for (size_t i=rounds-1; i>1; i-=2)
    {
        block = VecDecrypt(block, VecLoad(  i*16,   keys));
        block = VecDecrypt(block, VecLoad((i-1)*16, keys));
    }

    block = VecDecrypt(block, VecLoad(16, keys));
    block = VecDecryptLast(block, VecLoad(0, keys));
}

static inline void POWER8_Dec_6_Blocks(uint32x4_p &block0, uint32x4_p &block1,
            uint32x4_p &block2, uint32x4_p &block3, uint32x4_p &block4,
            uint32x4_p &block5, const word32 *subkeys, unsigned int rounds)
{
    CRYPTOPP_ASSERT(IsAlignedOn(subkeys, 16));
    const byte *keys = reinterpret_cast<const byte*>(subkeys);

    uint32x4_p k = VecLoad(rounds*16, keys);
    block0 = VecXor(block0, k);
    block1 = VecXor(block1, k);
    block2 = VecXor(block2, k);
    block3 = VecXor(block3, k);
    block4 = VecXor(block4, k);
    block5 = VecXor(block5, k);

    for (size_t i=rounds-1; i>0; --i)
    {
        k = VecLoad(i*16, keys);
        block0 = VecDecrypt(block0, k);
        block1 = VecDecrypt(block1, k);
        block2 = VecDecrypt(block2, k);
        block3 = VecDecrypt(block3, k);
        block4 = VecDecrypt(block4, k);
        block5 = VecDecrypt(block5, k);
    }

    k = VecLoad(0, keys);
    block0 = VecDecryptLast(block0, k);
    block1 = VecDecryptLast(block1, k);
    block2 = VecDecryptLast(block2, k);
    block3 = VecDecryptLast(block3, k);
    block4 = VecDecryptLast(block4, k);
    block5 = VecDecryptLast(block5, k);
}

ANONYMOUS_NAMESPACE_END

void Rijndael_UncheckedSetKey_POWER8(const byte* userKey, size_t keyLen, word32* rk, const byte* Se)
{
    const size_t rounds = keyLen / 4 + 6;
    const word32 *rc = s_rconBE;
    word32 *rkey = rk, temp;

    GetUserKey(BIG_ENDIAN_ORDER, rkey, keyLen/4, userKey, keyLen);

    // keySize: m_key allocates 4*(rounds+1) word32's.
    const size_t keySize = 4*(rounds+1);
    const word32* end = rkey + keySize;

    while (true)
    {
        temp  = rkey[keyLen/4-1];
        word32 x = (word32(Se[GETBYTE(temp, 2)]) << 24) ^ (word32(Se[GETBYTE(temp, 1)]) << 16) ^
                    (word32(Se[GETBYTE(temp, 0)]) << 8) ^ Se[GETBYTE(temp, 3)];
        rkey[keyLen/4] = rkey[0] ^ x ^ *(rc++);
        rkey[keyLen/4+1] = rkey[1] ^ rkey[keyLen/4];
        rkey[keyLen/4+2] = rkey[2] ^ rkey[keyLen/4+1];
        rkey[keyLen/4+3] = rkey[3] ^ rkey[keyLen/4+2];

        if (rkey + keyLen/4 + 4 == end)
            break;

        if (keyLen == 24)
        {
            rkey[10] = rkey[ 4] ^ rkey[ 9];
            rkey[11] = rkey[ 5] ^ rkey[10];
        }
        else if (keyLen == 32)
        {
            temp = rkey[11];
            rkey[12] = rkey[ 4] ^ (word32(Se[GETBYTE(temp, 3)]) << 24) ^ (word32(Se[GETBYTE(temp, 2)]) << 16) ^ (word32(Se[GETBYTE(temp, 1)]) << 8) ^ Se[GETBYTE(temp, 0)];
            rkey[13] = rkey[ 5] ^ rkey[12];
            rkey[14] = rkey[ 6] ^ rkey[13];
            rkey[15] = rkey[ 7] ^ rkey[14];
        }
        rkey += keyLen/4;
    }

#if (CRYPTOPP_LITTLE_ENDIAN)
    rkey = rk;
    const uint8x16_p mask = ((uint8x16_p){12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3});
    const uint8x16_p zero = {0};

    unsigned int i=0;
    for (i=0; i<rounds; i+=2, rkey+=8)
    {
        const uint8x16_p d1 = vec_vsx_ld( 0, (uint8_t*)rkey);
        const uint8x16_p d2 = vec_vsx_ld(16, (uint8_t*)rkey);
        vec_vsx_st(VecPermute(d1, zero, mask),  0, (uint8_t*)rkey);
        vec_vsx_st(VecPermute(d2, zero, mask), 16, (uint8_t*)rkey);
    }

    for ( ; i<rounds+1; i++, rkey+=4)
    {
        const uint8x16_p d = vec_vsx_ld( 0, (uint8_t*)rkey);
        vec_vsx_st(VecPermute(d, zero, mask),  0, (uint8_t*)rkey);
    }
#endif
}

size_t Rijndael_Enc_AdvancedProcessBlocks128_6x1_ALTIVEC(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_6x1_ALTIVEC(POWER8_Enc_Block, POWER8_Enc_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t Rijndael_Dec_AdvancedProcessBlocks128_6x1_ALTIVEC(const word32 *subKeys, size_t rounds,
            const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags)
{
    return AdvancedProcessBlocks128_6x1_ALTIVEC(POWER8_Dec_Block, POWER8_Dec_6_Blocks,
        subKeys, rounds, inBlocks, xorBlocks, outBlocks, length, flags);
}

#endif  // CRYPTOPP_POWER8_AES_AVAILABLE
NAMESPACE_END
