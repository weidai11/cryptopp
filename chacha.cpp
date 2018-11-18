// chacha.cpp - written and placed in the public domain by Jeffrey Walton.
//              Based on Wei Dai's Salsa20, Botan's SSE2 implementation,
//              and Bernstein's reference ChaCha family implementation at
//              http://cr.yp.to/chacha.html.

#include "pch.h"
#include "config.h"
#include "chacha.h"
#include "argnames.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
extern void ChaCha_OperateKeystream_NEON(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#endif

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)
extern void ChaCha_OperateKeystream_SSE2(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#endif

#if (CRYPTOPP_AVX2_AVAILABLE)
extern void ChaCha_OperateKeystream_AVX2(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#endif

#if (CRYPTOPP_POWER7_AVAILABLE)
extern void ChaCha_OperateKeystream_POWER7(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#elif (CRYPTOPP_ALTIVEC_AVAILABLE)
extern void ChaCha_OperateKeystream_ALTIVEC(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#endif

#define CHACHA_QUARTER_ROUND(a,b,c,d) \
    a += b; d ^= a; d = rotlConstant<16,word32>(d); \
    c += d; b ^= c; b = rotlConstant<12,word32>(b); \
    a += b; d ^= a; d = rotlConstant<8,word32>(d); \
    c += d; b ^= c; b = rotlConstant<7,word32>(b);

#define CHACHA_OUTPUT(x){\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 0, x0 + m_state[0]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 1, x1 + m_state[1]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 2, x2 + m_state[2]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 3, x3 + m_state[3]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 4, x4 + m_state[4]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 5, x5 + m_state[5]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 6, x6 + m_state[6]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 7, x7 + m_state[7]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 8, x8 + m_state[8]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 9, x9 + m_state[9]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 10, x10 + m_state[10]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 11, x11 + m_state[11]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 12, x12 + m_state[12]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 13, x13 + m_state[13]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 14, x14 + m_state[14]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 15, x15 + m_state[15]);}

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
void ChaCha_TestInstantiations()
{
    ChaCha::Encryption x;
}
#endif

std::string ChaCha_Policy::AlgorithmName() const
{
    return std::string("ChaCha")+IntToString(m_rounds);
}

std::string ChaCha_Policy::AlgorithmProvider() const
{
#if (CRYPTOPP_AVX2_AVAILABLE)
    if (HasAVX2())
        return "AVX2";
    else
#endif
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)
    if (HasSSE2())
        return "SSE2";
    else
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return "NEON";
    else
#endif
#if (CRYPTOPP_POWER7_AVAILABLE)
    if (HasPower7())
        return "Power7";
    else
#elif (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return "Altivec";
    else
#endif
    return "C++";
}

void ChaCha_Policy::CipherSetKey(const NameValuePairs &params, const byte *key, size_t length)
{
    CRYPTOPP_UNUSED(params);
    CRYPTOPP_ASSERT(length == 16 || length == 32);

    m_rounds = params.GetIntValueWithDefault(Name::Rounds(), 20);
    if (!(m_rounds == 8 || m_rounds == 12 || m_rounds == 20))
        throw InvalidRounds(ChaCha::StaticAlgorithmName(), m_rounds);

    // "expand 16-byte k" or "expand 32-byte k"
    m_state[0] = 0x61707865;
    m_state[1] = (length == 16) ? 0x3120646e : 0x3320646e;
    m_state[2] = (length == 16) ? 0x79622d36 : 0x79622d32;
    m_state[3] = 0x6b206574;

    GetBlock<word32, LittleEndian> get1(key);
    get1(m_state[4])(m_state[5])(m_state[6])(m_state[7]);

    GetBlock<word32, LittleEndian> get2(key + ((length == 32) ? 16 : 0));
    get2(m_state[8])(m_state[9])(m_state[10])(m_state[11]);
}

void ChaCha_Policy::CipherResynchronize(byte *keystreamBuffer, const byte *IV, size_t length)
{
    CRYPTOPP_UNUSED(keystreamBuffer), CRYPTOPP_UNUSED(length);
    CRYPTOPP_ASSERT(length==8);

    GetBlock<word32, LittleEndian> get(IV);
    m_state[12] = m_state[13] = 0;
    get(m_state[14])(m_state[15]);
}

void ChaCha_Policy::SeekToIteration(lword iterationCount)
{
    m_state[12] = (word32)iterationCount;  // low word
    m_state[13] = (word32)SafeRightShift<32>(iterationCount);
}

unsigned int ChaCha_Policy::GetAlignment() const
{
#if (CRYPTOPP_AVX2_AVAILABLE)
    if (HasAVX2())
        return 16;
    else
#endif
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)
    if (HasSSE2())
        return 16;
    else
#endif
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return 16;
    else
#endif
        return GetAlignmentOf<word32>();
}

unsigned int ChaCha_Policy::GetOptimalBlockSize() const
{
#if (CRYPTOPP_AVX2_AVAILABLE)
    if (HasAVX2())
        return 8 * BYTES_PER_ITERATION;
    else
#endif
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)
    if (HasSSE2())
        return 4*BYTES_PER_ITERATION;
    else
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return 4*BYTES_PER_ITERATION;
    else
#endif
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return 4*BYTES_PER_ITERATION;
    else
#endif
        return BYTES_PER_ITERATION;
}

bool ChaCha_Policy::MultiBlockSafe(unsigned int blocks) const
{
    return 0xffffffff - m_state[12] > blocks;
}

// OperateKeystream always produces a key stream. The key stream is written
// to output. Optionally a message may be supplied to xor with the key stream.
// The message is input, and output = output ^ input.
void ChaCha_Policy::OperateKeystream(KeystreamOperation operation,
        byte *output, const byte *input, size_t iterationCount)
{
    do
    {
#if (CRYPTOPP_AVX2_AVAILABLE)
        if (HasAVX2())
        {
            while (iterationCount >= 8 && MultiBlockSafe(8))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_AVX2(m_state, xorInput ? input : NULLPTR, output, m_rounds);

                // MultiBlockSafe avoids overflow on the counter words
                m_state[12] += 8;
                //if (m_state[12] < 8)
                //    m_state[13]++;

                input += (!!xorInput) * 8 * BYTES_PER_ITERATION;
                output += 8 * BYTES_PER_ITERATION;
                iterationCount -= 8;
            }
        }
#endif

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE || CRYPTOPP_SSE2_ASM_AVAILABLE)
        if (HasSSE2())
        {
            while (iterationCount >= 4 && MultiBlockSafe(4))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_SSE2(m_state, xorInput ? input : NULLPTR, output, m_rounds);

                // MultiBlockSafe avoids overflow on the counter words
                m_state[12] += 4;
                //if (m_state[12] < 4)
                //    m_state[13]++;

                input += (!!xorInput)*4*BYTES_PER_ITERATION;
                output += 4*BYTES_PER_ITERATION;
                iterationCount -= 4;
            }
        }
#endif

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
        if (HasNEON())
        {
            while (iterationCount >= 4 && MultiBlockSafe(4))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_NEON(m_state, xorInput ? input : NULLPTR, output, m_rounds);

                // MultiBlockSafe avoids overflow on the counter words
                m_state[12] += 4;
                //if (m_state[12] < 4)
                //    m_state[13]++;

                input += (!!xorInput)*4*BYTES_PER_ITERATION;
                output += 4*BYTES_PER_ITERATION;
                iterationCount -= 4;
            }
        }
#endif

#if (CRYPTOPP_POWER7_AVAILABLE)
        if (HasPower7())
        {
            while (iterationCount >= 4 && MultiBlockSafe(4))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_POWER7(m_state, xorInput ? input : NULLPTR, output, m_rounds);

                // MultiBlockSafe avoids overflow on the counter words
                m_state[12] += 4;
                //if (m_state[12] < 4)
                //    m_state[13]++;

                input += (!!xorInput)*4*BYTES_PER_ITERATION;
                output += 4*BYTES_PER_ITERATION;
                iterationCount -= 4;
            }
        }
#elif (CRYPTOPP_ALTIVEC_AVAILABLE)
        if (HasAltivec())
        {
            while (iterationCount >= 4 && MultiBlockSafe(4))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_ALTIVEC(m_state, xorInput ? input : NULLPTR, output, m_rounds);

                // MultiBlockSafe avoids overflow on the counter words
                m_state[12] += 4;
                //if (m_state[12] < 4)
                //    m_state[13]++;

                input += (!!xorInput)*4*BYTES_PER_ITERATION;
                output += 4*BYTES_PER_ITERATION;
                iterationCount -= 4;
            }
        }
#endif

        if (iterationCount)
        {
            word32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;

            x0 = m_state[0];    x1 = m_state[1];    x2 = m_state[2];    x3 = m_state[3];
            x4 = m_state[4];    x5 = m_state[5];    x6 = m_state[6];    x7 = m_state[7];
            x8 = m_state[8];    x9 = m_state[9];    x10 = m_state[10];  x11 = m_state[11];
            x12 = m_state[12];  x13 = m_state[13];  x14 = m_state[14];  x15 = m_state[15];

            for (int i = static_cast<int>(m_rounds); i > 0; i -= 2)
            {
                CHACHA_QUARTER_ROUND(x0, x4,  x8, x12);
                CHACHA_QUARTER_ROUND(x1, x5,  x9, x13);
                CHACHA_QUARTER_ROUND(x2, x6, x10, x14);
                CHACHA_QUARTER_ROUND(x3, x7, x11, x15);

                CHACHA_QUARTER_ROUND(x0, x5, x10, x15);
                CHACHA_QUARTER_ROUND(x1, x6, x11, x12);
                CHACHA_QUARTER_ROUND(x2, x7,  x8, x13);
                CHACHA_QUARTER_ROUND(x3, x4,  x9, x14);
            }

            CRYPTOPP_KEYSTREAM_OUTPUT_SWITCH(CHACHA_OUTPUT, BYTES_PER_ITERATION);

            if (++m_state[12] == 0)
                m_state[13]++;
        }

    // We may re-enter a SIMD keystream operation from here.
    } while (iterationCount--);
}

NAMESPACE_END
