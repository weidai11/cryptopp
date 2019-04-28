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

// Internal compiler error in GCC 3.3 and below
#if defined(__GNUC__) && (__GNUC__ < 4)
# undef CRYPTOPP_SSE2_INTRIN_AVAILABLE
#endif

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
extern void ChaCha_OperateKeystream_NEON(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#endif

#if (CRYPTOPP_AVX2_AVAILABLE)
extern void ChaCha_OperateKeystream_AVX2(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#endif
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
extern void ChaCha_OperateKeystream_SSE2(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#endif

#if (CRYPTOPP_POWER8_AVAILABLE)
extern void ChaCha_OperateKeystream_POWER8(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#elif (CRYPTOPP_ALTIVEC_AVAILABLE)
extern void ChaCha_OperateKeystream_ALTIVEC(const word32 *state, const byte* input, byte *output, unsigned int rounds);
#endif

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
void ChaCha_TestInstantiations()
{
    ChaCha::Encryption x;
    ChaChaTLS::Encryption y;
    XChaCha20::Encryption z;
}
#endif

NAMESPACE_END  // CryptoPP

////////////////////////////// ChaCha Core //////////////////////////////

#define CHACHA_QUARTER_ROUND(a,b,c,d) \
    a += b; d ^= a; d = rotlConstant<16,word32>(d); \
    c += d; b ^= c; b = rotlConstant<12,word32>(b); \
    a += b; d ^= a; d = rotlConstant<8,word32>(d); \
    c += d; b ^= c; b = rotlConstant<7,word32>(b);

#define CHACHA_OUTPUT(x){\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 0, x0 + state[0]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 1, x1 + state[1]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 2, x2 + state[2]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 3, x3 + state[3]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 4, x4 + state[4]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 5, x5 + state[5]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 6, x6 + state[6]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 7, x7 + state[7]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 8, x8 + state[8]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 9, x9 + state[9]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 10, x10 + state[10]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 11, x11 + state[11]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 12, x12 + state[12]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 13, x13 + state[13]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 14, x14 + state[14]);\
    CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 15, x15 + state[15]);}

ANONYMOUS_NAMESPACE_BEGIN

// Hacks... Bring in all symbols, and supply
// the stuff the templates normally provide.
using namespace CryptoPP;
typedef word32 WordType;
enum {BYTES_PER_ITERATION=64};

// MultiBlockSafe detects a condition that can arise in the SIMD
// implementations where we overflow one of the 32-bit state words during
// addition in an intermediate result. Preconditions for the issue include
// a user seeks to around 2^32 blocks (256 GB of data) for ChaCha; or a
// user specifies an arbitrarily large initial counter block for ChaChaTLS.
// Also see https://github.com/weidai11/cryptopp/issues/732.
inline bool MultiBlockSafe(unsigned int ctrLow, unsigned int blocks)
{
    return 0xffffffff - ctrLow > blocks;
}

// OperateKeystream always produces a key stream. The key stream is written
// to output. Optionally a message may be supplied to xor with the key stream.
// The message is input, and output = output ^ input.
void ChaCha_OperateKeystream(KeystreamOperation operation,
        word32 state[16], word32& ctrLow, word32& ctrHigh, word32 rounds,
        byte *output, const byte *input, size_t iterationCount)
{
    do
    {
#if (CRYPTOPP_AVX2_AVAILABLE)
        if (HasAVX2())
        {
            while (iterationCount >= 8 && MultiBlockSafe(state[12], 8))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_AVX2(state, xorInput ? input : NULLPTR, output, rounds);

                // MultiBlockSafe avoids overflow on the counter words
                state[12] += 8;

                input += (!!xorInput) * 8 * BYTES_PER_ITERATION;
                output += 8 * BYTES_PER_ITERATION;
                iterationCount -= 8;
            }
        }
#endif

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
        if (HasSSE2())
        {
            while (iterationCount >= 4 && MultiBlockSafe(state[12], 4))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_SSE2(state, xorInput ? input : NULLPTR, output, rounds);

                // MultiBlockSafe avoids overflow on the counter words
                state[12] += 4;

                input += (!!xorInput)*4*BYTES_PER_ITERATION;
                output += 4*BYTES_PER_ITERATION;
                iterationCount -= 4;
            }
        }
#endif

#if (CRYPTOPP_ARM_NEON_AVAILABLE)
        if (HasNEON())
        {
            while (iterationCount >= 4 && MultiBlockSafe(state[12], 4))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_NEON(state, xorInput ? input : NULLPTR, output, rounds);

                // MultiBlockSafe avoids overflow on the counter words
                state[12] += 4;

                input += (!!xorInput)*4*BYTES_PER_ITERATION;
                output += 4*BYTES_PER_ITERATION;
                iterationCount -= 4;
            }
        }
#endif

#if (CRYPTOPP_POWER8_AVAILABLE)
        if (HasPower8())
        {
            while (iterationCount >= 4 && MultiBlockSafe(state[12], 4))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_POWER8(state, xorInput ? input : NULLPTR, output, rounds);

                // MultiBlockSafe avoids overflow on the counter words
                state[12] += 4;

                input += (!!xorInput)*4*BYTES_PER_ITERATION;
                output += 4*BYTES_PER_ITERATION;
                iterationCount -= 4;
            }
        }
#elif (CRYPTOPP_ALTIVEC_AVAILABLE)
        if (HasAltivec())
        {
            while (iterationCount >= 4 && MultiBlockSafe(state[12], 4))
            {
                const bool xorInput = (operation & INPUT_NULL) != INPUT_NULL;
                ChaCha_OperateKeystream_ALTIVEC(state, xorInput ? input : NULLPTR, output, rounds);

                // MultiBlockSafe avoids overflow on the counter words
                state[12] += 4;

                input += (!!xorInput)*4*BYTES_PER_ITERATION;
                output += 4*BYTES_PER_ITERATION;
                iterationCount -= 4;
            }
        }
#endif

        if (iterationCount)
        {
            word32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;

            x0 = state[0];    x1 = state[1];    x2 = state[2];    x3 = state[3];
            x4 = state[4];    x5 = state[5];    x6 = state[6];    x7 = state[7];
            x8 = state[8];    x9 = state[9];    x10 = state[10];  x11 = state[11];
            x12 = state[12];  x13 = state[13];  x14 = state[14];  x15 = state[15];

            for (int i = static_cast<int>(rounds); i > 0; i -= 2)
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

            // This is state[12] and state[13] from ChaCha. In the case of
            // ChaChaTLS ctrHigh is a reference to a discard value.
            if (++ctrLow == 0)
                ctrHigh++;
        }

    // We may re-enter a SIMD keystream operation from here.
    } while (iterationCount--);
}

// XChaCha key derivation
void HChaCha_OperateKeystream(const word32 state[16], word32 output[8])
{
    word32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;

    x0 = state[0];    x1 = state[1];    x2 = state[2];    x3 = state[3];
    x4 = state[4];    x5 = state[5];    x6 = state[6];    x7 = state[7];
    x8 = state[8];    x9 = state[9];    x10 = state[10];  x11 = state[11];
    x12 = state[12];  x13 = state[13];  x14 = state[14];  x15 = state[15];

    for (int i = 20; i > 0; i -= 2)
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

    output[0] =  x0; output[1] =  x1;
    output[2] =  x2; output[3] =  x3;
    output[4] = x12; output[5] = x13;
    output[6] = x14; output[7] = x15;
}

std::string ChaCha_AlgorithmProvider()
{
#if (CRYPTOPP_AVX2_AVAILABLE)
    if (HasAVX2())
        return "AVX2";
    else
#endif
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
    if (HasSSE2())
        return "SSE2";
    else
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return "NEON";
    else
#endif
#if (CRYPTOPP_POWER8_AVAILABLE)
    if (HasPower8())
        return "Power8";
    else
#elif (CRYPTOPP_ALTIVEC_AVAILABLE)
    if (HasAltivec())
        return "Altivec";
    else
#endif
    return "C++";
}

unsigned int ChaCha_GetAlignment()
{
#if (CRYPTOPP_AVX2_AVAILABLE)
    if (HasAVX2())
        return 16;
    else
#endif
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
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

unsigned int ChaCha_GetOptimalBlockSize()
{
#if (CRYPTOPP_AVX2_AVAILABLE)
    if (HasAVX2())
        return 8 * BYTES_PER_ITERATION;
    else
#endif
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
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

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

////////////////////////////// Bernstein ChaCha //////////////////////////////

std::string ChaCha_Policy::AlgorithmName() const
{
    return std::string("ChaCha")+IntToString(m_rounds);
}

std::string ChaCha_Policy::AlgorithmProvider() const
{
    return ChaCha_AlgorithmProvider();
}

void ChaCha_Policy::CipherSetKey(const NameValuePairs &params, const byte *key, size_t length)
{
    CRYPTOPP_ASSERT(key); CRYPTOPP_ASSERT(length == 16 || length == 32);
    CRYPTOPP_UNUSED(key); CRYPTOPP_UNUSED(length);

    // Use previous rounds as the default value
    int rounds = params.GetIntValueWithDefault(Name::Rounds(), m_rounds);
    if (rounds != 20 && rounds != 12 && rounds != 8)
        throw InvalidRounds(ChaCha::StaticAlgorithmName(), rounds);

    // Latch a good value
    m_rounds = rounds;

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
    CRYPTOPP_ASSERT(length==8); CRYPTOPP_UNUSED(length);

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
    return ChaCha_GetAlignment();
}

unsigned int ChaCha_Policy::GetOptimalBlockSize() const
{
    return ChaCha_GetOptimalBlockSize();
}

void ChaCha_Policy::OperateKeystream(KeystreamOperation operation,
        byte *output, const byte *input, size_t iterationCount)
{
    ChaCha_OperateKeystream(operation, m_state, m_state[12], m_state[13],
        m_rounds, output, input, iterationCount);
}

////////////////////////////// IETF ChaChaTLS //////////////////////////////

std::string ChaChaTLS_Policy::AlgorithmName() const
{
    return std::string("ChaChaTLS");
}

std::string ChaChaTLS_Policy::AlgorithmProvider() const
{
    return ChaCha_AlgorithmProvider();
}

void ChaChaTLS_Policy::CipherSetKey(const NameValuePairs &params, const byte *key, size_t length)
{
    CRYPTOPP_ASSERT(key); CRYPTOPP_ASSERT(length == 32);
    CRYPTOPP_UNUSED(length);

    // ChaChaTLS is always 20 rounds. Fetch Rounds() to avoid a spurious failure.
    int rounds = params.GetIntValueWithDefault(Name::Rounds(), ROUNDS);
    if (rounds != 20)
        throw InvalidRounds(ChaChaTLS::StaticAlgorithmName(), rounds);

    // RFC 8439 test vectors use an initial block counter. However, the counter
    // can be an arbitrary value per RFC 8439 Section 2.4. We stash the counter
    // away in state[16] and use it for a Resynchronize() operation. I think
    // the initial counter is used more like a Tweak when non-0, and it should
    // be provided in Resynchronize() (light-weight re-keying). However,
    // Resynchronize() does not have an overload that allows us to pass it into
    // the function, so we have to use the heavier-weight SetKey to change it.
    word64 block;
    if (params.GetValue("InitialBlock", block))
        m_counter = static_cast<word32>(block);
    else
        m_counter = 0;

    // State words are defined in RFC 8439, Section 2.3. Key is 32-bytes.
    GetBlock<word32, LittleEndian> get(key);
    get(m_state[KEY+0])(m_state[KEY+1])(m_state[KEY+2])(m_state[KEY+3])
        (m_state[KEY+4])(m_state[KEY+5])(m_state[KEY+6])(m_state[KEY+7]);
}

void ChaChaTLS_Policy::CipherResynchronize(byte *keystreamBuffer, const byte *IV, size_t length)
{
    CRYPTOPP_UNUSED(keystreamBuffer), CRYPTOPP_UNUSED(length);
    CRYPTOPP_ASSERT(length==12);

    // State words are defined in RFC 8439, Section 2.3.
    m_state[0] = 0x61707865; m_state[1] = 0x3320646e;
    m_state[2] = 0x79622d32; m_state[3] = 0x6b206574;

    // Copy saved key into state
    std::memcpy(m_state+4, m_state+KEY, 8*sizeof(word32));

    // State words are defined in RFC 8439, Section 2.3
    GetBlock<word32, LittleEndian> get(IV);
    m_state[12] = m_counter;
    get(m_state[13])(m_state[14])(m_state[15]);
}

void ChaChaTLS_Policy::SeekToIteration(lword iterationCount)
{
    // Should we throw here??? If the initial block counter is
    // large then we can wrap and process more data as long as
    // data processed in the security context does not exceed
    // 2^32 blocks or approximately 256 GB of data.
    CRYPTOPP_ASSERT(iterationCount <= std::numeric_limits<word32>::max());
    m_state[12] = (word32)iterationCount;  // low word
}

unsigned int ChaChaTLS_Policy::GetAlignment() const
{
    return ChaCha_GetAlignment();
}

unsigned int ChaChaTLS_Policy::GetOptimalBlockSize() const
{
    return ChaCha_GetOptimalBlockSize();
}

void ChaChaTLS_Policy::OperateKeystream(KeystreamOperation operation,
        byte *output, const byte *input, size_t iterationCount)
{
    word32 discard=0;
    ChaCha_OperateKeystream(operation, m_state, m_state[12], discard,
            ROUNDS, output, input, iterationCount);

    // If this fires it means ChaCha_OperateKeystream generated a counter
    // block carry that was discarded. The problem is, the RFC does not
    // specify what should happen when the counter block wraps. All we can
    // do is inform the user that something bad may happen because we don't
    // know what we should do.
    // Also see https://github.com/weidai11/cryptopp/issues/790 and
    // https://mailarchive.ietf.org/arch/msg/cfrg/gsOnTJzcbgG6OqD8Sc0GO5aR_tU
    // CRYPTOPP_ASSERT(discard==0);
}

////////////////////////////// IETF XChaCha20 //////////////////////////////

std::string XChaCha20_Policy::AlgorithmName() const
{
    return std::string("XChaCha20");
}

std::string XChaCha20_Policy::AlgorithmProvider() const
{
    return ChaCha_AlgorithmProvider();
}

void XChaCha20_Policy::CipherSetKey(const NameValuePairs &params, const byte *key, size_t length)
{
    CRYPTOPP_ASSERT(key); CRYPTOPP_ASSERT(length == 32);
    CRYPTOPP_UNUSED(length);

    // Use previous rounds as the default value
    int rounds = params.GetIntValueWithDefault(Name::Rounds(), m_rounds);
    if (rounds != 20 && rounds != 12)
        throw InvalidRounds(ChaCha::StaticAlgorithmName(), rounds);

    // Latch a good value
    m_rounds = rounds;

    word64 block;
    if (params.GetValue("InitialBlock", block))
        m_counter = static_cast<word32>(block);
    else
        m_counter = 1;

    // Stash key away for use in CipherResynchronize
    GetBlock<word32, LittleEndian> get(key);
    get(m_state[KEY+0])(m_state[KEY+1])(m_state[KEY+2])(m_state[KEY+3])
        (m_state[KEY+4])(m_state[KEY+5])(m_state[KEY+6])(m_state[KEY+7]);
}

void XChaCha20_Policy::CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length)
{
    CRYPTOPP_UNUSED(keystreamBuffer), CRYPTOPP_UNUSED(length);
    CRYPTOPP_ASSERT(length==24);

    // HChaCha derivation
    m_state[0] = 0x61707865; m_state[1] = 0x3320646e;
    m_state[2] = 0x79622d32; m_state[3] = 0x6b206574;

    // Copy saved key into state
    std::memcpy(m_state+4, m_state+KEY, 8*sizeof(word32));

    GetBlock<word32, LittleEndian> get(iv);
    get(m_state[12])(m_state[13])(m_state[14])(m_state[15]);

    // Operate the keystream without adding state back in.
    // This function also gathers the key words into a
    // contiguous 8-word block.
    HChaCha_OperateKeystream(m_state, m_state+4);

    // XChaCha state
    m_state[0] = 0x61707865; m_state[1] = 0x3320646e;
    m_state[2] = 0x79622d32; m_state[3] = 0x6b206574;

    // Setup new IV
    m_state[12] = m_counter;
    m_state[13] = 0;
    m_state[14] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, iv+16);
    m_state[15] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, iv+20);
}

void XChaCha20_Policy::SeekToIteration(lword iterationCount)
{
    // Should we throw here??? XChaCha does not have a block
    // counter, so I'm not sure how to seek on it.
    CRYPTOPP_ASSERT(0); CRYPTOPP_UNUSED(iterationCount);
}

unsigned int XChaCha20_Policy::GetAlignment() const
{
    return ChaCha_GetAlignment();
}

unsigned int XChaCha20_Policy::GetOptimalBlockSize() const
{
    return ChaCha_GetOptimalBlockSize();
}

void XChaCha20_Policy::OperateKeystream(KeystreamOperation operation,
        byte *output, const byte *input, size_t iterationCount)
{
    ChaCha_OperateKeystream(operation, m_state, m_state[12], m_state[13],
            m_rounds, output, input, iterationCount);
}

NAMESPACE_END
