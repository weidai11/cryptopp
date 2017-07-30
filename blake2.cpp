// blake2.cpp - written and placed in the public domain by Jeffrey Walton and Zooko
//              Wilcox-O'Hearn. Based on Aumasson, Neves, Wilcox-O'Hearn and Winnerlein's
//              reference BLAKE2 implementation at http://github.com/BLAKE2/BLAKE2.

#include "pch.h"
#include "config.h"
#include "cryptlib.h"
#include "argnames.h"
#include "algparam.h"
#include "blake2.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

// Uncomment for benchmarking C++ against SSE2 or NEON
// #undef CRYPTOPP_SSE42_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

// Apple Clang 6.0/Clang 3.5 does not have SSSE3 intrinsics
//   http://llvm.org/bugs/show_bug.cgi?id=20213
#if (defined(CRYPTOPP_APPLE_CLANG_VERSION) && (CRYPTOPP_APPLE_CLANG_VERSION <= 60000)) || (defined(CRYPTOPP_LLVM_CLANG_VERSION) && (CRYPTOPP_LLVM_CLANG_VERSION <= 30500))
# undef CRYPTOPP_SSE42_AVAILABLE
#endif

// Sun Studio 12.3 and earlier lack SSE2's _mm_set_epi64x. Win32 lacks _mm_set_epi64x, Win64 supplies it except for VS2008.
// Also see http://stackoverflow.com/a/38547909/608639
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && ((__SUNPRO_CC >= 0x5100 && __SUNPRO_CC < 0x5130) || (defined(_MSC_VER) && _MSC_VER < 1600) || (defined(_M_IX86) && _MSC_VER >= 1600))
inline __m128i MM_SET_EPI64X(const word64 a, const word64 b)
{
    const word64 t[2] = {b,a}; __m128i r;
    memcpy(&r, &t, sizeof(t));
    return r;
}
#else
# define MM_SET_EPI64X(a, b) _mm_set_epi64x(a, b)
#endif

// C/C++ implementation
static void BLAKE2_Compress32_CXX(const byte* input, BLAKE2_State<word32, false>& state);
static void BLAKE2_Compress64_CXX(const byte* input, BLAKE2_State<word64, true>& state);

// Also see http://github.com/weidai11/cryptopp/issues/247 for SunCC 5.12
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
static void BLAKE2_Compress32_SSE2(const byte* input, BLAKE2_State<word32, false>& state);
# if (__SUNPRO_CC != 0x5120)
static void BLAKE2_Compress64_SSE2(const byte* input, BLAKE2_State<word64, true>& state);
# endif
#endif

#if CRYPTOPP_SSE42_AVAILABLE
extern void BLAKE2_Compress32_SSE4(const byte* input, BLAKE2_State<word32, false>& state);
extern void BLAKE2_Compress64_SSE4(const byte* input, BLAKE2_State<word64, true>& state);
#endif

// Disable NEON for Cortex-A53 and A57. Also see http://github.com/weidai11/cryptopp/issues/367
#if CRYPTOPP_BOOL_ARM32 && CRYPTOPP_ARM_NEON_AVAILABLE
extern void BLAKE2_Compress32_NEON(const byte* input, BLAKE2_State<word32, false>& state);
extern void BLAKE2_Compress64_NEON(const byte* input, BLAKE2_State<word64, true>& state);
#endif

ANONYMOUS_NAMESPACE_BEGIN

CRYPTOPP_ALIGN_DATA(16)
const word32 BLAKE2S_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

CRYPTOPP_ALIGN_DATA(16)
const word64 BLAKE2B_IV[8] = {
    W64LIT(0x6a09e667f3bcc908), W64LIT(0xbb67ae8584caa73b),
    W64LIT(0x3c6ef372fe94f82b), W64LIT(0xa54ff53a5f1d36f1),
    W64LIT(0x510e527fade682d1), W64LIT(0x9b05688c2b3e6c1f),
    W64LIT(0x1f83d9abfb41bd6b), W64LIT(0x5be0cd19137e2179)
};

CRYPTOPP_ALIGN_DATA(16)
const byte BLAKE2S_SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
};

CRYPTOPP_ALIGN_DATA(16)
const byte BLAKE2B_SIGMA[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

typedef void (*pfnCompress32)(const byte*, BLAKE2_State<word32, false>&);
typedef void (*pfnCompress64)(const byte*, BLAKE2_State<word64, true>&);

pfnCompress64 InitializeCompress64Fn()
{
#if CRYPTOPP_SSE42_AVAILABLE
    if (HasSSE4())
        return &BLAKE2_Compress64_SSE4;
    else
#endif
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
# if (__SUNPRO_CC != 0x5120)
    if (HasSSE2())
        return &BLAKE2_Compress64_SSE2;
    else
# endif
#endif
#if CRYPTOPP_BOOL_ARM32 && CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
        return &BLAKE2_Compress64_NEON;
    else
#endif
    return &BLAKE2_Compress64_CXX;
}

pfnCompress32 InitializeCompress32Fn()
{
#if CRYPTOPP_SSE42_AVAILABLE
    if (HasSSE4())
        return &BLAKE2_Compress32_SSE4;
    else
#endif
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
    if (HasSSE2())
        return &BLAKE2_Compress32_SSE2;
    else
#endif
#if CRYPTOPP_BOOL_ARM32 && CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
        return &BLAKE2_Compress32_NEON;
    else
#endif
    return &BLAKE2_Compress32_CXX;
}

ANONYMOUS_NAMESPACE_END

BLAKE2_ParameterBlock<false>::BLAKE2_ParameterBlock(size_t digestLen, size_t keyLen,
        const byte* saltStr, size_t saltLen,
        const byte* personalizationStr, size_t personalizationLen)
{
    // Avoid Coverity finding SIZEOF_MISMATCH/suspicious_sizeof
    digestLength = (byte)digestLen;
    keyLength = (byte)keyLen;
    fanout = depth = 1;
    nodeDepth = innerLength = 0;

    memset(leafLength, 0x00, COUNTOF(leafLength));
    memset(nodeOffset, 0x00, COUNTOF(nodeOffset));

    if (saltStr && saltLen)
    {
        memcpy_s(salt, COUNTOF(salt), saltStr, saltLen);
        const size_t rem = COUNTOF(salt) - saltLen;
        const size_t off = COUNTOF(salt) - rem;
        if (rem)
            memset(salt+off, 0x00, rem);
    }
    else
    {
        memset(salt, 0x00, COUNTOF(salt));
    }

    if (personalizationStr && personalizationLen)
    {
        memcpy_s(personalization, COUNTOF(personalization), personalizationStr, personalizationLen);
        const size_t rem = COUNTOF(personalization) - personalizationLen;
        const size_t off = COUNTOF(personalization) - rem;
        if (rem)
            memset(personalization+off, 0x00, rem);
    }
    else
    {
        memset(personalization, 0x00, COUNTOF(personalization));
    }
}

BLAKE2_ParameterBlock<true>::BLAKE2_ParameterBlock(size_t digestLen, size_t keyLen,
        const byte* saltStr, size_t saltLen,
        const byte* personalizationStr, size_t personalizationLen)
{
    // Avoid Coverity finding SIZEOF_MISMATCH/suspicious_sizeof
    digestLength = (byte)digestLen;
    keyLength = (byte)keyLen;
    fanout = depth = 1;
    nodeDepth = innerLength = 0;

    memset(rfu, 0x00, COUNTOF(rfu));
    memset(leafLength, 0x00, COUNTOF(leafLength));
    memset(nodeOffset, 0x00, COUNTOF(nodeOffset));

    if (saltStr && saltLen)
    {
        memcpy_s(salt, COUNTOF(salt), saltStr, saltLen);
        const size_t rem = COUNTOF(salt) - saltLen;
        const size_t off = COUNTOF(salt) - rem;
        if (rem)
            memset(salt+off, 0x00, rem);
    }
    else
    {
        memset(salt, 0x00, COUNTOF(salt));
    }

    if (personalizationStr && personalizationLen)
    {
        memcpy_s(personalization, COUNTOF(personalization), personalizationStr, personalizationLen);
        const size_t rem = COUNTOF(personalization) - personalizationLen;
        const size_t off = COUNTOF(personalization) - rem;
        if (rem)
            memset(personalization+off, 0x00, rem);
    }
    else
    {
        memset(personalization, 0x00, COUNTOF(personalization));
    }
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::UncheckedSetKey(const byte *key, unsigned int length, const CryptoPP::NameValuePairs& params)
{
    if (key && length)
    {
        AlignedSecByteBlock temp(BLOCKSIZE);
        memcpy_s(temp, BLOCKSIZE, key, length);

        const size_t rem = BLOCKSIZE - length;
        if (rem)
            memset(temp+length, 0x00, rem);

        m_key.swap(temp);
    }
    else
    {
        m_key.resize(0);
    }

#if defined(__COVERITY__)
    // Avoid Coverity finding SIZEOF_MISMATCH/suspicious_sizeof
    ParameterBlock& block = *m_block.data();
    memset(m_block.data(), 0x00, sizeof(ParameterBlock));
#else
    // Set Head bytes; Tail bytes are set below
    ParameterBlock& block = *m_block.data();
    memset(m_block.data(), 0x00, T_64bit ? 32 : 16);
#endif

    block.keyLength = (byte)length;
    block.digestLength = (byte)params.GetIntValueWithDefault(Name::DigestSize(), DIGESTSIZE);
    block.fanout = block.depth = 1;

    ConstByteArrayParameter t;
    if (params.GetValue(Name::Salt(), t) && t.begin() && t.size())
    {
        memcpy_s(block.salt, COUNTOF(block.salt), t.begin(), t.size());
        const size_t rem = COUNTOF(block.salt) - t.size();
        const size_t off = COUNTOF(block.salt) - rem;
        if (rem)
            memset(block.salt+off, 0x00, rem);
    }
    else
    {
        memset(block.salt, 0x00, COUNTOF(block.salt));
    }

    if (params.GetValue(Name::Personalization(), t) && t.begin() && t.size())
    {
        memcpy_s(block.personalization, COUNTOF(block.personalization), t.begin(), t.size());
        const size_t rem = COUNTOF(block.personalization) - t.size();
        const size_t off = COUNTOF(block.personalization) - rem;
        if (rem)
            memset(block.personalization+off, 0x00, rem);
    }
    else
    {
        memset(block.personalization, 0x00, COUNTOF(block.personalization));
    }
}

template <class W, bool T_64bit>
BLAKE2_Base<W, T_64bit>::BLAKE2_Base() : m_state(1), m_block(1), m_digestSize(DIGESTSIZE), m_treeMode(false)
{
    UncheckedSetKey(NULLPTR, 0, g_nullNameValuePairs);
    Restart();
}

template <class W, bool T_64bit>
BLAKE2_Base<W, T_64bit>::BLAKE2_Base(bool treeMode, unsigned int digestSize) : m_state(1), m_block(1), m_digestSize(digestSize), m_treeMode(treeMode)
{
    CRYPTOPP_ASSERT(digestSize <= DIGESTSIZE);

    UncheckedSetKey(NULLPTR, 0, MakeParameters(Name::DigestSize(), (int)digestSize)(Name::TreeMode(), treeMode, false));
    Restart();
}

template <class W, bool T_64bit>
BLAKE2_Base<W, T_64bit>::BLAKE2_Base(const byte *key, size_t keyLength, const byte* salt, size_t saltLength,
    const byte* personalization, size_t personalizationLength, bool treeMode, unsigned int digestSize)
    : m_state(1), m_block(1), m_digestSize(digestSize), m_treeMode(treeMode)
{
    CRYPTOPP_ASSERT(keyLength <= MAX_KEYLENGTH);
    CRYPTOPP_ASSERT(digestSize <= DIGESTSIZE);
    CRYPTOPP_ASSERT(saltLength <= SALTSIZE);
    CRYPTOPP_ASSERT(personalizationLength <= PERSONALIZATIONSIZE);

    UncheckedSetKey(key, static_cast<unsigned int>(keyLength), MakeParameters(Name::DigestSize(),(int)digestSize)(Name::TreeMode(),treeMode, false)
        (Name::Salt(), ConstByteArrayParameter(salt, saltLength))(Name::Personalization(), ConstByteArrayParameter(personalization, personalizationLength)));
    Restart();
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::Restart()
{
    static const W zero[2] = {0,0};
    Restart(*m_block.data(), zero);
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::Restart(const BLAKE2_ParameterBlock<T_64bit>& block, const W counter[2])
{
    // We take a parameter block as a parameter to allow customized state.
    // Avoid the copy of the parameter block when we are passing our own block.
    if (&block != m_block.data())
    {
        memcpy_s(m_block.data(), sizeof(ParameterBlock), &block, sizeof(ParameterBlock));
        m_block.data()->digestLength = (byte)m_digestSize;
        m_block.data()->keyLength = (byte)m_key.size();
    }

    State& state = *m_state.data();
    state.t[0] = state.t[1] = 0, state.f[0] = state.f[1] = 0, state.length = 0;

    if (counter != NULLPTR)
    {
        state.t[0] = counter[0];
        state.t[1] = counter[1];
    }

	const W* IV = T_64bit ? reinterpret_cast<const W*>(BLAKE2B_IV) : reinterpret_cast<const W*>(BLAKE2S_IV);
    PutBlock<W, LittleEndian, true> put(m_block.data(), &state.h[0]);
    put(IV[0])(IV[1])(IV[2])(IV[3])(IV[4])(IV[5])(IV[6])(IV[7]);

    // When BLAKE2 is keyed, the input stream is simply {key||message}. Key it
    // during Restart to avoid FirstPut and friends. Key size == 0 means no key.
    if (m_key.size())
        Update(m_key, m_key.size());
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::Update(const byte *input, size_t length)
{
    State& state = *m_state.data();
    if (state.length + length > BLOCKSIZE)
    {
        // Complete current block
        const size_t fill = BLOCKSIZE - state.length;
        memcpy_s(&state.buffer[state.length], fill, input, fill);

        IncrementCounter();
        Compress(state.buffer);
        state.length = 0;

        length -= fill, input += fill;

        // Compress in-place to avoid copies
        while (length > BLOCKSIZE)
        {
            IncrementCounter();
            Compress(input);
            length -= BLOCKSIZE, input += BLOCKSIZE;
        }
    }

    // Copy tail bytes
    if (input && length)
    {
        CRYPTOPP_ASSERT(length <= BLOCKSIZE - state.length);
        memcpy_s(&state.buffer[state.length], length, input, length);
        state.length += static_cast<unsigned int>(length);
    }
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::TruncatedFinal(byte *hash, size_t size)
{
    this->ThrowIfInvalidTruncatedSize(size);

    // Set last block unconditionally
    State& state = *m_state.data();
    state.f[0] = static_cast<W>(-1);

    // Set last node if tree mode
    if (m_treeMode)
        state.f[1] = static_cast<W>(-1);

    // Increment counter for tail bytes only
    IncrementCounter(state.length);

    memset(state.buffer + state.length, 0x00, BLOCKSIZE - state.length);
    Compress(state.buffer);

    // Copy to caller buffer
    memcpy_s(hash, size, &state.h[0], size);

    Restart();
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::IncrementCounter(size_t count)
{
    State& state = *m_state.data();
    state.t[0] += static_cast<W>(count);
    state.t[1] += !!(state.t[0] < count);
}

template <>
void BLAKE2_Base<word64, true>::Compress(const byte *input)
{
    // Selects the most advanced implementation at runtime
    static const pfnCompress64 s_pfn = InitializeCompress64Fn();
    s_pfn(input, *m_state.data());
}

template <>
void BLAKE2_Base<word32, false>::Compress(const byte *input)
{
    // Selects the most advanced implementation at runtime
    static const pfnCompress32 s_pfn = InitializeCompress32Fn();
    s_pfn(input, *m_state.data());
}

void BLAKE2_Compress64_CXX(const byte* input, BLAKE2_State<word64, true>& state)
{
    #undef BLAKE2_G
    #undef BLAKE2_ROUND

    #define BLAKE2_G(r,i,a,b,c,d) \
      do { \
        a = a + b + m[BLAKE2B_SIGMA[r][2*i+0]]; \
        d = rotrVariable<word64>(d ^ a, 32); \
        c = c + d; \
        b = rotrVariable<word64>(b ^ c, 24); \
        a = a + b + m[BLAKE2B_SIGMA[r][2*i+1]]; \
        d = rotrVariable<word64>(d ^ a, 16); \
        c = c + d; \
        b = rotrVariable<word64>(b ^ c, 63); \
      } while(0)

    #define BLAKE2_ROUND(r)  \
      do { \
        BLAKE2_G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
        BLAKE2_G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
        BLAKE2_G(r,2,v[ 2],v[ 6],v[10],v[14]); \
        BLAKE2_G(r,3,v[ 3],v[ 7],v[11],v[15]); \
        BLAKE2_G(r,4,v[ 0],v[ 5],v[10],v[15]); \
        BLAKE2_G(r,5,v[ 1],v[ 6],v[11],v[12]); \
        BLAKE2_G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
        BLAKE2_G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
      } while(0)

    word64 m[16], v[16];

    GetBlock<word64, LittleEndian, true> get1(input);
    get1(m[0])(m[1])(m[2])(m[3])(m[4])(m[5])(m[6])(m[7])(m[8])(m[9])(m[10])(m[11])(m[12])(m[13])(m[14])(m[15]);

    GetBlock<word64, LittleEndian, true> get2(&state.h[0]);
    get2(v[0])(v[1])(v[2])(v[3])(v[4])(v[5])(v[6])(v[7]);

    v[ 8] = BLAKE2B_IV[0];
    v[ 9] = BLAKE2B_IV[1];
    v[10] = BLAKE2B_IV[2];
    v[11] = BLAKE2B_IV[3];
    v[12] = state.t[0] ^ BLAKE2B_IV[4];
    v[13] = state.t[1] ^ BLAKE2B_IV[5];
    v[14] = state.f[0] ^ BLAKE2B_IV[6];
    v[15] = state.f[1] ^ BLAKE2B_IV[7];

    BLAKE2_ROUND(0);
    BLAKE2_ROUND(1);
    BLAKE2_ROUND(2);
    BLAKE2_ROUND(3);
    BLAKE2_ROUND(4);
    BLAKE2_ROUND(5);
    BLAKE2_ROUND(6);
    BLAKE2_ROUND(7);
    BLAKE2_ROUND(8);
    BLAKE2_ROUND(9);
    BLAKE2_ROUND(10);
    BLAKE2_ROUND(11);

    for(unsigned int i = 0; i < 8; ++i)
        state.h[i] = state.h[i] ^ ConditionalByteReverse(LittleEndian::ToEnum(), v[i] ^ v[i + 8]);
}

void BLAKE2_Compress32_CXX(const byte* input, BLAKE2_State<word32, false>& state)
{
    #undef BLAKE2_G
    #undef BLAKE2_ROUND

    #define BLAKE2_G(r,i,a,b,c,d) \
      do { \
        a = a + b + m[BLAKE2S_SIGMA[r][2*i+0]]; \
        d = rotrVariable<word32>(d ^ a, 16); \
        c = c + d; \
        b = rotrVariable<word32>(b ^ c, 12); \
        a = a + b + m[BLAKE2S_SIGMA[r][2*i+1]]; \
        d = rotrVariable<word32>(d ^ a, 8); \
        c = c + d; \
        b = rotrVariable<word32>(b ^ c, 7); \
      } while(0)

    #define BLAKE2_ROUND(r)  \
      do { \
        BLAKE2_G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
        BLAKE2_G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
        BLAKE2_G(r,2,v[ 2],v[ 6],v[10],v[14]); \
        BLAKE2_G(r,3,v[ 3],v[ 7],v[11],v[15]); \
        BLAKE2_G(r,4,v[ 0],v[ 5],v[10],v[15]); \
        BLAKE2_G(r,5,v[ 1],v[ 6],v[11],v[12]); \
        BLAKE2_G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
        BLAKE2_G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
      } while(0)

    word32 m[16], v[16];

    GetBlock<word32, LittleEndian, true> get1(input);
    get1(m[0])(m[1])(m[2])(m[3])(m[4])(m[5])(m[6])(m[7])(m[8])(m[9])(m[10])(m[11])(m[12])(m[13])(m[14])(m[15]);

    GetBlock<word32, LittleEndian, true> get2(&state.h[0]);
    get2(v[0])(v[1])(v[2])(v[3])(v[4])(v[5])(v[6])(v[7]);

    v[ 8] = BLAKE2S_IV[0];
    v[ 9] = BLAKE2S_IV[1];
    v[10] = BLAKE2S_IV[2];
    v[11] = BLAKE2S_IV[3];
    v[12] = state.t[0] ^ BLAKE2S_IV[4];
    v[13] = state.t[1] ^ BLAKE2S_IV[5];
    v[14] = state.f[0] ^ BLAKE2S_IV[6];
    v[15] = state.f[1] ^ BLAKE2S_IV[7];

    BLAKE2_ROUND(0);
    BLAKE2_ROUND(1);
    BLAKE2_ROUND(2);
    BLAKE2_ROUND(3);
    BLAKE2_ROUND(4);
    BLAKE2_ROUND(5);
    BLAKE2_ROUND(6);
    BLAKE2_ROUND(7);
    BLAKE2_ROUND(8);
    BLAKE2_ROUND(9);

    for(unsigned int i = 0; i < 8; ++i)
        state.h[i] = state.h[i] ^ ConditionalByteReverse(LittleEndian::ToEnum(), v[i] ^ v[i + 8]);
}

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
static void BLAKE2_Compress32_SSE2(const byte* input, BLAKE2_State<word32, false>& state)
{
  word32 m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15;
  GetBlock<word32, LittleEndian, true> get(input);
  get(m0)(m1)(m2)(m3)(m4)(m5)(m6)(m7)(m8)(m9)(m10)(m11)(m12)(m13)(m14)(m15);

  __m128i row1,row2,row3,row4;
  __m128i buf1,buf2,buf3,buf4;
  __m128i ff0,ff1;

  row1 = ff0 = _mm_loadu_si128((const __m128i*)(const void*)(&state.h[0]));
  row2 = ff1 = _mm_loadu_si128((const __m128i*)(const void*)(&state.h[4]));
  row3 = _mm_setr_epi32(BLAKE2S_IV[0],BLAKE2S_IV[1],BLAKE2S_IV[2],BLAKE2S_IV[3]);
  row4 = _mm_xor_si128(_mm_setr_epi32(BLAKE2S_IV[4],BLAKE2S_IV[5],BLAKE2S_IV[6],BLAKE2S_IV[7]),_mm_loadu_si128((const __m128i*)(const void*)(&state.t[0])));
  buf1 = _mm_set_epi32(m6,m4,m2,m0);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m7,m5,m3,m1);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m14,m12,m10,m8);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m15,m13,m11,m9);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m13,m9,m4,m14);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m6,m15,m8,m10);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m5,m11,m0,m1);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m3,m7,m2,m12);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m15,m5,m12,m11);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m13,m2,m0,m8);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m9,m7,m3,m10);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m4,m1,m6,m14);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m11,m13,m3,m7);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m14,m12,m1,m9);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m15,m4,m5,m2);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m8,m0,m10,m6);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m10,m2,m5,m9);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m15,m4,m7,m0);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m3,m6,m11,m14);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m13,m8,m12,m1);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m8,m0,m6,m2);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m3,m11,m10,m12);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m1,m15,m7,m4);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m9,m14,m5,m13);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m4,m14,m1,m12);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m10,m13,m15,m5);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m8,m9,m6,m0);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m11,m2,m3,m7);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m3,m12,m7,m13);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m9,m1,m14,m11);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m2,m8,m15,m5);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m10,m6,m4,m0);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m0,m11,m14,m6);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m8,m3,m9,m15);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m10,m1,m13,m12);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m5,m4,m7,m2);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  buf1 = _mm_set_epi32(m1,m7,m8,m10);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf1),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf2 = _mm_set_epi32(m5,m6,m4,m2);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf2),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(2,1,0,3));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(0,3,2,1));

  buf3 = _mm_set_epi32(m13,m3,m9,m15);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf3),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,16),_mm_slli_epi32(row4,16));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,12),_mm_slli_epi32(row2,20));

  buf4 = _mm_set_epi32(m0,m12,m14,m11);
  row1 = _mm_add_epi32(_mm_add_epi32(row1,buf4),row2);
  row4 = _mm_xor_si128(row4,row1);
  row4 = _mm_xor_si128(_mm_srli_epi32(row4,8),_mm_slli_epi32(row4,24));
  row3 = _mm_add_epi32(row3,row4);
  row2 = _mm_xor_si128(row2,row3);
  row2 = _mm_xor_si128(_mm_srli_epi32(row2,7),_mm_slli_epi32(row2,25));

  row4 = _mm_shuffle_epi32(row4,_MM_SHUFFLE(0,3,2,1));
  row3 = _mm_shuffle_epi32(row3,_MM_SHUFFLE(1,0,3,2));
  row2 = _mm_shuffle_epi32(row2,_MM_SHUFFLE(2,1,0,3));

  _mm_storeu_si128((__m128i *)(void*)(&state.h[0]),_mm_xor_si128(ff0,_mm_xor_si128(row1,row3)));
  _mm_storeu_si128((__m128i *)(void*)(&state.h[4]),_mm_xor_si128(ff1,_mm_xor_si128(row2,row4)));
}

# if (__SUNPRO_CC != 0x5120)
static void BLAKE2_Compress64_SSE2(const byte* input, BLAKE2_State<word64, true>& state)
{
  word64 m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15;
  GetBlock<word64, LittleEndian, true> get(input);
  get(m0)(m1)(m2)(m3)(m4)(m5)(m6)(m7)(m8)(m9)(m10)(m11)(m12)(m13)(m14)(m15);

  __m128i row1l, row1h, row2l, row2h;
  __m128i row3l, row3h, row4l, row4h;
  __m128i b0, b1, t0, t1;

  row1l = _mm_loadu_si128((const __m128i*)(const void*)(&state.h[0]));
  row1h = _mm_loadu_si128((const __m128i*)(const void*)(&state.h[2]));
  row2l = _mm_loadu_si128((const __m128i*)(const void*)(&state.h[4]));
  row2h = _mm_loadu_si128((const __m128i*)(const void*)(&state.h[6]));
  row3l = _mm_loadu_si128((const __m128i*)(const void*)(&BLAKE2B_IV[0]));
  row3h = _mm_loadu_si128((const __m128i*)(const void*)(&BLAKE2B_IV[2]));
  row4l = _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)(&BLAKE2B_IV[4])), _mm_loadu_si128((const __m128i*)(const void*)(&state.t[0])));
  row4h = _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)(&BLAKE2B_IV[6])), _mm_loadu_si128((const __m128i*)(const void*)(&state.f[0])));

  b0 = MM_SET_EPI64X(m2, m0);
  b1 = MM_SET_EPI64X(m6, m4);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l, 40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h, 40));

  b0 = MM_SET_EPI64X(m3, m1);
  b1 = MM_SET_EPI64X(m7, m5);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m10, m8);
  b1 = MM_SET_EPI64X(m14, m12);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m11, m9);
  b1 = MM_SET_EPI64X(m15, m13);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m4, m14);
  b1 = MM_SET_EPI64X(m13, m9);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m8, m10);
  b1 = MM_SET_EPI64X(m6, m15);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));
  b0 = MM_SET_EPI64X(m0, m1);
  b1 = MM_SET_EPI64X(m5, m11);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m2, m12);
  b1 = MM_SET_EPI64X(m3, m7);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m12, m11);
  b1 = MM_SET_EPI64X(m15, m5);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m0, m8);
  b1 = MM_SET_EPI64X(m13, m2);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));
  b0 = MM_SET_EPI64X(m3, m10);
  b1 = MM_SET_EPI64X(m9, m7);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m6, m14);
  b1 = MM_SET_EPI64X(m4, m1);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m3, m7);
  b1 = MM_SET_EPI64X(m11, m13);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m1, m9);
  b1 = MM_SET_EPI64X(m14, m12);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));
  b0 = MM_SET_EPI64X(m5, m2);
  b1 = MM_SET_EPI64X(m15, m4);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m10, m6);
  b1 = MM_SET_EPI64X(m8, m0);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m5, m9);
  b1 = MM_SET_EPI64X(m10, m2);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m7, m0);
  b1 = MM_SET_EPI64X(m15, m4);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m11, m14);
  b1 = MM_SET_EPI64X(m3, m6);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));


  b0 = MM_SET_EPI64X(m12, m1);
  b1 = MM_SET_EPI64X(m13, m8);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m6, m2);
  b1 = MM_SET_EPI64X(m8, m0);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m10, m12);
  b1 = MM_SET_EPI64X(m3, m11);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m7, m4);
  b1 = MM_SET_EPI64X(m1, m15);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m5, m13);
  b1 = MM_SET_EPI64X(m9, m14);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m1, m12);
  b1 = MM_SET_EPI64X(m4, m14);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m15, m5);
  b1 = MM_SET_EPI64X(m10, m13);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m6, m0);
  b1 = MM_SET_EPI64X(m8, m9);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m3, m7);
  b1 = MM_SET_EPI64X(m11, m2);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m7, m13);
  b1 = MM_SET_EPI64X(m3, m12);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m14, m11);
  b1 = MM_SET_EPI64X(m9, m1);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m15, m5);
  b1 = MM_SET_EPI64X(m2, m8);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m4, m0);
  b1 = MM_SET_EPI64X(m10, m6);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m14, m6);
  b1 = MM_SET_EPI64X(m0, m11);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m9, m15);
  b1 = MM_SET_EPI64X(m8, m3);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m13, m12);
  b1 = MM_SET_EPI64X(m10, m1);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m7, m2);
  b1 = MM_SET_EPI64X(m5, m4);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m8, m10);
  b1 = MM_SET_EPI64X(m1, m7);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m4, m2);
  b1 = MM_SET_EPI64X(m5, m6);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m9, m15);
  b1 = MM_SET_EPI64X(m13, m3);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m14, m11);
  b1 = MM_SET_EPI64X(m0, m12);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m2, m0);
  b1 = MM_SET_EPI64X(m6, m4);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m3, m1);
  b1 = MM_SET_EPI64X(m7, m5);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m10, m8);
  b1 = MM_SET_EPI64X(m14, m12);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m11, m9);
  b1 = MM_SET_EPI64X(m15, m13);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m4, m14);
  b1 = MM_SET_EPI64X(m13, m9);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m8, m10);
  b1 = MM_SET_EPI64X(m6, m15);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row4l, t1 = row2l, row4l = row3l, row3l = row3h, row3h = row4l;
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));

  b0 = MM_SET_EPI64X(m0, m1);
  b1 = MM_SET_EPI64X(m5, m11);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,32),_mm_slli_epi64(row4l,32));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,32),_mm_slli_epi64(row4h,32));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,24),_mm_slli_epi64(row2l,40));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,24),_mm_slli_epi64(row2h,40));

  b0 = MM_SET_EPI64X(m2, m12);
  b1 = MM_SET_EPI64X(m3, m7);
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
  row4l = _mm_xor_si128(row4l, row1l);
  row4h = _mm_xor_si128(row4h, row1h);
  row4l = _mm_xor_si128(_mm_srli_epi64(row4l,16),_mm_slli_epi64(row4l,48));
  row4h = _mm_xor_si128(_mm_srli_epi64(row4h,16),_mm_slli_epi64(row4h,48));
  row3l = _mm_add_epi64(row3l, row4l);
  row3h = _mm_add_epi64(row3h, row4h);
  row2l = _mm_xor_si128(row2l, row3l);
  row2h = _mm_xor_si128(row2h, row3h);
  row2l = _mm_xor_si128(_mm_srli_epi64(row2l,63),_mm_slli_epi64(row2l,1));
  row2h = _mm_xor_si128(_mm_srli_epi64(row2h,63),_mm_slli_epi64(row2h,1));

  t0 = row3l, row3l = row3h, row3h = t0, t0 = row2l, t1 = row4l;
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));

  row1l = _mm_xor_si128(row3l, row1l);
  row1h = _mm_xor_si128(row3h, row1h);
  _mm_storeu_si128((__m128i *)(void*)(&state.h[0]), _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)(&state.h[0])), row1l));
  _mm_storeu_si128((__m128i *)(void*)(&state.h[2]), _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)(&state.h[2])), row1h));

  row2l = _mm_xor_si128(row4l, row2l);
  row2h = _mm_xor_si128(row4h, row2h);
  _mm_storeu_si128((__m128i *)(void*)(&state.h[4]), _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)(&state.h[4])), row2l));
  _mm_storeu_si128((__m128i *)(void*)(&state.h[6]), _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)(&state.h[6])), row2h));
}
# endif // (__SUNPRO_CC != 0x5120)
#endif  // CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE

template class BLAKE2_Base<word32, false>;
template class BLAKE2_Base<word64, true>;

NAMESPACE_END
