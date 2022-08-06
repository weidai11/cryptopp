// sha.cpp - modified by Wei Dai from Steve Reid's public domain sha1.c

//    Steve Reid implemented SHA-1. Wei Dai implemented SHA-2. Jeffrey
//    Walton implemented Intel SHA extensions based on Intel articles and code
//    by Sean Gulley. Jeffrey Walton implemented ARM SHA-1 and SHA-256 based
//    on ARM code and code from Johannes Schneiders, Skip Hovsmith and
//    Barry O'Rourke. Jeffrey Walton and Bill Schmidt implemented Power8
//    SHA-256 and SHA-512. All code is in the public domain.

//    In August 2017 JW reworked the internals to align all the
//    implementations. Formerly all hashes were software based, IterHashBase
//    handled endian conversions, and IterHashBase dispatched a single to
//    block SHA{N}::Transform. SHA{N}::Transform then performed the single
//    block hashing. It was repeated for multiple blocks.
//
//    The rework added SHA{N}::HashMultipleBlocks (class) and
//    SHA{N}_HashMultipleBlocks (free standing). There are also hardware
//    accelerated variations. Callers enter SHA{N}::HashMultipleBlocks (class)
//    and the function calls SHA{N}_HashMultipleBlocks (free standing) or
//    SHA{N}_HashBlock (free standing) as a fallback.
//
//    An added wrinkle is hardware is little endian, C++ is big endian, and
//    callers use big endian, so SHA{N}_HashMultipleBlock accepts a ByteOrder
//    for the incoming data arrangement. Hardware based SHA{N}_HashMultipleBlock
//    can often perform the endian swap much easier by setting an EPI mask.
//    Endian swap incurs no penalty on Intel SHA, and 4-instruction penalty on
//    ARM SHA. Under C++ the full software based swap penalty is incurred due
//    to use of ReverseBytes().
//
//    In May 2019 JW added Cryptogams ARMv7 and NEON implementations for SHA1,
//    SHA256 and SHA512. The Cryptogams code closed a performance gap on modern
//    32-bit ARM devices. Cryptogams is Andy Polyakov's project used to create
//    high speed crypto algorithms and share them with other developers. Andy's
//    code runs 30% to 50% faster than C/C++ code. The Cryptogams code can be
//    disabled in config_asm.h. An example of integrating Andy's code is at
//    https://wiki.openssl.org/index.php/Cryptogams_SHA.

// use "cl /EP /P /DCRYPTOPP_GENERATE_X64_MASM sha.cpp" to generate MASM code

#include "pch.h"
#include "config.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4100 4731)
#endif

#ifndef CRYPTOPP_IMPORTS
#ifndef CRYPTOPP_GENERATE_X64_MASM

#include "secblock.h"
#include "sha.h"
#include "misc.h"
#include "cpu.h"

#if defined(CRYPTOPP_DISABLE_SHA_ASM)
# undef CRYPTOPP_X86_ASM_AVAILABLE
# undef CRYPTOPP_X32_ASM_AVAILABLE
# undef CRYPTOPP_X64_ASM_AVAILABLE
# undef CRYPTOPP_SSE2_ASM_AVAILABLE
#endif

NAMESPACE_BEGIN(CryptoPP)

#if CRYPTOPP_SHANI_AVAILABLE
extern void SHA1_HashMultipleBlocks_SHANI(word32 *state, const word32 *data, size_t length, ByteOrder order);
extern void SHA256_HashMultipleBlocks_SHANI(word32 *state, const word32 *data, size_t length, ByteOrder order);
#endif

#if CRYPTOGAMS_ARM_SHA1
extern "C" void cryptogams_sha1_block_data_order(word32* state, const word32 *data, size_t blocks);
extern "C" void cryptogams_sha1_block_data_order_neon(word32* state, const word32 *data, size_t blocks);
#endif

#if CRYPTOPP_ARM_SHA1_AVAILABLE
extern void SHA1_HashMultipleBlocks_ARMV8(word32 *state, const word32 *data, size_t length, ByteOrder order);
#endif

#if CRYPTOPP_ARM_SHA2_AVAILABLE
extern void SHA256_HashMultipleBlocks_ARMV8(word32 *state, const word32 *data, size_t length, ByteOrder order);
#endif

#if CRYPTOGAMS_ARM_SHA256
extern "C" void cryptogams_sha256_block_data_order(word32* state, const word32 *data, size_t blocks);
extern "C" void cryptogams_sha256_block_data_order_neon(word32* state, const word32 *data, size_t blocks);
#endif

#if CRYPTOPP_ARM_SHA512_AVAILABLE
extern void SHA512_HashMultipleBlocks_ARMV8(word32 *state, const word32 *data, size_t length, ByteOrder order);
#endif

#if CRYPTOPP_POWER8_SHA_AVAILABLE
extern void SHA256_HashMultipleBlocks_POWER8(word32 *state, const word32 *data, size_t length, ByteOrder order);
extern void SHA512_HashMultipleBlocks_POWER8(word64 *state, const word64 *data, size_t length, ByteOrder order);
#endif

#if CRYPTOGAMS_ARM_SHA512
extern "C" void cryptogams_sha512_block_data_order(word64* state, const word64 *data, size_t blocks);
extern "C" void cryptogams_sha512_block_data_order_neon(word64* state, const word64 *data, size_t blocks);
#endif

// We add extern to export table to sha_simd.cpp, but it
//  cleared http://github.com/weidai11/cryptopp/issues/502
extern const word32 SHA256_K[64];
extern const word64 SHA512_K[80];

CRYPTOPP_ALIGN_DATA(16)
const word64 SHA512_K[80] = {
    W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
    W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
    W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
    W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
    W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
    W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
    W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
    W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
    W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
    W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
    W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
    W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
    W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
    W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
    W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
    W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
    W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
    W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
    W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
    W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
    W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
    W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
    W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
    W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
    W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
    W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
    W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
    W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
    W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
    W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
    W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
    W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
    W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
    W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
    W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
    W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
    W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
    W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
    W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
    W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
};

CRYPTOPP_ALIGN_DATA(16)
const word32 SHA256_K[64] = {

    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

////////////////////////////////
// start of Steve Reid's code //
////////////////////////////////

ANONYMOUS_NAMESPACE_BEGIN

#define blk0(i) (W[i] = data[i])
#define blk1(i) (W[i&15] = rotlConstant<1>(W[(i+13)&15]^W[(i+8)&15]^W[(i+2)&15]^W[i&15]))

#define f1(x,y,z) (z^(x&(y^z)))
#define f2(x,y,z) (x^y^z)
#define f3(x,y,z) ((x&y)|(z&(x|y)))
#define f4(x,y,z) (x^y^z)

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=f1(w,x,y)+blk0(i)+0x5A827999+rotlConstant<5>(v);w=rotlConstant<30>(w);
#define R1(v,w,x,y,z,i) z+=f1(w,x,y)+blk1(i)+0x5A827999+rotlConstant<5>(v);w=rotlConstant<30>(w);
#define R2(v,w,x,y,z,i) z+=f2(w,x,y)+blk1(i)+0x6ED9EBA1+rotlConstant<5>(v);w=rotlConstant<30>(w);
#define R3(v,w,x,y,z,i) z+=f3(w,x,y)+blk1(i)+0x8F1BBCDC+rotlConstant<5>(v);w=rotlConstant<30>(w);
#define R4(v,w,x,y,z,i) z+=f4(w,x,y)+blk1(i)+0xCA62C1D6+rotlConstant<5>(v);w=rotlConstant<30>(w);

void SHA1_HashBlock_CXX(word32 *state, const word32 *data)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);

    word32 W[16];
    /* Copy context->state[] to working vars */
    word32 a = state[0];
    word32 b = state[1];
    word32 c = state[2];
    word32 d = state[3];
    word32 e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

#undef blk0
#undef blk1
#undef f1
#undef f2
#undef f3
#undef f4
#undef R1
#undef R2
#undef R3
#undef R4

ANONYMOUS_NAMESPACE_END

//////////////////////////////
// end of Steve Reid's code //
//////////////////////////////

std::string SHA1::AlgorithmProvider() const
{
#if CRYPTOPP_SHANI_AVAILABLE
    if (HasSHA())
        return "SHANI";
#endif
#if CRYPTOPP_SSE2_ASM_AVAILABLE
    if (HasSSE2())
        return "SSE2";
#endif
#if CRYPTOGAMS_ARM_SHA1
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
        return "NEON";
    else
# endif
    if (HasARMv7())
        return "ARMv7";
#endif
#if CRYPTOPP_ARM_SHA1_AVAILABLE
    if (HasSHA1())
        return "ARMv8";
#endif
    return "C++";
}

void SHA1::InitState(HashWordType *state)
{
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;
}

void SHA1::Transform(word32 *state, const word32 *data)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);

#if CRYPTOPP_SHANI_AVAILABLE
    if (HasSHA())
    {
        SHA1_HashMultipleBlocks_SHANI(state, data, SHA1::BLOCKSIZE, LITTLE_ENDIAN_ORDER);
        return;
    }
#endif
// Disabled at the moment due to MDC and SEAL failures
#if CRYPTOGAMS_ARM_SHA1 && 0
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
    {
#  if defined(CRYPTOPP_LITTLE_ENDIAN)
        word32 dataBuf[16];
        ByteReverse(dataBuf, data, SHA1::BLOCKSIZE);
        cryptogams_sha1_block_data_order_neon(state, dataBuf, 1);
#  else
        cryptogams_sha1_block_data_order_neon(state, data, 1);
#  endif
        return;
    }
    else
# endif
    if (HasARMv7())
    {
# if defined(CRYPTOPP_LITTLE_ENDIAN)
        word32 dataBuf[16];
        ByteReverse(dataBuf, data, SHA1::BLOCKSIZE);
        cryptogams_sha1_block_data_order(state, data, 1);
# else
        cryptogams_sha1_block_data_order(state, data, 1);
# endif
        return;
    }
#endif
#if CRYPTOPP_ARM_SHA1_AVAILABLE
    if (HasSHA1())
    {
        SHA1_HashMultipleBlocks_ARMV8(state, data, SHA1::BLOCKSIZE, LITTLE_ENDIAN_ORDER);
        return;
    }
#endif

    SHA1_HashBlock_CXX(state, data);
}

size_t SHA1::HashMultipleBlocks(const word32 *input, size_t length)
{
    CRYPTOPP_ASSERT(input);
    CRYPTOPP_ASSERT(length >= SHA1::BLOCKSIZE);

#if CRYPTOPP_SHANI_AVAILABLE
    if (HasSHA())
    {
        SHA1_HashMultipleBlocks_SHANI(m_state, input, length, BIG_ENDIAN_ORDER);
        return length & (SHA1::BLOCKSIZE - 1);
    }
#endif
#if CRYPTOGAMS_ARM_SHA1
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
    {
        cryptogams_sha1_block_data_order_neon(m_state, input, length / SHA1::BLOCKSIZE);
        return length & (SHA1::BLOCKSIZE - 1);
    }
    else
# endif
    if (HasARMv7())
    {
        cryptogams_sha1_block_data_order(m_state, input, length / SHA1::BLOCKSIZE);
        return length & (SHA1::BLOCKSIZE - 1);
    }
#endif
#if CRYPTOPP_ARM_SHA1_AVAILABLE
    if (HasSHA1())
    {
        SHA1_HashMultipleBlocks_ARMV8(m_state, input, length, BIG_ENDIAN_ORDER);
        return length & (SHA1::BLOCKSIZE - 1);
    }
#endif

    const bool noReverse = NativeByteOrderIs(this->GetByteOrder());
    word32 *dataBuf = this->DataBuf();
    do
    {
        if (noReverse)
        {
            SHA1_HashBlock_CXX(m_state, input);
        }
        else
        {
            ByteReverse(dataBuf, input, SHA1::BLOCKSIZE);
            SHA1_HashBlock_CXX(m_state, dataBuf);
        }

        input += SHA1::BLOCKSIZE/sizeof(word32);
        length -= SHA1::BLOCKSIZE;
    }
    while (length >= SHA1::BLOCKSIZE);
    return length;
}

// *************************************************************

ANONYMOUS_NAMESPACE_BEGIN

#define a(i) T[(0-i)&7]
#define b(i) T[(1-i)&7]
#define c(i) T[(2-i)&7]
#define d(i) T[(3-i)&7]
#define e(i) T[(4-i)&7]
#define f(i) T[(5-i)&7]
#define g(i) T[(6-i)&7]
#define h(i) T[(7-i)&7]

#define blk0(i) (W[i] = data[i])
#define blk2(i) (W[i&15]+=s1(W[(i-2)&15])+W[(i-7)&15]+s0(W[(i-15)&15]))

#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) (y^((x^y)&(y^z)))

#define R(i) h(i)+=S1(e(i))+Ch(e(i),f(i),g(i))+SHA256_K[i+j]+(j?blk2(i):blk0(i));\
    d(i)+=h(i);h(i)+=S0(a(i))+Maj(a(i),b(i),c(i))

// for SHA256
#define s0(x) (rotrConstant<7>(x)^rotrConstant<18>(x)^(x>>3))
#define s1(x) (rotrConstant<17>(x)^rotrConstant<19>(x)^(x>>10))
#define S0(x) (rotrConstant<2>(x)^rotrConstant<13>(x)^rotrConstant<22>(x))
#define S1(x) (rotrConstant<6>(x)^rotrConstant<11>(x)^rotrConstant<25>(x))

void SHA256_HashBlock_CXX(word32 *state, const word32 *data)
{
    word32 W[16]={0}, T[8];
    /* Copy context->state[] to working vars */
    memcpy(T, state, sizeof(T));
    /* 64 operations, partially loop unrolled */
    for (unsigned int j=0; j<64; j+=16)
    {
        R( 0); R( 1); R( 2); R( 3);
        R( 4); R( 5); R( 6); R( 7);
        R( 8); R( 9); R(10); R(11);
        R(12); R(13); R(14); R(15);
    }
    /* Add the working vars back into context.state[] */
    state[0] += a(0);
    state[1] += b(0);
    state[2] += c(0);
    state[3] += d(0);
    state[4] += e(0);
    state[5] += f(0);
    state[6] += g(0);
    state[7] += h(0);
}

#undef Ch
#undef Maj
#undef s0
#undef s1
#undef S0
#undef S1
#undef blk0
#undef blk1
#undef blk2
#undef R

#undef a
#undef b
#undef c
#undef d
#undef e
#undef f
#undef g
#undef h

ANONYMOUS_NAMESPACE_END

std::string SHA256_AlgorithmProvider()
{
#if CRYPTOPP_SHANI_AVAILABLE
    if (HasSHA())
        return "SHANI";
#endif
#if CRYPTOPP_SSE2_ASM_AVAILABLE
    if (HasSSE2())
        return "SSE2";
#endif
#if CRYPTOGAMS_ARM_SHA256
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
        return "NEON";
    else
# endif
    if (HasARMv7())
        return "ARMv7";
#endif
#if CRYPTOPP_ARM_SHA2_AVAILABLE
    if (HasSHA2())
        return "ARMv8";
#endif
#if (CRYPTOPP_POWER8_SHA_AVAILABLE)
    if (HasSHA256())
        return "Power8";
#endif
    return "C++";
}

std::string SHA224::AlgorithmProvider() const
{
    return SHA256_AlgorithmProvider();
}

void SHA224::InitState(HashWordType *state)
{
    static const word32 s[8] = {
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
    memcpy(state, s, sizeof(s));
}

void SHA256::InitState(HashWordType *state)
{
    static const word32 s[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(state, s, sizeof(s));
}
#endif // Not CRYPTOPP_GENERATE_X64_MASM

#if defined(CRYPTOPP_X86_ASM_AVAILABLE)

ANONYMOUS_NAMESPACE_BEGIN

void CRYPTOPP_FASTCALL SHA256_HashMultipleBlocks_SSE2(word32 *state, const word32 *data, size_t len)
{
    #define LOCALS_SIZE  8*4 + 16*4 + 4*WORD_SZ
    #define H(i)         [BASE+ASM_MOD(1024+7-(i),8)*4]
    #define G(i)         H(i+1)
    #define F(i)         H(i+2)
    #define E(i)         H(i+3)
    #define D(i)         H(i+4)
    #define C(i)         H(i+5)
    #define B(i)         H(i+6)
    #define A(i)         H(i+7)
    #define Wt(i)        BASE+8*4+ASM_MOD(1024+15-(i),16)*4
    #define Wt_2(i)      Wt((i)-2)
    #define Wt_15(i)     Wt((i)-15)
    #define Wt_7(i)      Wt((i)-7)
    #define K_END        [BASE+8*4+16*4+0*WORD_SZ]
    #define STATE_SAVE   [BASE+8*4+16*4+1*WORD_SZ]
    #define DATA_SAVE    [BASE+8*4+16*4+2*WORD_SZ]
    #define DATA_END     [BASE+8*4+16*4+3*WORD_SZ]
    #define Kt(i)        WORD_REG(si)+(i)*4
#if CRYPTOPP_BOOL_X86
    #define BASE         esp+4
#elif defined(__GNUC__)
    #define BASE         r8
#else
    #define BASE         rsp
#endif

#define RA0(i, edx, edi)        \
    AS2(    add edx, [Kt(i)]   )\
    AS2(    add edx, [Wt(i)]   )\
    AS2(    add edx, H(i)      )\

#define RA1(i, edx, edi)

#define RB0(i, edx, edi)

#define RB1(i, edx, edi)    \
    AS2(    mov AS_REG_7d, [Wt_2(i)]    )\
    AS2(    mov edi, [Wt_15(i)])\
    AS2(    mov ebx, AS_REG_7d    )\
    AS2(    shr AS_REG_7d, 10        )\
    AS2(    ror ebx, 17        )\
    AS2(    xor AS_REG_7d, ebx    )\
    AS2(    ror ebx, 2        )\
    AS2(    xor ebx, AS_REG_7d    )/* s1(W_t-2) */\
    AS2(    add ebx, [Wt_7(i)])\
    AS2(    mov AS_REG_7d, edi    )\
    AS2(    shr AS_REG_7d, 3        )\
    AS2(    ror edi, 7        )\
    AS2(    add ebx, [Wt(i)])/* s1(W_t-2) + W_t-7 + W_t-16 */\
    AS2(    xor AS_REG_7d, edi    )\
    AS2(    add edx, [Kt(i)])\
    AS2(    ror edi, 11        )\
    AS2(    add edx, H(i)    )\
    AS2(    xor AS_REG_7d, edi    )/* s0(W_t-15) */\
    AS2(    add AS_REG_7d, ebx    )/* W_t = s1(W_t-2) + W_t-7 + s0(W_t-15) W_t-16*/\
    AS2(    mov [Wt(i)], AS_REG_7d)\
    AS2(    add edx, AS_REG_7d    )\

#define ROUND(i, r, eax, ecx, edi, edx)\
    /* in: edi = E    */\
    /* unused: eax, ecx, temp: ebx, AS_REG_7d, out: edx = T1 */\
    AS2(    mov edx, F(i)      )\
    AS2(    xor edx, G(i)      )\
    AS2(    and edx, edi       )\
    AS2(    xor edx, G(i)      )/* Ch(E,F,G) = (G^(E&(F^G))) */\
    AS2(    mov AS_REG_7d, edi )\
    AS2(    ror edi, 6         )\
    AS2(    ror AS_REG_7d, 25  )\
    RA##r(i, edx, edi          )/* H + Wt + Kt + Ch(E,F,G) */\
    AS2(    xor AS_REG_7d, edi )\
    AS2(    ror edi, 5         )\
    AS2(    xor AS_REG_7d, edi )/* S1(E) */\
    AS2(    add edx, AS_REG_7d )/* T1 = S1(E) + Ch(E,F,G) + H + Wt + Kt */\
    RB##r(i, edx, edi          )/* H + Wt + Kt + Ch(E,F,G) */\
    /* in: ecx = A, eax = B^C, edx = T1 */\
    /* unused: edx, temp: ebx, AS_REG_7d, out: eax = A, ecx = B^C, edx = E */\
    AS2(    mov ebx, ecx       )\
    AS2(    xor ecx, B(i)      )/* A^B */\
    AS2(    and eax, ecx       )\
    AS2(    xor eax, B(i)      )/* Maj(A,B,C) = B^((A^B)&(B^C) */\
    AS2(    mov AS_REG_7d, ebx )\
    AS2(    ror ebx, 2         )\
    AS2(    add eax, edx       )/* T1 + Maj(A,B,C) */\
    AS2(    add edx, D(i)      )\
    AS2(    mov D(i), edx      )\
    AS2(    ror AS_REG_7d, 22  )\
    AS2(    xor AS_REG_7d, ebx )\
    AS2(    ror ebx, 11        )\
    AS2(    xor AS_REG_7d, ebx )\
    AS2(    add eax, AS_REG_7d )/* T1 + S0(A) + Maj(A,B,C) */\
    AS2(    mov H(i), eax      )\

// Unroll the use of CRYPTOPP_BOOL_X64 in assembler math. The GAS assembler on X32 (version 2.25)
//   complains "Error: invalid operands (*ABS* and *UND* sections) for `*` and `-`"
#if CRYPTOPP_BOOL_X64
#define SWAP_COPY(i)        \
    AS2(    mov        WORD_REG(bx), [WORD_REG(dx)+i*WORD_SZ])\
    AS1(    bswap      WORD_REG(bx))\
    AS2(    mov        [Wt(i*2+1)], WORD_REG(bx))
#else // X86 and X32
#define SWAP_COPY(i)        \
    AS2(    mov        WORD_REG(bx), [WORD_REG(dx)+i*WORD_SZ])\
    AS1(    bswap      WORD_REG(bx))\
    AS2(    mov        [Wt(i)], WORD_REG(bx))
#endif

#if defined(__GNUC__)
    #if CRYPTOPP_BOOL_X64
        FixedSizeAlignedSecBlock<byte, LOCALS_SIZE> workspace;
    #endif
    __asm__ __volatile__
    (
    #if CRYPTOPP_BOOL_X64
        "lea %4, %%r8;"
    #endif
    INTEL_NOPREFIX
#elif defined(CRYPTOPP_GENERATE_X64_MASM)
        ALIGN   8
    SHA256_HashMultipleBlocks_SSE2    PROC FRAME
        rex_push_reg rsi
        push_reg rdi
        push_reg rbx
        push_reg rbp
        alloc_stack(LOCALS_SIZE+8)
        .endprolog
        mov rdi, r8
        lea rsi, [?SHA256_K@CryptoPP@@3QBIB + 48*4]
#endif

#if CRYPTOPP_BOOL_X86
    #ifndef __GNUC__
        AS2(    mov        edi, [len])
        AS2(    lea        WORD_REG(si), [SHA256_K+48*4])
    #endif
    #if !defined(_MSC_VER) || (_MSC_VER < 1400)
        AS_PUSH_IF86(bx)
    #endif

    AS_PUSH_IF86(bp)
    AS2(    mov        ebx, esp)
    AS2(    and        esp, -16)
    AS2(    sub        WORD_REG(sp), LOCALS_SIZE)
    AS_PUSH_IF86(bx)
#endif
    AS2(    mov        STATE_SAVE, WORD_REG(cx))
    AS2(    mov        DATA_SAVE, WORD_REG(dx))
    AS2(    lea        WORD_REG(ax), [WORD_REG(di) + WORD_REG(dx)])
    AS2(    mov        DATA_END, WORD_REG(ax))
    AS2(    mov        K_END, WORD_REG(si))

#if CRYPTOPP_SSE2_ASM_AVAILABLE
#if CRYPTOPP_BOOL_X86
    AS2(    test    edi, 1)
    ASJ(    jnz,    2, f)
    AS1(    dec        DWORD PTR K_END)
#endif
    AS2(    movdqu    xmm0, XMMWORD_PTR [WORD_REG(cx)+0*16])
    AS2(    movdqu    xmm1, XMMWORD_PTR [WORD_REG(cx)+1*16])
#endif

#if CRYPTOPP_BOOL_X86
#if CRYPTOPP_SSE2_ASM_AVAILABLE
    ASJ(    jmp,    0, f)
#endif
    ASL(2)    // non-SSE2
    AS2(    mov        esi, ecx)
    AS2(    lea        edi, A(0))
    AS2(    mov        ecx, 8)
ATT_NOPREFIX
    AS1(    rep movsd)
INTEL_NOPREFIX
    AS2(    mov        esi, K_END)
    ASJ(    jmp,    3, f)
#endif

#if CRYPTOPP_SSE2_ASM_AVAILABLE
    ASL(0)
    AS2(    movdqu    E(0), xmm1)
    AS2(    movdqu    A(0), xmm0)
#endif
#if CRYPTOPP_BOOL_X86
    ASL(3)
#endif
    AS2(    sub        WORD_REG(si), 48*4)
    SWAP_COPY(0)    SWAP_COPY(1)    SWAP_COPY(2)    SWAP_COPY(3)
    SWAP_COPY(4)    SWAP_COPY(5)    SWAP_COPY(6)    SWAP_COPY(7)
#if CRYPTOPP_BOOL_X86
    SWAP_COPY(8)    SWAP_COPY(9)    SWAP_COPY(10)    SWAP_COPY(11)
    SWAP_COPY(12)    SWAP_COPY(13)    SWAP_COPY(14)    SWAP_COPY(15)
#endif
    AS2(    mov        edi, E(0))    // E
    AS2(    mov        eax, B(0))    // B
    AS2(    xor        eax, C(0))    // B^C
    AS2(    mov        ecx, A(0))    // A

    ROUND(0, 0, eax, ecx, edi, edx)
    ROUND(1, 0, ecx, eax, edx, edi)
    ROUND(2, 0, eax, ecx, edi, edx)
    ROUND(3, 0, ecx, eax, edx, edi)
    ROUND(4, 0, eax, ecx, edi, edx)
    ROUND(5, 0, ecx, eax, edx, edi)
    ROUND(6, 0, eax, ecx, edi, edx)
    ROUND(7, 0, ecx, eax, edx, edi)
    ROUND(8, 0, eax, ecx, edi, edx)
    ROUND(9, 0, ecx, eax, edx, edi)
    ROUND(10, 0, eax, ecx, edi, edx)
    ROUND(11, 0, ecx, eax, edx, edi)
    ROUND(12, 0, eax, ecx, edi, edx)
    ROUND(13, 0, ecx, eax, edx, edi)
    ROUND(14, 0, eax, ecx, edi, edx)
    ROUND(15, 0, ecx, eax, edx, edi)

    ASL(1)
    AS2(add WORD_REG(si), 4*16)
    ROUND(0, 1, eax, ecx, edi, edx)
    ROUND(1, 1, ecx, eax, edx, edi)
    ROUND(2, 1, eax, ecx, edi, edx)
    ROUND(3, 1, ecx, eax, edx, edi)
    ROUND(4, 1, eax, ecx, edi, edx)
    ROUND(5, 1, ecx, eax, edx, edi)
    ROUND(6, 1, eax, ecx, edi, edx)
    ROUND(7, 1, ecx, eax, edx, edi)
    ROUND(8, 1, eax, ecx, edi, edx)
    ROUND(9, 1, ecx, eax, edx, edi)
    ROUND(10, 1, eax, ecx, edi, edx)
    ROUND(11, 1, ecx, eax, edx, edi)
    ROUND(12, 1, eax, ecx, edi, edx)
    ROUND(13, 1, ecx, eax, edx, edi)
    ROUND(14, 1, eax, ecx, edi, edx)
    ROUND(15, 1, ecx, eax, edx, edi)
    AS2(    cmp        WORD_REG(si), K_END)
    ATT_NOPREFIX
    ASJ(    jb,        1, b)
    INTEL_NOPREFIX

    AS2(    mov        WORD_REG(dx), DATA_SAVE)
    AS2(    add        WORD_REG(dx), 64)
    AS2(    mov        AS_REG_7, STATE_SAVE)
    AS2(    mov        DATA_SAVE, WORD_REG(dx))

#if CRYPTOPP_SSE2_ASM_AVAILABLE
#if CRYPTOPP_BOOL_X86
    AS2(    test    DWORD PTR K_END, 1)
    ASJ(    jz,        4, f)
#endif
    AS2(    movdqu    xmm1, XMMWORD_PTR [AS_REG_7+1*16])
    AS2(    movdqu    xmm0, XMMWORD_PTR [AS_REG_7+0*16])
    AS2(    paddd     xmm1, E(0))
    AS2(    paddd     xmm0, A(0))
    AS2(    movdqu    [AS_REG_7+1*16], xmm1)
    AS2(    movdqu    [AS_REG_7+0*16], xmm0)
    AS2(    cmp       WORD_REG(dx), DATA_END)
    ATT_NOPREFIX
    ASJ(    jb,        0, b)
    INTEL_NOPREFIX
#endif

#if CRYPTOPP_BOOL_X86
#if CRYPTOPP_SSE2_ASM_AVAILABLE
    ASJ(    jmp,    5, f)
    ASL(4)    // non-SSE2
#endif
    AS2(    add        [AS_REG_7+0*4], ecx)    // A
    AS2(    add        [AS_REG_7+4*4], edi)    // E
    AS2(    mov        eax, B(0))
    AS2(    mov        ebx, C(0))
    AS2(    mov        ecx, D(0))
    AS2(    add        [AS_REG_7+1*4], eax)
    AS2(    add        [AS_REG_7+2*4], ebx)
    AS2(    add        [AS_REG_7+3*4], ecx)
    AS2(    mov        eax, F(0))
    AS2(    mov        ebx, G(0))
    AS2(    mov        ecx, H(0))
    AS2(    add        [AS_REG_7+5*4], eax)
    AS2(    add        [AS_REG_7+6*4], ebx)
    AS2(    add        [AS_REG_7+7*4], ecx)
    AS2(    mov        ecx, AS_REG_7d)
    AS2(    cmp        WORD_REG(dx), DATA_END)
    ASJ(    jb,        2, b)
#if CRYPTOPP_SSE2_ASM_AVAILABLE
    ASL(5)
#endif
#endif

    AS_POP_IF86(sp)
    AS_POP_IF86(bp)
    #if !defined(_MSC_VER) || (_MSC_VER < 1400)
        AS_POP_IF86(bx)
    #endif

#ifdef CRYPTOPP_GENERATE_X64_MASM
    add        rsp, LOCALS_SIZE+8
    pop        rbp
    pop        rbx
    pop        rdi
    pop        rsi
    ret
    SHA256_HashMultipleBlocks_SSE2 ENDP
#endif

#ifdef __GNUC__
    ATT_PREFIX
    :
    : "c" (state), "d" (data), "S" (SHA256_K+48), "D" (len)
    #if CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
        , "m" (workspace[0])
    #endif
    : "memory", "cc", "%eax", "%xmm0", "%xmm1", PERCENT_REG(AS_REG_7)
    #if CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
        , "%rbx", "%r8", "%r10"
    #else
        , "%ebx"
    #endif
    );
#endif
}

ANONYMOUS_NAMESPACE_END

#endif    // CRYPTOPP_X86_ASM_AVAILABLE

#ifndef CRYPTOPP_GENERATE_X64_MASM

#ifdef CRYPTOPP_X64_MASM_AVAILABLE
extern "C" {
void CRYPTOPP_FASTCALL SHA256_HashMultipleBlocks_SSE2(word32 *state, const word32 *data, size_t len);
}
#endif

std::string SHA256::AlgorithmProvider() const
{
    return SHA256_AlgorithmProvider();
}

void SHA256::Transform(word32 *state, const word32 *data)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);

#if CRYPTOPP_SHANI_AVAILABLE
    if (HasSHA())
    {
        SHA256_HashMultipleBlocks_SHANI(state, data, SHA256::BLOCKSIZE, LITTLE_ENDIAN_ORDER);
        return;
    }
#endif
// Disabled at the moment due to MDC and SEAL failures
#if CRYPTOGAMS_ARM_SHA256 && 0
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
    {
#  if defined(CRYPTOPP_LITTLE_ENDIAN)
        word32 dataBuf[16];
        ByteReverse(dataBuf, data, SHA256::BLOCKSIZE);
        cryptogams_sha256_block_data_order_neon(state, dataBuf, 1);
#  else
        cryptogams_sha256_block_data_order_neon(state, data, 1);
#  endif
        return;
    }
    else
# endif
    if (HasARMv7())
    {
# if defined(CRYPTOPP_LITTLE_ENDIAN)
        word32 dataBuf[16];
        ByteReverse(dataBuf, data, SHA256::BLOCKSIZE);
        cryptogams_sha256_block_data_order(state, data, 1);
# else
        cryptogams_sha256_block_data_order(state, data, 1);
# endif
        return;
    }
#endif
#if CRYPTOPP_ARM_SHA2_AVAILABLE
    if (HasSHA2())
    {
        SHA256_HashMultipleBlocks_ARMV8(state, data, SHA256::BLOCKSIZE, LITTLE_ENDIAN_ORDER);
        return;
    }
#endif
#if CRYPTOPP_POWER8_SHA_AVAILABLE
    if (HasSHA256())
    {
        SHA256_HashMultipleBlocks_POWER8(state, data, SHA256::BLOCKSIZE, LITTLE_ENDIAN_ORDER);
        return;
    }
#endif

    SHA256_HashBlock_CXX(state, data);
}

size_t SHA256::HashMultipleBlocks(const word32 *input, size_t length)
{
    CRYPTOPP_ASSERT(input);
    CRYPTOPP_ASSERT(length >= SHA256::BLOCKSIZE);

#if CRYPTOPP_SHANI_AVAILABLE
    if (HasSHA())
    {
        SHA256_HashMultipleBlocks_SHANI(m_state, input, length, BIG_ENDIAN_ORDER);
        return length & (SHA256::BLOCKSIZE - 1);
    }
#endif
#if CRYPTOPP_SSE2_ASM_AVAILABLE || CRYPTOPP_X64_MASM_AVAILABLE
    if (HasSSE2())
    {
        const size_t res = length & (SHA256::BLOCKSIZE - 1);
        SHA256_HashMultipleBlocks_SSE2(m_state, input, length-res);
        return res;
    }
#endif
#if CRYPTOGAMS_ARM_SHA256
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
    {
        cryptogams_sha256_block_data_order_neon(m_state, input, length / SHA256::BLOCKSIZE);
        return length & (SHA256::BLOCKSIZE - 1);
    }
    else
# endif
    if (HasARMv7())
    {
        cryptogams_sha256_block_data_order(m_state, input, length / SHA256::BLOCKSIZE);
        return length & (SHA256::BLOCKSIZE - 1);
    }
#endif
#if CRYPTOPP_ARM_SHA2_AVAILABLE
    if (HasSHA2())
    {
        SHA256_HashMultipleBlocks_ARMV8(m_state, input, length, BIG_ENDIAN_ORDER);
        return length & (SHA256::BLOCKSIZE - 1);
    }
#endif
#if CRYPTOPP_POWER8_SHA_AVAILABLE
    if (HasSHA256())
    {
        SHA256_HashMultipleBlocks_POWER8(m_state, input, length, BIG_ENDIAN_ORDER);
        return length & (SHA256::BLOCKSIZE - 1);
    }
#endif

    const bool noReverse = NativeByteOrderIs(this->GetByteOrder());
    word32 *dataBuf = this->DataBuf();
    do
    {
        if (noReverse)
        {
            SHA256_HashBlock_CXX(m_state, input);
        }
        else
        {
            ByteReverse(dataBuf, input, SHA256::BLOCKSIZE);
            SHA256_HashBlock_CXX(m_state, dataBuf);
        }

        input += SHA256::BLOCKSIZE/sizeof(word32);
        length -= SHA256::BLOCKSIZE;
    }
    while (length >= SHA256::BLOCKSIZE);
    return length;
}

size_t SHA224::HashMultipleBlocks(const word32 *input, size_t length)
{
    CRYPTOPP_ASSERT(input);
    CRYPTOPP_ASSERT(length >= SHA256::BLOCKSIZE);

#if CRYPTOPP_SHANI_AVAILABLE
    if (HasSHA())
    {
        SHA256_HashMultipleBlocks_SHANI(m_state, input, length, BIG_ENDIAN_ORDER);
        return length & (SHA256::BLOCKSIZE - 1);
    }
#endif
#if CRYPTOPP_SSE2_ASM_AVAILABLE || CRYPTOPP_X64_MASM_AVAILABLE
    if (HasSSE2())
    {
        const size_t res = length & (SHA256::BLOCKSIZE - 1);
        SHA256_HashMultipleBlocks_SSE2(m_state, input, length-res);
        return res;
    }
#endif
#if CRYPTOGAMS_ARM_SHA256
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
    {
        cryptogams_sha256_block_data_order_neon(m_state, input, length / SHA256::BLOCKSIZE);
        return length & (SHA256::BLOCKSIZE - 1);
    }
    else
# endif
    if (HasARMv7())
    {
        cryptogams_sha256_block_data_order(m_state, input, length / SHA256::BLOCKSIZE);
        return length & (SHA256::BLOCKSIZE - 1);
    }
#endif
#if CRYPTOPP_ARM_SHA2_AVAILABLE
    if (HasSHA2())
    {
        SHA256_HashMultipleBlocks_ARMV8(m_state, input, length, BIG_ENDIAN_ORDER);
        return length & (SHA256::BLOCKSIZE - 1);
    }
#endif
#if CRYPTOPP_POWER8_SHA_AVAILABLE
    if (HasSHA256())
    {
        SHA256_HashMultipleBlocks_POWER8(m_state, input, length, BIG_ENDIAN_ORDER);
        return length & (SHA256::BLOCKSIZE - 1);
    }
#endif

    const bool noReverse = NativeByteOrderIs(this->GetByteOrder());
    word32 *dataBuf = this->DataBuf();
    do
    {
        if (noReverse)
        {
            SHA256_HashBlock_CXX(m_state, input);
        }
        else
        {
            ByteReverse(dataBuf, input, SHA256::BLOCKSIZE);
            SHA256_HashBlock_CXX(m_state, dataBuf);
        }

        input += SHA256::BLOCKSIZE/sizeof(word32);
        length -= SHA256::BLOCKSIZE;
    }
    while (length >= SHA256::BLOCKSIZE);
    return length;
}

// *************************************************************

std::string SHA512_AlgorithmProvider()
{
#if CRYPTOPP_SSE2_ASM_AVAILABLE
    if (HasSSE2())
        return "SSE2";
#endif
#if CRYPTOGAMS_ARM_SHA512
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
        return "NEON";
    else
# endif
    if (HasARMv7())
        return "ARMv7";
#endif
#if (CRYPTOPP_POWER8_SHA_AVAILABLE)
    if (HasSHA512())
        return "Power8";
#endif
    return "C++";
}

std::string SHA384::AlgorithmProvider() const
{
    return SHA512_AlgorithmProvider();
}

std::string SHA512::AlgorithmProvider() const
{
    return SHA512_AlgorithmProvider();
}

void SHA384::InitState(HashWordType *state)
{
    const word64 s[8] = {
        W64LIT(0xcbbb9d5dc1059ed8), W64LIT(0x629a292a367cd507),
        W64LIT(0x9159015a3070dd17), W64LIT(0x152fecd8f70e5939),
        W64LIT(0x67332667ffc00b31), W64LIT(0x8eb44a8768581511),
        W64LIT(0xdb0c2e0d64f98fa7), W64LIT(0x47b5481dbefa4fa4)};
    memcpy(state, s, sizeof(s));
}

void SHA512::InitState(HashWordType *state)
{
    const word64 s[8] = {
        W64LIT(0x6a09e667f3bcc908), W64LIT(0xbb67ae8584caa73b),
        W64LIT(0x3c6ef372fe94f82b), W64LIT(0xa54ff53a5f1d36f1),
        W64LIT(0x510e527fade682d1), W64LIT(0x9b05688c2b3e6c1f),
        W64LIT(0x1f83d9abfb41bd6b), W64LIT(0x5be0cd19137e2179)};
    memcpy(state, s, sizeof(s));
}

#if CRYPTOPP_SSE2_ASM_AVAILABLE && (CRYPTOPP_BOOL_X86)

ANONYMOUS_NAMESPACE_BEGIN

// No inlining due to https://github.com/weidai11/cryptopp/issues/684
//   g++ -DNDEBUG -g2 -O3 -pthread -pipe -c sha.cpp
//   sha.cpp: Assembler messages:
//   sha.cpp:1155: Error: symbol `SHA512_Round' is already defined
//   sha.cpp:1155: Error: symbol `SHA512_Round' is already defined

CRYPTOPP_NOINLINE CRYPTOPP_NAKED
void CRYPTOPP_FASTCALL SHA512_HashBlock_SSE2(word64 *state, const word64 *data)
{
#ifdef __GNUC__
    __asm__ __volatile__
    (
    INTEL_NOPREFIX
    AS_PUSH_IF86(    bx)
    AS2(    mov      ebx, eax)
#else
    AS1(    push     ebx)
    AS1(    push     esi)
    AS1(    push     edi)
    AS2(    lea      ebx, SHA512_K)
#endif

    AS2(    mov      eax, esp)
    AS2(    and      esp, 0xfffffff0)
    AS2(    sub      esp, 27*16)                // 17*16 for expanded data, 20*8 for state
    AS_PUSH_IF86(    ax)
    AS2(    xor      eax, eax)

    AS2(    lea      edi, [esp+4+8*8])        // start at middle of state buffer. will decrement pointer each round to avoid copying
    AS2(    lea      esi, [esp+4+20*8+8])    // 16-byte alignment, then add 8

    AS2(    movdqu   xmm0, [ecx+0*16])
    AS2(    movdq2q  mm4, xmm0)
    AS2(    movdqu   [edi+0*16], xmm0)
    AS2(    movdqu   xmm0, [ecx+1*16])
    AS2(    movdqu   [edi+1*16], xmm0)
    AS2(    movdqu   xmm0, [ecx+2*16])
    AS2(    movdq2q  mm5, xmm0)
    AS2(    movdqu   [edi+2*16], xmm0)
    AS2(    movdqu   xmm0, [ecx+3*16])
    AS2(    movdqu   [edi+3*16], xmm0)
    ASJ(    jmp,     0, f)

#define SSE2_S0_S1(r, a, b, c)    \
    AS2(    movq     mm6, r)\
    AS2(    psrlq    r, a)\
    AS2(    movq     mm7, r)\
    AS2(    psllq    mm6, 64-c)\
    AS2(    pxor     mm7, mm6)\
    AS2(    psrlq    r, b-a)\
    AS2(    pxor     mm7, r)\
    AS2(    psllq    mm6, c-b)\
    AS2(    pxor     mm7, mm6)\
    AS2(    psrlq    r, c-b)\
    AS2(    pxor     r, mm7)\
    AS2(    psllq    mm6, b-a)\
    AS2(    pxor     r, mm6)

#define SSE2_s0(r, a, b, c)    \
    AS2(    movdqu   xmm6, r)\
    AS2(    psrlq    r, a)\
    AS2(    movdqu   xmm7, r)\
    AS2(    psllq    xmm6, 64-c)\
    AS2(    pxor     xmm7, xmm6)\
    AS2(    psrlq    r, b-a)\
    AS2(    pxor     xmm7, r)\
    AS2(    psrlq    r, c-b)\
    AS2(    pxor     r, xmm7)\
    AS2(    psllq    xmm6, c-a)\
    AS2(    pxor     r, xmm6)

#define SSE2_s1(r, a, b, c)    \
    AS2(    movdqu   xmm6, r)\
    AS2(    psrlq    r, a)\
    AS2(    movdqu   xmm7, r)\
    AS2(    psllq    xmm6, 64-c)\
    AS2(    pxor     xmm7, xmm6)\
    AS2(    psrlq    r, b-a)\
    AS2(    pxor     xmm7, r)\
    AS2(    psllq    xmm6, c-b)\
    AS2(    pxor     xmm7, xmm6)\
    AS2(    psrlq    r, c-b)\
    AS2(    pxor     r, xmm7)
    ASL(SHA512_Round)

    // k + w is in mm0, a is in mm4, e is in mm5
    AS2(    paddq    mm0, [edi+7*8])      // h
    AS2(    movq     mm2, [edi+5*8])      // f
    AS2(    movq     mm3, [edi+6*8])      // g
    AS2(    pxor     mm2, mm3)
    AS2(    pand     mm2, mm5)
    SSE2_S0_S1(mm5,14,18,41)
    AS2(    pxor     mm2, mm3)
    AS2(    paddq    mm0, mm2)            // h += Ch(e,f,g)
    AS2(    paddq    mm5, mm0)            // h += S1(e)
    AS2(    movq     mm2, [edi+1*8])      // b
    AS2(    movq     mm1, mm2)
    AS2(    por      mm2, mm4)
    AS2(    pand     mm2, [edi+2*8])      // c
    AS2(    pand     mm1, mm4)
    AS2(    por      mm1, mm2)
    AS2(    paddq    mm1, mm5)            // temp = h + Maj(a,b,c)
    AS2(    paddq    mm5, [edi+3*8])      // e = d + h
    AS2(    movq     [edi+3*8], mm5)
    AS2(    movq     [edi+11*8], mm5)
    SSE2_S0_S1(mm4,28,34,39)              // S0(a)
    AS2(    paddq    mm4, mm1)            // a = temp + S0(a)
    AS2(    movq     [edi-8], mm4)
    AS2(    movq     [edi+7*8], mm4)
    AS1(    ret)

    // first 16 rounds
    ASL(0)
    AS2(    movq     mm0, [edx+eax*8])
    AS2(    movq     [esi+eax*8], mm0)
    AS2(    movq     [esi+eax*8+16*8], mm0)
    AS2(    paddq    mm0, [ebx+eax*8])
    ASC(    call,    SHA512_Round)

    AS1(    inc      eax)
    AS2(    sub      edi, 8)
    AS2(    test     eax, 7)
    ASJ(    jnz,     0, b)
    AS2(    add      edi, 8*8)
    AS2(    cmp      eax, 16)
    ASJ(    jne,     0, b)

    // rest of the rounds
    AS2(    movdqu   xmm0, [esi+(16-2)*8])
    ASL(1)
    // data expansion, W[i-2] already in xmm0
    AS2(    movdqu   xmm3, [esi])
    AS2(    paddq    xmm3, [esi+(16-7)*8])
    AS2(    movdqu   xmm2, [esi+(16-15)*8])
    SSE2_s1(xmm0, 6, 19, 61)
    AS2(    paddq    xmm0, xmm3)
    SSE2_s0(xmm2, 1, 7, 8)
    AS2(    paddq    xmm0, xmm2)
    AS2(    movdq2q  mm0, xmm0)
    AS2(    movhlps  xmm1, xmm0)
    AS2(    paddq    mm0, [ebx+eax*8])
    AS2(    movlps   [esi], xmm0)
    AS2(    movlps   [esi+8], xmm1)
    AS2(    movlps   [esi+8*16], xmm0)
    AS2(    movlps   [esi+8*17], xmm1)
    // 2 rounds
    ASC(    call,    SHA512_Round)
    AS2(    sub      edi, 8)
    AS2(    movdq2q  mm0, xmm1)
    AS2(    paddq    mm0, [ebx+eax*8+8])
    ASC(    call,    SHA512_Round)
    // update indices and loop
    AS2(    add      esi, 16)
    AS2(    add      eax, 2)
    AS2(    sub      edi, 8)
    AS2(    test     eax, 7)
    ASJ(    jnz,     1, b)
    // do housekeeping every 8 rounds
    AS2(    mov      esi, 0xf)
    AS2(    and      esi, eax)
    AS2(    lea      esi, [esp+4+20*8+8+esi*8])
    AS2(    add      edi, 8*8)
    AS2(    cmp      eax, 80)
    ASJ(    jne,     1, b)

#define SSE2_CombineState(i)    \
    AS2(    movdqu   xmm0, [edi+i*16])\
    AS2(    paddq    xmm0, [ecx+i*16])\
    AS2(    movdqu   [ecx+i*16], xmm0)

    SSE2_CombineState(0)
    SSE2_CombineState(1)
    SSE2_CombineState(2)
    SSE2_CombineState(3)

    AS_POP_IF86(    sp)
    AS1(    emms)

#if defined(__GNUC__)
    AS_POP_IF86(    bx)
    ATT_PREFIX
        :
        : "a" (SHA512_K), "c" (state), "d" (data)
        : "%ebx", "%esi", "%edi", "%mm0", "%mm1", "%mm2", "%mm3", "%mm4", "%mm5",
          "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7",
          "memory", "cc"
    );
#else
    AS1(    pop        edi)
    AS1(    pop        esi)
    AS1(    pop        ebx)
    AS1(    ret)
#endif
}

ANONYMOUS_NAMESPACE_END

#endif    // CRYPTOPP_SSE2_ASM_AVAILABLE

ANONYMOUS_NAMESPACE_BEGIN

#define a(i) T[(0-i)&7]
#define b(i) T[(1-i)&7]
#define c(i) T[(2-i)&7]
#define d(i) T[(3-i)&7]
#define e(i) T[(4-i)&7]
#define f(i) T[(5-i)&7]
#define g(i) T[(6-i)&7]
#define h(i) T[(7-i)&7]

#define blk0(i) (W[i]=data[i])
#define blk2(i) (W[i&15]+=s1(W[(i-2)&15])+W[(i-7)&15]+s0(W[(i-15)&15]))

#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) (y^((x^y)&(y^z)))

#define s0(x) (rotrConstant<1>(x)^rotrConstant<8>(x)^(x>>7))
#define s1(x) (rotrConstant<19>(x)^rotrConstant<61>(x)^(x>>6))
#define S0(x) (rotrConstant<28>(x)^rotrConstant<34>(x)^rotrConstant<39>(x))
#define S1(x) (rotrConstant<14>(x)^rotrConstant<18>(x)^rotrConstant<41>(x))

#define R(i) h(i)+=S1(e(i))+Ch(e(i),f(i),g(i))+SHA512_K[i+j]+\
    (j?blk2(i):blk0(i));d(i)+=h(i);h(i)+=S0(a(i))+Maj(a(i),b(i),c(i));

void SHA512_HashBlock_CXX(word64 *state, const word64 *data)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);

    word64 W[16]={0}, T[8];

    /* Copy context->state[] to working vars */
    std::memcpy(T, state, sizeof(T));

    /* 80 operations, partially loop unrolled */
    for (unsigned int j=0; j<80; j+=16)
    {
        R( 0); R( 1); R( 2); R( 3);
        R( 4); R( 5); R( 6); R( 7);
        R( 8); R( 9); R(10); R(11);
        R(12); R(13); R(14); R(15);
    }

    state[0] += a(0);
    state[1] += b(0);
    state[2] += c(0);
    state[3] += d(0);
    state[4] += e(0);
    state[5] += f(0);
    state[6] += g(0);
    state[7] += h(0);
}

ANONYMOUS_NAMESPACE_END

void SHA512::Transform(word64 *state, const word64 *data)
{
    CRYPTOPP_ASSERT(state);
    CRYPTOPP_ASSERT(data);

#if CRYPTOPP_SSE2_ASM_AVAILABLE && (CRYPTOPP_BOOL_X86)
    if (HasSSE2())
    {
        SHA512_HashBlock_SSE2(state, data);
        return;
    }
#endif
#if CRYPTOGAMS_ARM_SHA512
# if CRYPTOPP_ARM_NEON_AVAILABLE
    if (HasNEON())
    {
#  if (CRYPTOPP_LITTLE_ENDIAN)
        word64 dataBuf[16];
        ByteReverse(dataBuf, data, SHA512::BLOCKSIZE);
        cryptogams_sha512_block_data_order_neon(state, dataBuf, 1);
#  else
        cryptogams_sha512_block_data_order_neon(state, data, 1);
#  endif
        return;
    }
    else
# endif
    if (HasARMv7())
    {
# if (CRYPTOPP_LITTLE_ENDIAN)
        word64 dataBuf[16];
        ByteReverse(dataBuf, data, SHA512::BLOCKSIZE);
        cryptogams_sha512_block_data_order(state, dataBuf, 1);
# else
        cryptogams_sha512_block_data_order(state, data, 1);
# endif
        return;
    }
#endif
#if CRYPTOPP_POWER8_SHA_AVAILABLE
    if (HasSHA512())
    {
        SHA512_HashMultipleBlocks_POWER8(state, data, SHA512::BLOCKSIZE, BIG_ENDIAN_ORDER);
        return;
    }
#endif

    SHA512_HashBlock_CXX(state, data);
}

#undef Ch
#undef Maj

#undef s0
#undef s1
#undef S0
#undef S1

#undef blk0
#undef blk1
#undef blk2

#undef R

#undef a
#undef b
#undef c
#undef d
#undef e
#undef f
#undef g
#undef h

NAMESPACE_END

#endif    // Not CRYPTOPP_GENERATE_X64_MASM
#endif    // Not CRYPTOPP_IMPORTS
