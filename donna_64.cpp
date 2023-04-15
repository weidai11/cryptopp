// donna_64.cpp - written and placed in public domain by Jeffrey Walton
//                Crypto++ specific implementation wrapped around Andrew
//                Moon's public domain curve25519-donna and ed25519-donna,
//                https://github.com/floodyberry/curve25519-donna and
//                https://github.com/floodyberry/ed25519-donna.

// The curve25519 and ed25519 source files multiplex different repos and
// architectures using namespaces. The repos are Andrew Moon's
// curve25519-donna and ed25519-donna. The architectures are 32-bit, 64-bit
// and SSE. For example, 32-bit x25519 uses symbols from Donna::X25519 and
// Donna::Arch32.

// A fair amount of duplication happens below, but we could not directly
// use curve25519 for both x25519 and ed25519. A close examination reveals
// slight differences in the implementation. For example, look at the
// two curve25519_sub functions.

// If needed, see Moon's commit "Go back to ignoring 256th bit [sic]",
// https://github.com/floodyberry/curve25519-donna/commit/57a683d18721a658

#include "pch.h"

#include "config.h"
#include "donna.h"
#include "secblock.h"
#include "sha.h"
#include "misc.h"
#include "cpu.h"

#include <istream>
#include <sstream>

#if CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE
# pragma GCC diagnostic ignored "-Wunused-function"
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4244)
#endif

// Squash MS LNK4221 and libtool warnings
extern const char DONNA64_FNAME[] = __FILE__;

ANONYMOUS_NAMESPACE_BEGIN

// Can't use GetAlignmentOf<word64>() because of C++11 and constexpr
// Can use 'const unsigned int' because of MSVC 2013
#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
# define ALIGN_SPEC 16
#else
# define ALIGN_SPEC 8
#endif

ANONYMOUS_NAMESPACE_END

#if defined(CRYPTOPP_CURVE25519_64BIT)

#include "donna_64.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word64;
using CryptoPP::GetWord;
using CryptoPP::PutWord;
using CryptoPP::LITTLE_ENDIAN_ORDER;

inline word64 U8TO64_LE(const byte* p)
{
    return GetWord<word64>(false, LITTLE_ENDIAN_ORDER, p);
}

inline void U64TO8_LE(byte* p, word64 w)
{
    PutWord(false, LITTLE_ENDIAN_ORDER, p, w);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)
NAMESPACE_BEGIN(X25519)
ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::sword32;
using CryptoPP::word64;
using CryptoPP::sword64;

using CryptoPP::GetBlock;
using CryptoPP::LittleEndian;

// Bring in all the symbols from the 64-bit header
using namespace CryptoPP::Donna::Arch64;

/* out = in */
inline void
curve25519_copy(bignum25519 out, const bignum25519 in) {
    out[0] = in[0]; out[1] = in[1];
    out[2] = in[2]; out[3] = in[3];
    out[4] = in[4];
}

/* out = a + b */
inline void
curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    out[0] = a[0] + b[0];
    out[1] = a[1] + b[1];
    out[2] = a[2] + b[2];
    out[3] = a[3] + b[3];
    out[4] = a[4] + b[4];
}

/* out = a - b */
inline void
curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    out[0] = a[0] + two54m152 - b[0];
    out[1] = a[1] + two54m8 - b[1];
    out[2] = a[2] + two54m8 - b[2];
    out[3] = a[3] + two54m8 - b[3];
    out[4] = a[4] + two54m8 - b[4];
}

/* out = (in * scalar) */
inline void
curve25519_scalar_product(bignum25519 out, const bignum25519 in, const word64 scalar) {
  word128 a;
  word64 c;

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    a = ((word128) in[0]) * scalar;     out[0] = (word64)a & reduce_mask_51; c = (word64)(a >> 51);
    a = ((word128) in[1]) * scalar + c; out[1] = (word64)a & reduce_mask_51; c = (word64)(a >> 51);
    a = ((word128) in[2]) * scalar + c; out[2] = (word64)a & reduce_mask_51; c = (word64)(a >> 51);
    a = ((word128) in[3]) * scalar + c; out[3] = (word64)a & reduce_mask_51; c = (word64)(a >> 51);
    a = ((word128) in[4]) * scalar + c; out[4] = (word64)a & reduce_mask_51; c = (word64)(a >> 51);
                                          out[0] += c * 19;
#else
    mul64x64_128(a, in[0], scalar)                  out[0] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
    mul64x64_128(a, in[1], scalar) add128_64(a, c)  out[1] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
    mul64x64_128(a, in[2], scalar) add128_64(a, c)  out[2] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
    mul64x64_128(a, in[3], scalar) add128_64(a, c)  out[3] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
    mul64x64_128(a, in[4], scalar) add128_64(a, c)  out[4] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
                                                    out[0] += c * 19;
#endif
}

/* out = a * b */
inline void
curve25519_mul(bignum25519 out, const bignum25519 a, const bignum25519 b) {
#if !defined(CRYPTOPP_WORD128_AVAILABLE)
    word128 mul;
#endif
    word128 t[5];
    word64 r0,r1,r2,r3,r4,s0,s1,s2,s3,s4,c;

    r0 = b[0]; r1 = b[1]; r2 = b[2]; r3 = b[3]; r4 = b[4];
    s0 = a[0]; s1 = a[1]; s2 = a[2]; s3 = a[3]; s4 = a[4];

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    t[0]  =  ((word128) r0) * s0;
    t[1]  =  ((word128) r0) * s1 + ((word128) r1) * s0;
    t[2]  =  ((word128) r0) * s2 + ((word128) r2) * s0 + ((word128) r1) * s1;
    t[3]  =  ((word128) r0) * s3 + ((word128) r3) * s0 + ((word128) r1) * s2 + ((word128) r2) * s1;
    t[4]  =  ((word128) r0) * s4 + ((word128) r4) * s0 + ((word128) r3) * s1 + ((word128) r1) * s3 + ((word128) r2) * s2;
#else
    mul64x64_128(t[0], r0, s0)
    mul64x64_128(t[1], r0, s1) mul64x64_128(mul, r1, s0) add128(t[1], mul)
    mul64x64_128(t[2], r0, s2) mul64x64_128(mul, r2, s0) add128(t[2], mul) mul64x64_128(mul, r1, s1) add128(t[2], mul)
    mul64x64_128(t[3], r0, s3) mul64x64_128(mul, r3, s0) add128(t[3], mul) mul64x64_128(mul, r1, s2) add128(t[3], mul) mul64x64_128(mul, r2, s1) add128(t[3], mul)
    mul64x64_128(t[4], r0, s4) mul64x64_128(mul, r4, s0) add128(t[4], mul) mul64x64_128(mul, r3, s1) add128(t[4], mul) mul64x64_128(mul, r1, s3) add128(t[4], mul) mul64x64_128(mul, r2, s2) add128(t[4], mul)
#endif

    r1 *= 19; r2 *= 19; r3 *= 19; r4 *= 19;

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    t[0] += ((word128) r4) * s1 + ((word128) r1) * s4 + ((word128) r2) * s3 + ((word128) r3) * s2;
    t[1] += ((word128) r4) * s2 + ((word128) r2) * s4 + ((word128) r3) * s3;
    t[2] += ((word128) r4) * s3 + ((word128) r3) * s4;
    t[3] += ((word128) r4) * s4;
#else
    mul64x64_128(mul, r4, s1) add128(t[0], mul) mul64x64_128(mul, r1, s4) add128(t[0], mul) mul64x64_128(mul, r2, s3) add128(t[0], mul) mul64x64_128(mul, r3, s2) add128(t[0], mul)
    mul64x64_128(mul, r4, s2) add128(t[1], mul) mul64x64_128(mul, r2, s4) add128(t[1], mul) mul64x64_128(mul, r3, s3) add128(t[1], mul)
    mul64x64_128(mul, r4, s3) add128(t[2], mul) mul64x64_128(mul, r3, s4) add128(t[2], mul)
    mul64x64_128(mul, r4, s4) add128(t[3], mul)
#endif

                         r0 = lo128(t[0]) & reduce_mask_51; shr128(c, t[0], 51);
    add128_64(t[1], c)   r1 = lo128(t[1]) & reduce_mask_51; shr128(c, t[1], 51);
    add128_64(t[2], c)   r2 = lo128(t[2]) & reduce_mask_51; shr128(c, t[2], 51);
    add128_64(t[3], c)   r3 = lo128(t[3]) & reduce_mask_51; shr128(c, t[3], 51);
    add128_64(t[4], c)   r4 = lo128(t[4]) & reduce_mask_51; shr128(c, t[4], 51);
    r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
    r1 +=   c;

    out[0] = r0; out[1] = r1; out[2] = r2; out[3] = r3; out[4] = r4;
}

/* out = in^(2 * count) */
inline void
curve25519_square_times(bignum25519 out, const bignum25519 in, word64 count) {
#if !defined(CRYPTOPP_WORD128_AVAILABLE)
    word128 mul;
#endif
    word128 t[5];
    word64 r0,r1,r2,r3,r4,c;
    word64 d0,d1,d2,d4,d419;

    r0 = in[0]; r1 = in[1]; r2 = in[2]; r3 = in[3]; r4 = in[4];

    do {
        d0 = r0 * 2; d1 = r1 * 2;
        d2 = r2 * 2 * 19;
        d419 = r4 * 19; d4 = d419 * 2;

#if defined(CRYPTOPP_WORD128_AVAILABLE)
        t[0] = ((word128) r0) * r0 + ((word128) d4) * r1 + (((word128) d2) * (r3     ));
        t[1] = ((word128) d0) * r1 + ((word128) d4) * r2 + (((word128) r3) * (r3 * 19));
        t[2] = ((word128) d0) * r2 + ((word128) r1) * r1 + (((word128) d4) * (r3     ));
        t[3] = ((word128) d0) * r3 + ((word128) d1) * r2 + (((word128) r4) * (d419   ));
        t[4] = ((word128) d0) * r4 + ((word128) d1) * r3 + (((word128) r2) * (r2     ));
#else
        mul64x64_128(t[0], r0, r0) mul64x64_128(mul, d4, r1) add128(t[0], mul) mul64x64_128(mul, d2,      r3) add128(t[0], mul)
        mul64x64_128(t[1], d0, r1) mul64x64_128(mul, d4, r2) add128(t[1], mul) mul64x64_128(mul, r3, r3 * 19) add128(t[1], mul)
        mul64x64_128(t[2], d0, r2) mul64x64_128(mul, r1, r1) add128(t[2], mul) mul64x64_128(mul, d4,      r3) add128(t[2], mul)
        mul64x64_128(t[3], d0, r3) mul64x64_128(mul, d1, r2) add128(t[3], mul) mul64x64_128(mul, r4,    d419) add128(t[3], mul)
        mul64x64_128(t[4], d0, r4) mul64x64_128(mul, d1, r3) add128(t[4], mul) mul64x64_128(mul, r2,      r2) add128(t[4], mul)
#endif

                             r0 = lo128(t[0]) & reduce_mask_51; shr128(c, t[0], 51);
        add128_64(t[1], c)   r1 = lo128(t[1]) & reduce_mask_51; shr128(c, t[1], 51);
        add128_64(t[2], c)   r2 = lo128(t[2]) & reduce_mask_51; shr128(c, t[2], 51);
        add128_64(t[3], c)   r3 = lo128(t[3]) & reduce_mask_51; shr128(c, t[3], 51);
        add128_64(t[4], c)   r4 = lo128(t[4]) & reduce_mask_51; shr128(c, t[4], 51);
        r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
        r1 +=   c;
    } while(--count);

    out[0] = r0; out[1] = r1; out[2] = r2; out[3] = r3; out[4] = r4;
}

inline void
curve25519_square(bignum25519 out, const bignum25519 in) {
#if !defined(CRYPTOPP_WORD128_AVAILABLE)
    word128 mul;
#endif
    word128 t[5];
    word64 r0,r1,r2,r3,r4,c;
    word64 d0,d1,d2,d4,d419;

    r0 = in[0]; r1 = in[1]; r2 = in[2]; r3 = in[3]; r4 = in[4];

    d0 = r0 * 2; d1 = r1 * 2;
    d2 = r2 * 2 * 19;
    d419 = r4 * 19; d4 = d419 * 2;

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    t[0] = ((word128) r0) * r0 + ((word128) d4) * r1 + (((word128) d2) * (r3     ));
    t[1] = ((word128) d0) * r1 + ((word128) d4) * r2 + (((word128) r3) * (r3 * 19));
    t[2] = ((word128) d0) * r2 + ((word128) r1) * r1 + (((word128) d4) * (r3     ));
    t[3] = ((word128) d0) * r3 + ((word128) d1) * r2 + (((word128) r4) * (d419   ));
    t[4] = ((word128) d0) * r4 + ((word128) d1) * r3 + (((word128) r2) * (r2     ));
#else
    mul64x64_128(t[0], r0, r0) mul64x64_128(mul, d4, r1) add128(t[0], mul) mul64x64_128(mul, d2,      r3) add128(t[0], mul)
    mul64x64_128(t[1], d0, r1) mul64x64_128(mul, d4, r2) add128(t[1], mul) mul64x64_128(mul, r3, r3 * 19) add128(t[1], mul)
    mul64x64_128(t[2], d0, r2) mul64x64_128(mul, r1, r1) add128(t[2], mul) mul64x64_128(mul, d4,      r3) add128(t[2], mul)
    mul64x64_128(t[3], d0, r3) mul64x64_128(mul, d1, r2) add128(t[3], mul) mul64x64_128(mul, r4,    d419) add128(t[3], mul)
    mul64x64_128(t[4], d0, r4) mul64x64_128(mul, d1, r3) add128(t[4], mul) mul64x64_128(mul, r2,      r2) add128(t[4], mul)
#endif

                         r0 = lo128(t[0]) & reduce_mask_51; shr128(c, t[0], 51);
    add128_64(t[1], c)   r1 = lo128(t[1]) & reduce_mask_51; shr128(c, t[1], 51);
    add128_64(t[2], c)   r2 = lo128(t[2]) & reduce_mask_51; shr128(c, t[2], 51);
    add128_64(t[3], c)   r3 = lo128(t[3]) & reduce_mask_51; shr128(c, t[3], 51);
    add128_64(t[4], c)   r4 = lo128(t[4]) & reduce_mask_51; shr128(c, t[4], 51);
    r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
    r1 +=   c;

    out[0] = r0; out[1] = r1; out[2] = r2; out[3] = r3; out[4] = r4;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
inline void
curve25519_expand(bignum25519 out, const byte *in) {
    word64 x0,x1,x2,x3;
    GetBlock<word64, LittleEndian> block(in);
    block(x0)(x1)(x2)(x3);

    out[0] = x0 & reduce_mask_51; x0 = (x0 >> 51) | (x1 << 13);
    out[1] = x0 & reduce_mask_51; x1 = (x1 >> 38) | (x2 << 26);
    out[2] = x1 & reduce_mask_51; x2 = (x2 >> 25) | (x3 << 39);
    out[3] = x2 & reduce_mask_51; x3 = (x3 >> 12);
    out[4] = x3 & reduce_mask_51; /* ignore the top bit */
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
inline void
curve25519_contract(byte *out, const bignum25519 input) {
    word64 t[5];
    word64 f, i;

    t[0] = input[0];
    t[1] = input[1];
    t[2] = input[2];
    t[3] = input[3];
    t[4] = input[4];

    #define curve25519_contract_carry() \
        t[1] += t[0] >> 51; t[0] &= reduce_mask_51; \
        t[2] += t[1] >> 51; t[1] &= reduce_mask_51; \
        t[3] += t[2] >> 51; t[2] &= reduce_mask_51; \
        t[4] += t[3] >> 51; t[3] &= reduce_mask_51;

    #define curve25519_contract_carry_full() curve25519_contract_carry() \
        t[0] += 19 * (t[4] >> 51); t[4] &= reduce_mask_51;

    #define curve25519_contract_carry_final() curve25519_contract_carry() \
        t[4] &= reduce_mask_51;

    curve25519_contract_carry_full()
    curve25519_contract_carry_full()

    /* now t is between 0 and 2^255-1, properly carried. */
    /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
    t[0] += 19;
    curve25519_contract_carry_full()

    /* now between 19 and 2^255-1 in both cases, and offset by 19. */
    t[0] += 0x8000000000000 - 19;
    t[1] += 0x8000000000000 - 1;
    t[2] += 0x8000000000000 - 1;
    t[3] += 0x8000000000000 - 1;
    t[4] += 0x8000000000000 - 1;

    /* now between 2^255 and 2^256-20, and offset by 2^255. */
    curve25519_contract_carry_final()

    #define write51full(n,shift) \
        f = ((t[n] >> shift) | (t[n+1] << (51 - shift))); \
        for (i = 0; i < 8; i++, f >>= 8) *out++ = (byte)f;
    #define write51(n) write51full(n,13*n)

    write51(0)
    write51(1)
    write51(2)
    write51(3)

    #undef curve25519_contract_carry
    #undef curve25519_contract_carry_full
    #undef curve25519_contract_carry_final
    #undef write51full
    #undef write51
}

/*
 * Swap the contents of [qx] and [qpx] iff @swap is non-zero
 */
inline void
curve25519_swap_conditional(bignum25519 x, bignum25519 qpx, word64 iswap) {
    const word64 swap = (word64)(-(sword64)iswap);
    word64 x0,x1,x2,x3,x4;

    x0 = swap & (x[0] ^ qpx[0]); x[0] ^= x0; qpx[0] ^= x0;
    x1 = swap & (x[1] ^ qpx[1]); x[1] ^= x1; qpx[1] ^= x1;
    x2 = swap & (x[2] ^ qpx[2]); x[2] ^= x2; qpx[2] ^= x2;
    x3 = swap & (x[3] ^ qpx[3]); x[3] ^= x3; qpx[3] ^= x3;
    x4 = swap & (x[4] ^ qpx[4]); x[4] ^= x4; qpx[4] ^= x4;
}

/*
 * In:  b =   2^5 - 2^0
 * Out: b = 2^250 - 2^0
 */
void
curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b) {
    ALIGN(ALIGN_SPEC) bignum25519 t0,c;

    /* 2^5  - 2^0 */ /* b */
    /* 2^10 - 2^5 */ curve25519_square_times(t0, b, 5);
    /* 2^10 - 2^0 */ curve25519_mul(b, t0, b);
    /* 2^20 - 2^10 */ curve25519_square_times(t0, b, 10);
    /* 2^20 - 2^0 */ curve25519_mul(c, t0, b);
    /* 2^40 - 2^20 */ curve25519_square_times(t0, c, 20);
    /* 2^40 - 2^0 */ curve25519_mul(t0, t0, c);
    /* 2^50 - 2^10 */ curve25519_square_times(t0, t0, 10);
    /* 2^50 - 2^0 */ curve25519_mul(b, t0, b);
    /* 2^100 - 2^50 */ curve25519_square_times(t0, b, 50);
    /* 2^100 - 2^0 */ curve25519_mul(c, t0, b);
    /* 2^200 - 2^100 */ curve25519_square_times(t0, c, 100);
    /* 2^200 - 2^0 */ curve25519_mul(t0, t0, c);
    /* 2^250 - 2^50 */ curve25519_square_times(t0, t0, 50);
    /* 2^250 - 2^0 */ curve25519_mul(b, t0, b);
}

/*
 * z^(p - 2) = z(2^255 - 21)
 */
void
curve25519_recip(bignum25519 out, const bignum25519 z) {
    ALIGN(ALIGN_SPEC) bignum25519 a, t0, b;

    /* 2 */ curve25519_square(a, z); /* a = 2 */
    /* 8 */ curve25519_square_times(t0, a, 2);
    /* 9 */ curve25519_mul(b, t0, z); /* b = 9 */
    /* 11 */ curve25519_mul(a, b, a); /* a = 11 */
    /* 22 */ curve25519_square(t0, a);
    /* 2^5 - 2^0 = 31 */ curve25519_mul(b, t0, b);
    /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
    /* 2^255 - 2^5 */ curve25519_square_times(b, b, 5);
    /* 2^255 - 21 */  curve25519_mul(out, b, a);
}

ANONYMOUS_NAMESPACE_END
NAMESPACE_END  // X25519
NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

//******************************* ed25519 *******************************//

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)
NAMESPACE_BEGIN(Ed25519)
ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::sword32;
using CryptoPP::word64;
using CryptoPP::sword64;

using CryptoPP::GetBlock;
using CryptoPP::LittleEndian;

using CryptoPP::SHA512;

// Bring in all the symbols from the 64-bit header
using namespace CryptoPP::Donna::Arch64;

/* out = in */
inline void
curve25519_copy(bignum25519 out, const bignum25519 in) {
    out[0] = in[0]; out[1] = in[1];
    out[2] = in[2]; out[3] = in[3];
    out[4] = in[4];
}

/* out = a + b */
inline void
curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    out[0] = a[0] + b[0]; out[1] = a[1] + b[1];
    out[2] = a[2] + b[2]; out[3] = a[3] + b[3];
    out[4] = a[4] + b[4];
}

/* out = a + b, where a and/or b are the result of a basic op (add,sub) */
inline void
curve25519_add_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    out[0] = a[0] + b[0]; out[1] = a[1] + b[1];
    out[2] = a[2] + b[2]; out[3] = a[3] + b[3];
    out[4] = a[4] + b[4];
}

inline void
curve25519_add_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word64 c;
    out[0] = a[0] + b[0]    ; c = (out[0] >> 51); out[0] &= reduce_mask_51;
    out[1] = a[1] + b[1] + c; c = (out[1] >> 51); out[1] &= reduce_mask_51;
    out[2] = a[2] + b[2] + c; c = (out[2] >> 51); out[2] &= reduce_mask_51;
    out[3] = a[3] + b[3] + c; c = (out[3] >> 51); out[3] &= reduce_mask_51;
    out[4] = a[4] + b[4] + c; c = (out[4] >> 51); out[4] &= reduce_mask_51;
    out[0] += c * 19;
}

/* out = a - b */
inline void
curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    out[0] = a[0] + twoP0    - b[0];
    out[1] = a[1] + twoP1234 - b[1];
    out[2] = a[2] + twoP1234 - b[2];
    out[3] = a[3] + twoP1234 - b[3];
    out[4] = a[4] + twoP1234 - b[4];
}

/* out = a - b, where a and/or b are the result of a basic op (add,sub) */
inline void
curve25519_sub_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    out[0] = a[0] + fourP0    - b[0];
    out[1] = a[1] + fourP1234 - b[1];
    out[2] = a[2] + fourP1234 - b[2];
    out[3] = a[3] + fourP1234 - b[3];
    out[4] = a[4] + fourP1234 - b[4];
}

inline void
curve25519_sub_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word64 c;
    out[0] = a[0] + fourP0    - b[0]    ; c = (out[0] >> 51); out[0] &= reduce_mask_51;
    out[1] = a[1] + fourP1234 - b[1] + c; c = (out[1] >> 51); out[1] &= reduce_mask_51;
    out[2] = a[2] + fourP1234 - b[2] + c; c = (out[2] >> 51); out[2] &= reduce_mask_51;
    out[3] = a[3] + fourP1234 - b[3] + c; c = (out[3] >> 51); out[3] &= reduce_mask_51;
    out[4] = a[4] + fourP1234 - b[4] + c; c = (out[4] >> 51); out[4] &= reduce_mask_51;
    out[0] += c * 19;
}

/* out = -a */
inline void
curve25519_neg(bignum25519 out, const bignum25519 a) {
    word64 c;
    out[0] = twoP0    - a[0]    ; c = (out[0] >> 51); out[0] &= reduce_mask_51;
    out[1] = twoP1234 - a[1] + c; c = (out[1] >> 51); out[1] &= reduce_mask_51;
    out[2] = twoP1234 - a[2] + c; c = (out[2] >> 51); out[2] &= reduce_mask_51;
    out[3] = twoP1234 - a[3] + c; c = (out[3] >> 51); out[3] &= reduce_mask_51;
    out[4] = twoP1234 - a[4] + c; c = (out[4] >> 51); out[4] &= reduce_mask_51;
    out[0] += c * 19;
}

/* out = a * b */
inline void
curve25519_mul(bignum25519 out, const bignum25519 in2, const bignum25519 in) {
#if !defined(CRYPTOPP_WORD128_AVAILABLE)
    word128 mul;
#endif
    word128 t[5];
    word64 r0,r1,r2,r3,r4,s0,s1,s2,s3,s4,c;

    r0 = in[0]; r1 = in[1];
    r2 = in[2]; r3 = in[3];
    r4 = in[4];

    s0 = in2[0]; s1 = in2[1];
    s2 = in2[2]; s3 = in2[3];
    s4 = in2[4];

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    t[0]  =  ((word128) r0) * s0;
    t[1]  =  ((word128) r0) * s1 + ((word128) r1) * s0;
    t[2]  =  ((word128) r0) * s2 + ((word128) r2) * s0 + ((word128) r1) * s1;
    t[3]  =  ((word128) r0) * s3 + ((word128) r3) * s0 + ((word128) r1) * s2 + ((word128) r2) * s1;
    t[4]  =  ((word128) r0) * s4 + ((word128) r4) * s0 + ((word128) r3) * s1 + ((word128) r1) * s3 + ((word128) r2) * s2;
#else
    mul64x64_128(t[0], r0, s0)
    mul64x64_128(t[1], r0, s1) mul64x64_128(mul, r1, s0) add128(t[1], mul)
    mul64x64_128(t[2], r0, s2) mul64x64_128(mul, r2, s0) add128(t[2], mul) mul64x64_128(mul, r1, s1) add128(t[2], mul)
    mul64x64_128(t[3], r0, s3) mul64x64_128(mul, r3, s0) add128(t[3], mul) mul64x64_128(mul, r1, s2) add128(t[3], mul) mul64x64_128(mul, r2, s1) add128(t[3], mul)
    mul64x64_128(t[4], r0, s4) mul64x64_128(mul, r4, s0) add128(t[4], mul) mul64x64_128(mul, r3, s1) add128(t[4], mul) mul64x64_128(mul, r1, s3) add128(t[4], mul) mul64x64_128(mul, r2, s2) add128(t[4], mul)
#endif

    r1 *= 19; r2 *= 19;
    r3 *= 19; r4 *= 19;

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    t[0] += ((word128) r4) * s1 + ((word128) r1) * s4 + ((word128) r2) * s3 + ((word128) r3) * s2;
    t[1] += ((word128) r4) * s2 + ((word128) r2) * s4 + ((word128) r3) * s3;
    t[2] += ((word128) r4) * s3 + ((word128) r3) * s4;
    t[3] += ((word128) r4) * s4;
#else
    mul64x64_128(mul, r4, s1) add128(t[0], mul) mul64x64_128(mul, r1, s4) add128(t[0], mul) mul64x64_128(mul, r2, s3) add128(t[0], mul) mul64x64_128(mul, r3, s2) add128(t[0], mul)
    mul64x64_128(mul, r4, s2) add128(t[1], mul) mul64x64_128(mul, r2, s4) add128(t[1], mul) mul64x64_128(mul, r3, s3) add128(t[1], mul)
    mul64x64_128(mul, r4, s3) add128(t[2], mul) mul64x64_128(mul, r3, s4) add128(t[2], mul)
    mul64x64_128(mul, r4, s4) add128(t[3], mul)
#endif

                         r0 = lo128(t[0]) & reduce_mask_51; shr128(c, t[0], 51);
    add128_64(t[1], c)   r1 = lo128(t[1]) & reduce_mask_51; shr128(c, t[1], 51);
    add128_64(t[2], c)   r2 = lo128(t[2]) & reduce_mask_51; shr128(c, t[2], 51);
    add128_64(t[3], c)   r3 = lo128(t[3]) & reduce_mask_51; shr128(c, t[3], 51);
    add128_64(t[4], c)   r4 = lo128(t[4]) & reduce_mask_51; shr128(c, t[4], 51);
    r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
    r1 +=   c;

    out[0] = r0; out[1] = r1;
    out[2] = r2; out[3] = r3;
    out[4] = r4;
}

void
curve25519_mul_noinline(bignum25519 out, const bignum25519 in2, const bignum25519 in) {
    curve25519_mul(out, in2, in);
}

/* out = in^(2 * count) */
void
curve25519_square_times(bignum25519 out, const bignum25519 in, word64 count) {
#if !defined(CRYPTOPP_WORD128_AVAILABLE)
    word128 mul;
#endif
    word128 t[5];
    word64 r0,r1,r2,r3,r4,c;
    word64 d0,d1,d2,d4,d419;

    r0 = in[0]; r1 = in[1];
    r2 = in[2]; r3 = in[3];
    r4 = in[4];

    do {
        d0 = r0 * 2;
        d1 = r1 * 2;
        d2 = r2 * 2 * 19;
        d419 = r4 * 19;
        d4 = d419 * 2;

#if defined(CRYPTOPP_WORD128_AVAILABLE)
        t[0] = ((word128) r0) * r0 + ((word128) d4) * r1 + (((word128) d2) * (r3     ));
        t[1] = ((word128) d0) * r1 + ((word128) d4) * r2 + (((word128) r3) * (r3 * 19));
        t[2] = ((word128) d0) * r2 + ((word128) r1) * r1 + (((word128) d4) * (r3     ));
        t[3] = ((word128) d0) * r3 + ((word128) d1) * r2 + (((word128) r4) * (d419   ));
        t[4] = ((word128) d0) * r4 + ((word128) d1) * r3 + (((word128) r2) * (r2     ));
#else
        mul64x64_128(t[0], r0, r0) mul64x64_128(mul, d4, r1) add128(t[0], mul) mul64x64_128(mul, d2,      r3) add128(t[0], mul)
        mul64x64_128(t[1], d0, r1) mul64x64_128(mul, d4, r2) add128(t[1], mul) mul64x64_128(mul, r3, r3 * 19) add128(t[1], mul)
        mul64x64_128(t[2], d0, r2) mul64x64_128(mul, r1, r1) add128(t[2], mul) mul64x64_128(mul, d4,      r3) add128(t[2], mul)
        mul64x64_128(t[3], d0, r3) mul64x64_128(mul, d1, r2) add128(t[3], mul) mul64x64_128(mul, r4,    d419) add128(t[3], mul)
        mul64x64_128(t[4], d0, r4) mul64x64_128(mul, d1, r3) add128(t[4], mul) mul64x64_128(mul, r2,      r2) add128(t[4], mul)
#endif

        r0 = lo128(t[0]) & reduce_mask_51;
        r1 = lo128(t[1]) & reduce_mask_51; shl128(c, t[0], 13); r1 += c;
        r2 = lo128(t[2]) & reduce_mask_51; shl128(c, t[1], 13); r2 += c;
        r3 = lo128(t[3]) & reduce_mask_51; shl128(c, t[2], 13); r3 += c;
        r4 = lo128(t[4]) & reduce_mask_51; shl128(c, t[3], 13); r4 += c;
                                           shl128(c, t[4], 13); r0 += c * 19;
                       c = r0 >> 51; r0 &= reduce_mask_51;
        r1 += c     ;  c = r1 >> 51; r1 &= reduce_mask_51;
        r2 += c     ;  c = r2 >> 51; r2 &= reduce_mask_51;
        r3 += c     ;  c = r3 >> 51; r3 &= reduce_mask_51;
        r4 += c     ;  c = r4 >> 51; r4 &= reduce_mask_51;
        r0 += c * 19;
    } while(--count);

    out[0] = r0; out[1] = r1;
    out[2] = r2; out[3] = r3;
    out[4] = r4;
}

inline void
curve25519_square(bignum25519 out, const bignum25519 in) {
#if !defined(CRYPTOPP_WORD128_AVAILABLE)
    word128 mul;
#endif
    word128 t[5];
    word64 r0,r1,r2,r3,r4,c;
    word64 d0,d1,d2,d4,d419;

    r0 = in[0]; r1 = in[1];
    r2 = in[2]; r3 = in[3];
    r4 = in[4];

    d0 = r0 * 2; d1 = r1 * 2;
    d2 = r2 * 2 * 19;
    d419 = r4 * 19;
    d4 = d419 * 2;

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    t[0] = ((word128) r0) * r0 + ((word128) d4) * r1 + (((word128) d2) * (r3     ));
    t[1] = ((word128) d0) * r1 + ((word128) d4) * r2 + (((word128) r3) * (r3 * 19));
    t[2] = ((word128) d0) * r2 + ((word128) r1) * r1 + (((word128) d4) * (r3     ));
    t[3] = ((word128) d0) * r3 + ((word128) d1) * r2 + (((word128) r4) * (d419   ));
    t[4] = ((word128) d0) * r4 + ((word128) d1) * r3 + (((word128) r2) * (r2     ));
#else
    mul64x64_128(t[0], r0, r0) mul64x64_128(mul, d4, r1) add128(t[0], mul) mul64x64_128(mul, d2,      r3) add128(t[0], mul)
    mul64x64_128(t[1], d0, r1) mul64x64_128(mul, d4, r2) add128(t[1], mul) mul64x64_128(mul, r3, r3 * 19) add128(t[1], mul)
    mul64x64_128(t[2], d0, r2) mul64x64_128(mul, r1, r1) add128(t[2], mul) mul64x64_128(mul, d4,      r3) add128(t[2], mul)
    mul64x64_128(t[3], d0, r3) mul64x64_128(mul, d1, r2) add128(t[3], mul) mul64x64_128(mul, r4,    d419) add128(t[3], mul)
    mul64x64_128(t[4], d0, r4) mul64x64_128(mul, d1, r3) add128(t[4], mul) mul64x64_128(mul, r2,      r2) add128(t[4], mul)
#endif

                         r0 = lo128(t[0]) & reduce_mask_51; shr128(c, t[0], 51);
    add128_64(t[1], c)   r1 = lo128(t[1]) & reduce_mask_51; shr128(c, t[1], 51);
    add128_64(t[2], c)   r2 = lo128(t[2]) & reduce_mask_51; shr128(c, t[2], 51);
    add128_64(t[3], c)   r3 = lo128(t[3]) & reduce_mask_51; shr128(c, t[3], 51);
    add128_64(t[4], c)   r4 = lo128(t[4]) & reduce_mask_51; shr128(c, t[4], 51);
    r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
    r1 +=   c;

    out[0] = r0; out[1] = r1;
    out[2] = r2; out[3] = r3;
    out[4] = r4;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
inline void
curve25519_expand(bignum25519 out, const byte *in) {
    word64 x0,x1,x2,x3;
    GetBlock<word64, LittleEndian> block(in);
    block(x0)(x1)(x2)(x3);

    out[0] = x0 & reduce_mask_51; x0 = (x0 >> 51) | (x1 << 13);
    out[1] = x0 & reduce_mask_51; x1 = (x1 >> 38) | (x2 << 26);
    out[2] = x1 & reduce_mask_51; x2 = (x2 >> 25) | (x3 << 39);
    out[3] = x2 & reduce_mask_51; x3 = (x3 >> 12);
    out[4] = x3 & reduce_mask_51;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
inline void
curve25519_contract(byte *out, const bignum25519 input) {
    word64 t[5];
    word64 f, i;

    t[0] = input[0];
    t[1] = input[1];
    t[2] = input[2];
    t[3] = input[3];
    t[4] = input[4];

    #define curve25519_contract_carry() \
        t[1] += t[0] >> 51; t[0] &= reduce_mask_51; \
        t[2] += t[1] >> 51; t[1] &= reduce_mask_51; \
        t[3] += t[2] >> 51; t[2] &= reduce_mask_51; \
        t[4] += t[3] >> 51; t[3] &= reduce_mask_51;

    #define curve25519_contract_carry_full() curve25519_contract_carry() \
        t[0] += 19 * (t[4] >> 51); t[4] &= reduce_mask_51;

    #define curve25519_contract_carry_final() curve25519_contract_carry() \
        t[4] &= reduce_mask_51;

    curve25519_contract_carry_full()
    curve25519_contract_carry_full()

    /* now t is between 0 and 2^255-1, properly carried. */
    /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
    t[0] += 19;
    curve25519_contract_carry_full()

    /* now between 19 and 2^255-1 in both cases, and offset by 19. */
    t[0] += (reduce_mask_51 + 1) - 19;
    t[1] += (reduce_mask_51 + 1) - 1;
    t[2] += (reduce_mask_51 + 1) - 1;
    t[3] += (reduce_mask_51 + 1) - 1;
    t[4] += (reduce_mask_51 + 1) - 1;

    /* now between 2^255 and 2^256-20, and offset by 2^255. */
    curve25519_contract_carry_final()

    #define write51full(n,shift) \
        f = ((t[n] >> shift) | (t[n+1] << (51 - shift))); \
        for (i = 0; i < 8; i++, f >>= 8) *out++ = (byte)f;
    #define write51(n) write51full(n,13*n)
    write51(0)
    write51(1)
    write51(2)
    write51(3)
}

#if !defined(ED25519_GCC_64BIT_CHOOSE)

/* out = (flag) ? in : out */
inline void
curve25519_move_conditional_bytes(byte out[96], const byte in[96], word64 flag)
{
    // TODO: enable this code path once we can test and benchmark it.
    // It is about 24 insns shorter, it avoids punning which may be UB,
    // and it is guaranteed constant time.
#if defined(__GNUC__) && defined(__x86_64__) && 0
    const word32 iter = 96/sizeof(word64);
    word64* outq = reinterpret_cast<word64*>(out);
    const word64* inq = reinterpret_cast<const word64*>(in);
    word64 idx=0, val;

    __asm__ __volatile__ (
        ".att_syntax                         ;\n"
        "cmpq     $0, %[flag]                ;\n"  // compare, set ZERO flag
        "movq     %[iter], %%rcx             ;\n"  // load iteration count
        "1:                                  ;\n"
        "  movq     (%[idx],%[out]), %[val]  ;\n"  // val = out[idx]
        "  cmovnzq  (%[idx],%[in]), %[val]   ;\n"  // copy in[idx] to val if NZ
        "  movq     %[val], (%[idx],%[out])  ;\n"  // out[idx] = val
        "  leaq     8(%[idx]), %[idx]        ;\n"  // increment index
        "  loopnz   1b                       ;\n"  // does not affect flags
        : [out] "+S" (outq), [in] "+D" (inq),
          [idx] "+b" (idx), [val] "=r" (val)
        : [flag] "g" (flag), [iter] "I" (iter)
        : "rcx", "memory", "cc"
    );
#else
    const word64 nb = flag - 1, b = ~nb;
    const word64 *inq = (const word64 *)(const void*)in;
    word64 *outq = (word64 *)(void *)out;
    outq[0] = (outq[0] & nb) | (inq[0] & b);
    outq[1] = (outq[1] & nb) | (inq[1] & b);
    outq[2] = (outq[2] & nb) | (inq[2] & b);
    outq[3] = (outq[3] & nb) | (inq[3] & b);
    outq[4] = (outq[4] & nb) | (inq[4] & b);
    outq[5] = (outq[5] & nb) | (inq[5] & b);
    outq[6] = (outq[6] & nb) | (inq[6] & b);
    outq[7] = (outq[7] & nb) | (inq[7] & b);
    outq[8] = (outq[8] & nb) | (inq[8] & b);
    outq[9] = (outq[9] & nb) | (inq[9] & b);
    outq[10] = (outq[10] & nb) | (inq[10] & b);
    outq[11] = (outq[11] & nb) | (inq[11] & b);
#endif
}

/* if (iswap) swap(a, b) */
inline void
curve25519_swap_conditional(bignum25519 a, bignum25519 b, word64 iswap) {
    const word64 swap = (word64)(-(sword64)iswap);
    word64 x0,x1,x2,x3,x4;

    x0 = swap & (a[0] ^ b[0]); a[0] ^= x0; b[0] ^= x0;
    x1 = swap & (a[1] ^ b[1]); a[1] ^= x1; b[1] ^= x1;
    x2 = swap & (a[2] ^ b[2]); a[2] ^= x2; b[2] ^= x2;
    x3 = swap & (a[3] ^ b[3]); a[3] ^= x3; b[3] ^= x3;
    x4 = swap & (a[4] ^ b[4]); a[4] ^= x4; b[4] ^= x4;
}

#endif /* ED25519_GCC_64BIT_CHOOSE */

// ************************************************************************************

inline void
ed25519_hash(byte *hash, const byte *in, size_t inlen) {
    SHA512().CalculateDigest(hash, in, inlen);
}

inline void
ed25519_extsk(hash_512bits extsk, const byte sk[32]) {
    ed25519_hash(extsk, sk, 32);
    extsk[0] &= 248;
    extsk[31] &= 127;
    extsk[31] |= 64;
}

void
UpdateFromStream(HashTransformation& hash, std::istream& stream)
{
    SecByteBlock block(4096);
    while (stream.read((char*)block.begin(), block.size()))
        hash.Update(block, block.size());

    std::streamsize rem = stream.gcount();
    if (rem)
        hash.Update(block, rem);

    block.SetMark(0);
}

void
ed25519_hram(hash_512bits hram, const byte RS[64], const byte pk[32], const byte *m, size_t mlen) {
    SHA512 hash;
    hash.Update(RS, 32);
    hash.Update(pk, 32);
    hash.Update(m, mlen);
    hash.Final(hram);
}

void
ed25519_hram(hash_512bits hram, const byte RS[64], const byte pk[32], std::istream& stream) {
    SHA512 hash;
    hash.Update(RS, 32);
    hash.Update(pk, 32);
    UpdateFromStream(hash, stream);
    hash.Final(hram);
}

bignum256modm_element_t
lt_modm(bignum256modm_element_t a, bignum256modm_element_t b) {
    return (a - b) >> 63;
}

void
reduce256_modm(bignum256modm r) {
    bignum256modm t;
    bignum256modm_element_t b = 0, pb, mask;

    /* t = r - m */
    pb = 0;
    pb += modm_m[0]; b = lt_modm(r[0], pb); t[0] = (r[0] - pb + (b << 56)); pb = b;
    pb += modm_m[1]; b = lt_modm(r[1], pb); t[1] = (r[1] - pb + (b << 56)); pb = b;
    pb += modm_m[2]; b = lt_modm(r[2], pb); t[2] = (r[2] - pb + (b << 56)); pb = b;
    pb += modm_m[3]; b = lt_modm(r[3], pb); t[3] = (r[3] - pb + (b << 56)); pb = b;
    pb += modm_m[4]; b = lt_modm(r[4], pb); t[4] = (r[4] - pb + (b << 32));

    /* keep r if r was smaller than m */
    mask = b - 1;

    r[0] ^= mask & (r[0] ^ t[0]);
    r[1] ^= mask & (r[1] ^ t[1]);
    r[2] ^= mask & (r[2] ^ t[2]);
    r[3] ^= mask & (r[3] ^ t[3]);
    r[4] ^= mask & (r[4] ^ t[4]);
}

void
barrett_reduce256_modm(bignum256modm r, const bignum256modm q1, const bignum256modm r1) {
    bignum256modm q3, r2;
    word128 c, mul;
    bignum256modm_element_t f, b, pb;

    /* q1 = x >> 248 = 264 bits = 5 56 bit elements
    q2 = mu * q1
    q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264 */
    mul64x64_128(c, modm_mu[0], q1[3])                 mul64x64_128(mul, modm_mu[3], q1[0]) add128(c, mul) mul64x64_128(mul, modm_mu[1], q1[2]) add128(c, mul) mul64x64_128(mul, modm_mu[2], q1[1]) add128(c, mul) shr128(f, c, 56);
    mul64x64_128(c, modm_mu[0], q1[4]) add128_64(c, f) mul64x64_128(mul, modm_mu[4], q1[0]) add128(c, mul) mul64x64_128(mul, modm_mu[3], q1[1]) add128(c, mul) mul64x64_128(mul, modm_mu[1], q1[3]) add128(c, mul) mul64x64_128(mul, modm_mu[2], q1[2]) add128(c, mul)
    f = lo128(c); q3[0] = (f >> 40) & 0xffff; shr128(f, c, 56);
    mul64x64_128(c, modm_mu[4], q1[1]) add128_64(c, f) mul64x64_128(mul, modm_mu[1], q1[4]) add128(c, mul) mul64x64_128(mul, modm_mu[2], q1[3]) add128(c, mul) mul64x64_128(mul, modm_mu[3], q1[2]) add128(c, mul)
    f = lo128(c); q3[0] |= (f << 16) & 0xffffffffffffff; q3[1] = (f >> 40) & 0xffff; shr128(f, c, 56);
    mul64x64_128(c, modm_mu[4], q1[2]) add128_64(c, f) mul64x64_128(mul, modm_mu[2], q1[4]) add128(c, mul) mul64x64_128(mul, modm_mu[3], q1[3]) add128(c, mul)
    f = lo128(c); q3[1] |= (f << 16) & 0xffffffffffffff; q3[2] = (f >> 40) & 0xffff; shr128(f, c, 56);
    mul64x64_128(c, modm_mu[4], q1[3]) add128_64(c, f) mul64x64_128(mul, modm_mu[3], q1[4]) add128(c, mul)
    f = lo128(c); q3[2] |= (f << 16) & 0xffffffffffffff; q3[3] = (f >> 40) & 0xffff; shr128(f, c, 56);
    mul64x64_128(c, modm_mu[4], q1[4]) add128_64(c, f)
    f = lo128(c); q3[3] |= (f << 16) & 0xffffffffffffff; q3[4] = (f >> 40) & 0xffff; shr128(f, c, 56);
    q3[4] |= (f << 16);

    mul64x64_128(c, modm_m[0], q3[0])
    r2[0] = lo128(c) & 0xffffffffffffff; shr128(f, c, 56);
    mul64x64_128(c, modm_m[0], q3[1]) add128_64(c, f) mul64x64_128(mul, modm_m[1], q3[0]) add128(c, mul)
    r2[1] = lo128(c) & 0xffffffffffffff; shr128(f, c, 56);
    mul64x64_128(c, modm_m[0], q3[2]) add128_64(c, f) mul64x64_128(mul, modm_m[2], q3[0]) add128(c, mul) mul64x64_128(mul, modm_m[1], q3[1]) add128(c, mul)
    r2[2] = lo128(c) & 0xffffffffffffff; shr128(f, c, 56);
    mul64x64_128(c, modm_m[0], q3[3]) add128_64(c, f) mul64x64_128(mul, modm_m[3], q3[0]) add128(c, mul) mul64x64_128(mul, modm_m[1], q3[2]) add128(c, mul) mul64x64_128(mul, modm_m[2], q3[1]) add128(c, mul)
    r2[3] = lo128(c) & 0xffffffffffffff; shr128(f, c, 56);
    mul64x64_128(c, modm_m[0], q3[4]) add128_64(c, f) mul64x64_128(mul, modm_m[4], q3[0]) add128(c, mul) mul64x64_128(mul, modm_m[3], q3[1]) add128(c, mul) mul64x64_128(mul, modm_m[1], q3[3]) add128(c, mul) mul64x64_128(mul, modm_m[2], q3[2]) add128(c, mul)
    r2[4] = lo128(c) & 0x0000ffffffffff;

    pb = 0;
    pb += r2[0]; b = lt_modm(r1[0], pb); r[0] = (r1[0] - pb + (b << 56)); pb = b;
    pb += r2[1]; b = lt_modm(r1[1], pb); r[1] = (r1[1] - pb + (b << 56)); pb = b;
    pb += r2[2]; b = lt_modm(r1[2], pb); r[2] = (r1[2] - pb + (b << 56)); pb = b;
    pb += r2[3]; b = lt_modm(r1[3], pb); r[3] = (r1[3] - pb + (b << 56)); pb = b;
    pb += r2[4]; b = lt_modm(r1[4], pb); r[4] = (r1[4] - pb + (b << 40));

    reduce256_modm(r);
    reduce256_modm(r);
}

void
add256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y) {
    bignum256modm_element_t c;

    c  = x[0] + y[0]; r[0] = c & 0xffffffffffffff; c >>= 56;
    c += x[1] + y[1]; r[1] = c & 0xffffffffffffff; c >>= 56;
    c += x[2] + y[2]; r[2] = c & 0xffffffffffffff; c >>= 56;
    c += x[3] + y[3]; r[3] = c & 0xffffffffffffff; c >>= 56;
    c += x[4] + y[4]; r[4] = c;

    reduce256_modm(r);
}

void
mul256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y) {
    bignum256modm q1, r1;
    word128 c, mul;
    bignum256modm_element_t f;

    mul64x64_128(c, x[0], y[0])
    f = lo128(c); r1[0] = f & 0xffffffffffffff; shr128(f, c, 56);
    mul64x64_128(c, x[0], y[1]) add128_64(c, f) mul64x64_128(mul, x[1], y[0]) add128(c, mul)
    f = lo128(c); r1[1] = f & 0xffffffffffffff; shr128(f, c, 56);
    mul64x64_128(c, x[0], y[2]) add128_64(c, f) mul64x64_128(mul, x[2], y[0]) add128(c, mul) mul64x64_128(mul, x[1], y[1]) add128(c, mul)
    f = lo128(c); r1[2] = f & 0xffffffffffffff; shr128(f, c, 56);
    mul64x64_128(c, x[0], y[3]) add128_64(c, f) mul64x64_128(mul, x[3], y[0]) add128(c, mul) mul64x64_128(mul, x[1], y[2]) add128(c, mul) mul64x64_128(mul, x[2], y[1]) add128(c, mul)
    f = lo128(c); r1[3] = f & 0xffffffffffffff; shr128(f, c, 56);
    mul64x64_128(c, x[0], y[4]) add128_64(c, f) mul64x64_128(mul, x[4], y[0]) add128(c, mul) mul64x64_128(mul, x[3], y[1]) add128(c, mul) mul64x64_128(mul, x[1], y[3]) add128(c, mul) mul64x64_128(mul, x[2], y[2]) add128(c, mul)
    f = lo128(c); r1[4] = f & 0x0000ffffffffff; q1[0] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
    mul64x64_128(c, x[4], y[1]) add128_64(c, f) mul64x64_128(mul, x[1], y[4]) add128(c, mul) mul64x64_128(mul, x[2], y[3]) add128(c, mul) mul64x64_128(mul, x[3], y[2]) add128(c, mul)
    f = lo128(c); q1[0] |= (f << 32) & 0xffffffffffffff; q1[1] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
    mul64x64_128(c, x[4], y[2]) add128_64(c, f) mul64x64_128(mul, x[2], y[4]) add128(c, mul) mul64x64_128(mul, x[3], y[3]) add128(c, mul)
    f = lo128(c); q1[1] |= (f << 32) & 0xffffffffffffff; q1[2] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
    mul64x64_128(c, x[4], y[3]) add128_64(c, f) mul64x64_128(mul, x[3], y[4]) add128(c, mul)
    f = lo128(c); q1[2] |= (f << 32) & 0xffffffffffffff; q1[3] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
    mul64x64_128(c, x[4], y[4]) add128_64(c, f)
    f = lo128(c); q1[3] |= (f << 32) & 0xffffffffffffff; q1[4] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
    q1[4] |= (f << 32);

    barrett_reduce256_modm(r, q1, r1);
}

void
expand256_modm(bignum256modm out, const byte *in, size_t len) {
    byte work[64] = {0};
    bignum256modm_element_t x[16];
    bignum256modm q1;

    std::memcpy(work, in, len);
    x[0] = U8TO64_LE(work +  0);
    x[1] = U8TO64_LE(work +  8);
    x[2] = U8TO64_LE(work + 16);
    x[3] = U8TO64_LE(work + 24);
    x[4] = U8TO64_LE(work + 32);
    x[5] = U8TO64_LE(work + 40);
    x[6] = U8TO64_LE(work + 48);
    x[7] = U8TO64_LE(work + 56);

    /* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
    out[0] = (                         x[0]) & 0xffffffffffffff;
    out[1] = ((x[ 0] >> 56) | (x[ 1] <<  8)) & 0xffffffffffffff;
    out[2] = ((x[ 1] >> 48) | (x[ 2] << 16)) & 0xffffffffffffff;
    out[3] = ((x[ 2] >> 40) | (x[ 3] << 24)) & 0xffffffffffffff;
    out[4] = ((x[ 3] >> 32) | (x[ 4] << 32)) & 0x0000ffffffffff;

    /* under 252 bits, no need to reduce */
    if (len < 32)
        return;

    /* q1 = x >> 248 = 264 bits */
    q1[0] = ((x[ 3] >> 56) | (x[ 4] <<  8)) & 0xffffffffffffff;
    q1[1] = ((x[ 4] >> 48) | (x[ 5] << 16)) & 0xffffffffffffff;
    q1[2] = ((x[ 5] >> 40) | (x[ 6] << 24)) & 0xffffffffffffff;
    q1[3] = ((x[ 6] >> 32) | (x[ 7] << 32)) & 0xffffffffffffff;
    q1[4] = ((x[ 7] >> 24)                );

    barrett_reduce256_modm(out, q1, out);
}

void
expand_raw256_modm(bignum256modm out, const byte in[32]) {
    bignum256modm_element_t x[4];

    x[0] = U8TO64_LE(in +  0);
    x[1] = U8TO64_LE(in +  8);
    x[2] = U8TO64_LE(in + 16);
    x[3] = U8TO64_LE(in + 24);

    out[0] = (                         x[0]) & 0xffffffffffffff;
    out[1] = ((x[ 0] >> 56) | (x[ 1] <<  8)) & 0xffffffffffffff;
    out[2] = ((x[ 1] >> 48) | (x[ 2] << 16)) & 0xffffffffffffff;
    out[3] = ((x[ 2] >> 40) | (x[ 3] << 24)) & 0xffffffffffffff;
    out[4] = ((x[ 3] >> 32)                ) & 0x000000ffffffff;
}

void
contract256_modm(byte out[32], const bignum256modm in) {
    U64TO8_LE(out +  0, (in[0]      ) | (in[1] << 56));
    U64TO8_LE(out +  8, (in[1] >>  8) | (in[2] << 48));
    U64TO8_LE(out + 16, (in[2] >> 16) | (in[3] << 40));
    U64TO8_LE(out + 24, (in[3] >> 24) | (in[4] << 32));
}

void
contract256_window4_modm(signed char r[64], const bignum256modm in) {
    char carry;
    signed char *quads = r;
    bignum256modm_element_t i, j, v, m;

    for (i = 0; i < 5; i++) {
        v = in[i];
        m = (i == 4) ? 8 : 14;
        for (j = 0; j < m; j++) {
            *quads++ = (v & 15);
            v >>= 4;
        }
    }

    /* making it signed */
    carry = 0;
    for(i = 0; i < 63; i++) {
        r[i] += carry;
        r[i+1] += (r[i] >> 4);
        r[i] &= 15;
        carry = (r[i] >> 3);
        r[i] -= (carry << 4);
    }
    r[63] += carry;
}

void
contract256_slidingwindow_modm(signed char r[256], const bignum256modm s, int windowsize) {
    int i,j,k,b;
    int m = (1 << (windowsize - 1)) - 1, soplen = 256;
    signed char *bits = r;
    bignum256modm_element_t v;

    /* first put the binary expansion into r  */
    for (i = 0; i < 4; i++) {
        v = s[i];
        for (j = 0; j < 56; j++, v >>= 1)
            *bits++ = (v & 1);
    }
    v = s[4];
    for (j = 0; j < 32; j++, v >>= 1)
        *bits++ = (v & 1);

    /* Making it sliding window */
    for (j = 0; j < soplen; j++) {
        if (!r[j])
            continue;

        for (b = 1; (b < (soplen - j)) && (b <= 6); b++) {
            if ((r[j] + (r[j + b] << b)) <= m) {
                r[j] += r[j + b] << b;
                r[j + b] = 0;
            } else if ((r[j] - (r[j + b] << b)) >= -m) {
                r[j] -= r[j + b] << b;
                for (k = j + b; k < soplen; k++) {
                    if (!r[k]) {
                        r[k] = 1;
                        break;
                    }
                    r[k] = 0;
                }
            } else if (r[j + b]) {
                break;
            }
        }
    }
}

/*
 * In:  b =   2^5 - 2^0
 * Out: b = 2^250 - 2^0
 */
void
curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b) {
    ALIGN(ALIGN_SPEC) bignum25519 t0,c;

    /* 2^5  - 2^0 */ /* b */
    /* 2^10 - 2^5 */ curve25519_square_times(t0, b, 5);
    /* 2^10 - 2^0 */ curve25519_mul_noinline(b, t0, b);
    /* 2^20 - 2^10 */ curve25519_square_times(t0, b, 10);
    /* 2^20 - 2^0 */ curve25519_mul_noinline(c, t0, b);
    /* 2^40 - 2^20 */ curve25519_square_times(t0, c, 20);
    /* 2^40 - 2^0 */ curve25519_mul_noinline(t0, t0, c);
    /* 2^50 - 2^10 */ curve25519_square_times(t0, t0, 10);
    /* 2^50 - 2^0 */ curve25519_mul_noinline(b, t0, b);
    /* 2^100 - 2^50 */ curve25519_square_times(t0, b, 50);
    /* 2^100 - 2^0 */ curve25519_mul_noinline(c, t0, b);
    /* 2^200 - 2^100 */ curve25519_square_times(t0, c, 100);
    /* 2^200 - 2^0 */ curve25519_mul_noinline(t0, t0, c);
    /* 2^250 - 2^50 */ curve25519_square_times(t0, t0, 50);
    /* 2^250 - 2^0 */ curve25519_mul_noinline(b, t0, b);
}

/*
 * z^(p - 2) = z(2^255 - 21)
 */
void
curve25519_recip(bignum25519 out, const bignum25519 z) {
    ALIGN(ALIGN_SPEC) bignum25519 a,t0,b;

    /* 2 */ curve25519_square_times(a, z, 1); /* a = 2 */
    /* 8 */ curve25519_square_times(t0, a, 2);
    /* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
    /* 11 */ curve25519_mul_noinline(a, b, a); /* a = 11 */
    /* 22 */ curve25519_square_times(t0, a, 1);
    /* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
    /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
    /* 2^255 - 2^5 */ curve25519_square_times(b, b, 5);
    /* 2^255 - 21 */ curve25519_mul_noinline(out, b, a);
}

/*
 * z^((p-5)/8) = z^(2^252 - 3)
 */
void
curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z) {
    ALIGN(ALIGN_SPEC) bignum25519 b,c,t0;

    /* 2 */ curve25519_square_times(c, z, 1); /* c = 2 */
    /* 8 */ curve25519_square_times(t0, c, 2); /* t0 = 8 */
    /* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
    /* 11 */ curve25519_mul_noinline(c, b, c); /* c = 11 */
    /* 22 */ curve25519_square_times(t0, c, 1);
    /* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
    /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
    /* 2^252 - 2^2 */ curve25519_square_times(b, b, 2);
    /* 2^252 - 3 */ curve25519_mul_noinline(two252m3, b, z);
}

inline void
ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p) {
    curve25519_mul(r->x, p->x, p->t);
    curve25519_mul(r->y, p->y, p->z);
    curve25519_mul(r->z, p->z, p->t);
}

inline void
ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p) {
    curve25519_mul(r->x, p->x, p->t);
    curve25519_mul(r->y, p->y, p->z);
    curve25519_mul(r->z, p->z, p->t);
    curve25519_mul(r->t, p->x, p->y);
}

void
ge25519_full_to_pniels(ge25519_pniels *p, const ge25519 *r) {
    curve25519_sub(p->ysubx, r->y, r->x);
    curve25519_add(p->xaddy, r->y, r->x);
    curve25519_copy(p->z, r->z);
    curve25519_mul(p->t2d, r->t, ge25519_ec2d);
}

void
ge25519_add_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519 *q) {
    bignum25519 a,b,c,d,t,u;

    curve25519_sub(a, p->y, p->x);
    curve25519_add(b, p->y, p->x);
    curve25519_sub(t, q->y, q->x);
    curve25519_add(u, q->y, q->x);
    curve25519_mul(a, a, t);
    curve25519_mul(b, b, u);
    curve25519_mul(c, p->t, q->t);
    curve25519_mul(c, c, ge25519_ec2d);
    curve25519_mul(d, p->z, q->z);
    curve25519_add(d, d, d);
    curve25519_sub(r->x, b, a);
    curve25519_add(r->y, b, a);
    curve25519_add_after_basic(r->z, d, c);
    curve25519_sub_after_basic(r->t, d, c);
}

void
ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p) {
    bignum25519 a,b,c;

    curve25519_square(a, p->x);
    curve25519_square(b, p->y);
    curve25519_square(c, p->z);
    curve25519_add_reduce(c, c, c);
    curve25519_add(r->x, p->x, p->y);
    curve25519_square(r->x, r->x);
    curve25519_add(r->y, b, a);
    curve25519_sub(r->z, b, a);
    curve25519_sub_after_basic(r->x, r->x, r->y);
    curve25519_sub_after_basic(r->t, c, r->z);
}

void
ge25519_nielsadd2_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_niels *q, byte signbit) {
    const bignum25519 *qb = (const bignum25519 *)q;
    bignum25519 *rb = (bignum25519 *)r;
    bignum25519 a,b,c;

    curve25519_sub(a, p->y, p->x);
    curve25519_add(b, p->y, p->x);
    curve25519_mul(a, a, qb[signbit]); /* x for +, y for - */
    curve25519_mul(r->x, b, qb[signbit^1]); /* y for +, x for - */
    curve25519_add(r->y, r->x, a);
    curve25519_sub(r->x, r->x, a);
    curve25519_mul(c, p->t, q->t2d);
    curve25519_add_reduce(r->t, p->z, p->z);
    curve25519_copy(r->z, r->t);
    curve25519_add(rb[2+signbit], rb[2+signbit], c); /* z for +, t for - */
    curve25519_sub(rb[2+(signbit^1)], rb[2+(signbit^1)], c); /* t for +, z for - */
}

void
ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_pniels *q, byte signbit) {
    const bignum25519 *qb = (const bignum25519 *)q;
    bignum25519 *rb = (bignum25519 *)r;
    bignum25519 a,b,c;

    curve25519_sub(a, p->y, p->x);
    curve25519_add(b, p->y, p->x);
    curve25519_mul(a, a, qb[signbit]); /* ysubx for +, xaddy for - */
    curve25519_mul(r->x, b, qb[signbit^1]); /* xaddy for +, ysubx for - */
    curve25519_add(r->y, r->x, a);
    curve25519_sub(r->x, r->x, a);
    curve25519_mul(c, p->t, q->t2d);
    curve25519_mul(r->t, p->z, q->z);
    curve25519_add_reduce(r->t, r->t, r->t);
    curve25519_copy(r->z, r->t);
    curve25519_add(rb[2+signbit], rb[2+signbit], c); /* z for +, t for - */
    curve25519_sub(rb[2+(signbit^1)], rb[2+(signbit^1)], c); /* t for +, z for - */
}

void
ge25519_double_partial(ge25519 *r, const ge25519 *p) {
    ge25519_p1p1 t;
    ge25519_double_p1p1(&t, p);
    ge25519_p1p1_to_partial(r, &t);
}

void
ge25519_double(ge25519 *r, const ge25519 *p) {
    ge25519_p1p1 t;
    ge25519_double_p1p1(&t, p);
    ge25519_p1p1_to_full(r, &t);
}

void
ge25519_add(ge25519 *r, const ge25519 *p,  const ge25519 *q) {
    ge25519_p1p1 t;
    ge25519_add_p1p1(&t, p, q);
    ge25519_p1p1_to_full(r, &t);
}

void
ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q) {
    bignum25519 a,b,c,e,f,g,h;

    curve25519_sub(a, r->y, r->x);
    curve25519_add(b, r->y, r->x);
    curve25519_mul(a, a, q->ysubx);
    curve25519_mul(e, b, q->xaddy);
    curve25519_add(h, e, a);
    curve25519_sub(e, e, a);
    curve25519_mul(c, r->t, q->t2d);
    curve25519_add(f, r->z, r->z);
    curve25519_add_after_basic(g, f, c);
    curve25519_sub_after_basic(f, f, c);
    curve25519_mul(r->x, e, f);
    curve25519_mul(r->y, h, g);
    curve25519_mul(r->z, g, f);
    curve25519_mul(r->t, e, h);
}

void
ge25519_pnielsadd(ge25519_pniels *r, const ge25519 *p, const ge25519_pniels *q) {
    bignum25519 a,b,c,x,y,z,t;

    curve25519_sub(a, p->y, p->x);
    curve25519_add(b, p->y, p->x);
    curve25519_mul(a, a, q->ysubx);
    curve25519_mul(x, b, q->xaddy);
    curve25519_add(y, x, a);
    curve25519_sub(x, x, a);
    curve25519_mul(c, p->t, q->t2d);
    curve25519_mul(t, p->z, q->z);
    curve25519_add(t, t, t);
    curve25519_add_after_basic(z, t, c);
    curve25519_sub_after_basic(t, t, c);
    curve25519_mul(r->xaddy, x, t);
    curve25519_mul(r->ysubx, y, z);
    curve25519_mul(r->z, z, t);
    curve25519_mul(r->t2d, x, y);
    curve25519_copy(y, r->ysubx);
    curve25519_sub(r->ysubx, r->ysubx, r->xaddy);
    curve25519_add(r->xaddy, r->xaddy, y);
    curve25519_mul(r->t2d, r->t2d, ge25519_ec2d);
}

void
ge25519_pack(byte r[32], const ge25519 *p) {
    bignum25519 tx, ty, zi;
    byte parity[32];
    curve25519_recip(zi, p->z);
    curve25519_mul(tx, p->x, zi);
    curve25519_mul(ty, p->y, zi);
    curve25519_contract(r, ty);
    curve25519_contract(parity, tx);
    r[31] ^= ((parity[0] & 1) << 7);
}

int
ed25519_verify(const byte *x, const byte *y, size_t len) {
    size_t differentbits = 0;
    while (len--)
        differentbits |= (*x++ ^ *y++);
    return (int) (1 & ((differentbits - 1) >> 8));
}

int
ge25519_unpack_negative_vartime(ge25519 *r, const byte p[32]) {
    const byte zero[32] = {0};
    const bignum25519 one = {1};
    byte parity = p[31] >> 7;
    byte check[32];
    bignum25519 t, root, num, den, d3;

    curve25519_expand(r->y, p);
    curve25519_copy(r->z, one);
    curve25519_square(num, r->y); /* x = y^2 */
    curve25519_mul(den, num, ge25519_ecd); /* den = dy^2 */
    curve25519_sub_reduce(num, num, r->z); /* x = y^1 - 1 */
    curve25519_add(den, den, r->z); /* den = dy^2 + 1 */

    /* Computation of sqrt(num/den) */
    /* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
    curve25519_square(t, den);
    curve25519_mul(d3, t, den);
    curve25519_square(r->x, d3);
    curve25519_mul(r->x, r->x, den);
    curve25519_mul(r->x, r->x, num);
    curve25519_pow_two252m3(r->x, r->x);

    /* 2. computation of r->x = num * den^3 * (num*den^7)^((p-5)/8) */
    curve25519_mul(r->x, r->x, d3);
    curve25519_mul(r->x, r->x, num);

    /* 3. Check if either of the roots works: */
    curve25519_square(t, r->x);
    curve25519_mul(t, t, den);
    curve25519_sub_reduce(root, t, num);
    curve25519_contract(check, root);
    if (!ed25519_verify(check, zero, 32)) {
        curve25519_add_reduce(t, t, num);
        curve25519_contract(check, t);
        if (!ed25519_verify(check, zero, 32))
            return 0;
        curve25519_mul(r->x, r->x, ge25519_sqrtneg1);
    }

    curve25519_contract(check, r->x);
    if ((check[0] & 1) == parity) {
        curve25519_copy(t, r->x);
        curve25519_neg(r->x, t);
    }
    curve25519_mul(r->t, r->x, r->y);
    return 1;
}

/* computes [s1]p1 + [s2]basepoint */
void
ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2) {
    signed char slide1[256], slide2[256];
    ge25519_pniels pre1[S1_TABLE_SIZE];
    ge25519 d1;
    ge25519_p1p1 t;
    sword32 i;

    contract256_slidingwindow_modm(slide1, s1, S1_SWINDOWSIZE);
    contract256_slidingwindow_modm(slide2, s2, S2_SWINDOWSIZE);

    ge25519_double(&d1, p1);
    ge25519_full_to_pniels(pre1, p1);
    for (i = 0; i < S1_TABLE_SIZE - 1; i++)
            ge25519_pnielsadd(&pre1[i+1], &d1, &pre1[i]);

    /* set neutral */
    std::memset(r, 0, sizeof(ge25519));
    r->y[0] = 1;
    r->z[0] = 1;

    i = 255;
    while ((i >= 0) && !(slide1[i] | slide2[i]))
        i--;

    for (; i >= 0; i--) {
        ge25519_double_p1p1(&t, r);

        if (slide1[i]) {
            ge25519_p1p1_to_full(r, &t);
            ge25519_pnielsadd_p1p1(&t, r, &pre1[abs(slide1[i]) / 2], (byte)slide1[i] >> 7);
        }

        if (slide2[i]) {
            ge25519_p1p1_to_full(r, &t);
            ge25519_nielsadd2_p1p1(&t, r, &ge25519_niels_sliding_multiples[abs(slide2[i]) / 2], (byte)slide2[i] >> 7);
        }

        ge25519_p1p1_to_partial(r, &t);
    }
}

#if !defined(HAVE_GE25519_SCALARMULT_BASE_CHOOSE_NIELS)

word32
ge25519_windowb_equal(word32 b, word32 c) {
    return ((b ^ c) - 1) >> 31;
}

void
ge25519_scalarmult_base_choose_niels(ge25519_niels *t, const byte table[256][96], word32 pos, signed char b) {
    bignum25519 neg;
    word32 sign = (word32)((byte)b >> 7);
    word32 mask = ~(sign - 1);
    word32 u = (b + mask) ^ mask;
    word32 i;

    /* ysubx, xaddy, t2d in packed form. initialize to ysubx = 1, xaddy = 1, t2d = 0 */
    byte packed[96] = {0};
    packed[0] = 1;
    packed[32] = 1;

    for (i = 0; i < 8; i++)
        curve25519_move_conditional_bytes(packed, table[(pos * 8) + i], ge25519_windowb_equal(u, i + 1));

    /* expand in to t */
    curve25519_expand(t->ysubx, packed +  0);
    curve25519_expand(t->xaddy, packed + 32);
    curve25519_expand(t->t2d  , packed + 64);

    /* adjust for sign */
    curve25519_swap_conditional(t->ysubx, t->xaddy, sign);
    curve25519_neg(neg, t->t2d);
    curve25519_swap_conditional(t->t2d, neg, sign);
}

#endif /* HAVE_GE25519_SCALARMULT_BASE_CHOOSE_NIELS */

/* computes [s]basepoint */
void
ge25519_scalarmult_base_niels(ge25519 *r, const byte basepoint_table[256][96], const bignum256modm s) {
    signed char b[64];
    word32 i;
    ge25519_niels t;

    contract256_window4_modm(b, s);

    ge25519_scalarmult_base_choose_niels(&t, basepoint_table, 0, b[1]);
    curve25519_sub_reduce(r->x, t.xaddy, t.ysubx);
    curve25519_add_reduce(r->y, t.xaddy, t.ysubx);
    std::memset(r->z, 0, sizeof(bignum25519));
    curve25519_copy(r->t, t.t2d);
    r->z[0] = 2;
    for (i = 3; i < 64; i += 2) {
        ge25519_scalarmult_base_choose_niels(&t, basepoint_table, i / 2, b[i]);
        ge25519_nielsadd2(r, &t);
    }
    ge25519_double_partial(r, r);
    ge25519_double_partial(r, r);
    ge25519_double_partial(r, r);
    ge25519_double(r, r);
    ge25519_scalarmult_base_choose_niels(&t, basepoint_table, 0, b[0]);
    curve25519_mul(t.t2d, t.t2d, ge25519_ecd);
    ge25519_nielsadd2(r, &t);
    for(i = 2; i < 64; i += 2) {
        ge25519_scalarmult_base_choose_niels(&t, basepoint_table, i / 2, b[i]);
        ge25519_nielsadd2(r, &t);
    }
}

ANONYMOUS_NAMESPACE_END
NAMESPACE_END  // Ed25519
NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

//***************************** curve25519 *****************************//

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)

int curve25519_mult_CXX(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32])
{
    using namespace CryptoPP::Donna::X25519;

    FixedSizeSecBlock<byte, 32> e;
    for (size_t i = 0;i < 32;++i)
        e[i] = secretKey[i];
    e[0] &= 0xf8; e[31] &= 0x7f; e[31] |= 0x40;

    bignum25519 nqpqx = {1}, nqpqz = {0}, nqz = {1}, nqx;
    bignum25519 q, qx, qpqx, qqx, zzz, zmone;
    size_t bit, lastbit;

    curve25519_expand(q, othersKey);
    curve25519_copy(nqx, q);

    /* bit 255 is always 0, and bit 254 is always 1, so skip bit 255 and
       start pre-swapped on bit 254 */
    lastbit = 1;

    /* we are doing bits 254..3 in the loop, but are swapping in bits 253..2 */
    for (int i = 253; i >= 2; i--) {
        curve25519_add(qx, nqx, nqz);
        curve25519_sub(nqz, nqx, nqz);
        curve25519_add(qpqx, nqpqx, nqpqz);
        curve25519_sub(nqpqz, nqpqx, nqpqz);
        curve25519_mul(nqpqx, qpqx, nqz);
        curve25519_mul(nqpqz, qx, nqpqz);
        curve25519_add(qqx, nqpqx, nqpqz);
        curve25519_sub(nqpqz, nqpqx, nqpqz);
        curve25519_square(nqpqz, nqpqz);
        curve25519_square(nqpqx, qqx);
        curve25519_mul(nqpqz, nqpqz, q);
        curve25519_square(qx, qx);
        curve25519_square(nqz, nqz);
        curve25519_mul(nqx, qx, nqz);
        curve25519_sub(nqz, qx, nqz);
        curve25519_scalar_product(zzz, nqz, 121665);
        curve25519_add(zzz, zzz, qx);
        curve25519_mul(nqz, nqz, zzz);

        bit = (e[i/8] >> (i & 7)) & 1;
        curve25519_swap_conditional(nqx, nqpqx, bit ^ lastbit);
        curve25519_swap_conditional(nqz, nqpqz, bit ^ lastbit);
        lastbit = bit;
    }

    /* the final 3 bits are always zero, so we only need to double */
    for (int i = 0; i < 3; i++) {
        curve25519_add(qx, nqx, nqz);
        curve25519_sub(nqz, nqx, nqz);
        curve25519_square(qx, qx);
        curve25519_square(nqz, nqz);
        curve25519_mul(nqx, qx, nqz);
        curve25519_sub(nqz, qx, nqz);
        curve25519_scalar_product(zzz, nqz, 121665);
        curve25519_add(zzz, zzz, qx);
        curve25519_mul(nqz, nqz, zzz);
    }

    curve25519_recip(zmone, nqz);
    curve25519_mul(nqz, nqx, zmone);
    curve25519_contract(sharedKey, nqz);

    return 0;
}

int curve25519_mult(byte publicKey[32], const byte secretKey[32])
{
    using namespace CryptoPP::Donna::X25519;

#if (CRYPTOPP_CURVE25519_SSE2)
    if (HasSSE2())
        return curve25519_mult_SSE2(publicKey, secretKey, basePoint);
    else
#endif

    return curve25519_mult_CXX(publicKey, secretKey, basePoint);
}

int curve25519_mult(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32])
{
#if (CRYPTOPP_CURVE25519_SSE2)
    if (HasSSE2())
        return curve25519_mult_SSE2(sharedKey, secretKey, othersKey);
    else
#endif

    return curve25519_mult_CXX(sharedKey, secretKey, othersKey);
}

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

//******************************* ed25519 *******************************//

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)

int
ed25519_publickey_CXX(byte publicKey[32], const byte secretKey[32])
{
    using namespace CryptoPP::Donna::Ed25519;

    bignum256modm a;
    ALIGN(ALIGN_SPEC) ge25519 A;
    hash_512bits extsk;

    /* A = aB */
    ed25519_extsk(extsk, secretKey);
    expand256_modm(a, extsk, 32);
    ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
    ge25519_pack(publicKey, &A);

    return 0;
}

int
ed25519_publickey(byte publicKey[32], const byte secretKey[32])
{
    return ed25519_publickey_CXX(publicKey, secretKey);
}

int
ed25519_sign_CXX(std::istream& stream, const byte sk[32], const byte pk[32], byte RS[64])
{
    using namespace CryptoPP::Donna::Ed25519;

    bignum256modm r, S, a;
    ALIGN(ALIGN_SPEC) ge25519 R;
    hash_512bits extsk, hashr, hram;

    // Unfortunately we need to read the stream twice. The first time calculates
    // 'r = H(aExt[32..64], m)'. The second time calculates 'S = H(R,A,m)'. There
    // is a data dependency due to hashing 'RS' with 'R = [r]B' that does not
    // allow us to read the stream once.
    std::streampos where = stream.tellg();

    ed25519_extsk(extsk, sk);

    /* r = H(aExt[32..64], m) */
    SHA512 hash;
    hash.Update(extsk + 32, 32);
    UpdateFromStream(hash, stream);
    hash.Final(hashr);
    expand256_modm(r, hashr, 64);

    /* R = rB */
    ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
    ge25519_pack(RS, &R);

    // Reset stream for the second digest
    stream.clear();
    stream.seekg(where);

    /* S = H(R,A,m).. */
    ed25519_hram(hram, RS, pk, stream);
    expand256_modm(S, hram, 64);

    /* S = H(R,A,m)a */
    expand256_modm(a, extsk, 32);
    mul256_modm(S, S, a);

    /* S = (r + H(R,A,m)a) */
    add256_modm(S, S, r);

    /* S = (r + H(R,A,m)a) mod L */
    contract256_modm(RS + 32, S);
    return 0;
}

int
ed25519_sign_CXX(const byte *m, size_t mlen, const byte sk[32], const byte pk[32], byte RS[64])
{
    using namespace CryptoPP::Donna::Ed25519;

    bignum256modm r, S, a;
    ALIGN(ALIGN_SPEC) ge25519 R;
    hash_512bits extsk, hashr, hram;

    ed25519_extsk(extsk, sk);

    /* r = H(aExt[32..64], m) */
    SHA512 hash;
    hash.Update(extsk + 32, 32);
    hash.Update(m, mlen);
    hash.Final(hashr);
    expand256_modm(r, hashr, 64);

    /* R = rB */
    ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
    ge25519_pack(RS, &R);

    /* S = H(R,A,m).. */
    ed25519_hram(hram, RS, pk, m, mlen);
    expand256_modm(S, hram, 64);

    /* S = H(R,A,m)a */
    expand256_modm(a, extsk, 32);
    mul256_modm(S, S, a);

    /* S = (r + H(R,A,m)a) */
    add256_modm(S, S, r);

    /* S = (r + H(R,A,m)a) mod L */
    contract256_modm(RS + 32, S);
    return 0;
}

int
ed25519_sign(std::istream& stream, const byte secretKey[32], const byte publicKey[32],
             byte signature[64])
{
    return ed25519_sign_CXX(stream, secretKey, publicKey, signature);
}

int
ed25519_sign(const byte* message, size_t messageLength, const byte secretKey[32],
             const byte publicKey[32], byte signature[64])
{
    return ed25519_sign_CXX(message, messageLength, secretKey, publicKey, signature);
}

int
ed25519_sign_open_CXX(const byte *m, size_t mlen, const byte pk[32], const byte RS[64]) {

    using namespace CryptoPP::Donna::Ed25519;

    ALIGN(ALIGN_SPEC) ge25519 R, A;
    hash_512bits hash;
    bignum256modm hram, S;
    byte checkR[32];

    if ((RS[63] & 224) || !ge25519_unpack_negative_vartime(&A, pk))
        return -1;

    /* hram = H(R,A,m) */
    ed25519_hram(hash, RS, pk, m, mlen);
    expand256_modm(hram, hash, 64);

    /* S */
    expand256_modm(S, RS + 32, 32);

    /* SB - H(R,A,m)A */
    ge25519_double_scalarmult_vartime(&R, &A, hram, S);
    ge25519_pack(checkR, &R);

    /* check that R = SB - H(R,A,m)A */
    return ed25519_verify(RS, checkR, 32) ? 0 : -1;
}

int
ed25519_sign_open_CXX(std::istream& stream, const byte pk[32], const byte RS[64]) {

    using namespace CryptoPP::Donna::Ed25519;

    ALIGN(ALIGN_SPEC) ge25519 R, A;
    hash_512bits hash;
    bignum256modm hram, S;
    byte checkR[32];

    if ((RS[63] & 224) || !ge25519_unpack_negative_vartime(&A, pk))
        return -1;

    /* hram = H(R,A,m) */
    ed25519_hram(hash, RS, pk, stream);
    expand256_modm(hram, hash, 64);

    /* S */
    expand256_modm(S, RS + 32, 32);

    /* SB - H(R,A,m)A */
    ge25519_double_scalarmult_vartime(&R, &A, hram, S);
    ge25519_pack(checkR, &R);

    /* check that R = SB - H(R,A,m)A */
    return ed25519_verify(RS, checkR, 32) ? 0 : -1;
}

int
ed25519_sign_open(std::istream& stream, const byte publicKey[32], const byte signature[64])
{
    return ed25519_sign_open_CXX(stream, publicKey, signature);
}

int
ed25519_sign_open(const byte *message, size_t messageLength, const byte publicKey[32], const byte signature[64])
{
    return ed25519_sign_open_CXX(message, messageLength, publicKey, signature);
}

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_CURVE25519_64BIT
