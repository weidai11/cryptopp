// donna_64.cpp - written and placed in public domain by Jeffrey Walton
//                This is a integration of Andrew Moon's public domain code.
//                Also see curve25519-donna-64bit.h.

#include "pch.h"

#include "config.h"
#include "donna.h"
#include "stdcpp.h"
#include "misc.h"
#include "cpu.h"

// This macro is not in a header like config.h because we don't want it
// exposed to user code. We also need a standard header like <stdint.h>
// or <stdef.h>.
#if (UINTPTR_MAX == 0xffffffff) || !defined(CRYPTOPP_WORD128_AVAILABLE)
# define CRYPTOPP_32BIT 1
#else
# define CRYPTOPP_64BIT 1
#endif

// Squash MS LNK4221 and libtool warnings
extern const char DONNA64_FNAME[] = __FILE__;

#if defined(CRYPTOPP_64BIT)

ANONYMOUS_NAMESPACE_BEGIN

using std::memcpy;
using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::sword32;
using CryptoPP::word64;
using CryptoPP::sword64;
using CryptoPP::word128;

using CryptoPP::GetBlock;
using CryptoPP::BigEndian;
using CryptoPP::LittleEndian;

typedef word64 bignum25519[5];

#define lo128(a) ((word64)a)
#define hi128(a) ((word64)(a >> 64))

#define add128(a,b) a += b;
#define add128_64(a,b) a += (word64)b;
#define mul64x64_128(out,a,b) out = (word128)a * b;
#define shr128(out,in,shift) out = (word64)(in >> (shift));
#define shl128(out,in,shift) out = (word64)((in << shift) >> 64);

const byte basePoint[32] = {9};
const word64 reduce_mask_40 = ((word64)1 << 40) - 1;
const word64 reduce_mask_51 = ((word64)1 << 51) - 1;
const word64 reduce_mask_56 = ((word64)1 << 56) - 1;

/* out = in */
inline void
curve25519_copy(bignum25519 out, const bignum25519 in) {
    out[0] = in[0];
    out[1] = in[1];
    out[2] = in[2];
    out[3] = in[3];
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

/* out = a + b, where a and/or b are the result of a basic op (add,sub) */
inline void
curve25519_add_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    out[0] = a[0] + b[0];
    out[1] = a[1] + b[1];
    out[2] = a[2] + b[2];
    out[3] = a[3] + b[3];
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

/* multiples of p */
const word64 twoP0      = 0x0fffffffffffda;
const word64 twoP1234   = 0x0ffffffffffffe;
const word64 fourP0     = 0x1fffffffffffb4;
const word64 fourP1234  = 0x1ffffffffffffc;

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

    r0 = in[0]; r1 = in[1]; r2 = in[2]; r3 = in[3]; r4 = in[4];
    s0 = in2[0]; s1 = in2[1]; s2 = in2[2]; s3 = in2[3]; s4 = in2[4];

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

    r0 = in[0]; r1 = in[1]; r2 = in[2]; r3 = in[3]; r4 = in[4];

    do {
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
    out[4] = x3 & reduce_mask_51;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
inline void
curve25519_contract(byte *out, const bignum25519 input) {
    word64 t[5];
    word64 f, i;

    t[0] = input[0]; t[1] = input[1]; t[2] = input[2];
    t[3] = input[3]; t[4] = input[4];

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

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)

int curve25519_CXX(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32])
{
    bignum25519 out, r, s;
    curve25519_expand(r, secretKey);
    curve25519_expand(s, othersKey);

    curve25519_mul(out, r, s);
    curve25519_contract(sharedKey, out);

    return 0;
}

int curve25519(byte publicKey[32], const byte secretKey[32])
{
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
    if (HasSSE2())
        return curve25519_SSE2(publicKey, secretKey, basePoint);
    else
#endif

    return curve25519_CXX(publicKey, secretKey, basePoint);
}

int curve25519(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32])
{
#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
    if (HasSSE2())
        return curve25519_SSE2(sharedKey, secretKey, othersKey);
    else
#endif

    return curve25519_CXX(sharedKey, secretKey, othersKey);
}

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_64BIT
