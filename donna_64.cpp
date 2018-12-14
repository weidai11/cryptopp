// donna_64.cpp - written and placed in public domain by Jeffrey Walton
//                This is a integration of Andrew Moon's public domain code.
//                Also see https://github.com/floodyberry/curve25519-donna.

// If needed, see Moon's commit "Go back to ignoring 256th bit [sic]",
// https://github.com/floodyberry/curve25519-donna/commit/57a683d18721a658

#include "pch.h"

#include "config.h"
#include "donna.h"
#include "secblock.h"
#include "misc.h"
#include "cpu.h"

// Squash MS LNK4221 and libtool warnings
extern const char DONNA64_FNAME[] = __FILE__;

#if defined(CRYPTOPP_CURVE25519_64BIT)

ANONYMOUS_NAMESPACE_BEGIN

using std::memcpy;
using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::sword32;
using CryptoPP::word64;
using CryptoPP::sword64;
using CryptoPP::word128;

using CryptoPP::GetBlock;
using CryptoPP::LittleEndian;

typedef word64 bignum25519[5];

#define lo128(a) ((word64)a)
#define hi128(a) ((word64)(a >> 64))

#define add128(a,b) a += b;
#define add128_64(a,b) a += (word64)b;
#define mul64x64_128(out,a,b) out = (word128)a * b;
#define shr128(out,in,shift) out = (word64)(in >> (shift));
#define shl128(out,in,shift) out = (word64)((in << shift) >> 64);

#define ALIGN(n) CRYPTOPP_ALIGN_DATA(n)

const byte basePoint[32] = {9};
const word64 reduce_mask_51 = ((word64)1 << 51) - 1;
// const word64 reduce_mask_52 = ((word64)1 << 52) - 1;

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

const word64 two54m152 = (((word64)1) << 54) - 152;
const word64 two54m8 = (((word64)1) << 54) - 8;

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
    const word64 swap = (word64)(-(int64_t)iswap);
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
    ALIGN(16) bignum25519 t0,c;

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
    ALIGN(16) bignum25519 a, t0, b;

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

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)

int curve25519_CXX(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32])
{
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

int curve25519(byte publicKey[32], const byte secretKey[32])
{
#if (CRYPTOPP_CURVE25519_SSE2)
    if (HasSSE2())
        return curve25519_SSE2(publicKey, secretKey, basePoint);
    else
#endif

    return curve25519_CXX(publicKey, secretKey, basePoint);
}

int curve25519(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32])
{
#if (CRYPTOPP_CURVE25519_SSE2)
    if (HasSSE2())
        return curve25519_SSE2(sharedKey, secretKey, othersKey);
    else
#endif

    return curve25519_CXX(sharedKey, secretKey, othersKey);
}

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_CURVE25519_64BIT
