// donna_32.cpp - written and placed in public domain by Jeffrey Walton
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
extern const char DONNA32_FNAME[] = __FILE__;

#if defined(CRYPTOPP_CURVE25519_32BIT)

ANONYMOUS_NAMESPACE_BEGIN

using std::memcpy;
using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::sword32;
using CryptoPP::word64;
using CryptoPP::sword64;

using CryptoPP::GetBlock;
using CryptoPP::LittleEndian;

typedef word32 bignum25519[10];

#define mul32x32_64(a,b) (((word64)(a))*(b))
#define ALIGN(n) CRYPTOPP_ALIGN_DATA(n)

const byte basePoint[32] = {9};
const word32 reduce_mask_25 = (1 << 25) - 1;
const word32 reduce_mask_26 = (1 << 26) - 1;

/* out = in */
inline void
curve25519_copy(bignum25519 out, const bignum25519 in) {
    out[0] = in[0]; out[1] = in[1];
    out[2] = in[2]; out[3] = in[3];
    out[4] = in[4]; out[5] = in[5];
    out[6] = in[6]; out[7] = in[7];
    out[8] = in[8]; out[9] = in[9];
}

/* out = a + b */
inline void
curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    out[0] = a[0] + b[0]; out[1] = a[1] + b[1];
    out[2] = a[2] + b[2]; out[3] = a[3] + b[3];
    out[4] = a[4] + b[4]; out[5] = a[5] + b[5];
    out[6] = a[6] + b[6]; out[7] = a[7] + b[7];
    out[8] = a[8] + b[8]; out[9] = a[9] + b[9];
}

/* out = a - b */
inline void
curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word32 c;
    out[0] = 0x7ffffda + a[0] - b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
    out[1] = 0x3fffffe + a[1] - b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
    out[2] = 0x7fffffe + a[2] - b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
    out[3] = 0x3fffffe + a[3] - b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
    out[4] = 0x7fffffe + a[4] - b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
    out[5] = 0x3fffffe + a[5] - b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
    out[6] = 0x7fffffe + a[6] - b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
    out[7] = 0x3fffffe + a[7] - b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
    out[8] = 0x7fffffe + a[8] - b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
    out[9] = 0x3fffffe + a[9] - b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
    out[0] += 19 * c;
}

/* out = in * scalar */
inline void
curve25519_scalar_product(bignum25519 out, const bignum25519 in, const word32 scalar) {
    word64 a;
    word32 c;
    a = mul32x32_64(in[0], scalar);     out[0] = (word32)a & reduce_mask_26; c = (word32)(a >> 26);
    a = mul32x32_64(in[1], scalar) + c; out[1] = (word32)a & reduce_mask_25; c = (word32)(a >> 25);
    a = mul32x32_64(in[2], scalar) + c; out[2] = (word32)a & reduce_mask_26; c = (word32)(a >> 26);
    a = mul32x32_64(in[3], scalar) + c; out[3] = (word32)a & reduce_mask_25; c = (word32)(a >> 25);
    a = mul32x32_64(in[4], scalar) + c; out[4] = (word32)a & reduce_mask_26; c = (word32)(a >> 26);
    a = mul32x32_64(in[5], scalar) + c; out[5] = (word32)a & reduce_mask_25; c = (word32)(a >> 25);
    a = mul32x32_64(in[6], scalar) + c; out[6] = (word32)a & reduce_mask_26; c = (word32)(a >> 26);
    a = mul32x32_64(in[7], scalar) + c; out[7] = (word32)a & reduce_mask_25; c = (word32)(a >> 25);
    a = mul32x32_64(in[8], scalar) + c; out[8] = (word32)a & reduce_mask_26; c = (word32)(a >> 26);
    a = mul32x32_64(in[9], scalar) + c; out[9] = (word32)a & reduce_mask_25; c = (word32)(a >> 25);
                                        out[0] += c * 19;
}

/* out = a * b */
inline void
curve25519_mul(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word32 r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
    word32 s0,s1,s2,s3,s4,s5,s6,s7,s8,s9;
    word64 m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
    word32 p;

    r0 = b[0]; r1 = b[1]; r2 = b[2]; r3 = b[3]; r4 = b[4];
    r5 = b[5]; r6 = b[6]; r7 = b[7]; r8 = b[8]; r9 = b[9];

    s0 = a[0]; s1 = a[1]; s2 = a[2]; s3 = a[3]; s4 = a[4];
    s5 = a[5]; s6 = a[6]; s7 = a[7]; s8 = a[8]; s9 = a[9];

    m1 = mul32x32_64(r0, s1) + mul32x32_64(r1, s0);
    m3 = mul32x32_64(r0, s3) + mul32x32_64(r1, s2) + mul32x32_64(r2, s1) + mul32x32_64(r3, s0);
    m5 = mul32x32_64(r0, s5) + mul32x32_64(r1, s4) + mul32x32_64(r2, s3) + mul32x32_64(r3, s2) + mul32x32_64(r4, s1) + mul32x32_64(r5, s0);
    m7 = mul32x32_64(r0, s7) + mul32x32_64(r1, s6) + mul32x32_64(r2, s5) + mul32x32_64(r3, s4) + mul32x32_64(r4, s3) + mul32x32_64(r5, s2) + mul32x32_64(r6, s1) + mul32x32_64(r7, s0);
    m9 = mul32x32_64(r0, s9) + mul32x32_64(r1, s8) + mul32x32_64(r2, s7) + mul32x32_64(r3, s6) + mul32x32_64(r4, s5) + mul32x32_64(r5, s4) + mul32x32_64(r6, s3) + mul32x32_64(r7, s2) + mul32x32_64(r8, s1) + mul32x32_64(r9, s0);

    r1 *= 2; r3 *= 2; r5 *= 2; r7 *= 2;

    m0 = mul32x32_64(r0, s0);
    m2 = mul32x32_64(r0, s2) + mul32x32_64(r1, s1) + mul32x32_64(r2, s0);
    m4 = mul32x32_64(r0, s4) + mul32x32_64(r1, s3) + mul32x32_64(r2, s2) + mul32x32_64(r3, s1) + mul32x32_64(r4, s0);
    m6 = mul32x32_64(r0, s6) + mul32x32_64(r1, s5) + mul32x32_64(r2, s4) + mul32x32_64(r3, s3) + mul32x32_64(r4, s2) + mul32x32_64(r5, s1) + mul32x32_64(r6, s0);
    m8 = mul32x32_64(r0, s8) + mul32x32_64(r1, s7) + mul32x32_64(r2, s6) + mul32x32_64(r3, s5) + mul32x32_64(r4, s4) + mul32x32_64(r5, s3) + mul32x32_64(r6, s2) + mul32x32_64(r7, s1) + mul32x32_64(r8, s0);

    r1 *= 19; r2 *= 19;
    r3 = (r3 / 2) * 19;
    r4 *= 19;
    r5 = (r5 / 2) * 19;
    r6 *= 19;
    r7 = (r7 / 2) * 19;
    r8 *= 19; r9 *= 19;

    m1 += (mul32x32_64(r9, s2) + mul32x32_64(r8, s3) + mul32x32_64(r7, s4) + mul32x32_64(r6, s5) + mul32x32_64(r5, s6) + mul32x32_64(r4, s7) + mul32x32_64(r3, s8) + mul32x32_64(r2, s9));
    m3 += (mul32x32_64(r9, s4) + mul32x32_64(r8, s5) + mul32x32_64(r7, s6) + mul32x32_64(r6, s7) + mul32x32_64(r5, s8) + mul32x32_64(r4, s9));
    m5 += (mul32x32_64(r9, s6) + mul32x32_64(r8, s7) + mul32x32_64(r7, s8) + mul32x32_64(r6, s9));
    m7 += (mul32x32_64(r9, s8) + mul32x32_64(r8, s9));

    r3 *= 2; r5 *= 2; r7 *= 2; r9 *= 2;

    m0 += (mul32x32_64(r9, s1) + mul32x32_64(r8, s2) + mul32x32_64(r7, s3) + mul32x32_64(r6, s4) + mul32x32_64(r5, s5) + mul32x32_64(r4, s6) + mul32x32_64(r3, s7) + mul32x32_64(r2, s8) + mul32x32_64(r1, s9));
    m2 += (mul32x32_64(r9, s3) + mul32x32_64(r8, s4) + mul32x32_64(r7, s5) + mul32x32_64(r6, s6) + mul32x32_64(r5, s7) + mul32x32_64(r4, s8) + mul32x32_64(r3, s9));
    m4 += (mul32x32_64(r9, s5) + mul32x32_64(r8, s6) + mul32x32_64(r7, s7) + mul32x32_64(r6, s8) + mul32x32_64(r5, s9));
    m6 += (mul32x32_64(r9, s7) + mul32x32_64(r8, s8) + mul32x32_64(r7, s9));
    m8 += (mul32x32_64(r9, s9));

                                 r0 = (word32)m0 & reduce_mask_26; c = (m0 >> 26);
    m1 += c;                     r1 = (word32)m1 & reduce_mask_25; c = (m1 >> 25);
    m2 += c;                     r2 = (word32)m2 & reduce_mask_26; c = (m2 >> 26);
    m3 += c;                     r3 = (word32)m3 & reduce_mask_25; c = (m3 >> 25);
    m4 += c;                     r4 = (word32)m4 & reduce_mask_26; c = (m4 >> 26);
    m5 += c;                     r5 = (word32)m5 & reduce_mask_25; c = (m5 >> 25);
    m6 += c;                     r6 = (word32)m6 & reduce_mask_26; c = (m6 >> 26);
    m7 += c;                     r7 = (word32)m7 & reduce_mask_25; c = (m7 >> 25);
    m8 += c;                     r8 = (word32)m8 & reduce_mask_26; c = (m8 >> 26);
    m9 += c;                     r9 = (word32)m9 & reduce_mask_25; p = (word32)(m9 >> 25);
    m0 = r0 + mul32x32_64(p,19); r0 = (word32)m0 & reduce_mask_26; p = (word32)(m0 >> 26);
    r1 += p;

    out[0] = r0; out[1] = r1; out[2] = r2; out[3] = r3; out[4] = r4;
    out[5] = r5; out[6] = r6; out[7] = r7; out[8] = r8; out[9] = r9;
}

/* out = in * in */
inline void
curve25519_square(bignum25519 out, const bignum25519 in) {
    word32 r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
    word32 d6,d7,d8,d9;
    word64 m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
    word32 p;

    r0 = in[0]; r1 = in[1]; r2 = in[2]; r3 = in[3]; r4 = in[4];
    r5 = in[5]; r6 = in[6]; r7 = in[7]; r8 = in[8]; r9 = in[9];

    m0 = mul32x32_64(r0, r0);
    r0 *= 2;
    m1 = mul32x32_64(r0, r1);
    m2 = mul32x32_64(r0, r2) + mul32x32_64(r1, r1 * 2);
    r1 *= 2;
    m3 = mul32x32_64(r0, r3) + mul32x32_64(r1, r2    );
    m4 = mul32x32_64(r0, r4) + mul32x32_64(r1, r3 * 2) + mul32x32_64(r2, r2);
    r2 *= 2;
    m5 = mul32x32_64(r0, r5) + mul32x32_64(r1, r4    ) + mul32x32_64(r2, r3);
    m6 = mul32x32_64(r0, r6) + mul32x32_64(r1, r5 * 2) + mul32x32_64(r2, r4) + mul32x32_64(r3, r3 * 2);
    r3 *= 2;
    m7 = mul32x32_64(r0, r7) + mul32x32_64(r1, r6    ) + mul32x32_64(r2, r5) + mul32x32_64(r3, r4    );
    m8 = mul32x32_64(r0, r8) + mul32x32_64(r1, r7 * 2) + mul32x32_64(r2, r6) + mul32x32_64(r3, r5 * 2) + mul32x32_64(r4, r4    );
    m9 = mul32x32_64(r0, r9) + mul32x32_64(r1, r8    ) + mul32x32_64(r2, r7) + mul32x32_64(r3, r6    ) + mul32x32_64(r4, r5 * 2);

    d6 = r6 * 19; d7 = r7 * 2 * 19;
    d8 = r8 * 19; d9 = r9 * 2 * 19;

    m0 += (mul32x32_64(d9, r1    ) + mul32x32_64(d8, r2    ) + mul32x32_64(d7, r3    ) + mul32x32_64(d6, r4 * 2) + mul32x32_64(r5, r5 * 2 * 19));
    m1 += (mul32x32_64(d9, r2 / 2) + mul32x32_64(d8, r3    ) + mul32x32_64(d7, r4    ) + mul32x32_64(d6, r5 * 2));
    m2 += (mul32x32_64(d9, r3    ) + mul32x32_64(d8, r4 * 2) + mul32x32_64(d7, r5 * 2) + mul32x32_64(d6, r6    ));
    m3 += (mul32x32_64(d9, r4    ) + mul32x32_64(d8, r5 * 2) + mul32x32_64(d7, r6    ));
    m4 += (mul32x32_64(d9, r5 * 2) + mul32x32_64(d8, r6 * 2) + mul32x32_64(d7, r7    ));
    m5 += (mul32x32_64(d9, r6    ) + mul32x32_64(d8, r7 * 2));
    m6 += (mul32x32_64(d9, r7 * 2) + mul32x32_64(d8, r8    ));
    m7 += (mul32x32_64(d9, r8    ));
    m8 += (mul32x32_64(d9, r9    ));

                                 r0 = (word32)m0 & reduce_mask_26; c = (m0 >> 26);
    m1 += c;                     r1 = (word32)m1 & reduce_mask_25; c = (m1 >> 25);
    m2 += c;                     r2 = (word32)m2 & reduce_mask_26; c = (m2 >> 26);
    m3 += c;                     r3 = (word32)m3 & reduce_mask_25; c = (m3 >> 25);
    m4 += c;                     r4 = (word32)m4 & reduce_mask_26; c = (m4 >> 26);
    m5 += c;                     r5 = (word32)m5 & reduce_mask_25; c = (m5 >> 25);
    m6 += c;                     r6 = (word32)m6 & reduce_mask_26; c = (m6 >> 26);
    m7 += c;                     r7 = (word32)m7 & reduce_mask_25; c = (m7 >> 25);
    m8 += c;                     r8 = (word32)m8 & reduce_mask_26; c = (m8 >> 26);
    m9 += c;                     r9 = (word32)m9 & reduce_mask_25; p = (word32)(m9 >> 25);
    m0 = r0 + mul32x32_64(p,19); r0 = (word32)m0 & reduce_mask_26; p = (word32)(m0 >> 26);
    r1 += p;

    out[0] = r0; out[1] = r1; out[2] = r2; out[3] = r3; out[4] = r4;
    out[5] = r5; out[6] = r6; out[7] = r7; out[8] = r8; out[9] = r9;
}

/* out = in^(2 * count) */
void
curve25519_square_times(bignum25519 out, const bignum25519 in, int count) {
    word32 r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
    word32 d6,d7,d8,d9;
    word64 m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
    word32 p;

    r0 = in[0]; r1 = in[1]; r2 = in[2]; r3 = in[3]; r4 = in[4];
    r5 = in[5]; r6 = in[6]; r7 = in[7]; r8 = in[8]; r9 = in[9];

    do {
        m0 = mul32x32_64(r0, r0);
        r0 *= 2;
        m1 = mul32x32_64(r0, r1);
        m2 = mul32x32_64(r0, r2) + mul32x32_64(r1, r1 * 2);
        r1 *= 2;
        m3 = mul32x32_64(r0, r3) + mul32x32_64(r1, r2    );
        m4 = mul32x32_64(r0, r4) + mul32x32_64(r1, r3 * 2) + mul32x32_64(r2, r2);
        r2 *= 2;
        m5 = mul32x32_64(r0, r5) + mul32x32_64(r1, r4    ) + mul32x32_64(r2, r3);
        m6 = mul32x32_64(r0, r6) + mul32x32_64(r1, r5 * 2) + mul32x32_64(r2, r4) + mul32x32_64(r3, r3 * 2);
        r3 *= 2;
        m7 = mul32x32_64(r0, r7) + mul32x32_64(r1, r6    ) + mul32x32_64(r2, r5) + mul32x32_64(r3, r4    );
        m8 = mul32x32_64(r0, r8) + mul32x32_64(r1, r7 * 2) + mul32x32_64(r2, r6) + mul32x32_64(r3, r5 * 2) + mul32x32_64(r4, r4    );
        m9 = mul32x32_64(r0, r9) + mul32x32_64(r1, r8    ) + mul32x32_64(r2, r7) + mul32x32_64(r3, r6    ) + mul32x32_64(r4, r5 * 2);

        d6 = r6 * 19; d7 = r7 * 2 * 19;
        d8 = r8 * 19; d9 = r9 * 2 * 19;

        m0 += (mul32x32_64(d9, r1    ) + mul32x32_64(d8, r2    ) + mul32x32_64(d7, r3    ) + mul32x32_64(d6, r4 * 2) + mul32x32_64(r5, r5 * 2 * 19));
        m1 += (mul32x32_64(d9, r2 / 2) + mul32x32_64(d8, r3    ) + mul32x32_64(d7, r4    ) + mul32x32_64(d6, r5 * 2));
        m2 += (mul32x32_64(d9, r3    ) + mul32x32_64(d8, r4 * 2) + mul32x32_64(d7, r5 * 2) + mul32x32_64(d6, r6    ));
        m3 += (mul32x32_64(d9, r4    ) + mul32x32_64(d8, r5 * 2) + mul32x32_64(d7, r6    ));
        m4 += (mul32x32_64(d9, r5 * 2) + mul32x32_64(d8, r6 * 2) + mul32x32_64(d7, r7    ));
        m5 += (mul32x32_64(d9, r6    ) + mul32x32_64(d8, r7 * 2));
        m6 += (mul32x32_64(d9, r7 * 2) + mul32x32_64(d8, r8    ));
        m7 += (mul32x32_64(d9, r8    ));
        m8 += (mul32x32_64(d9, r9    ));

                                     r0 = (word32)m0 & reduce_mask_26; c = (m0 >> 26);
        m1 += c;                     r1 = (word32)m1 & reduce_mask_25; c = (m1 >> 25);
        m2 += c;                     r2 = (word32)m2 & reduce_mask_26; c = (m2 >> 26);
        m3 += c;                     r3 = (word32)m3 & reduce_mask_25; c = (m3 >> 25);
        m4 += c;                     r4 = (word32)m4 & reduce_mask_26; c = (m4 >> 26);
        m5 += c;                     r5 = (word32)m5 & reduce_mask_25; c = (m5 >> 25);
        m6 += c;                     r6 = (word32)m6 & reduce_mask_26; c = (m6 >> 26);
        m7 += c;                     r7 = (word32)m7 & reduce_mask_25; c = (m7 >> 25);
        m8 += c;                     r8 = (word32)m8 & reduce_mask_26; c = (m8 >> 26);
        m9 += c;                     r9 = (word32)m9 & reduce_mask_25; p = (word32)(m9 >> 25);
        m0 = r0 + mul32x32_64(p,19); r0 = (word32)m0 & reduce_mask_26; p = (word32)(m0 >> 26);
        r1 += p;
    } while (--count);

    out[0] = r0; out[1] = r1; out[2] = r2; out[3] = r3; out[4] = r4;
    out[5] = r5; out[6] = r6; out[7] = r7; out[8] = r8; out[9] = r9;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
void
curve25519_expand(bignum25519 out, const byte in[32]) {

    word32 x0,x1,x2,x3,x4,x5,x6,x7;

    GetBlock<word32, LittleEndian> block(in);
    block(x0)(x1)(x2)(x3)(x4)(x5)(x6)(x7);

    out[0] = (                      x0       ) & reduce_mask_26;
    out[1] = ((((word64)x1 << 32) | x0) >> 26) & reduce_mask_25;
    out[2] = ((((word64)x2 << 32) | x1) >> 19) & reduce_mask_26;
    out[3] = ((((word64)x3 << 32) | x2) >> 13) & reduce_mask_25;
    out[4] = ((                     x3) >>  6) & reduce_mask_26;
    out[5] = (                      x4       ) & reduce_mask_25;
    out[6] = ((((word64)x5 << 32) | x4) >> 25) & reduce_mask_26;
    out[7] = ((((word64)x6 << 32) | x5) >> 19) & reduce_mask_25;
    out[8] = ((((word64)x7 << 32) | x6) >> 12) & reduce_mask_26;
    out[9] = ((                     x7) >>  6) & reduce_mask_25; /* ignore the top bit */
}

/* Take a fully reduced polynomial form number and contract it into a little-endian, 32-byte array */
void
curve25519_contract(byte out[32], const bignum25519 in) {
    bignum25519 f;
    curve25519_copy(f, in);

    #define carry_pass() \
        f[1] += f[0] >> 26; f[0] &= reduce_mask_26; \
        f[2] += f[1] >> 25; f[1] &= reduce_mask_25; \
        f[3] += f[2] >> 26; f[2] &= reduce_mask_26; \
        f[4] += f[3] >> 25; f[3] &= reduce_mask_25; \
        f[5] += f[4] >> 26; f[4] &= reduce_mask_26; \
        f[6] += f[5] >> 25; f[5] &= reduce_mask_25; \
        f[7] += f[6] >> 26; f[6] &= reduce_mask_26; \
        f[8] += f[7] >> 25; f[7] &= reduce_mask_25; \
        f[9] += f[8] >> 26; f[8] &= reduce_mask_26;

    #define carry_pass_full() \
        carry_pass() \
        f[0] += 19 * (f[9] >> 25); f[9] &= reduce_mask_25;

    #define carry_pass_final() \
        carry_pass() \
        f[9] &= reduce_mask_25;

    carry_pass_full()
    carry_pass_full()

    /* now t is between 0 and 2^255-1, properly carried. */
    /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
    f[0] += 19;
    carry_pass_full()

    /* now between 19 and 2^255-1 in both cases, and offset by 19. */
    f[0] += (1 << 26) - 19;
    f[1] += (1 << 25) - 1;
    f[2] += (1 << 26) - 1;
    f[3] += (1 << 25) - 1;
    f[4] += (1 << 26) - 1;
    f[5] += (1 << 25) - 1;
    f[6] += (1 << 26) - 1;
    f[7] += (1 << 25) - 1;
    f[8] += (1 << 26) - 1;
    f[9] += (1 << 25) - 1;

    /* now between 2^255 and 2^256-20, and offset by 2^255. */
    carry_pass_final()

    #undef carry_pass
    #undef carry_full
    #undef carry_final

    f[1] <<= 2;
    f[2] <<= 3;
    f[3] <<= 5;
    f[4] <<= 6;
    f[6] <<= 1;
    f[7] <<= 3;
    f[8] <<= 4;
    f[9] <<= 6;

    #define F(i, s) \
        out[s+0] |= (byte)( f[i] & 0xff); \
        out[s+1]  = (byte)((f[i] >>  8) & 0xff); \
        out[s+2]  = (byte)((f[i] >> 16) & 0xff); \
        out[s+3]  = (byte)((f[i] >> 24) & 0xff);

    out[0] = 0;
    out[16] = 0;
    F(0,0);
    F(1,3);
    F(2,6);
    F(3,9);
    F(4,12);
    F(5,16);
    F(6,19);
    F(7,22);
    F(8,25);
    F(9,28);
    #undef F
}

inline void
curve25519_swap_conditional(bignum25519 x, bignum25519 qpx, word32 iswap) {
    const word32 swap = (word32)(-(sword32)iswap);
    word32 x0,x1,x2,x3,x4,x5,x6,x7,x8,x9;

    x0 = swap & (x[0] ^ qpx[0]); x[0] ^= x0; qpx[0] ^= x0;
    x1 = swap & (x[1] ^ qpx[1]); x[1] ^= x1; qpx[1] ^= x1;
    x2 = swap & (x[2] ^ qpx[2]); x[2] ^= x2; qpx[2] ^= x2;
    x3 = swap & (x[3] ^ qpx[3]); x[3] ^= x3; qpx[3] ^= x3;
    x4 = swap & (x[4] ^ qpx[4]); x[4] ^= x4; qpx[4] ^= x4;
    x5 = swap & (x[5] ^ qpx[5]); x[5] ^= x5; qpx[5] ^= x5;
    x6 = swap & (x[6] ^ qpx[6]); x[6] ^= x6; qpx[6] ^= x6;
    x7 = swap & (x[7] ^ qpx[7]); x[7] ^= x7; qpx[7] ^= x7;
    x8 = swap & (x[8] ^ qpx[8]); x[8] ^= x8; qpx[8] ^= x8;
    x9 = swap & (x[9] ^ qpx[9]); x[9] ^= x9; qpx[9] ^= x9;
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

int curve25519_mult_CXX(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32])
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

int curve25519_mult(byte publicKey[32], const byte secretKey[32])
{
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

int ed25519_keypair(HashTransformation& hash, byte publicKey[32], byte secretKey[64], const byte seed[32])
{
    return 0;
}

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_CURVE25519_32BIT
