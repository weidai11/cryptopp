// donna_32.cpp - written and placed in public domain by Jeffrey Walton
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

// Squash MS LNK4221 and libtool warnings
extern const char DONNA32_FNAME[] = __FILE__;

#if defined(CRYPTOPP_CURVE25519_32BIT)

#include "donna_32.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::GetWord;
using CryptoPP::PutWord;
using CryptoPP::LITTLE_ENDIAN_ORDER;

inline word32 U8TO32_LE(const byte* p)
{
    return GetWord<word32>(false, LITTLE_ENDIAN_ORDER, p);
}

inline void U32TO8_LE(byte* p, word32 w)
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

// Bring in all the symbols from the 32-bit header
using namespace CryptoPP::Donna::Arch32;

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

    out[0] = out[16] = 0;
    F(0,0); F(1,3);
    F(2,6); F(3,9);
    F(4,12); F(5,16);
    F(6,19); F(7,22);
    F(8,25); F(9,28);
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

// Bring in all the symbols from the 32-bit header
using namespace CryptoPP::Donna::Arch32;

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

inline void
curve25519_add_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word32 c;
    out[0] = a[0] + b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
    out[1] = a[1] + b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
    out[2] = a[2] + b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
    out[3] = a[3] + b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
    out[4] = a[4] + b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
    out[5] = a[5] + b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
    out[6] = a[6] + b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
    out[7] = a[7] + b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
    out[8] = a[8] + b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
    out[9] = a[9] + b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
    out[0] += 19 * c;
}

inline void
curve25519_add_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word32 c;
    out[0] = a[0] + b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
    out[1] = a[1] + b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
    out[2] = a[2] + b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
    out[3] = a[3] + b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
    out[4] = a[4] + b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
    out[5] = a[5] + b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
    out[6] = a[6] + b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
    out[7] = a[7] + b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
    out[8] = a[8] + b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
    out[9] = a[9] + b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
    out[0] += 19 * c;
}

/* out = a - b */
inline void
curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word32 c;
    out[0] = twoP0     + a[0] - b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
    out[1] = twoP13579 + a[1] - b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
    out[2] = twoP2468  + a[2] - b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
    out[3] = twoP13579 + a[3] - b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
    out[4] = twoP2468  + a[4] - b[4] + c;
    out[5] = twoP13579 + a[5] - b[5]    ;
    out[6] = twoP2468  + a[6] - b[6]    ;
    out[7] = twoP13579 + a[7] - b[7]    ;
    out[8] = twoP2468  + a[8] - b[8]    ;
    out[9] = twoP13579 + a[9] - b[9]    ;
}

/* out = a - b, where a is the result of a basic op (add,sub) */
inline void
curve25519_sub_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word32 c;
    out[0] = fourP0     + a[0] - b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
    out[1] = fourP13579 + a[1] - b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
    out[2] = fourP2468  + a[2] - b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
    out[3] = fourP13579 + a[3] - b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
    out[4] = fourP2468  + a[4] - b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
    out[5] = fourP13579 + a[5] - b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
    out[6] = fourP2468  + a[6] - b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
    out[7] = fourP13579 + a[7] - b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
    out[8] = fourP2468  + a[8] - b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
    out[9] = fourP13579 + a[9] - b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
    out[0] += 19 * c;
}

inline void
curve25519_sub_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word32 c;
    out[0] = fourP0     + a[0] - b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
    out[1] = fourP13579 + a[1] - b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
    out[2] = fourP2468  + a[2] - b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
    out[3] = fourP13579 + a[3] - b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
    out[4] = fourP2468  + a[4] - b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
    out[5] = fourP13579 + a[5] - b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
    out[6] = fourP2468  + a[6] - b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
    out[7] = fourP13579 + a[7] - b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
    out[8] = fourP2468  + a[8] - b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
    out[9] = fourP13579 + a[9] - b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
    out[0] += 19 * c;
}

/* out = -a */
inline void
curve25519_neg(bignum25519 out, const bignum25519 a) {
    word32 c;
    out[0] = twoP0     - a[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
    out[1] = twoP13579 - a[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
    out[2] = twoP2468  - a[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
    out[3] = twoP13579 - a[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
    out[4] = twoP2468  - a[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
    out[5] = twoP13579 - a[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
    out[6] = twoP2468  - a[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
    out[7] = twoP13579 - a[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
    out[8] = twoP2468  - a[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
    out[9] = twoP13579 - a[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
    out[0] += 19 * c;
}

/* out = a * b */
void
curve25519_mul(bignum25519 out, const bignum25519 a, const bignum25519 b) {
    word32 r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
    word32 s0,s1,s2,s3,s4,s5,s6,s7,s8,s9;
    word64 m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
    word32 p;

    r0 = b[0]; r1 = b[1];
    r2 = b[2]; r3 = b[3];
    r4 = b[4]; r5 = b[5];
    r6 = b[6]; r7 = b[7];
    r8 = b[8]; r9 = b[9];

    s0 = a[0]; s1 = a[1];
    s2 = a[2]; s3 = a[3];
    s4 = a[4]; s5 = a[5];
    s6 = a[6]; s7 = a[7];
    s8 = a[8]; s9 = a[9];

    m1 = mul32x32_64(r0, s1) + mul32x32_64(r1, s0);
    m3 = mul32x32_64(r0, s3) + mul32x32_64(r1, s2) + mul32x32_64(r2, s1) + mul32x32_64(r3, s0);
    m5 = mul32x32_64(r0, s5) + mul32x32_64(r1, s4) + mul32x32_64(r2, s3) + mul32x32_64(r3, s2) + mul32x32_64(r4, s1) + mul32x32_64(r5, s0);
    m7 = mul32x32_64(r0, s7) + mul32x32_64(r1, s6) + mul32x32_64(r2, s5) + mul32x32_64(r3, s4) + mul32x32_64(r4, s3) + mul32x32_64(r5, s2) + mul32x32_64(r6, s1) + mul32x32_64(r7, s0);
    m9 = mul32x32_64(r0, s9) + mul32x32_64(r1, s8) + mul32x32_64(r2, s7) + mul32x32_64(r3, s6) + mul32x32_64(r4, s5) + mul32x32_64(r5, s4) + mul32x32_64(r6, s3) + mul32x32_64(r7, s2) + mul32x32_64(r8, s1) + mul32x32_64(r9, s0);

    r1 *= 2; r3 *= 2;
    r5 *= 2; r7 *= 2;

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

    r3 *= 2; r5 *= 2;
    r7 *= 2; r9 *= 2;

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

    out[0] = r0; out[1] = r1;
    out[2] = r2; out[3] = r3;
    out[4] = r4; out[5] = r5;
    out[6] = r6; out[7] = r7;
    out[8] = r8; out[9] = r9;
}

/* out = in*in */
void
curve25519_square(bignum25519 out, const bignum25519 in) {
    word32 r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
    word32 d6,d7,d8,d9;
    word64 m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
    word32 p;

    r0 = in[0]; r1 = in[1];
    r2 = in[2]; r3 = in[3];
    r4 = in[4]; r5 = in[5];
    r6 = in[6]; r7 = in[7];
    r8 = in[8]; r9 = in[9];

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

    d6 = r6 * 19;
    d7 = r7 * 2 * 19;
    d8 = r8 * 19;
    d9 = r9 * 2 * 19;

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

    out[0] = r0; out[1] = r1;
    out[2] = r2; out[3] = r3;
    out[4] = r4; out[5] = r5;
    out[6] = r6; out[7] = r7;
    out[8] = r8; out[9] = r9;
}

/* out = in ^ (2 * count) */
void
curve25519_square_times(bignum25519 out, const bignum25519 in, int count) {
    word32 r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
    word32 d6,d7,d8,d9,p;
    word64 m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;

    r0 = in[0]; r1 = in[1];
    r2 = in[2]; r3 = in[3];
    r4 = in[4]; r5 = in[5];
    r6 = in[6]; r7 = in[7];
    r8 = in[8]; r9 = in[9];

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

        d6 = r6 * 19;
        d7 = r7 * 2 * 19;
        d8 = r8 * 19;
        d9 = r9 * 2 * 19;

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

    out[0] = r0; out[1] = r1;
    out[2] = r2; out[3] = r3;
    out[4] = r4; out[5] = r5;
    out[6] = r6; out[7] = r7;
    out[8] = r8; out[9] = r9;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
void
curve25519_expand(bignum25519 out, const byte in[32]) {
    word32 x0,x1,x2,x3,x4,x5,x6,x7;
    GetBlock<word32, LittleEndian> block(in);
    block(x0)(x1)(x2)(x3)(x4)(x5)(x6)(x7);

    out[0] = (                      x0       ) & 0x3ffffff;
    out[1] = ((((word64)x1 << 32) | x0) >> 26) & 0x1ffffff;
    out[2] = ((((word64)x2 << 32) | x1) >> 19) & 0x3ffffff;
    out[3] = ((((word64)x3 << 32) | x2) >> 13) & 0x1ffffff;
    out[4] = ((                     x3) >>  6) & 0x3ffffff;
    out[5] = (                      x4       ) & 0x1ffffff;
    out[6] = ((((word64)x5 << 32) | x4) >> 25) & 0x3ffffff;
    out[7] = ((((word64)x6 << 32) | x5) >> 19) & 0x1ffffff;
    out[8] = ((((word64)x7 << 32) | x6) >> 12) & 0x3ffffff;
    out[9] = ((                     x7) >>  6) & 0x1ffffff;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
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
    f[0] += (reduce_mask_26 + 1) - 19;
    f[1] += (reduce_mask_25 + 1) - 1;
    f[2] += (reduce_mask_26 + 1) - 1;
    f[3] += (reduce_mask_25 + 1) - 1;
    f[4] += (reduce_mask_26 + 1) - 1;
    f[5] += (reduce_mask_25 + 1) - 1;
    f[6] += (reduce_mask_26 + 1) - 1;
    f[7] += (reduce_mask_25 + 1) - 1;
    f[8] += (reduce_mask_26 + 1) - 1;
    f[9] += (reduce_mask_25 + 1) - 1;

    /* now between 2^255 and 2^256-20, and offset by 2^255. */
    carry_pass_final()

    #undef carry_pass
    #undef carry_full
    #undef carry_final

    f[1] <<= 2; f[2] <<= 3;
    f[3] <<= 5; f[4] <<= 6;
    f[6] <<= 1; f[7] <<= 3;
    f[8] <<= 4; f[9] <<= 6;

    #define F(i, s) \
        out[s+0] |= (byte)( f[i] & 0xff); \
        out[s+1]  = (byte)((f[i] >> 8) & 0xff); \
        out[s+2]  = (byte)((f[i] >> 16) & 0xff); \
        out[s+3]  = (byte)((f[i] >> 24) & 0xff);

    out[0] = out[16] = 0;
    F(0,0); F(1,3);
    F(2,6); F(3,9);
    F(4,12); F(5,16);
    F(6,19); F(7,22);
    F(8,25); F(9,28);
    #undef F
}

/* out = (flag) ? in : out */
inline void
curve25519_move_conditional_bytes(byte out[96], const byte in[96], word32 flag) {
    const word32 nb = flag - 1, b = ~nb;
    const word32 *inl = (const word32 *)in;
    word32 *outl = (word32 *)out;
    outl[0] = (outl[0] & nb) | (inl[0] & b);
    outl[1] = (outl[1] & nb) | (inl[1] & b);
    outl[2] = (outl[2] & nb) | (inl[2] & b);
    outl[3] = (outl[3] & nb) | (inl[3] & b);
    outl[4] = (outl[4] & nb) | (inl[4] & b);
    outl[5] = (outl[5] & nb) | (inl[5] & b);
    outl[6] = (outl[6] & nb) | (inl[6] & b);
    outl[7] = (outl[7] & nb) | (inl[7] & b);
    outl[8] = (outl[8] & nb) | (inl[8] & b);
    outl[9] = (outl[9] & nb) | (inl[9] & b);
    outl[10] = (outl[10] & nb) | (inl[10] & b);
    outl[11] = (outl[11] & nb) | (inl[11] & b);
    outl[12] = (outl[12] & nb) | (inl[12] & b);
    outl[13] = (outl[13] & nb) | (inl[13] & b);
    outl[14] = (outl[14] & nb) | (inl[14] & b);
    outl[15] = (outl[15] & nb) | (inl[15] & b);
    outl[16] = (outl[16] & nb) | (inl[16] & b);
    outl[17] = (outl[17] & nb) | (inl[17] & b);
    outl[18] = (outl[18] & nb) | (inl[18] & b);
    outl[19] = (outl[19] & nb) | (inl[19] & b);
    outl[20] = (outl[20] & nb) | (inl[20] & b);
    outl[21] = (outl[21] & nb) | (inl[21] & b);
    outl[22] = (outl[22] & nb) | (inl[22] & b);
    outl[23] = (outl[23] & nb) | (inl[23] & b);
}

/* if (iswap) swap(a, b) */
inline void
curve25519_swap_conditional(bignum25519 a, bignum25519 b, word32 iswap) {
    const word32 swap = (word32)(-(sword32)iswap);
    word32 x0,x1,x2,x3,x4,x5,x6,x7,x8,x9;

    x0 = swap & (a[0] ^ b[0]); a[0] ^= x0; b[0] ^= x0;
    x1 = swap & (a[1] ^ b[1]); a[1] ^= x1; b[1] ^= x1;
    x2 = swap & (a[2] ^ b[2]); a[2] ^= x2; b[2] ^= x2;
    x3 = swap & (a[3] ^ b[3]); a[3] ^= x3; b[3] ^= x3;
    x4 = swap & (a[4] ^ b[4]); a[4] ^= x4; b[4] ^= x4;
    x5 = swap & (a[5] ^ b[5]); a[5] ^= x5; b[5] ^= x5;
    x6 = swap & (a[6] ^ b[6]); a[6] ^= x6; b[6] ^= x6;
    x7 = swap & (a[7] ^ b[7]); a[7] ^= x7; b[7] ^= x7;
    x8 = swap & (a[8] ^ b[8]); a[8] ^= x8; b[8] ^= x8;
    x9 = swap & (a[9] ^ b[9]); a[9] ^= x9; b[9] ^= x9;
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
    ALIGN(16) bignum25519 a,t0,b;

    /* 2 */ curve25519_square_times(a, z, 1); /* a = 2 */
    /* 8 */ curve25519_square_times(t0, a, 2);
    /* 9 */ curve25519_mul(b, t0, z); /* b = 9 */
    /* 11 */ curve25519_mul(a, b, a); /* a = 11 */
    /* 22 */ curve25519_square_times(t0, a, 1);
    /* 2^5 - 2^0 = 31 */ curve25519_mul(b, t0, b);
    /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
    /* 2^255 - 2^5 */ curve25519_square_times(b, b, 5);
    /* 2^255 - 21 */ curve25519_mul(out, b, a);
}

/*
 * z^((p-5)/8) = z^(2^252 - 3)
 */
void
curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z) {
    ALIGN(16) bignum25519 b,c,t0;

    /* 2 */ curve25519_square_times(c, z, 1); /* c = 2 */
    /* 8 */ curve25519_square_times(t0, c, 2); /* t0 = 8 */
    /* 9 */ curve25519_mul(b, t0, z); /* b = 9 */
    /* 11 */ curve25519_mul(c, b, c); /* c = 11 */
    /* 22 */ curve25519_square_times(t0, c, 1);
    /* 2^5 - 2^0 = 31 */ curve25519_mul(b, t0, b);
    /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
    /* 2^252 - 2^2 */ curve25519_square_times(b, b, 2);
    /* 2^252 - 3 */ curve25519_mul(two252m3, b, z);
}

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
        hash.Update(block, (size_t)rem);

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

inline bignum256modm_element_t
lt_modm(bignum256modm_element_t a, bignum256modm_element_t b) {
    return (a - b) >> 31;
}

/* see HAC, Alg. 14.42 Step 4 */
void
reduce256_modm(bignum256modm r) {
    bignum256modm t;
    bignum256modm_element_t b = 0, pb, mask;

    /* t = r - m */
    pb = 0;
    pb += modm_m[0]; b = lt_modm(r[0], pb); t[0] = (r[0] - pb + (b << 30)); pb = b;
    pb += modm_m[1]; b = lt_modm(r[1], pb); t[1] = (r[1] - pb + (b << 30)); pb = b;
    pb += modm_m[2]; b = lt_modm(r[2], pb); t[2] = (r[2] - pb + (b << 30)); pb = b;
    pb += modm_m[3]; b = lt_modm(r[3], pb); t[3] = (r[3] - pb + (b << 30)); pb = b;
    pb += modm_m[4]; b = lt_modm(r[4], pb); t[4] = (r[4] - pb + (b << 30)); pb = b;
    pb += modm_m[5]; b = lt_modm(r[5], pb); t[5] = (r[5] - pb + (b << 30)); pb = b;
    pb += modm_m[6]; b = lt_modm(r[6], pb); t[6] = (r[6] - pb + (b << 30)); pb = b;
    pb += modm_m[7]; b = lt_modm(r[7], pb); t[7] = (r[7] - pb + (b << 30)); pb = b;
    pb += modm_m[8]; b = lt_modm(r[8], pb); t[8] = (r[8] - pb + (b << 16));

    /* keep r if r was smaller than m */
    mask = b - 1;
    r[0] ^= mask & (r[0] ^ t[0]);
    r[1] ^= mask & (r[1] ^ t[1]);
    r[2] ^= mask & (r[2] ^ t[2]);
    r[3] ^= mask & (r[3] ^ t[3]);
    r[4] ^= mask & (r[4] ^ t[4]);
    r[5] ^= mask & (r[5] ^ t[5]);
    r[6] ^= mask & (r[6] ^ t[6]);
    r[7] ^= mask & (r[7] ^ t[7]);
    r[8] ^= mask & (r[8] ^ t[8]);
}

/* Barrett reduction, see HAC, Alg. 14.42 */
void
barrett_reduce256_modm(bignum256modm r, const bignum256modm q1, const bignum256modm r1) {
    bignum256modm q3, r2;
    word64 c;
    bignum256modm_element_t f, b, pb;

    /* q1 = x >> 248 = 264 bits = 9 30 bit elements
       q2 = mu * q1
       q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264
     */
    c  = mul32x32_64(modm_mu[0], q1[7]) + mul32x32_64(modm_mu[1], q1[6]) + mul32x32_64(modm_mu[2], q1[5]) + mul32x32_64(modm_mu[3], q1[4]) + mul32x32_64(modm_mu[4], q1[3]) + mul32x32_64(modm_mu[5], q1[2]) + mul32x32_64(modm_mu[6], q1[1]) + mul32x32_64(modm_mu[7], q1[0]);
    c >>= 30;
    c += mul32x32_64(modm_mu[0], q1[8]) + mul32x32_64(modm_mu[1], q1[7]) + mul32x32_64(modm_mu[2], q1[6]) + mul32x32_64(modm_mu[3], q1[5]) + mul32x32_64(modm_mu[4], q1[4]) + mul32x32_64(modm_mu[5], q1[3]) + mul32x32_64(modm_mu[6], q1[2]) + mul32x32_64(modm_mu[7], q1[1]) + mul32x32_64(modm_mu[8], q1[0]);
    f = (bignum256modm_element_t)c; q3[0] = (f >> 24) & 0x3f; c >>= 30;
    c += mul32x32_64(modm_mu[1], q1[8]) + mul32x32_64(modm_mu[2], q1[7]) + mul32x32_64(modm_mu[3], q1[6]) + mul32x32_64(modm_mu[4], q1[5]) + mul32x32_64(modm_mu[5], q1[4]) + mul32x32_64(modm_mu[6], q1[3]) + mul32x32_64(modm_mu[7], q1[2]) + mul32x32_64(modm_mu[8], q1[1]);
    f = (bignum256modm_element_t)c; q3[0] |= (f << 6) & 0x3fffffff; q3[1] = (f >> 24) & 0x3f; c >>= 30;
    c += mul32x32_64(modm_mu[2], q1[8]) + mul32x32_64(modm_mu[3], q1[7]) + mul32x32_64(modm_mu[4], q1[6]) + mul32x32_64(modm_mu[5], q1[5]) + mul32x32_64(modm_mu[6], q1[4]) + mul32x32_64(modm_mu[7], q1[3]) + mul32x32_64(modm_mu[8], q1[2]);
    f = (bignum256modm_element_t)c; q3[1] |= (f << 6) & 0x3fffffff; q3[2] = (f >> 24) & 0x3f; c >>= 30;
    c += mul32x32_64(modm_mu[3], q1[8]) + mul32x32_64(modm_mu[4], q1[7]) + mul32x32_64(modm_mu[5], q1[6]) + mul32x32_64(modm_mu[6], q1[5]) + mul32x32_64(modm_mu[7], q1[4]) + mul32x32_64(modm_mu[8], q1[3]);
    f = (bignum256modm_element_t)c; q3[2] |= (f << 6) & 0x3fffffff; q3[3] = (f >> 24) & 0x3f; c >>= 30;
    c += mul32x32_64(modm_mu[4], q1[8]) + mul32x32_64(modm_mu[5], q1[7]) + mul32x32_64(modm_mu[6], q1[6]) + mul32x32_64(modm_mu[7], q1[5]) + mul32x32_64(modm_mu[8], q1[4]);
    f = (bignum256modm_element_t)c; q3[3] |= (f << 6) & 0x3fffffff; q3[4] = (f >> 24) & 0x3f; c >>= 30;
    c += mul32x32_64(modm_mu[5], q1[8]) + mul32x32_64(modm_mu[6], q1[7]) + mul32x32_64(modm_mu[7], q1[6]) + mul32x32_64(modm_mu[8], q1[5]);
    f = (bignum256modm_element_t)c; q3[4] |= (f << 6) & 0x3fffffff; q3[5] = (f >> 24) & 0x3f; c >>= 30;
    c += mul32x32_64(modm_mu[6], q1[8]) + mul32x32_64(modm_mu[7], q1[7]) + mul32x32_64(modm_mu[8], q1[6]);
    f = (bignum256modm_element_t)c; q3[5] |= (f << 6) & 0x3fffffff; q3[6] = (f >> 24) & 0x3f; c >>= 30;
    c += mul32x32_64(modm_mu[7], q1[8]) + mul32x32_64(modm_mu[8], q1[7]);
    f = (bignum256modm_element_t)c; q3[6] |= (f << 6) & 0x3fffffff; q3[7] = (f >> 24) & 0x3f; c >>= 30;
    c += mul32x32_64(modm_mu[8], q1[8]);
    f = (bignum256modm_element_t)c; q3[7] |= (f << 6) & 0x3fffffff; q3[8] = (bignum256modm_element_t)(c >> 24);

    /* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1)
       r2 = (q3 * m) mod (256^(32+1)) = (q3 * m) & ((1 << 264) - 1)
     */
    c = mul32x32_64(modm_m[0], q3[0]);
    r2[0] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
    c += mul32x32_64(modm_m[0], q3[1]) + mul32x32_64(modm_m[1], q3[0]);
    r2[1] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
    c += mul32x32_64(modm_m[0], q3[2]) + mul32x32_64(modm_m[1], q3[1]) + mul32x32_64(modm_m[2], q3[0]);
    r2[2] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
    c += mul32x32_64(modm_m[0], q3[3]) + mul32x32_64(modm_m[1], q3[2]) + mul32x32_64(modm_m[2], q3[1]) + mul32x32_64(modm_m[3], q3[0]);
    r2[3] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
    c += mul32x32_64(modm_m[0], q3[4]) + mul32x32_64(modm_m[1], q3[3]) + mul32x32_64(modm_m[2], q3[2]) + mul32x32_64(modm_m[3], q3[1]) + mul32x32_64(modm_m[4], q3[0]);
    r2[4] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
    c += mul32x32_64(modm_m[0], q3[5]) + mul32x32_64(modm_m[1], q3[4]) + mul32x32_64(modm_m[2], q3[3]) + mul32x32_64(modm_m[3], q3[2]) + mul32x32_64(modm_m[4], q3[1]) + mul32x32_64(modm_m[5], q3[0]);
    r2[5] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
    c += mul32x32_64(modm_m[0], q3[6]) + mul32x32_64(modm_m[1], q3[5]) + mul32x32_64(modm_m[2], q3[4]) + mul32x32_64(modm_m[3], q3[3]) + mul32x32_64(modm_m[4], q3[2]) + mul32x32_64(modm_m[5], q3[1]) + mul32x32_64(modm_m[6], q3[0]);
    r2[6] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
    c += mul32x32_64(modm_m[0], q3[7]) + mul32x32_64(modm_m[1], q3[6]) + mul32x32_64(modm_m[2], q3[5]) + mul32x32_64(modm_m[3], q3[4]) + mul32x32_64(modm_m[4], q3[3]) + mul32x32_64(modm_m[5], q3[2]) + mul32x32_64(modm_m[6], q3[1]) + mul32x32_64(modm_m[7], q3[0]);
    r2[7] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
    c += mul32x32_64(modm_m[0], q3[8]) + mul32x32_64(modm_m[1], q3[7]) + mul32x32_64(modm_m[2], q3[6]) + mul32x32_64(modm_m[3], q3[5]) + mul32x32_64(modm_m[4], q3[4]) + mul32x32_64(modm_m[5], q3[3]) + mul32x32_64(modm_m[6], q3[2]) + mul32x32_64(modm_m[7], q3[1]) + mul32x32_64(modm_m[8], q3[0]);
    r2[8] = (bignum256modm_element_t)(c & 0xffffff);

    /* r = r1 - r2
       if (r < 0) r += (1 << 264) */
    pb = 0;
    pb += r2[0]; b = lt_modm(r1[0], pb); r[0] = (r1[0] - pb + (b << 30)); pb = b;
    pb += r2[1]; b = lt_modm(r1[1], pb); r[1] = (r1[1] - pb + (b << 30)); pb = b;
    pb += r2[2]; b = lt_modm(r1[2], pb); r[2] = (r1[2] - pb + (b << 30)); pb = b;
    pb += r2[3]; b = lt_modm(r1[3], pb); r[3] = (r1[3] - pb + (b << 30)); pb = b;
    pb += r2[4]; b = lt_modm(r1[4], pb); r[4] = (r1[4] - pb + (b << 30)); pb = b;
    pb += r2[5]; b = lt_modm(r1[5], pb); r[5] = (r1[5] - pb + (b << 30)); pb = b;
    pb += r2[6]; b = lt_modm(r1[6], pb); r[6] = (r1[6] - pb + (b << 30)); pb = b;
    pb += r2[7]; b = lt_modm(r1[7], pb); r[7] = (r1[7] - pb + (b << 30)); pb = b;
    pb += r2[8]; b = lt_modm(r1[8], pb); r[8] = (r1[8] - pb + (b << 24));

    reduce256_modm(r);
    reduce256_modm(r);
}

/* addition modulo m */
void
add256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y) {
    bignum256modm_element_t c;

    c  = x[0] + y[0]; r[0] = c & 0x3fffffff; c >>= 30;
    c += x[1] + y[1]; r[1] = c & 0x3fffffff; c >>= 30;
    c += x[2] + y[2]; r[2] = c & 0x3fffffff; c >>= 30;
    c += x[3] + y[3]; r[3] = c & 0x3fffffff; c >>= 30;
    c += x[4] + y[4]; r[4] = c & 0x3fffffff; c >>= 30;
    c += x[5] + y[5]; r[5] = c & 0x3fffffff; c >>= 30;
    c += x[6] + y[6]; r[6] = c & 0x3fffffff; c >>= 30;
    c += x[7] + y[7]; r[7] = c & 0x3fffffff; c >>= 30;
    c += x[8] + y[8]; r[8] = c;

    reduce256_modm(r);
}

/* multiplication modulo m */
void
mul256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y) {
    bignum256modm r1, q1;
    word64 c;
    bignum256modm_element_t f;

    c = mul32x32_64(x[0], y[0]);
    f = (bignum256modm_element_t)c; r1[0] = (f & 0x3fffffff); c >>= 30;
    c += mul32x32_64(x[0], y[1]) + mul32x32_64(x[1], y[0]);
    f = (bignum256modm_element_t)c; r1[1] = (f & 0x3fffffff); c >>= 30;
    c += mul32x32_64(x[0], y[2]) + mul32x32_64(x[1], y[1]) + mul32x32_64(x[2], y[0]);
    f = (bignum256modm_element_t)c; r1[2] = (f & 0x3fffffff); c >>= 30;
    c += mul32x32_64(x[0], y[3]) + mul32x32_64(x[1], y[2]) + mul32x32_64(x[2], y[1]) + mul32x32_64(x[3], y[0]);
    f = (bignum256modm_element_t)c; r1[3] = (f & 0x3fffffff); c >>= 30;
    c += mul32x32_64(x[0], y[4]) + mul32x32_64(x[1], y[3]) + mul32x32_64(x[2], y[2]) + mul32x32_64(x[3], y[1]) + mul32x32_64(x[4], y[0]);
    f = (bignum256modm_element_t)c; r1[4] = (f & 0x3fffffff); c >>= 30;
    c += mul32x32_64(x[0], y[5]) + mul32x32_64(x[1], y[4]) + mul32x32_64(x[2], y[3]) + mul32x32_64(x[3], y[2]) + mul32x32_64(x[4], y[1]) + mul32x32_64(x[5], y[0]);
    f = (bignum256modm_element_t)c; r1[5] = (f & 0x3fffffff); c >>= 30;
    c += mul32x32_64(x[0], y[6]) + mul32x32_64(x[1], y[5]) + mul32x32_64(x[2], y[4]) + mul32x32_64(x[3], y[3]) + mul32x32_64(x[4], y[2]) + mul32x32_64(x[5], y[1]) + mul32x32_64(x[6], y[0]);
    f = (bignum256modm_element_t)c; r1[6] = (f & 0x3fffffff); c >>= 30;
    c += mul32x32_64(x[0], y[7]) + mul32x32_64(x[1], y[6]) + mul32x32_64(x[2], y[5]) + mul32x32_64(x[3], y[4]) + mul32x32_64(x[4], y[3]) + mul32x32_64(x[5], y[2]) + mul32x32_64(x[6], y[1]) + mul32x32_64(x[7], y[0]);
    f = (bignum256modm_element_t)c; r1[7] = (f & 0x3fffffff); c >>= 30;
    c += mul32x32_64(x[0], y[8]) + mul32x32_64(x[1], y[7]) + mul32x32_64(x[2], y[6]) + mul32x32_64(x[3], y[5]) + mul32x32_64(x[4], y[4]) + mul32x32_64(x[5], y[3]) + mul32x32_64(x[6], y[2]) + mul32x32_64(x[7], y[1]) + mul32x32_64(x[8], y[0]);
    f = (bignum256modm_element_t)c; r1[8] = (f & 0x00ffffff); q1[0] = (f >> 8) & 0x3fffff; c >>= 30;
    c += mul32x32_64(x[1], y[8]) + mul32x32_64(x[2], y[7]) + mul32x32_64(x[3], y[6]) + mul32x32_64(x[4], y[5]) + mul32x32_64(x[5], y[4]) + mul32x32_64(x[6], y[3]) + mul32x32_64(x[7], y[2]) + mul32x32_64(x[8], y[1]);
    f = (bignum256modm_element_t)c; q1[0] = (q1[0] | (f << 22)) & 0x3fffffff; q1[1] = (f >> 8) & 0x3fffff; c >>= 30;
    c += mul32x32_64(x[2], y[8]) + mul32x32_64(x[3], y[7]) + mul32x32_64(x[4], y[6]) + mul32x32_64(x[5], y[5]) + mul32x32_64(x[6], y[4]) + mul32x32_64(x[7], y[3]) + mul32x32_64(x[8], y[2]);
    f = (bignum256modm_element_t)c; q1[1] = (q1[1] | (f << 22)) & 0x3fffffff; q1[2] = (f >> 8) & 0x3fffff; c >>= 30;
    c += mul32x32_64(x[3], y[8]) + mul32x32_64(x[4], y[7]) + mul32x32_64(x[5], y[6]) + mul32x32_64(x[6], y[5]) + mul32x32_64(x[7], y[4]) + mul32x32_64(x[8], y[3]);
    f = (bignum256modm_element_t)c; q1[2] = (q1[2] | (f << 22)) & 0x3fffffff; q1[3] = (f >> 8) & 0x3fffff; c >>= 30;
    c += mul32x32_64(x[4], y[8]) + mul32x32_64(x[5], y[7]) + mul32x32_64(x[6], y[6]) + mul32x32_64(x[7], y[5]) + mul32x32_64(x[8], y[4]);
    f = (bignum256modm_element_t)c; q1[3] = (q1[3] | (f << 22)) & 0x3fffffff; q1[4] = (f >> 8) & 0x3fffff; c >>= 30;
    c += mul32x32_64(x[5], y[8]) + mul32x32_64(x[6], y[7]) + mul32x32_64(x[7], y[6]) + mul32x32_64(x[8], y[5]);
    f = (bignum256modm_element_t)c; q1[4] = (q1[4] | (f << 22)) & 0x3fffffff; q1[5] = (f >> 8) & 0x3fffff; c >>= 30;
    c += mul32x32_64(x[6], y[8]) + mul32x32_64(x[7], y[7]) + mul32x32_64(x[8], y[6]);
    f = (bignum256modm_element_t)c; q1[5] = (q1[5] | (f << 22)) & 0x3fffffff; q1[6] = (f >> 8) & 0x3fffff; c >>= 30;
    c += mul32x32_64(x[7], y[8]) + mul32x32_64(x[8], y[7]);
    f = (bignum256modm_element_t)c; q1[6] = (q1[6] | (f << 22)) & 0x3fffffff; q1[7] = (f >> 8) & 0x3fffff; c >>= 30;
    c += mul32x32_64(x[8], y[8]);
    f = (bignum256modm_element_t)c; q1[7] = (q1[7] | (f << 22)) & 0x3fffffff; q1[8] = (f >> 8) & 0x3fffff;

    barrett_reduce256_modm(r, q1, r1);
}

void
expand256_modm(bignum256modm out, const byte *in, size_t len) {
    byte work[64] = {0};
    bignum256modm_element_t x[16];
    bignum256modm q1;

    memcpy(work, in, len);
    x[0] = U8TO32_LE(work +  0);
    x[1] = U8TO32_LE(work +  4);
    x[2] = U8TO32_LE(work +  8);
    x[3] = U8TO32_LE(work + 12);
    x[4] = U8TO32_LE(work + 16);
    x[5] = U8TO32_LE(work + 20);
    x[6] = U8TO32_LE(work + 24);
    x[7] = U8TO32_LE(work + 28);
    x[8] = U8TO32_LE(work + 32);
    x[9] = U8TO32_LE(work + 36);
    x[10] = U8TO32_LE(work + 40);
    x[11] = U8TO32_LE(work + 44);
    x[12] = U8TO32_LE(work + 48);
    x[13] = U8TO32_LE(work + 52);
    x[14] = U8TO32_LE(work + 56);
    x[15] = U8TO32_LE(work + 60);

    /* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
    out[0] = (                         x[0]) & 0x3fffffff;
    out[1] = ((x[ 0] >> 30) | (x[ 1] <<  2)) & 0x3fffffff;
    out[2] = ((x[ 1] >> 28) | (x[ 2] <<  4)) & 0x3fffffff;
    out[3] = ((x[ 2] >> 26) | (x[ 3] <<  6)) & 0x3fffffff;
    out[4] = ((x[ 3] >> 24) | (x[ 4] <<  8)) & 0x3fffffff;
    out[5] = ((x[ 4] >> 22) | (x[ 5] << 10)) & 0x3fffffff;
    out[6] = ((x[ 5] >> 20) | (x[ 6] << 12)) & 0x3fffffff;
    out[7] = ((x[ 6] >> 18) | (x[ 7] << 14)) & 0x3fffffff;
    out[8] = ((x[ 7] >> 16) | (x[ 8] << 16)) & 0x00ffffff;

    /* 8*31 = 248 bits, no need to reduce */
    if (len < 32)
            return;

    /* q1 = x >> 248 = 264 bits = 9 30 bit elements */
    q1[0] = ((x[ 7] >> 24) | (x[ 8] <<  8)) & 0x3fffffff;
    q1[1] = ((x[ 8] >> 22) | (x[ 9] << 10)) & 0x3fffffff;
    q1[2] = ((x[ 9] >> 20) | (x[10] << 12)) & 0x3fffffff;
    q1[3] = ((x[10] >> 18) | (x[11] << 14)) & 0x3fffffff;
    q1[4] = ((x[11] >> 16) | (x[12] << 16)) & 0x3fffffff;
    q1[5] = ((x[12] >> 14) | (x[13] << 18)) & 0x3fffffff;
    q1[6] = ((x[13] >> 12) | (x[14] << 20)) & 0x3fffffff;
    q1[7] = ((x[14] >> 10) | (x[15] << 22)) & 0x3fffffff;
    q1[8] = ((x[15] >>  8)                );

    barrett_reduce256_modm(out, q1, out);
}

void
expand_raw256_modm(bignum256modm out, const byte in[32]) {
    bignum256modm_element_t x[8];

    x[0] = U8TO32_LE(in +  0);
    x[1] = U8TO32_LE(in +  4);
    x[2] = U8TO32_LE(in +  8);
    x[3] = U8TO32_LE(in + 12);
    x[4] = U8TO32_LE(in + 16);
    x[5] = U8TO32_LE(in + 20);
    x[6] = U8TO32_LE(in + 24);
    x[7] = U8TO32_LE(in + 28);

    out[0] = (                         x[0]) & 0x3fffffff;
    out[1] = ((x[ 0] >> 30) | (x[ 1] <<  2)) & 0x3fffffff;
    out[2] = ((x[ 1] >> 28) | (x[ 2] <<  4)) & 0x3fffffff;
    out[3] = ((x[ 2] >> 26) | (x[ 3] <<  6)) & 0x3fffffff;
    out[4] = ((x[ 3] >> 24) | (x[ 4] <<  8)) & 0x3fffffff;
    out[5] = ((x[ 4] >> 22) | (x[ 5] << 10)) & 0x3fffffff;
    out[6] = ((x[ 5] >> 20) | (x[ 6] << 12)) & 0x3fffffff;
    out[7] = ((x[ 6] >> 18) | (x[ 7] << 14)) & 0x3fffffff;
    out[8] = ((x[ 7] >> 16)                ) & 0x0000ffff;
}

void
contract256_modm(byte out[32], const bignum256modm in) {
    U32TO8_LE(out +  0, (in[0]      ) | (in[1] << 30));
    U32TO8_LE(out +  4, (in[1] >>  2) | (in[2] << 28));
    U32TO8_LE(out +  8, (in[2] >>  4) | (in[3] << 26));
    U32TO8_LE(out + 12, (in[3] >>  6) | (in[4] << 24));
    U32TO8_LE(out + 16, (in[4] >>  8) | (in[5] << 22));
    U32TO8_LE(out + 20, (in[5] >> 10) | (in[6] << 20));
    U32TO8_LE(out + 24, (in[6] >> 12) | (in[7] << 18));
    U32TO8_LE(out + 28, (in[7] >> 14) | (in[8] << 16));
}

void
contract256_window4_modm(signed char r[64], const bignum256modm in) {
    char carry;
    signed char *quads = r;
    bignum256modm_element_t i, j, v;

    for (i = 0; i < 8; i += 2) {
        v = in[i];
        for (j = 0; j < 7; j++) {
            *quads++ = (v & 15);
            v >>= 4;
        }
        v |= (in[i+1] << 2);
        for (j = 0; j < 8; j++) {
            *quads++ = (v & 15);
            v >>= 4;
        }
    }

    v = in[8];
    *quads++ = (v & 15); v >>= 4;
    *quads++ = (v & 15); v >>= 4;
    *quads++ = (v & 15); v >>= 4;
    *quads++ = (v & 15); v >>= 4;

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
    for (i = 0; i < 8; i++) {
        v = s[i];
        for (j = 0; j < 30; j++, v >>= 1)
            *bits++ = (v & 1);
    }
    v = s[8];
    for (j = 0; j < 16; j++, v >>= 1)
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
    memset(r, 0, sizeof(ge25519));
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
    memset(r->z, 0, sizeof(bignum25519));
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
    for (size_t i = 0; i < 32; ++i)
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
    ALIGN(16) ge25519 A;
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
    ALIGN(16) ge25519 R;
    hash_512bits extsk, hashr, hram;

    // Unfortunately we need to read the stream twice. The fisrt time calculates
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
    ALIGN(16) ge25519 R;
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
ed25519_sign_open_CXX(std::istream& stream, const byte pk[32], const byte RS[64]) {

    using namespace CryptoPP::Donna::Ed25519;

    ALIGN(16) ge25519 R, A;
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
ed25519_sign_open_CXX(const byte *m, size_t mlen, const byte pk[32], const byte RS[64]) {

    using namespace CryptoPP::Donna::Ed25519;

    ALIGN(16) ge25519 R, A;
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
ed25519_sign_open(const byte *message, size_t messageLength, const byte publicKey[32], const byte signature[64])
{
    return ed25519_sign_open_CXX(message, messageLength, publicKey, signature);
}

int
ed25519_sign_open(std::istream& stream, const byte publicKey[32], const byte signature[64])
{
    return ed25519_sign_open_CXX(stream, publicKey, signature);
}

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_CURVE25519_32BIT
