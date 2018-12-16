// donna_64.h - written and placed in public domain by Jeffrey Walton
//              Crypto++ specific implementation wrapped around Andrew
//              Moon's public domain curve25519-donna and ed25519-donna,
//              https://github.com/floodyberry/curve25519-donna and
//              https://github.com/floodyberry/ed25519-donna.

#ifndef CRYPTOPP_DONNA_64_H
#define CRYPTOPP_DONNA_64_H

#include "config.h"

#if defined(_MSC_VER)
# include <intrin.h>
# pragma intrinsic(_umul128)
# pragma intrinsic(__shiftright128)
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)
NAMESPACE_BEGIN(Donna64)

using CryptoPP::byte;
using CryptoPP::word64;

#define ALIGN(n) CRYPTOPP_ALIGN_DATA(n)
typedef word64 bignum25519[5];

const byte basePoint[32] = {9};
const word64 reduce_mask_51 = ((word64)1 << 51) - 1;
const word64 reduce_mask_52 = ((word64)1 << 52) - 1;

#if defined(CRYPTOPP_WORD128_AVAILABLE)
using CryptoPP::word128;
# define lo128(a) ((word64)a)
# define hi128(a) ((word64)(a >> 64))
# define add128(a,b) a += b;
# define add128_64(a,b) a += (word64)b;
# define mul64x64_128(out,a,b) out = (word128)a * b;
# define shr128(out,in,shift) out = (word64)(in >> (shift));
// # define shl128(out,in,shift) out = (word64)((in << shift) >> 64);

#elif defined(_MSC_VER)
struct word128 { word64 lo, hi; };
# define mul64x64_128(out,a,b) out.lo = _umul128(a,b,&out.hi);
# define shr128_pair(out,hi,lo,shift) out = __shiftright128(lo, hi, shift);
// # define shl128_pair(out,hi,lo,shift) out = __shiftleft128(lo, hi, shift);
# define shr128(out,in,shift) shr128_pair(out, in.hi, in.lo, shift)
// # define shl128(out,in,shift) shl128_pair(out, in.hi, in.lo, shift)
# define add128(a,b) { word64 p = a.lo; a.lo += b.lo; a.hi += b.hi + (a.lo < p); }
# define add128_64(a,b) { word64 p = a.lo; a.lo += b; a.hi += (a.lo < p); }
# define lo128(a) (a.lo)
# define hi128(a) (a.hi)

#elif defined(__GNUC__)
struct word128 { word64 lo, hi; };
# define mul64x64_128(out,a,b) __asm__ ("mulq %3" : "=a" (out.lo), "=d" (out.hi) : "a" (a), "rm" (b));
# define shr128_pair(out,hi,lo,shift) __asm__ ("shrdq %2,%1,%0" : "+r" (lo) : "r" (hi), "J" (shift)); out = lo;
// # define shl128_pair(out,hi,lo,shift) __asm__ ("shldq %2,%1,%0" : "+r" (hi) : "r" (lo), "J" (shift)); out = hi;
# define shr128(out,in,shift) shr128_pair(out,in.hi, in.lo, shift)
// # define shl128(out,in,shift) shl128_pair(out,in.hi, in.lo, shift)
# define add128(a,b) __asm__ ("addq %4,%2; adcq %5,%3" : "=r" (a.hi), "=r" (a.lo) : "1" (a.lo), "0" (a.hi), "rm" (b.lo), "rm" (b.hi) : "cc");
# define add128_64(a,b) __asm__ ("addq %4,%2; adcq $0,%3" : "=r" (a.hi), "=r" (a.lo) : "1" (a.lo), "0" (a.hi), "rm" (b) : "cc");
# define lo128(a) (a.lo)
# define hi128(a) (a.hi)
#else
// https://groups.google.com/forum/#!forum/cryptopp-users
# error "Unsupported platform"
#endif

NAMESPACE_END  // Donna64
NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_DONNA_64_H
