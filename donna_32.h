// donna_32.h - written and placed in public domain by Jeffrey Walton
//              Crypto++ specific implementation wrapped around Andrew
//              Moon's public domain curve25519-donna and ed25519-donna,
//              https://github.com/floodyberry/curve25519-donna and
//              https://github.com/floodyberry/ed25519-donna.

#ifndef CRYPTOPP_DONNA_32_H
#define CRYPTOPP_DONNA_32_H

#include "config.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)
NAMESPACE_BEGIN(Donna32)

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;

#define ALIGN(n) CRYPTOPP_ALIGN_DATA(n)
#define mul32x32_64(a,b) (((word64)(a))*(b))

typedef word32 bignum25519[10];

const byte basePoint[32] = {9};
const word32 reduce_mask_25 = (1 << 25) - 1;
const word32 reduce_mask_26 = (1 << 26) - 1;

NAMESPACE_END  // Donna32
NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_DONNA_32_H
