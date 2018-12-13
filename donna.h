// donna.h - written and placed in public domain by Jeffrey Walton
//           This is a port of Adam Langley's curve25519-donna
//           located at https://github.com/agl/curve25519-donna

#ifndef CRYPTOPP_DONNA_H
#define CRYPTOPP_DONNA_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Donna)

/// \brief Generate public key
/// \param publicKey byte array for the public key
/// \param secretKey byte array with the private key
/// \returns 0 on success, non-0 otherwise
/// \details This curve25519() overload generates a public key from an existing
///   secret key. Internally curve25519() performs a scalar multiplication
///   using the base point and writes the result to <tt>pubkey</tt>.
int curve25519(byte publicKey[32], const byte secretKey[32]);

/// \brief Generate shared key
/// \param sharedKey byte array for the shared secret
/// \param secretKey byte array with the private key
/// \param othersKey byte array with the peer's public key
/// \returns 0 on success, non-0 otherwise
/// \details This curve25519() overload generates a shared key from an existing
///   a secret key and the other party's public key. Internally curve25519()
///   performs a scalar multiplication using the two keys and writes the result
///   to <tt>sharedKey</tt>.
int curve25519(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32]);

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE)
  extern int curve25519_SSE2(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32]);
#endif

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_DONNA_H
