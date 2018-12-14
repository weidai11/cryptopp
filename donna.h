// donna.h - written and placed in public domain by Jeffrey Walton
//           This is a integration of Andrew Moon's public domain code.
//           Also see https://github.com/floodyberry/curve25519-donna.

// Benchmarking on a modern Core i5-6400 shows SSE2 on Linux is not
// profitable. You can enable it with CRYPTOPP_CURVE25519_SSE2.

// If needed, see Moon's commit "Go back to ignoring 256th bit [sic]",
// https://github.com/floodyberry/curve25519-donna/commit/57a683d18721a658

#ifndef CRYPTOPP_DONNA_H
#define CRYPTOPP_DONNA_H

#include "cryptlib.h"
#include "stdcpp.h"

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

//****************************** Internal ******************************//

// CRYPTOPP_WORD128_AVAILABLE mostly depends upon GCC support for
// __SIZEOF_INT128__. If __SIZEOF_INT128__ is not available then Moon
// provides routines for MSC and GCC. It should cover most platforms,
// but there are gaps like MS ARM64 and XLC. We tried to enable the
// 64-bit path for SunCC from 12.5 but we got the dreaded compile
// error "The operand ___LCM cannot be assigned to".

#if defined(CRYPTOPP_WORD128_AVAILABLE) || \
   (defined(_MSC_VER) && defined(_M_X64)) || \
   (defined(__GNUC__) && (defined(__amd64__) || defined(__x86_64__)))
# define CRYPTOPP_CURVE25519_64BIT 1
#else
# define CRYPTOPP_CURVE25519_32BIT 1
#endif

// Benchmarking on a modern 64-bit Core i5-6400 @2.7 GHz shows SSE2 on Linux
// is not profitable. Here are the numbers in milliseconds/operation:
//
//   * Langley, C++, 0.050
//   * Moon, C++: 0.040
//   * Moon, SSE2: 0.061
//   * Moon, native: 0.045
//
// However, a modern 64-bit Core i5-3200 @2.3 GHz shows SSE2 is profitable
// for MS compilers. Here are the numbers in milliseconds/operation:
//
//   * x86, no SSE2, 0.294
//   * x86, SSE2, 0.097
//   * x64, no SSE2, 0.081
//   * x64, SSE2, 0.071

#if (CRYPTOPP_SSE2_INTRIN_AVAILABLE) && defined(_MSC_VER)
# define CRYPTOPP_CURVE25519_SSE2 1
#endif

#if (CRYPTOPP_CURVE25519_SSE2)
  extern int curve25519_SSE2(byte sharedKey[32], const byte secretKey[32], const byte othersKey[32]);
#endif

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_DONNA_H
