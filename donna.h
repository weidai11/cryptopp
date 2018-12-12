// donna.h - written and placed in public domain by Jeffrey Walton
//           This is a port of Adam Langley's curve25519-donna
//           located at https://github.com/agl/curve25519-donna

/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation. */

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

NAMESPACE_END  // Donna
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_DONNA_H
