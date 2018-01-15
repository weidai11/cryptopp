// nacl.h - written and placed in the public domain by Jeffrey Walton

/// \file nacl.h
/// \brief Crypto++ interface to TweetNaCl library (20140917)
/// \details TweetNaCl is a compact reimplementation of the NaCl library by
///   Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange,
///   Peter Schwabe and Sjaak Smetsers. The library is less than 20 KB in size
///   and provides 25 of the NaCl library functions.
/// \details The compact library uses curve25519, XSalsa20, Poly1305 and
///   SHA-512 as defult primitives, and includes both x25519 key exchange and
///   ed25519 signatures.
/// \sa <A HREF="https://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf">TweetNaCl:
///   A crypto library in 100 tweets</A> (20140917)
/// \since Crypto++ 6.0

#ifndef CRYPTOPP_NACL_H
#define CRYPTOPP_NACL_H

#include "config.h"
#include "stdcpp.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(NaCl)

/// \brief Hash size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/hash.html">NaCl crypto_hash documentation</a>
CRYPTOPP_CONSTANT(crypto_hash_BYTES = 64)

/// \brief Key size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/stream.html">NaCl crypto_stream documentation</a>
CRYPTOPP_CONSTANT(crypto_stream_KEYBYTES = 32)
/// \brief Nonce size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/stream.html">NaCl crypto_stream documentation</a>
CRYPTOPP_CONSTANT(crypto_stream_NONCEBYTES = 24)

/// \brief Key size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/auth.html">NaCl crypto_auth documentation</a>
CRYPTOPP_CONSTANT(crypto_auth_KEYBYTES = 32)
/// \brief Tag size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/auth.html">NaCl crypto_auth documentation</a>
CRYPTOPP_CONSTANT(crypto_auth_BYTES = 16)

/// \brief Key size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/onetimeauth.html">NaCl crypto_onetimeauth documentation</a>
CRYPTOPP_CONSTANT(crypto_onetimeauth_KEYBYTES = 32)
/// \brief Tag size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/onetimeauth.html">NaCl crypto_onetimeauth documentation</a>
CRYPTOPP_CONSTANT(crypto_onetimeauth_BYTES = 16)

/// \brief Key size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/secretbox.html">NaCl crypto_secretbox documentation</a>
CRYPTOPP_CONSTANT(crypto_secretbox_KEYBYTES = 32)
/// \brief Nonce size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/secretbox.html">NaCl crypto_secretbox documentation</a>
CRYPTOPP_CONSTANT(crypto_secretbox_NONCEBYTES = 24)
/// \brief Zero-padded message prefix in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/secretbox.html">NaCl crypto_secretbox documentation</a>
CRYPTOPP_CONSTANT(crypto_secretbox_ZEROBYTES = 32)
/// \brief Zero-padded message prefix in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/secretbox.html">NaCl crypto_secretbox documentation</a>
CRYPTOPP_CONSTANT(crypto_secretbox_BOXZEROBYTES = 16)

/// \brief Private key size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
CRYPTOPP_CONSTANT(crypto_box_SECRETKEYBYTES = 32)
/// \brief Public key size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
CRYPTOPP_CONSTANT(crypto_box_PUBLICKEYBYTES = 32)
/// \brief Nonce size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
CRYPTOPP_CONSTANT(crypto_box_NONCEBYTES = 24)
/// \brief Open box prefix in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
CRYPTOPP_CONSTANT(crypto_box_ZEROBYTES = 32)
/// \brief Open box precomputation size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
CRYPTOPP_CONSTANT(crypto_box_BEFORENMBYTES = 32)

/// \brief Private key size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/sign.html">NaCl crypto_sign documentation</a>
CRYPTOPP_CONSTANT(crypto_sign_SECRETKEYBYTES = 64)
/// \brief Public key size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/sign.html">NaCl crypto_sign documentation</a>
CRYPTOPP_CONSTANT(crypto_sign_PUBLICKEYBYTES = 32)
/// \brief Signature size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/sign.html">NaCl crypto_sign documentation</a>
CRYPTOPP_CONSTANT(crypto_sign_BYTES = 64)

/// \brief Group element size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/scalarmult.html">NaCl crypto_scalarmult documentation</a>
CRYPTOPP_CONSTANT(crypto_scalarmult_BYTES = 32)
/// \brief Integer size in bytes
/// \sa <A HREF="https://nacl.cr.yp.to/scalarmult.html">NaCl crypto_scalarmult documentation</a>
CRYPTOPP_CONSTANT(crypto_scalarmult_SCALARBYTES = 32)

/// \brief Encrypt and authenticate a message
/// \details crypto_box() uses crypto_box_curve25519xsalsa20poly1305
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
/// \since Crypto++ 6.0
int crypto_box(uint8_t *c,const uint8_t *m,uint64_t d,const uint8_t *n,const uint8_t *y,const uint8_t *x);

/// \brief Verify and decrypt a message
/// \details crypto_box_open() uses crypto_box_curve25519xsalsa20poly1305
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
/// \since Crypto++ 6.0
int crypto_box_open(uint8_t *m,const uint8_t *c,uint64_t d,const uint8_t *n,const uint8_t *y,const uint8_t *x);

/// \brief Generate a keypair for encryption
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
/// \since Crypto++ 6.0
int crypto_box_keypair(uint8_t *y,uint8_t *x);

/// \brief Encrypt and authenticate a message
/// \details crypto_box_beforenm() performs message-independent precomputation to derive the key.
///   Once the key is derived multiple calls to crypto_box_afternm() can be made to process the message.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
/// \since Crypto++ 6.0
int crypto_box_beforenm(uint8_t *k,const uint8_t *y,const uint8_t *x);

/// \brief Encrypt and authenticate a message
/// \details crypto_box_afternm() performs message-dependent computation using the derived the key.
///   Once the key is derived using crypto_box_beforenm() multiple calls to crypto_box_afternm()
///   can be made to process the message.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
/// \since Crypto++ 6.0
int crypto_box_afternm(uint8_t *c,const uint8_t *m,uint64_t d,const uint8_t *n,const uint8_t *k);

/// \brief Verify and decrypt a message
/// \details crypto_box_afternm() performs message-dependent computation using the derived the key.
///   Once the key is derived using crypto_box_beforenm() multiple calls to crypto_box_open_afternm()
///   can be made to process the message.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/box.html">NaCl crypto_box documentation</a>
/// \since Crypto++ 6.0
int crypto_box_open_afternm(uint8_t *m,const uint8_t *c,uint64_t d,const uint8_t *n,const uint8_t *k);

/// \brief TODO
int crypto_core_salsa20(uint8_t *out,const uint8_t *in,const uint8_t *k,const uint8_t *c);

/// \brief TODO
/// \returns 0 on success, non-0 otherwise
/// \since Crypto++ 6.0
int crypto_core_hsalsa20(uint8_t *out,const uint8_t *in,const uint8_t *k,const uint8_t *c);

/// \brief Hash multiple blocks
/// \details crypto_hashblocks() uses crypto_hashblocks_sha512.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/hash.html">NaCl crypto_hash documentation</a>
/// \since Crypto++ 6.0
int crypto_hashblocks(uint8_t *x,const uint8_t *m,uint64_t n);

/// \brief Hash a message
/// \details crypto_hash() uses crypto_hash_sha512.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/hash.html">NaCl crypto_hash documentation</a>
/// \since Crypto++ 6.0
int crypto_hash(uint8_t *out,const uint8_t *m,uint64_t n);

/// \brief Create an authentication tag for a message
/// \details crypto_onetimeauth() uses crypto_onetimeauth_poly1305.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/onetimeauth.html">NaCl crypto_onetimeauth documentation</a>
/// \since Crypto++ 6.0
int crypto_onetimeauth(uint8_t *out,const uint8_t *m,uint64_t n,const uint8_t *k);

/// \brief Verify an authentication tag on a message
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/onetimeauth.html">NaCl crypto_onetimeauth documentation</a>
/// \since Crypto++ 6.0
int crypto_onetimeauth_verify(const uint8_t *h,const uint8_t *m,uint64_t n,const uint8_t *k);

/// \brief Scalar multiplication of a point
/// \details crypto_scalarmult() uses crypto_scalarmult_curve25519
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/scalarmult.html">NaCl crypto_scalarmult documentation</a>
/// \since Crypto++ 6.0
int crypto_scalarmult(uint8_t *q,const uint8_t *n,const uint8_t *p);

/// \brief Scalar multiplication of base point
/// \details crypto_scalarmult_base() uses crypto_scalarmult_curve25519
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/scalarmult.html">NaCl crypto_scalarmult documentation</a>
/// \since Crypto++ 6.0
int crypto_scalarmult_base(uint8_t *q,const uint8_t *n);

/// \brief Encrypt and authenticate a message
/// \details crypto_secretbox() uses a symmetric key to encrypt and authenticate a message.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/secretbox.html">NaCl crypto_secretbox documentation</a>
/// \since Crypto++ 6.0
int crypto_secretbox(uint8_t *c,const uint8_t *m,uint64_t d,const uint8_t *n,const uint8_t *k);

/// \brief Verify and decrypt a message
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/secretbox.html">NaCl crypto_secretbox documentation</a>
/// \since Crypto++ 6.0
int crypto_secretbox_open(uint8_t *m,const uint8_t *c,uint64_t d,const uint8_t *n,const uint8_t *k);

/// \brief Sign a message
/// \details crypto_sign() uses crypto_sign_ed25519.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/sign.html">NaCl crypto_sign documentation</a>
/// \since Crypto++ 6.0
int crypto_sign(uint8_t *sm,uint64_t *smlen,const uint8_t *m,uint64_t n,const uint8_t *sk);

/// \brief Verify a message
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/sign.html">NaCl crypto_sign documentation</a>
/// \since Crypto++ 6.0
int crypto_sign_open(uint8_t *m,uint64_t *mlen,const uint8_t *sm,uint64_t n,const uint8_t *pk);

/// \brief Generate a keypair for signing
/// \details crypto_sign_keypair() creates an ed25519 keypair.
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/sign.html">NaCl crypto_sign documentation</a>
/// \since Crypto++ 6.0
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

/// \brief Produce a keystream using XSalsa20
/// \details crypto_stream() uses crypto_stream_xsalsa20
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/stream.html">NaCl crypto_stream documentation</a>
/// \since Crypto++ 6.0
int crypto_stream(uint8_t *c,uint64_t d,const uint8_t *n,const uint8_t *k);

/// \brief Encrypt a message using XSalsa20
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/stream.html">NaCl crypto_stream documentation</a>
/// \since Crypto++ 6.0
int crypto_stream_xor(uint8_t *c,const uint8_t *m,uint64_t d,const uint8_t *n,const uint8_t *k);

/// \brief Produce a keystream using Salsa20
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/stream.html">NaCl crypto_stream documentation</a>
/// \since Crypto++ 6.0
int crypto_stream_salsa20(uint8_t *c,uint64_t d,const uint8_t *n,const uint8_t *k);

/// \brief Encrypt a message using Salsa20
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/stream.html">NaCl crypto_stream documentation</a>
/// \since Crypto++ 6.0
int crypto_stream_salsa20_xor(uint8_t *c,const uint8_t *m,uint64_t b,const uint8_t *n,const uint8_t *k);

/// \brief Compare 16-byte buffers
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/verify.html">NaCl crypto_verify documentation</a>
/// \since Crypto++ 6.0
int crypto_verify_16(const uint8_t *x,const uint8_t *y);

/// \brief Compare 32-byte buffers
/// \returns 0 on success, non-0 otherwise
/// \sa <A HREF="https://nacl.cr.yp.to/verify.html">NaCl crypto_verify documentation</a>
/// \since Crypto++ 6.0
int crypto_verify_32(const uint8_t *x,const uint8_t *y);

NAMESPACE_END  // CryptoPP
NAMESPACE_END  // NaCl

#endif  // CRYPTOPP_NACL_H
