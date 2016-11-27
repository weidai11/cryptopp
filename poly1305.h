// poly1305.h - written and placed in the public domain by Jeffrey Walton and Jean-Pierre Munch
//              Based on Andy Polyakov's 32-bit OpenSSL implementation using scalar multiplication.
//              Copyright assigned to the Crypto++ project

//! \file poly1305.h
//! \brief Classes for Poly1305 message authentication code
//! \sa Daniel J. Bernstein <A HREF="http://cr.yp.to/mac/poly1305-20050329.pdf">The Poly1305-AES
//!   Message-Authentication Code (20050329)</A> and Andy Polyakov <A
//!   HREF="http://www.openssl.org/blog/blog/2016/02/15/poly1305-revised/">Poly1305 Revised</A>
//! \since Crypto++ 5.7

#ifndef CRYPTOPP_POLY1305_H
#define CRYPTOPP_POLY1305_H

#include "cryptlib.h"
#include "seckey.h"
#include "secblock.h"
#include "argnames.h"
#include "algparam.h"


#include "files.h"
#include "filters.h"
#include "hex.h"
#include <iostream>

NAMESPACE_BEGIN(CryptoPP)

//! \class Poly1305_Base
//! \brief Poly1305 message authentication code base class
//! \tparam T class derived from BlockCipherDocumentation with 16-byte key and 16-byte blocksize
//! \since Crypto++ 5.7
template <class T>
class CRYPTOPP_NO_VTABLE Poly1305_Base : public FixedKeyLength<32, SimpleKeyingInterface::UNIQUE_IV, 16>, public MessageAuthenticationCode
{
	CRYPTOPP_COMPILE_ASSERT(T::DEFAULT_KEYLENGTH == 16);
	CRYPTOPP_COMPILE_ASSERT(T::BLOCKSIZE == 16);

public:
	static std::string StaticAlgorithmName() {return std::string("Poly1305(") + T::StaticAlgorithmName() + ")";}

	CRYPTOPP_CONSTANT(DIGESTSIZE=T::BLOCKSIZE)
	CRYPTOPP_CONSTANT(BLOCKSIZE=T::BLOCKSIZE)

	Poly1305_Base() : m_used(true) {}

	void Resynchronize (const byte *iv, int ivLength=-1);
	void GetNextIV (RandomNumberGenerator &rng, byte *iv);

	void UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params);
	void Update(const byte *input, size_t length);
	void TruncatedFinal(byte *mac, size_t size);
	void Restart();

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return DIGESTSIZE;}

protected:
	void ProcessBlocks(const byte *input, size_t length, word32 padbit);
	void ProcessFinal(byte *mac, size_t length);

	CPP_TYPENAME T::Encryption m_cipher;

	// Accumulated hash, clamped r-key, and encrypted nonce
	FixedSizeAlignedSecBlock<word32, 5> m_h;
	FixedSizeAlignedSecBlock<word32, 4> m_r;
	FixedSizeAlignedSecBlock<word32, 4> m_n;

	// Accumulated message bytes and index
	FixedSizeAlignedSecBlock<byte, BLOCKSIZE> m_acc;
	size_t m_idx;

	// Track nonce reuse; assert in debug but continue
	bool m_used;
};

//! \class Poly1305
//! \brief Poly1305 message authentication code
//! \tparam T class derived from BlockCipherDocumentation
//! \sa Daniel J. Bernstein <A HREF="http://cr.yp.to/mac/poly1305-20050329.pdf">The Poly1305-AES
//!   Message-Authentication Code (20050329)</A> and Andy Polyakov <A
//!   HREF="http://www.openssl.org/blog/blog/2016/02/15/poly1305-revised/">Poly1305 Revised</A>
//! \since Crypto++ 5.7
template <class T>
class Poly1305 : public MessageAuthenticationCodeFinal<Poly1305_Base<T> >
{
public:
	CRYPTOPP_CONSTANT(DEFAULT_KEYLENGTH=Poly1305_Base<T>::DEFAULT_KEYLENGTH);

	//! \brief Construct a Poly1305
	Poly1305() {}

	//! \brief Construct a Poly1305
	//! \param key a byte array used to key the cipher
	//! \param length the size of the byte array, in bytes
	Poly1305(const byte *key, size_t keyLength=DEFAULT_KEYLENGTH, const byte *nonce=NULL, size_t nonceLength=0)
		{this->SetKey(key, keyLength, MakeParameters(Name::IV(), ConstByteArrayParameter(nonce, nonceLength)));}
};

NAMESPACE_END

#endif  // CRYPTOPP_POLY1305_H
