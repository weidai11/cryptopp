// sha3.h - written and placed in the public domain by Wei Dai

//! \file sha3.h
//! \brief Classes for SHA-3 message digests

#ifndef CRYPTOPP_SHA3_H
#define CRYPTOPP_SHA3_H

#include "cryptlib.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class SHA3
//! \brief SHA3 message digest base class
//! \sa <a href="http://en.wikipedia.org/wiki/SHA-3">SHA-3</a>
class SHA3 : public HashTransformation
{
public:
	//! \brief Construct a SHA3
	//! \param digestSize the digest size, in bytes
	//! \details SHA3 is the base class for SHA3_224, SHA3_256, SHA3_384 and SHA3_512.
	//!   Library users should construct a derived class instead, and only use SHA3
	//!   as a base class reference or pointer.
	SHA3(unsigned int digestSize) : m_digestSize(digestSize) {Restart();}
	unsigned int DigestSize() const {return m_digestSize;}
	std::string AlgorithmName() const {return "SHA-3-" + IntToString(m_digestSize*8);}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *hash, size_t size);

protected:
	inline unsigned int r() const {return 200 - 2 * m_digestSize;}

	FixedSizeSecBlock<word64, 25> m_state;
	unsigned int m_digestSize, m_counter;
};

//! \class SHA3_224
//! \brief SHA3-224 message digest
class SHA3_224 : public SHA3
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = 28)
		
	//! \brief Construct a SHA3-224 message digest
	SHA3_224() : SHA3(DIGESTSIZE) {}
	static const char * StaticAlgorithmName() {return "SHA-3-224";}
};

//! \class SHA3_256
//! \brief SHA3-256 message digest
class SHA3_256 : public SHA3
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = 32)
		
	//! \brief Construct a SHA3-256 message digest
	SHA3_256() : SHA3(DIGESTSIZE) {}
	static const char * StaticAlgorithmName() {return "SHA-3-256";}
};

//! \class SHA3_384
//! \brief SHA3-384 message digest
class SHA3_384 : public SHA3
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = 48)
		
	//! \brief Construct a SHA3-384 message digest
	SHA3_384() : SHA3(DIGESTSIZE) {}
	static const char * StaticAlgorithmName() {return "SHA-3-384";}
};

//! \class SHA3_512
//! \brief SHA3-512 message digest
class SHA3_512 : public SHA3
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = 64)
		
	//! \brief Construct a SHA3-512 message digest
	SHA3_512() : SHA3(DIGESTSIZE) {}
	static const char * StaticAlgorithmName() {return "SHA-3-512";}
};

NAMESPACE_END

#endif
