// sha3.h - originally written and placed in the public domain by Wei Dai

/// \file sha3.h
/// \brief Classes for SHA3 message digests
/// \details The Crypto++ implementation conforms to the FIPS 202 version of SHA3 using F1600 with XOF d=0x06.
///   Previous behavior (XOF d=0x01) is available in Keccak classes.
/// \sa <a href="http://en.wikipedia.org/wiki/SHA-3">SHA-3</a>,
///   <A HREF="http://csrc.nist.gov/groups/ST/hash/sha-3/fips202_standard_2015.html">SHA-3 STANDARD (FIPS 202)</A>.
/// \since Crypto++ 5.6.2

#ifndef CRYPTOPP_SHA3_H
#define CRYPTOPP_SHA3_H

#include "cryptlib.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief SHA3 message digest base class
/// \details The Crypto++ implementation conforms to FIPS 202 version of SHA3 using F1600 with XOF d=0x06.
///   Previous behavior (XOF d=0x01) is available in Keccak classes.
/// \details SHA3 is the base class for SHA3_224, SHA3_256, SHA3_384 and SHA3_512.
///   Library users should instantiate a derived class, and only use SHA3
///   as a base class reference or pointer.
/// \sa Keccak, SHA3_224, SHA3_256, SHA3_384 and SHA3_512.
/// \since Crypto++ 5.6.2
class SHA3 : public HashTransformation
{
public:
	/// \brief Construct a SHA3
	/// \param digestSize the digest size, in bytes
	/// \details SHA3 is the base class for SHA3_224, SHA3_256, SHA3_384 and SHA3_512.
	///   Library users should instantiate a derived class, and only use SHA3
	///   as a base class reference or pointer.
	SHA3(unsigned int digestSize) : m_digestSize(digestSize) {Restart();}
	unsigned int DigestSize() const {return m_digestSize;}
	std::string AlgorithmName() const {return "SHA3-" + IntToString(m_digestSize*8);}
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() { return "SHA3"; }
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *hash, size_t size);

	// unsigned int BlockSize() const { return r(); } // that's the idea behind it
protected:
	inline unsigned int r() const {return 200 - 2 * m_digestSize;}

	FixedSizeSecBlock<word64, 25> m_state;
	unsigned int m_digestSize, m_counter;
};

/// \brief SHA3 message digest template
/// \tparam T_DigestSize the size of the digest, in bytes
/// \since Crypto++ 5.6.2
template<unsigned int T_DigestSize>
class SHA3_Final : public SHA3
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = T_DigestSize)
	CRYPTOPP_CONSTANT(BLOCKSIZE = 200 - 2 * DIGESTSIZE)

	/// \brief Construct a SHA3-X message digest
	SHA3_Final() : SHA3(DIGESTSIZE) {}
	static std::string StaticAlgorithmName() { return "SHA3-" + IntToString(DIGESTSIZE * 8); }
	unsigned int BlockSize() const { return BLOCKSIZE; }
private:
#if !defined(__BORLANDC__)
	CRYPTOPP_COMPILE_ASSERT(BLOCKSIZE < 200); // ensure there was no underflow in the math
	CRYPTOPP_COMPILE_ASSERT(BLOCKSIZE > (int)T_DigestSize); // this is a general expectation by HMAC
#endif
};

/// \brief SHA3-224 message digest
/// \since Crypto++ 5.6.2
// typedef SHA3_Final<28> SHA3_224;
class SHA3_224 : public SHA3_Final<28>
{
};

/// \brief SHA3-256 message digest
/// \since Crypto++ 5.6.2
// typedef SHA3_Final<32> SHA3_256;
class SHA3_256 : public SHA3_Final<32>
{
};

/// \brief SHA3-384 message digest
/// \since Crypto++ 5.6.2
// typedef SHA3_Final<48> SHA3_384;
class SHA3_384 : public SHA3_Final<48>
{
};

/// \brief SHA3-512 message digest
/// \since Crypto++ 5.6.2
// typedef SHA3_Final<64> SHA3_512;
class SHA3_512 : public SHA3_Final<64>
{
};

NAMESPACE_END

#endif
