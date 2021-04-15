// lsh.h - written and placed in the public domain by Jeffrey Walton
//         Based on the specification and source code provided by KISA.
//         Also see https://seed.kisa.or.kr/kisa/Board/22/detailView.do.

/// \file lsh.h
/// \brief Classes for the LSH256 hash function
/// \since Crypto++ 8.6

#ifndef CRYPTOPP_LSH256_H
#define CRYPTOPP_LSH256_H

#include "cryptlib.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief LSH224 and LSH256 hash base class
/// \details LSH256_Base is the base class for LSH 256-bit based hashes
/// \since Crypto++ 8.6
template <unsigned int T_AlgType, unsigned int T_DigestSize, unsigned int T_BlockSize>
class LSH256_Base : public HashTransformation
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = T_DigestSize);
	CRYPTOPP_CONSTANT(BLOCKSIZE = T_BlockSize);

	virtual ~LSH256_Base() {}

	unsigned int BlockSize() const { return BLOCKSIZE; }
	unsigned int DigestSize() const {return DIGESTSIZE;}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word32>();}

	void Restart();
	void Update(const byte *input, size_t length);
	void TruncatedFinal(byte *hash, size_t size);

protected:
	// Working state is:
	//   * cv_l = 8 32-bit words
	//   * cv_r = 8 32-bit words
	//   * submsg_e_l = 8 32-bit words
	//   * submsg_e_r = 8 32-bit words
	//   * submsg_o_l = 8 32-bit words
	//   * submsg_o_r = 8 32-bit words
	//   * last_block = 32 32-bit words (128 bytes)
	FixedSizeSecBlock<word32, 80> m_state;
	word32 m_remainingBitLength;
};

/// \brief LSH-224 hash function
/// \since Crypto++ 8.6
class LSH224 : public LSH256_Base<0x000001C, 28, 64>
{
public:
	typedef LSH256_Base<0x000001C, 28, 64> ThisBase;

	CRYPTOPP_CONSTANT(DIGESTSIZE = ThisBase::DIGESTSIZE);
	CRYPTOPP_CONSTANT(BLOCKSIZE = ThisBase::BLOCKSIZE);

	static std::string StaticAlgorithmName() { return "LSH-224"; }

	/// \brief Construct a LSH-224
	LSH224() {Restart();}

	std::string AlgorithmName() const { return StaticAlgorithmName(); }
};

/// \brief LSH-256 hash function
/// \since Crypto++ 8.6
/// \details LSH_TYPE_224 is the magic value 0x0000020 defined in the lsh.cpp file.
class LSH256 : public LSH256_Base<0x0000020, 32, 64>
{
public:
	typedef LSH256_Base<0x0000020, 32, 64> ThisBase;

	CRYPTOPP_CONSTANT(DIGESTSIZE = ThisBase::DIGESTSIZE);
	CRYPTOPP_CONSTANT(BLOCKSIZE = ThisBase::BLOCKSIZE);

	static std::string StaticAlgorithmName() { return "LSH-256"; }

	/// \brief Construct a LSH-256
	LSH256() { Restart(); }

	std::string AlgorithmName() const { return StaticAlgorithmName(); }
};

NAMESPACE_END

#endif  // CRYPTOPP_LSH256_H
