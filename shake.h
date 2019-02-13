// shake.h - originally written and placed in the public domain by Jeffrey Walton

/// \file shake.h
/// \brief Classes for SHAKE message digests
/// \sa SHA3, SHAKE128, SHAKE256,
///   <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS 202,
///   SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions</a>
/// \since Crypto++ 8.1

#ifndef CRYPTOPP_SHAKE_H
#define CRYPTOPP_SHAKE_H

#include "cryptlib.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief SHAKE message digest base class
/// \details SHAKE is the base class for SHAKE128 and SHAKE258.
///   Library users should instantiate a derived class, and only use SHAKE
///   as a base class reference or pointer.
/// \sa SHA3, SHAKE128, SHAKE256,
///   <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS 202,
///   SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions</a>
/// \since Crypto++ 8.1
class SHAKE : public HashTransformation
{
protected:
    /// \brief Construct a SHAKE
    /// \param digestSize the digest size, in bytes
    /// \details SHAKE is the base class for SHAKE128 and SHAKE256.
    ///   Library users should instantiate a derived class, and only use SHAKE
    ///   as a base class reference or pointer.
    /// \since Crypto++ 8.1
    SHAKE(unsigned int digestSize) : m_digestSize(digestSize) {Restart();}

public:
    unsigned int DigestSize() const {return m_digestSize;}
    unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}

    void Update(const byte *input, size_t length);
    void Restart();
    void TruncatedFinal(byte *hash, size_t size);

protected:
    inline unsigned int r() const {return BlockSize();}

    FixedSizeSecBlock<word64, 25> m_state;
    unsigned int m_digestSize, m_counter;
};

/// \brief SHAKE message digest template
/// \tparam T_Strength the strength of the digest
/// \since Crypto++ 8.1
template<unsigned int T_Strength>
class SHAKE_Final : public SHAKE
{
public:
    CRYPTOPP_CONSTANT(DIGESTSIZE = (T_Strength == 128 ? 32 : 64))
    CRYPTOPP_CONSTANT(BLOCKSIZE = (T_Strength == 128 ? 1344/8 : 1088/8))
    static std::string StaticAlgorithmName()
        { return "SHAKE-" + IntToString(T_Strength); }

    /// \brief Construct a SHAKE-X message digest
    SHAKE_Final() : SHAKE(DIGESTSIZE) {}

    /// \brief Provides the block size of the compression function
    /// \return block size of the compression function, in bytes
    /// \details BlockSize() will return 0 if the hash is not block based
    ///   or does not have an equivalent block size. For example, Keccak
    ///   and SHA-3 do not have a block size, but they do have an equivalent
    ///   block size called rate expressed as <tt>r</tt>.
    unsigned int BlockSize() const { return BLOCKSIZE; }

private:
#if !defined(__BORLANDC__)
    // ensure there was no underflow in the math
    CRYPTOPP_COMPILE_ASSERT(BLOCKSIZE < 200);
    // this is a general expectation by HMAC
    CRYPTOPP_COMPILE_ASSERT(BLOCKSIZE > (int)DIGESTSIZE);
#endif
};

/// \brief SHAKE128 message digest
/// \since Crypto++ 8.1
class SHAKE128 : public SHAKE_Final<128> {};

/// \brief SHAKE256 message digest
/// \since Crypto++ 8.1
class SHAKE256 : public SHAKE_Final<256> {};

NAMESPACE_END

#endif
