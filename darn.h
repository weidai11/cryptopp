// darn.h - written and placed in public domain by Jeffrey Walton
//          DARN requires POWER9/ISA 3.0.

// At the moment only GCC 7.0 (and above) seems to support __builtin_darn()
// and __builtin_darn_32(). Clang 7.0 does not provide them. XLC is unknown.
// To cover more platforms we provide GCC inline assembly like we do with
// RDRAND and RDSEED. Platforms that don't support GCC inline assembly or
// the builtin will fail the compile. Also see
// https://gcc.gnu.org/onlinedocs/gcc/Basic-PowerPC-Built-in-Functions-Available-on-ISA-3_002e0.html

/// \file darn.h
/// \brief Classes for DARN RNG
/// \since Crypto++ 8.0

#ifndef CRYPTOPP_DARN_H
#define CRYPTOPP_DARN_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief Exception thrown when a DARN generator encounters
///    a generator related error.
/// \since Crypto++ 8.0
class DARN_Err : public Exception
{
public:
    DARN_Err(const std::string &operation)
        : Exception(OTHER_ERROR, "DARN: " + operation + " operation failed") {}
};

/// \brief Hardware generated random numbers using DARN instruction
/// \sa MaurerRandomnessTest() for random bit generators
/// \since Crypto++ 8.0
class DARN : public RandomNumberGenerator
{
public:
    CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() { return "DARN"; }

    virtual ~DARN() {}

    /// \brief Construct a DARN generator
     /// \throws DARN_Err if the random number generator is not available
    DARN();

    /// \brief Generate random array of bytes
    /// \param output the byte buffer
    /// \param size the length of the buffer, in bytes
    virtual void GenerateBlock(byte *output, size_t size);

    /// \brief Generate and discard n bytes
    /// \param n the number of bytes to generate and discard
    /// \details the RDSEED generator discards words, not bytes. If n is
    ///   not a multiple of a machine word, then it is rounded up to
    ///   that size.
    virtual void DiscardBytes(size_t n);

    /// \brief Update RNG state with additional unpredictable values
    /// \param input unused
    /// \param length unused
    /// \details The operation is a nop for this generator.
    virtual void IncorporateEntropy(const byte *input, size_t length)
    {
        // Override to avoid the base class' throw.
        CRYPTOPP_UNUSED(input); CRYPTOPP_UNUSED(length);
    }

    std::string AlgorithmProvider() const {
        return "Power9";
    }
};

NAMESPACE_END

#endif // CRYPTOPP_DARN_H
