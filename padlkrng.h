// via-rng.h - written and placed in public domain by Jeffrey Walton

//! \file PadlockRNG.h
//! \brief Class for VIA Padlock RNG
//! \since Crypto++ 6.0

#ifndef CRYPTOPP_PADLOCK_RNG_H
#define CRYPTOPP_PADLOCK_RNG_H

#include "cryptlib.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! \brief Exception thrown when a PadlockRNG generator encounters
//!    a generator related error.
//! \since Crypto++ 6.0
class PadlockRNG_Err : public Exception
{
public:
    PadlockRNG_Err(const std::string &operation)
        : Exception(OTHER_ERROR, "PadlockRNG: " + operation + " operation failed") {}
};

//! \brief Hardware generated random numbers using PadlockRNG instruction
//! \sa MaurerRandomnessTest() for random bit generators
//! \since Crypto++ 6.0
class PadlockRNG : public RandomNumberGenerator
{
public:
    CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() { return "PadlockRNG"; }

    virtual ~PadlockRNG() {}

    //! \brief Construct a PadlockRNG generator
    //! \details According to DJ of Intel, the Intel PadlockRNG circuit does not underflow.
    //!   If it did hypothetically underflow, then it would return 0 for the random value.
    //!   AMD's PadlockRNG implementation appears to provide the same behavior.
     //! \throws PadlockRNG_Err if the random number generator is not available
    PadlockRNG();

    //! \brief Generate random array of bytes
    //! \param output the byte buffer
    //! \param size the length of the buffer, in bytes
    virtual void GenerateBlock(byte *output, size_t size);

    //! \brief Generate and discard n bytes
    //! \param n the number of bytes to generate and discard
    //! \details the RDSEED generator discards words, not bytes. If n is
    //!   not a multiple of a machine word, then it is rounded up to
    //!   that size.
    virtual void DiscardBytes(size_t n);

    //! \brief Update RNG state with additional unpredictable values
    //! \param input unused
    //! \param length unused
    //! \details The operation is a nop for this generator.
    virtual void IncorporateEntropy(const byte *input, size_t length)
    {
        // Override to avoid the base class' throw.
        CRYPTOPP_UNUSED(input); CRYPTOPP_UNUSED(length);
    }

private:
	FixedSizeAlignedSecBlock<word32, 1, true> m_buffer;
};

NAMESPACE_END

#endif  // CRYPTOPP_PADLOCK_RNG_H
