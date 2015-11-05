// rdrand.h - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
//            Copyright assigned to Crypto++ project.

#ifndef CRYPTOPP_RDRAND_H
#define CRYPTOPP_RDRAND_H

#include "cryptlib.h"

// Microsoft added RDRAND in August 2012, VS2012. GCC added RDRAND in December 2010, GCC 4.6.
// Clang added RDRAND in July 2012, Clang 3.2. Intel added RDRAND in September 2011, ICC 12.1.

// Visual Studio 2015 (CL version 1900) is missing _rdseed{16|32|64}_step
#if (CRYPTOPP_MSC_VERSION <= 1900)
# define MSC_RDSEED_INTRINSIC_AVAILABLE 0
#endif

NAMESPACE_BEGIN(CryptoPP)

class RDRAND_Err : public Exception
{
public:
	RDRAND_Err(const std::string &operation)
		: Exception(OTHER_ERROR, "RDRAND: " + operation + " operation failed") {}
};

//! \brief Read hardware generated random numbers.

//! This file (and friends) provides both RDRAND and RDSEED, but its somewhat
//!   experimental. They were added at Crypto++ 5.6.3. At compile time, it
//!   indirectly uses CRYPTOPP_BOOL_{X86|X32|X64} (via CRYPTOPP_CPUID_AVAILABLE)
//!   to select an implementation or "throw NotImplemented". At runtime, the
//!   class uses the result of CPUID to determine if RDRAND or RDSEED are
//!   available. A lazy throw strategy is used in case the CPU does not support
//!   the instruction. I.e., the throw is deferred until GenerateBlock is called.
class RDRAND : public RandomNumberGenerator, public DeviceState
{
public:
	std::string AlgorithmName() const {return "RDRAND";}
	
	//! construct a RDRAND generator with a maximum number of retires for failed generation attempts
	RDRAND(unsigned int retries = 8) : m_retries(retries) {}
	
	virtual ~RDRAND() {}
	
	//! returns true if RDRAND is present or available according to CPUID, false otherwise
	bool Available() const;

	//! returns true if RDRAND is present or available according to CPUID, false otherwise. There is no exended information available.
	bool Available(word64& extendedInfo) const;
	
	//! returns true if RDRAND is online/ready to produce random numbers, false otherwise
	bool Ready() const;

	//! returns true if RDRAND is online/ready to produce random numbers, false otherwise. There is no exended information available.
	bool Ready(word64& extendedInfo) const;
	
	//! returns the number of times GenerateBlock will attempt to recover from a failed generation
	unsigned int GetRetries() const
	{
		return m_retries;
	}
	
	//! sets the number of times GenerateBlock will attempt to recover from a failed generation
	void SetRetries(unsigned int retries)
	{
		m_retries = retries;
	}

	//! generate random array of bytes
	//! \param output the byte buffer
	//! \param size the length of the buffer, in bytes
	virtual void GenerateBlock(byte *output, size_t size);

	//! generate and discard n bytes.
	//! \param n the number of bytes to discard
	virtual void DiscardBytes(size_t n);

	//! update RNG state with additional unpredictable values. The operation is a nop for this generator.
	//! \param input unused
	//! \param length unused
	virtual void IncorporateEntropy(const byte *input, size_t length)
	{
		// Override to avoid the base class' throw.
		CRYPTOPP_UNUSED(input); CRYPTOPP_UNUSED(length);
		assert(0); // warn in debug builds
	}

private:
	unsigned int m_retries;
};

class RDSEED_Err : public Exception
{
public:
	RDSEED_Err(const std::string &operation)
		: Exception(OTHER_ERROR, "RDSEED: " + operation + " operation failed") {}
};

//! \brief Read hardware generated random numbers.

//! This file (and friends) provides both RDRAND and RDSEED, but its somewhat
//!   experimental. They were added at Crypto++ 5.6.3. At compile time, it
//!   indirectly uses CRYPTOPP_BOOL_{X86|X32|X64} (via CRYPTOPP_CPUID_AVAILABLE)
//!   to select an implementation or "throw NotImplemented". At runtime, the
//!   class uses the result of CPUID to determine if RDRAND or RDSEED are
//!   available. A lazy throw strategy is used in case the CPU does not support
//!   the instruction. I.e., the throw is deferred until GenerateBlock is called.
class RDSEED : public RandomNumberGenerator, public DeviceState
{
public:
	std::string AlgorithmName() const {return "RDSEED";}
	
	//! construct a RDSEED generator with a maximum number of retires for failed generation attempts
	RDSEED(unsigned int retries = 8) : m_retries(retries) {}
	
	virtual ~RDSEED() {}
	
	//! returns true if RDSEED is present or available according to CPUID, false otherwise
	bool Available() const;

	//! returns true if RDSEED is present or available according to CPUID, false otherwise. There is no exended information available.
	bool Available(word64& extendedInfo) const;
	
	//! returns true if RDSEED is online/ready to produce random numbers, false otherwise
	bool Ready() const;

	//! returns true if RDSEED is online/ready to produce random numbers, false otherwise. There is no exended information available.
	bool Ready(word64& extendedInfo) const;
	
	//! returns the number of times GenerateBlock will attempt to recover from a failed generation
	unsigned int GetRetries() const
	{
		return m_retries;
	}
	
	//! sets the number of times GenerateBlock will attempt to recover from a failed generation
	void SetRetries(unsigned int retries)
	{
		m_retries = retries;
	}

	//! generate random array of bytes
	//! \param output the byte buffer
	//! \param size the length of the buffer, in bytes
	virtual void GenerateBlock(byte *output, size_t size);

	//! generate and discard n bytes.
	//! \param n the number of bytes to discard
	virtual void DiscardBytes(size_t n);

	//! update RNG state with additional unpredictable values. The operation is a nop for this generator.
	//! \param input unused
	//! \param length unused
	virtual void IncorporateEntropy(const byte *input, size_t length)
	{
		// Override to avoid the base class' throw.
		CRYPTOPP_UNUSED(input); CRYPTOPP_UNUSED(length);
		assert(0); // warn in debug builds
	}

private:
	unsigned int m_retries;
};

NAMESPACE_END

#endif // CRYPTOPP_RDRAND_H
