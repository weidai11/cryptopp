// randpool.h - originally written and placed in the public domain by Wei Dai
//              OldRandPool added by JW in August, 2017.

//! \file randpool.h
//! \brief Class file for Randomness Pool
//! \details RandomPool can be used to generate cryptographic quality pseudorandom bytes
//!   after seeding the pool with IncorporateEntropy(). Internally, the generator uses
//!   AES-256 to produce the stream. Entropy is stirred in using SHA-256.
//! \details RandomPool used to follow the design of randpool in PGP 2.6.x. At version 5.5
//!   RandomPool was redesigned to reduce the risk of reusing random numbers after state
//!   rollback (which may occur when running in a virtual machine like VMware or a hosted
//!   environment).
//! \details If you need the pre-Crypto++ 5.5 generator then use OldRandomPool class. You
//!   should migrate away from OldRandomPool at the earliest opportunity. Use RandomPool
//!   or AutoSeededRandomPool instead.
//! \since Crypto++ 4.0 (PGP 2.6.x style), Crypto++ 5.5 (AES-256 based)

#ifndef CRYPTOPP_RANDPOOL_H
#define CRYPTOPP_RANDPOOL_H

#include "cryptlib.h"
#include "filters.h"
#include "secblock.h"
#include "smartptr.h"
#include "aes.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class RandomPool
//! \brief Randomness Pool based on AES-256
//! \details RandomPool can be used to generate cryptographic quality pseudorandom bytes
//!   after seeding the pool with IncorporateEntropy(). Internally, the generator uses
//!   AES-256 to produce the stream. Entropy is stirred in using SHA-256.
//! \details RandomPool used to follow the design of randpool in PGP 2.6.x. At version 5.5
//!   RandomPool was redesigned to reduce the risk of reusing random numbers after state
//!   rollback (which may occur when running in a virtual machine like VMware or a hosted
//!   environment).
//! \details If you need the pre-Crypto++ 5.5 generator then use OldRandomPool class. You
//!   should migrate away from OldRandomPool at the earliest opportunity. Use RandomPool
//!   or AutoSeededRandomPool instead.
//! \since Crypto++ 4.0 (PGP 2.6.x style), Crypto++ 5.5 (AES-256 based)
class CRYPTOPP_DLL RandomPool : public RandomNumberGenerator, public NotCopyable
{
public:
	//! \brief Construct a RandomPool
	RandomPool();

	bool CanIncorporateEntropy() const {return true;}
	void IncorporateEntropy(const byte *input, size_t length);
	void GenerateIntoBufferedTransformation(BufferedTransformation &target, const std::string &channel, lword size);

	// for backwards compatibility. use RandomNumberSource, RandomNumberStore, and
	//   RandomNumberSink for other BufferTransformation functionality
	void Put(const byte *input, size_t length) {IncorporateEntropy(input, length);}

private:
	FixedSizeAlignedSecBlock<byte, 16, true> m_seed;
	FixedSizeAlignedSecBlock<byte, 32> m_key;
	member_ptr<BlockCipher> m_pCipher;
	bool m_keySet;
};

//! \class OldRandomPool
//! \brief Randomness Pool based on PGP 2.6.x with MDC
//! \details If you need the pre-Crypto++ 5.5 generator then use OldRandomPool class. The
//!   OldRandomPool class is always available so you dont need to define
//!   CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY. However, you should migrate away from
//!   OldRandomPool at the earliest opportunity. Use RandomPool or AutoSeededRandomPool instead.
//! \deprecated This class uses an old style PGP 2.6.x with MDC. The generator risks reusing
//!   random random numbers after state rollback. Migrate to RandomPool or AutoSeededRandomPool
//!   at the earliest opportunity.
//! \since Crypto++ 6.0 (PGP 2.6.x style)
class CRYPTOPP_DLL OldRandomPool : public RandomNumberGenerator,
                                   public Bufferless<BufferedTransformation>
{
public:
	//! \brief Construct an OldRandomPool
	//! \param poolSize internal pool size of the generator
	//! \details poolSize must be greater than 16
	OldRandomPool(unsigned int poolSize=384);

	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking);

	bool AnyRetrievable() const {return true;}
	lword MaxRetrievable() const {return ULONG_MAX;}

	size_t TransferTo2(BufferedTransformation &target, lword &transferBytes, const std::string &channel=DEFAULT_CHANNEL, bool blocking=true);
	size_t CopyRangeTo2(BufferedTransformation &target, lword &begin, lword end=LWORD_MAX, const std::string &channel=DEFAULT_CHANNEL, bool blocking=true) const
	{
		CRYPTOPP_UNUSED(target); CRYPTOPP_UNUSED(begin); CRYPTOPP_UNUSED(end);
		CRYPTOPP_UNUSED(channel); CRYPTOPP_UNUSED(blocking);
		throw NotImplemented("OldRandomPool: CopyRangeTo2() is not supported by this store");
	}

	byte GenerateByte();
	void GenerateBlock(byte *output, size_t size);

	void IsolatedInitialize(const NameValuePairs &parameters) {CRYPTOPP_UNUSED(parameters);}

protected:
	void Stir();

private:
	SecByteBlock pool, key;
	size_t addPos, getPos;
};

NAMESPACE_END

#endif
