// mdc.h - originally written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_MDC_H
#define CRYPTOPP_MDC_H

//! \file mdc.h
//! \brief Classes for the MDC message digest

#include "seckey.h"
#include "secblock.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class MDC_Info
//! \tparam B BlockCipher derived class
//! \brief MDC_Info cipher information
template <class B>
struct MDC_Info : public FixedBlockSize<B::DIGESTSIZE>, public FixedKeyLength<B::BLOCKSIZE>
{
	static std::string StaticAlgorithmName() {return std::string("MDC/")+B::StaticAlgorithmName();}
};

//! \brief MDC cipher
//! \tparam T HashTransformation derived class
//! \details MDC() is a construction by Peter Gutmann to turn an iterated hash function into a PRF
//! \sa <a href="http://www.weidai.com/scan-mirror/cs.html#MDC">MDC</a>
template <class H>
class MDC : public MDC_Info<H>
{
	//! \class Enc
	//! \brief MDC cipher encryption operation
	class CRYPTOPP_NO_VTABLE Enc : public BlockCipherImpl<MDC_Info<H> >
	{
		typedef typename H::HashWordType HashWordType;

	public:
		void UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs &params)
		{
			CRYPTOPP_UNUSED(params);
			this->AssertValidKeyLength(length);
			memcpy_s(m_key, m_key.size(), userKey, this->KEYLENGTH);
			m_hash.CorrectEndianess(Key(), Key(), this->KEYLENGTH);
		}

		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
		{
			m_hash.CorrectEndianess(Buffer(), (HashWordType *)inBlock, this->BLOCKSIZE);
			H::Transform(Buffer(), Key());
			if (xorBlock)
			{
				m_hash.CorrectEndianess(Buffer(), Buffer(), this->BLOCKSIZE);
				xorbuf(outBlock, xorBlock, m_buffer, this->BLOCKSIZE);
			}
			else
				m_hash.CorrectEndianess((HashWordType *)outBlock, Buffer(), this->BLOCKSIZE);
		}

		bool IsPermutation() const {return false;}

		unsigned int OptimalDataAlignment() const {return sizeof(HashWordType);}

	private:
		HashWordType *Key() {return (HashWordType *)m_key.data();}
		const HashWordType *Key() const {return (const HashWordType *)m_key.data();}
		HashWordType *Buffer() const {return (HashWordType *)m_buffer.data();}

		// VC60 workaround: bug triggered if using FixedSizeAllocatorWithCleanup
		FixedSizeSecBlock<byte, MDC_Info<H>::KEYLENGTH, AllocatorWithCleanup<byte> > m_key;
		mutable FixedSizeSecBlock<byte, MDC_Info<H>::BLOCKSIZE, AllocatorWithCleanup<byte> > m_buffer;
		mutable H m_hash;
	};

public:
	// use BlockCipher interface
	typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
};

NAMESPACE_END

#endif
