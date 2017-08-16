// shacal.h - originally written and placed in the public domain by Wei Dai

//! \file shacal2.h
//! \brief Classes for the SHACAL-2 block cipher
//! \since Crypto++ 5.2, Intel SHA since Crypto++ 6.0

#ifndef CRYPTOPP_SHACAL2_H
#define CRYPTOPP_SHACAL2_H

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class SHACAL2_Info
//! \brief SHACAL2 block cipher information
struct SHACAL2_Info : public FixedBlockSize<32>, public VariableKeyLength<16, 16, 64>
{
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "SHACAL-2";}
};

//! \class SHACAL2
//! \brief SHACAL2 block cipher
//! \since Crypto++ 5.2, Intel SHA since Crypto++ 6.0
//! \sa <a href="http://www.weidai.com/scan-mirror/cs.html#SHACAL-2">SHACAL-2</a>
class SHACAL2 : public SHACAL2_Info, public BlockCipherDocumentation
{
	//! \brief SHACAL2 block cipher data processing functions
	//! \details Provides implementation common to encryption and decryption
	class CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<SHACAL2_Info>
	{
	public:
		void UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs &params);

	protected:
		FixedSizeAlignedSecBlock<word32, 64> m_key;

		static const word32 K[64];
	};

	//! \brief SHACAL2 block cipher data processing functions
	//! \details Provides implementation for encryption transformation
	class CRYPTOPP_NO_VTABLE Enc : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	};

	//! \brief SHACAL2 block cipher data processing functions
	//! \details Provides implementation for decryption transformation
	class CRYPTOPP_NO_VTABLE Dec : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	};

public:
	typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

typedef SHACAL2::Encryption SHACAL2Encryption;
typedef SHACAL2::Decryption SHACAL2Decryption;

NAMESPACE_END

#endif
