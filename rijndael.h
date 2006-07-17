#ifndef CRYPTOPP_RIJNDAEL_H
#define CRYPTOPP_RIJNDAEL_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
struct Rijndael_Info : public FixedBlockSize<16>, public VariableKeyLength<16, 16, 32, 8>
{
	CRYPTOPP_DLL static const char * CRYPTOPP_API StaticAlgorithmName() {return CRYPTOPP_RIJNDAEL_NAME;}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#Rijndael">Rijndael</a>
class CRYPTOPP_DLL Rijndael : public Rijndael_Info, public BlockCipherDocumentation
{
	class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<Rijndael_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length);

	protected:
		// VS2005 workaround: have to put these on seperate lines, or error C2487 is triggered in DLL build
		CRYPTOPP_L1_CACHE_ALIGN(static const byte Se[256]);
		CRYPTOPP_L1_CACHE_ALIGN(static const byte Sd[256]);
		CRYPTOPP_L1_CACHE_ALIGN(static const word32 Te0[256]);
		static const word32 Te1[256];
		static const word32 Te2[256];
		static const word32 Te3[256];
		CRYPTOPP_L1_CACHE_ALIGN(static const word32 Td0[256]);
		static const word32 Td1[256];
		static const word32 Td2[256];
		static const word32 Td3[256];

		static const word32 rcon[];

		unsigned int m_rounds;
		SecBlock<word32> m_key;
	};

	class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE Enc : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	};

	class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE Dec : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	};

public:
	typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

typedef Rijndael::Encryption RijndaelEncryption;
typedef Rijndael::Decryption RijndaelDecryption;

NAMESPACE_END

#endif
