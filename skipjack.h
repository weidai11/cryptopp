#ifndef CRYPTOPP_SKIPJACK_H
#define CRYPTOPP_SKIPJACK_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

struct SKIPJACK_Info : public FixedBlockSize<8>, public FixedKeyLength<10>
{
	static const char *StaticAlgorithmName() {return "SKIPJACK";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#SKIPJACK">SKIPJACK</a>
class SKIPJACK : public SKIPJACK_Info, public BlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public BlockCipherBaseTemplate<SKIPJACK_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length);

	protected:
		static const byte fTable[256];

		FixedSizeSecBlock<byte[256], 10> tab;
	};

	class CRYPTOPP_NO_VTABLE Enc : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	private:
		static const byte Se[256];
		static const word32 Te[4][256];
	};

	class CRYPTOPP_NO_VTABLE Dec : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	private:
		static const byte Sd[256];
		static const word32 Td[4][256];
	};

public:
	typedef BlockCipherTemplate<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherTemplate<DECRYPTION, Dec> Decryption;
};

typedef SKIPJACK::Encryption SKIPJACKEncryption;
typedef SKIPJACK::Decryption SKIPJACKDecryption;

NAMESPACE_END

#endif
