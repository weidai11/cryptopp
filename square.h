#ifndef CRYPTOPP_SQUARE_H
#define CRYPTOPP_SQUARE_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

struct Square_Info : public FixedBlockSize<16>, public FixedKeyLength<16>, FixedRounds<8>
{
	static const char *StaticAlgorithmName() {return "Square";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#Square">Square</a>
class Square : public Square_Info, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<Square_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length);

	protected:
		FixedSizeSecBlock<word32[4], ROUNDS+1> roundkeys;
	};

	class Enc : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	private:
		static const byte Se[256];
		static const word32 Te[4][256];
	};

	class Dec : public Base
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

typedef Square::Encryption SquareEncryption;
typedef Square::Decryption SquareDecryption;

NAMESPACE_END

#endif
