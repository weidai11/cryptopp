#ifndef CRYPTOPP_THREEWAY_H
#define CRYPTOPP_THREEWAY_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

struct ThreeWay_Info : public FixedBlockSize<12>, public FixedKeyLength<12>, public VariableRounds<11>
{
	static const char *StaticAlgorithmName() {return "3-Way";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#3-Way">3-Way</a>
class ThreeWay : public ThreeWay_Info, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<ThreeWay_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *key, unsigned int length, unsigned int rounds);

	protected:
		unsigned int m_rounds;
		FixedSizeSecBlock<word32, 3> m_k;
	};

	class Enc : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	};

	class Dec : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	};

public:
	typedef BlockCipherTemplate<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherTemplate<DECRYPTION, Dec> Decryption;
};

typedef ThreeWay::Encryption ThreeWayEncryption;
typedef ThreeWay::Decryption ThreeWayDecryption;

NAMESPACE_END

#endif
