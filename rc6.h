#ifndef CRYPTOPP_RC6_H
#define CRYPTOPP_RC6_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

struct RC6_Info : public FixedBlockSize<16>, public VariableKeyLength<16, 0, 255>, public VariableRounds<20>
{
	static const char *StaticAlgorithmName() {return "RC6";}
	typedef word32 RC6_WORD;
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#RC6">RC6</a>
class RC6 : public RC6_Info, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<RC6_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length, unsigned int rounds);

	protected:
		unsigned int r;       // number of rounds
		SecBlock<RC6_WORD> sTable;  // expanded key table
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

typedef RC6::Encryption RC6Encryption;
typedef RC6::Decryption RC6Decryption;

NAMESPACE_END

#endif
