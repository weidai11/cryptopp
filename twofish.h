#ifndef CRYPTOPP_TWOFISH_H
#define CRYPTOPP_TWOFISH_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

struct Twofish_Info : public FixedBlockSize<16>, public VariableKeyLength<16, 0, 32>, FixedRounds<16>
{
	static const char *StaticAlgorithmName() {return "Twofish";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#Twofish">Twofish</a>
class Twofish : public Twofish_Info, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<Twofish_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length);

	protected:
		static word32 h0(word32 x, const word32 *key, unsigned int kLen);
		static word32 h(word32 x, const word32 *key, unsigned int kLen);

		static const byte q[2][256];
		static const word32 mds[4][256];

		FixedSizeSecBlock<word32, 40> m_k;
		FixedSizeSecBlock<word32[256], 4> m_s;
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

typedef Twofish::Encryption TwofishEncryption;
typedef Twofish::Decryption TwofishDecryption;

NAMESPACE_END

#endif
