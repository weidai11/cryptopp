#ifndef CRYPTOPP_CAMELLIA_H
#define CRYPTOPP_CAMELLIA_H

#include "config.h"

#ifdef WORD64_AVAILABLE

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
struct Camellia_Info : public FixedBlockSize<16>, public VariableKeyLength<16, 16, 32, 8>
{
	static const char *StaticAlgorithmName() {return "Camellia";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#Camellia">Camellia</a>
class Camellia : public Camellia_Info, public BlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<Camellia_Info>
	{
	public:
		void UncheckedSetKey(CipherDir dir, const byte *key, unsigned int keylen);
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

	protected:
		static word64 F(word64 X);
		static void FLlayer(word64 *x, word64 K1, word64 K2);

		static const byte s1[256];
		static const byte s2[256];
		static const byte s3[256];
		static const byte s4[256];

		unsigned int m_rounds;
		SecBlock<word64> m_key;
	};

public:
	typedef BlockCipherFinal<ENCRYPTION, Base> Encryption;
	typedef BlockCipherFinal<DECRYPTION, Base> Decryption;
};

typedef Camellia::Encryption CamelliaEncryption;
typedef Camellia::Decryption CamelliaDecryption;

NAMESPACE_END

#endif

#endif
