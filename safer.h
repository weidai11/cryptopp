#ifndef CRYPTOPP_SAFER_H
#define CRYPTOPP_SAFER_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// base class, do not use directly
class SAFER
{
public:
	class CRYPTOPP_NO_VTABLE Base : public BlockCipher
	{
	public:
		unsigned int GetAlignment() const {return 1;}
		void UncheckedSetKey(CipherDir dir, const byte *userkey, unsigned int length, unsigned nof_rounds);

		bool strengthened;
		SecByteBlock keySchedule;
		static const byte exp_tab[256];
		static const byte log_tab[256];
	};

	class CRYPTOPP_NO_VTABLE Enc : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	};

	class CRYPTOPP_NO_VTABLE Dec : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	};
};

//! _
struct SAFER_K_Info : public FixedBlockSize<8>, public VariableKeyLength<16, 8, 16, 8>, public VariableRounds<10, 1, 13>
{
	static const char *StaticAlgorithmName() {return "SAFER-K";}
	static unsigned int DefaultRounds(unsigned int keylength) {return keylength == 8 ? 6 : 10;}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#SAFER-K">SAFER-K</a>
class SAFER_K : public SAFER_K_Info, public SAFER, public BlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Enc : public BlockCipherImpl<SAFER_K_Info, SAFER::Enc>
	{
	public:
		Enc() {strengthened = false;}
	};

	class CRYPTOPP_NO_VTABLE Dec : public BlockCipherImpl<SAFER_K_Info, SAFER::Dec>
	{
	public:
		Dec() {strengthened = false;}
	};

public:
	typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

//! _
struct SAFER_SK_Info : public FixedBlockSize<8>, public VariableKeyLength<16, 8, 16, 8>, public VariableRounds<10, 1, 13>
{
	static const char *StaticAlgorithmName() {return "SAFER-SK";}
	static unsigned int DefaultRounds(unsigned int keylength) {return keylength == 8 ? 8 : 10;}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#SAFER-SK">SAFER-SK</a>
class SAFER_SK : public SAFER_SK_Info, public SAFER, public BlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Enc : public BlockCipherImpl<SAFER_SK_Info, SAFER::Enc>
	{
	public:
		Enc() {strengthened = true;}
	};

	class CRYPTOPP_NO_VTABLE Dec : public BlockCipherImpl<SAFER_SK_Info, SAFER::Dec>
	{
	public:
		Dec() {strengthened = true;}
	};

public:
	typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

typedef SAFER_K::Encryption SAFER_K_Encryption;
typedef SAFER_K::Decryption SAFER_K_Decryption;

typedef SAFER_SK::Encryption SAFER_SK_Encryption;
typedef SAFER_SK::Decryption SAFER_SK_Decryption;

NAMESPACE_END

#endif
