#ifndef CRYPTOPP_DES_H
#define CRYPTOPP_DES_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

struct DES_Info : public FixedBlockSize<8>, public FixedKeyLength<8>
{
	static const char *StaticAlgorithmName() {return "DES";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#DES">DES</a>
/*! The DES implementation in Crypto++ ignores the parity bits
	(the least significant bits of each byte) in the key. However
	you can use CheckKeyParityBits() and CorrectKeyParityBits() to
	check or correct the parity bits if you wish. */
class DES : public DES_Info, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<DES_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length = 8);
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

		// exposed for faster Triple-DES
		void RawProcessBlock(word32 &l, word32 &r) const;

	protected:
		static const word32 Spbox[8][64];

		FixedSizeSecBlock<word32, 32> k;
	};

public:
	//! check DES key parity bits
	static bool CheckKeyParityBits(const byte *key);
	//! correct DES key parity bits
	static void CorrectKeyParityBits(byte *key);

	typedef BlockCipherTemplate<ENCRYPTION, Base> Encryption;
	typedef BlockCipherTemplate<DECRYPTION, Base> Decryption;
};

struct DES_EDE2_Info : public FixedBlockSize<8>, public FixedKeyLength<16>
{
	static const char *StaticAlgorithmName() {return "DES-EDE2";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#DESede">DES-EDE2</a>
class DES_EDE2 : public DES_EDE2_Info, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<DES_EDE2_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length);
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

	protected:
		DES::Encryption m_des1, m_des2;
	};

public:
	typedef BlockCipherTemplate<ENCRYPTION, Base> Encryption;
	typedef BlockCipherTemplate<DECRYPTION, Base> Decryption;
};

struct DES_EDE3_Info : public FixedBlockSize<8>, public FixedKeyLength<24>
{
	static const char *StaticAlgorithmName() {return "DES-EDE3";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#DESede">DES-EDE3</a>
class DES_EDE3 : public DES_EDE3_Info, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<DES_EDE3_Info>
	{
	public:
		void UncheckedSetKey(CipherDir dir, const byte *key, unsigned int length);
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

	protected:
		DES::Encryption m_des1, m_des2, m_des3;
	};

public:
	typedef BlockCipherTemplate<ENCRYPTION, Base> Encryption;
	typedef BlockCipherTemplate<DECRYPTION, Base> Decryption;
};

struct DES_XEX3_Info : public FixedBlockSize<8>, public FixedKeyLength<24>
{
	static const char *StaticAlgorithmName() {return "DES-XEX3";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#DESX">DES-XEX3</a>, AKA DESX
class DES_XEX3 : public DES_XEX3_Info, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<DES_XEX3_Info>
	{
	public:
		void UncheckedSetKey(CipherDir dir, const byte *key, unsigned int length);
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

	protected:
		FixedSizeSecBlock<byte, BLOCKSIZE> m_x1, m_x3;
		DES::Encryption m_des;
	};

public:
	typedef BlockCipherTemplate<ENCRYPTION, Base> Encryption;
	typedef BlockCipherTemplate<DECRYPTION, Base> Decryption;
};

typedef DES::Encryption DESEncryption;
typedef DES::Decryption DESDecryption;

typedef DES_EDE2::Encryption DES_EDE2_Encryption;
typedef DES_EDE2::Decryption DES_EDE2_Decryption;

typedef DES_EDE3::Encryption DES_EDE3_Encryption;
typedef DES_EDE3::Decryption DES_EDE3_Decryption;

typedef DES_XEX3::Encryption DES_XEX3_Encryption;
typedef DES_XEX3::Decryption DES_XEX3_Decryption;

NAMESPACE_END

#endif
