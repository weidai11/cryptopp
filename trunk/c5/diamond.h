#ifndef CRYPTOPP_DIAMOND_H
#define CRYPTOPP_DIAMOND_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

struct Diamond2_Info : public FixedBlockSize<16>, public VariableKeyLength<16, 1, 256>, public VariableRounds<10>
{
	static const char *StaticAlgorithmName() {return "Diamond2";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#Diamond2">Diamond2</a>
class Diamond2 : public Diamond2_Info, public BlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<Diamond2_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length, unsigned int rounds);

	protected:
		enum {ROUNDSIZE=4096};
		inline void substitute(int round, byte *x, const byte *y) const;

		int numrounds;
		SecByteBlock s;         // Substitution boxes

		static inline void permute(byte *);
		static inline void ipermute(byte *);
#ifdef DIAMOND_USE_PERMTABLE
		static const word32 permtable[9][256];
		static const word32 ipermtable[9][256];
#endif
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

public:
	typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

typedef Diamond2::Encryption Diamond2Encryption;
typedef Diamond2::Decryption Diamond2Decryption;

struct Diamond2Lite_Info : public FixedBlockSize<8>, public VariableKeyLength<16, 1, 256>, public VariableRounds<8>
{
	static const char *StaticAlgorithmName() {return "Diamond2Lite";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#Diamond2">Diamond2Lite</a>
class Diamond2Lite : public Diamond2Lite_Info, public BlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<Diamond2Lite_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length, unsigned int rounds);

	protected:
		enum {ROUNDSIZE=2048};
		inline void substitute(int round, byte *x, const byte *y) const;
		int numrounds;
		SecByteBlock s;         // Substitution boxes

		static inline void permute(byte *);
		static inline void ipermute(byte *);
	#ifdef DIAMOND_USE_PERMTABLE
		static const word32 permtable[8][256];
		static const word32 ipermtable[8][256];
	#endif
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

public:
	typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

typedef Diamond2Lite::Encryption Diamond2LiteEncryption;
typedef Diamond2Lite::Decryption Diamond2LiteDecryption;

NAMESPACE_END

#endif
