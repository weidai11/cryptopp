#ifndef CRYPTOPP_RC2_H
#define CRYPTOPP_RC2_H

/** \file
*/

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
struct RC2_Info : public FixedBlockSize<8>, public VariableKeyLength<16, 1, 128>
{
	enum {DEFAULT_EFFECTIVE_KEYLENGTH = 1024, MAX_EFFECTIVE_KEYLENGTH = 1024};
	static const char *StaticAlgorithmName() {return "RC2";}
};

/// <a href="http://www.weidai.com/scan-mirror/cs.html#RC2">RC2</a>
class RC2 : public RC2_Info, public BlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<RC2_Info>
	{
	public:
		void UncheckedSetKey(CipherDir direction, const byte *key, unsigned int length, unsigned int effectiveKeyLength);
		void SetKeyWithEffectiveKeyLength(const byte *key, unsigned int length, unsigned int effectiveKeyLength);

	protected:
		template <class T>
		static inline void CheckedSetKey(T *obj, CipherDir dir, const byte *key, unsigned int length, const NameValuePairs &param)
		{
			obj->ThrowIfInvalidKeyLength(length);
			int effectiveKeyLength = param.GetIntValueWithDefault("EffectiveKeyLength", DEFAULT_EFFECTIVE_KEYLENGTH);
			obj->SetKeyWithEffectiveKeyLength(key, length, effectiveKeyLength);
		}

		FixedSizeSecBlock<word16, 64> K;  // expanded key table
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
	class Encryption : public BlockCipherFinal<ENCRYPTION, Enc>
	{
	public:
		Encryption() {}
		Encryption(const byte *key, unsigned int keyLen=DEFAULT_KEYLENGTH, unsigned int effectiveLen=1024)
			{SetKeyWithEffectiveKeyLength(key, keyLen, effectiveLen);}
	};

	class Decryption : public BlockCipherFinal<DECRYPTION, Dec>
	{
	public:
		Decryption() {}
		Decryption(const byte *key, unsigned int keyLen=DEFAULT_KEYLENGTH, unsigned int effectiveLen=1024)
			{SetKeyWithEffectiveKeyLength(key, keyLen, effectiveLen);}
	};
};

typedef RC2::Encryption RC2Encryption;
typedef RC2::Decryption RC2Decryption;

NAMESPACE_END

#endif
