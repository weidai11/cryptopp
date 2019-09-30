// blowfish.h - originally written and placed in the public domain by Wei Dai

/// \file blowfish.h
/// \brief Classes for the Blowfish block cipher

#ifndef CRYPTOPP_BLOWFISH_H
#define CRYPTOPP_BLOWFISH_H

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief Class specific implementation and overrides used to operate the cipher.
/// \details Implementations and overrides in \p Base apply to both \p ENCRYPTION and \p DECRYPTION directions
template<class Info, class ByteOrder>
class CRYPTOPP_NO_VTABLE Blowfish_Base : public BlockCipherImpl<Info>
{
public:
	void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
	void UncheckedSetKey(const byte *key_string, unsigned int keylength, const NameValuePairs &params);

private:
	void crypt_block(const word32 in[2], word32 out[2]) const;

	static const word32 p_init[Info::ROUNDS+2];
	static const word32 s_init[4*256];

	FixedSizeSecBlock<word32, Info::ROUNDS+2> pbox;
	FixedSizeSecBlock<word32, 4*256> sbox;
};

/// \brief Blowfish block cipher information
struct Blowfish_Info : public FixedBlockSize<8>, public VariableKeyLength<16, 4, 56>, public FixedRounds<16>
{
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "Blowfish";}
};

// <a href="http://www.cryptopp.com/wiki/Blowfish">Blowfish</a>

/// \brief Blowfish block cipher
/// \since Crypto++ 1.0
struct Blowfish : public Blowfish_Info, public BlockCipherDocumentation
{
	typedef BlockCipherFinal<ENCRYPTION, Blowfish_Base<Blowfish_Info, BigEndian> > Encryption;
	typedef BlockCipherFinal<DECRYPTION, Blowfish_Base<Blowfish_Info, BigEndian> > Decryption;
};

typedef Blowfish::Encryption BlowfishEncryption;
typedef Blowfish::Decryption BlowfishDecryption;

/// \brief BlowfishCompat block cipher information
struct BlowfishCompat_Info : public FixedBlockSize<8>, public VariableKeyLength<16, 4, 56>, public FixedRounds<16>
{
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "BlowfishCompat";}
};

/// \brief BlowfishCompat block cipher
struct BlowfishCompat : public BlowfishCompat_Info, public BlockCipherDocumentation
{
	typedef BlockCipherFinal<ENCRYPTION, Blowfish_Base<BlowfishCompat_Info, LittleEndian> > Encryption;
	typedef BlockCipherFinal<DECRYPTION, Blowfish_Base<BlowfishCompat_Info, LittleEndian> > Decryption;
};

typedef BlowfishCompat::Encryption BlowfishCompatEncryption;
typedef BlowfishCompat::Decryption BlowfishCompatDecryption;

NAMESPACE_END

#endif
