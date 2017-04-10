// aria.h - written and placed in the public domain by Jeffrey Walton

//! \file aria.h
//! \brief Classes for the ARIA block cipher
//! \sa <A HREF="http://tools.ietf.org/html/rfc5794">RFC 5794, A Description of the ARIA Encryption Algorithm</A>,
//!   <A HREF="http://seed.kisa.or.kr/iwt/ko/bbs/EgovReferenceList.do?bbsId=BBSMSTR_000000000002">Korea
//!   Internet & Security Agency homepage</A>

#ifndef CRYPTOPP_ARIA_H
#define CRYPTOPP_ARIA_H

#include "config.h"
#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class ARIA_Info
//! \brief ARIA block cipher information
struct ARIA_Info : public FixedBlockSize<16>, public VariableKeyLength<16, 16, 32, 8>
{
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "ARIA";}
};

//! \class ARIA
//! \brief ARIA block cipher
//! \sa <a href="http://www.weidai.com/scan-mirror/cs.html#ARIA">ARIA</a>
class ARIA : public ARIA_Info, public BlockCipherDocumentation
{
public:
	class CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<ARIA_Info>
	{
	public:
		void UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &params);
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

	protected:
		CRYPTOPP_ALIGN_DATA(16)
		static const byte S[4][256];

		CRYPTOPP_ALIGN_DATA(16)
		static const byte KRK[3][16];

		FixedSizeAlignedSecBlock<byte, 16*17> m_rkey;  // round keys
		FixedSizeAlignedSecBlock<byte, 16*6>  m_w;     // scratch, w0, w1, w2, w3 and t
		unsigned int m_rounds;
	};

public:
	typedef BlockCipherFinal<ENCRYPTION, Base> Encryption;
	typedef BlockCipherFinal<DECRYPTION, Base> Decryption;
};

typedef ARIA::Encryption ARIAEncryption;
typedef ARIA::Decryption ARIADecryption;

NAMESPACE_END

#endif
