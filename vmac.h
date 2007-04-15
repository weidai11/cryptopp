#ifndef CRYPTOPP_VMAC_H
#define CRYPTOPP_VMAC_H

#include "iterhash.h"
#include "seckey.h"

NAMESPACE_BEGIN(CryptoPP)

#define CRYPTOPP_BLOCK_1(n, t, s) t* m_##n() {return (t *)(m_aggregate+0);}     size_t SS1() {return       sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_2(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS1());} size_t SS2() {return SS1()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_3(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS2());} size_t SS3() {return SS2()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_4(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS3());} size_t SS4() {return SS3()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_5(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS4());} size_t SS5() {return SS4()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_6(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS5());} size_t SS6() {return SS5()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_7(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS6());} size_t SS7() {return SS6()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_8(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS7());} size_t SS8() {return SS7()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCKS_END(i) size_t SST() {return SS##i();} void AllocateBlocks() {m_aggregate.New(SST());} SecByteBlock m_aggregate;

/// .
class VMAC_Base : public IteratedHash<word64, LittleEndian, 16, MessageAuthenticationCode>
{
public:
	std::string AlgorithmName() const {return std::string("VMAC(") + GetCipher().AlgorithmName() + ")-" + IntToString(DigestSize()*8);}
	unsigned int IVSize() const {return GetCipher().BlockSize();}
	void Resynchronize(const byte *IV);
	void GetNextIV(byte *IV);
	unsigned int DigestSize() const {return m_is128 ? 16 : 8;};
	void UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &params);
	void TruncatedFinal(byte *mac, size_t size);

protected:
	virtual BlockCipher & AccessCipher() =0;
	virtual int DefaultDigestSize() const =0;
	const BlockCipher & GetCipher() const {return const_cast<VMAC_Base *>(this)->AccessCipher();}
	void HashEndianCorrectedBlock(const word64 *data);
	size_t HashMultipleBlocks(const word64 *input, size_t length);
	void Init();
	word64* StateBuf() {return NULL;}

	CRYPTOPP_BLOCK_1(polyKey, word64, 2)
	CRYPTOPP_BLOCK_2(polyAccum, word64, 2)
	CRYPTOPP_BLOCK_3(ipKey, word64, 2)
	CRYPTOPP_BLOCK_4(nhAccum, word64, 2*(m_is128+1))
	CRYPTOPP_BLOCK_5(nhKey, word64, m_L1KeyLength/sizeof(word64) + 2*m_is128)
	CRYPTOPP_BLOCK_6(nonce, byte, IVSize())
	CRYPTOPP_BLOCK_7(pad, byte, IVSize())
	CRYPTOPP_BLOCKS_END(7)

	int m_L1KeyLength;
	size_t m_nhCount;
	bool m_is128, m_padCached;
};

/// <a href="http://www.cryptolounge.org/wiki/VMAC">VMAC</a>
template <class T_BlockCipher, int T_DigestBitSize = 128>
class VMAC : public SimpleKeyingInterfaceImpl<VMAC_Base, SameKeyLengthAs<T_BlockCipher, SimpleKeyingInterface::UNIQUE_IV, T_BlockCipher::BLOCKSIZE> >
{
public:
	static std::string StaticAlgorithmName() {return std::string("VMAC(") + T_BlockCipher::StaticAlgorithmName() + ")-" + IntToString(T_DigestBitSize);}

private:
	BlockCipher & AccessCipher() {return m_cipher;}
	int DefaultDigestSize() const {return T_DigestBitSize/8;}
	typename T_BlockCipher::Encryption m_cipher;
};

NAMESPACE_END

#endif
