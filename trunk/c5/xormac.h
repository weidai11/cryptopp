// xormac.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_XORMAC_H
#define CRYPTOPP_XORMAC_H

#include "seckey.h"
#include "iterhash.h"
#include "argnames.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T> struct DigestSizeSubtract4Workaround {enum {RESULT = T::DIGESTSIZE-4};};	// VC60 workaround

template <class T>
class CRYPTOPP_NO_VTABLE XMACC_Base : public FixedKeyLength<DigestSizeSubtract4Workaround<T>::RESULT, SimpleKeyingInterface::INTERNALLY_GENERATED_IV>, 
					public IteratedHash<typename T::HashWordType, typename T::ByteOrderClass, T::BLOCKSIZE, MessageAuthenticationCode>
{
public:
	static std::string StaticAlgorithmName() {return std::string("XMAC(") + T::StaticAlgorithmName() + ")";}
	enum {DIGESTSIZE = 4+T::DIGESTSIZE};
	typedef typename T::HashWordType HashWordType;

	XMACC_Base() {SetStateSize(T::DIGESTSIZE);}

	void CheckedSetKey(void *, Empty empty, const byte *key, unsigned int length, const NameValuePairs &params);
	void Resynchronize(const byte *IV)
	{
		GetWord(false, BIG_ENDIAN_ORDER, m_counter, IV);
		this->Restart();
	}
	unsigned int IVSize() const
		{return 4;}
	void GetNextIV(byte *IV)
	{
		if (m_counter == 0xffffffff)
			throw NotImplemented("XMACC: must have a valid counter to get next IV");
		PutWord(false, BIG_ENDIAN_ORDER, IV, m_counter+1);
	}

	word32 CurrentCounter() const {return m_counter;}

	void TruncatedFinal(byte *mac, unsigned int size);
	bool TruncatedVerify(const byte *mac, unsigned int length);
	unsigned int DigestSize() const {return DIGESTSIZE;}	// need to override this

private:
	void Init();
	static void WriteWord32(byte *output, word32 value);
	static void XorDigest(HashWordType *digest, const HashWordType *buffer);
	void HashEndianCorrectedBlock(const HashWordType *data);

	FixedSizeSecBlock<byte, DigestSizeSubtract4Workaround<T>::RESULT> m_key;
	enum {BUFFER_SIZE = ((T::DIGESTSIZE) / sizeof(HashWordType))};	// VC60 workaround
	FixedSizeSecBlock<HashWordType, BUFFER_SIZE> m_buffer;
	word32 m_counter, m_index;
};

//! <a href="http://www.weidai.com/scan-mirror/mac.html#XMAC">XMAC</a>
/*! If you need to generate MACs with XMACC (instead of just verifying them),
	you must save the counter before destroying an XMACC object
	and reinitialize it the next time you create an XMACC with the same key.
	Start counter at 0 when using a key for the first time. */
template <class T>
class XMACC : public ClonableImpl<XMACC<T>, MessageAuthenticationCodeImpl<XMACC_Base<T> > >
{
public:
	XMACC() {}
	XMACC(const byte *key, word32 counter = 0xffffffff)
		{this->SetKey(key, this->KEYLENGTH, MakeParameters(Name::XMACC_Counter(), counter));}
};

template <class T> void XMACC_Base<T>::CheckedSetKey(void *, Empty empty, const byte *key, unsigned int length, const NameValuePairs &params)
{
	this->ThrowIfInvalidKeyLength(length);
	m_counter = 0xffffffff;
	const byte *iv = NULL;
	if (params.GetValue(Name::IV(), iv))
		GetWord(false, BIG_ENDIAN_ORDER, m_counter, iv);
	else
		params.GetValue(Name::XMACC_Counter(), m_counter);
	memcpy(m_key, key, this->KEYLENGTH);
	Init();
}

template <class T> void XMACC_Base<T>::Init()
{
	m_index = 0x80000000;
	memset(this->m_digest, 0, T::DIGESTSIZE);
}

template <class T> inline void XMACC_Base<T>::WriteWord32(byte *output, word32 value)
{
	output[0] = byte(value >> 24);
	output[1] = byte(value >> 16);
	output[2] = byte(value >> 8);
	output[3] = byte(value);
}

template <class T> inline void XMACC_Base<T>::XorDigest(HashWordType *digest, const HashWordType *buffer)
{
	for (unsigned i=0; i<(T::DIGESTSIZE/sizeof(HashWordType)); i++)
		digest[i] ^= buffer[i];
}

template <class T> void XMACC_Base<T>::HashEndianCorrectedBlock(const HashWordType *input)
{
	memcpy(m_buffer, m_key, this->KEYLENGTH);
	WriteWord32((byte *)m_buffer.begin()+this->KEYLENGTH, ++m_index);
	T::CorrectEndianess(m_buffer, m_buffer, T::DIGESTSIZE);
	T::Transform(m_buffer, input);
	XorDigest(this->m_digest, m_buffer);
}

template <class T> void XMACC_Base<T>::TruncatedFinal(byte *mac, unsigned int size)
{
	this->ThrowIfInvalidTruncatedSize(size);
	if (size < 4)
		throw InvalidArgument("XMACC: truncating the MAC to less than 4 bytes will cause it to be unverifiable");
	if (m_counter == 0xffffffff)
		throw InvalidArgument("XMACC: the counter must be initialized to a valid value for MAC generation");

	PadLastBlock(this->BLOCKSIZE - 2*sizeof(HashWordType));
	CorrectEndianess(this->m_data, this->m_data, this->BLOCKSIZE - 2*sizeof(HashWordType));
	this->m_data[this->m_data.size()-2] = ByteReverse(this->GetBitCountHi());	// ByteReverse for backwards compatibility
	this->m_data[this->m_data.size()-1] = ByteReverse(this->GetBitCountLo());
	HashEndianCorrectedBlock(this->m_data);

	memcpy(m_buffer, m_key, this->KEYLENGTH);
	WriteWord32((byte *)m_buffer.begin()+this->KEYLENGTH, 0);
	memset(this->m_data, 0, this->BLOCKSIZE-4);
	WriteWord32((byte *)this->m_data.begin()+this->BLOCKSIZE-4, ++m_counter);
	T::CorrectEndianess(m_buffer, m_buffer, T::DIGESTSIZE);
	T::CorrectEndianess(this->m_data, this->m_data, this->BLOCKSIZE);
	T::Transform(m_buffer, this->m_data);
	XorDigest(this->m_digest, m_buffer);

	WriteWord32(mac, m_counter);
	T::CorrectEndianess(this->m_digest, this->m_digest, T::DIGESTSIZE);
	memcpy(mac+4, this->m_digest, size-4);

	this->Restart();		// reinit for next use
}

template <class T> bool XMACC_Base<T>::TruncatedVerify(const byte *mac, unsigned int size)
{
	assert(4 <= size && size <= DIGESTSIZE);

	PadLastBlock(this->BLOCKSIZE - 2*sizeof(HashWordType));
	CorrectEndianess(this->m_data, this->m_data, this->BLOCKSIZE - 2*sizeof(HashWordType));
	this->m_data[this->m_data.size()-2] = ByteReverse(this->GetBitCountHi());	// ByteReverse for backwards compatibility
	this->m_data[this->m_data.size()-1] = ByteReverse(this->GetBitCountLo());
	HashEndianCorrectedBlock(this->m_data);

	memcpy(m_buffer, m_key, this->KEYLENGTH);
	WriteWord32((byte *)m_buffer.begin()+this->KEYLENGTH, 0);
	memset(this->m_data, 0, this->BLOCKSIZE-4);
	memcpy((byte *)this->m_data.begin()+this->BLOCKSIZE-4, mac, 4);
	T::CorrectEndianess(m_buffer, m_buffer, T::DIGESTSIZE);
	T::CorrectEndianess(this->m_data, this->m_data, this->BLOCKSIZE);
	T::Transform(m_buffer, this->m_data);
	XorDigest(this->m_digest, m_buffer);

	T::CorrectEndianess(this->m_digest, this->m_digest, T::DIGESTSIZE);
	bool macValid = (memcmp(mac+4, this->m_digest, size-4) == 0);
	this->Restart();		// reinit for next use
	return macValid;
}

NAMESPACE_END

#endif
