#ifndef CRYPTOPP_ITERHASH_H
#define CRYPTOPP_ITERHASH_H

#include "cryptlib.h"
#include "secblock.h"
#include "misc.h"
#include "simple.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T, class BASE>
class CRYPTOPP_NO_VTABLE IteratedHashBase : public BASE
{
public:
	typedef T HashWordType;

	IteratedHashBase() : m_countHi(0), m_countLo(0) {}
	void SetBlockSize(unsigned int blockSize) {m_data.resize(blockSize / sizeof(HashWordType));}
	void SetStateSize(unsigned int stateSize) {m_digest.resize(stateSize / sizeof(HashWordType));}
	unsigned int BlockSize() const {return m_data.size() * sizeof(T);}
	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return sizeof(T);}
	void Update(const byte *input, unsigned int length);
	byte * CreateUpdateSpace(unsigned int &size);
	void Restart();

protected:
	T GetBitCountHi() const {return (m_countLo >> (8*sizeof(T)-3)) + (m_countHi << 3);}
	T GetBitCountLo() const {return m_countLo << 3;}

	virtual unsigned int HashMultipleBlocks(const T *input, unsigned int length);
	void PadLastBlock(unsigned int lastBlockSize, byte padFirst=0x80);
	virtual void Init() =0;
	virtual void HashBlock(const T *input) =0;

	SecBlock<T> m_data;			// Data buffer
	SecBlock<T> m_digest;		// Message digest

private:
	T m_countLo, m_countHi;
};

#ifdef WORD64_AVAILABLE
CRYPTOPP_DLL_TEMPLATE_CLASS IteratedHashBase<word64, HashTransformation>;
CRYPTOPP_DLL_TEMPLATE_CLASS IteratedHashBase<word64, MessageAuthenticationCode>;
#endif

CRYPTOPP_DLL_TEMPLATE_CLASS IteratedHashBase<word32, HashTransformation>;
CRYPTOPP_DLL_TEMPLATE_CLASS IteratedHashBase<word32, MessageAuthenticationCode>;

//! .
template <class T, class B, class BASE>
class CRYPTOPP_NO_VTABLE IteratedHashBase2 : public IteratedHashBase<T, BASE>
{
public:
	typedef B ByteOrderClass;
	typedef typename IteratedHashBase<T, BASE>::HashWordType HashWordType;

	inline static void CorrectEndianess(HashWordType *out, const HashWordType *in, unsigned int byteCount)
	{
		ConditionalByteReverse(B::ToEnum(), out, in, byteCount);
	}

	void TruncatedFinal(byte *hash, unsigned int size);

protected:
	void HashBlock(const HashWordType *input);
	virtual void HashEndianCorrectedBlock(const HashWordType *data) =0;
};

//! .
template <class T_HashWordType, class T_Endianness, unsigned int T_BlockSize, class T_Base = HashTransformation>
class CRYPTOPP_NO_VTABLE IteratedHash : public IteratedHashBase2<T_HashWordType, T_Endianness, T_Base>
{
public:
	enum {BLOCKSIZE = T_BlockSize};
	CRYPTOPP_COMPILE_ASSERT((BLOCKSIZE & (BLOCKSIZE - 1)) == 0);		// blockSize is a power of 2

protected:
	IteratedHash() {SetBlockSize(T_BlockSize);}
};

template <class T_HashWordType, class T_Endianness, unsigned int T_BlockSize, unsigned int T_StateSize, class T_Transform, unsigned int T_DigestSize = T_StateSize>
class CRYPTOPP_NO_VTABLE IteratedHashWithStaticTransform
	: public ClonableImpl<T_Transform, AlgorithmImpl<IteratedHash<T_HashWordType, T_Endianness, T_BlockSize>, T_Transform> >
{
public:
	enum {DIGESTSIZE = T_DigestSize};
	unsigned int DigestSize() const {return DIGESTSIZE;};

protected:
	IteratedHashWithStaticTransform()
	{
		SetStateSize(T_StateSize);
		Init();
	}
	void HashEndianCorrectedBlock(const T_HashWordType *data) {T_Transform::Transform(m_digest, data);}
	void Init() {T_Transform::InitState(m_digest);}
};

// *************************************************************

template <class T, class B, class BASE> void IteratedHashBase2<T, B, BASE>::TruncatedFinal(byte *hash, unsigned int size)
{
	ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(BlockSize() - 2*sizeof(HashWordType));
	CorrectEndianess(m_data, m_data, BlockSize() - 2*sizeof(HashWordType));

	m_data[m_data.size()-2] = B::ToEnum() ? GetBitCountHi() : GetBitCountLo();
	m_data[m_data.size()-1] = B::ToEnum() ? GetBitCountLo() : GetBitCountHi();

	HashEndianCorrectedBlock(m_data);
	CorrectEndianess(m_digest, m_digest, DigestSize());
	memcpy(hash, m_digest, size);

	Restart();		// reinit for next use
}

template <class T, class B, class BASE> void IteratedHashBase2<T, B, BASE>::HashBlock(const HashWordType *input)
{
	if (NativeByteOrderIs(B::ToEnum()))
		HashEndianCorrectedBlock(input);
	else
	{
		ByteReverse(m_data.begin(), input, BlockSize());
		HashEndianCorrectedBlock(m_data);
	}
}

NAMESPACE_END

#endif
