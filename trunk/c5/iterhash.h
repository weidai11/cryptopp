#ifndef CRYPTOPP_ITERHASH_H
#define CRYPTOPP_ITERHASH_H

#include "cryptlib.h"
#include "secblock.h"
#include "misc.h"
#include "simple.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
template <class T, class BASE>
class CRYPTOPP_NO_VTABLE IteratedHashBase : public BASE
{
public:
	typedef T HashWordType;

	IteratedHashBase() : m_countHi(0), m_countLo(0) {}
	unsigned int BlockSize() const {return m_data.size() * sizeof(T);}
	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return sizeof(T);}
	void Update(const byte *input, unsigned int length);
	byte * CreateUpdateSpace(unsigned int &size);
	void Restart();

protected:
	void SetBlockSize(unsigned int blockSize) {m_data.resize(blockSize / sizeof(HashWordType));}
	void SetStateSize(unsigned int stateSize) {m_digest.resize(stateSize / sizeof(HashWordType));}

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
CRYPTOPP_STATIC_TEMPLATE_CLASS IteratedHashBase<word64, HashTransformation>;
CRYPTOPP_STATIC_TEMPLATE_CLASS IteratedHashBase<word64, MessageAuthenticationCode>;
#endif

CRYPTOPP_DLL_TEMPLATE_CLASS IteratedHashBase<word32, HashTransformation>;
CRYPTOPP_STATIC_TEMPLATE_CLASS IteratedHashBase<word32, MessageAuthenticationCode>;

//! _
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

	void TruncatedFinal(byte *digest, unsigned int size);

protected:
	void HashBlock(const HashWordType *input);
	virtual void HashEndianCorrectedBlock(const HashWordType *data) =0;
};

//! _
template <class T_HashWordType, class T_Endianness, unsigned int T_BlockSize, class T_Base = HashTransformation>
class CRYPTOPP_NO_VTABLE IteratedHash : public IteratedHashBase2<T_HashWordType, T_Endianness, T_Base>
{
public:
	enum {BLOCKSIZE = T_BlockSize};
	CRYPTOPP_COMPILE_ASSERT((BLOCKSIZE & (BLOCKSIZE - 1)) == 0);		// blockSize is a power of 2

protected:
	IteratedHash() {this->SetBlockSize(T_BlockSize);}
};

//! _
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
		this->SetStateSize(T_StateSize);
		Init();
	}
	void HashEndianCorrectedBlock(const T_HashWordType *data) {T_Transform::Transform(this->m_digest, data);}
	void Init() {T_Transform::InitState(this->m_digest);}
};

// *************************************************************

template <class T, class B, class BASE> void IteratedHashBase2<T, B, BASE>::TruncatedFinal(byte *digest, unsigned int size)
{
	this->ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(this->BlockSize() - 2*sizeof(HashWordType));
	CorrectEndianess(this->m_data, this->m_data, this->BlockSize() - 2*sizeof(HashWordType));

	this->m_data[this->m_data.size()-2] = B::ToEnum() ? this->GetBitCountHi() : this->GetBitCountLo();
	this->m_data[this->m_data.size()-1] = B::ToEnum() ? this->GetBitCountLo() : this->GetBitCountHi();

	HashEndianCorrectedBlock(this->m_data);
	CorrectEndianess(this->m_digest, this->m_digest, this->DigestSize());
	memcpy(digest, this->m_digest, size);

	this->Restart();		// reinit for next use
}

template <class T, class B, class BASE> void IteratedHashBase2<T, B, BASE>::HashBlock(const HashWordType *input)
{
	if (NativeByteOrderIs(B::ToEnum()))
		HashEndianCorrectedBlock(input);
	else
	{
		ByteReverse(this->m_data.begin(), input, this->BlockSize());
		HashEndianCorrectedBlock(this->m_data);
	}
}

NAMESPACE_END

#endif
