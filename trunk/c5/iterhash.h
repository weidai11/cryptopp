#ifndef CRYPTOPP_ITERHASH_H
#define CRYPTOPP_ITERHASH_H

#include "cryptlib.h"
#include "secblock.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T, class BASE>
class IteratedHashBase : public BASE
{
public:
	typedef T HashWordType;

	IteratedHashBase(unsigned int blockSize, unsigned int digestSize);
	unsigned int DigestSize() const {return m_digest.size() * sizeof(T);};
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
	virtual unsigned int BlockSize() const =0;

	SecBlock<T> m_data;			// Data buffer
	SecBlock<T> m_digest;		// Message digest

private:
	T m_countLo, m_countHi;
};

//! .
template <class T, class B, class BASE>
class IteratedHashBase2 : public IteratedHashBase<T, BASE>
{
public:
	IteratedHashBase2(unsigned int blockSize, unsigned int digestSize)
		: IteratedHashBase<T, BASE>(blockSize, digestSize) {}

	typedef B ByteOrderClass;
	typedef typename IteratedHashBase<T, BASE>::HashWordType HashWordType;

	inline static void CorrectEndianess(HashWordType *out, const HashWordType *in, unsigned int byteCount)
	{
		ConditionalByteReverse(B::ToEnum(), out, in, byteCount);
	}

	void TruncatedFinal(byte *hash, unsigned int size);

protected:
	void HashBlock(const HashWordType *input);

	virtual void vTransform(const HashWordType *data) =0;
};

//! .
template <class T, class B, unsigned int S, class BASE = HashTransformation>
class IteratedHash : public IteratedHashBase2<T, B, BASE>
{
public:
	enum {BLOCKSIZE = S};

private:
	CRYPTOPP_COMPILE_ASSERT((BLOCKSIZE & (BLOCKSIZE - 1)) == 0);		// blockSize is a power of 2

protected:
	IteratedHash(unsigned int digestSize) : IteratedHashBase2<T, B, BASE>(BLOCKSIZE, digestSize) {}
	unsigned int BlockSize() const {return BLOCKSIZE;}
};

template <class T, class B, unsigned int S, class M>
class IteratedHashWithStaticTransform : public IteratedHash<T, B, S>
{
protected:
	IteratedHashWithStaticTransform(unsigned int digestSize) : IteratedHash<T, B, S>(digestSize) {}
	void vTransform(const T *data) {M::Transform(m_digest, data);}
	std::string AlgorithmName() const {return M::StaticAlgorithmName();}
};

// *************************************************************

template <class T, class B, class BASE> void IteratedHashBase2<T, B, BASE>::TruncatedFinal(byte *hash, unsigned int size)
{
	ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(BlockSize() - 2*sizeof(HashWordType));
	CorrectEndianess(m_data, m_data, BlockSize() - 2*sizeof(HashWordType));

	m_data[m_data.size()-2] = B::ToEnum() ? GetBitCountHi() : GetBitCountLo();
	m_data[m_data.size()-1] = B::ToEnum() ? GetBitCountLo() : GetBitCountHi();

	vTransform(m_data);
	CorrectEndianess(m_digest, m_digest, DigestSize());
	memcpy(hash, m_digest, size);

	Restart();		// reinit for next use
}

template <class T, class B, class BASE> void IteratedHashBase2<T, B, BASE>::HashBlock(const HashWordType *input)
{
	if (NativeByteOrderIs(B::ToEnum()))
		vTransform(input);
	else
	{
		ByteReverse(m_data.begin(), input, BlockSize());
		vTransform(m_data);
	}
}

NAMESPACE_END

#endif
