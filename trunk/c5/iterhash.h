#ifndef CRYPTOPP_ITERHASH_H
#define CRYPTOPP_ITERHASH_H

#include "cryptlib.h"
#include "secblock.h"
#include "misc.h"
#include "simple.h"

NAMESPACE_BEGIN(CryptoPP)

//! exception thrown when trying to hash more data than is allowed by a hash function
class CRYPTOPP_DLL HashInputTooLong : public InvalidDataFormat
{
public:
	explicit HashInputTooLong(const std::string &alg)
		: InvalidDataFormat("IteratedHashBase: input data exceeds maximum allowed by hash function " + alg) {}
};

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
	void TruncatedFinal(byte *digest, unsigned int size);

protected:
	void SetBlockSize(unsigned int blockSize) {m_data.resize(blockSize / sizeof(HashWordType));}
	void SetStateSize(unsigned int stateSize) {m_digest.resize(stateSize / sizeof(HashWordType));}

	T GetBitCountHi() const {return (m_countLo >> (8*sizeof(T)-3)) + (m_countHi << 3);}
	T GetBitCountLo() const {return m_countLo << 3;}

	void PadLastBlock(unsigned int lastBlockSize, byte padFirst=0x80);
	virtual void Init() =0;

	virtual ByteOrder GetByteOrder() const =0;
	virtual void HashEndianCorrectedBlock(const HashWordType *data) =0;
	virtual unsigned int HashMultipleBlocks(const T *input, unsigned int length);
	void HashBlock(const HashWordType *input) {HashMultipleBlocks(input, BlockSize());}

	SecBlock<T> m_data;			// Data buffer
	SecBlock<T> m_digest;		// Message digest

private:
	T m_countLo, m_countHi;
};

#ifdef WORD64_AVAILABLE
CRYPTOPP_DLL_TEMPLATE_CLASS IteratedHashBase<word64, HashTransformation>;
CRYPTOPP_STATIC_TEMPLATE_CLASS IteratedHashBase<word64, MessageAuthenticationCode>;
#endif

CRYPTOPP_DLL_TEMPLATE_CLASS IteratedHashBase<word32, HashTransformation>;
CRYPTOPP_STATIC_TEMPLATE_CLASS IteratedHashBase<word32, MessageAuthenticationCode>;

//! _
template <class T_HashWordType, class T_Endianness, unsigned int T_BlockSize, class T_Base = HashTransformation>
class CRYPTOPP_NO_VTABLE IteratedHash : public IteratedHashBase<T_HashWordType, T_Base>
{
public:
	typedef T_Endianness ByteOrderClass;
	typedef T_HashWordType HashWordType;

	enum {BLOCKSIZE = T_BlockSize};
	CRYPTOPP_COMPILE_ASSERT((BLOCKSIZE & (BLOCKSIZE - 1)) == 0);		// blockSize is a power of 2

	ByteOrder GetByteOrder() const {return T_Endianness::ToEnum();}

	inline static void CorrectEndianess(HashWordType *out, const HashWordType *in, unsigned int byteCount)
	{
		ConditionalByteReverse(T_Endianness::ToEnum(), out, in, byteCount);
	}

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

NAMESPACE_END

#endif
