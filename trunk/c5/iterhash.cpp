// iterhash.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "iterhash.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T, class BASE> void IteratedHashBase<T, BASE>::Update(const byte *input, unsigned int len)
{
	HashWordType oldCountLo = m_countLo, oldCountHi = m_countHi;
	if ((m_countLo = oldCountLo + len) < oldCountLo)
		m_countHi++;             // carry from low to high
	m_countHi += SafeRightShift<8*sizeof(HashWordType)>(len);
	if (m_countHi < oldCountHi)
		throw HashInputTooLong(AlgorithmName());

	unsigned int blockSize = BlockSize();
	unsigned int num = ModPowerOf2(oldCountLo, blockSize);

	if (num != 0)	// process left over data
	{
		if ((num+len) >= blockSize)
		{
			memcpy((byte *)m_data.begin()+num, input, blockSize-num);
			HashBlock(m_data);
			input += (blockSize-num);
			len-=(blockSize - num);
			num=0;
			// drop through and do the rest
		}
		else
		{
			memcpy((byte *)m_data.begin()+num, input, len);
			return;
		}
	}

	// now process the input data in blocks of blockSize bytes and save the leftovers to m_data
	if (len >= blockSize)
	{
		if (input == (byte *)m_data.begin())
		{
			assert(len == blockSize);
			HashBlock(m_data);
			return;
		}
		else if (IsAligned<T>(input))
		{
			unsigned int leftOver = HashMultipleBlocks((T *)input, len);
			input += (len - leftOver);
			len = leftOver;
		}
		else
			do
			{   // copy input first if it's not aligned correctly
				memcpy(m_data, input, blockSize);
				HashBlock(m_data);
				input+=blockSize;
				len-=blockSize;
			} while (len >= blockSize);
	}

	memcpy(m_data, input, len);
}

template <class T, class BASE> byte * IteratedHashBase<T, BASE>::CreateUpdateSpace(unsigned int &size)
{
	unsigned int blockSize = BlockSize();
	unsigned int num = ModPowerOf2(m_countLo, blockSize);
	size = blockSize - num;
	return (byte *)m_data.begin() + num;
}

template <class T, class BASE> unsigned int IteratedHashBase<T, BASE>::HashMultipleBlocks(const T *input, unsigned int length)
{
	unsigned int blockSize = BlockSize();
	bool noReverse = NativeByteOrderIs(GetByteOrder());
	do
	{
		if (noReverse)
			HashEndianCorrectedBlock(input);
		else
		{
			ByteReverse(this->m_data.begin(), input, this->BlockSize());
			HashEndianCorrectedBlock(this->m_data);
		}

		input += blockSize/sizeof(T);
		length -= blockSize;
	}
	while (length >= blockSize);
	return length;
}

template <class T, class BASE> void IteratedHashBase<T, BASE>::PadLastBlock(unsigned int lastBlockSize, byte padFirst)
{
	unsigned int blockSize = BlockSize();
	unsigned int num = ModPowerOf2(m_countLo, blockSize);
	((byte *)m_data.begin())[num++]=padFirst;
	if (num <= lastBlockSize)
		memset((byte *)m_data.begin()+num, 0, lastBlockSize-num);
	else
	{
		memset((byte *)m_data.begin()+num, 0, blockSize-num);
		HashBlock(m_data);
		memset(m_data, 0, lastBlockSize);
	}
}

template <class T, class BASE> void IteratedHashBase<T, BASE>::Restart()
{
	m_countLo = m_countHi = 0;
	Init();
}

template <class T, class BASE> void IteratedHashBase<T, BASE>::TruncatedFinal(byte *digest, unsigned int size)
{
	this->ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(this->BlockSize() - 2*sizeof(HashWordType));
	ByteOrder order = this->GetByteOrder();
	ConditionalByteReverse<HashWordType>(order, this->m_data, this->m_data, this->BlockSize() - 2*sizeof(HashWordType));

	this->m_data[this->m_data.size()-2] = order ? this->GetBitCountHi() : this->GetBitCountLo();
	this->m_data[this->m_data.size()-1] = order ? this->GetBitCountLo() : this->GetBitCountHi();

	HashEndianCorrectedBlock(this->m_data);
	ConditionalByteReverse<HashWordType>(order, this->m_digest, this->m_digest, this->DigestSize());
	memcpy(digest, this->m_digest, size);

	this->Restart();		// reinit for next use
}

NAMESPACE_END
