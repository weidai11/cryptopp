// tea.cpp - modified by Wei Dai from code in the original paper

#include "pch.h"
#include "tea.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

const word32 TEA::Base::DELTA = 0x9e3779b9;

void TEA::Base::UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length)
{
	AssertValidKeyLength(length);

	GetUserKey(BIG_ENDIAN_ORDER, k.begin(), 4, userKey, KEYLENGTH);
}

typedef BlockGetAndPut<word32, BigEndian> Block;

void TEA::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	word32 y, z;
	Block::Get(inBlock)(y)(z);

	word32 sum = 0;
	for (int i=0; i<ROUNDS; i++)
	{   
		sum += DELTA;
		y += (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
		z += (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3];
	}

	Block::Put(xorBlock, outBlock)(y)(z);
}

typedef BlockGetAndPut<word32, BigEndian> Block;

void TEA::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	word32 y, z;
	Block::Get(inBlock)(y)(z);

	word32 sum = DELTA << LOG_ROUNDS;
	for (int i=0; i<ROUNDS; i++)
	{
		z -= (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3]; 
		y -= (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
		sum -= DELTA;
	}

	Block::Put(xorBlock, outBlock)(y)(z);
}

NAMESPACE_END
