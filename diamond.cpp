// diamond.cpp - modified by Wei Dai from:

/* diamond2.c - Encryption designed to exceed DES in security.
   This file and the Diamond2 and Diamond2 Lite Block Ciphers
   described herein are hereby dedicated to the Public Domain by the
   author and inventor, Michael Paul Johnson.  Feel free to use these
   for any purpose that is legally and morally right.  The names
   "Diamond2 Block Cipher" and "Diamond2 Lite Block Cipher" should only
   be used to describe the algorithms described in this file, to avoid
   confusion.

   Disclaimers:  the following comes with no warranty, expressed or
   implied.  You, the user, must determine the suitability of this
   information to your own uses.  You must also find out what legal
   requirements exist with respect to this data and programs using
   it, and comply with whatever valid requirements exist.
*/

#include "pch.h"
#include "diamond.h"
#include "crc.h"

NAMESPACE_BEGIN(CryptoPP)

class Diamond2SboxMaker
{
public:
	Diamond2SboxMaker(const byte *external_key, unsigned int key_size,
					 unsigned int rounds, bool lite);

	void MakeSbox(byte *sbox, CipherDir direction);

private:
	unsigned int keyrand(unsigned int max_value, const byte *prevSbox);
	void makeonebox(byte *s, unsigned int i, unsigned int j);

	CRC32 crc;
	const byte *const key;
	const unsigned keysize;
	unsigned keyindex;
	const unsigned numrounds;
	const unsigned roundsize; // Number of bytes in one round of substitution boxes
	const unsigned blocksize;
};

Diamond2SboxMaker::Diamond2SboxMaker(const byte *external_key, unsigned int key_size, unsigned int rounds,
								   bool lite)
	: key(external_key),
	  keysize(key_size),
	  keyindex(0),
	  numrounds(rounds),
	  roundsize(lite ? 2048 : 4096),
	  blocksize(lite ? 8 : 16)
{
	assert((rounds * blocksize) <= 255);
}

// Returns uniformly distributed pseudorandom value based on key[], sized keysize
inline unsigned int Diamond2SboxMaker::keyrand(unsigned int max_value, const byte *prevSbox)
{
	assert(max_value <= 255);

	if (!max_value) return 0;

	unsigned int mask, prandvalue, i;

	// Create a mask to get the minimum number of 
	// bits to cover the range 0 to max_value.
	for (i=max_value, mask=0; i > 0; i = i >> 1)
		mask = (mask << 1) | 1;

	assert(i==0);
	do
	{
		if (prevSbox)
			crc.UpdateByte(prevSbox[key[keyindex++]]);
		else
			crc.UpdateByte(key[keyindex++]);

		if (keyindex >= keysize)
		{
			keyindex = 0;   /* Recycle thru the key */
			crc.UpdateByte(byte(keysize));
			crc.UpdateByte(byte(keysize >> 8));
		}
		prandvalue = crc.GetCrcByte(0) & mask;
		if ((++i>97) && (prandvalue > max_value))   /* Don't loop forever. */
			prandvalue -= max_value;                /* Introduce negligible bias. */
	}
	while (prandvalue > max_value); /* Discard out of range values. */
	return prandvalue;
}

void Diamond2SboxMaker::makeonebox(byte *s, unsigned int i, unsigned int j)
{
	bool filled[256];
	byte *sbox = s + (roundsize*i) + (256*j);
	byte *prevSbox = (i||j) ? sbox-256 : 0;

	unsigned m;
	for (m = 0; m < 256; m++)   /* The filled array is used to make sure that */
		filled[m] = false;      /* each byte of the array is filled only once. */
	for (int n = 255; n >= 0 ; n--) /* n counts the number of bytes left to fill */
	{
		// pos is the position among the UNFILLED
		// components of the s array that the number n should be placed.
		unsigned pos = keyrand(n, prevSbox);   
		unsigned p=0;
		while (filled[p]) p++;
		for (m=0; m<pos; m++)
		{
			p++;
			while (filled[p]) p++;
		}
		assert(p<256);
		sbox[p] = n;
		filled[p] = true;
	}
}

void Diamond2SboxMaker::MakeSbox(byte *s, CipherDir direction)
{
	unsigned int i, j, k;

	for (i = 0; i < numrounds; i++)
		for (j = 0; j < blocksize; j++)
			makeonebox(s, i, j);

	if (direction==DECRYPTION)
	{
		SecByteBlock si(numrounds * roundsize);
		for (i = 0; i < numrounds; i++)
			for (j = 0; j < blocksize; j++)
				for (k = 0; k < 256; k++)
					*(si + (roundsize * i) + (256 * j) + *(s + (roundsize * i) + (256 * j) + k)) = k;
		memcpy(s, si, numrounds * roundsize);
	}
}

void Diamond2::Base::UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length, unsigned int rounds)
{
	AssertValidKeyLength(length);

	numrounds = rounds;
	s.New(numrounds * ROUNDSIZE);

	Diamond2SboxMaker m(userKey, length, rounds, false);
	m.MakeSbox(s, direction);
}

inline void Diamond2::Base::substitute(int round, byte *x, const byte *y) const
{
	const byte *sbox = s + (ROUNDSIZE*round);
	x[0] = sbox[0*256+y[0]];
	x[1] = sbox[1*256+y[1]];
	x[2] = sbox[2*256+y[2]];
	x[3] = sbox[3*256+y[3]];
	x[4] = sbox[4*256+y[4]];
	x[5] = sbox[5*256+y[5]];
	x[6] = sbox[6*256+y[6]];
	x[7] = sbox[7*256+y[7]];
	x[8] = sbox[8*256+y[8]];
	x[9] = sbox[9*256+y[9]];
	x[10] = sbox[10*256+y[10]];
	x[11] = sbox[11*256+y[11]];
	x[12] = sbox[12*256+y[12]];
	x[13] = sbox[13*256+y[13]];
	x[14] = sbox[14*256+y[14]];
	x[15] = sbox[15*256+y[15]];
}

#ifdef DIAMOND_USE_PERMTABLE

inline void Diamond2::Base::permute(byte *a)
{
#ifdef IS_LITTLE_ENDIAN
	word32 temp0     = (a[0] | (word32(a[10])<<24)) & 0x80000001;
#else
	word32 temp0     = ((word32(a[0])<<24) | a[10]) & 0x01000080;
#endif
		   temp0    |=                      permtable[0][a[1]] |
					   permtable[1][a[2]] | permtable[2][a[3]] |
					   permtable[3][a[4]] | permtable[4][a[5]] |
					   permtable[5][a[6]] | permtable[6][a[7]] |
					   permtable[7][a[8]] | permtable[8][a[9]];

#ifdef IS_LITTLE_ENDIAN
	word32 temp1     = (a[4] | (word32(a[14])<<24)) & 0x80000001;
#else
	word32 temp1     = ((word32(a[4])<<24) | a[14]) & 0x01000080;
#endif
		   temp1    |=                      permtable[0][a[5]] |
					   permtable[1][a[6]] | permtable[2][a[7]] |
					   permtable[3][a[8]] | permtable[4][a[9]] |
					   permtable[5][a[10]] | permtable[6][a[11]] |
					   permtable[7][a[12]] | permtable[8][a[13]];

#ifdef IS_LITTLE_ENDIAN
	word32 temp2     = (a[8] | (word32(a[2])<<24)) & 0x80000001;
#else
	word32 temp2     = ((word32(a[8])<<24) | a[2]) & 0x01000080;
#endif
		   temp2    |=                       permtable[0][a[9]] |
					   permtable[1][a[10]] | permtable[2][a[11]] |
					   permtable[3][a[12]] | permtable[4][a[13]] |
					   permtable[5][a[14]] | permtable[6][a[15]] |
					   permtable[7][a[0]] | permtable[8][a[1]];

#ifdef IS_LITTLE_ENDIAN
	word32 temp3     = (a[12] | (word32(a[6])<<24)) & 0x80000001;
#else
	word32 temp3     = ((word32(a[12])<<24) | a[6]) & 0x01000080;
#endif
	((word32 *)a)[3] = temp3 |               permtable[0][a[13]] |
					   permtable[1][a[14]] | permtable[2][a[15]] |
					   permtable[3][a[0]] | permtable[4][a[1]] |
					   permtable[5][a[2]] | permtable[6][a[3]] |
					   permtable[7][a[4]] | permtable[8][a[5]];

	((word32 *)a)[0] = temp0;
	((word32 *)a)[1] = temp1;
	((word32 *)a)[2] = temp2;
}

inline void Diamond2::Base::ipermute(byte *a)
{
#ifdef IS_LITTLE_ENDIAN
	word32 temp0     = (a[9] | (word32(a[3])<<24)) & 0x01000080;
#else
	word32 temp0     = ((word32(a[9])<<24) | a[3]) & 0x80000001;
#endif
		   temp0    |=                      ipermtable[0][a[2]] |
					   ipermtable[1][a[1]] | ipermtable[2][a[0]] |
					   ipermtable[3][a[15]] | ipermtable[4][a[14]] |
					   ipermtable[5][a[13]] | ipermtable[6][a[12]] |
					   ipermtable[7][a[11]] | ipermtable[8][a[10]];

#ifdef IS_LITTLE_ENDIAN
	word32 temp1     = (a[13] | (word32(a[7])<<24)) & 0x01000080;
#else
	word32 temp1     = ((word32(a[13])<<24) | a[7]) & 0x80000001;
#endif
		   temp1    |=                      ipermtable[0][a[6]] |
					   ipermtable[1][a[5]] | ipermtable[2][a[4]] |
					   ipermtable[3][a[3]] | ipermtable[4][a[2]] |
					   ipermtable[5][a[1]] | ipermtable[6][a[0]] |
					   ipermtable[7][a[15]] | ipermtable[8][a[14]];

#ifdef IS_LITTLE_ENDIAN
	word32 temp2     = (a[1] | (word32(a[11])<<24)) & 0x01000080;
#else
	word32 temp2     = ((word32(a[1])<<24) | a[11]) & 0x80000001;
#endif
		   temp2    |=                      ipermtable[0][a[10]] |
					   ipermtable[1][a[9]] | ipermtable[2][a[8]] |
					   ipermtable[3][a[7]] | ipermtable[4][a[6]] |
					   ipermtable[5][a[5]] | ipermtable[6][a[4]] |
					   ipermtable[7][a[3]] | ipermtable[8][a[2]];

#ifdef IS_LITTLE_ENDIAN
	word32 temp3     = (a[5] | (word32(a[15])<<24)) & 0x01000080;
#else
	word32 temp3     = ((word32(a[5])<<24) | a[15]) & 0x80000001;
#endif
	((word32 *)a)[3] = temp3 |               ipermtable[0][a[14]] |
					   ipermtable[1][a[13]] | ipermtable[2][a[12]] |
					   ipermtable[3][a[11]] | ipermtable[4][a[10]] |
					   ipermtable[5][a[9]] | ipermtable[6][a[8]] |
					   ipermtable[7][a[7]] | ipermtable[8][a[6]];

	((word32 *)a)[0] = temp0;
	((word32 *)a)[1] = temp1;
	((word32 *)a)[2] = temp2;
}

#else // DIAMOND_USE_PERMTABLE

inline void Diamond2::Base::permute(byte *x)
{
	byte y[16];

	y[0] = (x[0] & 1) | (x[1] & 2) | (x[2] & 4) |
			(x[3] & 8) | (x[4] & 16) | (x[5] & 32) |
			(x[6] & 64) | (x[7] & 128);
	y[1] = (x[1] & 1) | (x[2] & 2) | (x[3] & 4) |
			(x[4] & 8) | (x[5] & 16) | (x[6] & 32) |
			(x[7] & 64) | (x[8] & 128);
	y[2] = (x[2] & 1) | (x[3] & 2) | (x[4] & 4) |
			(x[5] & 8) | (x[6] & 16) | (x[7] & 32) |
			(x[8] & 64) | (x[9] & 128);
	y[3] = (x[3] & 1) | (x[4] & 2) | (x[5] & 4) |
			(x[6] & 8) | (x[7] & 16) | (x[8] & 32) |
			(x[9] & 64) | (x[10] & 128);
	y[4] = (x[4] & 1) | (x[5] & 2) | (x[6] & 4) |
			(x[7] & 8) | (x[8] & 16) | (x[9] & 32) |
			(x[10] & 64) | (x[11] & 128);
	y[5] = (x[5] & 1) | (x[6] & 2) | (x[7] & 4) |
			(x[8] & 8) | (x[9] & 16) | (x[10] & 32) |
			(x[11] & 64) | (x[12] & 128);
	y[6] = (x[6] & 1) | (x[7] & 2) | (x[8] & 4) |
			(x[9] & 8) | (x[10] & 16) | (x[11] & 32) |
			(x[12] & 64) | (x[13] & 128);
	y[7] = (x[7] & 1) | (x[8] & 2) | (x[9] & 4) |
			(x[10] & 8) | (x[11] & 16) | (x[12] & 32) |
			(x[13] & 64) | (x[14] & 128);
	y[8] = (x[8] & 1) | (x[9] & 2) | (x[10] & 4) |
			(x[11] & 8) | (x[12] & 16) | (x[13] & 32) |
			(x[14] & 64) | (x[15] & 128);
	y[9] = (x[9] & 1) | (x[10] & 2) | (x[11] & 4) |
			(x[12] & 8) | (x[13] & 16) | (x[14] & 32) |
			(x[15] & 64) | (x[0] & 128);
	y[10] = (x[10] & 1) | (x[11] & 2) | (x[12] & 4) |
			(x[13] & 8) | (x[14] & 16) | (x[15] & 32) |
			(x[0] & 64) | (x[1] & 128);
	y[11] = (x[11] & 1) | (x[12] & 2) | (x[13] & 4) |
			(x[14] & 8) | (x[15] & 16) | (x[0] & 32) |
			(x[1] & 64) | (x[2] & 128);
	y[12] = (x[12] & 1) | (x[13] & 2) | (x[14] & 4) |
			(x[15] & 8) | (x[0] & 16) | (x[1] & 32) |
			(x[2] & 64) | (x[3] & 128);
	y[13] = (x[13] & 1) | (x[14] & 2) | (x[15] & 4) |
			(x[0] & 8) | (x[1] & 16) | (x[2] & 32) |
			(x[3] & 64) | (x[4] & 128);
	y[14] = (x[14] & 1) | (x[15] & 2) | (x[0] & 4) |
			(x[1] & 8) | (x[2] & 16) | (x[3] & 32) |
			(x[4] & 64) | (x[5] & 128);
	y[15] = (x[15] & 1) | (x[0] & 2) | (x[1] & 4) |
			(x[2] & 8) | (x[3] & 16) | (x[4] & 32) |
			(x[5] & 64) | (x[6] & 128);

	memcpy(x, y, 16);
}

inline void Diamond2::Base::ipermute(byte *x)
{
	byte y[16];

	y[0] = (x[0] & 1) | (x[15] & 2) | (x[14] & 4) |
			(x[13] & 8) | (x[12] & 16) | (x[11] & 32) |
			(x[10] & 64) | (x[9] & 128);
	y[1] = (x[1] & 1) | (x[0] & 2) | (x[15] & 4) |
			(x[14] & 8) | (x[13] & 16) | (x[12] & 32) |
			(x[11] & 64) | (x[10] & 128);
	y[2] = (x[2] & 1) | (x[1] & 2) | (x[0] & 4) |
			(x[15] & 8) | (x[14] & 16) | (x[13] & 32) |
			(x[12] & 64) | (x[11] & 128);
	y[3] = (x[3] & 1) | (x[2] & 2) | (x[1] & 4) |
			(x[0] & 8) | (x[15] & 16) | (x[14] & 32) |
			(x[13] & 64) | (x[12] & 128);
	y[4] = (x[4] & 1) | (x[3] & 2) | (x[2] & 4) |
			(x[1] & 8) | (x[0] & 16) | (x[15] & 32) |
			(x[14] & 64) | (x[13] & 128);
	y[5] = (x[5] & 1) | (x[4] & 2) | (x[3] & 4) |
			(x[2] & 8) | (x[1] & 16) | (x[0] & 32) |
			(x[15] & 64) | (x[14] & 128);
	y[6] = (x[6] & 1) | (x[5] & 2) | (x[4] & 4) |
			(x[3] & 8) | (x[2] & 16) | (x[1] & 32) |
			(x[0] & 64) | (x[15] & 128);
	y[7] = (x[7] & 1) | (x[6] & 2) | (x[5] & 4) |
			(x[4] & 8) | (x[3] & 16) | (x[2] & 32) |
			(x[1] & 64) | (x[0] & 128);
	y[8] = (x[8] & 1) | (x[7] & 2) | (x[6] & 4) |
			(x[5] & 8) | (x[4] & 16) | (x[3] & 32) |
			(x[2] & 64) | (x[1] & 128);
	y[9] = (x[9] & 1) | (x[8] & 2) | (x[7] & 4) |
			(x[6] & 8) | (x[5] & 16) | (x[4] & 32) |
			(x[3] & 64) | (x[2] & 128);
	y[10] = (x[10] & 1) | (x[9] & 2) | (x[8] & 4) |
			(x[7] & 8) | (x[6] & 16) | (x[5] & 32) |
			(x[4] & 64) | (x[3] & 128);
	y[11] = (x[11] & 1) | (x[10] & 2) | (x[9] & 4) |
			(x[8] & 8) | (x[7] & 16) | (x[6] & 32) |
			(x[5] & 64) | (x[4] & 128);
	y[12] = (x[12] & 1) | (x[11] & 2) | (x[10] & 4) |
			(x[9] & 8) | (x[8] & 16) | (x[7] & 32) |
			(x[6] & 64) | (x[5] & 128);
	y[13] = (x[13] & 1) | (x[12] & 2) | (x[11] & 4) |
			(x[10] & 8) | (x[9] & 16) | (x[8] & 32) |
			(x[7] & 64) | (x[6] & 128);
	y[14] = (x[14] & 1) | (x[13] & 2) | (x[12] & 4) |
			(x[11] & 8) | (x[10] & 16) | (x[9] & 32) |
			(x[8] & 64) | (x[7] & 128);
	y[15] = (x[15] & 1) | (x[14] & 2) | (x[13] & 4) |
			(x[12] & 8) | (x[11] & 16) | (x[10] & 32) |
			(x[9] & 64) | (x[8] & 128);

	memcpy(x, y, 16);
}

#endif // DIAMOND_USE_PERMTABLE

void Diamond2::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	const byte *x = inBlock;
	byte y[16];

	substitute(0, y, x);
	for (int round=1; round < numrounds; round++)
	{
		permute(y);
		substitute(round, y, y);
	}

	if (xorBlock)
		xorbuf(outBlock, xorBlock, y, BLOCKSIZE);
	else
		memcpy(outBlock, y, BLOCKSIZE);
}

void Diamond2::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	const byte *x = inBlock;
	byte y[16];

	substitute(numrounds-1, y, x);
	for (int round=numrounds-2; round >= 0; round--)
	{
		ipermute(y);
		substitute(round, y, y);
	}

	if (xorBlock)
		xorbuf(outBlock, xorBlock, y, BLOCKSIZE);
	else
		memcpy(outBlock, y, BLOCKSIZE);
}

void Diamond2Lite::Base::UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length, unsigned int rounds)
{
	AssertValidKeyLength(length);

	numrounds = rounds;
	s.New(numrounds * ROUNDSIZE);

	Diamond2SboxMaker m(userKey, length, rounds, true);
	m.MakeSbox(s, direction);
}

inline void Diamond2Lite::Base::substitute(int round, byte *x, const byte *y) const
{
	const byte *sbox = s + (ROUNDSIZE*round);
	x[0] = sbox[0*256+y[0]];
	x[1] = sbox[1*256+y[1]];
	x[2] = sbox[2*256+y[2]];
	x[3] = sbox[3*256+y[3]];
	x[4] = sbox[4*256+y[4]];
	x[5] = sbox[5*256+y[5]];
	x[6] = sbox[6*256+y[6]];
	x[7] = sbox[7*256+y[7]];
}

#ifdef DIAMOND_USE_PERMTABLE

inline void Diamond2Lite::Base::permute(byte *a)
{
	word32 temp      = permtable[0][a[0]] | permtable[1][a[1]] |
					   permtable[2][a[2]] | permtable[3][a[3]] |
					   permtable[4][a[4]] | permtable[5][a[5]] |
					   permtable[6][a[6]] | permtable[7][a[7]];

	((word32 *)a)[1] = permtable[0][a[4]] | permtable[1][a[5]] |
					   permtable[2][a[6]] | permtable[3][a[7]] |
					   permtable[4][a[0]] | permtable[5][a[1]] |
					   permtable[6][a[2]] | permtable[7][a[3]];

	((word32 *)a)[0] = temp;
}

inline void Diamond2Lite::Base::ipermute(byte *a)
{
	word32 temp      = ipermtable[0][a[0]] | ipermtable[1][a[1]] |
					   ipermtable[2][a[2]] | ipermtable[3][a[3]] |
					   ipermtable[4][a[4]] | ipermtable[5][a[5]] |
					   ipermtable[6][a[6]] | ipermtable[7][a[7]];

	((word32 *)a)[1] = ipermtable[0][a[4]] | ipermtable[1][a[5]] |
					   ipermtable[2][a[6]] | ipermtable[3][a[7]] |
					   ipermtable[4][a[0]] | ipermtable[5][a[1]] |
					   ipermtable[6][a[2]] | ipermtable[7][a[3]];

	((word32 *)a)[0] = temp;
}

#else

inline void Diamond2Lite::Base::permute(byte *a)
{
	byte b[8];

	b[0] = (a[0] & 1) + (a[1] & 2) + (a[2] & 4) + (a[3] & 8) + (a[4] & 0x10) +
		(a[5] & 0x20) + (a[6] & 0x40) + (a[7] & 0x80);
	b[1] = (a[1] & 1) + (a[2] & 2) + (a[3] & 4) + (a[4] & 8) + (a[5] & 0x10) +
		(a[6] & 0x20) + (a[7] & 0x40) + (a[0] & 0x80);
	b[2] = (a[2] & 1) + (a[3] & 2) + (a[4] & 4) + (a[5] & 8) + (a[6] & 0x10) +
		(a[7] & 0x20) + (a[0] & 0x40) + (a[1] & 0x80);
	b[3] = (a[3] & 1) + (a[4] & 2) + (a[5] & 4) + (a[6] & 8) + (a[7] & 0x10) +
		(a[0] & 0x20) + (a[1] & 0x40) + (a[2] & 0x80);
	b[4] = (a[4] & 1) + (a[5] & 2) + (a[6] & 4) + (a[7] & 8) + (a[0] & 0x10) +
		(a[1] & 0x20) + (a[2] & 0x40) + (a[3] & 0x80);
	b[5] = (a[5] & 1) + (a[6] & 2) + (a[7] & 4) + (a[0] & 8) + (a[1] & 0x10) +
		(a[2] & 0x20) + (a[3] & 0x40) + (a[4] & 0x80);
	b[6] = (a[6] & 1) + (a[7] & 2) + (a[0] & 4) + (a[1] & 8) + (a[2] & 0x10) +
		(a[3] & 0x20) + (a[4] & 0x40) + (a[5] & 0x80);
	b[7] = (a[7] & 1) + (a[0] & 2) + (a[1] & 4) + (a[2] & 8) + (a[3] & 0x10) +
		(a[4] & 0x20) + (a[5] & 0x40) + (a[6] & 0x80);

	memcpy(a, b, 8);
}

inline void Diamond2Lite::Base::ipermute(byte *b)
{
	byte a[8];

	a[0] = (b[0] & 1) + (b[7] & 2) + (b[6] & 4) + (b[5] & 8) + (b[4] & 0x10) +
		(b[3] & 0x20) + (b[2] & 0x40) + (b[1] & 0x80);
	a[1] = (b[1] & 1) + (b[0] & 2) + (b[7] & 4) + (b[6] & 8) + (b[5] & 0x10) +
		(b[4] & 0x20) + (b[3] & 0x40) + (b[2] & 0x80);
	a[2] = (b[2] & 1) + (b[1] & 2) + (b[0] & 4) + (b[7] & 8) + (b[6] & 0x10) +
		(b[5] & 0x20) + (b[4] & 0x40) + (b[3] & 0x80);
	a[3] = (b[3] & 1) + (b[2] & 2) + (b[1] & 4) + (b[0] & 8) + (b[7] & 0x10) +
		(b[6] & 0x20) + (b[5] & 0x40) + (b[4] & 0x80);
	a[4] = (b[4] & 1) + (b[3] & 2) + (b[2] & 4) + (b[1] & 8) + (b[0] & 0x10) +
		(b[7] & 0x20) + (b[6] & 0x40) + (b[5] & 0x80);
	a[5] = (b[5] & 1) + (b[4] & 2) + (b[3] & 4) + (b[2] & 8) + (b[1] & 0x10) +
		(b[0] & 0x20) + (b[7] & 0x40) + (b[6] & 0x80);
	a[6] = (b[6] & 1) + (b[5] & 2) + (b[4] & 4) + (b[3] & 8) + (b[2] & 0x10) +
		(b[1] & 0x20) + (b[0] & 0x40) + (b[7] & 0x80);
	a[7] = (b[7] & 1) + (b[6] & 2) + (b[5] & 4) + (b[4] & 8) + (b[3] & 0x10) +
		(b[2] & 0x20) + (b[1] & 0x40) + (b[0] & 0x80);

	memcpy(b, a, 8);
}

#endif // DIAMOND_USE_PERMTABLE

void Diamond2Lite::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	const byte *x = inBlock;
	byte y[8];

	substitute(0, y, x);
	for (int round=1; round < numrounds; round++)
	{
		permute(y);
		substitute(round, y, y);
	}

	if (xorBlock)
		xorbuf(outBlock, xorBlock, y, BLOCKSIZE);
	else
		memcpy(outBlock, y, BLOCKSIZE);
}

void Diamond2Lite::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	const byte *x = inBlock;
	byte y[8];

	substitute(numrounds-1, y, x);
	for (int round=numrounds-2; round >= 0; round--)
	{
		ipermute(y);
		substitute(round, y, y);
	}

	if (xorBlock)
		xorbuf(outBlock, xorBlock, y, BLOCKSIZE);
	else
		memcpy(outBlock, y, BLOCKSIZE);
}

NAMESPACE_END
