// mars.cpp - modified by Sean Woods from Brian Gladman's mars6.c for Crypto++
// key setup updated by Wei Dai to reflect IBM's "tweak" proposed in August 1999

/* This is an independent implementation of the MARS encryption         */
/* algorithm designed by a team at IBM as a candidate for the US        */
/* NIST Advanced Encryption Standard (AES) effort. The algorithm        */
/* is subject to Patent action by IBM, who intend to offer royalty      */
/* free use if a Patent is granted.                                     */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but       */
/* I hereby give permission for its free direct or derivative use       */
/* subject to acknowledgment of its origin and compliance with any      */
/* constraints that IBM place on the use of the MARS algorithm.         */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 4th October 1998      */

#include "pch.h"
#include "mars.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

ANONYMOUS_NAMESPACE_BEGIN
static word32 gen_mask(word32 x)
{
	word32	m;

	m = (~x ^ (x >> 1)) & 0x7fffffff;
	m &= (m >> 1) & (m >> 2); m &= (m >> 3) & (m >> 6); 

	if(!m)
		return 0;

	m <<= 1; m |= (m << 1); m |= (m << 2); m |= (m << 4);
	m |= (m << 1) & ~x & 0x80000000;

	return m & 0xfffffffc;
};
NAMESPACE_END

void MARS::Base::UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs &)
{
	AssertValidKeyLength(length);

	// Initialize T[] with the key data
	FixedSizeSecBlock<word32, 15> T;
	GetUserKey(LITTLE_ENDIAN_ORDER, T.begin(), 15, userKey, length);
	T[length/4] = length/4;

	for (unsigned int j=0; j<4; j++)	// compute 10 words of K[] in each iteration
	{
		unsigned int i;
		// Do linear transformation
		for (i=0; i<15; i++)
			T[i] = T[i] ^ rotlFixed(T[(i+8)%15] ^ T[(i+13)%15], 3) ^ (4*i+j);

		// Do four rounds of stirring
		for (unsigned int k=0; k<4; k++)
			for (i=0; i<15; i++)
			   T[i] = rotlFixed(T[i] + Sbox[T[(i+14)%15]%512], 9);

		// Store next 10 key words into K[]
		for (i=0; i<10; i++)
			EK[10*j+i] = T[4*i%15];
	}

	// Modify multiplication key-words
	for(unsigned int i = 5; i < 37; i += 2)
	{
		word32 w = EK[i] | 3;
		word32 m = gen_mask(w);
		if(m)
			w ^= (rotlMod(Sbox[265 + (EK[i] & 3)], EK[i-1]) & m);
		EK[i] = w;
	}
}

#define f_mix(a,b,c,d)					\
		r = rotrFixed(a, 8); 				\
		b ^= Sbox[a & 255];				\
		b += Sbox[(r & 255) + 256];		\
		r = rotrFixed(a, 16);				\
		a  = rotrFixed(a, 24);				\
		c += Sbox[r & 255];				\
		d ^= Sbox[(a & 255) + 256]

#define b_mix(a,b,c,d)					\
		r = rotlFixed(a, 8); 				\
		b ^= Sbox[(a & 255) + 256];		\
		c -= Sbox[r & 255];				\
		r = rotlFixed(a, 16);				\
		a  = rotlFixed(a, 24);				\
		d -= Sbox[(r & 255) + 256];		\
		d ^= Sbox[a & 255]

#define f_ktr(a,b,c,d,i)	\
	m = a + EK[i];			\
	a = rotlFixed(a, 13);		\
	r = a * EK[i + 1];		\
	l = Sbox[m & 511]; 		\
	r = rotlFixed(r, 5); 		\
	l ^= r; 				\
	c += rotlMod(m, r);		\
	r = rotlFixed(r, 5); 		\
	l ^= r; 				\
	d ^= r; 				\
	b += rotlMod(l, r)

#define r_ktr(a,b,c,d,i)	\
	r = a * EK[i + 1];		\
	a = rotrFixed(a, 13);		\
	m = a + EK[i];			\
	l = Sbox[m & 511]; 		\
	r = rotlFixed(r, 5); 		\
	l ^= r; 				\
	c -= rotlMod(m, r);		\
	r = rotlFixed(r, 5); 		\
	l ^= r; 				\
	d ^= r; 				\
	b -= rotlMod(l, r)

typedef BlockGetAndPut<word32, LittleEndian> Block;

void MARS::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	word32 a, b, c, d, l, m, r;
	
	Block::Get(inBlock)(a)(b)(c)(d);

	a += EK[0];
	b += EK[1];
	c += EK[2];
	d += EK[3];

	int i;
	for (i = 0; i < 2; i++) {
		f_mix(a,b,c,d);
		a += d;
		f_mix(b,c,d,a);
		b += c;
		f_mix(c,d,a,b);
		f_mix(d,a,b,c);
	}

	f_ktr(a,b,c,d, 4); f_ktr(b,c,d,a, 6); f_ktr(c,d,a,b, 8); f_ktr(d,a,b,c,10); 
	f_ktr(a,b,c,d,12); f_ktr(b,c,d,a,14); f_ktr(c,d,a,b,16); f_ktr(d,a,b,c,18); 
	f_ktr(a,d,c,b,20); f_ktr(b,a,d,c,22); f_ktr(c,b,a,d,24); f_ktr(d,c,b,a,26); 
	f_ktr(a,d,c,b,28); f_ktr(b,a,d,c,30); f_ktr(c,b,a,d,32); f_ktr(d,c,b,a,34); 

	for (i = 0; i < 2; i++) {
		b_mix(a,b,c,d);
		b_mix(b,c,d,a);
		c -= b;
		b_mix(c,d,a,b);
		d -= a;
		b_mix(d,a,b,c);
	}

	a -= EK[36];
	b -= EK[37];
	c -= EK[38];
	d -= EK[39];

	Block::Put(xorBlock, outBlock)(a)(b)(c)(d);
}

void MARS::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	word32 a, b, c, d, l, m, r;

	Block::Get(inBlock)(d)(c)(b)(a);
	
	d += EK[36];
	c += EK[37];
	b += EK[38];
	a += EK[39];

	int i;
	for (i = 0; i < 2; i++) {
		f_mix(a,b,c,d);
		a += d;
		f_mix(b,c,d,a);
		b += c;
		f_mix(c,d,a,b);
		f_mix(d,a,b,c);
	}

	r_ktr(a,b,c,d,34); r_ktr(b,c,d,a,32); r_ktr(c,d,a,b,30); r_ktr(d,a,b,c,28);
	r_ktr(a,b,c,d,26); r_ktr(b,c,d,a,24); r_ktr(c,d,a,b,22); r_ktr(d,a,b,c,20);
	r_ktr(a,d,c,b,18); r_ktr(b,a,d,c,16); r_ktr(c,b,a,d,14); r_ktr(d,c,b,a,12);
	r_ktr(a,d,c,b,10); r_ktr(b,a,d,c, 8); r_ktr(c,b,a,d, 6); r_ktr(d,c,b,a, 4);

	for (i = 0; i < 2; i++) {
		b_mix(a,b,c,d);
		b_mix(b,c,d,a);
		c -= b;
		b_mix(c,d,a,b);
		d -= a;
		b_mix(d,a,b,c);
	}

	d -= EK[0];
	c -= EK[1];
	b -= EK[2];
	a -= EK[3];

	Block::Put(xorBlock, outBlock)(d)(c)(b)(a);
}

NAMESPACE_END
