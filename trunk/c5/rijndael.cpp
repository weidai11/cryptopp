// rijndael.cpp - modified by Chris Morgan <cmorgan@wpi.edu>
// and Wei Dai from Paulo Baretto's Rijndael implementation
// The original code and all modifications are in the public domain.

/*
Defense against timing attacks was added in July 2006 by Wei Dai.

The code now uses smaller tables in the first and last rounds,
and preloads them into L1 cache before usage (by loading at least 
one element in each cache line). 

We try to delay subsequent accesses to each table (used in the first 
and last rounds) until all of the table has been preloaded. Hopefully
the compiler isn't smart enough to optimize that code away.

After preloading the table, we also try not to access any memory location
other than the table and the stack, in order to prevent table entries from 
being unloaded from L1 cache, until that round is finished.
(Some popular CPUs have 2-way associative caches.)
*/

// This is the original introductory comment:

/**
 * version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "rijndael.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

void Rijndael::Base::UncheckedSetKey(const byte *userKey, unsigned int keylen, const NameValuePairs &)
{
	AssertValidKeyLength(keylen);

	m_rounds = keylen/4 + 6;
	m_key.New(4*(m_rounds+1));

	word32 temp, *rk = m_key;
	const word32 *rc = rcon;

	GetUserKey(BIG_ENDIAN_ORDER, rk, keylen/4, userKey, keylen);

	while (true)
	{
		temp  = rk[keylen/4-1];
		rk[keylen/4] = rk[0] ^
			(word32(Se[GETBYTE(temp, 2)]) << 24) ^
			(word32(Se[GETBYTE(temp, 1)]) << 16) ^
			(word32(Se[GETBYTE(temp, 0)]) << 8) ^
			Se[GETBYTE(temp, 3)] ^
			*(rc++);
		rk[keylen/4+1] = rk[1] ^ rk[keylen/4];
		rk[keylen/4+2] = rk[2] ^ rk[keylen/4+1];
		rk[keylen/4+3] = rk[3] ^ rk[keylen/4+2];

		if (rk + keylen/4 + 4 == m_key.end())
			break;

		if (keylen == 24)
		{
			rk[10] = rk[ 4] ^ rk[ 9];
			rk[11] = rk[ 5] ^ rk[10];
		}
		else if (keylen == 32)
		{
    		temp = rk[11];
    		rk[12] = rk[ 4] ^
				(word32(Se[GETBYTE(temp, 3)]) << 24) ^
				(word32(Se[GETBYTE(temp, 2)]) << 16) ^
				(word32(Se[GETBYTE(temp, 1)]) << 8) ^
				Se[GETBYTE(temp, 0)];
    		rk[13] = rk[ 5] ^ rk[12];
    		rk[14] = rk[ 6] ^ rk[13];
    		rk[15] = rk[ 7] ^ rk[14];
		}
		rk += keylen/4;
	}

	if (!IsForwardTransformation())
	{
		unsigned int i, j;
		rk = m_key;

		/* invert the order of the round keys: */
		for (i = 0, j = 4*m_rounds; i < j; i += 4, j -= 4) {
			temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
			temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
			temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
			temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
		}
		/* apply the inverse MixColumn transform to all round keys but the first and the last: */
		for (i = 1; i < m_rounds; i++) {
			rk += 4;
			rk[0] =
				Td[0*256+Se[GETBYTE(rk[0], 3)]] ^
				Td[1*256+Se[GETBYTE(rk[0], 2)]] ^
				Td[2*256+Se[GETBYTE(rk[0], 1)]] ^
				Td[3*256+Se[GETBYTE(rk[0], 0)]];
			rk[1] =
				Td[0*256+Se[GETBYTE(rk[1], 3)]] ^
				Td[1*256+Se[GETBYTE(rk[1], 2)]] ^
				Td[2*256+Se[GETBYTE(rk[1], 1)]] ^
				Td[3*256+Se[GETBYTE(rk[1], 0)]];
			rk[2] =
				Td[0*256+Se[GETBYTE(rk[2], 3)]] ^
				Td[1*256+Se[GETBYTE(rk[2], 2)]] ^
				Td[2*256+Se[GETBYTE(rk[2], 1)]] ^
				Td[3*256+Se[GETBYTE(rk[2], 0)]];
			rk[3] =
				Td[0*256+Se[GETBYTE(rk[3], 3)]] ^
				Td[1*256+Se[GETBYTE(rk[3], 2)]] ^
				Td[2*256+Se[GETBYTE(rk[3], 1)]] ^
				Td[3*256+Se[GETBYTE(rk[3], 0)]];
		}
	}

	ConditionalByteReverse(BIG_ENDIAN_ORDER, m_key.begin(), m_key.begin(), 16);
	ConditionalByteReverse(BIG_ENDIAN_ORDER, m_key + m_rounds*4, m_key + m_rounds*4, 16);
}

#pragma warning(disable: 4731)	// frame pointer register 'ebp' modified by inline assembly code

void Rijndael::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
#ifdef CRYPTOPP_X86_ASM_AVAILABLE
	if (HasMMX())
	{
		const word32 *k = m_key;
		const word32 *kLoopEnd = k + m_rounds*4;
#ifdef __GNUC__
		word32 t0, t1, t2, t3;
		__asm__ __volatile__
		(
		".intel_syntax noprefix;"
		AS1(	push	ebx)
		AS1(	push	ebp)
		AS2(	mov		ebp, eax)
		AS2(	movd	mm5, ecx)
#else
		AS2(	mov		edx, g_cacheLineSize)
		AS2(	mov		edi, inBlock)
		AS2(	mov		esi, k)
		AS2(	movd	mm5, kLoopEnd)
		AS1(	push	ebp)
		AS2(	lea		ebp, Te)
#endif
		AS2(	mov		eax, [esi+0*4])	// s0
		AS2(	xor		eax, [edi+0*4])
		AS2(	movd	mm0, eax)
		AS2(	mov		ebx, [esi+1*4])
		AS2(	xor		ebx, [edi+1*4])
		AS2(	movd	mm1, ebx)
		AS2(	and		ebx, eax)
		AS2(	mov		eax, [esi+2*4])
		AS2(	xor		eax, [edi+2*4])
		AS2(	movd	mm2, eax)
		AS2(	and		ebx, eax)
		AS2(	mov		ecx, [esi+3*4])
		AS2(	xor		ecx, [edi+3*4])
		AS2(	and		ebx, ecx)

		// read Te0 into L1 cache. this code could be simplifed by using lfence, but that is an SSE2 instruction
		AS2(	and		ebx, 0)
		AS2(	mov		edi, ebx)	// make index depend on previous loads to simulate lfence
		ASL(2)
		AS2(	and		ebx, [ebp+edi])
		AS2(	add		edi, edx)
		AS2(	and		ebx, [ebp+edi])
		AS2(	add		edi, edx)
		AS2(	and		ebx, [ebp+edi])
		AS2(	add		edi, edx)
		AS2(	and		ebx, [ebp+edi])
		AS2(	add		edi, edx)
		AS2(	cmp		edi, 1024)
		ASJ(	jl,		2, b)
		AS2(	and		ebx, [ebp+1020])
		AS2(	movd	mm6, ebx)
		AS2(	pxor	mm2, mm6)
		AS2(	pxor	mm1, mm6)
		AS2(	pxor	mm0, mm6)
		AS2(	xor		ecx, ebx)

		AS2(	mov		edi, [esi+4*4])	// t0
		AS2(	mov		eax, [esi+5*4])
		AS2(	mov		ebx, [esi+6*4])
		AS2(	mov		edx, [esi+7*4])
		AS2(	add		esi, 8*4)
		AS2(	movd	mm4, esi)

#define QUARTER_ROUND(t, a, b, c, d)	\
	AS2(movzx esi, t##l)\
	AS2(d, [ebp+0*1024+4*esi])\
	AS2(movzx esi, t##h)\
	AS2(c, [ebp+1*1024+4*esi])\
	AS2(shr e##t##x, 16)\
	AS2(movzx esi, t##l)\
	AS2(b, [ebp+2*1024+4*esi])\
	AS2(movzx esi, t##h)\
	AS2(a, [ebp+3*1024+4*esi])

#define s0		xor edi
#define s1		xor eax
#define s2		xor ebx
#define s3		xor ecx
#define t0		xor edi
#define t1		xor eax
#define t2		xor ebx
#define t3		xor edx

		QUARTER_ROUND(c, t0, t1, t2, t3)
		AS2(	movd	ecx, mm2)
		QUARTER_ROUND(c, t3, t0, t1, t2)
		AS2(	movd	ecx, mm1)
		QUARTER_ROUND(c, t2, t3, t0, t1)
		AS2(	movd	ecx, mm0)
		QUARTER_ROUND(c, t1, t2, t3, t0)
		AS2(	movd	mm2, ebx)
		AS2(	movd	mm1, eax)
		AS2(	movd	mm0, edi)
#undef QUARTER_ROUND

		AS2(	movd	esi, mm4)

		ASL(0)
		AS2(	mov		edi, [esi+0*4])
		AS2(	mov		eax, [esi+1*4])
		AS2(	mov		ebx, [esi+2*4])
		AS2(	mov		ecx, [esi+3*4])

#define QUARTER_ROUND(t, a, b, c, d)	\
	AS2(movzx esi, t##l)\
	AS2(a, [ebp+3*1024+4*esi])\
	AS2(movzx esi, t##h)\
	AS2(b, [ebp+2*1024+4*esi])\
	AS2(shr e##t##x, 16)\
	AS2(movzx esi, t##l)\
	AS2(c, [ebp+1*1024+4*esi])\
	AS2(movzx esi, t##h)\
	AS2(d, [ebp+0*1024+4*esi])

		QUARTER_ROUND(d, s0, s1, s2, s3)
		AS2(	movd	edx, mm2)
		QUARTER_ROUND(d, s3, s0, s1, s2)
		AS2(	movd	edx, mm1)
		QUARTER_ROUND(d, s2, s3, s0, s1)
		AS2(	movd	edx, mm0)
		QUARTER_ROUND(d, s1, s2, s3, s0)
		AS2(	movd	esi, mm4)
		AS2(	movd	mm2, ebx)
		AS2(	movd	mm1, eax)
		AS2(	movd	mm0, edi)

		AS2(	mov		edi, [esi+4*4])
		AS2(	mov		eax, [esi+5*4])
		AS2(	mov		ebx, [esi+6*4])
		AS2(	mov		edx, [esi+7*4])

		QUARTER_ROUND(c, t0, t1, t2, t3)
		AS2(	movd	ecx, mm2)
		QUARTER_ROUND(c, t3, t0, t1, t2)
		AS2(	movd	ecx, mm1)
		QUARTER_ROUND(c, t2, t3, t0, t1)
		AS2(	movd	ecx, mm0)
		QUARTER_ROUND(c, t1, t2, t3, t0)
		AS2(	movd	mm2, ebx)
		AS2(	movd	mm1, eax)
		AS2(	movd	mm0, edi)

		AS2(	movd	esi, mm4)
		AS2(	movd	edi, mm5)
		AS2(	add		esi, 8*4)
		AS2(	movd	mm4, esi)
		AS2(	cmp		edi, esi)
		ASJ(	jne,	0, b)

#undef QUARTER_ROUND
#undef s0
#undef s1
#undef s2
#undef s3
#undef t0
#undef t1
#undef t2
#undef t3

		AS2(	mov		eax, [edi+0*4])
		AS2(	mov		ecx, [edi+1*4])
		AS2(	mov		esi, [edi+2*4])
		AS2(	mov		edi, [edi+3*4])

#define QUARTER_ROUND(a, b, c, d)	\
	AS2(	movzx	ebx, dl)\
	AS2(	movzx	ebx, BYTE PTR [ebp+1+4*ebx])\
	AS2(	shl		ebx, 3*8)\
	AS2(	xor		a, ebx)\
	AS2(	movzx	ebx, dh)\
	AS2(	movzx	ebx, BYTE PTR [ebp+1+4*ebx])\
	AS2(	shl		ebx, 2*8)\
	AS2(	xor		b, ebx)\
	AS2(	shr		edx, 16)\
	AS2(	movzx	ebx, dl)\
	AS2(	shr		edx, 8)\
	AS2(	movzx	ebx, BYTE PTR [ebp+1+4*ebx])\
	AS2(	shl		ebx, 1*8)\
	AS2(	xor		c, ebx)\
	AS2(	movzx	ebx, BYTE PTR [ebp+1+4*edx])\
	AS2(	xor		d, ebx)

		QUARTER_ROUND(eax, ecx, esi, edi)
		AS2(	movd	edx, mm2)
		QUARTER_ROUND(edi, eax, ecx, esi)
		AS2(	movd	edx, mm1)
		QUARTER_ROUND(esi, edi, eax, ecx)
		AS2(	movd	edx, mm0)
		QUARTER_ROUND(ecx, esi, edi, eax)

#undef QUARTER_ROUND

		AS1(	pop		ebp)
		AS1(	emms)

#ifdef __GNUC__
		AS1(	pop		ebx)
		".att_syntax prefix;"
			: "=a" (t0), "=c" (t1), "=S" (t2), "=D" (t3)
			: "a" (Te), "D" (inBlock), "S" (k), "c" (kLoopEnd), "d" (g_cacheLineSize)
			: "memory", "cc"
		);

		if (xorBlock)
		{
			t0 ^= ((const word32 *)xorBlock)[0];
			t1 ^= ((const word32 *)xorBlock)[1];
			t2 ^= ((const word32 *)xorBlock)[2];
			t3 ^= ((const word32 *)xorBlock)[3];
		}
		((word32 *)outBlock)[0] = t0;
		((word32 *)outBlock)[1] = t1;
		((word32 *)outBlock)[2] = t2;
		((word32 *)outBlock)[3] = t3;
#else
		AS2(	mov		ebx, xorBlock)
		AS2(	test	ebx, ebx)
		ASJ(	jz,		1, f)
		AS2(	xor		eax, [ebx+0*4])
		AS2(	xor		ecx, [ebx+1*4])
		AS2(	xor		esi, [ebx+2*4])
		AS2(	xor		edi, [ebx+3*4])
		ASL(1)
		AS2(	mov		ebx, outBlock)
		AS2(	mov		[ebx+0*4], eax)
		AS2(	mov		[ebx+1*4], ecx)
		AS2(	mov		[ebx+2*4], esi)
		AS2(	mov		[ebx+3*4], edi)
#endif
	}
	else
#endif	// #ifdef CRYPTOPP_X86_ASM_AVAILABLE
	{
	word32 s0, s1, s2, s3, t0, t1, t2, t3;
	const word32 *rk = m_key;

	s0 = ((const word32 *)inBlock)[0] ^ rk[0];
	s1 = ((const word32 *)inBlock)[1] ^ rk[1];
	s2 = ((const word32 *)inBlock)[2] ^ rk[2];
	s3 = ((const word32 *)inBlock)[3] ^ rk[3];
	t0 = rk[4];
	t1 = rk[5];
	t2 = rk[6];
	t3 = rk[7];
	rk += 8;

	// timing attack countermeasure. see comments at top for more details
	const int cacheLineSize = GetCacheLineSize();
	unsigned int i;
	word32 u = 0;
	for (i=0; i<1024; i+=cacheLineSize)
		u &= *(const word32 *)(((const byte *)Te)+i);
	u &= Te[255];
	s0 |= u; s1 |= u; s2 |= u; s3 |= u;

	// first round
#ifdef IS_BIG_ENDIAN
#define QUARTER_ROUND(t, a, b, c, d)	\
		a ^= rotrFixed(Te[byte(t)], 24);	t >>= 8;\
		b ^= rotrFixed(Te[byte(t)], 16);	t >>= 8;\
		c ^= rotrFixed(Te[byte(t)], 8);	t >>= 8;\
		d ^= Te[t];
#else
#define QUARTER_ROUND(t, a, b, c, d)	\
		d ^= Te[byte(t)];					t >>= 8;\
		c ^= rotrFixed(Te[byte(t)], 8);	t >>= 8;\
		b ^= rotrFixed(Te[byte(t)], 16);	t >>= 8;\
		a ^= rotrFixed(Te[t], 24);
#endif

	QUARTER_ROUND(s3, t0, t1, t2, t3)
	QUARTER_ROUND(s2, t3, t0, t1, t2)
	QUARTER_ROUND(s1, t2, t3, t0, t1)
	QUARTER_ROUND(s0, t1, t2, t3, t0)
#undef QUARTER_ROUND

	// Nr - 2 full rounds:
    unsigned int r = m_rounds/2 - 1;
    do
	{
#define QUARTER_ROUND(t, a, b, c, d)	\
		a ^= Te[3*256+byte(t)]; t >>= 8;\
		b ^= Te[2*256+byte(t)]; t >>= 8;\
		c ^= Te[1*256+byte(t)]; t >>= 8;\
		d ^= Te[t];

		s0 = rk[0]; s1 = rk[1]; s2 = rk[2]; s3 = rk[3];

		QUARTER_ROUND(t3, s0, s1, s2, s3)
		QUARTER_ROUND(t2, s3, s0, s1, s2)
		QUARTER_ROUND(t1, s2, s3, s0, s1)
		QUARTER_ROUND(t0, s1, s2, s3, s0)

		t0 = rk[4]; t1 = rk[5]; t2 = rk[6]; t3 = rk[7];

		QUARTER_ROUND(s3, t0, t1, t2, t3)
		QUARTER_ROUND(s2, t3, t0, t1, t2)
		QUARTER_ROUND(s1, t2, t3, t0, t1)
		QUARTER_ROUND(s0, t1, t2, t3, t0)
#undef QUARTER_ROUND

        rk += 8;
    } while (--r);

	// timing attack countermeasure. see comments at top for more details
	u = 0;
	for (i=0; i<256; i+=cacheLineSize)
		u &= *(const word32 *)(Se+i);
	u &= *(const word32 *)(Se+252);
	t0 |= u; t1 |= u; t2 |= u; t3 |= u;

	word32 tbw[4];
	byte *const tempBlock = (byte *)tbw;
	word32 *const obw = (word32 *)outBlock;
	const word32 *const xbw = (const word32 *)xorBlock;

#define QUARTER_ROUND(t, a, b, c, d)	\
	tempBlock[a] = Se[byte(t)]; t >>= 8;\
	tempBlock[b] = Se[byte(t)]; t >>= 8;\
	tempBlock[c] = Se[byte(t)]; t >>= 8;\
	tempBlock[d] = Se[t];

	QUARTER_ROUND(t2, 15, 2, 5, 8)
	QUARTER_ROUND(t1, 11, 14, 1, 4)
	QUARTER_ROUND(t0, 7, 10, 13, 0)
	QUARTER_ROUND(t3, 3, 6, 9, 12)
#undef QUARTER_ROUND

	if (xbw)
	{
		obw[0] = tbw[0] ^ xbw[0] ^ rk[0];
		obw[1] = tbw[1] ^ xbw[1] ^ rk[1];
		obw[2] = tbw[2] ^ xbw[2] ^ rk[2];
		obw[3] = tbw[3] ^ xbw[3] ^ rk[3];
	}
	else
	{
		obw[0] = tbw[0] ^ rk[0];
		obw[1] = tbw[1] ^ rk[1];
		obw[2] = tbw[2] ^ rk[2];
		obw[3] = tbw[3] ^ rk[3];
	}
	}
}

void Rijndael::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	word32 s0, s1, s2, s3, t0, t1, t2, t3;
	const word32 *rk = m_key;

	s0 = ((const word32 *)inBlock)[0] ^ rk[0];
	s1 = ((const word32 *)inBlock)[1] ^ rk[1];
	s2 = ((const word32 *)inBlock)[2] ^ rk[2];
	s3 = ((const word32 *)inBlock)[3] ^ rk[3];
	t0 = rk[4];
	t1 = rk[5];
	t2 = rk[6];
	t3 = rk[7];
	rk += 8;

	// timing attack countermeasure. see comments at top for more details
	const int cacheLineSize = GetCacheLineSize();
	unsigned int i;
	word32 u = 0;
	for (i=0; i<1024; i+=cacheLineSize)
		u &= *(const word32 *)(((const byte *)Td)+i);
	u &= Td[255];
	s0 |= u; s1 |= u; s2 |= u; s3 |= u;

	// first round
#ifdef IS_BIG_ENDIAN
#define QUARTER_ROUND(t, a, b, c, d)	\
		a ^= rotrFixed(Td[byte(t)], 24);	t >>= 8;\
		b ^= rotrFixed(Td[byte(t)], 16);	t >>= 8;\
		c ^= rotrFixed(Td[byte(t)], 8);		t >>= 8;\
		d ^= Td[t];
#else
#define QUARTER_ROUND(t, a, b, c, d)	\
		d ^= Td[byte(t)];					t >>= 8;\
		c ^= rotrFixed(Td[byte(t)], 8);		t >>= 8;\
		b ^= rotrFixed(Td[byte(t)], 16);	t >>= 8;\
		a ^= rotrFixed(Td[t], 24);
#endif

	QUARTER_ROUND(s3, t2, t1, t0, t3)
	QUARTER_ROUND(s2, t1, t0, t3, t2)
	QUARTER_ROUND(s1, t0, t3, t2, t1)
	QUARTER_ROUND(s0, t3, t2, t1, t0)
#undef QUARTER_ROUND

	// Nr - 2 full rounds:
    unsigned int r = m_rounds/2 - 1;
    do
	{
#define QUARTER_ROUND(t, a, b, c, d)	\
		a ^= Td[3*256+byte(t)]; t >>= 8;\
		b ^= Td[2*256+byte(t)]; t >>= 8;\
		c ^= Td[1*256+byte(t)]; t >>= 8;\
		d ^= Td[t];

		s0 = rk[0]; s1 = rk[1]; s2 = rk[2]; s3 = rk[3];

		QUARTER_ROUND(t3, s2, s1, s0, s3)
		QUARTER_ROUND(t2, s1, s0, s3, s2)
		QUARTER_ROUND(t1, s0, s3, s2, s1)
		QUARTER_ROUND(t0, s3, s2, s1, s0)

		t0 = rk[4]; t1 = rk[5]; t2 = rk[6]; t3 = rk[7];

		QUARTER_ROUND(s3, t2, t1, t0, t3)
		QUARTER_ROUND(s2, t1, t0, t3, t2)
		QUARTER_ROUND(s1, t0, t3, t2, t1)
		QUARTER_ROUND(s0, t3, t2, t1, t0)
#undef QUARTER_ROUND

        rk += 8;
    } while (--r);

	// timing attack countermeasure. see comments at top for more details
	u = 0;
	for (i=0; i<256; i+=cacheLineSize)
		u &= *(const word32 *)(Sd+i);
	u &= *(const word32 *)(Sd+252);
	t0 |= u; t1 |= u; t2 |= u; t3 |= u;

	word32 tbw[4];
	byte *const tempBlock = (byte *)tbw;
	word32 *const obw = (word32 *)outBlock;
	const word32 *const xbw = (const word32 *)xorBlock;

#define QUARTER_ROUND(t, a, b, c, d)	\
	tempBlock[a] = Sd[byte(t)]; t >>= 8;\
	tempBlock[b] = Sd[byte(t)]; t >>= 8;\
	tempBlock[c] = Sd[byte(t)]; t >>= 8;\
	tempBlock[d] = Sd[t];

	QUARTER_ROUND(t2, 7, 2, 13, 8)
	QUARTER_ROUND(t1, 3, 14, 9, 4)
	QUARTER_ROUND(t0, 15, 10, 5, 0)
	QUARTER_ROUND(t3, 11, 6, 1, 12)
#undef QUARTER_ROUND

	if (xbw)
	{
		obw[0] = tbw[0] ^ xbw[0] ^ rk[0];
		obw[1] = tbw[1] ^ xbw[1] ^ rk[1];
		obw[2] = tbw[2] ^ xbw[2] ^ rk[2];
		obw[3] = tbw[3] ^ xbw[3] ^ rk[3];
	}
	else
	{
		obw[0] = tbw[0] ^ rk[0];
		obw[1] = tbw[1] ^ rk[1];
		obw[2] = tbw[2] ^ rk[2];
		obw[3] = tbw[3] ^ rk[3];
	}
}

NAMESPACE_END

#endif
