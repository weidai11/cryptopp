// rijndael.cpp - modified by Chris Morgan <cmorgan@wpi.edu>
// and Wei Dai from Paulo Baretto's Rijndael implementation
// The original code and all modifications are in the public domain.

// use "cl /EP /P /DCRYPTOPP_GENERATE_X64_MASM rijndael.cpp" to generate MASM code

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
#ifndef CRYPTOPP_GENERATE_X64_MASM

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

#ifdef CRYPTOPP_X64_MASM_AVAILABLE
extern "C" {
void Rijndael_Enc_ProcessAndXorBlock(const word32 *table, word32 cacheLineSize, const word32 *k, const word32 *kLoopEnd, const byte *inBlock, const byte *xorBlock, byte *outBlock);
}
#endif

#pragma warning(disable: 4731)	// frame pointer register 'ebp' modified by inline assembly code

void Rijndael::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
#endif	// #ifdef CRYPTOPP_GENERATE_X64_MASM

#ifdef CRYPTOPP_X64_MASM_AVAILABLE
	Rijndael_Enc_ProcessAndXorBlock(Te, g_cacheLineSize, m_key, m_key + m_rounds*4, inBlock, xorBlock, outBlock);
	return;
#endif

#if defined(CRYPTOPP_X86_ASM_AVAILABLE)
	#ifdef CRYPTOPP_GENERATE_X64_MASM
		ALIGN   8
	Rijndael_Enc_ProcessAndXorBlock	PROC FRAME
		rex_push_reg rbx
		push_reg rsi
		push_reg rdi
		push_reg r12
		push_reg r13
		push_reg r14
		push_reg r15
		.endprolog
		mov		AS_REG_7, rcx
		mov		rdi, [rsp + 5*8 + 7*8]			; inBlock
	#else
	if (HasMMX())
	{
		const word32 *k = m_key;
		const word32 *kLoopEnd = k + m_rounds*4;
	#endif

		#if CRYPTOPP_BOOL_X64
			#define K_REG			r8
			#define K_END_REG		r9
			#define SAVE_K
			#define RESTORE_K
			#define RESTORE_K_END
			#define SAVE_0(x)		AS2(mov	r13d, x)
			#define SAVE_1(x)		AS2(mov	r14d, x)
			#define SAVE_2(x)		AS2(mov	r15d, x)
			#define RESTORE_0(x)	AS2(mov	x, r13d)
			#define RESTORE_1(x)	AS2(mov	x, r14d)
			#define RESTORE_2(x)	AS2(mov	x, r15d)
		#else
			#define K_REG			esi
			#define K_END_REG		edi
			#define SAVE_K			AS2(movd	mm4, esi)
			#define RESTORE_K		AS2(movd	esi, mm4)
			#define RESTORE_K_END	AS2(movd	edi, mm5)
			#define SAVE_0(x)		AS2(movd	mm0, x)
			#define SAVE_1(x)		AS2(movd	mm1, x)
			#define SAVE_2(x)		AS2(movd	mm2, x)
			#define RESTORE_0(x)	AS2(movd	x, mm0)
			#define RESTORE_1(x)	AS2(movd	x, mm1)
			#define RESTORE_2(x)	AS2(movd	x, mm2)
		#endif
#ifdef __GNUC__
		word32 t0, t1, t2, t3;
		__asm__ __volatile__
		(
		".intel_syntax noprefix;"
	#if CRYPTOPP_BOOL_X64
		AS2(	mov		K_REG, rsi)
		AS2(	mov		K_END_REG, rcx)
	#else
		AS1(	push	ebx)
		AS1(	push	ebp)
		AS2(	movd	mm5, ecx)
	#endif
		AS2(	mov		AS_REG_7, WORD_REG(ax))
#elif CRYPTOPP_BOOL_X86
	#if _MSC_VER < 1300
		const word32 *t = Te;
		AS2(	mov		eax, t)
	#endif
		AS2(	mov		edx, g_cacheLineSize)
		AS2(	mov		WORD_REG(di), inBlock)
		AS2(	mov		K_REG, k)
		AS2(	movd	mm5, kLoopEnd)
	#if _MSC_VER < 1300
		AS1(	push	ebx)
		AS1(	push	ebp)
		AS2(	mov		AS_REG_7, eax)
	#else
		AS1(	push	ebp)
		AS2(	lea		AS_REG_7, Te)
	#endif
#endif
		AS2(	mov		eax, [K_REG+0*4])	// s0
		AS2(	xor		eax, [WORD_REG(di)+0*4])
		SAVE_0(eax)
		AS2(	mov		ebx, [K_REG+1*4])
		AS2(	xor		ebx, [WORD_REG(di)+1*4])
		SAVE_1(ebx)
		AS2(	and		ebx, eax)
		AS2(	mov		eax, [K_REG+2*4])
		AS2(	xor		eax, [WORD_REG(di)+2*4])
		SAVE_2(eax)
		AS2(	and		ebx, eax)
		AS2(	mov		ecx, [K_REG+3*4])
		AS2(	xor		ecx, [WORD_REG(di)+3*4])
		AS2(	and		ebx, ecx)

		// read Te0 into L1 cache. this code could be simplifed by using lfence, but that is an SSE2 instruction
		AS2(	and		ebx, 0)
		AS2(	mov		edi, ebx)	// make index depend on previous loads to simulate lfence
		ASL(2)
		AS2(	and		ebx, [AS_REG_7+WORD_REG(di)])
		AS2(	add		edi, edx)
		AS2(	and		ebx, [AS_REG_7+WORD_REG(di)])
		AS2(	add		edi, edx)
		AS2(	and		ebx, [AS_REG_7+WORD_REG(di)])
		AS2(	add		edi, edx)
		AS2(	and		ebx, [AS_REG_7+WORD_REG(di)])
		AS2(	add		edi, edx)
		AS2(	cmp		edi, 1024)
		ASJ(	jl,		2, b)
		AS2(	and		ebx, [AS_REG_7+1020])
#if CRYPTOPP_BOOL_X64
		AS2(	xor		r13d, ebx)
		AS2(	xor		r14d, ebx)
		AS2(	xor		r15d, ebx)
#else
		AS2(	movd	mm6, ebx)
		AS2(	pxor	mm2, mm6)
		AS2(	pxor	mm1, mm6)
		AS2(	pxor	mm0, mm6)
#endif
		AS2(	xor		ecx, ebx)

		AS2(	mov		edi, [K_REG+4*4])	// t0
		AS2(	mov		eax, [K_REG+5*4])
		AS2(	mov		ebx, [K_REG+6*4])
		AS2(	mov		edx, [K_REG+7*4])
		AS2(	add		K_REG, 8*4)
		SAVE_K

#define QUARTER_ROUND(t, a, b, c, d)	\
	AS2(movzx esi, t##l)\
	AS2(d, [AS_REG_7+0*1024+4*WORD_REG(si)])\
	AS2(movzx esi, t##h)\
	AS2(c, [AS_REG_7+1*1024+4*WORD_REG(si)])\
	AS2(shr e##t##x, 16)\
	AS2(movzx esi, t##l)\
	AS2(b, [AS_REG_7+2*1024+4*WORD_REG(si)])\
	AS2(movzx esi, t##h)\
	AS2(a, [AS_REG_7+3*1024+4*WORD_REG(si)])

#define s0		xor edi
#define s1		xor eax
#define s2		xor ebx
#define s3		xor ecx
#define t0		xor edi
#define t1		xor eax
#define t2		xor ebx
#define t3		xor edx

		QUARTER_ROUND(c, t0, t1, t2, t3)
		RESTORE_2(ecx)
		QUARTER_ROUND(c, t3, t0, t1, t2)
		RESTORE_1(ecx)
		QUARTER_ROUND(c, t2, t3, t0, t1)
		RESTORE_0(ecx)
		QUARTER_ROUND(c, t1, t2, t3, t0)
		SAVE_2(ebx)
		SAVE_1(eax)
		SAVE_0(edi)
#undef QUARTER_ROUND

		RESTORE_K

		ASL(0)
		AS2(	mov		edi, [K_REG+0*4])
		AS2(	mov		eax, [K_REG+1*4])
		AS2(	mov		ebx, [K_REG+2*4])
		AS2(	mov		ecx, [K_REG+3*4])

#define QUARTER_ROUND(t, a, b, c, d)	\
	AS2(movzx esi, t##l)\
	AS2(a, [AS_REG_7+3*1024+4*WORD_REG(si)])\
	AS2(movzx esi, t##h)\
	AS2(b, [AS_REG_7+2*1024+4*WORD_REG(si)])\
	AS2(shr e##t##x, 16)\
	AS2(movzx esi, t##l)\
	AS2(c, [AS_REG_7+1*1024+4*WORD_REG(si)])\
	AS2(movzx esi, t##h)\
	AS2(d, [AS_REG_7+0*1024+4*WORD_REG(si)])

		QUARTER_ROUND(d, s0, s1, s2, s3)
		RESTORE_2(edx)
		QUARTER_ROUND(d, s3, s0, s1, s2)
		RESTORE_1(edx)
		QUARTER_ROUND(d, s2, s3, s0, s1)
		RESTORE_0(edx)
		QUARTER_ROUND(d, s1, s2, s3, s0)
		RESTORE_K
		SAVE_2(ebx)
		SAVE_1(eax)
		SAVE_0(edi)

		AS2(	mov		edi, [K_REG+4*4])
		AS2(	mov		eax, [K_REG+5*4])
		AS2(	mov		ebx, [K_REG+6*4])
		AS2(	mov		edx, [K_REG+7*4])

		QUARTER_ROUND(c, t0, t1, t2, t3)
		RESTORE_2(ecx)
		QUARTER_ROUND(c, t3, t0, t1, t2)
		RESTORE_1(ecx)
		QUARTER_ROUND(c, t2, t3, t0, t1)
		RESTORE_0(ecx)
		QUARTER_ROUND(c, t1, t2, t3, t0)
		SAVE_2(ebx)
		SAVE_1(eax)
		SAVE_0(edi)

		RESTORE_K
		RESTORE_K_END
		AS2(	add		K_REG, 8*4)
		SAVE_K
		AS2(	cmp		K_END_REG, K_REG)
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

		AS2(	mov		eax, [K_END_REG+0*4])
		AS2(	mov		ecx, [K_END_REG+1*4])
		AS2(	mov		esi, [K_END_REG+2*4])
		AS2(	mov		edi, [K_END_REG+3*4])

#define QUARTER_ROUND(a, b, c, d)	\
	AS2(	movzx	ebx, dl)\
	AS2(	movzx	ebx, BYTE PTR [AS_REG_7+1+4*WORD_REG(bx)])\
	AS2(	shl		ebx, 3*8)\
	AS2(	xor		a, ebx)\
	AS2(	movzx	ebx, dh)\
	AS2(	movzx	ebx, BYTE PTR [AS_REG_7+1+4*WORD_REG(bx)])\
	AS2(	shl		ebx, 2*8)\
	AS2(	xor		b, ebx)\
	AS2(	shr		edx, 16)\
	AS2(	movzx	ebx, dl)\
	AS2(	shr		edx, 8)\
	AS2(	movzx	ebx, BYTE PTR [AS_REG_7+1+4*WORD_REG(bx)])\
	AS2(	shl		ebx, 1*8)\
	AS2(	xor		c, ebx)\
	AS2(	movzx	ebx, BYTE PTR [AS_REG_7+1+4*WORD_REG(dx)])\
	AS2(	xor		d, ebx)

		QUARTER_ROUND(eax, ecx, esi, edi)
		RESTORE_2(edx)
		QUARTER_ROUND(edi, eax, ecx, esi)
		RESTORE_1(edx)
		QUARTER_ROUND(esi, edi, eax, ecx)
		RESTORE_0(edx)
		QUARTER_ROUND(ecx, esi, edi, eax)

#undef QUARTER_ROUND

#if CRYPTOPP_BOOL_X86
		AS1(emms)
		AS1(pop		ebp)
	#if defined(__GNUC__) || (defined(_MSC_VER) && _MSC_VER < 1300)
		AS1(pop		ebx)
	#endif
#endif

#ifdef __GNUC__
		".att_syntax prefix;"
			: "=a" (t0), "=c" (t1), "=S" (t2), "=D" (t3)
			: "a" (Te), "D" (inBlock), "S" (k), "c" (kLoopEnd), "d" (g_cacheLineSize)
			: "memory", "cc"
	#if CRYPTOPP_BOOL_X64
			, "%ebx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"
	#endif
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
	#if CRYPTOPP_BOOL_X64
		mov		rbx, [rsp + 6*8 + 7*8]			; xorBlock
	#else
		AS2(	mov		ebx, xorBlock)
	#endif
		AS2(	test	WORD_REG(bx), WORD_REG(bx))
		ASJ(	jz,		1, f)
		AS2(	xor		eax, [WORD_REG(bx)+0*4])
		AS2(	xor		ecx, [WORD_REG(bx)+1*4])
		AS2(	xor		esi, [WORD_REG(bx)+2*4])
		AS2(	xor		edi, [WORD_REG(bx)+3*4])
		ASL(1)
	#if CRYPTOPP_BOOL_X64
		mov		rbx, [rsp + 7*8 + 7*8]			; outBlock
	#else
		AS2(	mov		ebx, outBlock)
	#endif
		AS2(	mov		[WORD_REG(bx)+0*4], eax)
		AS2(	mov		[WORD_REG(bx)+1*4], ecx)
		AS2(	mov		[WORD_REG(bx)+2*4], esi)
		AS2(	mov		[WORD_REG(bx)+3*4], edi)
#endif

#if CRYPTOPP_GENERATE_X64_MASM
		pop r15
		pop r14
		pop r13
		pop r12
		pop rdi
		pop rsi
		pop rbx
		ret
	Rijndael_Enc_ProcessAndXorBlock ENDP
#else
	}
	else
#endif
#endif	// #ifdef CRYPTOPP_X86_ASM_AVAILABLE
#ifndef CRYPTOPP_GENERATE_X64_MASM
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
#endif
