// rijndael.cpp - modified by Chris Morgan <cmorgan@wpi.edu>
// and Wei Dai from Paulo Baretto's Rijndael implementation
// The original code and all modifications are in the public domain.

// use "cl /EP /P /DCRYPTOPP_GENERATE_X64_MASM rijndael.cpp" to generate MASM code

/*
Feb 2009: The x86/x64 assembly code was rewritten in by Wei Dai to do counter mode 
caching, which was invented by Hongjun Wu and popularized by Daniel J. Bernstein 
and Peter Schwabe in their paper "New AES software speed records". The round 
function was also modified to include a trick similar to one in Brian Gladman's 
x86 assembly code, doing an 8-bit register move to minimize the number of 
register spills. Also switched to compressed tables and copying round keys to 
the stack.

The C++ implementation now uses compressed tables if 
CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS is defined.
*/

/*
July 2006: Defense against timing attacks was added in by Wei Dai.

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

#ifdef __sun
#include <alloca.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE || defined(CRYPTOPP_X64_MASM_AVAILABLE)
namespace rdtable {CRYPTOPP_ALIGN_DATA(16) word64 Te[256+2];}
using namespace rdtable;
#else
static word64 Te[256];
#endif
static word64 Td[256];
#else
static word32 Te[256*4], Td[256*4];
#endif
static bool s_TeFilled = false, s_TdFilled = false;

// ************************* Portable Code ************************************

#define QUARTER_ROUND(L, T, t, a, b, c, d)	\
	a ^= L(T, 3, byte(t)); t >>= 8;\
	b ^= L(T, 2, byte(t)); t >>= 8;\
	c ^= L(T, 1, byte(t)); t >>= 8;\
	d ^= L(T, 0, t);

#define QUARTER_ROUND_LE(t, a, b, c, d)	\
	tempBlock[a] = ((byte *)(Te+byte(t)))[1]; t >>= 8;\
	tempBlock[b] = ((byte *)(Te+byte(t)))[1]; t >>= 8;\
	tempBlock[c] = ((byte *)(Te+byte(t)))[1]; t >>= 8;\
	tempBlock[d] = ((byte *)(Te+t))[1];

#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	#define QUARTER_ROUND_LD(t, a, b, c, d)	\
		tempBlock[a] = ((byte *)(Td+byte(t)))[GetNativeByteOrder()*7]; t >>= 8;\
		tempBlock[b] = ((byte *)(Td+byte(t)))[GetNativeByteOrder()*7]; t >>= 8;\
		tempBlock[c] = ((byte *)(Td+byte(t)))[GetNativeByteOrder()*7]; t >>= 8;\
		tempBlock[d] = ((byte *)(Td+t))[GetNativeByteOrder()*7];
#else
	#define QUARTER_ROUND_LD(t, a, b, c, d)	\
		tempBlock[a] = Sd[byte(t)]; t >>= 8;\
		tempBlock[b] = Sd[byte(t)]; t >>= 8;\
		tempBlock[c] = Sd[byte(t)]; t >>= 8;\
		tempBlock[d] = Sd[t];
#endif

#define QUARTER_ROUND_E(t, a, b, c, d)		QUARTER_ROUND(TL_M, Te, t, a, b, c, d)
#define QUARTER_ROUND_D(t, a, b, c, d)		QUARTER_ROUND(TL_M, Td, t, a, b, c, d)

#ifdef IS_LITTLE_ENDIAN
	#define QUARTER_ROUND_FE(t, a, b, c, d)		QUARTER_ROUND(TL_F, Te, t, d, c, b, a)
	#define QUARTER_ROUND_FD(t, a, b, c, d)		QUARTER_ROUND(TL_F, Td, t, d, c, b, a)
	#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
		#define TL_F(T, i, x)	(*(word32 *)((byte *)T + x*8 + (6-i)%4+1))
		#define TL_M(T, i, x)	(*(word32 *)((byte *)T + x*8 + (i+3)%4+1))
	#else
		#define TL_F(T, i, x)	rotrFixed(T[x], (3-i)*8)
		#define TL_M(T, i, x)	T[i*256 + x]
	#endif
#else
	#define QUARTER_ROUND_FE(t, a, b, c, d)		QUARTER_ROUND(TL_F, Te, t, a, b, c, d)
	#define QUARTER_ROUND_FD(t, a, b, c, d)		QUARTER_ROUND(TL_F, Td, t, a, b, c, d)
	#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
		#define TL_F(T, i, x)	(*(word32 *)((byte *)T + x*8 + (4-i)%4))
		#define TL_M			TL_F
	#else
		#define TL_F(T, i, x)	rotrFixed(T[x], i*8)
		#define TL_M(T, i, x)	T[i*256 + x]
	#endif
#endif


#define f2(x)   ((x<<1)^(((x>>7)&1)*0x11b))
#define f4(x)   ((x<<2)^(((x>>6)&1)*0x11b)^(((x>>6)&2)*0x11b))
#define f8(x)   ((x<<3)^(((x>>5)&1)*0x11b)^(((x>>5)&2)*0x11b)^(((x>>5)&4)*0x11b))

#define f3(x)   (f2(x) ^ x)
#define f9(x)   (f8(x) ^ x)
#define fb(x)   (f8(x) ^ f2(x) ^ x)
#define fd(x)   (f8(x) ^ f4(x) ^ x)
#define fe(x)   (f8(x) ^ f4(x) ^ f2(x))

void Rijndael::Base::FillEncTable()
{
	for (int i=0; i<256; i++)
	{
		byte x = Se[i];
#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
		word32 y = word32(x)<<8 | word32(x)<<16 | word32(f2(x))<<24;
		Te[i] = word64(y | f3(x))<<32 | y;
#else
		word32 y = f3(x) | word32(x)<<8 | word32(x)<<16 | word32(f2(x))<<24;
		for (int j=0; j<4; j++)
		{
			Te[i+j*256] = y;
			y = rotrFixed(y, 8);
		}
#endif
	}
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE || defined(CRYPTOPP_X64_MASM_AVAILABLE)
	Te[256] = Te[257] = 0;
#endif
	s_TeFilled = true;
}

void Rijndael::Base::FillDecTable()
{
	for (int i=0; i<256; i++)
	{
		byte x = Sd[i];
#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
		word32 y = word32(fd(x))<<8 | word32(f9(x))<<16 | word32(fe(x))<<24;
		Td[i] = word64(y | fb(x))<<32 | y | x;
#else
		word32 y = fb(x) | word32(fd(x))<<8 | word32(f9(x))<<16 | word32(fe(x))<<24;;
		for (int j=0; j<4; j++)
		{
			Td[i+j*256] = y;
			y = rotrFixed(y, 8);
		}
#endif
	}
	s_TdFilled = true;
}

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

	if (IsForwardTransformation())
	{
		if (!s_TeFilled)
			FillEncTable();
	}
	else
	{
		if (!s_TdFilled)
			FillDecTable();

		unsigned int i, j;
		rk = m_key;

		/* invert the order of the round keys: */
		for (i = 0, j = 4*m_rounds; i < j; i += 4, j -= 4) {
			temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
			temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
			temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
			temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
		}

#define InverseMixColumn(x)		x = TL_M(Td, 0, Se[GETBYTE(x, 3)]) ^ TL_M(Td, 1, Se[GETBYTE(x, 2)]) ^ TL_M(Td, 2, Se[GETBYTE(x, 1)]) ^ TL_M(Td, 3, Se[GETBYTE(x, 0)])

		/* apply the inverse MixColumn transform to all round keys but the first and the last: */
		for (i = 1; i < m_rounds; i++) {
			rk += 4;
			InverseMixColumn(rk[0]);
			InverseMixColumn(rk[1]);
			InverseMixColumn(rk[2]);
			InverseMixColumn(rk[3]);
		}
	}

	ConditionalByteReverse(BIG_ENDIAN_ORDER, m_key.begin(), m_key.begin(), 16);
	ConditionalByteReverse(BIG_ENDIAN_ORDER, m_key + m_rounds*4, m_key + m_rounds*4, 16);
}

void Rijndael::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE || defined(CRYPTOPP_X64_MASM_AVAILABLE)
	if (HasSSE2())
	{
		Rijndael::Enc::AdvancedProcessBlocks(inBlock, xorBlock, outBlock, 16, 0);
		return;
	}
#endif

	typedef BlockGetAndPut<word32, NativeByteOrder> Block;

	word32 s0, s1, s2, s3, t0, t1, t2, t3;
	Block::Get(inBlock)(s0)(s1)(s2)(s3);

	const word32 *rk = m_key;
	s0 ^= rk[0];
	s1 ^= rk[1];
	s2 ^= rk[2];
	s3 ^= rk[3];
	t0 = rk[4];
	t1 = rk[5];
	t2 = rk[6];
	t3 = rk[7];
	rk += 8;

	// timing attack countermeasure. see comments at top for more details
	const int cacheLineSize = GetCacheLineSize();
	unsigned int i;
	word32 u = 0;
#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	for (i=0; i<2048; i+=cacheLineSize)
#else
	for (i=0; i<1024; i+=cacheLineSize)
#endif
		u &= *(const word32 *)(((const byte *)Te)+i);
	u &= Te[255];
	s0 |= u; s1 |= u; s2 |= u; s3 |= u;

	QUARTER_ROUND_FE(s3, t0, t1, t2, t3)
	QUARTER_ROUND_FE(s2, t3, t0, t1, t2)
	QUARTER_ROUND_FE(s1, t2, t3, t0, t1)
	QUARTER_ROUND_FE(s0, t1, t2, t3, t0)

	// Nr - 2 full rounds:
    unsigned int r = m_rounds/2 - 1;
    do
	{
		s0 = rk[0]; s1 = rk[1]; s2 = rk[2]; s3 = rk[3];

		QUARTER_ROUND_E(t3, s0, s1, s2, s3)
		QUARTER_ROUND_E(t2, s3, s0, s1, s2)
		QUARTER_ROUND_E(t1, s2, s3, s0, s1)
		QUARTER_ROUND_E(t0, s1, s2, s3, s0)

		t0 = rk[4]; t1 = rk[5]; t2 = rk[6]; t3 = rk[7];

		QUARTER_ROUND_E(s3, t0, t1, t2, t3)
		QUARTER_ROUND_E(s2, t3, t0, t1, t2)
		QUARTER_ROUND_E(s1, t2, t3, t0, t1)
		QUARTER_ROUND_E(s0, t1, t2, t3, t0)

        rk += 8;
    } while (--r);

	word32 tbw[4];
	byte *const tempBlock = (byte *)tbw;

	QUARTER_ROUND_LE(t2, 15, 2, 5, 8)
	QUARTER_ROUND_LE(t1, 11, 14, 1, 4)
	QUARTER_ROUND_LE(t0, 7, 10, 13, 0)
	QUARTER_ROUND_LE(t3, 3, 6, 9, 12)

	Block::Put(xorBlock, outBlock)(tbw[0]^rk[0])(tbw[1]^rk[1])(tbw[2]^rk[2])(tbw[3]^rk[3]);
}

void Rijndael::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	typedef BlockGetAndPut<word32, NativeByteOrder> Block;

	word32 s0, s1, s2, s3, t0, t1, t2, t3;
	Block::Get(inBlock)(s0)(s1)(s2)(s3);

	const word32 *rk = m_key;
	s0 ^= rk[0];
	s1 ^= rk[1];
	s2 ^= rk[2];
	s3 ^= rk[3];
	t0 = rk[4];
	t1 = rk[5];
	t2 = rk[6];
	t3 = rk[7];
	rk += 8;

	// timing attack countermeasure. see comments at top for more details
	const int cacheLineSize = GetCacheLineSize();
	unsigned int i;
	word32 u = 0;
#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	for (i=0; i<2048; i+=cacheLineSize)
#else
	for (i=0; i<1024; i+=cacheLineSize)
#endif
		u &= *(const word32 *)(((const byte *)Td)+i);
	u &= Td[255];
	s0 |= u; s1 |= u; s2 |= u; s3 |= u;

	QUARTER_ROUND_FD(s3, t2, t1, t0, t3)
	QUARTER_ROUND_FD(s2, t1, t0, t3, t2)
	QUARTER_ROUND_FD(s1, t0, t3, t2, t1)
	QUARTER_ROUND_FD(s0, t3, t2, t1, t0)

	// Nr - 2 full rounds:
    unsigned int r = m_rounds/2 - 1;
    do
	{
		s0 = rk[0]; s1 = rk[1]; s2 = rk[2]; s3 = rk[3];

		QUARTER_ROUND_D(t3, s2, s1, s0, s3)
		QUARTER_ROUND_D(t2, s1, s0, s3, s2)
		QUARTER_ROUND_D(t1, s0, s3, s2, s1)
		QUARTER_ROUND_D(t0, s3, s2, s1, s0)

		t0 = rk[4]; t1 = rk[5]; t2 = rk[6]; t3 = rk[7];

		QUARTER_ROUND_D(s3, t2, t1, t0, t3)
		QUARTER_ROUND_D(s2, t1, t0, t3, t2)
		QUARTER_ROUND_D(s1, t0, t3, t2, t1)
		QUARTER_ROUND_D(s0, t3, t2, t1, t0)

        rk += 8;
    } while (--r);

#ifndef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	// timing attack countermeasure. see comments at top for more details
	// If CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS is defined, 
	// QUARTER_ROUND_LD will use Td, which is already preloaded.
	u = 0;
	for (i=0; i<256; i+=cacheLineSize)
		u &= *(const word32 *)(Sd+i);
	u &= *(const word32 *)(Sd+252);
	t0 |= u; t1 |= u; t2 |= u; t3 |= u;
#endif

	word32 tbw[4];
	byte *const tempBlock = (byte *)tbw;

	QUARTER_ROUND_LD(t2, 7, 2, 13, 8)
	QUARTER_ROUND_LD(t1, 3, 14, 9, 4)
	QUARTER_ROUND_LD(t0, 15, 10, 5, 0)
	QUARTER_ROUND_LD(t3, 11, 6, 1, 12)

	Block::Put(xorBlock, outBlock)(tbw[0]^rk[0])(tbw[1]^rk[1])(tbw[2]^rk[2])(tbw[3]^rk[3]);
}

// ************************* Assembly Code ************************************

#pragma warning(disable: 4731)	// frame pointer register 'ebp' modified by inline assembly code

#endif	// #ifndef CRYPTOPP_GENERATE_X64_MASM

#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE

CRYPTOPP_NAKED void CRYPTOPP_FASTCALL Rijndael_Enc_AdvancedProcessBlocks(void *locals, const word32 *k)
{
#if CRYPTOPP_BOOL_X86

#define L_REG			esp
#define L_INDEX(i)		(L_REG+512+i)
#define L_INXORBLOCKS	L_INBLOCKS+4
#define L_OUTXORBLOCKS	L_INBLOCKS+8
#define L_OUTBLOCKS		L_INBLOCKS+12
#define L_INCREMENTS	L_INDEX(16*15)
#define L_SP			L_INDEX(16*16)
#define L_LENGTH		L_INDEX(16*16+4)
#define L_KEYS_BEGIN	L_INDEX(16*16+8)

#define MOVD			movd
#define MM(i)			mm##i

#define MXOR(a,b,c)	\
	AS2(	movzx	esi, b)\
	AS2(	movd	mm7, DWORD PTR [AS_REG_7+8*WORD_REG(si)+MAP0TO4(c)])\
	AS2(	pxor	MM(a), mm7)\

#define MMOV(a,b,c)	\
	AS2(	movzx	esi, b)\
	AS2(	movd	MM(a), DWORD PTR [AS_REG_7+8*WORD_REG(si)+MAP0TO4(c)])\

#else

#define L_REG			r8
#define L_INDEX(i)		(L_REG+i)
#define L_INXORBLOCKS	L_INBLOCKS+8
#define L_OUTXORBLOCKS	L_INBLOCKS+16
#define L_OUTBLOCKS		L_INBLOCKS+24
#define L_INCREMENTS	L_INDEX(16*16)
#define L_LENGTH		L_INDEX(16*18+8)
#define L_KEYS_BEGIN	L_INDEX(16*19)

#define MOVD			mov
#define MM_0			r9d
#define MM_1			r12d
#ifdef __GNUC__
#define MM_2			r11d
#else
#define MM_2			r10d
#endif
#define MM(i)			MM_##i

#define MXOR(a,b,c)	\
	AS2(	movzx	esi, b)\
	AS2(	xor		MM(a), DWORD PTR [AS_REG_7+8*WORD_REG(si)+MAP0TO4(c)])\

#define MMOV(a,b,c)	\
	AS2(	movzx	esi, b)\
	AS2(	mov		MM(a), DWORD PTR [AS_REG_7+8*WORD_REG(si)+MAP0TO4(c)])\

#endif

#define L_SUBKEYS		L_INDEX(0)
#define L_SAVED_X		L_SUBKEYS
#define L_KEY12			L_INDEX(16*12)
#define L_LASTROUND		L_INDEX(16*13)
#define L_INBLOCKS		L_INDEX(16*14)
#define MAP0TO4(i)		(ASM_MOD(i+3,4)+1)

#define XOR(a,b,c)	\
	AS2(	movzx	esi, b)\
	AS2(	xor		a, DWORD PTR [AS_REG_7+8*WORD_REG(si)+MAP0TO4(c)])\

#define MOV(a,b,c)	\
	AS2(	movzx	esi, b)\
	AS2(	mov		a, DWORD PTR [AS_REG_7+8*WORD_REG(si)+MAP0TO4(c)])\

#ifdef CRYPTOPP_GENERATE_X64_MASM
		ALIGN   8
	Rijndael_Enc_AdvancedProcessBlocks	PROC FRAME
		rex_push_reg rsi
		push_reg rdi
		push_reg rbx
		push_reg r12
		.endprolog
		mov L_REG, rcx
		mov AS_REG_7, ?Te@rdtable@CryptoPP@@3PA_KA
		mov rdi, QWORD PTR [?g_cacheLineSize@CryptoPP@@3IA]
#elif defined(__GNUC__)
	__asm__ __volatile__
	(
	".intel_syntax noprefix;"
	#if CRYPTOPP_BOOL_X64
	AS2(	mov		L_REG, rcx)
	#endif
	AS_PUSH_IF86(bx)
	AS_PUSH_IF86(bp)
	AS2(	mov		AS_REG_7, WORD_REG(si))
#else
	AS_PUSH_IF86(si)
	AS_PUSH_IF86(di)
#if !defined(_MSC_VER) || (_MSC_VER < 1400)
	AS_PUSH_IF86(bx)
#endif
	AS_PUSH_IF86(bp)
	AS2(	lea		AS_REG_7, [Te])
	AS2(	mov		edi, [g_cacheLineSize])
#endif

#if CRYPTOPP_BOOL_X86
	AS2(	mov		[ecx+16*12+16*4], esp)	// save esp to L_SP
	AS2(	lea		esp, [ecx-512])
#endif

	// copy subkeys to stack
	AS2(	mov		WORD_REG(si), [L_KEYS_BEGIN])
	AS2(	mov		WORD_REG(ax), 16)
	AS2(	and		WORD_REG(ax), WORD_REG(si))
	AS2(	movdqa	xmm3, XMMWORD_PTR [WORD_REG(dx)+16+WORD_REG(ax)])	// subkey 1 (non-counter) or 2 (counter)
	AS2(	movdqa	[L_KEY12], xmm3)
	AS2(	lea		WORD_REG(ax), [WORD_REG(dx)+WORD_REG(ax)+2*16])
	AS2(	sub		WORD_REG(ax), WORD_REG(si))
	ASL(0)
	AS2(	movdqa	xmm0, [WORD_REG(ax)+WORD_REG(si)])
	AS2(	movdqa	XMMWORD_PTR [L_SUBKEYS+WORD_REG(si)], xmm0)
	AS2(	add		WORD_REG(si), 16)
	AS2(	cmp		WORD_REG(si), 16*12)
	ASJ(	jl,		0, b)

	// read subkeys 0, 1 and last
	AS2(	movdqa	xmm4, [WORD_REG(ax)+WORD_REG(si)])	// last subkey
	AS2(	movdqa	xmm1, [WORD_REG(dx)])			// subkey 0
	AS2(	MOVD	MM(1), [WORD_REG(dx)+4*4])		// 0,1,2,3
	AS2(	mov		ebx, [WORD_REG(dx)+5*4])		// 4,5,6,7
	AS2(	mov		ecx, [WORD_REG(dx)+6*4])		// 8,9,10,11
	AS2(	mov		edx, [WORD_REG(dx)+7*4])		// 12,13,14,15

	// load table into cache
	AS2(	xor		WORD_REG(ax), WORD_REG(ax))
	ASL(9)
	AS2(	mov		esi, [AS_REG_7+WORD_REG(ax)])
	AS2(	add		WORD_REG(ax), WORD_REG(di))
	AS2(	mov		esi, [AS_REG_7+WORD_REG(ax)])
	AS2(	add		WORD_REG(ax), WORD_REG(di))
	AS2(	mov		esi, [AS_REG_7+WORD_REG(ax)])
	AS2(	add		WORD_REG(ax), WORD_REG(di))
	AS2(	mov		esi, [AS_REG_7+WORD_REG(ax)])
	AS2(	add		WORD_REG(ax), WORD_REG(di))
	AS2(	cmp		WORD_REG(ax), 2048)
	ASJ(	jl,		9, b)
	AS1(	lfence)

	AS2(	test	DWORD PTR [L_LENGTH], 1)
	ASJ(	jz,		8, f)

	// counter mode one-time setup
	AS2(	mov		WORD_REG(si), [L_INBLOCKS])
	AS2(	movdqu	xmm2, [WORD_REG(si)])	// counter
	AS2(	pxor	xmm2, xmm1)
	AS2(	psrldq	xmm1, 14)
	AS2(	movd	eax, xmm1)
	AS2(	mov		al, BYTE PTR [WORD_REG(si)+15])
	AS2(	MOVD	MM(2), eax)
#if CRYPTOPP_BOOL_X86
	AS2(	mov		eax, 1)
	AS2(	movd	mm3, eax)
#endif

	// partial first round, in: xmm2(15,14,13,12;11,10,9,8;7,6,5,4;3,2,1,0), out: mm1, ebx, ecx, edx
	AS2(	movd	eax, xmm2)
	AS2(	psrldq	xmm2, 4)
	AS2(	movd	edi, xmm2)
	AS2(	psrldq	xmm2, 4)
		MXOR(		1, al, 0)		// 0
		XOR(		edx, ah, 1)		// 1
	AS2(	shr		eax, 16)
		XOR(		ecx, al, 2)		// 2
		XOR(		ebx, ah, 3)		// 3
	AS2(	mov		eax, edi)
	AS2(	movd	edi, xmm2)
	AS2(	psrldq	xmm2, 4)
		XOR(		ebx, al, 0)		// 4
		MXOR(		1, ah, 1)		// 5
	AS2(	shr		eax, 16)
		XOR(		edx, al, 2)		// 6
		XOR(		ecx, ah, 3)		// 7
	AS2(	mov		eax, edi)
	AS2(	movd	edi, xmm2)
		XOR(		ecx, al, 0)		// 8
		XOR(		ebx, ah, 1)		// 9
	AS2(	shr		eax, 16)
		MXOR(		1, al, 2)		// 10
		XOR(		edx, ah, 3)		// 11
	AS2(	mov		eax, edi)
		XOR(		edx, al, 0)		// 12
		XOR(		ecx, ah, 1)		// 13
	AS2(	shr		eax, 16)
		XOR(		ebx, al, 2)		// 14
	AS2(	psrldq	xmm2, 3)

	// partial second round, in: ebx(4,5,6,7), ecx(8,9,10,11), edx(12,13,14,15), out: eax, ebx, edi, mm0
	AS2(	mov		eax, [L_KEY12+0*4])
	AS2(	mov		edi, [L_KEY12+2*4])
	AS2(	MOVD	MM(0), [L_KEY12+3*4])
		MXOR(	0, cl, 3)	/* 11 */
		XOR(	edi, bl, 3)	/* 7 */
		MXOR(	0, bh, 2)	/* 6 */
	AS2(	shr ebx, 16)	/* 4,5 */
		XOR(	eax, bl, 1)	/* 5 */
		MOV(	ebx, bh, 0)	/* 4 */
	AS2(	xor		ebx, [L_KEY12+1*4])
		XOR(	eax, ch, 2)	/* 10 */
	AS2(	shr ecx, 16)	/* 8,9 */
		XOR(	eax, dl, 3)	/* 15 */
		XOR(	ebx, dh, 2)	/* 14 */
	AS2(	shr edx, 16)	/* 12,13 */
		XOR(	edi, ch, 0)	/* 8 */
		XOR(	ebx, cl, 1)	/* 9 */
		XOR(	edi, dl, 1)	/* 13 */
		MXOR(	0, dh, 0)	/* 12 */

	AS2(	movd	ecx, xmm2)
	AS2(	MOVD	edx, MM(1))
	AS2(	MOVD	[L_SAVED_X+3*4], MM(0))
	AS2(	mov		[L_SAVED_X+0*4], eax)
	AS2(	mov		[L_SAVED_X+1*4], ebx)
	AS2(	mov		[L_SAVED_X+2*4], edi)
	ASJ(	jmp,	5, f)

	ASL(3)
	// non-counter mode per-block setup
	AS2(	MOVD	MM(1), [L_KEY12+0*4])	// 0,1,2,3
	AS2(	mov		ebx, [L_KEY12+1*4])		// 4,5,6,7
	AS2(	mov		ecx, [L_KEY12+2*4])		// 8,9,10,11
	AS2(	mov		edx, [L_KEY12+3*4])		// 12,13,14,15
	ASL(8)
	AS2(	mov		WORD_REG(ax), [L_INBLOCKS])
	AS2(	movdqu	xmm2, [WORD_REG(ax)])
	AS2(	mov		WORD_REG(si), [L_INXORBLOCKS])
	AS2(	movdqu	xmm5, [WORD_REG(si)])
	AS2(	pxor	xmm2, xmm1)
	AS2(	pxor	xmm2, xmm5)

	// first round, in: xmm2(15,14,13,12;11,10,9,8;7,6,5,4;3,2,1,0), out: eax, ebx, ecx, edx
	AS2(	movd	eax, xmm2)
	AS2(	psrldq	xmm2, 4)
	AS2(	movd	edi, xmm2)
	AS2(	psrldq	xmm2, 4)
		MXOR(		1, al, 0)		// 0
		XOR(		edx, ah, 1)		// 1
	AS2(	shr		eax, 16)
		XOR(		ecx, al, 2)		// 2
		XOR(		ebx, ah, 3)		// 3
	AS2(	mov		eax, edi)
	AS2(	movd	edi, xmm2)
	AS2(	psrldq	xmm2, 4)
		XOR(		ebx, al, 0)		// 4
		MXOR(		1, ah, 1)		// 5
	AS2(	shr		eax, 16)
		XOR(		edx, al, 2)		// 6
		XOR(		ecx, ah, 3)		// 7
	AS2(	mov		eax, edi)
	AS2(	movd	edi, xmm2)
		XOR(		ecx, al, 0)		// 8
		XOR(		ebx, ah, 1)		// 9
	AS2(	shr		eax, 16)
		MXOR(		1, al, 2)		// 10
		XOR(		edx, ah, 3)		// 11
	AS2(	mov		eax, edi)
		XOR(		edx, al, 0)		// 12
		XOR(		ecx, ah, 1)		// 13
	AS2(	shr		eax, 16)
		XOR(		ebx, al, 2)		// 14
		MXOR(		1, ah, 3)		// 15
	AS2(	MOVD	eax, MM(1))

	AS2(	add		L_REG, [L_KEYS_BEGIN])
	AS2(	add		L_REG, 4*16)
	ASJ(	jmp,	2, f)

	ASL(1)
	// counter-mode per-block setup
	AS2(	MOVD	ecx, MM(2))
	AS2(	MOVD	edx, MM(1))
	AS2(	mov		eax, [L_SAVED_X+0*4])
	AS2(	mov		ebx, [L_SAVED_X+1*4])
	AS2(	xor		cl, ch)
	AS2(	and		WORD_REG(cx), 255)
	ASL(5)
#if CRYPTOPP_BOOL_X86
	AS2(	paddb	MM(2), mm3)
#else
	AS2(	add		MM(2), 1)
#endif
	// remaining part of second round, in: edx(previous round),esi(keyed counter byte) eax,ebx,[L_SAVED_X+2*4],[L_SAVED_X+3*4], out: eax,ebx,ecx,edx
	AS2(	xor		edx, DWORD PTR [AS_REG_7+WORD_REG(cx)*8+3])
		XOR(		ebx, dl, 3)
		MOV(		ecx, dh, 2)
	AS2(	shr		edx, 16)
	AS2(	xor		ecx, [L_SAVED_X+2*4])
		XOR(		eax, dh, 0)
		MOV(		edx, dl, 1)
	AS2(	xor		edx, [L_SAVED_X+3*4])

	AS2(	add		L_REG, [L_KEYS_BEGIN])
	AS2(	add		L_REG, 3*16)
	ASJ(	jmp,	4, f)

// in: eax(0,1,2,3), ebx(4,5,6,7), ecx(8,9,10,11), edx(12,13,14,15)
// out: eax, ebx, edi, mm0
#define ROUND()		\
		MXOR(	0, cl, 3)	/* 11 */\
	AS2(	mov	cl, al)		/* 8,9,10,3 */\
		XOR(	edi, ah, 2)	/* 2 */\
	AS2(	shr eax, 16)	/* 0,1 */\
		XOR(	edi, bl, 3)	/* 7 */\
		MXOR(	0, bh, 2)	/* 6 */\
	AS2(	shr ebx, 16)	/* 4,5 */\
		MXOR(	0, al, 1)	/* 1 */\
		MOV(	eax, ah, 0)	/* 0 */\
		XOR(	eax, bl, 1)	/* 5 */\
		MOV(	ebx, bh, 0)	/* 4 */\
		XOR(	eax, ch, 2)	/* 10 */\
		XOR(	ebx, cl, 3)	/* 3 */\
	AS2(	shr ecx, 16)	/* 8,9 */\
		XOR(	eax, dl, 3)	/* 15 */\
		XOR(	ebx, dh, 2)	/* 14 */\
	AS2(	shr edx, 16)	/* 12,13 */\
		XOR(	edi, ch, 0)	/* 8 */\
		XOR(	ebx, cl, 1)	/* 9 */\
		XOR(	edi, dl, 1)	/* 13 */\
		MXOR(	0, dh, 0)	/* 12 */\

	ASL(2)	// 2-round loop
	AS2(	MOVD	MM(0), [L_SUBKEYS-4*16+3*4])
	AS2(	mov		edi, [L_SUBKEYS-4*16+2*4])
	ROUND()
	AS2(	mov		ecx, edi)
	AS2(	xor		eax, [L_SUBKEYS-4*16+0*4])
	AS2(	xor		ebx, [L_SUBKEYS-4*16+1*4])
	AS2(	MOVD	edx, MM(0))

	ASL(4)
	AS2(	MOVD	MM(0), [L_SUBKEYS-4*16+7*4])
	AS2(	mov		edi, [L_SUBKEYS-4*16+6*4])
	ROUND()
	AS2(	mov		ecx, edi)
	AS2(	xor		eax, [L_SUBKEYS-4*16+4*4])
	AS2(	xor		ebx, [L_SUBKEYS-4*16+5*4])
	AS2(	MOVD	edx, MM(0))

	AS2(	add		L_REG, 32)
	AS2(	test	L_REG, 255)
	ASJ(	jnz,	2, b)
	AS2(	sub		L_REG, 16*16)

#define LAST(a, b, c)												\
	AS2(	movzx	esi, a											)\
	AS2(	movzx	edi, BYTE PTR [AS_REG_7+WORD_REG(si)*8+1]	)\
	AS2(	movzx	esi, b											)\
	AS2(	xor		edi, DWORD PTR [AS_REG_7+WORD_REG(si)*8+0]	)\
	AS2(	mov		WORD PTR [L_LASTROUND+c], di					)\

	// last round
	LAST(ch, dl, 2)
	LAST(dh, al, 6)
	AS2(	shr		edx, 16)
	LAST(ah, bl, 10)
	AS2(	shr		eax, 16)
	LAST(bh, cl, 14)
	AS2(	shr		ebx, 16)
	LAST(dh, al, 12)
	AS2(	shr		ecx, 16)
	LAST(ah, bl, 0)
	LAST(bh, cl, 4)
	LAST(ch, dl, 8)

	AS2(	mov		WORD_REG(ax), [L_OUTXORBLOCKS])
	AS2(	mov		WORD_REG(bx), [L_OUTBLOCKS])

	AS2(	mov		WORD_REG(cx), [L_LENGTH])
	AS2(	sub		WORD_REG(cx), 16)

	AS2(	movdqu	xmm2, [WORD_REG(ax)])
	AS2(	pxor	xmm2, xmm4)

#if CRYPTOPP_BOOL_X86
	AS2(	movdqa	xmm0, [L_INCREMENTS])
	AS2(	paddd	xmm0, [L_INBLOCKS])
	AS2(	movdqa	[L_INBLOCKS], xmm0)
#else
	AS2(	movdqa	xmm0, [L_INCREMENTS+16])
	AS2(	paddq	xmm0, [L_INBLOCKS+16])
	AS2(	movdqa	[L_INBLOCKS+16], xmm0)
#endif

	AS2(	pxor	xmm2, [L_LASTROUND])
	AS2(	movdqu	[WORD_REG(bx)], xmm2)

	ASJ(	jle,	7, f)
	AS2(	mov		[L_LENGTH], WORD_REG(cx))
	AS2(	test	WORD_REG(cx), 1)
	ASJ(	jnz,	1, b)
#if CRYPTOPP_BOOL_X64
	AS2(	movdqa	xmm0, [L_INCREMENTS])
	AS2(	paddq	xmm0, [L_INBLOCKS])
	AS2(	movdqa	[L_INBLOCKS], xmm0)
#endif
	ASJ(	jmp,	3, b)

	ASL(7)
	// erase keys on stack
	AS2(	xorps	xmm0, xmm0)
	AS2(	lea		WORD_REG(ax), [L_SUBKEYS+7*16])
	AS2(	movaps	[WORD_REG(ax)-7*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)-6*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)-5*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)-4*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)-3*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)-2*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)-1*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)+0*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)+1*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)+2*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)+3*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)+4*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)+5*16], xmm0)
	AS2(	movaps	[WORD_REG(ax)+6*16], xmm0)
#if CRYPTOPP_BOOL_X86
	AS2(	mov		esp, [L_SP])
	AS1(	emms)
#endif
	AS_POP_IF86(bp)
#if !defined(_MSC_VER) || (_MSC_VER < 1400)
	AS_POP_IF86(bx)
#endif
#if defined(_MSC_VER) && CRYPTOPP_BOOL_X86
	AS_POP_IF86(di)
	AS_POP_IF86(si)
	AS1(ret)
#endif
#ifdef CRYPTOPP_GENERATE_X64_MASM
	pop r12
	pop rbx
	pop rdi
	pop rsi
	ret
	Rijndael_Enc_AdvancedProcessBlocks ENDP
#endif
#ifdef __GNUC__
	".att_syntax prefix;"
	: 
	: "c" (locals), "d" (k), "S" (Te), "D" (g_cacheLineSize)
	: "memory", "cc", "%eax"
	#if CRYPTOPP_BOOL_X64
		, "%rbx", "%r8", "%r9", "%r10", "%r11", "%r12"
	#endif
	);
#endif
}

#endif

#ifndef CRYPTOPP_GENERATE_X64_MASM

#ifdef CRYPTOPP_X64_MASM_AVAILABLE
extern "C" {
void Rijndael_Enc_AdvancedProcessBlocks(void *locals, const word32 *k);
}
#endif

#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE || defined(CRYPTOPP_X64_MASM_AVAILABLE)

static inline bool AliasedWithTable(const byte *begin, const byte *end)
{
	size_t s0 = size_t(begin)%4096, s1 = size_t(end)%4096;
	size_t t0 = size_t(Te)%4096, t1 = (size_t(Te)+sizeof(Te))%4096;
	if (t1 > t0)
		return (s0 >= t0 && s0 < t1) || (s1 > t0 && s1 <= t1);
	else
		return (s0 < t1 || s1 <= t1) || (s0 >= t0 || s1 > t0);
}

size_t Rijndael::Enc::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags) const
{
	if (length < BLOCKSIZE)
		return length;

	if (HasSSE2())
	{
		struct Locals
		{
			word32 subkeys[4*12], workspace[8];
			const byte *inBlocks, *inXorBlocks, *outXorBlocks;
			byte *outBlocks;
			size_t inIncrement, inXorIncrement, outXorIncrement, outIncrement;
			size_t regSpill, lengthAndCounterFlag, keysBegin;
		};

		size_t increment = BLOCKSIZE;
		const byte* zeros = (byte *)(Te+256);
		byte *space;

		do {
			space = (byte *)alloca(255+sizeof(Locals));
			space += (256-(size_t)space%256)%256;
		}
		while (AliasedWithTable(space, space+sizeof(Locals)));

		if (flags & BT_ReverseDirection)
		{
			assert(length % BLOCKSIZE == 0);
			inBlocks += length - BLOCKSIZE;
			xorBlocks += length - BLOCKSIZE;
			outBlocks += length - BLOCKSIZE;
			increment = 0-increment;
		}

		Locals &locals = *(Locals *)space;

		locals.inBlocks = inBlocks;
		locals.inXorBlocks = (flags & BT_XorInput) && xorBlocks ? xorBlocks : zeros;
		locals.outXorBlocks = (flags & BT_XorInput) || !xorBlocks ? zeros : xorBlocks;
		locals.outBlocks = outBlocks;

		locals.inIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : increment;
		locals.inXorIncrement = (flags & BT_XorInput) && xorBlocks ? increment : 0;
		locals.outXorIncrement = (flags & BT_XorInput) || !xorBlocks ? 0 : increment;
		locals.outIncrement = (flags & BT_DontIncrementInOutPointers) ? 0 : increment;

		locals.lengthAndCounterFlag = length - (length%16) - bool(flags & BT_InBlockIsCounter);
		int keysToCopy = m_rounds - (flags & BT_InBlockIsCounter ? 3 : 2);
		locals.keysBegin = (12-keysToCopy)*16;

		Rijndael_Enc_AdvancedProcessBlocks(&locals, m_key);
		return length%16;
	}
	else
		return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

#endif

NAMESPACE_END

#endif
#endif
