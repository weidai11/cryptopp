// gcm.cpp - written and placed in the public domain by Wei Dai

// use "cl /EP /P /DCRYPTOPP_GENERATE_X64_MASM gcm.cpp" to generate MASM code

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS
#ifndef CRYPTOPP_GENERATE_X64_MASM

#include "gcm.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

word16 GCM_Base::s_reductionTable[256];
bool GCM_Base::s_reductionTableInitialized = false;

void GCM_Base::GCTR::IncrementCounterBy256()
{
	IncrementCounterByOne(m_counterArray+BlockSize()-4, 3);
}

#if 0
// preserved for testing
void gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
	word64 Z0=0, Z1=0, V0, V1;

	typedef BlockGetAndPut<word64, BigEndian> Block;
	Block::Get(a)(V0)(V1);

	for (int i=0; i<16; i++) 
	{
		for (int j=0x80; j!=0; j>>=1)
		{
			int x = b[i] & j;
			Z0 ^= x ? V0 : 0;
			Z1 ^= x ? V1 : 0;
			x = (int)V1 & 1;
			V1 = (V1>>1) | (V0<<63);
			V0 = (V0>>1) ^ (x ? W64LIT(0xe1) << 56 : 0);
		}
	}
	Block::Put(NULL, c)(Z0)(Z1);
}
#endif

void GCM_Base::SetKeyWithoutResync(const byte *userKey, size_t keylength, const NameValuePairs &params)
{
	BlockCipher &blockCipher = AccessBlockCipher();
	blockCipher.SetKey(userKey, keylength, params);

	if (blockCipher.BlockSize() != REQUIRED_BLOCKSIZE)
		throw InvalidArgument(AlgorithmName() + ": block size of underlying block cipher is not 16");

	int tableSize;
	if (params.GetIntValue(Name::TableSize(), tableSize))
		tableSize = (tableSize >= 64*1024) ? 64*1024 : 2*1024;
	else
		tableSize = (GetTablesOption() == GCM_64K_Tables) ? 64*1024 : 2*1024;

	m_buffer.resize(3*REQUIRED_BLOCKSIZE + tableSize);
	byte *hashKey = HashKey();
	memset(hashKey, 0, REQUIRED_BLOCKSIZE);
	blockCipher.ProcessBlock(hashKey);

	byte *table = MulTable();
	int i, j, k;
	word64 V0, V1;

	typedef BlockGetAndPut<word64, BigEndian> Block;
	Block::Get(hashKey)(V0)(V1);

	if (tableSize == 64*1024)
	{
		for (i=0; i<128; i++)
		{
			k = i%8;
			Block::Put(NULL, table+(i/8)*256*16+(size_t(1)<<(11-k)))(V0)(V1);

			int x = (int)V1 & 1; 
			V1 = (V1>>1) | (V0<<63);
			V0 = (V0>>1) ^ (x ? W64LIT(0xe1) << 56 : 0);
		}

		for (i=0; i<16; i++)
		{
			memset(table+i*256*16, 0, 16);
			for (j=2; j<=0x80; j*=2)
				for (k=1; k<j; k++)
					xorbuf(table+i*256*16+(j+k)*16, table+i*256*16+j*16, table+i*256*16+k*16, 16);
		}
	}
	else
	{
		if (!s_reductionTableInitialized)
		{
			s_reductionTable[0] = 0;
			word16 x = 0x01c2;
			s_reductionTable[1] = ConditionalByteReverse(BIG_ENDIAN_ORDER, x);
			for (int i=2; i<=0x80; i*=2)
			{
				x <<= 1;
				s_reductionTable[i] = ConditionalByteReverse(BIG_ENDIAN_ORDER, x);
				for (int j=1; j<i; j++)
					s_reductionTable[i+j] = s_reductionTable[i] ^ s_reductionTable[j];
			}
			s_reductionTableInitialized = true;
		}

		for (i=0; i<128-24; i++)
		{
			k = i%32;
			if (k < 4)
				Block::Put(NULL, table+1024+(i/32)*256+(size_t(1)<<(7-k)))(V0)(V1);
			else if (k < 8)
				Block::Put(NULL, table+(i/32)*256+(size_t(1)<<(11-k)))(V0)(V1);

			int x = (int)V1 & 1; 
			V1 = (V1>>1) | (V0<<63);
			V0 = (V0>>1) ^ (x ? W64LIT(0xe1) << 56 : 0);
		}

		for (i=0; i<4; i++)
		{
			memset(table+i*256, 0, 16);
			memset(table+1024+i*256, 0, 16);
			for (j=2; j<=8; j*=2)
				for (k=1; k<j; k++)
				{
					xorbuf(table+i*256+(j+k)*16, table+i*256+j*16, table+i*256+k*16, 16);
					xorbuf(table+1024+i*256+(j+k)*16, table+1024+i*256+j*16, table+1024+i*256+k*16, 16);
				}
		}
	}
}

void GCM_Base::Resync(const byte *iv, size_t len)
{
	BlockCipher &cipher = AccessBlockCipher();
	byte *hashBuffer = HashBuffer();

	if (len == 12)
	{
		memcpy(hashBuffer, iv, len);
		memset(hashBuffer+len, 0, 3);
		hashBuffer[len+3] = 1;
	}
	else
	{
		size_t origLen = len;
		memset(hashBuffer, 0, HASH_BLOCKSIZE);

		if (len >= HASH_BLOCKSIZE)
		{
			len = GCM_Base::AuthenticateBlocks(iv, len);
			iv += (origLen - len);
		}

		if (len > 0)
		{
			memcpy(m_buffer, iv, len);
			memset(m_buffer+len, 0, HASH_BLOCKSIZE-len);
			GCM_Base::AuthenticateBlocks(m_buffer, HASH_BLOCKSIZE);
		}

		PutBlock<word64, BigEndian, true>::PutBlock(NULL, m_buffer)(0)(origLen*8);
		GCM_Base::AuthenticateBlocks(m_buffer, HASH_BLOCKSIZE);
	}

	if (m_state >= State_IVSet)
		m_ctr.Resynchronize(hashBuffer, REQUIRED_BLOCKSIZE);
	else
		m_ctr.SetCipherWithIV(cipher, hashBuffer);

	m_ctr.Seek(HASH_BLOCKSIZE);

	memset(hashBuffer, 0, HASH_BLOCKSIZE);
}

unsigned int GCM_Base::OptimalDataAlignment() const
{
	return HasSSE2() ? 16 : GetBlockCipher().OptimalDataAlignment();
}

#pragma warning(disable: 4731)	// frame pointer register 'ebp' modified by inline assembly code

#endif	// #ifndef CRYPTOPP_GENERATE_X64_MASM

#ifdef CRYPTOPP_X64_MASM_AVAILABLE
extern "C" {
void GCM_AuthenticateBlocks_2K(const byte *data, size_t blocks, word64 *hashBuffer, const word16 *reductionTable);
void GCM_AuthenticateBlocks_64K(const byte *data, size_t blocks, word64 *hashBuffer);
}
#endif

#ifndef CRYPTOPP_GENERATE_X64_MASM

size_t GCM_Base::AuthenticateBlocks(const byte *data, size_t len)
{
	typedef BlockGetAndPut<word64, NativeByteOrder, false, true> Block;
	word64 *hashBuffer = (word64 *)HashBuffer();

	switch (2*(m_buffer.size()>=64*1024)
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE || defined(CRYPTOPP_X64_MASM_AVAILABLE)
		+ HasSSE2()
#endif
		)
	{
	case 0:		// non-SSE2 and 2K tables
		{
		byte *table = MulTable();
		word64 x0 = hashBuffer[0], x1 = hashBuffer[1];

		do
		{
			word64 y0, y1, a0, a1, b0, b1, c0, c1, d0, d1;
			Block::Get(data)(y0)(y1);
			x0 ^= y0;
			x1 ^= y1;

			data += HASH_BLOCKSIZE;
			len -= HASH_BLOCKSIZE;

			#define READ_TABLE_WORD64_COMMON(a, b, c, d)	*(word64 *)(table+(a*1024)+(b*256)+c+d*8)

			#ifdef IS_LITTLE_ENDIAN
				#if CRYPTOPP_BOOL_SLOW_WORD64
					word32 z0 = (word32)x0;
					word32 z1 = (word32)(x0>>32);
					word32 z2 = (word32)x1;
					word32 z3 = (word32)(x1>>32);
					#define READ_TABLE_WORD64(a, b, c, d, e)	READ_TABLE_WORD64_COMMON((d%2), c, (d?(z##c>>((d?d-1:0)*4))&0xf0:(z##c&0xf)<<4), e)
				#else
					#define READ_TABLE_WORD64(a, b, c, d, e)	READ_TABLE_WORD64_COMMON((d%2), c, ((d+8*b)?(x##a>>(((d+8*b)?(d+8*b)-1:1)*4))&0xf0:(x##a&0xf)<<4), e)
				#endif
				#define GF_MOST_SIG_8BITS(a) (a##1 >> 7*8)
				#define GF_SHIFT_8(a) a##1 = (a##1 << 8) ^ (a##0 >> 7*8); a##0 <<= 8;
			#else
				#define READ_TABLE_WORD64(a, b, c, d, e)	READ_TABLE_WORD64_COMMON((1-d%2), c, ((15-d-8*b)?(x##a>>(((15-d-8*b)?(15-d-8*b)-1:0)*4))&0xf0:(x##a&0xf)<<4), e)
				#define GF_MOST_SIG_8BITS(a) (a##1 & 0xff)
				#define GF_SHIFT_8(a) a##1 = (a##1 >> 8) ^ (a##0 << 7*8); a##0 >>= 8;
			#endif

			#define GF_MUL_32BY128(op, a, b, c)											\
				a0 op READ_TABLE_WORD64(a, b, c, 0, 0) ^ READ_TABLE_WORD64(a, b, c, 1, 0);\
				a1 op READ_TABLE_WORD64(a, b, c, 0, 1) ^ READ_TABLE_WORD64(a, b, c, 1, 1);\
				b0 op READ_TABLE_WORD64(a, b, c, 2, 0) ^ READ_TABLE_WORD64(a, b, c, 3, 0);\
				b1 op READ_TABLE_WORD64(a, b, c, 2, 1) ^ READ_TABLE_WORD64(a, b, c, 3, 1);\
				c0 op READ_TABLE_WORD64(a, b, c, 4, 0) ^ READ_TABLE_WORD64(a, b, c, 5, 0);\
				c1 op READ_TABLE_WORD64(a, b, c, 4, 1) ^ READ_TABLE_WORD64(a, b, c, 5, 1);\
				d0 op READ_TABLE_WORD64(a, b, c, 6, 0) ^ READ_TABLE_WORD64(a, b, c, 7, 0);\
				d1 op READ_TABLE_WORD64(a, b, c, 6, 1) ^ READ_TABLE_WORD64(a, b, c, 7, 1);\

			GF_MUL_32BY128(=, 0, 0, 0)
			GF_MUL_32BY128(^=, 0, 1, 1)
			GF_MUL_32BY128(^=, 1, 0, 2)
			GF_MUL_32BY128(^=, 1, 1, 3)

			word32 r = (word32)s_reductionTable[GF_MOST_SIG_8BITS(d)] << 16;
			GF_SHIFT_8(d)
			c0 ^= d0; c1 ^= d1;
			r ^= (word32)s_reductionTable[GF_MOST_SIG_8BITS(c)] << 8;
			GF_SHIFT_8(c)
			b0 ^= c0; b1 ^= c1;
			r ^= s_reductionTable[GF_MOST_SIG_8BITS(b)];
			GF_SHIFT_8(b)
			a0 ^= b0; a1 ^= b1;
			a0 ^= ConditionalByteReverse<word64>(LITTLE_ENDIAN_ORDER, r);
			x0 = a0; x1 = a1;
		}
		while (len >= HASH_BLOCKSIZE);

		hashBuffer[0] = x0; hashBuffer[1] = x1;
		return len;
		}

	case 2:		// non-SSE2 and 64K tables
		{
		byte *table = MulTable();
		word64 x0 = hashBuffer[0], x1 = hashBuffer[1];

		do
		{
			word64 y0, y1, a0, a1;
			Block::Get(data)(y0)(y1);
			x0 ^= y0;
			x1 ^= y1;

			data += HASH_BLOCKSIZE;
			len -= HASH_BLOCKSIZE;

			#undef READ_TABLE_WORD64_COMMON
			#undef READ_TABLE_WORD64

			#define READ_TABLE_WORD64_COMMON(a, c, d)	*(word64 *)(table+(a)*256*16+(c)+(d)*8)

			#ifdef IS_LITTLE_ENDIAN
				#if CRYPTOPP_BOOL_SLOW_WORD64
					word32 z0 = (word32)x0;
					word32 z1 = (word32)(x0>>32);
					word32 z2 = (word32)x1;
					word32 z3 = (word32)(x1>>32);
					#define READ_TABLE_WORD64(b, c, d, e)	READ_TABLE_WORD64_COMMON(c*4+d, (d?(z##c>>((d?d:1)*8-4))&0xff0:(z##c&0xff)<<4), e)
				#else
					#define READ_TABLE_WORD64(b, c, d, e)	READ_TABLE_WORD64_COMMON(c*4+d, ((d+4*(c%2))?(x##b>>(((d+4*(c%2))?(d+4*(c%2)):1)*8-4))&0xff0:(x##b&0xff)<<4), e)
				#endif
			#else
				#define READ_TABLE_WORD64(b, c, d, e)	READ_TABLE_WORD64_COMMON(c*4+d, ((7-d-4*(c%2))?(x##b>>(((7-d-4*(c%2))?(7-d-4*(c%2)):1)*8-4))&0xff0:(x##b&0xff)<<4), e)
			#endif

			#define GF_MUL_8BY128(op, b, c, d)		\
				a0 op READ_TABLE_WORD64(b, c, d, 0);\
				a1 op READ_TABLE_WORD64(b, c, d, 1);\

			GF_MUL_8BY128(=, 0, 0, 0)
			GF_MUL_8BY128(^=, 0, 0, 1)
			GF_MUL_8BY128(^=, 0, 0, 2)
			GF_MUL_8BY128(^=, 0, 0, 3)
			GF_MUL_8BY128(^=, 0, 1, 0)
			GF_MUL_8BY128(^=, 0, 1, 1)
			GF_MUL_8BY128(^=, 0, 1, 2)
			GF_MUL_8BY128(^=, 0, 1, 3)
			GF_MUL_8BY128(^=, 1, 2, 0)
			GF_MUL_8BY128(^=, 1, 2, 1)
			GF_MUL_8BY128(^=, 1, 2, 2)
			GF_MUL_8BY128(^=, 1, 2, 3)
			GF_MUL_8BY128(^=, 1, 3, 0)
			GF_MUL_8BY128(^=, 1, 3, 1)
			GF_MUL_8BY128(^=, 1, 3, 2)
			GF_MUL_8BY128(^=, 1, 3, 3)

			x0 = a0; x1 = a1;
		}
		while (len >= HASH_BLOCKSIZE);

		hashBuffer[0] = x0; hashBuffer[1] = x1;
		return len;
		}
#endif	// #ifndef CRYPTOPP_GENERATE_X64_MASM

#ifdef CRYPTOPP_X64_MASM_AVAILABLE
	case 1:		// SSE2 and 2K tables
		GCM_AuthenticateBlocks_2K(data, len/16, hashBuffer, s_reductionTable);
		return len % 16;
	case 3:		// SSE2 and 64K tables
		GCM_AuthenticateBlocks_64K(data, len/16, hashBuffer);
		return len % 16;
#endif

#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	case 1:		// SSE2 and 2K tables
		{
		#ifdef __GNUC__
			__asm__ __volatile__
			(
			".intel_syntax noprefix;"
		#elif defined(CRYPTOPP_GENERATE_X64_MASM)
			ALIGN   8
			GCM_AuthenticateBlocks_2K	PROC FRAME
			rex_push_reg rsi
			push_reg rdi
			push_reg rbx
			.endprolog
			mov rsi, r8
			mov r11, r9
		#else
			AS2(	mov		WORD_REG(cx), data			)
			AS2(	mov		WORD_REG(dx), len			)
			AS2(	mov		WORD_REG(si), hashBuffer	)
			AS2(	shr		WORD_REG(dx), 4				)
		#endif

		#if !defined(_MSC_VER) || (_MSC_VER < 1300)
			AS_PUSH_IF86(	bx)
		#endif
		AS_PUSH_IF86(	bp)

		#ifdef __GNUC__
			AS2(	mov		AS_REG_7, WORD_REG(di))
		#elif CRYPTOPP_BOOL_X86
			AS2(	lea		AS_REG_7, s_reductionTable)
		#endif

		AS2(	movdqa	xmm0, [WORD_REG(si)]			)

		#define MUL_TABLE_0 WORD_REG(si) + 32
		#define MUL_TABLE_1 WORD_REG(si) + 32 + 1024
		#define RED_TABLE AS_REG_7

		ASL(0)
		AS2(	movdqu	xmm4, [WORD_REG(cx)]			)
		AS2(	pxor	xmm0, xmm4						)

		AS2(	movd	ebx, xmm0						)
		AS2(	mov		eax, AS_HEX(f0f0f0f0)			)
		AS2(	and		eax, ebx						)
		AS2(	shl		ebx, 4							)
		AS2(	and		ebx, AS_HEX(f0f0f0f0)			)
		AS2(	movzx	edi, ah							)
		AS2(	movdqa	xmm5, XMMWORD_PTR [MUL_TABLE_1 + WORD_REG(di)]	)
		AS2(	movzx	edi, al					)
		AS2(	movdqa	xmm4, XMMWORD_PTR [MUL_TABLE_1 + WORD_REG(di)]	)
		AS2(	shr		eax, 16							)
		AS2(	movzx	edi, ah					)
		AS2(	movdqa	xmm3, XMMWORD_PTR [MUL_TABLE_1 + WORD_REG(di)]	)
		AS2(	movzx	edi, al					)
		AS2(	movdqa	xmm2, XMMWORD_PTR [MUL_TABLE_1 + WORD_REG(di)]	)

		#define SSE2_MUL_32BITS(i)											\
			AS2(	psrldq	xmm0, 4											)\
			AS2(	movd	eax, xmm0										)\
			AS2(	and		eax, AS_HEX(f0f0f0f0)									)\
			AS2(	movzx	edi, bh											)\
			AS2(	pxor	xmm5, XMMWORD_PTR [MUL_TABLE_0 + (i-1)*256 + WORD_REG(di)]	)\
			AS2(	movzx	edi, bl											)\
			AS2(	pxor	xmm4, XMMWORD_PTR [MUL_TABLE_0 + (i-1)*256 + WORD_REG(di)]	)\
			AS2(	shr		ebx, 16											)\
			AS2(	movzx	edi, bh											)\
			AS2(	pxor	xmm3, XMMWORD_PTR [MUL_TABLE_0 + (i-1)*256 + WORD_REG(di)]	)\
			AS2(	movzx	edi, bl											)\
			AS2(	pxor	xmm2, XMMWORD_PTR [MUL_TABLE_0 + (i-1)*256 + WORD_REG(di)]	)\
			AS2(	movd	ebx, xmm0										)\
			AS2(	shl		ebx, 4											)\
			AS2(	and		ebx, AS_HEX(f0f0f0f0)									)\
			AS2(	movzx	edi, ah											)\
			AS2(	pxor	xmm5, XMMWORD_PTR [MUL_TABLE_1 + i*256 + WORD_REG(di)]		)\
			AS2(	movzx	edi, al											)\
			AS2(	pxor	xmm4, XMMWORD_PTR [MUL_TABLE_1 + i*256 + WORD_REG(di)]		)\
			AS2(	shr		eax, 16											)\
			AS2(	movzx	edi, ah											)\
			AS2(	pxor	xmm3, XMMWORD_PTR [MUL_TABLE_1 + i*256 + WORD_REG(di)]		)\
			AS2(	movzx	edi, al											)\
			AS2(	pxor	xmm2, XMMWORD_PTR [MUL_TABLE_1 + i*256 + WORD_REG(di)]		)\

		SSE2_MUL_32BITS(1)
		SSE2_MUL_32BITS(2)
		SSE2_MUL_32BITS(3)

		AS2(	movzx	edi, bh					)
		AS2(	pxor	xmm5, XMMWORD_PTR [MUL_TABLE_0 + 3*256 + WORD_REG(di)]	)
		AS2(	movzx	edi, bl					)
		AS2(	pxor	xmm4, XMMWORD_PTR [MUL_TABLE_0 + 3*256 + WORD_REG(di)]	)
		AS2(	shr		ebx, 16						)
		AS2(	movzx	edi, bh					)
		AS2(	pxor	xmm3, XMMWORD_PTR [MUL_TABLE_0 + 3*256 + WORD_REG(di)]	)
		AS2(	movzx	edi, bl					)
		AS2(	pxor	xmm2, XMMWORD_PTR [MUL_TABLE_0 + 3*256 + WORD_REG(di)]	)

		AS2(	movdqa	xmm0, xmm3						)
		AS2(	pslldq	xmm3, 1							)
		AS2(	pxor	xmm2, xmm3						)
		AS2(	movdqa	xmm1, xmm2						)
		AS2(	pslldq	xmm2, 1							)
		AS2(	pxor	xmm5, xmm2						)

		AS2(	psrldq	xmm0, 15						)
		AS2(	movd	WORD_REG(di), xmm0					)
		AS2(	movzx	eax, WORD PTR [RED_TABLE + WORD_REG(di)*2]	)
		AS2(	shl		eax, 8							)

		AS2(	movdqa	xmm0, xmm5						)
		AS2(	pslldq	xmm5, 1							)
		AS2(	pxor	xmm4, xmm5						)

		AS2(	psrldq	xmm1, 15						)
		AS2(	movd	WORD_REG(di), xmm1					)
		AS2(	xor		ax, WORD PTR [RED_TABLE + WORD_REG(di)*2]	)
		AS2(	shl		eax, 8							)

		AS2(	psrldq	xmm0, 15						)
		AS2(	movd	WORD_REG(di), xmm0					)
		AS2(	xor		ax, WORD PTR [RED_TABLE + WORD_REG(di)*2]	)

		AS2(	movd	xmm0, eax						)
		AS2(	pxor	xmm0, xmm4						)

		AS2(	add		WORD_REG(cx), 16					)
		AS2(	sub		WORD_REG(dx), 1						)
		ASJ(	jnz,	0, b							)
		AS2(	movdqa	[WORD_REG(si)], xmm0				)

		AS_POP_IF86(	bp)
		#if !defined(_MSC_VER) || (_MSC_VER < 1300)
			AS_POP_IF86(	bx)
		#endif

		#ifdef __GNUC__
				".att_syntax prefix;"
					: 
					: "c" (data), "d" (len/16), "S" (hashBuffer), "D" (s_reductionTable)
					: "memory", "cc", "%eax"
			#if CRYPTOPP_BOOL_X64
					, "%ebx", "%r11"
			#endif
				);
		#elif defined(CRYPTOPP_GENERATE_X64_MASM)
			pop rbx
			pop rdi
			pop rsi
			ret
			GCM_AuthenticateBlocks_2K ENDP
		#endif

		return len%16;
		}
	case 3:		// SSE2 and 64K tables
		{
		#ifdef __GNUC__
			__asm__ __volatile__
			(
			".intel_syntax noprefix;"
		#elif defined(CRYPTOPP_GENERATE_X64_MASM)
			ALIGN   8
			GCM_AuthenticateBlocks_64K	PROC FRAME
			rex_push_reg rsi
			push_reg rdi
			.endprolog
			mov rsi, r8
		#else
			AS2(	mov		WORD_REG(cx), data			)
			AS2(	mov		WORD_REG(dx), len			)
			AS2(	mov		WORD_REG(si), hashBuffer	)
			AS2(	shr		WORD_REG(dx), 4				)
		#endif

		AS2(	movdqa	xmm0, [WORD_REG(si)]				)

		#undef MUL_TABLE
		#define MUL_TABLE(i,j) WORD_REG(si) + 32 + (i*4+j)*256*16

		ASL(1)
		AS2(	movdqu	xmm1, [WORD_REG(cx)]				)
		AS2(	pxor	xmm1, xmm0						)
		AS2(	pxor	xmm0, xmm0						)

		#undef SSE2_MUL_32BITS
		#define SSE2_MUL_32BITS(i)								\
			AS2(	movd	eax, xmm1							)\
			AS2(	psrldq	xmm1, 4								)\
			AS2(	movzx	edi, al						)\
			AS2(	add		WORD_REG(di), WORD_REG(di)					)\
			AS2(	pxor	xmm0, [MUL_TABLE(i,0) + WORD_REG(di)*8]	)\
			AS2(	movzx	edi, ah						)\
			AS2(	add		WORD_REG(di), WORD_REG(di)					)\
			AS2(	pxor	xmm0, [MUL_TABLE(i,1) + WORD_REG(di)*8]	)\
			AS2(	shr		eax, 16								)\
			AS2(	movzx	edi, al						)\
			AS2(	add		WORD_REG(di), WORD_REG(di)					)\
			AS2(	pxor	xmm0, [MUL_TABLE(i,2) + WORD_REG(di)*8]	)\
			AS2(	movzx	edi, ah						)\
			AS2(	add		WORD_REG(di), WORD_REG(di)					)\
			AS2(	pxor	xmm0, [MUL_TABLE(i,3) + WORD_REG(di)*8]	)\

		SSE2_MUL_32BITS(0)
		SSE2_MUL_32BITS(1)
		SSE2_MUL_32BITS(2)
		SSE2_MUL_32BITS(3)

		AS2(	add		WORD_REG(cx), 16					)
		AS2(	sub		WORD_REG(dx), 1						)
		ASJ(	jnz,	1, b							)
		AS2(	movdqa	[WORD_REG(si)], xmm0				)

		#ifdef __GNUC__
				".att_syntax prefix;"
					: 
					: "c" (data), "d" (len/16), "S" (hashBuffer)
					: "memory", "cc", "%edi", "%eax"
				);
		#elif defined(CRYPTOPP_GENERATE_X64_MASM)
			pop rdi
			pop rsi
			ret
			GCM_AuthenticateBlocks_64K ENDP
		#endif

		return len%16;
		}
#endif
#ifndef CRYPTOPP_GENERATE_X64_MASM
	}

	return len%16;

#if 0
		byte *hashBuffer = HashBuffer(), *hashKey = HashKey();

		__m128i b = _mm_load_si128((__m128i *)hashBuffer);
		__m128i mask = _mm_load_si128((__m128i *)s_GCM_mask);
		byte *table = MulTable();

		do
		{
			b = _mm_xor_si128(b, _mm_loadu_si128((__m128i *)data));
			data += HASH_BLOCKSIZE;
			len -= HASH_BLOCKSIZE;

#define SSE2_READ_TABLE(a, b, c)	*(__m128i *)(table+(a*1024)+(b*16*16)+(c?(x>>((c?c-1:1)*4))&0xf0:(x&0xf)<<4))

			word32 x = _mm_cvtsi128_si32(b);
			__m128i a0 = _mm_xor_si128(SSE2_READ_TABLE(0, 0, 0), SSE2_READ_TABLE(1, 0, 1));
			__m128i a1 = _mm_xor_si128(SSE2_READ_TABLE(0, 0, 2), SSE2_READ_TABLE(1, 0, 3));
			__m128i a2 = _mm_xor_si128(SSE2_READ_TABLE(0, 0, 4), SSE2_READ_TABLE(1, 0, 5));
			__m128i a3 = _mm_xor_si128(SSE2_READ_TABLE(0, 0, 6), SSE2_READ_TABLE(1, 0, 7));

#define SSE2_MULTIPLY_32(i)	\
			b = _mm_srli_si128(b, 4);							\
			x = _mm_cvtsi128_si32(b);							\
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(0, i, 0));	\
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(1, i, 1));	\
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(0, i, 2));	\
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(1, i, 3));	\
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(0, i, 4));	\
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(1, i, 5));	\
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(0, i, 6));	\
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(1, i, 7));

			SSE2_MULTIPLY_32(1)
			SSE2_MULTIPLY_32(2)
			SSE2_MULTIPLY_32(3)

			word32 r = (word32)s_reductionTable[_mm_cvtsi128_si32(_mm_srli_si128(a3, 15))] << 16;
			a3 = _mm_slli_si128(a3, 1);
			a2 = _mm_xor_si128(a2, a3);
			r ^= (word32)s_reductionTable[_mm_cvtsi128_si32(_mm_srli_si128(a2, 15))] << 8;
			a2 = _mm_slli_si128(a2, 1);
			a1 = _mm_xor_si128(a1, a2);
			r ^= s_reductionTable[_mm_cvtsi128_si32(_mm_srli_si128(a1, 15))];
			a1 = _mm_slli_si128(a1, 1);
			a0 = _mm_xor_si128(a0, a1);
			b = _mm_xor_si128(a0, _mm_cvtsi32_si128(r));
		}
		while (len >= HASH_BLOCKSIZE);

		_mm_store_si128((__m128i *)hashBuffer, b);
		__m128i b = *(__m128i *)hashBuffer;
		__m128i mask = *(__m128i *)s_GCM_mask;
		byte *table = MulTable();

		do
		{
			b = _mm_xor_si128(b, _mm_loadu_si128((__m128i *)data));
			data += HASH_BLOCKSIZE;
			len -= HASH_BLOCKSIZE;

			__m128i c0 = _mm_and_si128(_mm_slli_epi16(b, 4), mask);
			__m128i c1 = _mm_and_si128(b, mask);
			__m128i c2 = _mm_and_si128(_mm_srli_epi16(b, 4), mask);
			__m128i c3 = _mm_and_si128(_mm_srli_epi16(b, 8), mask);

#define SSE2_READ_TABLE(a, c, d) *(__m128i *)(table+(a*1024)+((d/2)*16*16)+(size_t)(word16)_mm_extract_epi16(c, d))

			__m128i a3 = SSE2_READ_TABLE(0, c2, 1);
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(1, c3, 1));
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(0, c2, 3));
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(1, c3, 3));
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(0, c2, 5));
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(1, c3, 5));
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(0, c2, 7));
			a3 = _mm_xor_si128(a3, SSE2_READ_TABLE(1, c3, 7));

			word32 r = (word32)s_reductionTable[((word16)_mm_extract_epi16(a3, 7))>>8] << 16;
			a3 = _mm_slli_si128(a3, 1);

			__m128i a2 = _mm_xor_si128(a3, SSE2_READ_TABLE(0, c0, 1));
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(1, c1, 1));
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(0, c0, 3));
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(1, c1, 3));
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(0, c0, 5));
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(1, c1, 5));
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(0, c0, 7));
			a2 = _mm_xor_si128(a2, SSE2_READ_TABLE(1, c1, 7));

			r ^= (word32)s_reductionTable[_mm_cvtsi128_si32(_mm_srli_si128(a2, 15))] << 8;
			a2 = _mm_slli_si128(a2, 1);

			__m128i a1 = _mm_xor_si128(a2, SSE2_READ_TABLE(0, c2, 0));
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(1, c3, 0));
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(0, c2, 2));
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(1, c3, 2));
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(0, c2, 4));
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(1, c3, 4));
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(0, c2, 6));
			a1 = _mm_xor_si128(a1, SSE2_READ_TABLE(1, c3, 6));

			r ^= s_reductionTable[_mm_cvtsi128_si32(_mm_srli_si128(a1, 15))];
			a1 = _mm_slli_si128(a1, 1);

			__m128i a0 = _mm_xor_si128(a1, SSE2_READ_TABLE(0, c0, 0));
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(1, c1, 0));
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(0, c0, 2));
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(1, c1, 2));
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(0, c0, 4));
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(1, c1, 4));
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(0, c0, 6));
			a0 = _mm_xor_si128(a0, SSE2_READ_TABLE(1, c1, 6));

			b = _mm_xor_si128(a0, _mm_cvtsi32_si128(r));
		}
		while (len >= HASH_BLOCKSIZE);

		_mm_store_si128((__m128i *)hashBuffer, b);

	return len;
#endif
}

void GCM_Base::AuthenticateLastHeaderBlock()
{
	if (m_bufferedDataLength > 0)
	{
		memset(m_buffer+m_bufferedDataLength, 0, HASH_BLOCKSIZE-m_bufferedDataLength);
		m_bufferedDataLength = 0;
		GCM_Base::AuthenticateBlocks(m_buffer, HASH_BLOCKSIZE);
	}
}

void GCM_Base::AuthenticateLastConfidentialBlock()
{
	GCM_Base::AuthenticateLastHeaderBlock();
	PutBlock<word64, BigEndian, true>(NULL, m_buffer)(m_totalHeaderLength*8)(m_totalMessageLength*8);
	GCM_Base::AuthenticateBlocks(m_buffer, HASH_BLOCKSIZE);
}

void GCM_Base::AuthenticateLastFooterBlock(byte *mac, size_t macSize)
{
	m_ctr.Seek(0);
	m_ctr.ProcessData(mac, HashBuffer(), macSize);
}

NAMESPACE_END

#endif	// #ifndef CRYPTOPP_GENERATE_X64_MASM
#endif
