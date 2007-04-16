// salsa.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "salsa.h"
#include "misc.h"
#include "argnames.h"
#include "cpu.h"

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
#include <emmintrin.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

void Salsa20_TestInstantiations()
{
	Salsa20::Encryption x;
}

void Salsa20_Policy::CipherGetNextIV(byte *IV)
{
	word32 j6, j7;

	j6 = m_state[14] + 1;
	j7 = m_state[11] + (j6 == 0);

	PutWord(false, LITTLE_ENDIAN_ORDER, IV, j6);
	PutWord(false, LITTLE_ENDIAN_ORDER, IV+4, j7);
}

void Salsa20_Policy::CipherSetKey(const NameValuePairs &params, const byte *key, size_t length)
{
	m_rounds = params.GetIntValueWithDefault(Name::Rounds(), 20);

	if (!(m_rounds == 8 || m_rounds == 12 || m_rounds == 20))
		throw InvalidRounds(StaticAlgorithmName(), m_rounds);

	// m_state is reordered for SSE2
	GetBlock<word32, LittleEndian, false> get1(key);
	get1(m_state[13])(m_state[10])(m_state[7])(m_state[4]);
	GetBlock<word32, LittleEndian, false> get2(key + length - 16);
	get2(m_state[15])(m_state[12])(m_state[9])(m_state[6]);

	// "expand 16-byte k" or "expand 32-byte k"
	m_state[0] = 0x61707865;
	m_state[1] = (length == 16) ? 0x3120646e : 0x3320646e;
	m_state[2] = (length == 16) ? 0x79622d36 : 0x79622d32;
	m_state[3] = 0x6b206574;
}

void Salsa20_Policy::CipherResynchronize(byte *keystreamBuffer, const byte *IV)
{
	GetBlock<word32, LittleEndian, false> get(IV);
	get(m_state[14])(m_state[11]);
	m_state[8] = m_state[5] = 0;
}

void Salsa20_Policy::SeekToIteration(lword iterationCount)
{
	m_state[8] = (word32)iterationCount;
	m_state[5] = (word32)SafeRightShift<32>(iterationCount);
}

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X64
unsigned int Salsa20_Policy::GetAlignment() const
{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
	if (HasSSE2())
		return 16;
	else
#endif
		return 1;
}

unsigned int Salsa20_Policy::GetOptimalBlockSize() const
{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
	if (HasSSE2())
		return 4*BYTES_PER_ITERATION;
	else
#endif
		return BYTES_PER_ITERATION;
}
#endif

void Salsa20_Policy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount)
{
	int i;
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
	if (HasSSE2())
	{
		__m128i *s = (__m128i *)m_state.data();

		if (iterationCount >= 4)
		{
			__m128i ss[16];
			ss[0] = _mm_shuffle_epi32(s[0], _MM_SHUFFLE(0, 0, 0, 0));
			ss[1] = _mm_shuffle_epi32(s[0], _MM_SHUFFLE(1, 1, 1, 1));
			ss[2] = _mm_shuffle_epi32(s[0], _MM_SHUFFLE(2, 2, 2, 2));
			ss[3] = _mm_shuffle_epi32(s[0], _MM_SHUFFLE(3, 3, 3, 3));
			ss[4] = _mm_shuffle_epi32(s[1], _MM_SHUFFLE(0, 0, 0, 0));
			ss[6] = _mm_shuffle_epi32(s[1], _MM_SHUFFLE(2, 2, 2, 2));
			ss[7] = _mm_shuffle_epi32(s[1], _MM_SHUFFLE(3, 3, 3, 3));
			ss[9] = _mm_shuffle_epi32(s[2], _MM_SHUFFLE(1, 1, 1, 1));
			ss[10] = _mm_shuffle_epi32(s[2], _MM_SHUFFLE(2, 2, 2, 2));
			ss[11] = _mm_shuffle_epi32(s[2], _MM_SHUFFLE(3, 3, 3, 3));
			ss[12] = _mm_shuffle_epi32(s[3], _MM_SHUFFLE(0, 0, 0, 0));
			ss[13] = _mm_shuffle_epi32(s[3], _MM_SHUFFLE(1, 1, 1, 1));
			ss[14] = _mm_shuffle_epi32(s[3], _MM_SHUFFLE(2, 2, 2, 2));
			ss[15] = _mm_shuffle_epi32(s[3], _MM_SHUFFLE(3, 3, 3, 3));

			do
			{
				word32 *countersLo = (word32*)&(ss[8]), *countersHi = (word32*)&(ss[5]);
				for (i=0; i<4; i++)
				{
					countersLo[i] = m_state[8];
					countersHi[i] = m_state[5];
					if (++m_state[8] == 0)
						++m_state[5];
				}

				__m128i x0 = ss[0];
				__m128i x1 = ss[1];
				__m128i x2 = ss[2];
				__m128i x3 = ss[3];
				__m128i x4 = ss[4];
				__m128i x5 = ss[5];
				__m128i x6 = ss[6];
				__m128i x7 = ss[7];
				__m128i x8 = ss[8];
				__m128i x9 = ss[9];
				__m128i x10 = ss[10];
				__m128i x11 = ss[11];
				__m128i x12 = ss[12];
				__m128i x13 = ss[13];
				__m128i x14 = ss[14];
				__m128i x15 = ss[15];

				for (i=m_rounds; i>0; i-=2)
				{
					#define SSE2_QUARTER_ROUND(a, b, d, i)				{\
						__m128i t = _mm_add_epi32(a, d);				\
						b = _mm_xor_si128(b, _mm_slli_epi32(t, i));		\
						b = _mm_xor_si128(b, _mm_srli_epi32(t, 32-i));}

					#define QUARTER_ROUND(a, b, c, d)	\
						SSE2_QUARTER_ROUND(a, b, d, 7)	\
						SSE2_QUARTER_ROUND(b, c, a, 9)	\
						SSE2_QUARTER_ROUND(c, d, b, 13)	\
						SSE2_QUARTER_ROUND(d, a, c, 18)	

					QUARTER_ROUND(x0, x4, x8, x12)
					QUARTER_ROUND(x1, x5, x9, x13)
					QUARTER_ROUND(x2, x6, x10, x14)
					QUARTER_ROUND(x3, x7, x11, x15)

					QUARTER_ROUND(x0, x13, x10, x7)
					QUARTER_ROUND(x1, x14, x11, x4)
					QUARTER_ROUND(x2, x15, x8, x5)
					QUARTER_ROUND(x3, x12, x9, x6)

					#undef QUARTER_ROUND
				}

				x0 = _mm_add_epi32(x0, ss[0]);
				x1 = _mm_add_epi32(x1, ss[1]);
				x2 = _mm_add_epi32(x2, ss[2]);
				x3 = _mm_add_epi32(x3, ss[3]);
				x4 = _mm_add_epi32(x4, ss[4]);
				x5 = _mm_add_epi32(x5, ss[5]);
				x6 = _mm_add_epi32(x6, ss[6]);
				x7 = _mm_add_epi32(x7, ss[7]);
				x8 = _mm_add_epi32(x8, ss[8]);
				x9 = _mm_add_epi32(x9, ss[9]);
				x10 = _mm_add_epi32(x10, ss[10]);
				x11 = _mm_add_epi32(x11, ss[11]);
				x12 = _mm_add_epi32(x12, ss[12]);
				x13 = _mm_add_epi32(x13, ss[13]);
				x14 = _mm_add_epi32(x14, ss[14]);
				x15 = _mm_add_epi32(x15, ss[15]);

				#define OUTPUT_4(x, a, b, c, d, e, f, g, h)	{\
					__m128i t0 = _mm_unpacklo_epi32(a, b);\
					__m128i t1 = _mm_unpacklo_epi32(c, d);\
					__m128i t2 = _mm_unpacklo_epi64(t0, t1);\
					CRYPTOPP_KEYSTREAM_OUTPUT_XMM(x, e, t2)\
					t2 = _mm_unpackhi_epi64(t0, t1);\
					CRYPTOPP_KEYSTREAM_OUTPUT_XMM(x, f, t2)\
					t0 = _mm_unpackhi_epi32(a, b);\
					t1 = _mm_unpackhi_epi32(c, d);\
					t2 = _mm_unpacklo_epi64(t0, t1);\
					CRYPTOPP_KEYSTREAM_OUTPUT_XMM(x, g, t2)\
					t2 = _mm_unpackhi_epi64(t0, t1);\
					CRYPTOPP_KEYSTREAM_OUTPUT_XMM(x, h, t2)}

				#define SALSA_OUTPUT(x)		\
					OUTPUT_4(x, x0, x13, x10, x7, 0, 4, 8, 12)\
					OUTPUT_4(x, x4, x1, x14, x11, 1, 5, 9, 13)\
					OUTPUT_4(x, x8, x5, x2, x15, 2, 6, 10, 14)\
					OUTPUT_4(x, x12, x9, x6, x3, 3, 7, 11, 15)

				CRYPTOPP_KEYSTREAM_OUTPUT_SWITCH(SALSA_OUTPUT, 4*BYTES_PER_ITERATION)

				#undef SALSA_OUTPUT
			} while ((iterationCount-=4) >= 4);
		}

		if (!IsP4()) while (iterationCount)
		{
			--iterationCount;
			__m128i x0 = s[0];
			__m128i x1 = s[1];
			__m128i x2 = s[2];
			__m128i x3 = s[3];

			for (i=m_rounds; i>0; i-=2)
			{
				SSE2_QUARTER_ROUND(x0, x1, x3, 7)
				SSE2_QUARTER_ROUND(x1, x2, x0, 9)
				SSE2_QUARTER_ROUND(x2, x3, x1, 13)
				SSE2_QUARTER_ROUND(x3, x0, x2, 18)

				x1 = _mm_shuffle_epi32(x1, _MM_SHUFFLE(2, 1, 0, 3));
				x2 = _mm_shuffle_epi32(x2, _MM_SHUFFLE(1, 0, 3, 2));
				x3 = _mm_shuffle_epi32(x3, _MM_SHUFFLE(0, 3, 2, 1));

				SSE2_QUARTER_ROUND(x0, x3, x1, 7)
				SSE2_QUARTER_ROUND(x3, x2, x0, 9)
				SSE2_QUARTER_ROUND(x2, x1, x3, 13)
				SSE2_QUARTER_ROUND(x1, x0, x2, 18)

				x1 = _mm_shuffle_epi32(x1, _MM_SHUFFLE(0, 3, 2, 1));
				x2 = _mm_shuffle_epi32(x2, _MM_SHUFFLE(1, 0, 3, 2));
				x3 = _mm_shuffle_epi32(x3, _MM_SHUFFLE(2, 1, 0, 3));
			}

			x0 = _mm_add_epi32(x0, s[0]);
			x1 = _mm_add_epi32(x1, s[1]);
			x2 = _mm_add_epi32(x2, s[2]);
			x3 = _mm_add_epi32(x3, s[3]);

			if (++m_state[8] == 0)
				++m_state[5];

			CRYPTOPP_ALIGN_DATA(16) static const word32 masks[8] CRYPTOPP_SECTION_ALIGN16 = 
				{0, 0xffffffff, 0, 0xffffffff, 0xffffffff, 0, 0xffffffff, 0};

			__m128i k02 = _mm_or_si128(_mm_slli_epi64(x0, 32), _mm_srli_epi64(x3, 32));
			k02 = _mm_shuffle_epi32(k02, _MM_SHUFFLE(0, 1, 2, 3));
			__m128i k13 = _mm_or_si128(_mm_slli_epi64(x1, 32), _mm_srli_epi64(x0, 32));
			k13 = _mm_shuffle_epi32(k13, _MM_SHUFFLE(0, 1, 2, 3));
			__m128i maskLo32 = ((__m128i*)masks)[1], maskHi32 = ((__m128i*)masks)[0];
			__m128i k20 = _mm_or_si128(_mm_and_si128(x2, maskLo32), _mm_and_si128(x1, maskHi32));
			__m128i k31 = _mm_or_si128(_mm_and_si128(x3, maskLo32), _mm_and_si128(x2, maskHi32));

			__m128i k0 = _mm_unpackhi_epi64(k02, k20);
			__m128i k1 = _mm_unpackhi_epi64(k13, k31);
			__m128i k2 = _mm_unpacklo_epi64(k20, k02);
			__m128i k3 = _mm_unpacklo_epi64(k31, k13);

			#define SSE2_OUTPUT(x)	{\
				CRYPTOPP_KEYSTREAM_OUTPUT_XMM(x, 0, k0)\
				CRYPTOPP_KEYSTREAM_OUTPUT_XMM(x, 1, k1)\
				CRYPTOPP_KEYSTREAM_OUTPUT_XMM(x, 2, k2)\
				CRYPTOPP_KEYSTREAM_OUTPUT_XMM(x, 3, k3)}

			CRYPTOPP_KEYSTREAM_OUTPUT_SWITCH(SSE2_OUTPUT, BYTES_PER_ITERATION);
		}
	}
#endif

	word32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;

	while (iterationCount--)
	{
		x0 = m_state[0];
		x1 = m_state[1];
		x2 = m_state[2];
		x3 = m_state[3];
		x4 = m_state[4];
		x5 = m_state[5];
		x6 = m_state[6];
		x7 = m_state[7];
		x8 = m_state[8];
		x9 = m_state[9];
		x10 = m_state[10];
		x11 = m_state[11];
		x12 = m_state[12];
		x13 = m_state[13];
		x14 = m_state[14];
		x15 = m_state[15];

		for (i=m_rounds; i>0; i-=2)
		{
			#define QUARTER_ROUND(a, b, c, d)	\
				b = b ^ rotlFixed(a + d, 7);	\
				c = c ^ rotlFixed(b + a, 9);	\
				d = d ^ rotlFixed(c + b, 13);	\
				a = a ^ rotlFixed(d + c, 18);

			QUARTER_ROUND(x0, x4, x8, x12)
			QUARTER_ROUND(x1, x5, x9, x13)
			QUARTER_ROUND(x2, x6, x10, x14)
			QUARTER_ROUND(x3, x7, x11, x15)

			QUARTER_ROUND(x0, x13, x10, x7)
			QUARTER_ROUND(x1, x14, x11, x4)
			QUARTER_ROUND(x2, x15, x8, x5)
			QUARTER_ROUND(x3, x12, x9, x6)
		}

		#define SALSA_OUTPUT(x)	{\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 0, x0 + m_state[0]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 1, x13 + m_state[13]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 2, x10 + m_state[10]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 3, x7 + m_state[7]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 4, x4 + m_state[4]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 5, x1 + m_state[1]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 6, x14 + m_state[14]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 7, x11 + m_state[11]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 8, x8 + m_state[8]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 9, x5 + m_state[5]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 10, x2 + m_state[2]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 11, x15 + m_state[15]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 12, x12 + m_state[12]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 13, x9 + m_state[9]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 14, x6 + m_state[6]);\
			CRYPTOPP_KEYSTREAM_OUTPUT_WORD(x, LITTLE_ENDIAN_ORDER, 15, x3 + m_state[3]);}

		CRYPTOPP_KEYSTREAM_OUTPUT_SWITCH(SALSA_OUTPUT, BYTES_PER_ITERATION);

		if (++m_state[8] == 0)
			++m_state[5];
	}
}

NAMESPACE_END
