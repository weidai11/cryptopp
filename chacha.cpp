// chacha.cpp - written and placed in the public domain by Jeffrey Walton.
//              Copyright assigned to the Crypto++ project.

#include "pch.h"
#include "config.h"
#include "chacha.h"
#include "argnames.h"
#include "misc.h"
#include "cpu.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4702 4740)
#endif

NAMESPACE_BEGIN(CryptoPP)
	
#define CHACHA_QUARTER_ROUND(z,a,b,c,d) \
    z[a] += z[b]; z[d] ^= z[a]; z[d] = rotrFixed<word32>(z[d],16); \
    z[c] += z[d]; z[b] ^= z[c]; z[b] = rotrFixed<word32>(z[b],12); \
    z[a] += z[b]; z[d] ^= z[a]; z[d] = rotrFixed<word32>(z[d], 8); \
    z[c] += z[d]; z[b] ^= z[c]; z[b] = rotrFixed<word32>(z[b], 7);

#if !defined(NDEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
void ChaCha_TestInstantiations()
{
	ChaCha8::Encryption x1;
	ChaCha12::Encryption x2;
	ChaCha20::Encryption x3;
}
#endif


static inline void salsa20_wordtobyte(byte output[64], const word32 input[16])
{
	word32 x[16];
	unsigned int i;

	for (i = 0;i < 16;++i)
		x[i] = input[i];

	for (i = 8;i > 0;i -= 2)
	{
		CHACHA_QUARTER_ROUND(x, 0, 4, 8,12);
		CHACHA_QUARTER_ROUND(x, 1, 5, 9,13);
		CHACHA_QUARTER_ROUND(x, 2, 6,10,14);
		CHACHA_QUARTER_ROUND(x, 3, 7,11,15);
		CHACHA_QUARTER_ROUND(x, 0, 5,10,15);
		CHACHA_QUARTER_ROUND(x, 1, 6,11,12);
		CHACHA_QUARTER_ROUND(x, 2, 7, 8,13);
		CHACHA_QUARTER_ROUND(x, 3, 4, 9,14);
	}

	for (i = 0;i < 16;++i)
		x[i] += input[i];
 
	//for (i = 0;i < 16;++i)
	//	U32TO8_LITTLE(output + 4 * i,x[i]);

	//for (i = 0;i < 16;++i)
	//	PutWord<>(output + 4 * i,x[i]);
}

template <unsigned int R>
void ChaCha_Base<R>::CipherSetKey(const NameValuePairs &params, const byte *key, size_t length)
{
	// m_state is reordered for SSE2
	GetBlock<word32, LittleEndian> get1(key);
	get1(m_state[13])(m_state[10])(m_state[7])(m_state[4]);
	GetBlock<word32, LittleEndian> get2(key + length - 16);
	get2(m_state[15])(m_state[12])(m_state[9])(m_state[6]);

	// "expand 16-byte k" or "expand 32-byte k"
	m_state[0] = 0x61707865;
	m_state[1] = (length == 16) ? 0x3120646e : 0x3320646e;
	m_state[2] = (length == 16) ? 0x79622d36 : 0x79622d32;
	m_state[3] = 0x6b206574;
}

template <unsigned int R>
void ChaCha_Base<R>::CipherResynchronize(byte *keystreamBuffer, const byte *IV, size_t length)
{
	CRYPTOPP_UNUSED(keystreamBuffer), CRYPTOPP_UNUSED(length);
	assert(length==8);

	GetBlock<word32, LittleEndian> get(IV);
	get(m_state[14])(m_state[11]);
	m_state[8] = m_state[5] = 0;
}

template<unsigned int R>
void ChaCha_Base<R>::SeekToIteration(lword iterationCount)
{
	m_state[8] = (word32)iterationCount;
	m_state[5] = (word32)SafeRightShift<32>(iterationCount);
}

template<unsigned int R>
unsigned int ChaCha_Base<R>::GetAlignment() const
{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	if (HasSSE2())
		return 16;
	else
#endif
		return GetAlignmentOf<word32>();
}

template<unsigned int R>
unsigned int ChaCha_Base<R>::GetOptimalBlockSize() const
{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	if (HasSSE2())
		return 4*BYTES_PER_ITERATION;
	else
#endif
		return BYTES_PER_ITERATION;
}

template<unsigned int R>
void ChaCha_Base<R>::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount)
{
    byte buffer[64];
    size_t i, bytes=64;

	if (!bytes) return;

	for (;;)
	{
		salsa20_wordtobyte(buffer,m_state);

		m_state[12]++;
		if (!m_state[12])
			m_state[13]++;

		if (bytes <= 64)
		{
			for (i = 0;i < bytes;++i)
				output[i] = input[i] ^ buffer[i];
			return;
		}

		for (i = 0;i < 64;++i)
			output[i] = input[i] ^ buffer[i];
		
		bytes -= 64;
		output += 64;
		input += 64;
	}
}

NAMESPACE_END
	