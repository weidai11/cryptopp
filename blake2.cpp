// blake2.cpp - written and placed in the public domain by Jeffrey Walton and Zooko Wilcox-O'Hearn
//              Based on Aumasson, Neves, Wilcox-O’Hearn and Winnerlein's reference BLAKE2 
//              implementation at http://github.com/BLAKE2/BLAKE2.

#include "pch.h"
#include "config.h"
#include "cryptlib.h"
#include "blake2.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

// TODO
#undef CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
#undef CRYPTOPP_BOOL_SSE4_INTRINSICS_AVAILABLE

// C/C++ implementation
static inline void BLAKE2_CXX_Compress32(const byte* input, BLAKE2_State<word32, false>& state);
static inline void BLAKE2_CXX_Compress64(const byte* input, BLAKE2_State<word64, true>& state);

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
static inline void BLAKE2_SSE2_Compress32(const byte* input, BLAKE2_State<word32, false>& state);
static inline void BLAKE2_SSE2_Compress64(const byte* input, BLAKE2_State<word64, true>& state);
#endif

#if CRYPTOPP_BOOL_SSE4_INTRINSICS_AVAILABLE
static inline void BLAKE2_SSE4_Compress32(const byte* input, BLAKE2_State<word32, false>& state);
static inline void BLAKE2_SSE4_Compress64(const byte* input, BLAKE2_State<word64, true>& state);
#endif

#ifndef CRYPTOPP_DOXYGEN_PROCESSING

//! \class BLAKE2_IV
//! \brief BLAKE2 initialization vector
//! \tparam T_64bit flag indicating 64-bit
//! \details IV and Sigma are a better fit as part of BLAKE2_Base, but that
//!   places the constants out of reach for the SSE2 and SSE4 implementations.
template<bool T_64bit>
struct CRYPTOPP_NO_VTABLE BLAKE2_IV {};

//! \brief BLAKE2s initialization vector specialization
template<>
struct CRYPTOPP_NO_VTABLE BLAKE2_IV<false>
{
	CRYPTOPP_CONSTANT(IVSIZE = 8);
	static const word32 iv[8];
};

const word32 BLAKE2_IV<false>::iv[8] = {
	0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
	0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

//! \brief BLAKE2b initialization vector specialization
template<>
struct CRYPTOPP_NO_VTABLE BLAKE2_IV<true>
{
	CRYPTOPP_CONSTANT(IVSIZE = 8);
	static const word64 iv[8];
};

const word64 BLAKE2_IV<true>::iv[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

//! \class BLAKE2_Sigma
//! \brief BLAKE2 sigma table
//! \tparam T_64bit flag indicating 64-bit
//! \details IV and Sigma are a better fit as part of BLAKE2_Base, but that
//!   places the constants out of reach for the SSE2 and SSE4 implementations.
template<bool T_64bit>
struct CRYPTOPP_NO_VTABLE BLAKE2_Sigma {};

//! \brief BLAKE2s sigma table specialization
template<>
struct CRYPTOPP_NO_VTABLE BLAKE2_Sigma<false>
{
	CRYPTOPP_CONSTANT(ROW = 10);
	CRYPTOPP_CONSTANT(COL = 16);
	static const byte sigma[10][16];
};

const byte BLAKE2_Sigma<false>::sigma[10][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
};

//! \brief BLAKE2b sigma table specialization
template<>
struct CRYPTOPP_NO_VTABLE BLAKE2_Sigma<true>
{
	CRYPTOPP_CONSTANT(ROW = 12);
	CRYPTOPP_CONSTANT(COL = 16);
	static const byte sigma[12][16];
};

const byte BLAKE2_Sigma<true>::sigma[12][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

// i-th word, not byte
template<class W, bool T_64bit>
inline W ReadWord(const BLAKE2_ParameterBlock<T_64bit>& block, size_t i)
{
	assert(sizeof(block) > ((i+1)*sizeof(W)) - 1);
	const byte* p = reinterpret_cast<const byte*>(&block) + i*sizeof(W);
	return GetWord<W>(true, LITTLE_ENDIAN_ORDER, p);
}

// i-th word, not byte
template<class W, bool T_64bit>
inline W ReadWord(const byte* block, size_t i)
{
	const byte* p = block + i*sizeof(W);
	return GetWord<W>(true, LITTLE_ENDIAN_ORDER, p);
}

// i-th word, not byte
template<class W, bool T_64bit>
inline void WriteWord(W value, byte* block, size_t i)
{
	byte* p = block + i*sizeof(W);
	PutWord<W>(true, LITTLE_ENDIAN_ORDER, p, value, NULL);
}

template<bool T_64bit>
inline void ThrowIfInvalidSalt(size_t size)
{
	if (size > BLAKE2_Info<T_64bit>::SALTSIZE)
		throw InvalidSaltLength(T_64bit ? "Blake2b" : "Blake2s", size);
}

template<bool T_64bit>
inline void ThrowIfInvalidPersonalization(size_t size)
{
	if (size > BLAKE2_Info<T_64bit>::PERSONALIZATIONSIZE)
		throw InvalidPersonalizationLength(T_64bit ? "Blake2b" : "Blake2s", size);
}
#endif // CRYPTOPP_DOXYGEN_PROCESSING

BLAKE2_ParameterBlock<false>::BLAKE2_ParameterBlock(size_t digestLen, size_t keyLen,
		const byte* salt, size_t saltLen,
		const byte* personalization, size_t personalizationLen)
{
	ThrowIfInvalidSalt<false>(saltLen);
	ThrowIfInvalidPersonalization<false>(personalizationLen);

	memset(this, 0x00, sizeof(*this));
	this->digestLength = digestLen;
	this->keyLength = keyLen;
	fanout = depth = 1;

	if (salt && saltLen)
			memcpy_s(this->salt, sizeof(this->salt), salt, saltLen);

	if (personalization && personalizationLen)
			memcpy_s(this->personalization, sizeof(this->personalization), personalization, personalizationLen);
}

BLAKE2_ParameterBlock<true>::BLAKE2_ParameterBlock(size_t digestLen, size_t keyLen,
		const byte* salt, size_t saltLen,
		const byte* personalization, size_t personalizationLen)
{
	ThrowIfInvalidSalt<true>(saltLen);
	ThrowIfInvalidPersonalization<true>(personalizationLen);

	memset(this, 0x00, sizeof(*this));
	this->digestLength = (byte)digestLen;
	this->keyLength = (byte)keyLen;
	fanout = depth = 1;

	if (salt && saltLen)
			memcpy_s(this->salt, sizeof(this->salt), salt, saltLen);

	if (personalization && personalizationLen)
			memcpy_s(this->personalization, sizeof(this->personalization), personalization, personalizationLen);
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::UncheckedSetKey(const byte *key, unsigned int length, const CryptoPP::NameValuePairs&)
{
	CRYPTOPP_CONSTANT(KEYBLOCKSIZE = BLAKE2_Info<T_64bit>::BLOCKSIZE);
	if (key && length)
	{
		AlignedSecByteBlock k(KEYBLOCKSIZE);
		memcpy_s(k, KEYBLOCKSIZE, key, length);
		memset(k+length, 0x00, KEYBLOCKSIZE-length);
		m_key.swap(k);
	}
	else
	{
		m_key.resize(0);
	}
}

template <class W, bool T_64bit>
BLAKE2_Base<W, T_64bit>::BLAKE2_Base() : m_digestSize(DIGESTSIZE), m_treeMode(false)
{
	UncheckedSetKey(NULL, 0, g_nullNameValuePairs);
	Restart();
}

template <class W, bool T_64bit>
BLAKE2_Base<W, T_64bit>::BLAKE2_Base(bool treeMode, unsigned int digestSize) : m_digestSize(digestSize), m_treeMode(treeMode)
{
	this->ThrowIfInvalidTruncatedSize(digestSize);

	UncheckedSetKey(NULL, 0, g_nullNameValuePairs);
	Restart();
}

template <class W, bool T_64bit>
BLAKE2_Base<W, T_64bit>::BLAKE2_Base(const byte *key, size_t keyLength, const byte* salt, size_t saltLength,
	const byte* personalization, size_t personalizationLength, bool treeMode, unsigned int digestSize)
	: m_block(ParameterBlock(digestSize, keyLength, salt, saltLength,
	  personalization, personalizationLength)), m_digestSize(digestSize), m_treeMode(false)
{
	this->ThrowIfInvalidKeyLength(keyLength);
	this->ThrowIfInvalidTruncatedSize(digestSize);

	UncheckedSetKey(key, keyLength, g_nullNameValuePairs);
	Restart();
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::Restart()
{
	static const W zero[2] = {0,0};
	Restart(m_block, zero);
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::Restart(const BLAKE2_ParameterBlock<T_64bit>& block, const W counter[2])
{
	m_state.t[0] = m_state.t[1] = 0, m_state.f[0] = m_state.f[1] = 0, m_state.length = 0;
	for(unsigned int i = 0; i < BLAKE2_IV<T_64bit>::IVSIZE; ++i)
		m_state.h[i] = BLAKE2_IV<T_64bit>::iv[i];

	if (&block != &m_block)
	{
		m_block = block;
		m_block.digestLength = (byte)m_digestSize;
		m_block.keyLength = (byte)m_key.size();
	}

	if (counter != NULL)
	{
		m_state.t[0] = counter[0];
		m_state.t[1] = counter[1];
	}

	// When BLAKE2 is keyed, the input stream is simply {key||message}. Key it
	// during Restart to avoid FirstPut and friends. Key size == 0 means no key.
	if (m_key.size())
	{
		// Key is properly sized and padded
		Update(m_key, m_key.size());
	}

	for(unsigned int i = 0; i < BLAKE2_IV<T_64bit>::IVSIZE; ++i)
		m_state.h[i] ^= ReadWord<W, T_64bit>(m_block, i);
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::Update(const byte *input, size_t length)
{
	if (m_state.length + length > BLOCKSIZE)
	{
		/* Complete current block */
		size_t left = m_state.length;
		size_t fill = BLOCKSIZE - left;
		memcpy(&m_state.buffer[left], input, fill);

		IncrementCounter();
		Compress(m_state.buffer);

		m_state.length = 0;
		length -= fill;
		input += fill;

		/* Avoid buffer copies when possible */
		while (length > BLOCKSIZE) {
			IncrementCounter();
			Compress(input);
			length -= BLOCKSIZE;
			input += BLOCKSIZE;
		}
	}

	memcpy(&m_state.buffer[m_state.length], input, length);
	m_state.length += static_cast<unsigned int>(length);
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::TruncatedFinal(byte *hash, size_t size)
{
	// Set last block unconditionally
	m_state.f[0] = static_cast<W>(-1);

	// Set last node if tree mode
	if (m_treeMode)
		m_state.f[1] = static_cast<W>(-1);

	// Increment counter for tail bytes only
	IncrementCounter(m_state.length);

	memset(m_state.buffer + m_state.length, 0x00, BLOCKSIZE - m_state.length);
	Compress(m_state.buffer);

	if (size < DIGESTSIZE) 
	{
		SecByteBlock buffer(DIGESTSIZE);
		for(unsigned int i = 0; i < 8; ++i)
			WriteWord<W, T_64bit>(m_state.h[i], buffer, i);

		memcpy_s(hash, DIGESTSIZE, buffer, size);
	}
	else
	{
		// Write directly to the caller buffer
		for(unsigned int i = 0; i < 8; ++i)
			WriteWord<W, T_64bit>(m_state.h[i], hash, i);
	}

	Restart();
}

template <class W, bool T_64bit>
void BLAKE2_Base<W, T_64bit>::IncrementCounter(size_t count)
{
	m_state.t[0] += count;
	m_state.t[1] += !!(m_state.t[0] < count);
}

template <>
void BLAKE2_Base<word64, true>::Compress(const byte *input)
{
#if CRYPTOPP_BOOL_SSE4_INTRINSICS_AVAILABLE
	if (HasSSE4())
		BLAKE2_SSE4_Compress64(m_state);
	else
#endif
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
	if (HasSSE2())
		BLAKE2_SSE2_Compress64(input, m_state);
	else
#endif

	BLAKE2_CXX_Compress64(input, m_state);
}

template <>
void BLAKE2_Base<word32, false>::Compress(const byte *input)
{
#if CRYPTOPP_BOOL_SSE4_INTRINSICS_AVAILABLE
	if (HasSSE4())
		BLAKE2_SSE4_Compress32(input, m_state);
	else
#endif
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
	if (HasSSE2())
		BLAKE2_SSE2_Compress32(input, m_state);
	else
#endif

	BLAKE2_CXX_Compress32(input, m_state);
}

void BLAKE2_CXX_Compress64(const byte* input, BLAKE2_State<word64, true>& state)
{
	#undef BLAKE2_G
	#undef BLAKE2_ROUND

	#define BLAKE2_G(r,i,a,b,c,d) \
	  do { \
	    a = a + b + m[BLAKE2_Sigma<true>::sigma[r][2*i+0]]; \
	    d = rotrVariable<word64>(d ^ a, 32); \
	    c = c + d; \
	    b = rotrVariable<word64>(b ^ c, 24); \
	    a = a + b + m[BLAKE2_Sigma<true>::sigma[r][2*i+1]]; \
	    d = rotrVariable<word64>(d ^ a, 16); \
	    c = c + d; \
	    b = rotrVariable<word64>(b ^ c, 63); \
	  } while(0)

	#define BLAKE2_ROUND(r)  \
	  do { \
	    BLAKE2_G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
	    BLAKE2_G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
	    BLAKE2_G(r,2,v[ 2],v[ 6],v[10],v[14]); \
	    BLAKE2_G(r,3,v[ 3],v[ 7],v[11],v[15]); \
	    BLAKE2_G(r,4,v[ 0],v[ 5],v[10],v[15]); \
	    BLAKE2_G(r,5,v[ 1],v[ 6],v[11],v[12]); \
	    BLAKE2_G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
	    BLAKE2_G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
	  } while(0)

	word64 m[16], v[16];
	unsigned int i;

	for(i = 0; i < 16; ++i)
 		m[i] = ReadWord<word64, true>(input, i);

	for(i = 0; i < 8; ++i)
		v[i] = state.h[i];

	v[ 8] = BLAKE2_IV<true>::iv[0];
	v[ 9] = BLAKE2_IV<true>::iv[1];
	v[10] = BLAKE2_IV<true>::iv[2];
	v[11] = BLAKE2_IV<true>::iv[3];
	v[12] = state.t[0] ^ BLAKE2_IV<true>::iv[4];
	v[13] = state.t[1] ^ BLAKE2_IV<true>::iv[5];
	v[14] = state.f[0] ^ BLAKE2_IV<true>::iv[6];
	v[15] = state.f[1] ^ BLAKE2_IV<true>::iv[7];

	BLAKE2_ROUND( 0 );
	BLAKE2_ROUND( 1 );
	BLAKE2_ROUND( 2 );
	BLAKE2_ROUND( 3 );
	BLAKE2_ROUND( 4 );
	BLAKE2_ROUND( 5 );
	BLAKE2_ROUND( 6 );
	BLAKE2_ROUND( 7 );
	BLAKE2_ROUND( 8 );
	BLAKE2_ROUND( 9 );
	BLAKE2_ROUND( 10 );
	BLAKE2_ROUND( 11 );

	for(i = 0; i < 8; ++i)
		state.h[i] = state.h[i] ^ v[i] ^ v[i + 8];
}

void BLAKE2_CXX_Compress32(const byte* input, BLAKE2_State<word32, false>& state)
{
	#undef BLAKE2_G
	#undef BLAKE2_ROUND

	#define BLAKE2_G(r,i,a,b,c,d) \
	  do { \
	    a = a + b + m[BLAKE2_Sigma<false>::sigma[r][2*i+0]]; \
	    d = rotrVariable<word32>(d ^ a, 16); \
	    c = c + d; \
	    b = rotrVariable<word32>(b ^ c, 12); \
	    a = a + b + m[BLAKE2_Sigma<false>::sigma[r][2*i+1]]; \
	    d = rotrVariable<word32>(d ^ a, 8); \
	    c = c + d; \
	    b = rotrVariable<word32>(b ^ c, 7); \
	  } while(0)

	#define BLAKE2_ROUND(r)  \
	  do { \
	    BLAKE2_G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
	    BLAKE2_G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
	    BLAKE2_G(r,2,v[ 2],v[ 6],v[10],v[14]); \
	    BLAKE2_G(r,3,v[ 3],v[ 7],v[11],v[15]); \
	    BLAKE2_G(r,4,v[ 0],v[ 5],v[10],v[15]); \
	    BLAKE2_G(r,5,v[ 1],v[ 6],v[11],v[12]); \
	    BLAKE2_G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
	    BLAKE2_G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
	  } while(0)

	word32 m[16], v[16];
	unsigned int i;

	for(i = 0; i < 16; ++i)
		m[i] = ReadWord<word32, false>(input, i);

	for(i = 0; i < 8; ++i)
		v[i] = state.h[i];

	v[ 8] = BLAKE2_IV<false>::iv[0];
	v[ 9] = BLAKE2_IV<false>::iv[1];
	v[10] = BLAKE2_IV<false>::iv[2];
	v[11] = BLAKE2_IV<false>::iv[3];
	v[12] = state.t[0] ^ BLAKE2_IV<false>::iv[4];
	v[13] = state.t[1] ^ BLAKE2_IV<false>::iv[5];
	v[14] = state.f[0] ^ BLAKE2_IV<false>::iv[6];
	v[15] = state.f[1] ^ BLAKE2_IV<false>::iv[7];

	BLAKE2_ROUND( 0 );
	BLAKE2_ROUND( 1 );
	BLAKE2_ROUND( 2 );
	BLAKE2_ROUND( 3 );
	BLAKE2_ROUND( 4 );
	BLAKE2_ROUND( 5 );
	BLAKE2_ROUND( 6 );
	BLAKE2_ROUND( 7 );
	BLAKE2_ROUND( 8 );
	BLAKE2_ROUND( 9 );

	for(i = 0; i < 8; ++i)
		state.h[i] = state.h[i] ^ v[i] ^ v[i + 8];
}

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
static inline void BLAKE2_SSE2_Compress32(const byte* input, BLAKE2_State<word32, false>& state)
{
	// TODO... fall back to C++
	BLAKE2_CXX_Compress32(input, state);
}

static inline void BLAKE2_SSE2_Compress64(const byte* input, BLAKE2_State<word64, true>& state)
{
	// TODO... fall back to C++
	BLAKE2_CXX_Compress64(input, state);
}
#endif  // CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE

#if CRYPTOPP_BOOL_SSE4_INTRINSICS_AVAILABLE
static inline void BLAKE2_SSE4_Compress32(const byte* input, BLAKE2_State<word32, false>& state)
{
	// TODO... fall back to C++
	BLAKE2_CXX_Compress32(input, state);
}

static inline void BLAKE2_SSE4_Compress64(const byte* input, BLAKE2_State<word64, true>& state)
{
	// TODO... fall back to C++
	BLAKE2_CXX_Compress64(input, state);
}
#endif  // CRYPTOPP_BOOL_SSE4_INTRINSICS_AVAILABLE

template class BLAKE2_Base<word32, false>;
template class BLAKE2_Base<word64, true>;

NAMESPACE_END

