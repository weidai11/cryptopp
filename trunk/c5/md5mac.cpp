// md5mac.cpp - modified by Wei Dai from Colin Plumb's public domain md5.c
// any modifications are placed in the public domain

#include "pch.h"
#include "md5mac.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

const word32 MD5MAC_Base::T[12] =
	{ 0xac45ef97,0xcd430f29,0x551b7e45,0x3411801c,
	  0x96ce77b1,0x7c8e722e,0x0aab5a5f,0x18be4336,
	  0x21b4219d,0x4db987bc,0xbd279da2,0xc3d75bc7 };

void MD5MAC_Base::UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &)
{
	const word32 zeros[4] = {0,0,0,0};

	for (unsigned i=0, j; i<3; i++)
	{
		m_key[4*i+0] = 0x67452301L;
		m_key[4*i+1] = 0xefcdab89L;
		m_key[4*i+2] = 0x98badcfeL;
		m_key[4*i+3] = 0x10325476L;

		memcpy(m_data, userKey, KEYLENGTH);
		CorrectEndianess(m_data, m_data, KEYLENGTH);
		for (j=0; j<3; j++)
			memcpy(m_data+4+4*j, T+((i+j)%3)*4, 16);
		Transform(m_key+4*i, m_data, zeros);

		for (j=0; j<3; j++)
			memcpy(m_data+4*j, T+((i+j)%3)*4, 16);
		memcpy(m_data+12, userKey, KEYLENGTH);
		CorrectEndianess(m_data+12, m_data+12, KEYLENGTH);
		Transform(m_key+4*i, m_data, zeros);
	}

	Init();
}

void MD5MAC_Base::Init()
{
	m_digest[0] = m_key[0];
	m_digest[1] = m_key[1];
	m_digest[2] = m_key[2];
	m_digest[3] = m_key[3];
}

void MD5MAC_Base::TruncatedFinal(byte *hash, size_t size)
{
	ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(56);
	CorrectEndianess(m_data, m_data, 56);

	m_data[14] = GetBitCountLo();
	m_data[15] = GetBitCountHi();

	Transform(m_digest, m_data, m_key+4);

	unsigned i;
	for (i=0; i<4; i++)
		m_data[i] = m_key[8+i];
	for (i=0; i<12; i++)
		m_data[i+4] = T[i] ^ m_key[8+i%4];
	Transform(m_digest, m_data, m_key+4);

	CorrectEndianess(m_digest, m_digest, DIGESTSIZE);
	memcpy(hash, m_digest, size);

	Restart();		// reinit for next use
}

void MD5MAC_Base::Transform(word32 *digest, const word32 *in, const word32 *key)
{
#define F1(x, y, z) ((z ^ (x & (y ^ z))) + key[0])
#define F2(x, y, z) ((y ^ (z & (x ^ y))) + key[1])
#define F3(x, y, z) ((x ^ y ^ z) + key[2])
#define F4(x, y, z) ((y ^ (x | ~z)) + key[3])

#define MD5STEP(f, w, x, y, z, data, s) \
	w = rotlFixed(w + f(x, y, z) + data, s) + x

    word32 a, b, c, d;

	a=digest[0];
	b=digest[1];
	c=digest[2];
	d=digest[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	digest[0]+=a;
	digest[1]+=b;
	digest[2]+=c;
	digest[3]+=d;
}

NAMESPACE_END
