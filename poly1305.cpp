// poly1305.cpp - written and placed in the public domain by Jeffrey Walton and Jean-Pierre Munch
//                Based on Andy Polyakov's Base-2^26 scalar multiplication implementation for OpenSSL.
//                Copyright assigned to the Crypto++ project

#include "pch.h"
#include "cryptlib.h"
#include "aes.h"
#include "cpu.h"
#include "poly1305.h"

NAMESPACE_BEGIN(CryptoPP)

#define CONSTANT_TIME_CARRY(a,b) ((a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1))

template <class T>
void Poly1305_Base<T>::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	if (key && length)
	{
		// key is {k,r} pair, r is 16 bytes
		length = SaturatingSubtract(length, (unsigned)BLOCKSIZE);
		m_cipher.SetKey(key, length);
		key += length;

		// Rbar is clamped and little endian
		m_r[0] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  0) & 0x0fffffff;
		m_r[1] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  4) & 0x0ffffffc;
		m_r[2] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  8) & 0x0ffffffc;
		m_r[3] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key + 12) & 0x0ffffffc;

		m_used = false;
	}

	ConstByteArrayParameter t;
	if (params.GetValue(Name::IV(), t) && t.begin() && t.size())
	{
		SecByteBlock nk(16);
		m_cipher.ProcessBlock(t.begin(), nk);

		m_n[0] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, nk +  0);
		m_n[1] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, nk +  4);
		m_n[2] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, nk +  8);
		m_n[3] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, nk + 12);

		m_used = false;
	}

	Restart();
}

template <class T>
void Poly1305_Base<T>::Update(const byte *input, size_t length)
{
	CRYPTOPP_ASSERT((input && length) || !length);
	if (!length) return;

	size_t rem, num = m_idx;
	if (num)
	{
		rem = BLOCKSIZE - num;
		if (length >= rem)
		{
			// Process
			memcpy_s(m_acc + num, BLOCKSIZE - num, input, rem);
			HashBlocks(m_acc, BLOCKSIZE, 1);
			input += rem;
			length -= rem;
		}
		else
		{
			// Accumulate
			memcpy_s(m_acc + num, BLOCKSIZE - num, input, length);
			m_idx = num + length;
			return;
		}
	}

	rem = length % BLOCKSIZE;
	length -= rem;

	if (length >= BLOCKSIZE) {
		HashBlocks(input, length, 1);
		input += length;
	}

	if (rem)
		memcpy(m_acc, input, rem);

	m_idx = rem;
}

template <class T>
void Poly1305_Base<T>::HashBlocks(const byte *input, size_t length, word32 padbit)
{
	word32 r0, r1, r2, r3;
	word32 s1, s2, s3;
	word32 h0, h1, h2, h3, h4, c;
	word64 d0, d1, d2, d3;

	r0 = m_r[0]; r1 = m_r[1];
	r2 = m_r[2]; r3 = m_r[3];

	s1 = r1 + (r1 >> 2);
	s2 = r2 + (r2 >> 2);
	s3 = r3 + (r3 >> 2);

	h0 = m_h[0]; h1 = m_h[1]; h2 = m_h[2];
	h3 = m_h[3]; h4 = m_h[4];

	while (length >= BLOCKSIZE)
	{
		// h += m[i]
		h0 = (word32)(d0 = (word64)h0 +	             GetWord<word32>(false, LITTLE_ENDIAN_ORDER, input +  0));
		h1 = (word32)(d1 = (word64)h1 + (d0 >> 32) + GetWord<word32>(false, LITTLE_ENDIAN_ORDER, input +  4));
		h2 = (word32)(d2 = (word64)h2 + (d1 >> 32) + GetWord<word32>(false, LITTLE_ENDIAN_ORDER, input +  8));
		h3 = (word32)(d3 = (word64)h3 + (d2 >> 32) + GetWord<word32>(false, LITTLE_ENDIAN_ORDER, input + 12));
		h4 += (word32)(d3 >> 32) + padbit;

		// h *= r "%" p
		d0 = ((word64)h0 * r0) +
			 ((word64)h1 * s3) +
			 ((word64)h2 * s2) +
			 ((word64)h3 * s1);
		d1 = ((word64)h0 * r1) +
			 ((word64)h1 * r0) +
			 ((word64)h2 * s3) +
			 ((word64)h3 * s2) +
			 (h4 * s1);
		d2 = ((word64)h0 * r2) +
			 ((word64)h1 * r1) +
			 ((word64)h2 * r0) +
			 ((word64)h3 * s3) +
			 (h4 * s2);
		d3 = ((word64)h0 * r3) +
			 ((word64)h1 * r2) +
			 ((word64)h2 * r1) +
			 ((word64)h3 * r0) +
			 (h4 * s3);
		h4 = (h4 * r0);

		// a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0
		h0 = (word32)d0;
		h1 = (word32)(d1 += d0 >> 32);
		h2 = (word32)(d2 += d1 >> 32);
		h3 = (word32)(d3 += d2 >> 32);
		h4 += (word32)(d3 >> 32);

		// b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130
		c = (h4 >> 2) + (h4 & ~3U);
		h4 &= 3;
		h0 += c;
		h1 += (c = CONSTANT_TIME_CARRY(h0,c));
		h2 += (c = CONSTANT_TIME_CARRY(h1,c));
		h3 += (c = CONSTANT_TIME_CARRY(h2,c));
		h4 +=      CONSTANT_TIME_CARRY(h3,c);

		input += BLOCKSIZE;
		length -= BLOCKSIZE;
	}

	m_h[0] = h0; m_h[1] = h1; m_h[2] = h2;
	m_h[3] = h3; m_h[4] = h4;
}

template <class T>
void Poly1305_Base<T>::TruncatedFinal(byte *mac, size_t size)
{
	CRYPTOPP_ASSERT(mac);      // Pointer is valid
	CRYPTOPP_ASSERT(!m_used);  // Nonce is fresh

	ThrowIfInvalidTruncatedSize(size);

	size_t num = m_idx;
	if (num)
	{
		m_acc[num++] = 1;   /* pad bit */
		while (num < BLOCKSIZE)
			m_acc[num++] = 0;
		HashBlocks(m_acc, BLOCKSIZE, 0);
	}

	HashFinal(mac, size);

	// Restart
	m_used = true;
	Restart();
}

template <class T>
void Poly1305_Base<T>::HashFinal(byte *mac, size_t size)
{
	word32 h0, h1, h2, h3, h4;
	word32 g0, g1, g2, g3, g4;
	word32 mask;
	word64 t;

	h0 = m_h[0];
	h1 = m_h[1];
	h2 = m_h[2];
	h3 = m_h[3];
	h4 = m_h[4];

	// compare to modulus by computing h + -p
	g0 = (word32)(t = (word64)h0 + 5);
	g1 = (word32)(t = (word64)h1 + (t >> 32));
	g2 = (word32)(t = (word64)h2 + (t >> 32));
	g3 = (word32)(t = (word64)h3 + (t >> 32));
	g4 = h4 + (word32)(t >> 32);

	// if there was carry into 131st bit, h3:h0 = g3:g0
	mask = 0 - (g4 >> 2);
	g0 &= mask; g1 &= mask;
	g2 &= mask; g3 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3;

	// mac = (h + nonce) % (2^128)
	h0 = (word32)(t = (word64)h0 + m_n[0]);
	h1 = (word32)(t = (word64)h1 + (t >> 32) + m_n[1]);
	h2 = (word32)(t = (word64)h2 + (t >> 32) + m_n[2]);
	h3 = (word32)(t = (word64)h3 + (t >> 32) + m_n[3]);

	if (size >= BLOCKSIZE)
	{
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, mac +  0, h0);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, mac +  4, h1);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, mac +  8, h2);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, mac + 12, h3);
	}
	else
	{
		FixedSizeAlignedSecBlock<byte, BLOCKSIZE> m;
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, m +  0, h0);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, m +  4, h1);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, m +  8, h2);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, m + 12, h3);
		memcpy(mac, m, size);
	}
}

template <class T>
void Poly1305_Base<T>::Resynchronize(const byte *nonce, int nonceLength)
{
	CRYPTOPP_ASSERT(nonceLength == -1 || nonceLength == (int)BLOCKSIZE);
	nonceLength == -1 ? nonceLength = BLOCKSIZE : nonceLength;
	this->UncheckedSetKey(NULL, 0, MakeParameters(Name::IV(), ConstByteArrayParameter(nonce, nonceLength)));
}

template <class T>
void Poly1305_Base<T>::GetNextIV(RandomNumberGenerator &rng, byte *iv)
{
	rng.GenerateBlock(iv, BLOCKSIZE);
}

template <class T>
void Poly1305_Base<T>::Restart()
{
	m_h[0] = m_h[1] = m_h[2] = m_h[3] = m_h[4] = 0;
	// m_r[0] = m_r[1] = m_r[2] = m_r[3] = 0;
	m_idx = 0;
}

template class Poly1305<AES>;

NAMESPACE_END
