// poly1305.cpp - written and placed in the public domain by Jeffrey Walton and Jean-Pierre Munch
//                Based on Andy Polyakov's Base-2^26 scalar multiplication implementation.
//                For more information, see https://www.openssl.org/~appro/cryptogams/.

// Copyright (c) 2006-2017, CRYPTOGAMS by <appro@openssl.org>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// * Redistributions of source code must retain copyright notices,
//   this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following
//   disclaimer in the documentation and/or other materials
//   provided with the distribution.
// * Neither the name of the CRYPTOGAMS nor the names of its copyright
//   holder and contributors may be used to endorse or promote products
//   derived from this software without specific prior written permission.

#include "pch.h"
#include "cryptlib.h"
#include "poly1305.h"
#include "aes.h"
#include "cpu.h"

////////////////////////////// Common Poly1305 //////////////////////////////

ANONYMOUS_NAMESPACE_BEGIN

using namespace CryptoPP;

inline word32 CONSTANT_TIME_CARRY(word32 a, word32 b)
{
	return ((a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1));
}

void Poly1305_HashBlocks(word32 h[5], word32 r[4], const byte *input, size_t length, word32 padbit)
{
	word32 r0, r1, r2, r3;
	word32 s1, s2, s3;
	word32 h0, h1, h2, h3, h4, c;
	word64 d0, d1, d2, d3;

	r0 = r[0]; r1 = r[1];
	r2 = r[2]; r3 = r[3];

	s1 = r1 + (r1 >> 2);
	s2 = r2 + (r2 >> 2);
	s3 = r3 + (r3 >> 2);

	h0 = h[0]; h1 = h[1]; h2 = h[2];
	h3 = h[3]; h4 = h[4];

	while (length >= 16)
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

		input += 16;
		length -= 16;
	}

	h[0] = h0; h[1] = h1; h[2] = h2;
	h[3] = h3; h[4] = h4;
}

void Poly1305_HashFinal(word32 h[5], word32 n[4], byte *mac, size_t size)
{
	word32 h0, h1, h2, h3, h4;
	word32 g0, g1, g2, g3, g4;
	word32 mask;
	word64 t;

	h0 = h[0];
	h1 = h[1];
	h2 = h[2];
	h3 = h[3];
	h4 = h[4];

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
	h0 = (word32)(t = (word64)h0 + n[0]);
	h1 = (word32)(t = (word64)h1 + (t >> 32) + n[1]);
	h2 = (word32)(t = (word64)h2 + (t >> 32) + n[2]);
	h3 = (word32)(t = (word64)h3 + (t >> 32) + n[3]);

	if (size >= 16)
	{
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, mac +  0, h0);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, mac +  4, h1);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, mac +  8, h2);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, mac + 12, h3);
	}
	else
	{
		FixedSizeAlignedSecBlock<byte, 16> m;
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, m +  0, h0);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, m +  4, h1);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, m +  8, h2);
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, m + 12, h3);
		std::memcpy(mac, m, size);
	}
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

////////////////////////////// Bernstein Poly1305 //////////////////////////////

// TODO: No longer needed. Remove at next major version bump
template <class T>
void Poly1305_Base<T>::HashBlocks(const byte *input, size_t length, word32 padbit) {
	CRYPTOPP_UNUSED(input); CRYPTOPP_UNUSED(length); CRYPTOPP_UNUSED(padbit);
	CRYPTOPP_ASSERT(0);
}

// TODO: No longer needed. Remove at next major version bump
template <class T>
void Poly1305_Base<T>::HashFinal(byte *mac, size_t length) {
	CRYPTOPP_UNUSED(mac); CRYPTOPP_UNUSED(length);
	CRYPTOPP_ASSERT(0);
}

template <class T>
std::string Poly1305_Base<T>::AlgorithmProvider() const
{
	return m_cipher.AlgorithmProvider();
}

template <class T>
void Poly1305_Base<T>::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	CRYPTOPP_ASSERT(key && length >= 32);

	// key is {k,r} pair. k is AES key, r is the additional key that gets clamped
	length = SaturatingSubtract(length, (unsigned)BLOCKSIZE);
	m_cipher.SetKey(key, length);
	key += length;

	// Rbar is clamped and little endian
	m_r[0] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  0) & 0x0fffffff;
	m_r[1] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  4) & 0x0ffffffc;
	m_r[2] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  8) & 0x0ffffffc;
	m_r[3] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key + 12) & 0x0ffffffc;

	// Mark the nonce as dirty, meaning we need a new one
	m_used = true;

	ConstByteArrayParameter t;
	if (params.GetValue(Name::IV(), t) && t.begin() && t.size())
	{
		CRYPTOPP_ASSERT(t.size() == m_nk.size());
		Resynchronize(t.begin(), (int)t.size());
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
			Poly1305_HashBlocks(m_h, m_r, m_acc, BLOCKSIZE, 1);
			input += rem; length -= rem;
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
		Poly1305_HashBlocks(m_h, m_r, input, length, 1);
		input += length;
	}

	if (rem)
		memcpy(m_acc, input, rem);

	m_idx = rem;
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
		Poly1305_HashBlocks(m_h, m_r, m_acc, BLOCKSIZE, 0);
	}

	Poly1305_HashFinal(m_h, m_n, mac, size);

	// Restart
	m_used = true;
	Restart();
}

template <class T>
void Poly1305_Base<T>::Resynchronize(const byte *nonce, int nonceLength)
{
	CRYPTOPP_ASSERT(nonceLength == -1 || nonceLength == (int)BLOCKSIZE);
	nonceLength == -1 ? nonceLength = BLOCKSIZE : nonceLength;

	// Encrypt the nonce, stash in m_nk
	m_cipher.ProcessBlock(nonce, m_nk.begin());

	m_n[0] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, m_nk +  0);
	m_n[1] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, m_nk +  4);
	m_n[2] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, m_nk +  8);
	m_n[3] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, m_nk + 12);

	// Mark nonce as unused, meaning it is fresh
	m_used = false;
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
	m_idx = 0;
}

////////////////////////////// IETF Poly1305 //////////////////////////////

void Poly1305TLS_Base::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	CRYPTOPP_UNUSED(params); CRYPTOPP_UNUSED(length);
	CRYPTOPP_ASSERT(key && length >= 32);

	// key is {r,s} pair. r is the additional key that gets clamped, s is the nonce.
	m_r[0] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  0) & 0x0fffffff;
	m_r[1] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  4) & 0x0ffffffc;
	m_r[2] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  8) & 0x0ffffffc;
	m_r[3] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key + 12) & 0x0ffffffc;

	key += 16;
	m_n[0] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  0);
	m_n[1] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  4);
	m_n[2] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key +  8);
	m_n[3] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key + 12);

	Restart();
}

void Poly1305TLS_Base::Update(const byte *input, size_t length)
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
			Poly1305_HashBlocks(m_h, m_r, m_acc, BLOCKSIZE, 1);
			input += rem; length -= rem;
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
		Poly1305_HashBlocks(m_h, m_r, input, length, 1);
		input += length;
	}

	if (rem)
		memcpy(m_acc, input, rem);

	m_idx = rem;
}

void Poly1305TLS_Base::TruncatedFinal(byte *mac, size_t size)
{
	CRYPTOPP_ASSERT(mac);      // Pointer is valid

	ThrowIfInvalidTruncatedSize(size);

	size_t num = m_idx;
	if (num)
	{
		m_acc[num++] = 1;   /* pad bit */
		while (num < BLOCKSIZE)
			m_acc[num++] = 0;
		Poly1305_HashBlocks(m_h, m_r, m_acc, BLOCKSIZE, 0);
	}

	Poly1305_HashFinal(m_h, m_n, mac, size);

	Restart();
}

void Poly1305TLS_Base::Restart()
{
	m_h[0] = m_h[1] = m_h[2] = m_h[3] = m_h[4] = 0;
	m_idx = 0;
}

template class Poly1305_Base<AES>;
template class Poly1305<AES>;

NAMESPACE_END
