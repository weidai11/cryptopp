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
				Td0[Se[GETBYTE(rk[0], 3)]] ^
				Td1[Se[GETBYTE(rk[0], 2)]] ^
				Td2[Se[GETBYTE(rk[0], 1)]] ^
				Td3[Se[GETBYTE(rk[0], 0)]];
			rk[1] =
				Td0[Se[GETBYTE(rk[1], 3)]] ^
				Td1[Se[GETBYTE(rk[1], 2)]] ^
				Td2[Se[GETBYTE(rk[1], 1)]] ^
				Td3[Se[GETBYTE(rk[1], 0)]];
			rk[2] =
				Td0[Se[GETBYTE(rk[2], 3)]] ^
				Td1[Se[GETBYTE(rk[2], 2)]] ^
				Td2[Se[GETBYTE(rk[2], 1)]] ^
				Td3[Se[GETBYTE(rk[2], 0)]];
			rk[3] =
				Td0[Se[GETBYTE(rk[3], 3)]] ^
				Td1[Se[GETBYTE(rk[3], 2)]] ^
				Td2[Se[GETBYTE(rk[3], 1)]] ^
				Td3[Se[GETBYTE(rk[3], 0)]];
		}
	}

	ConditionalByteReverse(BIG_ENDIAN_ORDER, m_key.begin(), m_key.begin(), 16);
	ConditionalByteReverse(BIG_ENDIAN_ORDER, m_key + m_rounds*4, m_key + m_rounds*4, 16);
}

const static unsigned int s_lineSizeDiv4 = CRYPTOPP_L1_CACHE_LINE_SIZE/4;
#ifdef IS_BIG_ENDIAN
const static unsigned int s_i3=3, s_i2=2, s_i1=1, s_i0=0;
#else
const static unsigned int s_i3=0, s_i2=1, s_i1=2, s_i0=3;
#endif

void Rijndael::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
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
	unsigned int i;
	word32 u = 0;
	for (i=0; i<sizeof(Te0)/4; i+=CRYPTOPP_L1_CACHE_LINE_SIZE)
		u &= (Te0[i+0*s_lineSizeDiv4] & Te0[i+2*s_lineSizeDiv4]) & (Te0[i+1*s_lineSizeDiv4] & Te0[i+3*s_lineSizeDiv4]);
	s0 |= u; s1 |= u; s2 |= u; s3 |= u;

	// first round
    t0 ^=
        Te0[GETBYTE(s0, s_i3)] ^
        rotrFixed(Te0[GETBYTE(s1, s_i2)], 8) ^
        rotrFixed(Te0[GETBYTE(s2, s_i1)], 16) ^
        rotrFixed(Te0[GETBYTE(s3, s_i0)], 24);
    t1 ^=
        Te0[GETBYTE(s1, s_i3)] ^
        rotrFixed(Te0[GETBYTE(s2, s_i2)], 8) ^
        rotrFixed(Te0[GETBYTE(s3, s_i1)], 16) ^
        rotrFixed(Te0[GETBYTE(s0, s_i0)], 24);
    t2 ^=
        Te0[GETBYTE(s2, s_i3)] ^
        rotrFixed(Te0[GETBYTE(s3, s_i2)], 8) ^
        rotrFixed(Te0[GETBYTE(s0, s_i1)], 16) ^
        rotrFixed(Te0[GETBYTE(s1, s_i0)], 24);
    t3 ^=
        Te0[GETBYTE(s3, s_i3)] ^
        rotrFixed(Te0[GETBYTE(s0, s_i2)], 8) ^
        rotrFixed(Te0[GETBYTE(s1, s_i1)], 16) ^
        rotrFixed(Te0[GETBYTE(s2, s_i0)], 24);

	// Nr - 2 full rounds:
    unsigned int r = m_rounds/2 - 1;
    do
	{
        s0 =
            Te0[GETBYTE(t0, 3)] ^
            Te1[GETBYTE(t1, 2)] ^
            Te2[GETBYTE(t2, 1)] ^
            Te3[GETBYTE(t3, 0)] ^
            rk[0];
        s1 =
            Te0[GETBYTE(t1, 3)] ^
            Te1[GETBYTE(t2, 2)] ^
            Te2[GETBYTE(t3, 1)] ^
            Te3[GETBYTE(t0, 0)] ^
            rk[1];
        s2 =
            Te0[GETBYTE(t2, 3)] ^
            Te1[GETBYTE(t3, 2)] ^
            Te2[GETBYTE(t0, 1)] ^
            Te3[GETBYTE(t1, 0)] ^
            rk[2];
        s3 =
            Te0[GETBYTE(t3, 3)] ^
            Te1[GETBYTE(t0, 2)] ^
            Te2[GETBYTE(t1, 1)] ^
            Te3[GETBYTE(t2, 0)] ^
            rk[3];

        t0 =
            Te0[GETBYTE(s0, 3)] ^
            Te1[GETBYTE(s1, 2)] ^
            Te2[GETBYTE(s2, 1)] ^
            Te3[GETBYTE(s3, 0)] ^
            rk[4];
        t1 =
            Te0[GETBYTE(s1, 3)] ^
            Te1[GETBYTE(s2, 2)] ^
            Te2[GETBYTE(s3, 1)] ^
            Te3[GETBYTE(s0, 0)] ^
            rk[5];
        t2 =
            Te0[GETBYTE(s2, 3)] ^
            Te1[GETBYTE(s3, 2)] ^
            Te2[GETBYTE(s0, 1)] ^
            Te3[GETBYTE(s1, 0)] ^
            rk[6];
        t3 =
            Te0[GETBYTE(s3, 3)] ^
            Te1[GETBYTE(s0, 2)] ^
            Te2[GETBYTE(s1, 1)] ^
            Te3[GETBYTE(s2, 0)] ^
            rk[7];

        rk += 8;
    } while (--r);

	// timing attack countermeasure. see comments at top for more details
	u = 0;
	for (i=0; i<sizeof(Se)/4; i+=CRYPTOPP_L1_CACHE_LINE_SIZE)
		u &= (((word32*)Se)[i+0*s_lineSizeDiv4] & ((word32*)Se)[i+2*s_lineSizeDiv4]) & (((word32*)Se)[i+1*s_lineSizeDiv4] & ((word32*)Se)[i+3*s_lineSizeDiv4]);
	t0 |= u; t1 |= u; t2 |= u; t3 |= u;

	word32 tbw[4];
	byte *const tempBlock = (byte *)tbw;
	word32 *const obw = (word32 *)outBlock;
	const word32 *const xbw = (const word32 *)xorBlock;

	// last round
	tempBlock[0] = Se[GETBYTE(t0, 3)];
	tempBlock[1] = Se[GETBYTE(t1, 2)];
	tempBlock[2] = Se[GETBYTE(t2, 1)];
	tempBlock[3] = Se[GETBYTE(t3, 0)];
	tempBlock[4] = Se[GETBYTE(t1, 3)];
	tempBlock[5] = Se[GETBYTE(t2, 2)];
	tempBlock[6] = Se[GETBYTE(t3, 1)];
	tempBlock[7] = Se[GETBYTE(t0, 0)];
	tempBlock[8] = Se[GETBYTE(t2, 3)];
	tempBlock[9] = Se[GETBYTE(t3, 2)];
	tempBlock[10] = Se[GETBYTE(t0, 1)];
	tempBlock[11] = Se[GETBYTE(t1, 0)];
	tempBlock[12] = Se[GETBYTE(t3, 3)];
	tempBlock[13] = Se[GETBYTE(t0, 2)];
	tempBlock[14] = Se[GETBYTE(t1, 1)];
	tempBlock[15] = Se[GETBYTE(t2, 0)];

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
	unsigned int i;
	word32 u = 0;
	for (i=0; i<sizeof(Td0)/4; i+=CRYPTOPP_L1_CACHE_LINE_SIZE)
		u &= (Td0[i+0*s_lineSizeDiv4] & Td0[i+2*s_lineSizeDiv4]) & (Td0[i+1*s_lineSizeDiv4] & Td0[i+3*s_lineSizeDiv4]);
	s0 |= u; s1 |= u; s2 |= u; s3 |= u;

	// first round
    t0 ^=
        Td0[GETBYTE(s0, s_i3)] ^
        rotrFixed(Td0[GETBYTE(s3, s_i2)], 8) ^
        rotrFixed(Td0[GETBYTE(s2, s_i1)], 16) ^
        rotrFixed(Td0[GETBYTE(s1, s_i0)], 24);
    t1 ^=
        Td0[GETBYTE(s1, s_i3)] ^
        rotrFixed(Td0[GETBYTE(s0, s_i2)], 8) ^
        rotrFixed(Td0[GETBYTE(s3, s_i1)], 16) ^
        rotrFixed(Td0[GETBYTE(s2, s_i0)], 24);
    t2 ^=
        Td0[GETBYTE(s2, s_i3)] ^
        rotrFixed(Td0[GETBYTE(s1, s_i2)], 8) ^
        rotrFixed(Td0[GETBYTE(s0, s_i1)], 16) ^
        rotrFixed(Td0[GETBYTE(s3, s_i0)], 24);
    t3 ^=
        Td0[GETBYTE(s3, s_i3)] ^
        rotrFixed(Td0[GETBYTE(s2, s_i2)], 8) ^
        rotrFixed(Td0[GETBYTE(s1, s_i1)], 16) ^
        rotrFixed(Td0[GETBYTE(s0, s_i0)], 24);

	// Nr - 2 full rounds:
    unsigned int r = m_rounds/2 - 1;
    do
	{
        s0 =
            Td0[GETBYTE(t0, 3)] ^
            Td1[GETBYTE(t3, 2)] ^
            Td2[GETBYTE(t2, 1)] ^
            Td3[GETBYTE(t1, 0)] ^
            rk[0];
        s1 =
            Td0[GETBYTE(t1, 3)] ^
            Td1[GETBYTE(t0, 2)] ^
            Td2[GETBYTE(t3, 1)] ^
            Td3[GETBYTE(t2, 0)] ^
            rk[1];
        s2 =
            Td0[GETBYTE(t2, 3)] ^
            Td1[GETBYTE(t1, 2)] ^
            Td2[GETBYTE(t0, 1)] ^
            Td3[GETBYTE(t3, 0)] ^
            rk[2];
        s3 =
            Td0[GETBYTE(t3, 3)] ^
            Td1[GETBYTE(t2, 2)] ^
            Td2[GETBYTE(t1, 1)] ^
            Td3[GETBYTE(t0, 0)] ^
            rk[3];

        t0 =
            Td0[GETBYTE(s0, 3)] ^
            Td1[GETBYTE(s3, 2)] ^
            Td2[GETBYTE(s2, 1)] ^
            Td3[GETBYTE(s1, 0)] ^
            rk[4];
        t1 =
            Td0[GETBYTE(s1, 3)] ^
            Td1[GETBYTE(s0, 2)] ^
            Td2[GETBYTE(s3, 1)] ^
            Td3[GETBYTE(s2, 0)] ^
            rk[5];
        t2 =
            Td0[GETBYTE(s2, 3)] ^
            Td1[GETBYTE(s1, 2)] ^
            Td2[GETBYTE(s0, 1)] ^
            Td3[GETBYTE(s3, 0)] ^
            rk[6];
        t3 =
            Td0[GETBYTE(s3, 3)] ^
            Td1[GETBYTE(s2, 2)] ^
            Td2[GETBYTE(s1, 1)] ^
            Td3[GETBYTE(s0, 0)] ^
            rk[7];

        rk += 8;
    } while (--r);

	// timing attack countermeasure. see comments at top for more details
	u = 0;
	for (i=0; i<sizeof(Sd)/4; i+=CRYPTOPP_L1_CACHE_LINE_SIZE)
		u &= (((word32*)Sd)[i+0*s_lineSizeDiv4] & ((word32*)Sd)[i+2*s_lineSizeDiv4]) & (((word32*)Sd)[i+1*s_lineSizeDiv4] & ((word32*)Sd)[i+3*s_lineSizeDiv4]);
	t0 |= u; t1 |= u; t2 |= u; t3 |= u;

	word32 tbw[4];
	byte *const tempBlock = (byte *)tbw;
	word32 *const obw = (word32 *)outBlock;
	const word32 *const xbw = (const word32 *)xorBlock;

	// last round
	tempBlock[0] = Sd[GETBYTE(t0, 3)];
	tempBlock[1] = Sd[GETBYTE(t3, 2)];
	tempBlock[2] = Sd[GETBYTE(t2, 1)];
	tempBlock[3] = Sd[GETBYTE(t1, 0)];
	tempBlock[4] = Sd[GETBYTE(t1, 3)];
	tempBlock[5] = Sd[GETBYTE(t0, 2)];
	tempBlock[6] = Sd[GETBYTE(t3, 1)];
	tempBlock[7] = Sd[GETBYTE(t2, 0)];
	tempBlock[8] = Sd[GETBYTE(t2, 3)];
	tempBlock[9] = Sd[GETBYTE(t1, 2)];
	tempBlock[10] = Sd[GETBYTE(t0, 1)];
	tempBlock[11] = Sd[GETBYTE(t3, 0)];
	tempBlock[12] = Sd[GETBYTE(t3, 3)];
	tempBlock[13] = Sd[GETBYTE(t2, 2)];
	tempBlock[14] = Sd[GETBYTE(t1, 1)];
	tempBlock[15] = Sd[GETBYTE(t0, 0)];

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
