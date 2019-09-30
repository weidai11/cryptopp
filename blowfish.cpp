// blowfish.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "blowfish.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

extern template const word32 Blowfish_Base<Blowfish_Info, BigEndian>::p_init[Blowfish_Info::ROUNDS+2];
extern template const word32 Blowfish_Base<Blowfish_Info, BigEndian>::s_init[4*256];

extern template const word32 Blowfish_Base<BlowfishCompat_Info, LittleEndian>::p_init[BlowfishCompat_Info::ROUNDS+2];
extern template const word32 Blowfish_Base<BlowfishCompat_Info, LittleEndian>::s_init[4*256];

template<class Info, class ByteOrder>
void Blowfish_Base<Info, ByteOrder>::UncheckedSetKey(const byte *key_string, unsigned int keylength, const NameValuePairs &)
{
	this->AssertValidKeyLength(keylength);

	unsigned i, j=0, k;
	word32 data, dspace[2] = {0, 0};

	memcpy(pbox, p_init, sizeof(p_init));
	memcpy(sbox, s_init, sizeof(s_init));

	// Xor key string into encryption key vector
	for (i=0 ; i<Info::ROUNDS+2 ; ++i)
	{
		data = 0 ;
		for (k=0 ; k<4 ; ++k )
			data = (data << 8) | key_string[j++ % keylength];
		pbox[i] ^= data;
	}

	crypt_block(dspace, pbox);

	for (i=0; i<Info::ROUNDS; i+=2)
		crypt_block(pbox+i, pbox+i+2);

	crypt_block(pbox+Info::ROUNDS, sbox);

	for (i=0; i<4*256-2; i+=2)
		crypt_block(sbox+i, sbox+i+2);

	if (!this->IsForwardTransformation())
		for (i=0; i<(Info::ROUNDS+2)/2; i++)
			std::swap(pbox[i], pbox[Info::ROUNDS+1-i]);
}

// this version is only used to make pbox and sbox
template<class Info, class ByteOrder>
void Blowfish_Base<Info, ByteOrder>::crypt_block(const word32 in[2], word32 out[2]) const
{
	word32 left = in[0];
	word32 right = in[1];

	const word32 *const s=sbox;
	const word32 *p=pbox;

	left ^= p[0];

	for (unsigned i=0; i<Info::ROUNDS/2; i++)
	{
		right ^= (((s[GETBYTE(left,3)] + s[256+GETBYTE(left,2)])
			  ^ s[2*256+GETBYTE(left,1)]) + s[3*256+GETBYTE(left,0)])
			  ^ p[2*i+1];

		left ^= (((s[GETBYTE(right,3)] + s[256+GETBYTE(right,2)])
			 ^ s[2*256+GETBYTE(right,1)]) + s[3*256+GETBYTE(right,0)])
			 ^ p[2*i+2];
	}

	right ^= p[Info::ROUNDS+1];

	out[0] = right;
	out[1] = left;
}

template<class Info, class ByteOrder>
void Blowfish_Base<Info, ByteOrder>::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	typedef BlockGetAndPut<word32, ByteOrder> Block;

	word32 left, right;
	Block::Get(inBlock)(left)(right);

	const word32 *const s=sbox;
	const word32 *p=pbox;

	left ^= p[0];

	for (unsigned i=0; i<Info::ROUNDS/2; i++)
	{
		right ^= (((s[GETBYTE(left,3)] + s[256+GETBYTE(left,2)])
			  ^ s[2*256+GETBYTE(left,1)]) + s[3*256+GETBYTE(left,0)])
			  ^ p[2*i+1];

		left ^= (((s[GETBYTE(right,3)] + s[256+GETBYTE(right,2)])
			 ^ s[2*256+GETBYTE(right,1)]) + s[3*256+GETBYTE(right,0)])
			 ^ p[2*i+2];
	}

	right ^= p[Info::ROUNDS+1];

	typename Block::Put(xorBlock, outBlock)(right)(left);
}

template class Blowfish_Base<Blowfish_Info, BigEndian>;
template class Blowfish_Base<BlowfishCompat_Info, LittleEndian>;

NAMESPACE_END
