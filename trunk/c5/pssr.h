#ifndef CRYPTOPP_PSSR_H
#define CRYPTOPP_PSSR_H

#include "pubkey.h"
#include <functional>

NAMESPACE_BEGIN(CryptoPP)

// TODO: implement standard variant of PSSR
template <class H, class MGF=P1363_MGF1<H> >
class PSSR : public SignatureEncodingMethodWithRecovery
{
public:
	PSSR(unsigned int representativeBitLen);
	PSSR(const byte *representative, unsigned int representativeBitLen);
	~PSSR() {}
	void Update(const byte *input, unsigned int length);
	unsigned int DigestSize() const {return BitsToBytes(representativeBitLen);}
	void Restart() {h.Restart();}
	void Encode(RandomNumberGenerator &rng, byte *representative);
	bool Verify(const byte *representative);
	DecodingResult Decode(byte *message);
	unsigned int MaximumRecoverableLength() const {return MaximumRecoverableLength(representativeBitLen);}
	static unsigned int MaximumRecoverableLength(unsigned int representativeBitLen);
	static bool AllowLeftoverMessage() {return true;}

protected:
	static void EncodeRepresentative(byte *representative, unsigned int representativeBitLen, const byte *w, const byte *seed, const byte *m1, unsigned int m1Len);
	static unsigned int DecodeRepresentative(const byte *representative, unsigned int representativeBitLen, byte *w, byte *seed, byte *m1);

	unsigned int representativeBitLen, m1Len;
	H h;
	SecByteBlock m1, w, seed;
};

template <class H, class MGF>
PSSR<H,MGF>::PSSR(unsigned int representativeBitLen)
	: representativeBitLen(representativeBitLen), m1Len(0)
	, m1(MaximumRecoverableLength()), w(H::DIGESTSIZE), seed(H::DIGESTSIZE)
{
}

template <class H, class MGF>
PSSR<H,MGF>::PSSR(const byte *representative, unsigned int representativeBitLen)
	: representativeBitLen(representativeBitLen), m1Len(0)
	, m1(MaximumRecoverableLength()), w(H::DIGESTSIZE), seed(H::DIGESTSIZE)
{
	m1Len = DecodeRepresentative(representative, representativeBitLen, w, seed, m1);
	h.Update(m1, m1Len);
}

template <class H, class MGF>
void PSSR<H,MGF>::Update(const byte *input, unsigned int length)
{
	unsigned int m1LenInc = STDMIN(length, MaximumRecoverableLength() - m1Len);
	memcpy(m1+m1Len, input, m1LenInc);
	m1Len += m1LenInc;
	h.Update(input, length);
}

template <class H, class MGF>
void PSSR<H,MGF>::Encode(RandomNumberGenerator &rng, byte *representative)
{
	rng.GenerateBlock(seed, seed.size());
	h.Update(seed, seed.size());
	h.Final(w);
	EncodeRepresentative(representative, representativeBitLen, w, seed, m1, m1Len);
}

template <class H, class MGF>
bool PSSR<H,MGF>::Verify(const byte *representative)
{
	SecByteBlock m1r(MaximumRecoverableLength()), wr(H::DIGESTSIZE);
	unsigned int m1rLen = DecodeRepresentative(representative, representativeBitLen, wr, seed, m1r);
	h.Update(seed, seed.size());
	h.Final(w);
	return m1Len==m1rLen && memcmp(m1, m1r, m1Len)==0 && w==wr;
}

template <class H, class MGF>
DecodingResult PSSR<H,MGF>::Decode(byte *message)
{
	SecByteBlock wh(H::DIGESTSIZE);
	h.Update(seed, seed.size());
	h.Final(wh);
	if (wh == w)
	{
		memcpy(message, m1, m1Len);
		return DecodingResult(m1Len);
	}
	else
		return DecodingResult();
}

template <class H, class MGF>
unsigned int PSSR<H,MGF>::MaximumRecoverableLength(unsigned int paddedLength)
{
	return paddedLength/8 > 1+2*H::DIGESTSIZE ? paddedLength/8-1-2*H::DIGESTSIZE : 0;
}

template <class H, class MGF>
void PSSR<H,MGF>::EncodeRepresentative(byte *pssrBlock, unsigned int pssrBlockLen, const byte *w, const byte *seed, const byte *m1, unsigned int m1Len)
{
	assert (m1Len <= MaximumRecoverableLength(pssrBlockLen));

	// convert from bit length to byte length
	if (pssrBlockLen % 8 != 0)
	{
		pssrBlock[0] = 0;
		pssrBlock++;
	}
	pssrBlockLen /= 8;

	const unsigned int hLen = H::DIGESTSIZE;
	const unsigned int wLen = hLen, seedLen = hLen, dbLen = pssrBlockLen-wLen-seedLen;
	byte *const maskedSeed = pssrBlock+wLen;
	byte *const maskedDB = pssrBlock+wLen+seedLen;

	memcpy(pssrBlock, w, wLen);
	memcpy(maskedSeed, seed, seedLen);
	memset(maskedDB, 0, dbLen-m1Len-1);
	maskedDB[dbLen-m1Len-1] = 0x01;
	memcpy(maskedDB+dbLen-m1Len, m1, m1Len);

	MGF::GenerateAndMask(maskedSeed, seedLen+dbLen, w, wLen);
}

template <class H, class MGF>
unsigned int PSSR<H,MGF>::DecodeRepresentative(const byte *pssrBlock, unsigned int pssrBlockLen, byte *w, byte *seed, byte *m1)
{
	// convert from bit length to byte length
	if (pssrBlockLen % 8 != 0)
	{
		if (pssrBlock[0] != 0)
			return 0;
		pssrBlock++;
	}
	pssrBlockLen /= 8;

	const unsigned int hLen = H::DIGESTSIZE;
	const unsigned int wLen = hLen, seedLen = hLen, dbLen = pssrBlockLen-wLen-seedLen;

	if (pssrBlockLen < 2*hLen+1)
		return 0;

	memcpy(w, pssrBlock, wLen);
	SecByteBlock t(pssrBlock+wLen, pssrBlockLen-wLen);
	byte *const maskedSeed = t;
	byte *const maskedDB = t+seedLen;

	MGF::GenerateAndMask(maskedSeed, seedLen+dbLen, w, wLen);
	memcpy(seed, maskedSeed, seedLen);

	// DB = 00 ... || 01 || M

	byte *M = std::find_if(maskedDB, maskedDB+dbLen, std::bind2nd(std::not_equal_to<byte>(), 0));
	if (M!=maskedDB+dbLen && *M == 0x01)
	{
		M++;
		memcpy(m1, M, maskedDB+dbLen-M);
		return maskedDB+dbLen-M;
	}
	else
		return 0;
}

NAMESPACE_END

#endif
