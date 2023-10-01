// aria.cpp - written and placed in the public domain by Jeffrey Walton

#include "pch.h"
#include "config.h"

#include "aria.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(ARIATab)

extern const word32 S1[256];
extern const word32 S2[256];
extern const word32 X1[256];
extern const word32 X2[256];
extern const word32 KRK[3][4];

NAMESPACE_END
NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

using CryptoPP::ARIATab::S1;
using CryptoPP::ARIATab::S2;
using CryptoPP::ARIATab::X1;
using CryptoPP::ARIATab::X2;
using CryptoPP::ARIATab::KRK;

inline byte ARIA_BRF(const word32 x, const int y) {
	return static_cast<byte>(GETBYTE(x, y));
}

// Key XOR Layer. Bumps the round key pointer.
inline const byte* ARIA_KXL(const byte rk[16], word32 t[4]) {
	typedef BlockGetAndPut<word32, NativeByteOrder, true, true>  NativeBlock;
	NativeBlock::Put(rk, t)(t[0])(t[1])(t[2])(t[3]);
	return rk+16;
}

// S-Box Layer 1 + M
inline void SBL1_M(word32& T0, word32& T1, word32& T2, word32& T3) {
	T0=S1[ARIA_BRF(T0,3)]^S2[ARIA_BRF(T0,2)]^X1[ARIA_BRF(T0,1)]^X2[ARIA_BRF(T0,0)];
	T1=S1[ARIA_BRF(T1,3)]^S2[ARIA_BRF(T1,2)]^X1[ARIA_BRF(T1,1)]^X2[ARIA_BRF(T1,0)];
	T2=S1[ARIA_BRF(T2,3)]^S2[ARIA_BRF(T2,2)]^X1[ARIA_BRF(T2,1)]^X2[ARIA_BRF(T2,0)];
	T3=S1[ARIA_BRF(T3,3)]^S2[ARIA_BRF(T3,2)]^X1[ARIA_BRF(T3,1)]^X2[ARIA_BRF(T3,0)];
}

// S-Box Layer 2 + M
inline void SBL2_M(word32& T0, word32& T1, word32& T2, word32& T3) {
	T0=X1[ARIA_BRF(T0,3)]^X2[ARIA_BRF(T0,2)]^S1[ARIA_BRF(T0,1)]^S2[ARIA_BRF(T0,0)];
	T1=X1[ARIA_BRF(T1,3)]^X2[ARIA_BRF(T1,2)]^S1[ARIA_BRF(T1,1)]^S2[ARIA_BRF(T1,0)];
	T2=X1[ARIA_BRF(T2,3)]^X2[ARIA_BRF(T2,2)]^S1[ARIA_BRF(T2,1)]^S2[ARIA_BRF(T2,0)];
	T3=X1[ARIA_BRF(T3,3)]^X2[ARIA_BRF(T3,2)]^S1[ARIA_BRF(T3,1)]^S2[ARIA_BRF(T3,0)];
  }

inline void ARIA_P(word32& T0, word32& T1, word32& T2, word32& T3) {
	CRYPTOPP_UNUSED(T0);
	T1 = ((T1<< 8)&0xff00ff00) ^ ((T1>> 8)&0x00ff00ff);
	T2 = rotrConstant<16>(T2);
	T3 = ByteReverse((T3));
}

inline void ARIA_M(word32& X, word32& Y) {
	Y=X<<8 ^ X>>8 ^ X<<16 ^ X>>16 ^ X<<24 ^ X>>24;
}


inline void ARIA_MM(word32& T0, word32& T1, word32& T2, word32& T3) {
	T1^=T2; T2^=T3; T0^=T1;
	T3^=T1; T2^=T0; T1^=T2;
}

inline void ARIA_FO(word32 t[4]) {
	SBL1_M(t[0],t[1],t[2],t[3]);
	ARIA_MM(t[0],t[1],t[2],t[3]);
	ARIA_P(t[0],t[1],t[2],t[3]);
	ARIA_MM(t[0],t[1],t[2],t[3]);
}

inline void ARIA_FE(word32 t[4]) {
	SBL2_M(t[0],t[1],t[2],t[3]);
	ARIA_MM(t[0],t[1],t[2],t[3]);
	ARIA_P(t[2],t[3],t[0],t[1]);
	ARIA_MM(t[0],t[1],t[2],t[3]);
}

// n-bit right shift of Y XORed to X
template <unsigned int N>
inline void ARIA_GSRK(const word32 X[4], const word32 Y[4], word32 RK[4])
{
	// MSVC is not generating a "rotate immediate". Constify to help it along.
	static const unsigned int Q = 4-(N/32);
	static const unsigned int R = N % 32;

	RK[0] = (X[0]) ^ ((Y[(Q  )%4])>>R) ^ ((Y[(Q+3)%4])<<(32-R));
	RK[1] = (X[1]) ^ ((Y[(Q+1)%4])>>R) ^ ((Y[(Q  )%4])<<(32-R));
	RK[2] = (X[2]) ^ ((Y[(Q+2)%4])>>R) ^ ((Y[(Q+1)%4])<<(32-R));
	RK[3] = (X[3]) ^ ((Y[(Q+3)%4])>>R) ^ ((Y[(Q+2)%4])<<(32-R));
}

void ARIA::Base::UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &params)
{
	CRYPTOPP_UNUSED(params);

	m_rk.New(4*17);  // round keys
	m_w.New(4*24);	 // w0, w1, w2, w3, t and u

	int Q, q, R, r;

	switch (keylen)
	{
	case 16:
		R = r = m_rounds = 12;
		Q = q = 0;
		break;
	case 32:
		R = r = m_rounds = 16;
		Q = q = 2;
		break;
	case 24:
		R = r = m_rounds = 14;
		Q = q = 1;
		break;
	default:
		Q = q = R = r = m_rounds = 0;
		CRYPTOPP_ASSERT(0);
	}

	// w0-w3 each has room for 4 words (16 bytes). t and u are each 4 words (16 bytes) temp areas.
	// The storage requrements for w0-w3, t and u are 96 bytes or 24 words.
	word32 *w0 = m_w.data(), *w1 = m_w.data()+4, *w2 = m_w.data()+8, *w3 = m_w.data()+12, *t = m_w.data()+16;

	GetBlock<word32, BigEndian, false>block(key);
	block(w0[0])(w0[1])(w0[2])(w0[3]);

	t[0]=w0[0]^KRK[q][0]; t[1]=w0[1]^KRK[q][1];
	t[2]=w0[2]^KRK[q][2]; t[3]=w0[3]^KRK[q][3];

	ARIA_FO(t);

	if (keylen == 32)
	{
		block(w1[0])(w1[1])(w1[2])(w1[3]);
	}
	else if (keylen == 24)
	{
		block(w1[0])(w1[1]); w1[2] = w1[3] = 0;
	}
	else
	{
		w1[0]=w1[1]=w1[2]=w1[3]=0;
	}

	w1[0]^=t[0]; w1[1]^=t[1]; w1[2]^=t[2]; w1[3]^=t[3];
	std::memcpy(t, w1, 16);

	q = (q==2) ? 0 : (q+1);
	t[0]^=KRK[q][0]; t[1]^=KRK[q][1]; t[2]^=KRK[q][2]; t[3]^=KRK[q][3];

	ARIA_FE(t);

	t[0]^=w0[0]; t[1]^=w0[1]; t[2]^=w0[2]; t[3]^=w0[3];
	std::memcpy(w2, t, 16);

	q = (q==2) ? 0 : (q+1);
	t[0]^=KRK[q][0]; t[1]^=KRK[q][1]; t[2]^=KRK[q][2]; t[3]^=KRK[q][3];

	ARIA_FO(t);

	w3[0]=t[0]^w1[0]; w3[1]=t[1]^w1[1]; w3[2]=t[2]^w1[2]; w3[3]=t[3]^w1[3];

	ARIA_GSRK<19>(w0, w1, m_rk +  0);
	ARIA_GSRK<19>(w1, w2, m_rk +  4);
	ARIA_GSRK<19>(w2, w3, m_rk +  8);
	ARIA_GSRK<19>(w3, w0, m_rk + 12);
	ARIA_GSRK<31>(w0, w1, m_rk + 16);
	ARIA_GSRK<31>(w1, w2, m_rk + 20);
	ARIA_GSRK<31>(w2, w3, m_rk + 24);
	ARIA_GSRK<31>(w3, w0, m_rk + 28);
	ARIA_GSRK<67>(w0, w1, m_rk + 32);
	ARIA_GSRK<67>(w1, w2, m_rk + 36);
	ARIA_GSRK<67>(w2, w3, m_rk + 40);
	ARIA_GSRK<67>(w3, w0, m_rk + 44);
	ARIA_GSRK<97>(w0, w1, m_rk + 48);

	if (keylen > 16)
	{
		ARIA_GSRK<97>(w1, w2, m_rk + 52);
		ARIA_GSRK<97>(w2, w3, m_rk + 56);

		if (keylen > 24)
		{
			ARIA_GSRK< 97>(w3, w0, m_rk + 60);
			ARIA_GSRK<109>(w0, w1, m_rk + 64);
		}
	}

	// Decryption operation
	if (!IsForwardTransformation())
	{
		word32 *a, *z, *s;
		r = R; q = Q;

		// s reuses w0 temp area
		a=m_rk.data(); s=m_w.data()+0; z=a+r*4;
		std::memcpy(t, a, 16); std::memcpy(a, z, 16); std::memcpy(z, t, 16);

		a+=4; z-=4;
		for (; a<z; a+=4, z-=4)
		{
			ARIA_M(a[0],t[0]); ARIA_M(a[1],t[1]); ARIA_M(a[2],t[2]); ARIA_M(a[3],t[3]);
			ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
			std::memcpy(s, t, 16);

			ARIA_M(z[0],t[0]); ARIA_M(z[1],t[1]); ARIA_M(z[2],t[2]); ARIA_M(z[3],t[3]);
			ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
			std::memcpy(a, t, 16); std::memcpy(z, s, 16);
		}

		ARIA_M(a[0],t[0]); ARIA_M(a[1],t[1]); ARIA_M(a[2],t[2]); ARIA_M(a[3],t[3]);
		ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
		std::memcpy(z, t, 16);
	}

	// Silence warnings
	CRYPTOPP_UNUSED(Q); CRYPTOPP_UNUSED(R);
	CRYPTOPP_UNUSED(q); CRYPTOPP_UNUSED(r);
}

void ARIA::Base::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	const byte *rk = reinterpret_cast<const byte*>(m_rk.data());
	word32 *t = const_cast<word32*>(m_w.data()+16);

	// Timing attack countermeasure. See comments in Rijndael for more details.
	// We used Yun's 32-bit implementation, so we use words rather than bytes.
	const int cacheLineSize = GetCacheLineSize();
	unsigned int i;
	volatile word32 _u = 0;
	word32 u = _u;

	for (i=0; i<COUNTOF(S1); i+=cacheLineSize/(sizeof(S1[0])))
		u |= *(S1+i);
	t[0] |= u;

	GetBlock<word32, BigEndian>block(inBlock);
	block(t[0])(t[1])(t[2])(t[3]);

	if (m_rounds > 12) {
		rk = ARIA_KXL(rk, t); ARIA_FO(t);
		rk = ARIA_KXL(rk, t); ARIA_FE(t);
	}

	if (m_rounds > 14) {
		rk = ARIA_KXL(rk, t); ARIA_FO(t);
		rk = ARIA_KXL(rk, t); ARIA_FE(t);
	}

	rk = ARIA_KXL(rk, t); ARIA_FO(t); rk = ARIA_KXL(rk, t); ARIA_FE(t);
	rk = ARIA_KXL(rk, t); ARIA_FO(t); rk = ARIA_KXL(rk, t); ARIA_FE(t);
	rk = ARIA_KXL(rk, t); ARIA_FO(t); rk = ARIA_KXL(rk, t); ARIA_FE(t);
	rk = ARIA_KXL(rk, t); ARIA_FO(t); rk = ARIA_KXL(rk, t); ARIA_FE(t);
	rk = ARIA_KXL(rk, t); ARIA_FO(t); rk = ARIA_KXL(rk, t); ARIA_FE(t);
	rk = ARIA_KXL(rk, t); ARIA_FO(t); rk = ARIA_KXL(rk, t);

#if (CRYPTOPP_LITTLE_ENDIAN)
	if (xorBlock)
	{
		outBlock[ 0] = static_cast<byte>(X1[ARIA_BRF(t[0],3)]   ) ^ rk[ 3] ^ xorBlock[ 0];
		outBlock[ 1] = static_cast<byte>(X2[ARIA_BRF(t[0],2)]>>8) ^ rk[ 2] ^ xorBlock[ 1];
		outBlock[ 2] = static_cast<byte>(S1[ARIA_BRF(t[0],1)]   ) ^ rk[ 1] ^ xorBlock[ 2];
		outBlock[ 3] = static_cast<byte>(S2[ARIA_BRF(t[0],0)]   ) ^ rk[ 0] ^ xorBlock[ 3];
		outBlock[ 4] = static_cast<byte>(X1[ARIA_BRF(t[1],3)]   ) ^ rk[ 7] ^ xorBlock[ 4];
		outBlock[ 5] = static_cast<byte>(X2[ARIA_BRF(t[1],2)]>>8) ^ rk[ 6] ^ xorBlock[ 5];
		outBlock[ 6] = static_cast<byte>(S1[ARIA_BRF(t[1],1)]   ) ^ rk[ 5] ^ xorBlock[ 6];
		outBlock[ 7] = static_cast<byte>(S2[ARIA_BRF(t[1],0)]   ) ^ rk[ 4] ^ xorBlock[ 7];
		outBlock[ 8] = static_cast<byte>(X1[ARIA_BRF(t[2],3)]   ) ^ rk[11] ^ xorBlock[ 8];
		outBlock[ 9] = static_cast<byte>(X2[ARIA_BRF(t[2],2)]>>8) ^ rk[10] ^ xorBlock[ 9];
		outBlock[10] = static_cast<byte>(S1[ARIA_BRF(t[2],1)]   ) ^ rk[ 9] ^ xorBlock[10];
		outBlock[11] = static_cast<byte>(S2[ARIA_BRF(t[2],0)]   ) ^ rk[ 8] ^ xorBlock[11];
		outBlock[12] = static_cast<byte>(X1[ARIA_BRF(t[3],3)]   ) ^ rk[15] ^ xorBlock[12];
		outBlock[13] = static_cast<byte>(X2[ARIA_BRF(t[3],2)]>>8) ^ rk[14] ^ xorBlock[13];
		outBlock[14] = static_cast<byte>(S1[ARIA_BRF(t[3],1)]   ) ^ rk[13] ^ xorBlock[14];
		outBlock[15] = static_cast<byte>(S2[ARIA_BRF(t[3],0)]   ) ^ rk[12] ^ xorBlock[15];
	}
	else
	{
		outBlock[ 0] = static_cast<byte>(X1[ARIA_BRF(t[0],3)]   ) ^ rk[ 3];
		outBlock[ 1] = static_cast<byte>(X2[ARIA_BRF(t[0],2)]>>8) ^ rk[ 2];
		outBlock[ 2] = static_cast<byte>(S1[ARIA_BRF(t[0],1)]   ) ^ rk[ 1];
		outBlock[ 3] = static_cast<byte>(S2[ARIA_BRF(t[0],0)]   ) ^ rk[ 0];
		outBlock[ 4] = static_cast<byte>(X1[ARIA_BRF(t[1],3)]   ) ^ rk[ 7];
		outBlock[ 5] = static_cast<byte>(X2[ARIA_BRF(t[1],2)]>>8) ^ rk[ 6];
		outBlock[ 6] = static_cast<byte>(S1[ARIA_BRF(t[1],1)]   ) ^ rk[ 5];
		outBlock[ 7] = static_cast<byte>(S2[ARIA_BRF(t[1],0)]   ) ^ rk[ 4];
		outBlock[ 8] = static_cast<byte>(X1[ARIA_BRF(t[2],3)]   ) ^ rk[11];
		outBlock[ 9] = static_cast<byte>(X2[ARIA_BRF(t[2],2)]>>8) ^ rk[10];
		outBlock[10] = static_cast<byte>(S1[ARIA_BRF(t[2],1)]   ) ^ rk[ 9];
		outBlock[11] = static_cast<byte>(S2[ARIA_BRF(t[2],0)]   ) ^ rk[ 8];
		outBlock[12] = static_cast<byte>(X1[ARIA_BRF(t[3],3)]   ) ^ rk[15];
		outBlock[13] = static_cast<byte>(X2[ARIA_BRF(t[3],2)]>>8) ^ rk[14];
		outBlock[14] = static_cast<byte>(S1[ARIA_BRF(t[3],1)]   ) ^ rk[13];
		outBlock[15] = static_cast<byte>(S2[ARIA_BRF(t[3],0)]   ) ^ rk[12];
	}
#else
	if (xorBlock)
	{
		outBlock[ 0] = static_cast<byte>(X1[ARIA_BRF(t[0],3)]   ) ^ rk[ 0] ^ xorBlock[ 0];
		outBlock[ 1] = static_cast<byte>(X2[ARIA_BRF(t[0],2)]>>8) ^ rk[ 1] ^ xorBlock[ 1];
		outBlock[ 2] = static_cast<byte>(S1[ARIA_BRF(t[0],1)]   ) ^ rk[ 2] ^ xorBlock[ 2];
		outBlock[ 3] = static_cast<byte>(S2[ARIA_BRF(t[0],0)]   ) ^ rk[ 3] ^ xorBlock[ 3];
		outBlock[ 4] = static_cast<byte>(X1[ARIA_BRF(t[1],3)]   ) ^ rk[ 4] ^ xorBlock[ 4];
		outBlock[ 5] = static_cast<byte>(X2[ARIA_BRF(t[1],2)]>>8) ^ rk[ 5] ^ xorBlock[ 5];
		outBlock[ 6] = static_cast<byte>(S1[ARIA_BRF(t[1],1)]   ) ^ rk[ 6] ^ xorBlock[ 6];
		outBlock[ 7] = static_cast<byte>(S2[ARIA_BRF(t[1],0)]   ) ^ rk[ 7] ^ xorBlock[ 7];
		outBlock[ 8] = static_cast<byte>(X1[ARIA_BRF(t[2],3)]   ) ^ rk[ 8] ^ xorBlock[ 8];
		outBlock[ 9] = static_cast<byte>(X2[ARIA_BRF(t[2],2)]>>8) ^ rk[ 9] ^ xorBlock[ 9];
		outBlock[10] = static_cast<byte>(S1[ARIA_BRF(t[2],1)]   ) ^ rk[10] ^ xorBlock[10];
		outBlock[11] = static_cast<byte>(S2[ARIA_BRF(t[2],0)]   ) ^ rk[11] ^ xorBlock[11];
		outBlock[12] = static_cast<byte>(X1[ARIA_BRF(t[3],3)]   ) ^ rk[12] ^ xorBlock[12];
		outBlock[13] = static_cast<byte>(X2[ARIA_BRF(t[3],2)]>>8) ^ rk[13] ^ xorBlock[13];
		outBlock[14] = static_cast<byte>(S1[ARIA_BRF(t[3],1)]   ) ^ rk[14] ^ xorBlock[14];
		outBlock[15] = static_cast<byte>(S2[ARIA_BRF(t[3],0)]   ) ^ rk[15] ^ xorBlock[15];
	}
	else
	{
		outBlock[ 0] = static_cast<byte>(X1[ARIA_BRF(t[0],3)]   ) ^ rk[ 0];
		outBlock[ 1] = static_cast<byte>(X2[ARIA_BRF(t[0],2)]>>8) ^ rk[ 1];
		outBlock[ 2] = static_cast<byte>(S1[ARIA_BRF(t[0],1)]   ) ^ rk[ 2];
		outBlock[ 3] = static_cast<byte>(S2[ARIA_BRF(t[0],0)]   ) ^ rk[ 3];
		outBlock[ 4] = static_cast<byte>(X1[ARIA_BRF(t[1],3)]   ) ^ rk[ 4];
		outBlock[ 5] = static_cast<byte>(X2[ARIA_BRF(t[1],2)]>>8) ^ rk[ 5];
		outBlock[ 6] = static_cast<byte>(S1[ARIA_BRF(t[1],1)]   ) ^ rk[ 6];
		outBlock[ 7] = static_cast<byte>(S2[ARIA_BRF(t[1],0)]   ) ^ rk[ 7];
		outBlock[ 8] = static_cast<byte>(X1[ARIA_BRF(t[2],3)]   ) ^ rk[ 8];
		outBlock[ 9] = static_cast<byte>(X2[ARIA_BRF(t[2],2)]>>8) ^ rk[ 9];
		outBlock[10] = static_cast<byte>(S1[ARIA_BRF(t[2],1)]   ) ^ rk[10];
		outBlock[11] = static_cast<byte>(S2[ARIA_BRF(t[2],0)]   ) ^ rk[11];
		outBlock[12] = static_cast<byte>(X1[ARIA_BRF(t[3],3)]   ) ^ rk[12];
		outBlock[13] = static_cast<byte>(X2[ARIA_BRF(t[3],2)]>>8) ^ rk[13];
		outBlock[14] = static_cast<byte>(S1[ARIA_BRF(t[3],1)]   ) ^ rk[14];
		outBlock[15] = static_cast<byte>(S2[ARIA_BRF(t[3],0)]   ) ^ rk[15];
	}
#endif  // CRYPTOPP_LITTLE_ENDIAN
}

NAMESPACE_END
