// haval.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "haval.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

HAVAL::HAVAL(unsigned int digestSize, unsigned int pass)
	: digestSize(digestSize), pass(pass)
{
	SetStateSize(DIGESTSIZE);

	if (!(digestSize >= 16 && digestSize <= 32 && digestSize%4==0))
		throw InvalidArgument("HAVAL: invalid digest size");

	if (!(pass >= 3 && pass <= 5))
		throw InvalidArgument("HAVAL: invalid number of passes");

	Init();
}

void HAVAL::Init()
{
	m_digest[0] = 0x243F6A88;
	m_digest[1] = 0x85A308D3;
	m_digest[2] = 0x13198A2E;
	m_digest[3] = 0x03707344;
	m_digest[4] = 0xA4093822;
	m_digest[5] = 0x299F31D0;
	m_digest[6] = 0x082EFA98;
	m_digest[7] = 0xEC4E6C89;
}

void HAVAL::HashEndianCorrectedBlock(const word32 *in)
{
	if (pass==3)
		HAVAL3::Transform(m_digest, in);
	else if (pass==4)
		HAVAL4::Transform(m_digest, in);
	else
		HAVAL5::Transform(m_digest, in);
}

void HAVAL::TruncatedFinal(byte *hash, unsigned int size)
{
	ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(118, 1);	// first byte of padding for HAVAL is 1 instead of 0x80
	CorrectEndianess(m_data, m_data, 120);

	m_data[29] &= 0xffff;
	m_data[29] |= ((word32)digestSize<<25) | ((word32)pass<<19) | ((word32)HAVAL_VERSION<<16);
	m_data[30] = GetBitCountLo();
	m_data[31] = GetBitCountHi();

	HashEndianCorrectedBlock(m_data);
	Tailor(digestSize*8);
	CorrectEndianess(m_digest, m_digest, digestSize);
	memcpy(hash, m_digest, size);

	Restart();		// reinit for next use
}

#define ROTR(x, y) rotrFixed(x, y##u)

// fold digest down to desired size
void HAVAL::Tailor(unsigned int bitlen)
{
#define EB(a, b, c) (m_digest[a] & (((~(word32)0) << b) & ((~(word32)0) >> (8*sizeof(word32)-b-c))))
#define S(a, b) (a > b ? a - b : 32 + a - b)
#define T128(a, b, c, d, e) ROTR(EB(7, b, S(a,b)) | EB(6, c, S(b,c)) | EB(5, d, S(c,d)) | EB(4, e, S(d,e)), e)
#define T160(a, b, c, d) ROTR(EB(7, b, S(a,b)) | EB(6, c, S(b,c)) | EB(5, d, S(c,d)), d)
#define T192(a, b, c) ROTR(EB(7, b, S(a,b)) | EB(6, c, S(b,c)), c)
#define T224(a, b) ROTR(EB(7, b, S(a,b)), b)

	switch (bitlen)
	{
	case 128:
		m_digest[0] += T128(8, 0, 24, 16, 8);
		m_digest[1] += T128(16, 8, 0, 24, 16);
		m_digest[2] += T128(24, 16, 8, 0, 24);
		m_digest[3] += T128(0, 24, 16, 8, 0);
		break;

	case 160:
		m_digest[0] += T160(6, 0, 25, 19);
		m_digest[1] += T160(12, 6, 0, 25);
		m_digest[2] += T160(19, 12, 6, 0);
		m_digest[3] += T160(25, 19, 12, 6);
		m_digest[4] += T160(0, 25, 19, 12);
		break;

	case 192:
		m_digest[0] += T192(5, 0, 26);
		m_digest[1] += T192(10, 5, 0);
		m_digest[2] += T192(16, 10, 5);
		m_digest[3] += T192(21, 16, 10);
		m_digest[4] += T192(26, 21, 16);
		m_digest[5] += T192(0, 26, 21);
		break;

	case 224:
		m_digest[0] += T224(0, 27);
		m_digest[1] += T224(27, 22);
		m_digest[2] += T224(22, 18);
		m_digest[3] += T224(18, 13);
		m_digest[4] += T224(13, 9);
		m_digest[5] += T224(9, 4);
		m_digest[6] += T224(4, 0);
		break;

	case 256:
		break;

	default:
		assert(false);
	}
}

/* Nonlinear F functions */

/* #define F1(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X4) ^ (X2) & (X5) ^ (X3) & (X6) ^ (X0) & (X1) ^ (X0))*/
#define F1(X6, X5, X4, X3, X2, X1, X0) \
	(((X1) & ((X4) ^ (X0))) ^ ((X2) & (X5)) ^ ((X3) & (X6)) ^ (X0))

/* #define F2(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X2) & (X3) ^ (X2) & (X4) & (X5) ^ \
	(X1) & (X2) ^ (X1) & (X4) ^ (X2) & (X6) ^ (X3) & (X5) ^ \
	(X4) & (X5) ^ (X0) & (X2) ^ (X0))*/
#define F2(X6, X5, X4, X3, X2, X1, X0) \
	(((X2) & (((X1) & (~(X3))) ^ ((X4) & (X5)) ^ (X6) ^ (X0))) ^ \
	(((X4) & ((X1) ^ (X5))) ^ ((X3) & (X5)) ^ (X0)))

/* #define F3(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X2) & (X3) ^ (X1) & (X4) ^ (X2) & (X5) ^ (X3) & (X6) ^ (X0) &
(X3) ^ (X0))*/
#define F3(X6, X5, X4, X3, X2, X1, X0) \
	(((X3) & (((X1) & (X2)) ^ (X6) ^ (X0))) ^ ((X1) & (X4)) ^ \
	((X2) & (X5)) ^ (X0))

/* #define F4(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X2) & (X3) ^ (X2) & (X4) & (X5) ^ (X3) & (X4) & (X6) ^ \
	(X1) & (X4) ^ (X2) & (X6) ^ (X3) & (X4) ^ (X3) & (X5) ^ \
	(X3) & (X6) ^ (X4) & (X5) ^ (X4) & (X6) ^ (X0) & (X4) ^(X0))*/
#define F4(X6, X5, X4, X3, X2, X1, X0) \
	(((X4) & (((~(X2)) & (X5)) ^ ((X3) | (X6)) ^ (X1) ^ (X0))) ^ \
	((X3) & (((X1) & (X2)) ^ (X5) ^ (X6))) ^ ((X2) & (X6)) ^ (X0))

/* #define F5(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X4) ^ (X2) & (X5) ^ (X3) & (X6) ^ \
	(X0) & (X1) & (X2) & (X3) ^ (X0) & (X5) ^ (X0))*/
#define F5(X6, X5, X4, X3, X2, X1, X0) \
	(((X1) & ((X4) ^ ((X0) & (X2) & (X3)))) ^ \
	(((X2) ^ (X0)) & (X5)) ^ ((X3) & (X6)) ^ (X0))

#define p31(x) (x==0 ? 1 : (x==1 ? 0 : (x==2 ? 3 : (x==3 ? 5 : (x==4 ? 6 : (x==5 ? 2 : (x==6 ? 4 : 7)))))))
#define p41(x) (x==0 ? 2 : (x==1 ? 6 : (x==2 ? 1 : (x==3 ? 4 : (x==4 ? 5 : (x==5 ? 3 : (x==6 ? 0 : 7)))))))
#define p51(x) (x==0 ? 3 : (x==1 ? 4 : (x==2 ? 1 : (x==3 ? 0 : (x==4 ? 5 : (x==5 ? 2 : (x==6 ? 6 : 7)))))))
#define p32(x) (x==0 ? 4 : (x==1 ? 2 : (x==2 ? 1 : (x==3 ? 0 : (x==4 ? 5 : (x==5 ? 3 : (x==6 ? 6 : 7)))))))
#define p42(x) (x==0 ? 3 : (x==1 ? 5 : (x==2 ? 2 : (x==3 ? 0 : (x==4 ? 1 : (x==5 ? 6 : (x==6 ? 4 : 7)))))))
#define p52(x) (x==0 ? 6 : (x==1 ? 2 : (x==2 ? 1 : (x==3 ? 0 : (x==4 ? 3 : (x==5 ? 4 : (x==6 ? 5 : 7)))))))
#define p33(x) (x==0 ? 6 : (x==1 ? 1 : (x==2 ? 2 : (x==3 ? 3 : (x==4 ? 4 : (x==5 ? 5 : (x==6 ? 0 : 7)))))))
#define p43(x) (x==0 ? 1 : (x==1 ? 4 : (x==2 ? 3 : (x==3 ? 6 : (x==4 ? 0 : (x==5 ? 2 : (x==6 ? 5 : 7)))))))
#define p53(x) (x==0 ? 2 : (x==1 ? 6 : (x==2 ? 0 : (x==3 ? 4 : (x==4 ? 3 : (x==5 ? 1 : (x==6 ? 5 : 7)))))))
#define p44(x) (x==0 ? 6 : (x==1 ? 4 : (x==2 ? 0 : (x==3 ? 5 : (x==4 ? 2 : (x==5 ? 1 : (x==6 ? 3 : 7)))))))
#define p54(x) (x==0 ? 1 : (x==1 ? 5 : (x==2 ? 3 : (x==3 ? 2 : (x==4 ? 0 : (x==5 ? 4 : (x==6 ? 6 : 7)))))))
#define p55(x) (x==0 ? 2 : (x==1 ? 5 : (x==2 ? 0 : (x==3 ? 6 : (x==4 ? 4 : (x==5 ? 3 : (x==6 ? 1 : 7)))))))

#define t(b,p,x,j) ((b&&((p(x)+8-j)%8<(8-j)))?E:T)[(p(x)+8-j)%8]

#define FF(b, e, F, p, j, w, c)	\
	T[7-j] = rotrFixed(F(t(b,p,0,j), t(b,p,1,j), t(b,p,2,j), t(b,p,3,j), t(b,p,4,j), t(b,p,5,j), t(b,p,6,j)), 7U) + rotrFixed(t(b,p,7,j), 11U) + w + c;	\
	if (e) E[7-j] += T[7-j];

#ifdef CRYPTOPP_DOXYGEN_PROCESSING
// Doxygen can't handle these macros
#define Round1(t)
#define Round(t, n)
#else
#define Round1(t)					\
	for (i=0; i<4; i++)				\
	{								\
		FF(i==0, 0, F1, p##t##1, 0, W[8*i+0], 0);	\
		FF(i==0, 0, F1, p##t##1, 1, W[8*i+1], 0);	\
		FF(i==0, 0, F1, p##t##1, 2, W[8*i+2], 0);	\
		FF(i==0, 0, F1, p##t##1, 3, W[8*i+3], 0);	\
		FF(i==0, 0, F1, p##t##1, 4, W[8*i+4], 0);	\
		FF(i==0, 0, F1, p##t##1, 5, W[8*i+5], 0);	\
		FF(i==0, 0, F1, p##t##1, 6, W[8*i+6], 0);	\
		FF(i==0, 0, F1, p##t##1, 7, W[8*i+7], 0);	\
	}
#define Round(t, n)					\
	for (i=0; i<4; i++)				\
	{								\
		FF(0, t==n && i==3, F##n, p##t##n, 0, W[wi##n[8*i+0]], mc##n[8*i+0]);	\
		FF(0, t==n && i==3, F##n, p##t##n, 1, W[wi##n[8*i+1]], mc##n[8*i+1]);	\
		FF(0, t==n && i==3, F##n, p##t##n, 2, W[wi##n[8*i+2]], mc##n[8*i+2]);	\
		FF(0, t==n && i==3, F##n, p##t##n, 3, W[wi##n[8*i+3]], mc##n[8*i+3]);	\
		FF(0, t==n && i==3, F##n, p##t##n, 4, W[wi##n[8*i+4]], mc##n[8*i+4]);	\
		FF(0, t==n && i==3, F##n, p##t##n, 5, W[wi##n[8*i+5]], mc##n[8*i+5]);	\
		FF(0, t==n && i==3, F##n, p##t##n, 6, W[wi##n[8*i+6]], mc##n[8*i+6]);	\
		FF(0, t==n && i==3, F##n, p##t##n, 7, W[wi##n[8*i+7]], mc##n[8*i+7]);	\
	}
#endif

const unsigned int HAVAL::wi2[32] = { 5,14,26,18,11,28, 7,16, 0,23,20,22, 1,10, 4, 8,30, 3,21, 9,17,24,29, 6,19,12,15,13, 2,25,31,27};
const unsigned int HAVAL::wi3[32] = {19, 9, 4,20,28,17, 8,22,29,14,25,12,24,30,16,26,31,15, 7, 3, 1, 0,18,27,13, 6,21,10,23,11, 5, 2};
const unsigned int HAVAL::wi4[32] = {24, 4, 0,14, 2, 7,28,23,26, 6,30,20,18,25,19, 3,22,11,31,21, 8,27,12, 9, 1,29, 5,15,17,10,16,13};
const unsigned int HAVAL::wi5[32] = {27, 3,21,26,17,11,20,29,19, 0,12, 7,13, 8,31,10, 5, 9,14,30,18, 6,28,24, 2,23,16,22, 4, 1,25,15};

const word32 HAVAL::mc2[32] = {
  0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
, 0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96
, 0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69
, 0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5};

const word32 HAVAL::mc3[32] = {
0x9C30D539,0x2AF26013,0xC5D1B023,0x286085F0,0xCA417918,0xB8DB38EF,0x8E79DCB0,0x603A180E,
0x6C9E0E8B,0xB01E8A3E,0xD71577C1,0xBD314B27,0x78AF2FDA,0x55605C60,0xE65525F3,0xAA55AB94,
0x57489862,0x63E81440,0x55CA396A,0x2AAB10B6,0xB4CC5C34,0x1141E8CE,0xA15486AF,0x7C72E993,
0xB3EE1411,0x636FBC2A,0x2BA9C55D,0x741831F6,0xCE5C3E16,0x9B87931E,0xAFD6BA33,0x6C24CF5C};

const word32 HAVAL::mc4[32] = {
0x7A325381,0x28958677,0x3B8F4898,0x6B4BB9AF,0xC4BFE81B,0x66282193,0x61D809CC,0xFB21A991,
0x487CAC60,0x5DEC8032,0xEF845D5D,0xE98575B1,0xDC262302,0xEB651B88,0x23893E81,0xD396ACC5,
0x0F6D6FF3,0x83F44239,0x2E0B4482,0xA4842004,0x69C8F04A,0x9E1F9B5E,0x21C66842,0xF6E96C9A,
0x670C9C61,0xABD388F0,0x6A51A0D2,0xD8542F68,0x960FA728,0xAB5133A3,0x6EEF0B6C,0x137A3BE4};

const word32 HAVAL::mc5[32] = {
0xBA3BF050,0x7EFB2A98,0xA1F1651D,0x39AF0176,0x66CA593E,0x82430E88,0x8CEE8619,0x456F9FB4,
0x7D84A5C3,0x3B8B5EBE,0xE06F75D8,0x85C12073,0x401A449F,0x56C16AA6,0x4ED3AA62,0x363F7706,
0x1BFEDF72,0x429B023D,0x37D0D724,0xD00A1248,0xDB0FEAD3,0x49F1C09B,0x075372C9,0x80991B7B,
0x25D479D8,0xF6E8DEF7,0xE3FE501A,0xB6794C3B,0x976CE0BD,0x04C006BA,0xC1A94FB6,0x409F60C4};

void HAVAL3::Transform(word32 *E, const word32 *W)
{
	word32 T[8];
	unsigned int i;

	Round1(3);
	Round(3, 2);
	Round(3, 3);

	memset(T, 0, sizeof(T));
}

void HAVAL4::Transform(word32 *E, const word32 *W)
{
	word32 T[8];
	unsigned int i;

	Round1(4);
	Round(4, 2);
	Round(4, 3);
	Round(4, 4);

	memset(T, 0, sizeof(T));
}

void HAVAL5::Transform(word32 *E, const word32 *W)
{
	word32 T[8];
	unsigned int i;

	Round1(5);
	Round(5, 2);
	Round(5, 3);
	Round(5, 4);
	Round(5, 5);

	memset(T, 0, sizeof(T));
}

NAMESPACE_END
