// tweetnacl.cpp - modified tweetnacl.c placed in public domain by Jeffrey Walton.
//                 The NaCl library and tweetnacl.c is public domain source code
//                 written by Daniel J. Bernstein, Bernard van Gastel, Wesley
//                 Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers.

#include "pch.h"
#include "config.h"
#include "naclite.h"
#include "misc.h"
#include "osrng.h"
#include "stdcpp.h"

// Don't destroy const time properties when squashing warnings.
#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4146 4242 4244 4245)
#endif

#ifndef CRYPTOPP_DISABLE_NACL

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(NaCl)

typedef sword64 gf[16];

static const byte
  _0[32] = {0},
  _9[32] = {9};

static const gf
  gf0 = {0},
  gf1 = {1},
  _121665 = {0xDB41,1},
  D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

// Added by Crypto++ for TweetNaCl
static void randombytes(byte * block, word64 size)
{
    DefaultAutoSeededRNG prng;
    prng.GenerateBlock(block, (size_t)size);
}

static word32 L32(word32 x,int c) { return (x << c) | ((x&0xffffffff) >> (32 - c)); }

static word32 ld32(const byte *x)
{
  word32 u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

static word64 dl64(const byte *x)
{
  word64 i,u=0;
  for(i=0; i<8; ++i) u=(u<<8)|x[i];
  return u;
}

static void st32(byte *x,word32 u)
{
  int i;
  for(i=0; i<4; ++i) { x[i] = u; u >>= 8; }
}

static void ts64(byte *x,word64 u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}

// Extra cast due to Coverity CID 186949
static int verify_n(const byte *x,const byte *y,word32 n)
{
  word32 i,d = 0;
  for(i=0; i<n; ++i) d |= x[i]^y[i];
  const sword32 v = (sword32) d;
  return (1 & ((word32)(v - 1) >> 8)) - 1;
}

int crypto_verify_16(const byte *x,const byte *y)
{
  return verify_n(x,y,16);
}

int crypto_verify_32(const byte *x,const byte *y)
{
  return verify_n(x,y,32);
}

static void core(byte *out,const byte *in,const byte *k,const byte *c,int h)
{
  word32 w[16],x[16],y[16],t[4];
  int i,j,m;

  for(i=0; i<4; ++i) {
    x[5*i] = ld32(c+4*i);
    x[1+i] = ld32(k+4*i);
    x[6+i] = ld32(in+4*i);
    x[11+i] = ld32(k+16+4*i);
  }

  for(i=0; i<16; ++i) y[i] = x[i];

  for(i=0; i<20; ++i) {
    for(j=0; j<4; ++j) {
      for(m=0; m<4; ++m) t[m] = x[(5*j+4*m)%16];
      t[1] ^= L32(t[0]+t[3], 7);
      t[2] ^= L32(t[1]+t[0], 9);
      t[3] ^= L32(t[2]+t[1],13);
      t[0] ^= L32(t[3]+t[2],18);
      for(m=0; m<4; ++m) w[4*j+(j+m)%4] = t[m];
    }
    for(m=0; m<16; ++m) x[m] = w[m];
  }

  if (h) {
    for(i=0; i<16; ++i) x[i] += y[i];
    for(i=0; i<4; ++i) {
      x[5*i] -= ld32(c+4*i);
      x[6+i] -= ld32(in+4*i);
    }
    for(i=0; i<4; ++i) {
      st32(out+4*i,x[5*i]);
      st32(out+16+4*i,x[6+i]);
    }
  } else
    for(i=0; i<16; ++i) st32(out + 4 * i,x[i] + y[i]);
}

int crypto_core_salsa20(byte *out,const byte *in,const byte *k,const byte *c)
{
  core(out,in,k,c,0);
  return 0;
}

int crypto_core_hsalsa20(byte *out,const byte *in,const byte *k,const byte *c)
{
  core(out,in,k,c,1);
  return 0;
}

static const byte sigma[16] = {0x65,0x78,0x70,0x61,0x6E,0x64,0x20,0x33,0x32,0x2D,0x62,0x79,0x74,0x65,0x20,0x6B};

int crypto_stream_salsa20_xor(byte *c,const byte *m,word64 b,const byte *n,const byte *k)
{
  byte z[16],x[64];
  word32 u,i;
  if (!b) return 0;
  for(i=0; i<16; ++i) z[i] = 0;
  for(i=0; i<8; ++i) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x,z,k,sigma);
    for(i=0; i<64; ++i) c[i] = (m?m[i]:0) ^ x[i];
    u = 1;
    for (i = 8;i < 16;++i) {
      u += (word32) z[i];
      z[i] = u;
      u >>= 8;
    }
    b -= 64;
    c += 64;
    if (m) m += 64;
  }
  if (b) {
    crypto_core_salsa20(x,z,k,sigma);
    for(i=0; i<b; ++i) c[i] = (m?m[i]:0) ^ x[i];
  }
  return 0;
}

int crypto_stream_salsa20(byte *c,word64 d,const byte *n,const byte *k)
{
  return crypto_stream_salsa20_xor(c,0,d,n,k);
}

int crypto_stream(byte *c,word64 d,const byte *n,const byte *k)
{
  byte s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20(c,d,n+16,s);
}

int crypto_stream_xor(byte *c,const byte *m,word64 d,const byte *n,const byte *k)
{
  byte s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20_xor(c,m,d,n+16,s);
}

static void add1305(word32 *h,const word32 *c)
{
  word32 j,u = 0;
  for(j=0; j<17; ++j) {
    u += h[j] + c[j];
    h[j] = u & 255;
    u >>= 8;
  }
}

static const word32 minusp[17] = {
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
} ;

int crypto_onetimeauth(byte *out,const byte *m,word64 n,const byte *k)
{
  word32 s,i,j,u,x[17],r[17],h[17],c[17],g[17];

  for(j=0; j<17; ++j) r[j]=h[j]=0;
  for(j=0; j<16; ++j) r[j]=k[j];
  r[3]&=15;
  r[4]&=252;
  r[7]&=15;
  r[8]&=252;
  r[11]&=15;
  r[12]&=252;
  r[15]&=15;

  while (n > 0) {
    for(j=0; j<17; ++j) c[j] = 0;
    for (j = 0;(j < 16) && (j < n);++j) c[j] = m[j];
    c[j] = 1;
    m += j; n -= j;
    add1305(h,c);
    for(i=0; i<17; ++i) {
      x[i] = 0;
      for(j=0; j<17; ++j) x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
    }
    for(i=0; i<17; ++i) h[i] = x[i];
    u = 0;
    for(j=0; j<16; ++j) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u & 3;
    u = 5 * (u >> 2);
    for(j=0; j<16; ++j) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u;
  }

  for(j=0; j<17; ++j) g[j] = h[j];
  add1305(h,minusp);
  s = -(h[16] >> 7);
  for(j=0; j<17; ++j) h[j] ^= s & (g[j] ^ h[j]);

  for(j=0; j<16; ++j) c[j] = k[j + 16];
  c[16] = 0;
  add1305(h,c);
  for(j=0; j<16; ++j) out[j] = h[j];
  return 0;
}

int crypto_onetimeauth_verify(const byte *h,const byte *m,word64 n,const byte *k)
{
  byte x[16];
  crypto_onetimeauth(x,m,n,k);
  return crypto_verify_16(h,x);
}

int crypto_secretbox(byte *c,const byte *m,word64 d,const byte *n,const byte *k)
{
  int i;
  if (d < 32) return -1;
  crypto_stream_xor(c,m,d,n,k);
  crypto_onetimeauth(c + 16,c + 32,d - 32,c);
  for(i=0; i<16; ++i) c[i] = 0;
  return 0;
}

int crypto_secretbox_open(byte *m,const byte *c,word64 d,const byte *n,const byte *k)
{
  int i;
  byte x[32];
  if (d < 32) return -1;
  crypto_stream(x,32,n,k);
  if (crypto_onetimeauth_verify(c + 16,c + 32,d - 32,x) != 0) return -1;
  crypto_stream_xor(m,c,d,n,k);
  for(i=0; i<32; ++i) m[i] = 0;
  return 0;
}

static void set25519(gf r, const gf a)
{
  int i;
  for(i=0; i<16; ++i) r[i]=a[i];
}

static void car25519(gf o)
{
  int i;
  sword64 c;
  for(i=0; i<16; ++i) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=((word64)c)<<16;
  }
}

static void sel25519(gf p,gf q,int b)
{
  sword64 t,i,c=~(b-1);
  for(i=0; i<16; ++i) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

static void pack25519(byte *o,const gf n)
{
  int i,j,b;
  gf m,t;
  for(i=0; i<16; ++i) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for(j=0; j<2; ++j) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  for(i=0; i<16; ++i) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int neq25519(const gf a, const gf b)
{
  byte c[32],d[32];
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

static byte par25519(const gf a)
{
  byte d[32];
  pack25519(d,a);
  return d[0]&1;
}

static void unpack25519(gf o, const byte *n)
{
  int i;
  for(i=0; i<16; ++i) o[i]=n[2*i]+((sword64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

static void A(gf o,const gf a,const gf b)
{
  int i;
  for(i=0; i<16; ++i) o[i]=a[i]+b[i];
}

static void Z(gf o,const gf a,const gf b)
{
  int i;
  for(i=0; i<16; ++i) o[i]=a[i]-b[i];
}

static void M(gf o,const gf a,const gf b)
{
  sword64 i,j,t[31];
  for(i=0; i<31; ++i) t[i]=0;
  for(i=0; i<16; ++i) for(j=0; j<16; ++j) t[i+j]+=a[i]*b[j];
  for(i=0; i<15; ++i) t[i]+=38*t[i+16];
  for(i=0; i<16; ++i) o[i]=t[i];
  car25519(o);
  car25519(o);
}

static void S(gf o,const gf a)
{
  M(o,a,a);
}

static void inv25519(gf o,const gf i)
{
  gf c;
  int a;
  for(a=0; a<16; ++a) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  for(a=0; a<16; ++a) o[a]=c[a];
}

static void pow2523(gf o,const gf i)
{
  gf c;
  int a;
  for(a=0; a<16; ++a) c[a]=i[a];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  for(a=0; a<16; ++a) o[a]=c[a];
}

// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
static int has_small_order(const byte s[32])
{
  CRYPTOPP_ALIGN_DATA(16)
  const byte blacklist[][32] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
    { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
    { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    { 0xcd, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x80 },
    { 0x4c, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7 },
    { 0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    { 0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    { 0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
  };
  CRYPTOPP_COMPILE_ASSERT(12 == COUNTOF(blacklist));

  byte c[12] = { 0 };
  for (size_t j = 0; j < 32; j++) {
    for (size_t i = 0; i < COUNTOF(blacklist); i++) {
      c[i] |= s[j] ^ blacklist[i][j];
    }
  }

  unsigned int k = 0;
  for (size_t i = 0; i < COUNTOF(blacklist); i++) {
    k |= (c[i] - 1);
  }

  return (int) ((k >> 8) & 1);
}

int crypto_scalarmult(byte *q,const byte *n,const byte *p)
{
  byte z[32];
  sword64 x[80],r,i;
  gf a,b,c,d,e,f;
  for(i=0; i<31; ++i) z[i]=n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  for(i=0; i<16; ++i) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for(i=254;i>=0;--i) {
    r=(z[i>>3]>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  for(i=0; i<16; ++i) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  inv25519(x+32,x+32);
  M(x+16,x+16,x+32);
  pack25519(q,x+16);
  return 0;
}

int crypto_scalarmult_base(byte *q,const byte *n)
{
  return crypto_scalarmult(q,n,_9);
}

int crypto_box_keypair(byte *y,byte *x)
{
  randombytes(x,32);
  return crypto_scalarmult_base(y,x);
}

// Avoid small order elements. Also see https://eprint.iacr.org/2017/806.pdf
// and https://github.com/jedisct1/libsodium/commit/675149b9b8b66ff4.
int crypto_box_beforenm(byte *k,const byte *y,const byte *x)
{
  byte s[32];
  if(crypto_scalarmult(s,x,y) != 0) return -1;
  if(has_small_order(s) != 0) return -1;
  return crypto_core_hsalsa20(k,_0,s,sigma);
}

// Allow small order elements. Also see https://eprint.iacr.org/2017/806.pdf
int crypto_box_beforenm_unchecked(byte *k,const byte *y,const byte *x)
{
  byte s[32];
  if(crypto_scalarmult(s,x,y) != 0) return -1;
  return crypto_core_hsalsa20(k,_0,s,sigma);
}

int crypto_box_afternm(byte *c,const byte *m,word64 d,const byte *n,const byte *k)
{
  return crypto_secretbox(c,m,d,n,k);
}

int crypto_box_open_afternm(byte *m,const byte *c,word64 d,const byte *n,const byte *k)
{
  return crypto_secretbox_open(m,c,d,n,k);
}

int crypto_box(byte *c, const byte *m, word64 d, const byte *n, const byte *y, const byte *x)
{
  byte k[32];
  if (crypto_box_beforenm(k, y, x) != 0) return -1;
  return crypto_box_afternm(c, m, d, n, k);
}

int crypto_box_unchecked(byte *c, const byte *m, word64 d, const byte *n, const byte *y, const byte *x)
{
  byte k[32];
  crypto_box_beforenm_unchecked(k, y, x);
  return crypto_box_afternm(c, m, d, n, k);
}

int crypto_box_open(byte *m,const byte *c,word64 d,const byte *n,const byte *y,const byte *x)
{
  byte k[32];
  if(crypto_box_beforenm(k,y,x) != 0) return -1;
  return crypto_box_open_afternm(m,c,d,n,k);
}

int crypto_box_open_unchecked(byte *m,const byte *c,word64 d,const byte *n,const byte *y,const byte *x)
{
  byte k[32];
  crypto_box_beforenm_unchecked(k,y,x);
  return crypto_box_open_afternm(m,c,d,n,k);
}

static word64 R(word64 x,int c) { return (x >> c) | (x << (64 - c)); }
static word64 Ch(word64 x,word64 y,word64 z) { return (x & y) ^ (~x & z); }
static word64 Maj(word64 x,word64 y,word64 z) { return (x & y) ^ (x & z) ^ (y & z); }
static word64 Sigma0(word64 x) { return R(x,28) ^ R(x,34) ^ R(x,39); }
static word64 Sigma1(word64 x) { return R(x,14) ^ R(x,18) ^ R(x,41); }
static word64 sigma0(word64 x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
static word64 sigma1(word64 x) { return R(x,19) ^ R(x,61) ^ (x >> 6); }

static const word64 K[80] =
{
  W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd), W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
  W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019), W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
  W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe), W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
  W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1), W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
  W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3), W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
  W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483), W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
  W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210), W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
  W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725), W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
  W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926), W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
  W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8), W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
  W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001), W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
  W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910), W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
  W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53), W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
  W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb), W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
  W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60), W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
  W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9), W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
  W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207), W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
  W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6), W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
  W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493), W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
  W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a), W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
};

int crypto_hashblocks(byte *x,const byte *m,word64 n)
{
  word64 z[8],b[8],a[8],w[16],t;
  int i,j;

  for(i=0; i<8; ++i) z[i] = a[i] = dl64(x + 8 * i);

  while (n >= 128) {
    for(i=0; i<16; ++i) w[i] = dl64(m + 8 * i);

    for(i=0; i<80; ++i) {
      for(j=0; j<8; ++j) b[j] = a[j];
      t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
      b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
      b[3] += t;
      for(j=0; j<8; ++j) a[(j+1)%8] = b[j];
      if (i%16 == 15)
        for(j=0; j<16; ++j)
          w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
    }

    for(i=0; i<8; ++i) { a[i] += z[i]; z[i] = a[i]; }

    m += 128;
    n -= 128;
  }

  for(i=0; i<8; ++i) ts64(x+8*i,z[i]);

  return n;
}

static const byte iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

int crypto_hash(byte *out,const byte *m,word64 n)
{
  byte h[64],x[256];
  word64 i,b = n;

  for(i=0; i<64; ++i) h[i] = iv[i];

  crypto_hashblocks(h,m,n);
  m += n;
  n &= 127;
  m -= n;

  for(i=0; i<256; ++i) x[i] = 0;
  for(i=0; i<n; ++i) x[i] = m[i];
  x[n] = 128;

  n = 256-128*(n<112);
  x[n-9] = b >> 61;
  ts64(x+n-8,b<<3);
  crypto_hashblocks(h,x,n);

  for(i=0; i<64; ++i) out[i] = h[i];

  return 0;
}

static void add(gf p[4],gf q[4])
{
  gf a,b,c,d,t,e,f,g,h;

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

static void cswap(gf p[4],gf q[4],byte b)
{
  int i;
  for(i=0; i<4; ++i)
    sel25519(p[i],q[i],b);
}

static void pack(byte *r,gf p[4])
{
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

static void scalarmult(gf p[4],gf q[4],const byte *s)
{
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    byte b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  }
}

static void scalarbase(gf p[4],const byte *s)
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

int crypto_sign_keypair(byte *pk, byte *sk)
{
  byte d[64];
  gf p[4];
  int i;

  randombytes(sk, 32);
  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p,d);
  pack(pk,p);

  for(i=0; i<32; ++i) sk[32 + i] = pk[i];
  return 0;
}

static const word64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static void modL(byte *r,sword64 x[64])
{
  sword64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= ((word64)carry) << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for(j=0; j<32; ++j) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for(j=0; j<32; ++j) x[j] -= carry * L[j];
  for(i=0; i<32; ++i) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

static void reduce(byte *r)
{
  sword64 x[64],i;
  for(i=0; i<64; ++i) x[i] = (word64) r[i];
  for(i=0; i<64; ++i) r[i] = 0;
  modL(r,x);
}

int crypto_sign(byte *sm,word64 *smlen,const byte *m,word64 n,const byte *sk)
{
  byte d[64],h[64],r[64];
  word64 i; sword64 j,x[64];
  gf p[4];

  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  *smlen = n+64;
  for(i=0; i<n; ++i) sm[64 + i] = m[i];
  for(i=0; i<32; ++i) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm+32, n+32);
  reduce(r);
  scalarbase(p,r);
  pack(sm,p);

  for(i=0; i<32; ++i) sm[i+32] = sk[i+32];
  crypto_hash(h,sm,n + 64);
  reduce(h);

  for(i=0; i<64; ++i) x[i] = 0;
  for(i=0; i<32; ++i) x[i] = (word64) r[i];
  for(i=0; i<32; ++i) for(j=0; j<32; ++j) x[i+j] += h[i] * (word64) d[j];
  modL(sm + 32,x);

  return 0;
}

static int unpackneg(gf r[4],const byte p[32])
{
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
  return 0;
}

int crypto_sign_open(byte *m,word64 *mlen,const byte *sm,word64 n,const byte *pk)
{
  word32 i;
  byte t[32],h[64];
  gf p[4],q[4];

  *mlen = -1;
  if (n < 64) return -1;

  if (unpackneg(q,pk)) return -1;

  for(i=0; i<n; ++i) m[i] = sm[i];
  for(i=0; i<32; ++i) m[i+32] = pk[i];
  crypto_hash(h,m,n);
  reduce(h);
  scalarmult(p,q,h);

  scalarbase(q,sm + 32);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm, t)) {
    for(i=0; i<n; ++i) m[i] = 0;
    return -1;
  }

  for(i=0; i<n; ++i) m[i] = sm[i + 64];
  *mlen = n;
  return 0;
}

NAMESPACE_END  // CryptoPP
NAMESPACE_END  // NaCl

#endif  // NO_OS_DEPENDENCE



