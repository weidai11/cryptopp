// lsh.cpp - written and placed in the public domain by Jeffrey Walton
//           Based on the specification and source code provided by
//           Korea Internet & Security Agency (KISA) website. Also
//           see https://seed.kisa.or.kr/kisa/algorithm/EgovLSHInfo.do
//           and https://seed.kisa.or.kr/kisa/Board/22/detailView.do.

#include "pch.h"
#include "config.h"

#include "lsh.h"
#include "misc.h"

// Only enable the intrinsics for 64-bit machines
#ifndef CRYPTOPP_DISABLE_ASM
# if defined(__SSE2__) && (defined(__amd64__) || defined(_M_X64))
#  define CRYPTOPP_LSH256_ASM_AVAILABLE 1
# endif
#endif

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
# include <emmintrin.h>
# define M128_CAST(x) ((__m128i *)(void *)(x))
# define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))
#endif

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
# if defined(__XOP__)
#  include <ammintrin.h>
#  if defined(__GNUC__)
#   include <x86intrin.h>
#  endif
# endif
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::rotlFixed;
using CryptoPP::rotlConstant;

using CryptoPP::GetBlock;
using CryptoPP::LittleEndian;
using CryptoPP::ConditionalByteReverse;
using CryptoPP::LITTLE_ENDIAN_ORDER;

typedef byte lsh_u8;
typedef word32 lsh_u32;
typedef word32 lsh_uint;
typedef word32 lsh_err;
typedef word32 lsh_type;

struct LSH256_Context
{
	LSH256_Context(word32* state, word32 algType, word32& remainingBitLength) :
		cv_l(state+0), cv_r(state+8), sub_msgs(state+16),
		last_block(reinterpret_cast<byte*>(state+48)) ,
		remain_databitlen(remainingBitLength), algtype(algType) {}

	lsh_u32* cv_l;  // start of our state block
	lsh_u32* cv_r;
	lsh_u32* sub_msgs;
	lsh_u8*  last_block;
	lsh_u32& remain_databitlen;
	lsh_type algtype;
};

struct LSH256_Internal
{
	LSH256_Internal(word32* state) :
		submsg_e_l(state+16), submsg_e_r(state+24),
		submsg_o_l(state+32), submsg_o_r(state+40) { }

	lsh_u32* submsg_e_l; /* even left sub-message  */
	lsh_u32* submsg_e_r; /* even right sub-message */
	lsh_u32* submsg_o_l; /* odd left sub-message   */
	lsh_u32* submsg_o_r; /* odd right sub-message  */
};

// const unsigned int MSG_BLK_WORD_LEN = 32;
const unsigned int MSG_BLK_BYTE_LEN = 32*4;
const unsigned int CV_WORD_LEN = 16;
const unsigned int CONST_WORD_LEN = 8;
const unsigned int HASH_VAL_MAX_WORD_LEN = 8;
// const unsigned int WORD_BIT_LEN = 32;
const unsigned int NUM_STEPS = 26;

const unsigned int ROT_EVEN_ALPHA = 29;
const unsigned int ROT_EVEN_BETA = 1;
const unsigned int ROT_ODD_ALPHA = 5;
const unsigned int ROT_ODD_BETA = 17;

const unsigned int LSH_TYPE_256_256 = 0x0000020;
const unsigned int LSH_TYPE_256_224 = 0x000001C;

// const unsigned int LSH_TYPE_224 = LSH_TYPE_256_224;
// const unsigned int LSH_TYPE_256 = LSH_TYPE_256_256;

/* LSH AlgType Macro */

inline bool LSH_IS_LSH512(lsh_uint val) {
	return (val & 0xf0000) == 0;
}

inline lsh_uint LSH_GET_SMALL_HASHBIT(lsh_uint val) {
	return val >> 24;
}

inline lsh_uint LSH_GET_HASHBYTE(lsh_uint val) {
	return val & 0xffff;
}

inline lsh_uint LSH_GET_HASHBIT(lsh_uint val) {
	return (LSH_GET_HASHBYTE(val) << 3) - LSH_GET_SMALL_HASHBIT(val);
}

/* LSH Constants */

const unsigned int LSH256_MSG_BLK_BYTE_LEN = 128;
// const unsigned int LSH256_MSG_BLK_BIT_LEN = 1024;
// const unsigned int LSH256_CV_BYTE_LEN = 64;
const unsigned int LSH256_HASH_VAL_MAX_BYTE_LEN = 32;

/* Error Code */

const unsigned int LSH_SUCCESS = 0x0;
// const unsigned int LSH_ERR_NULL_PTR = 0x2401;
// const unsigned int LSH_ERR_INVALID_ALGTYPE = 0x2402;
const unsigned int LSH_ERR_INVALID_DATABITLEN = 0x2403;
const unsigned int LSH_ERR_INVALID_STATE = 0x2404;

inline lsh_u32 loadLE32(lsh_u32 v) {
	return ConditionalByteReverse(LITTLE_ENDIAN_ORDER, v);
}

lsh_u32 ROTL(lsh_u32 x, lsh_u32 r) {
	return rotlFixed(x, r);
}

/* -------------------------------------------------------- *
* LSH: iv
* -------------------------------------------------------- */

#if (CRYPTOPP_CXX11_CONSTEXPR)
# define MAYBE_CONSTEXPR constexpr
#else
# define MAYBE_CONSTEXPR const
#endif

CRYPTOPP_ALIGN_DATA(16)
MAYBE_CONSTEXPR lsh_u32 g_IV224[CV_WORD_LEN] = {
	0x068608D3, 0x62D8F7A7, 0xD76652AB, 0x4C600A43, 0xBDC40AA8, 0x1ECA0B68, 0xDA1A89BE, 0x3147D354,
	0x707EB4F9, 0xF65B3862, 0x6B0B2ABE, 0x56B8EC0A, 0xCF237286, 0xEE0D1727, 0x33636595, 0x8BB8D05F,
};

CRYPTOPP_ALIGN_DATA(16)
MAYBE_CONSTEXPR lsh_u32 g_IV256[CV_WORD_LEN] = {
	0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d, 0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
	0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe, 0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41
};

MAYBE_CONSTEXPR lsh_uint g_gamma256[8] = { 0, 8, 16, 24, 24, 16, 8, 0 };

/* -------------------------------------------------------- *
* LSH: step constants
* -------------------------------------------------------- */

MAYBE_CONSTEXPR lsh_u32 g_StepConstants[CONST_WORD_LEN * NUM_STEPS] = {
	0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243, 0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
	0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612, 0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870,
	0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858, 0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a,
	0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098, 0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5,
	0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898, 0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a,
	0xd2580983, 0x29967709, 0x182df3dd, 0x61916130, 0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351,
	0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191, 0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd,
	0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383, 0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277,
	0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768, 0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32,
	0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1, 0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2,
	0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2, 0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b,
	0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342, 0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06,
	0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601, 0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200,
	0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800, 0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9,
	0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802, 0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c,
	0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d, 0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b,
	0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729, 0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9,
	0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e, 0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32,
	0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6, 0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf,
	0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548, 0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074,
	0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55, 0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520,
	0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b, 0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4,
	0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10, 0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20,
	0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0, 0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a,
	0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f, 0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7,
	0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a, 0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1
};

// Original code relied upon unaligned lsh_u32 buffer
inline void load_msg_blk(LSH256_Internal* i_state, const lsh_u8* msgblk)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);
	CRYPTOPP_ASSERT(msgblk != NULLPTR);

	lsh_u32* submsg_e_l = i_state->submsg_e_l;
	lsh_u32* submsg_e_r = i_state->submsg_e_r;
	lsh_u32* submsg_o_l = i_state->submsg_o_l;
	lsh_u32* submsg_o_r = i_state->submsg_o_r;

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(submsg_e_l+0),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+0)));
	_mm_storeu_si128(M128_CAST(submsg_e_l+4),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+16)));
	_mm_storeu_si128(M128_CAST(submsg_e_r+0),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+32)));
	_mm_storeu_si128(M128_CAST(submsg_e_r+4),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+48)));
	_mm_storeu_si128(M128_CAST(submsg_o_l+0),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+64)));
	_mm_storeu_si128(M128_CAST(submsg_o_l+4),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+80)));
	_mm_storeu_si128(M128_CAST(submsg_o_r+0),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+96)));
	_mm_storeu_si128(M128_CAST(submsg_o_r+4),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+112)));
#else
	typedef GetBlock<word32, LittleEndian, false> InBlock;
	InBlock input(msgblk);

	input(submsg_e_l[0])(submsg_e_l[1])(submsg_e_l[2])(submsg_e_l[3])(submsg_e_l[4])(submsg_e_l[5])(submsg_e_l[6])(submsg_e_l[7])
		(submsg_e_r[0])(submsg_e_r[1])(submsg_e_r[2])(submsg_e_r[3])(submsg_e_r[4])(submsg_e_r[5])(submsg_e_r[6])(submsg_e_r[7])
		(submsg_o_l[0])(submsg_o_l[1])(submsg_o_l[2])(submsg_o_l[3])(submsg_o_l[4])(submsg_o_l[5])(submsg_o_l[6])(submsg_o_l[7])
		(submsg_o_r[0])(submsg_o_r[1])(submsg_o_r[2])(submsg_o_r[3])(submsg_o_r[4])(submsg_o_r[5])(submsg_o_r[6])(submsg_o_r[7]);
#endif
}

inline void msg_exp_even(LSH256_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_e_l = i_state->submsg_e_l;
	lsh_u32* submsg_e_r = i_state->submsg_e_r;
	lsh_u32* submsg_o_l = i_state->submsg_o_l;
	lsh_u32* submsg_o_r = i_state->submsg_o_r;

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(submsg_e_l+0), _mm_add_epi32(
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+0)), _MM_SHUFFLE(3,2,1,0)),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+0)), _MM_SHUFFLE(1,0,2,3))));

	_mm_storeu_si128(M128_CAST(submsg_e_l+4), _mm_add_epi32(
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+4)), _MM_SHUFFLE(3,2,1,0)),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+4)), _MM_SHUFFLE(2,1,0,3))));

	_mm_storeu_si128(M128_CAST(submsg_e_r+0), _mm_add_epi32(
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+0)), _MM_SHUFFLE(3,2,1,0)),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+0)), _MM_SHUFFLE(1,0,2,3))));

	_mm_storeu_si128(M128_CAST(submsg_e_r+4), _mm_add_epi32(
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+4)), _MM_SHUFFLE(3,2,1,0)),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+4)), _MM_SHUFFLE(2,1,0,3))));
#else
	lsh_u32 temp;
	temp = submsg_e_l[0];
	submsg_e_l[0] = submsg_o_l[0] + submsg_e_l[3];
	submsg_e_l[3] = submsg_o_l[3] + submsg_e_l[1];
	submsg_e_l[1] = submsg_o_l[1] + submsg_e_l[2];
	submsg_e_l[2] = submsg_o_l[2] + temp;
	temp = submsg_e_l[4];
	submsg_e_l[4] = submsg_o_l[4] + submsg_e_l[7];
	submsg_e_l[7] = submsg_o_l[7] + submsg_e_l[6];
	submsg_e_l[6] = submsg_o_l[6] + submsg_e_l[5];
	submsg_e_l[5] = submsg_o_l[5] + temp;
	temp = submsg_e_r[0];
	submsg_e_r[0] = submsg_o_r[0] + submsg_e_r[3];
	submsg_e_r[3] = submsg_o_r[3] + submsg_e_r[1];
	submsg_e_r[1] = submsg_o_r[1] + submsg_e_r[2];
	submsg_e_r[2] = submsg_o_r[2] + temp;
	temp = submsg_e_r[4];
	submsg_e_r[4] = submsg_o_r[4] + submsg_e_r[7];
	submsg_e_r[7] = submsg_o_r[7] + submsg_e_r[6];
	submsg_e_r[6] = submsg_o_r[6] + submsg_e_r[5];
	submsg_e_r[5] = submsg_o_r[5] + temp;
#endif
}

inline void msg_exp_odd(LSH256_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_e_l = i_state->submsg_e_l;
	lsh_u32* submsg_e_r = i_state->submsg_e_r;
	lsh_u32* submsg_o_l = i_state->submsg_o_l;
	lsh_u32* submsg_o_r = i_state->submsg_o_r;

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(submsg_o_l+0), _mm_add_epi32(
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+0)), _MM_SHUFFLE(3,2,1,0)),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+0)), _MM_SHUFFLE(1,0,2,3))));

	_mm_storeu_si128(M128_CAST(submsg_o_l+4), _mm_add_epi32(
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+4)), _MM_SHUFFLE(3,2,1,0)),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+4)), _MM_SHUFFLE(2,1,0,3))));

	_mm_storeu_si128(M128_CAST(submsg_o_r+0), _mm_add_epi32(
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+0)), _MM_SHUFFLE(3,2,1,0)),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+0)), _MM_SHUFFLE(1,0,2,3))));

	_mm_storeu_si128(M128_CAST(submsg_o_r+4), _mm_add_epi32(
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+4)), _MM_SHUFFLE(3,2,1,0)),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+4)), _MM_SHUFFLE(2,1,0,3))));
#else
	lsh_u32 temp;
	temp = submsg_o_l[0];
	submsg_o_l[0] = submsg_e_l[0] + submsg_o_l[3];
	submsg_o_l[3] = submsg_e_l[3] + submsg_o_l[1];
	submsg_o_l[1] = submsg_e_l[1] + submsg_o_l[2];
	submsg_o_l[2] = submsg_e_l[2] + temp;
	temp = submsg_o_l[4];
	submsg_o_l[4] = submsg_e_l[4] + submsg_o_l[7];
	submsg_o_l[7] = submsg_e_l[7] + submsg_o_l[6];
	submsg_o_l[6] = submsg_e_l[6] + submsg_o_l[5];
	submsg_o_l[5] = submsg_e_l[5] + temp;
	temp = submsg_o_r[0];
	submsg_o_r[0] = submsg_e_r[0] + submsg_o_r[3];
	submsg_o_r[3] = submsg_e_r[3] + submsg_o_r[1];
	submsg_o_r[1] = submsg_e_r[1] + submsg_o_r[2];
	submsg_o_r[2] = submsg_e_r[2] + temp;
	temp = submsg_o_r[4];
	submsg_o_r[4] = submsg_e_r[4] + submsg_o_r[7];
	submsg_o_r[7] = submsg_e_r[7] + submsg_o_r[6];
	submsg_o_r[6] = submsg_e_r[6] + submsg_o_r[5];
	submsg_o_r[5] = submsg_e_r[5] + temp;
#endif
}

inline void load_sc(const lsh_u32** p_const_v, size_t i)
{
	CRYPTOPP_ASSERT(p_const_v != NULLPTR);

	*p_const_v = &g_StepConstants[i];
}

inline void msg_add_even(lsh_u32* cv_l, lsh_u32* cv_r, LSH256_Internal* i_state)
{
	CRYPTOPP_ASSERT(cv_l != NULLPTR);
	CRYPTOPP_ASSERT(cv_r != NULLPTR);
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_e_l = i_state->submsg_e_l;
	lsh_u32* submsg_e_r = i_state->submsg_e_r;

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(cv_l), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l))));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+4))));
	_mm_storeu_si128(M128_CAST(cv_r), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r))));
	_mm_storeu_si128(M128_CAST(cv_r+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+4)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+4))));
#else
	cv_l[0] ^= submsg_e_l[0];  cv_l[1] ^= submsg_e_l[1];
	cv_l[2] ^= submsg_e_l[2];  cv_l[3] ^= submsg_e_l[3];
	cv_l[4] ^= submsg_e_l[4];  cv_l[5] ^= submsg_e_l[5];
	cv_l[6] ^= submsg_e_l[6];  cv_l[7] ^= submsg_e_l[7];
	cv_r[0] ^= submsg_e_r[0];  cv_r[1] ^= submsg_e_r[1];
	cv_r[2] ^= submsg_e_r[2];  cv_r[3] ^= submsg_e_r[3];
	cv_r[4] ^= submsg_e_r[4];  cv_r[5] ^= submsg_e_r[5];
	cv_r[6] ^= submsg_e_r[6];  cv_r[7] ^= submsg_e_r[7];
#endif
}

inline void msg_add_odd(lsh_u32* cv_l, lsh_u32* cv_r, LSH256_Internal* i_state)
{
	CRYPTOPP_ASSERT(cv_l != NULLPTR);
	CRYPTOPP_ASSERT(cv_r != NULLPTR);
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_o_l = i_state->submsg_o_l;
	lsh_u32* submsg_o_r = i_state->submsg_o_r;

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(cv_l), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l))));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+4))));
	_mm_storeu_si128(M128_CAST(cv_r), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r))));
	_mm_storeu_si128(M128_CAST(cv_r+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+4)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+4))));
#else
	cv_l[0] ^= submsg_o_l[0];  cv_l[1] ^= submsg_o_l[1];
	cv_l[2] ^= submsg_o_l[2];  cv_l[3] ^= submsg_o_l[3];
	cv_l[4] ^= submsg_o_l[4];  cv_l[5] ^= submsg_o_l[5];
	cv_l[6] ^= submsg_o_l[6];  cv_l[7] ^= submsg_o_l[7];
	cv_r[0] ^= submsg_o_r[0];  cv_r[1] ^= submsg_o_r[1];
	cv_r[2] ^= submsg_o_r[2];  cv_r[3] ^= submsg_o_r[3];
	cv_r[4] ^= submsg_o_r[4];  cv_r[5] ^= submsg_o_r[5];
	cv_r[6] ^= submsg_o_r[6];  cv_r[7] ^= submsg_o_r[7];
#endif
}

inline void add_blk(lsh_u32* cv_l, const lsh_u32* cv_r)
{
	CRYPTOPP_ASSERT(cv_l != NULLPTR);
	CRYPTOPP_ASSERT(cv_r != NULLPTR);

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(cv_l), _mm_add_epi32(
		_mm_loadu_si128(CONST_M128_CAST(cv_l)),
		_mm_loadu_si128(CONST_M128_CAST(cv_r))));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_add_epi32(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(cv_r+4))));
#else
	cv_l[0] += cv_r[0];
	cv_l[1] += cv_r[1];
	cv_l[2] += cv_r[2];
	cv_l[3] += cv_r[3];
	cv_l[4] += cv_r[4];
	cv_l[5] += cv_r[5];
	cv_l[6] += cv_r[6];
	cv_l[7] += cv_r[7];
#endif
}

template <unsigned int R>
inline void rotate_blk(lsh_u32 cv[8])
{
	CRYPTOPP_ASSERT(cv != NULLPTR);

#if defined(__XOP__)
	_mm_storeu_si128(M128_CAST(cv),
		_mm_roti_epi32(_mm_loadu_si128(CONST_M128_CAST(cv)), R));
	_mm_storeu_si128(M128_CAST(cv+4),
		_mm_roti_epi32(_mm_loadu_si128(CONST_M128_CAST(cv+4)), R));
#elif defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(cv), _mm_or_si128(
		_mm_slli_epi32(_mm_loadu_si128(CONST_M128_CAST(cv)), R),
		_mm_srli_epi32(_mm_loadu_si128(CONST_M128_CAST(cv)), 32-R)));
	_mm_storeu_si128(M128_CAST(cv+4), _mm_or_si128(
		_mm_slli_epi32(_mm_loadu_si128(CONST_M128_CAST(cv+4)), R),
		_mm_srli_epi32(_mm_loadu_si128(CONST_M128_CAST(cv+4)), 32-R)));
#else
	cv[0] = rotlConstant<R>(cv[0]);
	cv[1] = rotlConstant<R>(cv[1]);
	cv[2] = rotlConstant<R>(cv[2]);
	cv[3] = rotlConstant<R>(cv[3]);
	cv[4] = rotlConstant<R>(cv[4]);
	cv[5] = rotlConstant<R>(cv[5]);
	cv[6] = rotlConstant<R>(cv[6]);
	cv[7] = rotlConstant<R>(cv[7]);
#endif
}

inline void xor_with_const(lsh_u32* cv_l, const lsh_u32* const_v)
{
	CRYPTOPP_ASSERT(cv_l != NULLPTR);
	CRYPTOPP_ASSERT(const_v != NULLPTR);

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(cv_l), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l)),
		_mm_loadu_si128(CONST_M128_CAST(const_v))));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(const_v+4))));
#else
	cv_l[0] ^= const_v[0];
	cv_l[1] ^= const_v[1];
	cv_l[2] ^= const_v[2];
	cv_l[3] ^= const_v[3];
	cv_l[4] ^= const_v[4];
	cv_l[5] ^= const_v[5];
	cv_l[6] ^= const_v[6];
	cv_l[7] ^= const_v[7];
#endif
}

inline void rotate_msg_gamma(lsh_u32* cv_r)
{
	CRYPTOPP_ASSERT(cv_r != NULLPTR);

	cv_r[1] = rotlFixed(cv_r[1], g_gamma256[1]);
	cv_r[2] = rotlFixed(cv_r[2], g_gamma256[2]);
	cv_r[3] = rotlFixed(cv_r[3], g_gamma256[3]);
	cv_r[4] = rotlFixed(cv_r[4], g_gamma256[4]);
	cv_r[5] = rotlFixed(cv_r[5], g_gamma256[5]);
	cv_r[6] = rotlFixed(cv_r[6], g_gamma256[6]);
}

inline void word_perm(lsh_u32* cv_l, lsh_u32* cv_r)
{
	CRYPTOPP_ASSERT(cv_l != NULLPTR);
	CRYPTOPP_ASSERT(cv_r != NULLPTR);

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(cv_l+0), _mm_shuffle_epi32(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+0)), _MM_SHUFFLE(3,1,0,2)));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_shuffle_epi32(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)), _MM_SHUFFLE(3,1,0,2)));
	_mm_storeu_si128(M128_CAST(cv_r+0), _mm_shuffle_epi32(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+0)), _MM_SHUFFLE(1,2,3,0)));
	_mm_storeu_si128(M128_CAST(cv_r+4), _mm_shuffle_epi32(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+4)), _MM_SHUFFLE(1,2,3,0)));

	__m128i cv_l_temp = _mm_loadu_si128(CONST_M128_CAST(cv_l+0));
	_mm_storeu_si128(M128_CAST(cv_l+0), _mm_loadu_si128(CONST_M128_CAST(cv_l+4)));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_loadu_si128(CONST_M128_CAST(cv_r+4)));
	_mm_storeu_si128(M128_CAST(cv_r+4), _mm_loadu_si128(CONST_M128_CAST(cv_r+0)));
	_mm_storeu_si128(M128_CAST(cv_r+0), cv_l_temp);
#else
	lsh_u32 temp;
	temp = cv_l[0];
	cv_l[0] = cv_l[6];
	cv_l[6] = cv_r[6];
	cv_r[6] = cv_r[2];
	cv_r[2] = cv_l[1];
	cv_l[1] = cv_l[4];
	cv_l[4] = cv_r[4];
	cv_r[4] = cv_r[0];
	cv_r[0] = cv_l[2];
	cv_l[2] = cv_l[5];
	cv_l[5] = cv_r[7];
	cv_r[7] = cv_r[1];
	cv_r[1] = temp;
	temp = cv_l[3];
	cv_l[3] = cv_l[7];
	cv_l[7] = cv_r[5];
	cv_r[5] = cv_r[3];
	cv_r[3] = temp;
#endif
};

/* -------------------------------------------------------- *
* step function
* -------------------------------------------------------- */

template <unsigned int Alpha, unsigned int Beta>
inline void mix(lsh_u32* cv_l, lsh_u32* cv_r, const lsh_u32* const_v)
{
	CRYPTOPP_ASSERT(cv_l != NULLPTR);
	CRYPTOPP_ASSERT(cv_r != NULLPTR);
	CRYPTOPP_ASSERT(const_v != NULLPTR);

	add_blk(cv_l, cv_r);
	rotate_blk<Alpha>(cv_l);
	xor_with_const(cv_l, const_v);
	add_blk(cv_r, cv_l);
	rotate_blk<Beta>(cv_r);
	add_blk(cv_l, cv_r);
	rotate_msg_gamma(cv_r);
}

/* -------------------------------------------------------- *
* compression function
* -------------------------------------------------------- */

inline void compress(LSH256_Context* ctx, const lsh_u8 pdMsgBlk[MSG_BLK_BYTE_LEN])
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	LSH256_Internal  s_state(ctx->cv_l);
	LSH256_Internal* i_state = &s_state;

	const lsh_u32* const_v = NULL;
	lsh_u32* cv_l = ctx->cv_l;
	lsh_u32* cv_r = ctx->cv_r;

	load_msg_blk(i_state, pdMsgBlk);

	msg_add_even(cv_l, cv_r, i_state);
	load_sc(&const_v, 0);
	mix<ROT_EVEN_ALPHA, ROT_EVEN_BETA>(cv_l, cv_r, const_v);
	word_perm(cv_l, cv_r);

	msg_add_odd(cv_l, cv_r, i_state);
	load_sc(&const_v, 8);
	mix<ROT_ODD_ALPHA, ROT_ODD_BETA>(cv_l, cv_r, const_v);
	word_perm(cv_l, cv_r);

	for (size_t i = 1; i < NUM_STEPS / 2; i++)
	{
		msg_exp_even(i_state);
		msg_add_even(cv_l, cv_r, i_state);
		load_sc(&const_v, 16 * i);
		mix<ROT_EVEN_ALPHA, ROT_EVEN_BETA>(cv_l, cv_r, const_v);
		word_perm(cv_l, cv_r);

		msg_exp_odd(i_state);
		msg_add_odd(cv_l, cv_r, i_state);
		load_sc(&const_v, 16 * i + 8);
		mix<ROT_ODD_ALPHA, ROT_ODD_BETA>(cv_l, cv_r, const_v);
		word_perm(cv_l, cv_r);
	}

	msg_exp_even(i_state);
	msg_add_even(cv_l, cv_r, i_state);
}

/* -------------------------------------------------------- */

inline void load_iv(word32* cv_l, word32* cv_r, const word32* iv)
{
#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	// The IV's are aligned so we can use _mm_load_si128.
	_mm_storeu_si128(M128_CAST(cv_l+ 0), _mm_load_si128(CONST_M128_CAST(iv+ 0)));
	_mm_storeu_si128(M128_CAST(cv_l+ 4), _mm_load_si128(CONST_M128_CAST(iv+ 4)));
	_mm_storeu_si128(M128_CAST(cv_r+ 0), _mm_load_si128(CONST_M128_CAST(iv+ 8)));
	_mm_storeu_si128(M128_CAST(cv_r+ 4), _mm_load_si128(CONST_M128_CAST(iv+12)));
#else
	cv_l[0] = iv[0];
	cv_l[1] = iv[1];
	cv_l[2] = iv[2];
	cv_l[3] = iv[3];
	cv_l[4] = iv[4];
	cv_l[5] = iv[5];
	cv_l[6] = iv[6];
	cv_l[7] = iv[7];
	cv_r[0] = iv[8];
	cv_r[1] = iv[9];
	cv_r[2] = iv[10];
	cv_r[3] = iv[11];
	cv_r[4] = iv[12];
	cv_r[5] = iv[13];
	cv_r[6] = iv[14];
	cv_r[7] = iv[15];
#endif
}

inline void init224(LSH256_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	load_iv(ctx->cv_l, ctx->cv_r, g_IV224);
	memset(ctx->sub_msgs, 0x00, 32*sizeof(lsh_u32));
}

inline void init256(LSH256_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	load_iv(ctx->cv_l, ctx->cv_r, g_IV256);
	memset(ctx->sub_msgs, 0x00, 32*sizeof(lsh_u32));
}

/* -------------------------------------------------------- */

inline void fin(LSH256_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	_mm_storeu_si128(M128_CAST(ctx->cv_l+0), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(ctx->cv_l+0)),
		_mm_loadu_si128(CONST_M128_CAST(ctx->cv_r+0))));
	_mm_storeu_si128(M128_CAST(ctx->cv_l+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(ctx->cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(ctx->cv_r+4))));
#else
	for (size_t i = 0; i < HASH_VAL_MAX_WORD_LEN; i++){
		ctx->cv_l[i] = loadLE32(ctx->cv_l[i] ^ ctx->cv_r[i]);
	}
#endif
}

/* -------------------------------------------------------- */

inline void get_hash(LSH256_Context* ctx, lsh_u8* pbHashVal)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(ctx->algtype != 0);
	CRYPTOPP_ASSERT(pbHashVal != NULLPTR);

	lsh_uint algtype = ctx->algtype;
	lsh_uint hash_val_byte_len = LSH_GET_HASHBYTE(algtype);
	lsh_uint hash_val_bit_len = LSH_GET_SMALL_HASHBIT(algtype);

	// Multiplying by sizeof(lsh_u8) looks odd...
	memcpy(pbHashVal, ctx->cv_l, sizeof(lsh_u8) * hash_val_byte_len);
	if (hash_val_bit_len){
		pbHashVal[hash_val_byte_len-1] &= (((lsh_u8)0xff) << hash_val_bit_len);
	}
}

/* -------------------------------------------------------- */

lsh_err lsh256_init(LSH256_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(ctx->algtype != 0);

	lsh_u32 algtype = ctx->algtype;
	const lsh_u32* const_v = NULL;

	ctx->remain_databitlen = 0;

	switch (algtype)
	{
	case LSH_TYPE_256_256:
		init256(ctx);
		return LSH_SUCCESS;
	case LSH_TYPE_256_224:
		init224(ctx);
		return LSH_SUCCESS;
	default:
		break;
	}

	lsh_u32* cv_l = ctx->cv_l;
	lsh_u32* cv_r = ctx->cv_r;

	memset(ctx->cv_l, 0, 8 * sizeof(lsh_u32));
	memset(ctx->cv_r, 0, 8 * sizeof(lsh_u32));

	ctx->cv_l[0] = LSH256_HASH_VAL_MAX_BYTE_LEN;
	ctx->cv_l[1] = LSH_GET_HASHBIT(algtype);

	for (size_t i = 0; i < NUM_STEPS / 2; i++)
	{
		//Mix
		load_sc(&const_v, i * 16);
		mix<ROT_EVEN_ALPHA, ROT_EVEN_BETA>(cv_l, cv_r, const_v);
		word_perm(cv_l, cv_r);

		load_sc(&const_v, i * 16 + 8);
		mix<ROT_ODD_ALPHA, ROT_ODD_BETA>(cv_l, cv_r, const_v);
		word_perm(cv_l, cv_r);
	}

	return LSH_SUCCESS;
}

lsh_err lsh256_update(LSH256_Context* ctx, const lsh_u8* data, size_t databitlen)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(data != NULLPTR);
	CRYPTOPP_ASSERT(databitlen % 8 == 0);
	CRYPTOPP_ASSERT(ctx->algtype != 0);

	if (databitlen == 0){
		return LSH_SUCCESS;
	}

	size_t databytelen = databitlen >> 3;
	lsh_uint pos2 = databitlen & 0x7;

	// We are byte oriented. remain_msg_bit will always be 0.
	lsh_uint remain_msg_byte = ctx->remain_databitlen >> 3;
	// lsh_uint remain_msg_bit = ctx->remain_databitlen & 7;
	lsh_uint remain_msg_bit = 0;

	if (remain_msg_byte >= LSH256_MSG_BLK_BYTE_LEN){
		return LSH_ERR_INVALID_STATE;
	}
	if (remain_msg_bit > 0){
		return LSH_ERR_INVALID_DATABITLEN;
	}

	if (databytelen + remain_msg_byte < LSH256_MSG_BLK_BYTE_LEN)
	{
		memcpy(ctx->last_block + remain_msg_byte, data, databytelen);
		ctx->remain_databitlen += (lsh_uint)databitlen;
		remain_msg_byte += (lsh_uint)databytelen;
		if (pos2){
			ctx->last_block[remain_msg_byte] = data[databytelen] & ((0xff >> pos2) ^ 0xff);
		}
		return LSH_SUCCESS;
	}

	if (remain_msg_byte > 0){
		lsh_uint more_byte = LSH256_MSG_BLK_BYTE_LEN - remain_msg_byte;
		memcpy(ctx->last_block + remain_msg_byte, data, more_byte);
		compress(ctx, ctx->last_block);
		data += more_byte;
		databytelen -= more_byte;
		remain_msg_byte = 0;
		ctx->remain_databitlen = 0;
	}

	while (databytelen >= LSH256_MSG_BLK_BYTE_LEN)
	{
		compress(ctx, data);
		data += LSH256_MSG_BLK_BYTE_LEN;
		databytelen -= LSH256_MSG_BLK_BYTE_LEN;
	}

	if (databytelen > 0){
		memcpy(ctx->last_block, data, databytelen);
		ctx->remain_databitlen = (lsh_uint)(databytelen << 3);
	}

	if (pos2){
		ctx->last_block[databytelen] = data[databytelen] & ((0xff >> pos2) ^ 0xff);
		ctx->remain_databitlen += pos2;
	}

	return LSH_SUCCESS;
}

lsh_err lsh256_final(LSH256_Context* ctx, lsh_u8* hashval)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(hashval != NULLPTR);

	// We are byte oriented. remain_msg_bit will always be 0.
	lsh_uint remain_msg_byte = ctx->remain_databitlen >> 3;
	// lsh_uint remain_msg_bit = ctx->remain_databitlen & 7;
	lsh_uint remain_msg_bit = 0;

	if (remain_msg_byte >= LSH256_MSG_BLK_BYTE_LEN){
		return LSH_ERR_INVALID_STATE;
	}

	if (remain_msg_bit){
		ctx->last_block[remain_msg_byte] |= (0x1 << (7 - remain_msg_bit));
	}
	else{
		ctx->last_block[remain_msg_byte] = 0x80;
	}
	memset(ctx->last_block + remain_msg_byte + 1, 0, LSH256_MSG_BLK_BYTE_LEN - remain_msg_byte - 1);

	compress(ctx, ctx->last_block);

	fin(ctx);
	get_hash(ctx, hashval);

	return LSH_SUCCESS;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

std::string LSH256_Base::AlgorithmProvider() const
{
#if defined(CRYPTOPP_LSH256_ASM_AVAILABLE)
	return "SSE2";
#else
	return "C++";
#endif
}

void LSH256_Base::Restart()
{
	LSH256_Context ctx(m_state, m_algType, m_remainingBitLength);
	lsh_err err = lsh256_init(&ctx);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH256_Base: lsh256_init failed");
}

void LSH256_Base::Update(const byte *input, size_t length)
{
	CRYPTOPP_ASSERT(input != NULLPTR);
	CRYPTOPP_ASSERT(length);

	LSH256_Context ctx(m_state, m_algType, m_remainingBitLength);
	lsh_err err = lsh256_update(&ctx, input, 8*length);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH256_Base: lsh256_update failed");
}

void LSH256_Base::TruncatedFinal(byte *hash, size_t size)
{
	CRYPTOPP_ASSERT(hash != NULLPTR);
	ThrowIfInvalidTruncatedSize(size);

	LSH256_Context ctx(m_state, m_algType, m_remainingBitLength);
	lsh_err err;

	if (size >= DigestSize())
	{
		err = lsh256_final(&ctx, hash);
	}
	else
	{
		// TODO: determine if LSH256 supports truncated hashes. See the code in get_hash(),
		// where a bit-length is added to the last output byte of the hash function.
		// CRYPTOPP_ASSERT(0);

		byte fullHash[HASH_VAL_MAX_WORD_LEN * sizeof(lsh_u32)];
		err = lsh256_final(&ctx, fullHash);
		memcpy(hash, fullHash, size);
	}

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH256_Base: lsh256_final failed");

    Restart();
}

NAMESPACE_END
