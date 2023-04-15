// lsh.cpp - written and placed in the public domain by Jeffrey Walton
//           Based on the specification and source code provided by
//           Korea Internet & Security Agency (KISA) website. Also
//           see https://seed.kisa.or.kr/kisa/algorithm/EgovLSHInfo.do
//           and https://seed.kisa.or.kr/kisa/Board/22/detailView.do.

// We are hitting some sort of GCC bug in the LSH AVX2 code path.
// Clang is OK on the AVX2 code path. We believe it is GCC Issue
// 82735, https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735. It
// makes using zeroupper a little tricky.

#include "pch.h"
#include "config.h"

#include "lsh.h"
#include "misc.h"

// Squash MS LNK4221 and libtool warnings
extern const char LSH256_AVX_FNAME[] = __FILE__;

#if defined(CRYPTOPP_AVX2_AVAILABLE) && defined(CRYPTOPP_ENABLE_64BIT_SSE)

#if defined(CRYPTOPP_AVX2_AVAILABLE)
# include <emmintrin.h>
# include <immintrin.h>
#endif

#if defined(CRYPTOPP_GCC_COMPATIBLE)
# include <x86intrin.h>
#endif

ANONYMOUS_NAMESPACE_BEGIN

/* LSH Constants */

const unsigned int LSH256_MSG_BLK_BYTE_LEN = 128;
// const unsigned int LSH256_MSG_BLK_BIT_LEN = 1024;
// const unsigned int LSH256_CV_BYTE_LEN = 64;
const unsigned int LSH256_HASH_VAL_MAX_BYTE_LEN = 32;

// const unsigned int MSG_BLK_WORD_LEN = 32;
const unsigned int CV_WORD_LEN = 16;
const unsigned int CONST_WORD_LEN = 8;
// const unsigned int HASH_VAL_MAX_WORD_LEN = 8;
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

/* Error Code */

const unsigned int LSH_SUCCESS = 0x0;
// const unsigned int LSH_ERR_NULL_PTR = 0x2401;
// const unsigned int LSH_ERR_INVALID_ALGTYPE = 0x2402;
const unsigned int LSH_ERR_INVALID_DATABITLEN = 0x2403;
const unsigned int LSH_ERR_INVALID_STATE = 0x2404;

/* Index into our state array */

const unsigned int AlgorithmType = 80;
const unsigned int RemainingBits = 81;

NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(LSH)

// lsh256.cpp
extern const word32 LSH256_IV224[CV_WORD_LEN];
extern const word32 LSH256_IV256[CV_WORD_LEN];
extern const word32 LSH256_StepConstants[CONST_WORD_LEN * NUM_STEPS];

NAMESPACE_END  // LSH
NAMESPACE_END  // Crypto++

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

using CryptoPP::LSH::LSH256_IV224;
using CryptoPP::LSH::LSH256_IV256;
using CryptoPP::LSH::LSH256_StepConstants;

struct LSH256_AVX2_Context
{
	LSH256_AVX2_Context(word32* state, word32 algType, word32& remainingBitLength) :
		cv_l(state+0), cv_r(state+8), sub_msgs(state+16),
		last_block(reinterpret_cast<byte*>(state+48)),
		remain_databitlen(remainingBitLength),
		alg_type(static_cast<lsh_type>(algType)) {}

	lsh_u32* cv_l;  // start of our state block
	lsh_u32* cv_r;
	lsh_u32* sub_msgs;
	lsh_u8*  last_block;
	lsh_u32& remain_databitlen;
	lsh_type alg_type;
};

struct LSH256_AVX2_Internal
{
	LSH256_AVX2_Internal(word32* state) :
		submsg_e_l(state+16), submsg_e_r(state+24),
		submsg_o_l(state+32), submsg_o_r(state+40) { }

	lsh_u32* submsg_e_l; /* even left sub-message  */
	lsh_u32* submsg_e_r; /* even right sub-message */
	lsh_u32* submsg_o_l; /* odd left sub-message   */
	lsh_u32* submsg_o_r; /* odd right sub-message  */
};

// Zero the upper 128 bits of all YMM registers on exit.
// It avoids AVX state transition penalties when saving state.
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735
// makes using zeroupper a little tricky.

struct AVX_Cleanup
{
	~AVX_Cleanup() {
		_mm256_zeroupper();
	}
};

// const word32 g_gamma256[8] = { 0, 8, 16, 24, 24, 16, 8, 0 };

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

inline lsh_u32 loadLE32(lsh_u32 v) {
	return ConditionalByteReverse(LITTLE_ENDIAN_ORDER, v);
}

lsh_u32 ROTL(lsh_u32 x, lsh_u32 r) {
	return rotlFixed(x, r);
}

// Original code relied upon unaligned lsh_u32 buffer
inline void load_msg_blk(LSH256_AVX2_Internal* i_state, const lsh_u8 msgblk[LSH256_MSG_BLK_BYTE_LEN])
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_e_l = i_state->submsg_e_l;
	lsh_u32* submsg_e_r = i_state->submsg_e_r;
	lsh_u32* submsg_o_l = i_state->submsg_o_l;
	lsh_u32* submsg_o_r = i_state->submsg_o_r;

	_mm256_storeu_si256(M256_CAST(submsg_e_l+0),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+0)));
	_mm256_storeu_si256(M256_CAST(submsg_e_r+0),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+32)));
	_mm256_storeu_si256(M256_CAST(submsg_o_l+0),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+64)));
	_mm256_storeu_si256(M256_CAST(submsg_o_r+0),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+96)));
}

inline void msg_exp_even(LSH256_AVX2_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_e_l = i_state->submsg_e_l;
	lsh_u32* submsg_e_r = i_state->submsg_e_r;
	lsh_u32* submsg_o_l = i_state->submsg_o_l;
	lsh_u32* submsg_o_r = i_state->submsg_o_r;

	const __m256i mask = _mm256_set_epi32(0x1b1a1918, 0x17161514,
		0x13121110, 0x1f1e1d1c, 0x07060504, 0x03020100, 0x0b0a0908, 0x0f0e0d0c);

	_mm256_storeu_si256(M256_CAST(submsg_e_l+0), _mm256_add_epi32(
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l+0)),
		_mm256_shuffle_epi8(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l+0)), mask)));
	_mm256_storeu_si256(M256_CAST(submsg_e_r+0), _mm256_add_epi32(
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r+0)),
		_mm256_shuffle_epi8(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r+0)), mask)));
}

inline void msg_exp_odd(LSH256_AVX2_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_e_l = i_state->submsg_e_l;
	lsh_u32* submsg_e_r = i_state->submsg_e_r;
	lsh_u32* submsg_o_l = i_state->submsg_o_l;
	lsh_u32* submsg_o_r = i_state->submsg_o_r;

	const __m256i mask = _mm256_set_epi32(0x1b1a1918, 0x17161514,
		0x13121110, 0x1f1e1d1c, 0x07060504, 0x03020100, 0x0b0a0908, 0x0f0e0d0c);

	_mm256_storeu_si256(M256_CAST(submsg_o_l+0), _mm256_add_epi32(
		_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l+0)),
		_mm256_shuffle_epi8(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l+0)), mask)));
	_mm256_storeu_si256(M256_CAST(submsg_o_r+0), _mm256_add_epi32(
		_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r+0)),
		_mm256_shuffle_epi8(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r+0)), mask)));
}

inline void load_sc(const lsh_u32** p_const_v, size_t i)
{
	CRYPTOPP_ASSERT(p_const_v != NULLPTR);

	*p_const_v = &LSH256_StepConstants[i];
}

inline void msg_add_even(lsh_u32 cv_l[8], lsh_u32 cv_r[8], LSH256_AVX2_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_e_l = i_state->submsg_e_l;
	lsh_u32* submsg_e_r = i_state->submsg_e_r;

	_mm256_storeu_si256(M256_CAST(cv_l+0), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l+0)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l+0))));
	_mm256_storeu_si256(M256_CAST(cv_r+0), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_r+0)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r+0))));
}

inline void msg_add_odd(lsh_u32 cv_l[8], lsh_u32 cv_r[8], LSH256_AVX2_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u32* submsg_o_l = i_state->submsg_o_l;
	lsh_u32* submsg_o_r = i_state->submsg_o_r;

	_mm256_storeu_si256(M256_CAST(cv_l), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l))));
	_mm256_storeu_si256(M256_CAST(cv_r), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_r)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r))));
}

inline void add_blk(lsh_u32 cv_l[8], lsh_u32 cv_r[8])
{
	_mm256_storeu_si256(M256_CAST(cv_l), _mm256_add_epi32(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l)),
		_mm256_loadu_si256(CONST_M256_CAST(cv_r))));
}

template <unsigned int R>
inline void rotate_blk(lsh_u32 cv[8])
{
	_mm256_storeu_si256(M256_CAST(cv), _mm256_or_si256(
		_mm256_slli_epi32(_mm256_loadu_si256(CONST_M256_CAST(cv)), R),
		_mm256_srli_epi32(_mm256_loadu_si256(CONST_M256_CAST(cv)), 32-R)));
}

inline void xor_with_const(lsh_u32 cv_l[8], const lsh_u32 const_v[8])
{
	_mm256_storeu_si256(M256_CAST(cv_l), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l)),
		_mm256_loadu_si256(CONST_M256_CAST(const_v))));
}

inline void rotate_msg_gamma(lsh_u32 cv_r[8])
{
	// g_gamma256[8] = { 0, 8, 16, 24, 24, 16, 8, 0 };
	_mm256_storeu_si256(M256_CAST(cv_r+0),
		_mm256_shuffle_epi8(_mm256_loadu_si256(CONST_M256_CAST(cv_r+0)),
			_mm256_set_epi8(
				/* hi lane */ 15,14,13,12, 10,9,8,11, 5,4,7,6, 0,3,2,1,
				/* lo lane */ 12,15,14,13, 9,8,11,10, 6,5,4,7, 3,2,1,0)));
}

inline void word_perm(lsh_u32 cv_l[8], lsh_u32 cv_r[8])
{
	__m256i temp = _mm256_shuffle_epi32(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l)), _MM_SHUFFLE(3,1,0,2));
	_mm256_storeu_si256(M256_CAST(cv_r),
		_mm256_shuffle_epi32(
			_mm256_loadu_si256(CONST_M256_CAST(cv_r)), _MM_SHUFFLE(1,2,3,0)));
	_mm256_storeu_si256(M256_CAST(cv_l),
		_mm256_permute2x128_si256(temp,
			_mm256_loadu_si256(CONST_M256_CAST(cv_r)), _MM_SHUFFLE(0,3,0,1)));
	_mm256_storeu_si256(M256_CAST(cv_r),
		_mm256_permute2x128_si256(temp,
			_mm256_loadu_si256(CONST_M256_CAST(cv_r)), _MM_SHUFFLE(0,2,0,0)));
}

/* -------------------------------------------------------- *
* step function
* -------------------------------------------------------- */

template <unsigned int Alpha, unsigned int Beta>
inline void mix(lsh_u32 cv_l[8], lsh_u32 cv_r[8], const lsh_u32 const_v[8])
{
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

inline void compress(LSH256_AVX2_Context* ctx, const lsh_u8 pdMsgBlk[LSH256_MSG_BLK_BYTE_LEN])
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	LSH256_AVX2_Internal  s_state(ctx->cv_l);
	LSH256_AVX2_Internal* i_state = &s_state;

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

inline void load_iv(word32 cv_l[8], word32 cv_r[8], const word32 iv[16])
{
	// The IV's are 32-byte aligned so we can use aligned loads.
	_mm256_storeu_si256(M256_CAST(cv_l+0),
		_mm256_load_si256(CONST_M256_CAST(iv+0)));
	_mm256_storeu_si256(M256_CAST(cv_r+0),
		_mm256_load_si256(CONST_M256_CAST(iv+8)));
}

inline void zero_iv(lsh_u32 cv_l[8], lsh_u32 cv_r[8])
{
	_mm256_storeu_si256(M256_CAST(cv_l+0), _mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(cv_r+0), _mm256_setzero_si256());
}

inline void zero_submsgs(LSH256_AVX2_Context* ctx)
{
	lsh_u32* sub_msgs = ctx->sub_msgs;

	_mm256_storeu_si256(M256_CAST(sub_msgs+ 0), _mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(sub_msgs+ 8), _mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(sub_msgs+16), _mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(sub_msgs+24), _mm256_setzero_si256());
}

inline void init224(LSH256_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH256_IV224);
}

inline void init256(LSH256_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH256_IV256);
}

/* -------------------------------------------------------- */

inline void fin(LSH256_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	_mm256_storeu_si256(M256_CAST(ctx->cv_l+0), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(ctx->cv_l+0)),
		_mm256_loadu_si256(CONST_M256_CAST(ctx->cv_r+0))));
}

/* -------------------------------------------------------- */

inline void get_hash(LSH256_AVX2_Context* ctx, lsh_u8* pbHashVal)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(ctx->alg_type != 0);
	CRYPTOPP_ASSERT(pbHashVal != NULLPTR);

	lsh_uint alg_type = ctx->alg_type;
	lsh_uint hash_val_byte_len = LSH_GET_HASHBYTE(alg_type);
	lsh_uint hash_val_bit_len = LSH_GET_SMALL_HASHBIT(alg_type);

	// Multiplying by looks odd...
	std::memcpy(pbHashVal, ctx->cv_l, hash_val_byte_len);
	if (hash_val_bit_len){
		pbHashVal[hash_val_byte_len-1] &= (((lsh_u8)0xff) << hash_val_bit_len);
	}
}

/* -------------------------------------------------------- */

lsh_err lsh256_init_avx2(LSH256_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(ctx->alg_type != 0);

	lsh_u32 alg_type = ctx->alg_type;
	const lsh_u32* const_v = NULL;
	ctx->remain_databitlen = 0;

	// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735.
	AVX_Cleanup cleanup;

	switch (alg_type)
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

	zero_iv(cv_l, cv_r);
	cv_l[0] = LSH256_HASH_VAL_MAX_BYTE_LEN;
	cv_l[1] = LSH_GET_HASHBIT(alg_type);

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

lsh_err lsh256_update_avx2(LSH256_AVX2_Context* ctx, const lsh_u8* data, size_t databitlen)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(data != NULLPTR);
	CRYPTOPP_ASSERT(databitlen % 8 == 0);
	CRYPTOPP_ASSERT(ctx->alg_type != 0);

	// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735.
	AVX_Cleanup cleanup;

	if (databitlen == 0){
		return LSH_SUCCESS;
	}

	// We are byte oriented. tail bits will always be 0.
	size_t databytelen = databitlen >> 3;
	// lsh_uint pos2 = databitlen & 0x7;
	const size_t pos2 = 0;

	size_t remain_msg_byte = ctx->remain_databitlen >> 3;
	// lsh_uint remain_msg_bit = ctx->remain_databitlen & 7;
	const size_t remain_msg_bit = 0;

	if (remain_msg_byte >= LSH256_MSG_BLK_BYTE_LEN){
		return LSH_ERR_INVALID_STATE;
	}
	if (remain_msg_bit > 0){
		return LSH_ERR_INVALID_DATABITLEN;
	}

	if (databytelen + remain_msg_byte < LSH256_MSG_BLK_BYTE_LEN)
	{
		std::memcpy(ctx->last_block + remain_msg_byte, data, databytelen);
		ctx->remain_databitlen += (lsh_uint)databitlen;
		remain_msg_byte += (lsh_uint)databytelen;
		if (pos2){
			ctx->last_block[remain_msg_byte] = data[databytelen] & ((0xff >> pos2) ^ 0xff);
		}
		return LSH_SUCCESS;
	}

	if (remain_msg_byte > 0){
		size_t more_byte = LSH256_MSG_BLK_BYTE_LEN - remain_msg_byte;
		std::memcpy(ctx->last_block + remain_msg_byte, data, more_byte);
		compress(ctx, ctx->last_block);
		data += more_byte;
		databytelen -= more_byte;
		remain_msg_byte = 0;
		ctx->remain_databitlen = 0;
	}

	while (databytelen >= LSH256_MSG_BLK_BYTE_LEN)
	{
		// This call to compress caused some trouble.
		// The data pointer can become unaligned in the
		// previous block.
		compress(ctx, data);
		data += LSH256_MSG_BLK_BYTE_LEN;
		databytelen -= LSH256_MSG_BLK_BYTE_LEN;
	}

	if (databytelen > 0){
		std::memcpy(ctx->last_block, data, databytelen);
		ctx->remain_databitlen = (lsh_uint)(databytelen << 3);
	}

	if (pos2){
		ctx->last_block[databytelen] = data[databytelen] & ((0xff >> pos2) ^ 0xff);
		ctx->remain_databitlen += pos2;
	}

	return LSH_SUCCESS;
}

lsh_err lsh256_final_avx2(LSH256_AVX2_Context* ctx, lsh_u8* hashval)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(hashval != NULLPTR);

	// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735.
	AVX_Cleanup cleanup;

	// We are byte oriented. tail bits will always be 0.
	size_t remain_msg_byte = ctx->remain_databitlen >> 3;
	// lsh_uint remain_msg_bit = ctx->remain_databitlen & 7;
	const size_t remain_msg_bit = 0;

	if (remain_msg_byte >= LSH256_MSG_BLK_BYTE_LEN){
		return LSH_ERR_INVALID_STATE;
	}

	if (remain_msg_bit){
		ctx->last_block[remain_msg_byte] |= (0x1 << (7 - remain_msg_bit));
	}
	else{
		ctx->last_block[remain_msg_byte] = 0x80;
	}
	std::memset(ctx->last_block + remain_msg_byte + 1, 0, LSH256_MSG_BLK_BYTE_LEN - remain_msg_byte - 1);

	compress(ctx, ctx->last_block);

	fin(ctx);
	get_hash(ctx, hashval);

	return LSH_SUCCESS;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

extern
void LSH256_Base_Restart_AVX2(word32* state)
{
	state[RemainingBits] = 0;
	LSH256_AVX2_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh256_init_avx2(&ctx);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH256_Base: lsh256_init_avx2 failed");
}

extern
void LSH256_Base_Update_AVX2(word32* state, const byte *input, size_t size)
{
	LSH256_AVX2_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh256_update_avx2(&ctx, input, 8*size);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH256_Base: lsh256_update_avx2 failed");
}

extern
void LSH256_Base_TruncatedFinal_AVX2(word32* state, byte *hash, size_t)
{
	LSH256_AVX2_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh256_final_avx2(&ctx, hash);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH256_Base: lsh256_final_avx2 failed");
}

NAMESPACE_END

#endif  // CRYPTOPP_AVX2_AVAILABLE
