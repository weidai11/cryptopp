// lsh.cpp - written and placed in the public domain by Jeffrey Walton
//           Based on the specification and source code provided by
//           Korea Internet & Security Agency (KISA) website. Also
//           see https://seed.kisa.or.kr/kisa/algorithm/EgovLSHInfo.do
//           and https://seed.kisa.or.kr/kisa/Board/22/detailView.do.

// The source file below uses GCC's function multiversioning to
// speed up a rotate when SSE is available. When the rotate is
// performed with the SSE unit there's a 2.5 to 3.0 cpb profit.
// When AVX is available multiversioning is not used.

// Function multiversioning does not work with GCC 4.8 through 7.5.
// We have lots of failed compiles on test machines and Travis.
// It appears to work as expected around GCC 8 or GCC 9.

// Function multiversioning does not work with Clang. Enabling it for
// LLVM Clang 7.0 and above resulted in linker errors. We think it
// will work with Clang 13.0 and above due to Issue 50025. Also see
// https://bugs.llvm.org/show_bug.cgi?id=50025.

// We are hitting some sort of GCC bug in the LSH AVX2 code path.
// Clang is OK on the AVX2 code path. We believe it is GCC Issue
// 82735, https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735. We
// have to use SSE2 until GCC provides a workaround or fix. Also
// see CRYPTOPP_WORKAROUND_GCC_AVX_ZEROUPPER_BUG below.

#include "pch.h"
#include "config.h"

#if defined(CRYPTOPP_AVX2_AVAILABLE)

#include "lsh.h"
#include "misc.h"

#if defined(CRYPTOPP_SSE2_INTRIN_AVAILABLE)
# include <emmintrin.h>
#endif

#if defined(CRYPTOPP_AVX2_AVAILABLE)
# include <immintrin.h>
#endif

#if defined(__GNUC__) && defined(__amd64__)
# include <x86intrin.h>
#endif

ANONYMOUS_NAMESPACE_BEGIN

/* LSH Constants */

const unsigned int LSH512_MSG_BLK_BYTE_LEN = 256;
// const unsigned int LSH512_MSG_BLK_BIT_LEN = 2048;
// const unsigned int LSH512_CV_BYTE_LEN = 128;
const unsigned int LSH512_HASH_VAL_MAX_BYTE_LEN = 64;

// const unsigned int MSG_BLK_WORD_LEN = 32;
const unsigned int CV_WORD_LEN = 16;
const unsigned int CONST_WORD_LEN = 8;
const unsigned int HASH_VAL_MAX_WORD_LEN = 8;
const unsigned int NUM_STEPS = 28;

const unsigned int ROT_EVEN_ALPHA = 23;
const unsigned int ROT_EVEN_BETA = 59;
const unsigned int ROT_ODD_ALPHA = 7;
const unsigned int ROT_ODD_BETA = 3;

const unsigned int LSH_TYPE_512_512 = 0x0010040;
const unsigned int LSH_TYPE_512_384 = 0x0010030;
const unsigned int LSH_TYPE_512_256 = 0x0010020;
const unsigned int LSH_TYPE_512_224 = 0x001001C;

// const unsigned int LSH_TYPE_384 = LSH_TYPE_512_384;
// const unsigned int LSH_TYPE_512 = LSH_TYPE_512_512;

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

// lsh512.cpp
extern const word64 LSH512_IV224[CV_WORD_LEN];
extern const word64 LSH512_IV256[CV_WORD_LEN];
extern const word64 LSH512_IV384[CV_WORD_LEN];
extern const word64 LSH512_IV512[CV_WORD_LEN];
extern const word64 LSH512_StepConstants[CONST_WORD_LEN * NUM_STEPS];

NAMESPACE_END  // LSH
NAMESPACE_END  // Crypto++

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlFixed;
using CryptoPP::rotlConstant;

using CryptoPP::GetBlock;
using CryptoPP::LittleEndian;
using CryptoPP::ConditionalByteReverse;
using CryptoPP::LITTLE_ENDIAN_ORDER;

using CryptoPP::LSH::LSH512_IV224;
using CryptoPP::LSH::LSH512_IV256;
using CryptoPP::LSH::LSH512_IV384;
using CryptoPP::LSH::LSH512_IV512;
using CryptoPP::LSH::LSH512_StepConstants;

typedef byte lsh_u8;
typedef word32 lsh_u32;
typedef word64 lsh_u64;
typedef word32 lsh_uint;
typedef word32 lsh_err;
typedef word32 lsh_type;

struct LSH512_AVX2_Context
{
	LSH512_AVX2_Context(word64* state, word32 algType, word64& remainingBitLength) :
		cv_l(state+0), cv_r(state+8), sub_msgs(state+16),
		last_block(reinterpret_cast<byte*>(state+48)) ,
		remain_databitlen(remainingBitLength), algtype(algType) {}

	lsh_u64* cv_l;  // start of our state block
	lsh_u64* cv_r;
	lsh_u64* sub_msgs;
	lsh_u8*  last_block;
	lsh_u64& remain_databitlen;
	lsh_type algtype;
};

struct LSH512_AVX2_Internal
{
	LSH512_AVX2_Internal(word64* state) :
		submsg_e_l(state+16), submsg_e_r(state+24),
		submsg_o_l(state+32), submsg_o_r(state+40) { }

	lsh_u64* submsg_e_l; /* even left sub-message  */
	lsh_u64* submsg_e_r; /* even right sub-message */
	lsh_u64* submsg_o_l; /* odd left sub-message   */
	lsh_u64* submsg_o_r; /* odd right sub-message  */
};

// Zero the upper 128 bits of all YMM registers on exit.
// It avoids AVX state transition penalties when saving state.
// There are two flavors due to GCC bug 82735. AVX_Cleanup
// is fine grained, and can be used near a group of small
// inline functions to keep the cleanup close to the AVX code,
// like mix_avx2() and rotate_avx2(). AVX_BuggyCleanup is
// coarse grained and is used at the end of a large function
// block, like Update() or Final().
struct AVX_Cleanup
{
#ifndef CRYPTOPP_WORKAROUND_GCC_AVX_ZEROUPPER_BUG
	~AVX_Cleanup() {
		_mm256_zeroupper();
	}
#endif
};

struct AVX_BuggyCleanup
{
#ifdef CRYPTOPP_WORKAROUND_GCC_AVX_ZEROUPPER_BUG
	~AVX_BuggyCleanup() {
		_mm256_zeroupper();
	}
#endif
};

// const lsh_u32 g_gamma512[8] = { 0, 16, 32, 48, 8, 24, 40, 56 };

/* LSH AlgType Macro */

inline bool LSH_IS_LSH512(lsh_uint val) {
	return (val & 0xf0000) == 0x10000;
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

inline lsh_u64 loadLE64(lsh_u64 v) {
	return ConditionalByteReverse(LITTLE_ENDIAN_ORDER, v);
}

lsh_u64 ROTL64(lsh_u64 x, lsh_u32 r) {
	return rotlFixed(x, r);
}

// Original code relied upon unaligned lsh_u64 buffer
inline void load_msg_blk(LSH512_AVX2_Internal* i_state, const lsh_u8 msgblk[LSH512_MSG_BLK_BYTE_LEN])
{
	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;
	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

	_mm256_storeu_si256(M256_CAST(submsg_e_l+0),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+0)));
	_mm256_storeu_si256(M256_CAST(submsg_e_l+4),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+32)));

	_mm256_storeu_si256(M256_CAST(submsg_e_r+0),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+64)));
	_mm256_storeu_si256(M256_CAST(submsg_e_r+4),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+96)));

	_mm256_storeu_si256(M256_CAST(submsg_o_l+0),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+128)));
	_mm256_storeu_si256(M256_CAST(submsg_o_l+4),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+160)));

	_mm256_storeu_si256(M256_CAST(submsg_o_r+0),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+192)));
	_mm256_storeu_si256(M256_CAST(submsg_o_r+4),
		_mm256_loadu_si256(CONST_M256_CAST(msgblk+224)));
}

inline void msg_exp_even(LSH512_AVX2_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;
	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

	_mm256_storeu_si256(M256_CAST(submsg_e_l+0), _mm256_add_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l+0)),
		_mm256_permute4x64_epi64(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l+0)),
			_MM_SHUFFLE(1,0,2,3))));
	_mm256_storeu_si256(M256_CAST(submsg_e_l+4), _mm256_add_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l+4)),
		_mm256_permute4x64_epi64(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l+4)),
			_MM_SHUFFLE(2,1,0,3))));

	_mm256_storeu_si256(M256_CAST(submsg_e_r+0), _mm256_add_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r+0)),
		_mm256_permute4x64_epi64(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r+0)),
			_MM_SHUFFLE(1,0,2,3))));
	_mm256_storeu_si256(M256_CAST(submsg_e_r+4), _mm256_add_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r+4)),
		_mm256_permute4x64_epi64(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r+4)),
			_MM_SHUFFLE(2,1,0,3))));
}

inline void msg_exp_odd(LSH512_AVX2_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;
	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

	_mm256_storeu_si256(M256_CAST(submsg_o_l+0),
		_mm256_add_epi64(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l+0)),
			_mm256_permute4x64_epi64(
				_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l+0)),
				_MM_SHUFFLE(1,0,2,3))));
	_mm256_storeu_si256(M256_CAST(submsg_o_l+4),
		_mm256_add_epi64(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l+4)),
			_mm256_permute4x64_epi64(
				_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l+4)),
				_MM_SHUFFLE(2,1,0,3))));

	_mm256_storeu_si256(M256_CAST(submsg_o_r+0),
		_mm256_add_epi64(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r+0)),
			_mm256_permute4x64_epi64(
				_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r+0)),
				_MM_SHUFFLE(1,0,2,3))));
	_mm256_storeu_si256(M256_CAST(submsg_o_r+4),
		_mm256_add_epi64(
			_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r+4)),
			_mm256_permute4x64_epi64(
				_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r+4)),
				_MM_SHUFFLE(2,1,0,3))));
}

inline void load_sc(const lsh_u64** p_const_v, size_t i)
{
	*p_const_v = &LSH512_StepConstants[i];
}

inline void msg_add_even(lsh_u64 cv_l[8], lsh_u64 cv_r[8], LSH512_AVX2_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;

	_mm256_storeu_si256(M256_CAST(cv_l), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l))));
	_mm256_storeu_si256(M256_CAST(cv_r), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_r)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r))));

	_mm256_storeu_si256(M256_CAST(cv_l+4), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l+4)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_e_l+4))));
	_mm256_storeu_si256(M256_CAST(cv_r+4), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_r+4)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_e_r+4))));
}

inline void msg_add_odd(lsh_u64 cv_l[8], lsh_u64 cv_r[8], LSH512_AVX2_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

	_mm256_storeu_si256(M256_CAST(cv_l), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l))));
	_mm256_storeu_si256(M256_CAST(cv_r), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_r)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r))));

	_mm256_storeu_si256(M256_CAST(cv_l+4), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l+4)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_l+4))));
	_mm256_storeu_si256(M256_CAST(cv_r+4), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_r+4)),
		_mm256_loadu_si256(CONST_M256_CAST(submsg_o_r+4))));
}

inline void add_blk(lsh_u64 cv_l[8], lsh_u64 cv_r[8])
{
	_mm256_storeu_si256(M256_CAST(cv_l), _mm256_add_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l)),
		_mm256_loadu_si256(CONST_M256_CAST(cv_r))));
	_mm256_storeu_si256(M256_CAST(cv_l+4), _mm256_add_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l+4)),
		_mm256_loadu_si256(CONST_M256_CAST(cv_r+4))));
}

template <unsigned int R>
inline void rotate_blk(lsh_u64 cv[8])
{
	_mm256_storeu_si256(M256_CAST(cv), _mm256_or_si256(
		_mm256_slli_epi64(_mm256_loadu_si256(CONST_M256_CAST(cv)), R),
		_mm256_srli_epi64(_mm256_loadu_si256(CONST_M256_CAST(cv)), 64-R)));
	_mm256_storeu_si256(M256_CAST(cv+4), _mm256_or_si256(
		_mm256_slli_epi64(_mm256_loadu_si256(CONST_M256_CAST(cv+4)), R),
		_mm256_srli_epi64(_mm256_loadu_si256(CONST_M256_CAST(cv+4)), 64-R)));
}

inline void xor_with_const(lsh_u64 cv_l[8], const lsh_u64 const_v[8])
{
	_mm256_storeu_si256(M256_CAST(cv_l), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l)),
		_mm256_loadu_si256(CONST_M256_CAST(const_v))));
	_mm256_storeu_si256(M256_CAST(cv_l+4), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l+4)),
		_mm256_loadu_si256(CONST_M256_CAST(const_v+4))));
}

inline void rotate_msg_gamma(lsh_u64 cv_r[8])
{
	// g_gamma512[8] = { 0, 16, 32, 48, 8, 24, 40, 56 };
	_mm256_storeu_si256(M256_CAST(cv_r+0),
		_mm256_shuffle_epi8(
			_mm256_loadu_si256(CONST_M256_CAST(cv_r+0)),
			_mm256_set_epi8(
				/* hi lane */ 9,8,15,14, 13,12,11,10, 3,2,1,0, 7,6,5,4,
				/* lo lane */ 13,12,11,10, 9,8,15,14, 7,6,5,4, 3,2,1,0)));
	_mm256_storeu_si256(M256_CAST(cv_r+4),
		_mm256_shuffle_epi8(
			_mm256_loadu_si256(CONST_M256_CAST(cv_r+4)),
			_mm256_set_epi8(
				/* hi lane */ 8,15,14,13, 12,11,10,9, 2,1,0,7, 6,5,4,3,
				/* lo lane */ 12,11,10,9, 8,15,14,13, 6,5,4,3, 2,1,0,7)));
}

inline void word_perm(lsh_u64 cv_l[8], lsh_u64 cv_r[8])
{
	__m256i temp[2];
	_mm256_storeu_si256(M256_CAST(cv_l+0), _mm256_permute4x64_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l+0)), _MM_SHUFFLE(3,1,0,2)));
	_mm256_storeu_si256(M256_CAST(cv_l+4), _mm256_permute4x64_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(cv_l+4)), _MM_SHUFFLE(3,1,0,2)));
	_mm256_storeu_si256(M256_CAST(cv_r+0), _mm256_permute4x64_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(cv_r+0)), _MM_SHUFFLE(1,2,3,0)));
	_mm256_storeu_si256(M256_CAST(cv_r+4), _mm256_permute4x64_epi64(
		_mm256_loadu_si256(CONST_M256_CAST(cv_r+4)), _MM_SHUFFLE(1,2,3,0)));

	temp[0] = _mm256_loadu_si256(CONST_M256_CAST(cv_l+0));
	temp[1] = _mm256_loadu_si256(CONST_M256_CAST(cv_r+0));

	_mm256_storeu_si256(M256_CAST(cv_l+0),
		_mm256_loadu_si256(CONST_M256_CAST(cv_l+4)));
	_mm256_storeu_si256(M256_CAST(cv_l+4),
		_mm256_loadu_si256(CONST_M256_CAST(cv_r+4)));

	_mm256_storeu_si256(M256_CAST(cv_r+0), temp[0]);
	_mm256_storeu_si256(M256_CAST(cv_r+4), temp[1]);
};

/* -------------------------------------------------------- *
* step function
* -------------------------------------------------------- */

template <unsigned int Alpha, unsigned int Beta>
inline void mix(lsh_u64 cv_l[8], lsh_u64 cv_r[8], const lsh_u64 const_v[8])
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

inline void compress(LSH512_AVX2_Context* ctx, const lsh_u8 pdMsgBlk[LSH512_MSG_BLK_BYTE_LEN])
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	LSH512_AVX2_Internal  s_state(ctx->cv_l);
	LSH512_AVX2_Internal* i_state = &s_state;

	const lsh_u64* const_v = NULL;
	lsh_u64 *cv_l = ctx->cv_l;
	lsh_u64 *cv_r = ctx->cv_r;

	AVX_Cleanup cleanup;

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

inline void load_iv(word64 cv_l[8], word64 cv_r[8], const word64 iv[16])
{
	// The IV's are 32-byte aligned so we can use aligned loads.
	_mm256_storeu_si256(M256_CAST(cv_l+0),
		_mm256_load_si256(CONST_M256_CAST(iv+0)));
	_mm256_storeu_si256(M256_CAST(cv_l+4),
		_mm256_load_si256(CONST_M256_CAST(iv+4)));

	_mm256_storeu_si256(M256_CAST(cv_r+0),
		_mm256_load_si256(CONST_M256_CAST(iv+8)));
	_mm256_storeu_si256(M256_CAST(cv_r+4),
		_mm256_load_si256(CONST_M256_CAST(iv+12)));
}

inline void zero_iv(lsh_u64 cv_l[8], lsh_u64 cv_r[8])
{
	_mm256_storeu_si256(M256_CAST(cv_l+0), _mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(cv_l+4), _mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(cv_r+0), _mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(cv_r+4), _mm256_setzero_si256());
}

inline void zero_submsgs(LSH512_AVX2_Context* ctx)
{
	lsh_u64* sub_msgs = ctx->sub_msgs;

	_mm256_storeu_si256(M256_CAST(sub_msgs+ 0),
		_mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(sub_msgs+ 4),
		_mm256_setzero_si256());

	_mm256_storeu_si256(M256_CAST(sub_msgs+ 8),
		_mm256_setzero_si256());
	_mm256_storeu_si256(M256_CAST(sub_msgs+12),
		_mm256_setzero_si256());
}

inline void init224(LSH512_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	AVX_Cleanup cleanup;

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH512_IV224);
}

inline void init256(LSH512_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	AVX_Cleanup cleanup;

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH512_IV256);
}

inline void init384(LSH512_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	AVX_Cleanup cleanup;

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH512_IV384);
}

inline void init512(LSH512_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	AVX_Cleanup cleanup;

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH512_IV512);
}

/* -------------------------------------------------------- */

inline void fin(LSH512_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	AVX_Cleanup cleanup;

	_mm256_storeu_si256(M256_CAST(ctx->cv_l+0), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(ctx->cv_l+0)),
		_mm256_loadu_si256(CONST_M256_CAST(ctx->cv_r+0))));

	_mm256_storeu_si256(M256_CAST(ctx->cv_l+4), _mm256_xor_si256(
		_mm256_loadu_si256(CONST_M256_CAST(ctx->cv_l+4)),
		_mm256_loadu_si256(CONST_M256_CAST(ctx->cv_r+4))));
}

/* -------------------------------------------------------- */

inline void get_hash(LSH512_AVX2_Context* ctx, lsh_u8* pbHashVal)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(ctx->algtype != 0);
	CRYPTOPP_ASSERT(pbHashVal != NULLPTR);

	lsh_uint algtype = ctx->algtype;
	lsh_uint hash_val_byte_len = LSH_GET_HASHBYTE(algtype);
	lsh_uint hash_val_bit_len = LSH_GET_SMALL_HASHBIT(algtype);

	// Multiplying by sizeof(lsh_u8) looks odd...
	memcpy(pbHashVal, ctx->cv_l, hash_val_byte_len);
	if (hash_val_bit_len){
		pbHashVal[hash_val_byte_len-1] &= (((lsh_u8)0xff) << hash_val_bit_len);
	}
}

/* -------------------------------------------------------- */

lsh_err lsh512_init_avx2(LSH512_AVX2_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(ctx->algtype != 0);

	lsh_u32 algtype = ctx->algtype;
	const lsh_u64* const_v = NULL;
	ctx->remain_databitlen = 0;

	switch (algtype){
	case LSH_TYPE_512_512:
		init512(ctx);
		return LSH_SUCCESS;
	case LSH_TYPE_512_384:
		init384(ctx);
		return LSH_SUCCESS;
	case LSH_TYPE_512_256:
		init256(ctx);
		return LSH_SUCCESS;
	case LSH_TYPE_512_224:
		init224(ctx);
		return LSH_SUCCESS;
	default:
		break;
	}

	lsh_u64* cv_l = ctx->cv_l;
	lsh_u64* cv_r = ctx->cv_r;

	AVX_Cleanup cleanup;

	zero_iv(cv_l, cv_r);
	cv_l[0] = LSH512_HASH_VAL_MAX_BYTE_LEN;
	cv_l[1] = LSH_GET_HASHBIT(algtype);

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

lsh_err lsh512_update_avx2(LSH512_AVX2_Context* ctx, const lsh_u8* data, size_t databitlen)
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
	// remain_msg_bit = ctx->remain_databitlen & 7;
	const lsh_uint remain_msg_bit = 0;

	if (remain_msg_byte >= LSH512_MSG_BLK_BYTE_LEN){
		return LSH_ERR_INVALID_STATE;
	}
	if (remain_msg_bit > 0){
		return LSH_ERR_INVALID_DATABITLEN;
	}

	if (databytelen + remain_msg_byte < LSH512_MSG_BLK_BYTE_LEN){
		memcpy(ctx->last_block + remain_msg_byte, data, databytelen);
		ctx->remain_databitlen += (lsh_uint)databitlen;
		remain_msg_byte += (lsh_uint)databytelen;
		if (pos2){
			ctx->last_block[remain_msg_byte] = data[databytelen] & ((0xff >> pos2) ^ 0xff);
		}
		return LSH_SUCCESS;
	}

	if (remain_msg_byte > 0){
		lsh_uint more_byte = LSH512_MSG_BLK_BYTE_LEN - remain_msg_byte;
		memcpy(ctx->last_block + remain_msg_byte, data, more_byte);
		compress(ctx, ctx->last_block);
		data += more_byte;
		databytelen -= more_byte;
		remain_msg_byte = 0;
		ctx->remain_databitlen = 0;
	}

	while (databytelen >= LSH512_MSG_BLK_BYTE_LEN)
	{
		// This call to compress caused some trouble.
		// The data pointer can become unaligned in the
		// previous block.
		compress(ctx, data);
		data += LSH512_MSG_BLK_BYTE_LEN;
		databytelen -= LSH512_MSG_BLK_BYTE_LEN;
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

lsh_err lsh512_final_avx2(LSH512_AVX2_Context* ctx, lsh_u8* hashval)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(hashval != NULLPTR);

	// We are byte oriented. remain_msg_bit will always be 0.
	lsh_uint remain_msg_byte = ctx->remain_databitlen >> 3;
	// lsh_uint remain_msg_bit = ctx->remain_databitlen & 7;
	const lsh_uint remain_msg_bit = 0;

	if (remain_msg_byte >= LSH512_MSG_BLK_BYTE_LEN){
		return LSH_ERR_INVALID_STATE;
	}

	if (remain_msg_bit){
		ctx->last_block[remain_msg_byte] |= (0x1 << (7 - remain_msg_bit));
	}
	else{
		ctx->last_block[remain_msg_byte] = 0x80;
	}
	memset(ctx->last_block + remain_msg_byte + 1, 0, LSH512_MSG_BLK_BYTE_LEN - remain_msg_byte - 1);

	compress(ctx, ctx->last_block);

	fin(ctx);
	get_hash(ctx, hashval);

	return LSH_SUCCESS;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

extern
void LSH512_Base_Restart_AVX2(word64* state)
{
	// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735.
	AVX_BuggyCleanup cleanup;

	state[RemainingBits] = 0;
	LSH512_AVX2_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh512_init_avx2(&ctx);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_init_avx2 failed");
}

extern
void LSH512_Base_Update_AVX2(word64* state, const byte *input, size_t size)
{
	// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735.
	AVX_BuggyCleanup cleanup;

	LSH512_AVX2_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh512_update_avx2(&ctx, input, 8*size);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_update_avx2 failed");
}

extern
void LSH512_Base_TruncatedFinal_AVX2(word64* state, byte *hash, size_t size)
{
	// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82735.
	AVX_BuggyCleanup cleanup;

	LSH512_AVX2_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh512_final_avx2(&ctx, hash);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_final_avx2 failed");
}

NAMESPACE_END

#endif  // CRYPTOPP_AVX2_AVAILABLE
