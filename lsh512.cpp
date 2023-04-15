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
#include "cpu.h"
#include "misc.h"

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

/* -------------------------------------------------------- *
* LSH: iv
* -------------------------------------------------------- */

//extern const word64 LSH512_IV224[CV_WORD_LEN];
//extern const word64 LSH512_IV256[CV_WORD_LEN];
//extern const word64 LSH512_IV384[CV_WORD_LEN];
//extern const word64 LSH512_IV512[CV_WORD_LEN];
//extern const word64 LSH512_StepConstants[CONST_WORD_LEN * NUM_STEPS];

CRYPTOPP_ALIGN_DATA(32)
extern
const word64 LSH512_IV224[CV_WORD_LEN] = {
	W64LIT(0x0C401E9FE8813A55), W64LIT(0x4A5F446268FD3D35), W64LIT(0xFF13E452334F612A), W64LIT(0xF8227661037E354A),
	W64LIT(0xA5F223723C9CA29D), W64LIT(0x95D965A11AED3979), W64LIT(0x01E23835B9AB02CC), W64LIT(0x52D49CBAD5B30616),
	W64LIT(0x9E5C2027773F4ED3), W64LIT(0x66A5C8801925B701), W64LIT(0x22BBC85B4C6779D9), W64LIT(0xC13171A42C559C23),
	W64LIT(0x31E2B67D25BE3813), W64LIT(0xD522C4DEED8E4D83), W64LIT(0xA79F5509B43FBAFE), W64LIT(0xE00D2CD88B4B6C6A),
};

CRYPTOPP_ALIGN_DATA(32)
extern
const word64 LSH512_IV256[CV_WORD_LEN] = {
	W64LIT(0x6DC57C33DF989423), W64LIT(0xD8EA7F6E8342C199), W64LIT(0x76DF8356F8603AC4), W64LIT(0x40F1B44DE838223A),
	W64LIT(0x39FFE7CFC31484CD), W64LIT(0x39C4326CC5281548), W64LIT(0x8A2FF85A346045D8), W64LIT(0xFF202AA46DBDD61E),
	W64LIT(0xCF785B3CD5FCDB8B), W64LIT(0x1F0323B64A8150BF), W64LIT(0xFF75D972F29EA355), W64LIT(0x2E567F30BF1CA9E1),
	W64LIT(0xB596875BF8FF6DBA), W64LIT(0xFCCA39B089EF4615), W64LIT(0xECFF4017D020B4B6), W64LIT(0x7E77384C772ED802),
};

CRYPTOPP_ALIGN_DATA(32)
extern
const word64 LSH512_IV384[CV_WORD_LEN] = {
	W64LIT(0x53156A66292808F6), W64LIT(0xB2C4F362B204C2BC), W64LIT(0xB84B7213BFA05C4E), W64LIT(0x976CEB7C1B299F73),
	W64LIT(0xDF0CC63C0570AE97), W64LIT(0xDA4441BAA486CE3F), W64LIT(0x6559F5D9B5F2ACC2), W64LIT(0x22DACF19B4B52A16),
	W64LIT(0xBBCDACEFDE80953A), W64LIT(0xC9891A2879725B3E), W64LIT(0x7C9FE6330237E440), W64LIT(0xA30BA550553F7431),
	W64LIT(0xBB08043FB34E3E30), W64LIT(0xA0DEC48D54618EAD), W64LIT(0x150317267464BC57), W64LIT(0x32D1501FDE63DC93)
};

CRYPTOPP_ALIGN_DATA(32)
extern
const word64 LSH512_IV512[CV_WORD_LEN] = {
	W64LIT(0xadd50f3c7f07094e), W64LIT(0xe3f3cee8f9418a4f), W64LIT(0xb527ecde5b3d0ae9), W64LIT(0x2ef6dec68076f501),
	W64LIT(0x8cb994cae5aca216), W64LIT(0xfbb9eae4bba48cc7), W64LIT(0x650a526174725fea), W64LIT(0x1f9a61a73f8d8085),
	W64LIT(0xb6607378173b539b), W64LIT(0x1bc99853b0c0b9ed), W64LIT(0xdf727fc19b182d47), W64LIT(0xdbef360cf893a457),
	W64LIT(0x4981f5e570147e80), W64LIT(0xd00c4490ca7d3e30), W64LIT(0x5d73940c0e4ae1ec), W64LIT(0x894085e2edb2d819)
};

/* -------------------------------------------------------- *
* LSH: step constants
* -------------------------------------------------------- */

extern
const word64 LSH512_StepConstants[CONST_WORD_LEN * NUM_STEPS] = {
	W64LIT(0x97884283c938982a), W64LIT(0xba1fca93533e2355), W64LIT(0xc519a2e87aeb1c03), W64LIT(0x9a0fc95462af17b1),
	W64LIT(0xfc3dda8ab019a82b), W64LIT(0x02825d079a895407), W64LIT(0x79f2d0a7ee06a6f7), W64LIT(0xd76d15eed9fdf5fe),
	W64LIT(0x1fcac64d01d0c2c1), W64LIT(0xd9ea5de69161790f), W64LIT(0xdebc8b6366071fc8), W64LIT(0xa9d91db711c6c94b),
	W64LIT(0x3a18653ac9c1d427), W64LIT(0x84df64a223dd5b09), W64LIT(0x6cc37895f4ad9e70), W64LIT(0x448304c8d7f3f4d5),
	W64LIT(0xea91134ed29383e0), W64LIT(0xc4484477f2da88e8), W64LIT(0x9b47eec96d26e8a6), W64LIT(0x82f6d4c8d89014f4),
	W64LIT(0x527da0048b95fb61), W64LIT(0x644406c60138648d), W64LIT(0x303c0e8aa24c0edc), W64LIT(0xc787cda0cbe8ca19),
	W64LIT(0x7ba46221661764ca), W64LIT(0x0c8cbc6acd6371ac), W64LIT(0xe336b836940f8f41), W64LIT(0x79cb9da168a50976),
	W64LIT(0xd01da49021915cb3), W64LIT(0xa84accc7399cf1f1), W64LIT(0x6c4a992cee5aeb0c), W64LIT(0x4f556e6cb4b2e3e0),
	W64LIT(0x200683877d7c2f45), W64LIT(0x9949273830d51db8), W64LIT(0x19eeeecaa39ed124), W64LIT(0x45693f0a0dae7fef),
	W64LIT(0xedc234b1b2ee1083), W64LIT(0xf3179400d68ee399), W64LIT(0xb6e3c61b4945f778), W64LIT(0xa4c3db216796c42f),
	W64LIT(0x268a0b04f9ab7465), W64LIT(0xe2705f6905f2d651), W64LIT(0x08ddb96e426ff53d), W64LIT(0xaea84917bc2e6f34),
	W64LIT(0xaff6e664a0fe9470), W64LIT(0x0aab94d765727d8c), W64LIT(0x9aa9e1648f3d702e), W64LIT(0x689efc88fe5af3d3),
	W64LIT(0xb0950ffea51fd98b), W64LIT(0x52cfc86ef8c92833), W64LIT(0xe69727b0b2653245), W64LIT(0x56f160d3ea9da3e2),
	W64LIT(0xa6dd4b059f93051f), W64LIT(0xb6406c3cd7f00996), W64LIT(0x448b45f3ccad9ec8), W64LIT(0x079b8587594ec73b),
	W64LIT(0x45a50ea3c4f9653b), W64LIT(0x22983767c1f15b85), W64LIT(0x7dbed8631797782b), W64LIT(0x485234be88418638),
	W64LIT(0x842850a5329824c5), W64LIT(0xf6aca914c7f9a04c), W64LIT(0xcfd139c07a4c670c), W64LIT(0xa3210ce0a8160242),
	W64LIT(0xeab3b268be5ea080), W64LIT(0xbacf9f29b34ce0a7), W64LIT(0x3c973b7aaf0fa3a8), W64LIT(0x9a86f346c9c7be80),
	W64LIT(0xac78f5d7cabcea49), W64LIT(0xa355bddcc199ed42), W64LIT(0xa10afa3ac6b373db), W64LIT(0xc42ded88be1844e5),
	W64LIT(0x9e661b271cff216a), W64LIT(0x8a6ec8dd002d8861), W64LIT(0xd3d2b629beb34be4), W64LIT(0x217a3a1091863f1a),
	W64LIT(0x256ecda287a733f5), W64LIT(0xf9139a9e5b872fe5), W64LIT(0xac0535017a274f7c), W64LIT(0xf21b7646d65d2aa9),
	W64LIT(0x048142441c208c08), W64LIT(0xf937a5dd2db5e9eb), W64LIT(0xa688dfe871ff30b7), W64LIT(0x9bb44aa217c5593b),
	W64LIT(0x943c702a2edb291a), W64LIT(0x0cae38f9e2b715de), W64LIT(0xb13a367ba176cc28), W64LIT(0x0d91bd1d3387d49b),
	W64LIT(0x85c386603cac940c), W64LIT(0x30dd830ae39fd5e4), W64LIT(0x2f68c85a712fe85d), W64LIT(0x4ffeecb9dd1e94d6),
	W64LIT(0xd0ac9a590a0443ae), W64LIT(0xbae732dc99ccf3ea), W64LIT(0xeb70b21d1842f4d9), W64LIT(0x9f4eda50bb5c6fa8),
	W64LIT(0x4949e69ce940a091), W64LIT(0x0e608dee8375ba14), W64LIT(0x983122cba118458c), W64LIT(0x4eeba696fbb36b25),
	W64LIT(0x7d46f3630e47f27e), W64LIT(0xa21a0f7666c0dea4), W64LIT(0x5c22cf355b37cec4), W64LIT(0xee292b0c17cc1847),
	W64LIT(0x9330838629e131da), W64LIT(0x6eee7c71f92fce22), W64LIT(0xc953ee6cb95dd224), W64LIT(0x3a923d92af1e9073),
	W64LIT(0xc43a5671563a70fb), W64LIT(0xbc2985dd279f8346), W64LIT(0x7ef2049093069320), W64LIT(0x17543723e3e46035),
	W64LIT(0xc3b409b00b130c6d), W64LIT(0x5d6aee6b28fdf090), W64LIT(0x1d425b26172ff6ed), W64LIT(0xcccfd041cdaf03ad),
	W64LIT(0xfe90c7c790ab6cbf), W64LIT(0xe5af6304c722ca02), W64LIT(0x70f695239999b39e), W64LIT(0x6b8b5b07c844954c),
	W64LIT(0x77bdb9bb1e1f7a30), W64LIT(0xc859599426ee80ed), W64LIT(0x5f9d813d4726e40a), W64LIT(0x9ca0120f7cb2b179),
	W64LIT(0x8f588f583c182cbd), W64LIT(0x951267cbe9eccce7), W64LIT(0x678bb8bd334d520e), W64LIT(0xf6e662d00cd9e1b7),
	W64LIT(0x357774d93d99aaa7), W64LIT(0x21b2edbb156f6eb5), W64LIT(0xfd1ebe846e0aee69), W64LIT(0x3cb2218c2f642b15),
	W64LIT(0xe7e7e7945444ea4c), W64LIT(0xa77a33b5d6b9b47c), W64LIT(0xf34475f0809f6075), W64LIT(0xdd4932dce6bb99ad),
	W64LIT(0xacec4e16d74451dc), W64LIT(0xd4a0a8d084de23d6), W64LIT(0x1bdd42f278f95866), W64LIT(0xeed3adbb938f4051),
	W64LIT(0xcfcf7be8992f3733), W64LIT(0x21ade98c906e3123), W64LIT(0x37ba66711fffd668), W64LIT(0x267c0fc3a255478a),
	W64LIT(0x993a64ee1b962e88), W64LIT(0x754979556301faaa), W64LIT(0xf920356b7251be81), W64LIT(0xc281694f22cf923f),
	W64LIT(0x9f4b6481c8666b02), W64LIT(0xcf97761cfe9f5444), W64LIT(0xf220d7911fd63e9f), W64LIT(0xa28bd365f79cd1b0),
	W64LIT(0xd39f5309b1c4b721), W64LIT(0xbec2ceb864fca51f), W64LIT(0x1955a0ddc410407a), W64LIT(0x43eab871f261d201),
	W64LIT(0xeaafe64a2ed16da1), W64LIT(0x670d931b9df39913), W64LIT(0x12f868b0f614de91), W64LIT(0x2e5f395d946e8252),
	W64LIT(0x72f25cbb767bd8f4), W64LIT(0x8191871d61a1c4dd), W64LIT(0x6ef67ea1d450ba93), W64LIT(0x2ea32a645433d344),
	W64LIT(0x9a963079003f0f8b), W64LIT(0x74a0aeb9918cac7a), W64LIT(0x0b6119a70af36fa3), W64LIT(0x8d9896f202f0d480),
	W64LIT(0x654f1831f254cd66), W64LIT(0x1318a47f0366a25e), W64LIT(0x65752076250b4e01), W64LIT(0xd1cd8eb888071772),
	W64LIT(0x30c6a9793f4e9b25), W64LIT(0x154f684b1e3926ee), W64LIT(0x6c7ac0b1fe6312ae), W64LIT(0x262f88f4f3c5550d),
	W64LIT(0xb4674a24472233cb), W64LIT(0x2bbd23826a090071), W64LIT(0xda95969b30594f66), W64LIT(0x9f5c47408f1e8a43),
	W64LIT(0xf77022b88de9c055), W64LIT(0x64b7b36957601503), W64LIT(0xe73b72b06175c11a), W64LIT(0x55b87de8b91a6233),
	W64LIT(0x1bb16e6b6955ff7f), W64LIT(0xe8e0a5ec7309719c), W64LIT(0x702c31cb89a8b640), W64LIT(0xfba387cfada8cde2),
	W64LIT(0x6792db4677aa164c), W64LIT(0x1c6b1cc0b7751867), W64LIT(0x22ae2311d736dc01), W64LIT(0x0e3666a1d37c9588),
	W64LIT(0xcd1fd9d4bf557e9a), W64LIT(0xc986925f7c7b0e84), W64LIT(0x9c5dfd55325ef6b0), W64LIT(0x9f2b577d5676b0dd),
	W64LIT(0xfa6e21be21c062b3), W64LIT(0x8787dd782c8d7f83), W64LIT(0xd0d134e90e12dd23), W64LIT(0x449d087550121d96),
	W64LIT(0xecf9ae9414d41967), W64LIT(0x5018f1dbf789934d), W64LIT(0xfa5b52879155a74c), W64LIT(0xca82d4d3cd278e7c),
	W64LIT(0x688fdfdfe22316ad), W64LIT(0x0f6555a4ba0d030a), W64LIT(0xa2061df720f000f3), W64LIT(0xe1a57dc5622fb3da),
	W64LIT(0xe6a842a8e8ed8153), W64LIT(0x690acdd3811ce09d), W64LIT(0x55adda18e6fcf446), W64LIT(0x4d57a8a0f4b60b46),
	W64LIT(0xf86fbfc20539c415), W64LIT(0x74bafa5ec7100d19), W64LIT(0xa824151810f0f495), W64LIT(0x8723432791e38ebb),
	W64LIT(0x8eeaeb91d66ed539), W64LIT(0x73d8a1549dfd7e06), W64LIT(0x0387f2ffe3f13a9b), W64LIT(0xa5004995aac15193),
	W64LIT(0x682f81c73efdda0d), W64LIT(0x2fb55925d71d268d), W64LIT(0xcc392d2901e58a3d), W64LIT(0xaa666ab975724a42)
};

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

struct LSH512_Context
{
	LSH512_Context(word64* state, word64 algType, word64& remainingBitLength) :
		cv_l(state+0), cv_r(state+8), sub_msgs(state+16),
		last_block(reinterpret_cast<byte*>(state+48)),
		remain_databitlen(remainingBitLength),
		alg_type(static_cast<lsh_type>(algType)) {}

	lsh_u64* cv_l;  // start of our state block
	lsh_u64* cv_r;
	lsh_u64* sub_msgs;
	lsh_u8*  last_block;
	lsh_u64& remain_databitlen;
	lsh_type alg_type;
};

struct LSH512_Internal
{
	LSH512_Internal(word64* state) :
		submsg_e_l(state+16), submsg_e_r(state+24),
		submsg_o_l(state+32), submsg_o_r(state+40) { }

	lsh_u64* submsg_e_l; /* even left sub-message  */
	lsh_u64* submsg_e_r; /* even right sub-message */
	lsh_u64* submsg_o_l; /* odd left sub-message   */
	lsh_u64* submsg_o_r; /* odd right sub-message  */
};

const lsh_u32 g_gamma512[8] = { 0, 16, 32, 48, 8, 24, 40, 56 };

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
inline void load_msg_blk(LSH512_Internal* i_state, const lsh_u8* msgblk)
{
	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;
	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

	typedef GetBlock<word64, LittleEndian, false> InBlock;

	InBlock input(msgblk);
	input(submsg_e_l[0])(submsg_e_l[1])(submsg_e_l[2])(submsg_e_l[3])
		(submsg_e_l[4])(submsg_e_l[5])(submsg_e_l[6])(submsg_e_l[7])
		(submsg_e_r[0])(submsg_e_r[1])(submsg_e_r[2])(submsg_e_r[3])
		(submsg_e_r[4])(submsg_e_r[5])(submsg_e_r[6])(submsg_e_r[7])
		(submsg_o_l[0])(submsg_o_l[1])(submsg_o_l[2])(submsg_o_l[3])
		(submsg_o_l[4])(submsg_o_l[5])(submsg_o_l[6])(submsg_o_l[7])
		(submsg_o_r[0])(submsg_o_r[1])(submsg_o_r[2])(submsg_o_r[3])
		(submsg_o_r[4])(submsg_o_r[5])(submsg_o_r[6])(submsg_o_r[7]);
}

inline void msg_exp_even(LSH512_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;
	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

	lsh_u64 temp;
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
}

inline void msg_exp_odd(LSH512_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;
	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

	lsh_u64 temp;
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
}

inline void load_sc(const lsh_u64** p_const_v, size_t i)
{
	*p_const_v = &LSH512_StepConstants[i];
}

inline void msg_add_even(lsh_u64 cv_l[8], lsh_u64 cv_r[8], LSH512_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;

	cv_l[0] ^= submsg_e_l[0];  cv_l[1] ^= submsg_e_l[1];
	cv_l[2] ^= submsg_e_l[2];  cv_l[3] ^= submsg_e_l[3];
	cv_l[4] ^= submsg_e_l[4];  cv_l[5] ^= submsg_e_l[5];
	cv_l[6] ^= submsg_e_l[6];  cv_l[7] ^= submsg_e_l[7];
	cv_r[0] ^= submsg_e_r[0];  cv_r[1] ^= submsg_e_r[1];
	cv_r[2] ^= submsg_e_r[2];  cv_r[3] ^= submsg_e_r[3];
	cv_r[4] ^= submsg_e_r[4];  cv_r[5] ^= submsg_e_r[5];
	cv_r[6] ^= submsg_e_r[6];  cv_r[7] ^= submsg_e_r[7];
}

inline void msg_add_odd(lsh_u64 cv_l[8], lsh_u64 cv_r[8], LSH512_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

	cv_l[0] ^= submsg_o_l[0];  cv_l[1] ^= submsg_o_l[1];
	cv_l[2] ^= submsg_o_l[2];  cv_l[3] ^= submsg_o_l[3];
	cv_l[4] ^= submsg_o_l[4];  cv_l[5] ^= submsg_o_l[5];
	cv_l[6] ^= submsg_o_l[6];  cv_l[7] ^= submsg_o_l[7];
	cv_r[0] ^= submsg_o_r[0];  cv_r[1] ^= submsg_o_r[1];
	cv_r[2] ^= submsg_o_r[2];  cv_r[3] ^= submsg_o_r[3];
	cv_r[4] ^= submsg_o_r[4];  cv_r[5] ^= submsg_o_r[5];
	cv_r[6] ^= submsg_o_r[6];  cv_r[7] ^= submsg_o_r[7];
}

inline void add_blk(lsh_u64 cv_l[8], lsh_u64 cv_r[8])
{
	cv_l[0] += cv_r[0];
	cv_l[1] += cv_r[1];
	cv_l[2] += cv_r[2];
	cv_l[3] += cv_r[3];
	cv_l[4] += cv_r[4];
	cv_l[5] += cv_r[5];
	cv_l[6] += cv_r[6];
	cv_l[7] += cv_r[7];
}

template <unsigned int R>
inline void rotate_blk(lsh_u64 cv[8])
{
	cv[0] = rotlConstant<R>(cv[0]);
	cv[1] = rotlConstant<R>(cv[1]);
	cv[2] = rotlConstant<R>(cv[2]);
	cv[3] = rotlConstant<R>(cv[3]);
	cv[4] = rotlConstant<R>(cv[4]);
	cv[5] = rotlConstant<R>(cv[5]);
	cv[6] = rotlConstant<R>(cv[6]);
	cv[7] = rotlConstant<R>(cv[7]);
}

inline void xor_with_const(lsh_u64 cv_l[8], const lsh_u64* const_v)
{
	cv_l[0] ^= const_v[0];
	cv_l[1] ^= const_v[1];
	cv_l[2] ^= const_v[2];
	cv_l[3] ^= const_v[3];
	cv_l[4] ^= const_v[4];
	cv_l[5] ^= const_v[5];
	cv_l[6] ^= const_v[6];
	cv_l[7] ^= const_v[7];
}

inline void rotate_msg_gamma(lsh_u64 cv_r[8])
{
	cv_r[1] = ROTL64(cv_r[1], g_gamma512[1]);
	cv_r[2] = ROTL64(cv_r[2], g_gamma512[2]);
	cv_r[3] = ROTL64(cv_r[3], g_gamma512[3]);
	cv_r[4] = ROTL64(cv_r[4], g_gamma512[4]);
	cv_r[5] = ROTL64(cv_r[5], g_gamma512[5]);
	cv_r[6] = ROTL64(cv_r[6], g_gamma512[6]);
	cv_r[7] = ROTL64(cv_r[7], g_gamma512[7]);
}

inline void word_perm(lsh_u64 cv_l[8], lsh_u64 cv_r[8])
{
	lsh_u64 temp;
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
}

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

inline void compress(LSH512_Context* ctx, const lsh_u8 pdMsgBlk[LSH512_MSG_BLK_BYTE_LEN])
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	LSH512_Internal  s_state(ctx->cv_l);
	LSH512_Internal* i_state = &s_state;

	const lsh_u64* const_v = NULL;
	lsh_u64 *cv_l = ctx->cv_l;
	lsh_u64 *cv_r = ctx->cv_r;

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

inline void load_iv(lsh_u64 cv_l[8], lsh_u64 cv_r[8], const lsh_u64 iv[16])
{
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
}

inline void zero_iv(lsh_u64 cv_l[8], lsh_u64 cv_r[8])
{
	std::memset(cv_l, 0, 8*sizeof(lsh_u64));
	std::memset(cv_r, 0, 8*sizeof(lsh_u64));
}

inline void zero_submsgs(LSH512_Context* ctx)
{
	lsh_u64* sub_msgs = ctx->sub_msgs;

	std::memset(sub_msgs, 0x00, 32*sizeof(lsh_u64));
}

inline void init224(LSH512_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH512_IV224);
}

inline void init256(LSH512_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH512_IV256);
}

inline void init384(LSH512_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH512_IV384);
}

inline void init512(LSH512_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	zero_submsgs(ctx);
	load_iv(ctx->cv_l, ctx->cv_r, LSH512_IV512);
}

/* -------------------------------------------------------- */

inline void fin(LSH512_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);

	for (size_t i = 0; i < HASH_VAL_MAX_WORD_LEN; i++){
		ctx->cv_l[i] = loadLE64(ctx->cv_l[i] ^ ctx->cv_r[i]);
	}
}

/* -------------------------------------------------------- */

inline void get_hash(LSH512_Context* ctx, lsh_u8* pbHashVal)
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

lsh_err lsh512_init(LSH512_Context* ctx)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(ctx->alg_type != 0);

	lsh_u32 alg_type = ctx->alg_type;
	const lsh_u64* const_v = NULL;
	ctx->remain_databitlen = 0;

	switch (alg_type){
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

	zero_iv(cv_l, cv_r);
	cv_l[0] = LSH512_HASH_VAL_MAX_BYTE_LEN;
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

lsh_err lsh512_update(LSH512_Context* ctx, const lsh_u8* data, size_t databitlen)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(data != NULLPTR);
	CRYPTOPP_ASSERT(databitlen % 8 == 0);
	CRYPTOPP_ASSERT(ctx->alg_type != 0);

	if (databitlen == 0){
		return LSH_SUCCESS;
	}

	// We are byte oriented. tail bits will always be 0.
	size_t databytelen = databitlen >> 3;
	// lsh_uint pos2 = databitlen & 0x7;
	const size_t pos2 = 0;

	size_t remain_msg_byte = static_cast<size_t>(ctx->remain_databitlen >> 3);
	// lsh_uint remain_msg_bit = ctx->remain_databitlen & 7;
	const size_t remain_msg_bit = 0;

	if (remain_msg_byte >= LSH512_MSG_BLK_BYTE_LEN){
		return LSH_ERR_INVALID_STATE;
	}
	if (remain_msg_bit > 0){
		return LSH_ERR_INVALID_DATABITLEN;
	}

	if (databytelen + remain_msg_byte < LSH512_MSG_BLK_BYTE_LEN){
		std::memcpy(ctx->last_block + remain_msg_byte, data, databytelen);
		ctx->remain_databitlen += (lsh_uint)databitlen;
		remain_msg_byte += (lsh_uint)databytelen;
		if (pos2){
			ctx->last_block[remain_msg_byte] = data[databytelen] & ((0xff >> pos2) ^ 0xff);
		}
		return LSH_SUCCESS;
	}

	if (remain_msg_byte > 0){
		size_t more_byte = LSH512_MSG_BLK_BYTE_LEN - remain_msg_byte;
		std::memcpy(ctx->last_block + remain_msg_byte, data, more_byte);
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
		std::memcpy(ctx->last_block, data, databytelen);
		ctx->remain_databitlen = (lsh_uint)(databytelen << 3);
	}

	if (pos2){
		ctx->last_block[databytelen] = data[databytelen] & ((0xff >> pos2) ^ 0xff);
		ctx->remain_databitlen += pos2;
	}
	return LSH_SUCCESS;
}

lsh_err lsh512_final(LSH512_Context* ctx, lsh_u8* hashval)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(hashval != NULLPTR);

	// We are byte oriented. tail bits will always be 0.
	size_t remain_msg_byte = static_cast<size_t>(ctx->remain_databitlen >> 3);
	// lsh_uint remain_msg_bit = ctx->remain_databitlen & 7;
	const size_t remain_msg_bit = 0;

	if (remain_msg_byte >= LSH512_MSG_BLK_BYTE_LEN){
		return LSH_ERR_INVALID_STATE;
	}

	if (remain_msg_bit){
		ctx->last_block[remain_msg_byte] |= (0x1 << (7 - remain_msg_bit));
	}
	else{
		ctx->last_block[remain_msg_byte] = 0x80;
	}
	std::memset(ctx->last_block + remain_msg_byte + 1, 0, LSH512_MSG_BLK_BYTE_LEN - remain_msg_byte - 1);

	compress(ctx, ctx->last_block);

	fin(ctx);
	get_hash(ctx, hashval);

	return LSH_SUCCESS;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_ENABLE_64BIT_SSE)
# if defined(CRYPTOPP_AVX2_AVAILABLE)
	extern void LSH512_Base_Restart_AVX2(word64* state);
	extern void LSH512_Base_Update_AVX2(word64* state, const byte *input, size_t size);
	extern void LSH512_Base_TruncatedFinal_AVX2(word64* state, byte *hash, size_t size);
# endif
# if defined(CRYPTOPP_SSSE3_AVAILABLE)
	extern void LSH512_Base_Restart_SSSE3(word64* state);
	extern void LSH512_Base_Update_SSSE3(word64* state, const byte *input, size_t size);
	extern void LSH512_Base_TruncatedFinal_SSSE3(word64* state, byte *hash, size_t size);
# endif
#endif

std::string LSH512_Base::AlgorithmProvider() const
{
#if defined(CRYPTOPP_ENABLE_64BIT_SSE)
#if defined(CRYPTOPP_AVX2_AVAILABLE)
	if (HasAVX2())
		return "AVX2";
	else
#endif
#if defined(CRYPTOPP_SSSE3_AVAILABLE)
	if (HasSSSE3())
		return "SSSE3";
	else
#endif
#endif  // CRYPTOPP_ENABLE_64BIT_SSE

	return "C++";
}

void LSH512_Base_Restart_CXX(word64* state)
{
	state[RemainingBits] = 0;
	LSH512_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh512_init(&ctx);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_init failed");
}

void LSH512_Base_Update_CXX(word64* state, const byte *input, size_t size)
{
	LSH512_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh512_update(&ctx, input, 8*size);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_update failed");
}

void LSH512_Base_TruncatedFinal_CXX(word64* state, byte *hash, size_t)
{
	LSH512_Context ctx(state, state[AlgorithmType], state[RemainingBits]);
	lsh_err err = lsh512_final(&ctx, hash);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_final failed");
}


void LSH512_Base::Restart()
{
#if defined(CRYPTOPP_AVX2_AVAILABLE) && defined(CRYPTOPP_ENABLE_64BIT_SSE)
	if (HasAVX2())
		LSH512_Base_Restart_AVX2(m_state);
	else
#endif
#if defined(CRYPTOPP_SSSE3_AVAILABLE) && defined(CRYPTOPP_ENABLE_64BIT_SSE)
	if (HasSSSE3())
		LSH512_Base_Restart_SSSE3(m_state);
	else
#endif

	LSH512_Base_Restart_CXX(m_state);
}

void LSH512_Base::Update(const byte *input, size_t size)
{
	CRYPTOPP_ASSERT(input != NULLPTR);
	CRYPTOPP_ASSERT(size);

#if defined(CRYPTOPP_AVX2_AVAILABLE) && defined(CRYPTOPP_ENABLE_64BIT_SSE)
	if (HasAVX2())
		LSH512_Base_Update_AVX2(m_state, input, size);
	else
#endif
#if defined(CRYPTOPP_SSSE3_AVAILABLE) && defined(CRYPTOPP_ENABLE_64BIT_SSE)
	if (HasSSSE3())
		LSH512_Base_Update_SSSE3(m_state, input, size);
	else
#endif

	LSH512_Base_Update_CXX(m_state, input, size);
}

void LSH512_Base::TruncatedFinal(byte *hash, size_t size)
{
	CRYPTOPP_ASSERT(hash != NULLPTR);
	ThrowIfInvalidTruncatedSize(size);

	// TODO: determine if LSH512 supports truncated hashes. See the code
	// in get_hash(), where a bit-length is added to the last output
	// byte of the hash function.
	byte fullHash[LSH512_HASH_VAL_MAX_BYTE_LEN];
	bool copyOut = (size < DigestSize());

#if defined(CRYPTOPP_AVX2_AVAILABLE) && defined(CRYPTOPP_ENABLE_64BIT_SSE)
	if (HasAVX2())
		LSH512_Base_TruncatedFinal_AVX2(m_state, copyOut ? fullHash : hash, size);
	else
#endif
#if defined(CRYPTOPP_SSSE3_AVAILABLE) && defined(CRYPTOPP_ENABLE_64BIT_SSE)
	if (HasSSSE3())
		LSH512_Base_TruncatedFinal_SSSE3(m_state, copyOut ? fullHash : hash, size);
	else
#endif

	LSH512_Base_TruncatedFinal_CXX(m_state, copyOut ? fullHash : hash, size);

	if (copyOut)
		std::memcpy(hash, fullHash, size);

    Restart();
}

NAMESPACE_END
