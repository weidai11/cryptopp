// lsh.cpp - written and placed in the public domain by Jeffrey Walton
//           Based on the specification and source code provided by
//           Korea Internet & Security Agency (KISA) website. Also
//           see https://seed.kisa.or.kr/kisa/algorithm/EgovLSHInfo.do
//           and https://seed.kisa.or.kr/kisa/Board/22/detailView.do.

#include "pch.h"
#include "config.h"

#include "lsh.h"
#include "misc.h"

#if defined(__SSE2__)
# include <emmintrin.h>
# define M128_CAST(x) ((__m128i *)(void *)(x))
# define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))
#endif

#if defined(__XOP__)
# include <ammintrin.h>
# if defined(__GNUC__)
#  include <x86intrin.h>
# endif
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::rotlFixed;
using CryptoPP::rotrFixed;
using CryptoPP::rotlConstant;
using CryptoPP::rotrConstant;

using CryptoPP::LSH256;
using CryptoPP::Exception;

using CryptoPP::LITTLE_ENDIAN_ORDER;
using CryptoPP::ConditionalByteReverse;

typedef byte lsh_u8;
typedef word32 lsh_u32;
typedef word64 lsh_u64;
typedef word32 lsh_uint;
typedef word32 lsh_err;
typedef word32 lsh_type;

struct LSH512_Context
{
	LSH512_Context(word64* state, word32 algType, word32& remainingBitLength) :
		cv_l(state+0), cv_r(state+8), sub_msgs(state+16),
		last_block(reinterpret_cast<byte*>(state+48)) ,
		remain_databitlen(remainingBitLength), algtype(algType) {}

	lsh_u64* cv_l;  // start of our state block
	lsh_u64* cv_r;
	lsh_u64* sub_msgs;
	lsh_u8*  last_block;
	lsh_u32& remain_databitlen;
	lsh_type algtype;
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

const unsigned int MSG_BLK_WORD_LEN = 32;
const unsigned int CV_WORD_LENN = 16;
const unsigned int CONST_WORD_LENN = 8;
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

const unsigned int LSH_TYPE_384 = LSH_TYPE_512_384;
const unsigned int LSH_TYPE_512 = LSH_TYPE_512_512;


/* LSH AlgType Macro */

#define LSH_IS_LSH512(lsh_type_val)			(((lsh_type_val)&0xf0000)==0x10000)

#define LSH_GET_SMALL_HASHBIT(lsh_type_val)		((lsh_type_val)>>24)
#define LSH_GET_HASHBYTE(lsh_type_val)			((lsh_type_val) & 0xffff)
#define LSH_GET_HASHBIT(lsh_type_val)			((LSH_GET_HASHBYTE(lsh_type_val)<<3)-LSH_GET_SMALL_HASHBIT(lsh_type_val))

/* LSH Constants */

const unsigned int LSH512_MSG_BLK_BYTE_LEN = 256;
const unsigned int LSH512_MSG_BLK_BIT_LEN = 2048;
const unsigned int LSH512_CV_BYTE_LEN = 128;
const unsigned int LSH512_HASH_VAL_MAX_BYTE_LEN = 64;

/* Error Code */

const unsigned int LSH_SUCCESS = 0x0;
const unsigned int LSH_ERR_NULL_PTR = 0x2401;
const unsigned int LSH_ERR_INVALID_ALGTYPE = 0x2402;
const unsigned int LSH_ERR_INVALID_DATABITLEN = 0x2403;
const unsigned int LSH_ERR_INVALID_STATE = 0x2404;

inline lsh_u64 loadLE64(lsh_u64 v) {
	return ConditionalByteReverse(LITTLE_ENDIAN_ORDER, v);
}

lsh_u64 ROTL64(lsh_u64 x, lsh_u64 r) {
	return rotlFixed(x, r);
}

//lsh_u64 ROTR64(lsh_u64 x, lsh_u64 r) {
//	return rotrFixed(x, r);
//}

/* -------------------------------------------------------- *
* LSH: iv
* -------------------------------------------------------- */

#if (CRYPTOPP_CXX11_CONSTEXPR)
# define MAYBE_CONSTEXPR constexpr
#else
# define MAYBE_CONSTEXPR const
#endif

CRYPTOPP_ALIGN_DATA(16)
MAYBE_CONSTEXPR lsh_u64 g_IV224[16] = {
	0x0C401E9FE8813A55ULL, 0x4A5F446268FD3D35ULL, 0xFF13E452334F612AULL, 0xF8227661037E354AULL,
	0xA5F223723C9CA29DULL, 0x95D965A11AED3979ULL, 0x01E23835B9AB02CCULL, 0x52D49CBAD5B30616ULL,
	0x9E5C2027773F4ED3ULL, 0x66A5C8801925B701ULL, 0x22BBC85B4C6779D9ULL, 0xC13171A42C559C23ULL,
	0x31E2B67D25BE3813ULL, 0xD522C4DEED8E4D83ULL, 0xA79F5509B43FBAFEULL, 0xE00D2CD88B4B6C6AULL,
};

CRYPTOPP_ALIGN_DATA(16)
MAYBE_CONSTEXPR lsh_u64 g_IV256[16] = {
	0x6DC57C33DF989423ULL, 0xD8EA7F6E8342C199ULL, 0x76DF8356F8603AC4ULL, 0x40F1B44DE838223AULL,
	0x39FFE7CFC31484CDULL, 0x39C4326CC5281548ULL, 0x8A2FF85A346045D8ULL, 0xFF202AA46DBDD61EULL,
	0xCF785B3CD5FCDB8BULL, 0x1F0323B64A8150BFULL, 0xFF75D972F29EA355ULL, 0x2E567F30BF1CA9E1ULL,
	0xB596875BF8FF6DBAULL, 0xFCCA39B089EF4615ULL, 0xECFF4017D020B4B6ULL, 0x7E77384C772ED802ULL,
};

CRYPTOPP_ALIGN_DATA(16)
MAYBE_CONSTEXPR lsh_u64 g_IV384[16] = {
	0x53156A66292808F6ULL, 0xB2C4F362B204C2BCULL, 0xB84B7213BFA05C4EULL, 0x976CEB7C1B299F73ULL,
	0xDF0CC63C0570AE97ULL, 0xDA4441BAA486CE3FULL, 0x6559F5D9B5F2ACC2ULL, 0x22DACF19B4B52A16ULL,
	0xBBCDACEFDE80953AULL, 0xC9891A2879725B3EULL, 0x7C9FE6330237E440ULL, 0xA30BA550553F7431ULL,
	0xBB08043FB34E3E30ULL, 0xA0DEC48D54618EADULL, 0x150317267464BC57ULL, 0x32D1501FDE63DC93ULL
};

CRYPTOPP_ALIGN_DATA(16)
MAYBE_CONSTEXPR lsh_u64 g_IV512[16] = {
	0xadd50f3c7f07094eULL, 0xe3f3cee8f9418a4fULL, 0xb527ecde5b3d0ae9ULL, 0x2ef6dec68076f501ULL,
	0x8cb994cae5aca216ULL, 0xfbb9eae4bba48cc7ULL, 0x650a526174725feaULL, 0x1f9a61a73f8d8085ULL,
	0xb6607378173b539bULL, 0x1bc99853b0c0b9edULL, 0xdf727fc19b182d47ULL, 0xdbef360cf893a457ULL,
	0x4981f5e570147e80ULL, 0xd00c4490ca7d3e30ULL, 0x5d73940c0e4ae1ecULL, 0x894085e2edb2d819ULL
};

MAYBE_CONSTEXPR lsh_uint g_gamma512[8] = { 0, 16, 32, 48, 8, 24, 40, 56 };

/* -------------------------------------------------------- *
* LSH: step constants
* -------------------------------------------------------- */

/* -------------------------------------------------------- *
* LSH: step constants
* -------------------------------------------------------- */

MAYBE_CONSTEXPR lsh_u64 g_StepConstants[16 * NUM_STEPS] = {
	0x97884283c938982aULL, 0xba1fca93533e2355ULL, 0xc519a2e87aeb1c03ULL, 0x9a0fc95462af17b1ULL,
	0xfc3dda8ab019a82bULL, 0x02825d079a895407ULL, 0x79f2d0a7ee06a6f7ULL, 0xd76d15eed9fdf5feULL,
	0x1fcac64d01d0c2c1ULL, 0xd9ea5de69161790fULL, 0xdebc8b6366071fc8ULL, 0xa9d91db711c6c94bULL,
	0x3a18653ac9c1d427ULL, 0x84df64a223dd5b09ULL, 0x6cc37895f4ad9e70ULL, 0x448304c8d7f3f4d5ULL,
	0xea91134ed29383e0ULL, 0xc4484477f2da88e8ULL, 0x9b47eec96d26e8a6ULL, 0x82f6d4c8d89014f4ULL,
	0x527da0048b95fb61ULL, 0x644406c60138648dULL, 0x303c0e8aa24c0edcULL, 0xc787cda0cbe8ca19ULL,
	0x7ba46221661764caULL, 0x0c8cbc6acd6371acULL, 0xe336b836940f8f41ULL, 0x79cb9da168a50976ULL,
	0xd01da49021915cb3ULL, 0xa84accc7399cf1f1ULL, 0x6c4a992cee5aeb0cULL, 0x4f556e6cb4b2e3e0ULL,
	0x200683877d7c2f45ULL, 0x9949273830d51db8ULL, 0x19eeeecaa39ed124ULL, 0x45693f0a0dae7fefULL,
	0xedc234b1b2ee1083ULL, 0xf3179400d68ee399ULL, 0xb6e3c61b4945f778ULL, 0xa4c3db216796c42fULL,
	0x268a0b04f9ab7465ULL, 0xe2705f6905f2d651ULL, 0x08ddb96e426ff53dULL, 0xaea84917bc2e6f34ULL,
	0xaff6e664a0fe9470ULL, 0x0aab94d765727d8cULL, 0x9aa9e1648f3d702eULL, 0x689efc88fe5af3d3ULL,
	0xb0950ffea51fd98bULL, 0x52cfc86ef8c92833ULL, 0xe69727b0b2653245ULL, 0x56f160d3ea9da3e2ULL,
	0xa6dd4b059f93051fULL, 0xb6406c3cd7f00996ULL, 0x448b45f3ccad9ec8ULL, 0x079b8587594ec73bULL,
	0x45a50ea3c4f9653bULL, 0x22983767c1f15b85ULL, 0x7dbed8631797782bULL, 0x485234be88418638ULL,
	0x842850a5329824c5ULL, 0xf6aca914c7f9a04cULL, 0xcfd139c07a4c670cULL, 0xa3210ce0a8160242ULL,
	0xeab3b268be5ea080ULL, 0xbacf9f29b34ce0a7ULL, 0x3c973b7aaf0fa3a8ULL, 0x9a86f346c9c7be80ULL,
	0xac78f5d7cabcea49ULL, 0xa355bddcc199ed42ULL, 0xa10afa3ac6b373dbULL, 0xc42ded88be1844e5ULL,
	0x9e661b271cff216aULL, 0x8a6ec8dd002d8861ULL, 0xd3d2b629beb34be4ULL, 0x217a3a1091863f1aULL,
	0x256ecda287a733f5ULL, 0xf9139a9e5b872fe5ULL, 0xac0535017a274f7cULL, 0xf21b7646d65d2aa9ULL,
	0x048142441c208c08ULL, 0xf937a5dd2db5e9ebULL, 0xa688dfe871ff30b7ULL, 0x9bb44aa217c5593bULL,
	0x943c702a2edb291aULL, 0x0cae38f9e2b715deULL, 0xb13a367ba176cc28ULL, 0x0d91bd1d3387d49bULL,
	0x85c386603cac940cULL, 0x30dd830ae39fd5e4ULL, 0x2f68c85a712fe85dULL, 0x4ffeecb9dd1e94d6ULL,
	0xd0ac9a590a0443aeULL, 0xbae732dc99ccf3eaULL, 0xeb70b21d1842f4d9ULL, 0x9f4eda50bb5c6fa8ULL,
	0x4949e69ce940a091ULL, 0x0e608dee8375ba14ULL, 0x983122cba118458cULL, 0x4eeba696fbb36b25ULL,
	0x7d46f3630e47f27eULL, 0xa21a0f7666c0dea4ULL, 0x5c22cf355b37cec4ULL, 0xee292b0c17cc1847ULL,
	0x9330838629e131daULL, 0x6eee7c71f92fce22ULL, 0xc953ee6cb95dd224ULL, 0x3a923d92af1e9073ULL,
	0xc43a5671563a70fbULL, 0xbc2985dd279f8346ULL, 0x7ef2049093069320ULL, 0x17543723e3e46035ULL,
	0xc3b409b00b130c6dULL, 0x5d6aee6b28fdf090ULL, 0x1d425b26172ff6edULL, 0xcccfd041cdaf03adULL,
	0xfe90c7c790ab6cbfULL, 0xe5af6304c722ca02ULL, 0x70f695239999b39eULL, 0x6b8b5b07c844954cULL,
	0x77bdb9bb1e1f7a30ULL, 0xc859599426ee80edULL, 0x5f9d813d4726e40aULL, 0x9ca0120f7cb2b179ULL,
	0x8f588f583c182cbdULL, 0x951267cbe9eccce7ULL, 0x678bb8bd334d520eULL, 0xf6e662d00cd9e1b7ULL,
	0x357774d93d99aaa7ULL, 0x21b2edbb156f6eb5ULL, 0xfd1ebe846e0aee69ULL, 0x3cb2218c2f642b15ULL,
	0xe7e7e7945444ea4cULL, 0xa77a33b5d6b9b47cULL, 0xf34475f0809f6075ULL, 0xdd4932dce6bb99adULL,
	0xacec4e16d74451dcULL, 0xd4a0a8d084de23d6ULL, 0x1bdd42f278f95866ULL, 0xeed3adbb938f4051ULL,
	0xcfcf7be8992f3733ULL, 0x21ade98c906e3123ULL, 0x37ba66711fffd668ULL, 0x267c0fc3a255478aULL,
	0x993a64ee1b962e88ULL, 0x754979556301faaaULL, 0xf920356b7251be81ULL, 0xc281694f22cf923fULL,
	0x9f4b6481c8666b02ULL, 0xcf97761cfe9f5444ULL, 0xf220d7911fd63e9fULL, 0xa28bd365f79cd1b0ULL,
	0xd39f5309b1c4b721ULL, 0xbec2ceb864fca51fULL, 0x1955a0ddc410407aULL, 0x43eab871f261d201ULL,
	0xeaafe64a2ed16da1ULL, 0x670d931b9df39913ULL, 0x12f868b0f614de91ULL, 0x2e5f395d946e8252ULL,
	0x72f25cbb767bd8f4ULL, 0x8191871d61a1c4ddULL, 0x6ef67ea1d450ba93ULL, 0x2ea32a645433d344ULL,
	0x9a963079003f0f8bULL, 0x74a0aeb9918cac7aULL, 0x0b6119a70af36fa3ULL, 0x8d9896f202f0d480ULL,
	0x654f1831f254cd66ULL, 0x1318a47f0366a25eULL, 0x65752076250b4e01ULL, 0xd1cd8eb888071772ULL,
	0x30c6a9793f4e9b25ULL, 0x154f684b1e3926eeULL, 0x6c7ac0b1fe6312aeULL, 0x262f88f4f3c5550dULL,
	0xb4674a24472233cbULL, 0x2bbd23826a090071ULL, 0xda95969b30594f66ULL, 0x9f5c47408f1e8a43ULL,
	0xf77022b88de9c055ULL, 0x64b7b36957601503ULL, 0xe73b72b06175c11aULL, 0x55b87de8b91a6233ULL,
	0x1bb16e6b6955ff7fULL, 0xe8e0a5ec7309719cULL, 0x702c31cb89a8b640ULL, 0xfba387cfada8cde2ULL,
	0x6792db4677aa164cULL, 0x1c6b1cc0b7751867ULL, 0x22ae2311d736dc01ULL, 0x0e3666a1d37c9588ULL,
	0xcd1fd9d4bf557e9aULL, 0xc986925f7c7b0e84ULL, 0x9c5dfd55325ef6b0ULL, 0x9f2b577d5676b0ddULL,
	0xfa6e21be21c062b3ULL, 0x8787dd782c8d7f83ULL, 0xd0d134e90e12dd23ULL, 0x449d087550121d96ULL,
	0xecf9ae9414d41967ULL, 0x5018f1dbf789934dULL, 0xfa5b52879155a74cULL, 0xca82d4d3cd278e7cULL,
	0x688fdfdfe22316adULL, 0x0f6555a4ba0d030aULL, 0xa2061df720f000f3ULL, 0xe1a57dc5622fb3daULL,
	0xe6a842a8e8ed8153ULL, 0x690acdd3811ce09dULL, 0x55adda18e6fcf446ULL, 0x4d57a8a0f4b60b46ULL,
	0xf86fbfc20539c415ULL, 0x74bafa5ec7100d19ULL, 0xa824151810f0f495ULL, 0x8723432791e38ebbULL,
	0x8eeaeb91d66ed539ULL, 0x73d8a1549dfd7e06ULL, 0x0387f2ffe3f13a9bULL, 0xa5004995aac15193ULL,
	0x682f81c73efdda0dULL, 0x2fb55925d71d268dULL, 0xcc392d2901e58a3dULL, 0xaa666ab975724a42ULL
};

inline void load_msg_blk(LSH512_Internal* i_state, const lsh_u64 * msgblk)
{
#if defined(__SSE2__)
	_mm_storeu_si128(M128_CAST(i_state->submsg_e_l+0),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+0)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_e_l+2),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+2)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_e_l+4),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+4)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_e_l+6),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+6)));

	_mm_storeu_si128(M128_CAST(i_state->submsg_e_r+0),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+8)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_e_r+2),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+10)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_e_r+4),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+12)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_e_r+8),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+14)));

	_mm_storeu_si128(M128_CAST(i_state->submsg_o_l+0),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+16)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_o_l+2),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+18)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_o_l+4),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+20)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_o_l+6),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+22)));

	_mm_storeu_si128(M128_CAST(i_state->submsg_o_r+0),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+24)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_o_r+2),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+26)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_o_r+4),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+28)));
	_mm_storeu_si128(M128_CAST(i_state->submsg_o_r+6),
		_mm_loadu_si128(CONST_M128_CAST(msgblk+30)));
#else
	i_state->submsg_e_l[0] = loadLE64(msgblk[0]);
	i_state->submsg_e_l[1] = loadLE64(msgblk[1]);
	i_state->submsg_e_l[2] = loadLE64(msgblk[2]);
	i_state->submsg_e_l[3] = loadLE64(msgblk[3]);
	i_state->submsg_e_l[4] = loadLE64(msgblk[4]);
	i_state->submsg_e_l[5] = loadLE64(msgblk[5]);
	i_state->submsg_e_l[6] = loadLE64(msgblk[6]);
	i_state->submsg_e_l[7] = loadLE64(msgblk[7]);
	i_state->submsg_e_r[0] = loadLE64(msgblk[8]);
	i_state->submsg_e_r[1] = loadLE64(msgblk[9]);
	i_state->submsg_e_r[2] = loadLE64(msgblk[10]);
	i_state->submsg_e_r[3] = loadLE64(msgblk[11]);
	i_state->submsg_e_r[4] = loadLE64(msgblk[12]);
	i_state->submsg_e_r[5] = loadLE64(msgblk[13]);
	i_state->submsg_e_r[6] = loadLE64(msgblk[14]);
	i_state->submsg_e_r[7] = loadLE64(msgblk[15]);
	i_state->submsg_o_l[0] = loadLE64(msgblk[16]);
	i_state->submsg_o_l[1] = loadLE64(msgblk[17]);
	i_state->submsg_o_l[2] = loadLE64(msgblk[18]);
	i_state->submsg_o_l[3] = loadLE64(msgblk[19]);
	i_state->submsg_o_l[4] = loadLE64(msgblk[20]);
	i_state->submsg_o_l[5] = loadLE64(msgblk[21]);
	i_state->submsg_o_l[6] = loadLE64(msgblk[22]);
	i_state->submsg_o_l[7] = loadLE64(msgblk[23]);
	i_state->submsg_o_r[0] = loadLE64(msgblk[24]);
	i_state->submsg_o_r[1] = loadLE64(msgblk[25]);
	i_state->submsg_o_r[2] = loadLE64(msgblk[26]);
	i_state->submsg_o_r[3] = loadLE64(msgblk[27]);
	i_state->submsg_o_r[4] = loadLE64(msgblk[28]);
	i_state->submsg_o_r[5] = loadLE64(msgblk[29]);
	i_state->submsg_o_r[6] = loadLE64(msgblk[30]);
	i_state->submsg_o_r[7] = loadLE64(msgblk[31]);
#endif
}

inline void msg_exp_even(LSH512_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;
	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

#if defined(__SSE2__)
	__m128i temp;
	_mm_storeu_si128(M128_CAST(submsg_e_l+2),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+2)), _MM_SHUFFLE(1,0,3,2)));

	temp = _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+0));
	_mm_storeu_si128(M128_CAST(submsg_e_l+0), _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+2)));
	_mm_storeu_si128(M128_CAST(submsg_e_l+2), temp);
	_mm_storeu_si128(M128_CAST(submsg_e_l+6),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+6)), _MM_SHUFFLE(1,0,3,2)));

	temp = _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+4));
	_mm_storeu_si128(M128_CAST(submsg_e_l+4), _mm_unpacklo_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+6)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+4))));

	_mm_storeu_si128(M128_CAST(submsg_e_l+6), _mm_unpackhi_epi64(
		temp, _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+6))));

	_mm_storeu_si128(M128_CAST(submsg_e_r+2),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+2)), _MM_SHUFFLE(1,0,3,2)));

	temp = _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+0));
	_mm_storeu_si128(M128_CAST(submsg_e_r+0), _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+2)));
	_mm_storeu_si128(M128_CAST(submsg_e_r+2), temp);
	_mm_storeu_si128(M128_CAST(submsg_e_r+6),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+6)), _MM_SHUFFLE(1,0,3,2)));

	temp = _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+4));
	_mm_storeu_si128(M128_CAST(submsg_e_r+4), _mm_unpacklo_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+6)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+4))));

	_mm_storeu_si128(M128_CAST(submsg_e_r+6), _mm_unpackhi_epi64(
		temp, _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+6))));

	_mm_storeu_si128(M128_CAST(submsg_e_l+0), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+0)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+0))));
	_mm_storeu_si128(M128_CAST(submsg_e_l+2), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+2)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+2))));
	_mm_storeu_si128(M128_CAST(submsg_e_l+4), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+4)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+4))));
	_mm_storeu_si128(M128_CAST(submsg_e_l+6), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+6)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_l+6))));
	_mm_storeu_si128(M128_CAST(submsg_e_r+0), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+0)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+0))));
	_mm_storeu_si128(M128_CAST(submsg_e_r+2), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+2)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+2))));
	_mm_storeu_si128(M128_CAST(submsg_e_r+4), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+4)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+4))));
	_mm_storeu_si128(M128_CAST(submsg_e_r+6), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+6)), _mm_loadu_si128(CONST_M128_CAST(submsg_e_r+6))));
#else
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
#endif
}

inline void msg_exp_odd(LSH512_Internal* i_state)
{
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;
	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

#if defined(__SSE2__)
	__m128i temp;
	_mm_storeu_si128(M128_CAST(submsg_o_l+2),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+2)), _MM_SHUFFLE(1,0,3,2)));

	temp = _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+0));
	_mm_storeu_si128(M128_CAST(submsg_o_l+0), _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+2)));
	_mm_storeu_si128(M128_CAST(submsg_o_l+2), temp);
	_mm_storeu_si128(M128_CAST(submsg_o_l+6),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+6)), _MM_SHUFFLE(1,0,3,2)));

	temp = _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+4));
	_mm_storeu_si128(M128_CAST(submsg_o_l+4), _mm_unpacklo_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+6)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+4))));
	_mm_storeu_si128(M128_CAST(submsg_o_l+6), _mm_unpackhi_epi64(
		temp, _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+6))));
	_mm_storeu_si128(M128_CAST(submsg_o_r+2),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+2)), _MM_SHUFFLE(1,0,3,2)));

	temp = _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+0));
	_mm_storeu_si128(M128_CAST(submsg_o_r+0), _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+2)));
	_mm_storeu_si128(M128_CAST(submsg_o_r+2), temp);
	_mm_storeu_si128(M128_CAST(submsg_o_r+6),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+6)), _MM_SHUFFLE(1,0,3,2)));

	temp = _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+4));
	_mm_storeu_si128(M128_CAST(submsg_o_r+4), _mm_unpacklo_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+6)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+4))));
	_mm_storeu_si128(M128_CAST(submsg_o_r+6), _mm_unpackhi_epi64(
		temp, _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+6))));

	_mm_storeu_si128(M128_CAST(submsg_o_l+0), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+0)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+0))));
	_mm_storeu_si128(M128_CAST(submsg_o_l+2), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+2)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+2))));
	_mm_storeu_si128(M128_CAST(submsg_o_l+4), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+4)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+4))));
	_mm_storeu_si128(M128_CAST(submsg_o_l+6), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+5)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_l+5))));
	_mm_storeu_si128(M128_CAST(submsg_o_r+0), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+0)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+0))));
	_mm_storeu_si128(M128_CAST(submsg_o_r+2), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+2)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+2))));
	_mm_storeu_si128(M128_CAST(submsg_o_r+4), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+4)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+4))));
	_mm_storeu_si128(M128_CAST(submsg_o_r+6), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+6)), _mm_loadu_si128(CONST_M128_CAST(submsg_o_r+6))));
#else
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
#endif
}

inline void load_sc(const lsh_u64** p_const_v, lsh_uint i)
{
	*p_const_v = &g_StepConstants[i];
}

inline void msg_add_even(lsh_u64 cv_l[8], lsh_u64 cv_r[8], LSH512_Internal* i_state)
{
	CRYPTOPP_ASSERT(cv_l != NULLPTR);
	CRYPTOPP_ASSERT(cv_r != NULLPTR);
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_e_l = i_state->submsg_e_l;
	lsh_u64* submsg_e_r = i_state->submsg_e_r;

#if defined(__SSE2__)
	_mm_storeu_si128(M128_CAST(cv_l), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l))));
	_mm_storeu_si128(M128_CAST(cv_r), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r))));
	_mm_storeu_si128(M128_CAST(cv_l+2), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+2)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+2))));
	_mm_storeu_si128(M128_CAST(cv_r+2), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+2)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+2))));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+4))));
	_mm_storeu_si128(M128_CAST(cv_r+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+4)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+4))));
	_mm_storeu_si128(M128_CAST(cv_l+6), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+6)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_l+6))));
	_mm_storeu_si128(M128_CAST(cv_r+6), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+6)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_e_r+6))));
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
inline void msg_add_odd(lsh_u64 cv_l[8], lsh_u64 cv_r[8], LSH512_Internal* i_state)
{
	CRYPTOPP_ASSERT(cv_l != NULLPTR);
	CRYPTOPP_ASSERT(cv_r != NULLPTR);
	CRYPTOPP_ASSERT(i_state != NULLPTR);

	lsh_u64* submsg_o_l = i_state->submsg_o_l;
	lsh_u64* submsg_o_r = i_state->submsg_o_r;

#if defined(__SSE2__)
	_mm_storeu_si128(M128_CAST(cv_l), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l))));
	_mm_storeu_si128(M128_CAST(cv_r), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r))));
	_mm_storeu_si128(M128_CAST(cv_l+2), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+2)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+2))));
	_mm_storeu_si128(M128_CAST(cv_r+2), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+2)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+2))));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+4))));
	_mm_storeu_si128(M128_CAST(cv_r+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+4)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+4))));
	_mm_storeu_si128(M128_CAST(cv_l+6), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+6)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_l+6))));
	_mm_storeu_si128(M128_CAST(cv_r+6), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+6)),
		_mm_loadu_si128(CONST_M128_CAST(submsg_o_r+6))));
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

inline void add_blk(lsh_u64 cv_l[8], lsh_u64 cv_r[8])
{
#if defined(__SSE2__)
	_mm_storeu_si128(M128_CAST(cv_l), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_l)),
		_mm_loadu_si128(CONST_M128_CAST(cv_r))));
	_mm_storeu_si128(M128_CAST(cv_l+2), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+2)),
		_mm_loadu_si128(CONST_M128_CAST(cv_r+2))));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(cv_r+4))));
	_mm_storeu_si128(M128_CAST(cv_l+6), _mm_add_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+6)),
		_mm_loadu_si128(CONST_M128_CAST(cv_r+6))));
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
inline void rotate_blk(lsh_u64 cv[8])
{
#if defined(__XOP__)
	_mm_storeu_si128(M128_CAST(cv),
		_mm_roti_epi64(_mm_loadu_si128(CONST_M128_CAST(cv)), R));
	_mm_storeu_si128(M128_CAST(cv+2),
		_mm_roti_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+2)), R));
	_mm_storeu_si128(M128_CAST(cv+4),
		_mm_roti_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+4)), R));
	_mm_storeu_si128(M128_CAST(cv+6),
		_mm_roti_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+6)), R));
#elif defined(__SSE2__)
	_mm_storeu_si128(M128_CAST(cv), _mm_or_si128(
		_mm_slli_epi64(_mm_loadu_si128(CONST_M128_CAST(cv)), R),
		_mm_srli_epi64(_mm_loadu_si128(CONST_M128_CAST(cv)), 64-R)));
	_mm_storeu_si128(M128_CAST(cv+2), _mm_or_si128(
		_mm_slli_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+2)), R),
		_mm_srli_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+2)), 64-R)));
	_mm_storeu_si128(M128_CAST(cv+4), _mm_or_si128(
		_mm_slli_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+4)), R),
		_mm_srli_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+4)), 64-R)));
	_mm_storeu_si128(M128_CAST(cv+6), _mm_or_si128(
		_mm_slli_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+6)), R),
		_mm_srli_epi64(_mm_loadu_si128(CONST_M128_CAST(cv+6)), 64-R)));
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

inline void xor_with_const(lsh_u64 cv_l[8], const lsh_u64* const_v)
{
#if defined(__SSE2__)
	_mm_storeu_si128(M128_CAST(cv_l), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l)),
		_mm_loadu_si128(CONST_M128_CAST(const_v))));
	_mm_storeu_si128(M128_CAST(cv_l+2), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+2)),
		_mm_loadu_si128(CONST_M128_CAST(const_v+2))));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4)),
		_mm_loadu_si128(CONST_M128_CAST(const_v+4))));
	_mm_storeu_si128(M128_CAST(cv_l+6), _mm_xor_si128(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+6)),
		_mm_loadu_si128(CONST_M128_CAST(const_v+6))));
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
#if defined(__SSE2__)
	__m128i temp[2];
	temp[0] = _mm_loadu_si128(CONST_M128_CAST(cv_l+0));
	_mm_storeu_si128(M128_CAST(cv_l+0), _mm_unpacklo_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+2)),
		_mm_loadu_si128(CONST_M128_CAST(cv_l+0))));
	_mm_storeu_si128(M128_CAST(cv_l+2), _mm_unpackhi_epi64(
		temp[0], _mm_loadu_si128(CONST_M128_CAST(cv_l+2))));

	temp[0] = _mm_loadu_si128(CONST_M128_CAST(cv_l+4));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_unpacklo_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_l+6)),
		_mm_loadu_si128(CONST_M128_CAST(cv_l+4))));
	_mm_storeu_si128(M128_CAST(cv_l+6), _mm_unpackhi_epi64(
		temp[0], _mm_loadu_si128(CONST_M128_CAST(cv_l+6))));
	_mm_storeu_si128(M128_CAST(cv_r+2),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(cv_r+2)), _MM_SHUFFLE(1,0,3,2)));

	temp[0] = _mm_loadu_si128(CONST_M128_CAST(cv_r+0));
	_mm_storeu_si128(M128_CAST(cv_r+0), _mm_unpacklo_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+0)),
		_mm_loadu_si128(CONST_M128_CAST(cv_r+2))));
	_mm_storeu_si128(M128_CAST(cv_r+2), _mm_unpackhi_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+2)), temp[0]));
	_mm_storeu_si128(M128_CAST(cv_r+6),
		_mm_shuffle_epi32(_mm_loadu_si128(CONST_M128_CAST(cv_r+6)), _MM_SHUFFLE(1,0,3,2)));

	temp[0] = _mm_loadu_si128(CONST_M128_CAST(cv_r+4));
	_mm_storeu_si128(M128_CAST(cv_r+4), _mm_unpacklo_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+4)),
		_mm_loadu_si128(CONST_M128_CAST(cv_r+6))));
	_mm_storeu_si128(M128_CAST(cv_r+6), _mm_unpackhi_epi64(
		_mm_loadu_si128(CONST_M128_CAST(cv_r+6)), temp[0]));

	temp[0] = _mm_loadu_si128(CONST_M128_CAST(cv_l+0));
	temp[1] = _mm_loadu_si128(CONST_M128_CAST(cv_l+2));

	_mm_storeu_si128(M128_CAST(cv_l+0), _mm_loadu_si128(CONST_M128_CAST(cv_l+4)));
	_mm_storeu_si128(M128_CAST(cv_l+2), _mm_loadu_si128(CONST_M128_CAST(cv_l+6)));
	_mm_storeu_si128(M128_CAST(cv_l+4), _mm_loadu_si128(CONST_M128_CAST(cv_r+4)));
	_mm_storeu_si128(M128_CAST(cv_l+6), _mm_loadu_si128(CONST_M128_CAST(cv_r+6)));
	_mm_storeu_si128(M128_CAST(cv_r+4), _mm_loadu_si128(CONST_M128_CAST(cv_r+0)));
	_mm_storeu_si128(M128_CAST(cv_r+6), _mm_loadu_si128(CONST_M128_CAST(cv_r+2)));

	_mm_storeu_si128(M128_CAST(cv_r+0), temp[0]);
	_mm_storeu_si128(M128_CAST(cv_r+2), temp[1]);
#else
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
#endif
};

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

inline void compress(LSH512_Context* ctx, const lsh_u64 pdMsgBlk[MSG_BLK_WORD_LEN])
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

inline void init224(LSH512_Context* ctx)
{
	ctx->cv_l[0] = g_IV224[0];
	ctx->cv_l[1] = g_IV224[1];
	ctx->cv_l[2] = g_IV224[2];
	ctx->cv_l[3] = g_IV224[3];
	ctx->cv_l[4] = g_IV224[4];
	ctx->cv_l[5] = g_IV224[5];
	ctx->cv_l[6] = g_IV224[6];
	ctx->cv_l[7] = g_IV224[7];
	ctx->cv_r[0] = g_IV224[8];
	ctx->cv_r[1] = g_IV224[9];
	ctx->cv_r[2] = g_IV224[10];
	ctx->cv_r[3] = g_IV224[11];
	ctx->cv_r[4] = g_IV224[12];
	ctx->cv_r[5] = g_IV224[13];
	ctx->cv_r[6] = g_IV224[14];
	ctx->cv_r[7] = g_IV224[15];

	memset(ctx->sub_msgs, 0x00, 32*sizeof(lsh_u64));
}

inline void init256(LSH512_Context* ctx)
{
	ctx->cv_l[0] = g_IV256[0];
	ctx->cv_l[1] = g_IV256[1];
	ctx->cv_l[2] = g_IV256[2];
	ctx->cv_l[3] = g_IV256[3];
	ctx->cv_l[4] = g_IV256[4];
	ctx->cv_l[5] = g_IV256[5];
	ctx->cv_l[6] = g_IV256[6];
	ctx->cv_l[7] = g_IV256[7];
	ctx->cv_r[0] = g_IV256[8];
	ctx->cv_r[1] = g_IV256[9];
	ctx->cv_r[2] = g_IV256[10];
	ctx->cv_r[3] = g_IV256[11];
	ctx->cv_r[4] = g_IV256[12];
	ctx->cv_r[5] = g_IV256[13];
	ctx->cv_r[6] = g_IV256[14];
	ctx->cv_r[7] = g_IV256[15];

	memset(ctx->sub_msgs, 0x00, 32*sizeof(lsh_u64));
}

inline void init384(LSH512_Context* ctx)
{
	ctx->cv_l[0] = g_IV384[0];
	ctx->cv_l[1] = g_IV384[1];
	ctx->cv_l[2] = g_IV384[2];
	ctx->cv_l[3] = g_IV384[3];
	ctx->cv_l[4] = g_IV384[4];
	ctx->cv_l[5] = g_IV384[5];
	ctx->cv_l[6] = g_IV384[6];
	ctx->cv_l[7] = g_IV384[7];
	ctx->cv_r[0] = g_IV384[8];
	ctx->cv_r[1] = g_IV384[9];
	ctx->cv_r[2] = g_IV384[10];
	ctx->cv_r[3] = g_IV384[11];
	ctx->cv_r[4] = g_IV384[12];
	ctx->cv_r[5] = g_IV384[13];
	ctx->cv_r[6] = g_IV384[14];
	ctx->cv_r[7] = g_IV384[15];

	memset(ctx->sub_msgs, 0x00, 32*sizeof(lsh_u64));
}

inline void init512(LSH512_Context* ctx)
{
	ctx->cv_l[0] = g_IV512[0];
	ctx->cv_l[1] = g_IV512[1];
	ctx->cv_l[2] = g_IV512[2];
	ctx->cv_l[3] = g_IV512[3];
	ctx->cv_l[4] = g_IV512[4];
	ctx->cv_l[5] = g_IV512[5];
	ctx->cv_l[6] = g_IV512[6];
	ctx->cv_l[7] = g_IV512[7];
	ctx->cv_r[0] = g_IV512[8];
	ctx->cv_r[1] = g_IV512[9];
	ctx->cv_r[2] = g_IV512[10];
	ctx->cv_r[3] = g_IV512[11];
	ctx->cv_r[4] = g_IV512[12];
	ctx->cv_r[5] = g_IV512[13];
	ctx->cv_r[6] = g_IV512[14];
	ctx->cv_r[7] = g_IV512[15];

	memset(ctx->sub_msgs, 0x00, 32*sizeof(lsh_u64));
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

inline void get_hash(LSH512_Context* ctx, lsh_u8 * pbHashVal)
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

lsh_err lsh512_init(LSH512_Context* ctx)
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

	memset(cv_l, 0, 8 * sizeof(lsh_u64));
	memset(cv_r, 0, 8 * sizeof(lsh_u64));
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

lsh_err lsh512_update(LSH512_Context* ctx, const lsh_u8 * data, size_t databitlen)
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
	lsh_uint remain_msg_bit = 0;

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
		compress(ctx, (lsh_u64*)ctx->last_block);
		data += more_byte;
		databytelen -= more_byte;
		remain_msg_byte = 0;
		ctx->remain_databitlen = 0;
	}

	while (databytelen >= LSH512_MSG_BLK_BYTE_LEN)
	{
		compress(ctx, (lsh_u64*)data);
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

lsh_err lsh512_final(LSH512_Context* ctx, lsh_u8* hashval)
{
	CRYPTOPP_ASSERT(ctx != NULLPTR);
	CRYPTOPP_ASSERT(hashval != NULLPTR);

	// We are byte oriented. remain_msg_bit will always be 0.
	lsh_uint remain_msg_byte = ctx->remain_databitlen >> 3;
	// lsh_uint remain_msg_bit = ctx->remain_databitlen & 7;
	lsh_uint remain_msg_bit = 0;

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

	compress(ctx, (lsh_u64*)ctx->last_block);

	fin(ctx);
	get_hash(ctx, hashval);

	return LSH_SUCCESS;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

std::string LSH512_Base::AlgorithmProvider() const
{
#if defined(__SSE2__)
	return "SSE2";
#else
	return "C++";
#endif
}

void LSH512_Base::Restart()
{
	LSH512_Context ctx(m_state, m_algType, m_remainingBitLength);
	lsh_err err = lsh512_init(&ctx);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_init failed");
}

void LSH512_Base::Update(const byte *input, size_t length)
{
	CRYPTOPP_ASSERT(input != NULLPTR);
	CRYPTOPP_ASSERT(length);

	LSH512_Context ctx(m_state, m_algType, m_remainingBitLength);
	lsh_err err = lsh512_update(&ctx, input, 8*length);

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_update failed");
}

void LSH512_Base::TruncatedFinal(byte *hash, size_t size)
{
	CRYPTOPP_ASSERT(hash != NULLPTR);
	ThrowIfInvalidTruncatedSize(size);

	LSH512_Context ctx(m_state, m_algType, m_remainingBitLength);
	lsh_err err;

	if (size >= DigestSize())
	{
		err = lsh512_final(&ctx, hash);
	}
	else
	{
		// TODO: determine if LSH512 supports truncated hashes. See the code in get_hash(),
		// where a bit-length is added to the last output byte of the hash function.
		// CRYPTOPP_ASSERT(0);

		byte fullHash[HASH_VAL_MAX_WORD_LEN * sizeof(lsh_uint)];
		err = lsh512_final(&ctx, fullHash);
		memcpy(hash, fullHash, size);
	}

	if (err != LSH_SUCCESS)
		throw Exception(Exception::OTHER_ERROR, "LSH512_Base: lsh512_final failed");

    Restart();
}

NAMESPACE_END
