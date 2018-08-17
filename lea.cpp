// lea.cpp - written and placed in the public domain by Kim Sung Hee and Jeffrey Walton
//           Based on "LEA: A 128-Bit Block Cipher for Fast Encryption on Common
//           Processors" by Deukjo Hong, Jung-Keun Lee, Dong-Chan Kim, Daesung Kwon,
//           Kwon Ho Ryu, and Dong-Geon Lee.
//
//           This implementation is based on source files found in a zip file at the
//           Korea Internet and Security Agency (https://www.kisa.or.kr/eng/main.jsp).
//           The zip files was downloaded from the Korean language area of the site so we
//           don't have a url or english zip filename to cite. The source filename from
//           the zip is lea_core.c.
//
//           The LEA team appears to have applied optimizations to functions in lea_core.c.
//           The implementation does not exactly follow the aglorithmic description from
//           the LEA paper.

#include "pch.h"
#include "config.h"

#include "lea.h"
#include "misc.h"
#include "cpu.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::word32;
using CryptoPP::rotlConstant;

ANONYMOUS_NAMESPACE_END

const word32 delta[8][36] = {
    {0xc3efe9db, 0x87dfd3b7, 0x0fbfa76f, 0x1f7f4ede, 0x3efe9dbc, 0x7dfd3b78, 0xfbfa76f0, 0xf7f4ede1,
    0xefe9dbc3, 0xdfd3b787, 0xbfa76f0f, 0x7f4ede1f, 0xfe9dbc3e, 0xfd3b787d, 0xfa76f0fb, 0xf4ede1f7,
    0xe9dbc3ef, 0xd3b787df, 0xa76f0fbf, 0x4ede1f7f, 0x9dbc3efe, 0x3b787dfd, 0x76f0fbfa, 0xede1f7f4,
    0xdbc3efe9, 0xb787dfd3, 0x6f0fbfa7, 0xde1f7f4e, 0xbc3efe9d, 0x787dfd3b, 0xf0fbfa76, 0xe1f7f4eD,
    0xc3efe9db,    0x87dfd3b7, 0x0fbfa76f, 0x1f7f4ede},
    {0x44626b02, 0x88c4d604, 0x1189ac09, 0x23135812, 0x4626b024, 0x8c4d6048, 0x189ac091, 0x31358122,
    0x626b0244, 0xc4d60488, 0x89ac0911, 0x13581223, 0x26b02446, 0x4d60488c, 0x9ac09118, 0x35812231,
    0x6b024462, 0xd60488c4, 0xac091189, 0x58122313, 0xb0244626, 0x60488c4d, 0xc091189a, 0x81223135,
    0x0244626b, 0x0488c4d6, 0x091189ac, 0x12231358, 0x244626b0, 0x488c4d60, 0x91189ac0, 0x22313581,
    0x44626b02, 0x88c4d604, 0x1189ac09, 0x23135812},
    {0x79e27c8a, 0xf3c4f914, 0xe789f229, 0xcf13e453, 0x9e27c8a7, 0x3c4f914f, 0x789f229e, 0xf13e453c,
    0xe27c8a79, 0xc4f914f3, 0x89f229e7, 0x13e453cf, 0x27c8a79e, 0x4f914f3c, 0x9f229e78, 0x3e453cf1,
    0x7c8a79e2, 0xf914f3c4, 0xf229e789, 0xe453cf13, 0xc8a79e27, 0x914f3c4f, 0x229e789f, 0x453cf13e,
    0x8a79e27c, 0x14f3c4f9, 0x29e789f2, 0x53cf13e4, 0xa79e27c8, 0x4f3c4f91, 0x9e789f22, 0x3cf13e45,
    0x79e27c8a, 0xf3c4f914, 0xe789f229, 0xcf13e453},
    {0x78df30ec, 0xf1be61d8, 0xe37cc3b1, 0xc6f98763, 0x8df30ec7, 0x1be61d8f, 0x37cc3b1e, 0x6f98763c,
    0xdf30ec78, 0xbe61d8f1, 0x7cc3b1e3, 0xf98763c6, 0xf30ec78d, 0xe61d8f1b, 0xcc3b1e37, 0x98763c6f,
    0x30ec78df, 0x61d8f1be, 0xc3b1e37c, 0x8763c6f9, 0x0ec78df3, 0x1d8f1be6, 0x3b1e37cc, 0x763c6f98,
    0xec78df30, 0xd8f1be61, 0xb1e37cc3, 0x63c6f987, 0xc78df30e, 0x8f1be61d, 0x1e37cc3b, 0x3c6f9876,
    0x78df30ec,    0xf1be61d8, 0xe37cc3b1, 0xc6f98763},
    {0x715ea49e, 0xe2bd493c, 0xc57a9279, 0x8af524f3, 0x15ea49e7, 0x2bd493ce, 0x57a9279c, 0xaf524f38,
    0x5ea49e71, 0xbd493ce2, 0x7a9279c5, 0xf524f38a, 0xea49e715, 0xd493ce2b, 0xa9279c57, 0x524f38af,
    0xa49e715e, 0x493ce2bd, 0x9279c57a, 0x24f38af5, 0x49e715ea, 0x93ce2bd4, 0x279c57a9, 0x4f38af52,
    0x9e715ea4, 0x3ce2bd49, 0x79c57a92, 0xf38af524, 0xe715ea49, 0xce2bd493, 0x9c57a927, 0x38af524f,
    0x715ea49e,    0xe2bd493c, 0xc57a9279, 0x8af524f3},
    {0xc785da0a, 0x8f0bb415, 0x1e17682b, 0x3c2ed056, 0x785da0ac, 0xf0bb4158, 0xe17682b1, 0xc2ed0563,
    0x85da0ac7, 0x0bb4158f, 0x17682b1e, 0x2ed0563c, 0x5da0ac78, 0xbb4158f0, 0x7682b1e1, 0xed0563c2,
    0xda0ac785, 0xb4158f0b, 0x682b1e17, 0xd0563c2e, 0xa0ac785d, 0x4158f0bb, 0x82b1e176, 0x0563c2ed,
    0x0ac785da, 0x158f0bb4, 0x2b1e1768, 0x563c2ed0, 0xac785da0, 0x58f0bb41, 0xb1e17682, 0x63c2ed05,
    0xc785da0a, 0x8f0bb415, 0x1e17682b, 0x3c2ed056},
    {0xe04ef22a, 0xc09de455, 0x813bc8ab, 0x02779157, 0x04ef22ae, 0x09de455c, 0x13bc8ab8, 0x27791570,
    0x4ef22ae0, 0x9de455c0, 0x3bc8ab81, 0x77915702, 0xef22ae04, 0xde455c09, 0xbc8ab813, 0x79157027,
    0xf22ae04e, 0xe455c09d, 0xc8ab813b, 0x91570277, 0x22ae04ef, 0x455c09de, 0x8ab813bc, 0x15702779,
    0x2ae04ef2, 0x55c09de4, 0xab813bc8, 0x57027791, 0xae04ef22, 0x5c09de45, 0xb813bc8a, 0x70277915,
    0xe04ef22a,    0xc09de455, 0x813bc8ab, 0x02779157},
    {0xe5c40957, 0xcb8812af, 0x9710255f, 0x2e204abf, 0x5c40957e, 0xb8812afc, 0x710255f9, 0xe204abf2,
    0xc40957e5, 0x8812afcb, 0x10255f97, 0x204abf2e, 0x40957e5c, 0x812afcb8, 0x0255f971, 0x04abf2e2,
    0x0957e5c4, 0x12afcb88, 0x255f9710, 0x4abf2e20, 0x957e5c40, 0x2afcb881, 0x55f97102, 0xabf2e204,
    0x57e5c409, 0xafcb8812, 0x5f971025, 0xbf2e204a, 0x7e5c4095, 0xfcb8812a, 0xf9710255, 0xf2e204ab,
    0xe5c40957,    0xcb8812af, 0x9710255f, 0x2e204abf}
};

inline void SetKey128(word32 rkey[144], const word32 key[4])
{
    rkey[  0] = rotlConstant<1>( key[  0] + delta[0][ 0]);
    rkey[  6] = rotlConstant<1>(rkey[  0] + delta[1][ 1]);
    rkey[ 12] = rotlConstant<1>(rkey[  6] + delta[2][ 2]);
    rkey[ 18] = rotlConstant<1>(rkey[ 12] + delta[3][ 3]);
    rkey[ 24] = rotlConstant<1>(rkey[ 18] + delta[0][ 4]);
    rkey[ 30] = rotlConstant<1>(rkey[ 24] + delta[1][ 5]);
    rkey[ 36] = rotlConstant<1>(rkey[ 30] + delta[2][ 6]);
    rkey[ 42] = rotlConstant<1>(rkey[ 36] + delta[3][ 7]);
    rkey[ 48] = rotlConstant<1>(rkey[ 42] + delta[0][ 8]);
    rkey[ 54] = rotlConstant<1>(rkey[ 48] + delta[1][ 9]);
    rkey[ 60] = rotlConstant<1>(rkey[ 54] + delta[2][10]);
    rkey[ 66] = rotlConstant<1>(rkey[ 60] + delta[3][11]);
    rkey[ 72] = rotlConstant<1>(rkey[ 66] + delta[0][12]);
    rkey[ 78] = rotlConstant<1>(rkey[ 72] + delta[1][13]);
    rkey[ 84] = rotlConstant<1>(rkey[ 78] + delta[2][14]);
    rkey[ 90] = rotlConstant<1>(rkey[ 84] + delta[3][15]);
    rkey[ 96] = rotlConstant<1>(rkey[ 90] + delta[0][16]);
    rkey[102] = rotlConstant<1>(rkey[ 96] + delta[1][17]);
    rkey[108] = rotlConstant<1>(rkey[102] + delta[2][18]);
    rkey[114] = rotlConstant<1>(rkey[108] + delta[3][19]);
    rkey[120] = rotlConstant<1>(rkey[114] + delta[0][20]);
    rkey[126] = rotlConstant<1>(rkey[120] + delta[1][21]);
    rkey[132] = rotlConstant<1>(rkey[126] + delta[2][22]);
    rkey[138] = rotlConstant<1>(rkey[132] + delta[3][23]);

    rkey[  1] = rkey[  3] = rkey[  5] = rotlConstant<3>( key[  1] + delta[0][ 1]);
    rkey[  7] = rkey[  9] = rkey[ 11] = rotlConstant<3>(rkey[  1] + delta[1][ 2]);
    rkey[ 13] = rkey[ 15] = rkey[ 17] = rotlConstant<3>(rkey[  7] + delta[2][ 3]);
    rkey[ 19] = rkey[ 21] = rkey[ 23] = rotlConstant<3>(rkey[ 13] + delta[3][ 4]);
    rkey[ 25] = rkey[ 27] = rkey[ 29] = rotlConstant<3>(rkey[ 19] + delta[0][ 5]);
    rkey[ 31] = rkey[ 33] = rkey[ 35] = rotlConstant<3>(rkey[ 25] + delta[1][ 6]);
    rkey[ 37] = rkey[ 39] = rkey[ 41] = rotlConstant<3>(rkey[ 31] + delta[2][ 7]);
    rkey[ 43] = rkey[ 45] = rkey[ 47] = rotlConstant<3>(rkey[ 37] + delta[3][ 8]);
    rkey[ 49] = rkey[ 51] = rkey[ 53] = rotlConstant<3>(rkey[ 43] + delta[0][ 9]);
    rkey[ 55] = rkey[ 57] = rkey[ 59] = rotlConstant<3>(rkey[ 49] + delta[1][10]);
    rkey[ 61] = rkey[ 63] = rkey[ 65] = rotlConstant<3>(rkey[ 55] + delta[2][11]);
    rkey[ 67] = rkey[ 69] = rkey[ 71] = rotlConstant<3>(rkey[ 61] + delta[3][12]);
    rkey[ 73] = rkey[ 75] = rkey[ 77] = rotlConstant<3>(rkey[ 67] + delta[0][13]);
    rkey[ 79] = rkey[ 81] = rkey[ 83] = rotlConstant<3>(rkey[ 73] + delta[1][14]);
    rkey[ 85] = rkey[ 87] = rkey[ 89] = rotlConstant<3>(rkey[ 79] + delta[2][15]);
    rkey[ 91] = rkey[ 93] = rkey[ 95] = rotlConstant<3>(rkey[ 85] + delta[3][16]);
    rkey[ 97] = rkey[ 99] = rkey[101] = rotlConstant<3>(rkey[ 91] + delta[0][17]);
    rkey[103] = rkey[105] = rkey[107] = rotlConstant<3>(rkey[ 97] + delta[1][18]);
    rkey[109] = rkey[111] = rkey[113] = rotlConstant<3>(rkey[103] + delta[2][19]);
    rkey[115] = rkey[117] = rkey[119] = rotlConstant<3>(rkey[109] + delta[3][20]);
    rkey[121] = rkey[123] = rkey[125] = rotlConstant<3>(rkey[115] + delta[0][21]);
    rkey[127] = rkey[129] = rkey[131] = rotlConstant<3>(rkey[121] + delta[1][22]);
    rkey[133] = rkey[135] = rkey[137] = rotlConstant<3>(rkey[127] + delta[2][23]);
    rkey[139] = rkey[141] = rkey[143] = rotlConstant<3>(rkey[133] + delta[3][24]);

    rkey[  2] = rotlConstant<6>( key[  2] + delta[0][ 2]);
    rkey[  8] = rotlConstant<6>(rkey[  2] + delta[1][ 3]);
    rkey[ 14] = rotlConstant<6>(rkey[  8] + delta[2][ 4]);
    rkey[ 20] = rotlConstant<6>(rkey[ 14] + delta[3][ 5]);
    rkey[ 26] = rotlConstant<6>(rkey[ 20] + delta[0][ 6]);
    rkey[ 32] = rotlConstant<6>(rkey[ 26] + delta[1][ 7]);
    rkey[ 38] = rotlConstant<6>(rkey[ 32] + delta[2][ 8]);
    rkey[ 44] = rotlConstant<6>(rkey[ 38] + delta[3][ 9]);
    rkey[ 50] = rotlConstant<6>(rkey[ 44] + delta[0][10]);
    rkey[ 56] = rotlConstant<6>(rkey[ 50] + delta[1][11]);
    rkey[ 62] = rotlConstant<6>(rkey[ 56] + delta[2][12]);
    rkey[ 68] = rotlConstant<6>(rkey[ 62] + delta[3][13]);
    rkey[ 74] = rotlConstant<6>(rkey[ 68] + delta[0][14]);
    rkey[ 80] = rotlConstant<6>(rkey[ 74] + delta[1][15]);
    rkey[ 86] = rotlConstant<6>(rkey[ 80] + delta[2][16]);
    rkey[ 92] = rotlConstant<6>(rkey[ 86] + delta[3][17]);
    rkey[ 98] = rotlConstant<6>(rkey[ 92] + delta[0][18]);
    rkey[104] = rotlConstant<6>(rkey[ 98] + delta[1][19]);
    rkey[110] = rotlConstant<6>(rkey[104] + delta[2][20]);
    rkey[116] = rotlConstant<6>(rkey[110] + delta[3][21]);
    rkey[122] = rotlConstant<6>(rkey[116] + delta[0][22]);
    rkey[128] = rotlConstant<6>(rkey[122] + delta[1][23]);
    rkey[134] = rotlConstant<6>(rkey[128] + delta[2][24]);
    rkey[140] = rotlConstant<6>(rkey[134] + delta[3][25]);

    rkey[  4] = rotlConstant<11>( key[  3] + delta[0][ 3]);
    rkey[ 10] = rotlConstant<11>(rkey[  4] + delta[1][ 4]);
    rkey[ 16] = rotlConstant<11>(rkey[ 10] + delta[2][ 5]);
    rkey[ 22] = rotlConstant<11>(rkey[ 16] + delta[3][ 6]);
    rkey[ 28] = rotlConstant<11>(rkey[ 22] + delta[0][ 7]);
    rkey[ 34] = rotlConstant<11>(rkey[ 28] + delta[1][ 8]);
    rkey[ 40] = rotlConstant<11>(rkey[ 34] + delta[2][ 9]);
    rkey[ 46] = rotlConstant<11>(rkey[ 40] + delta[3][10]);
    rkey[ 52] = rotlConstant<11>(rkey[ 46] + delta[0][11]);
    rkey[ 58] = rotlConstant<11>(rkey[ 52] + delta[1][12]);
    rkey[ 64] = rotlConstant<11>(rkey[ 58] + delta[2][13]);
    rkey[ 70] = rotlConstant<11>(rkey[ 64] + delta[3][14]);
    rkey[ 76] = rotlConstant<11>(rkey[ 70] + delta[0][15]);
    rkey[ 82] = rotlConstant<11>(rkey[ 76] + delta[1][16]);
    rkey[ 88] = rotlConstant<11>(rkey[ 82] + delta[2][17]);
    rkey[ 94] = rotlConstant<11>(rkey[ 88] + delta[3][18]);
    rkey[100] = rotlConstant<11>(rkey[ 94] + delta[0][19]);
    rkey[106] = rotlConstant<11>(rkey[100] + delta[1][20]);
    rkey[112] = rotlConstant<11>(rkey[106] + delta[2][21]);
    rkey[118] = rotlConstant<11>(rkey[112] + delta[3][22]);
    rkey[124] = rotlConstant<11>(rkey[118] + delta[0][23]);
    rkey[130] = rotlConstant<11>(rkey[124] + delta[1][24]);
    rkey[136] = rotlConstant<11>(rkey[130] + delta[2][25]);
    rkey[142] = rotlConstant<11>(rkey[136] + delta[3][26]);
}

inline void SetKey192(word32 rkey[168], const word32 key[6])
{
    rkey[  0] = rotlConstant<1>( key[  0] + delta[0][ 0]);
    rkey[  6] = rotlConstant<1>(rkey[  0] + delta[1][ 1]);
    rkey[ 12] = rotlConstant<1>(rkey[  6] + delta[2][ 2]);
    rkey[ 18] = rotlConstant<1>(rkey[ 12] + delta[3][ 3]);
    rkey[ 24] = rotlConstant<1>(rkey[ 18] + delta[4][ 4]);
    rkey[ 30] = rotlConstant<1>(rkey[ 24] + delta[5][ 5]);
    rkey[ 36] = rotlConstant<1>(rkey[ 30] + delta[0][ 6]);
    rkey[ 42] = rotlConstant<1>(rkey[ 36] + delta[1][ 7]);
    rkey[ 48] = rotlConstant<1>(rkey[ 42] + delta[2][ 8]);
    rkey[ 54] = rotlConstant<1>(rkey[ 48] + delta[3][ 9]);
    rkey[ 60] = rotlConstant<1>(rkey[ 54] + delta[4][10]);
    rkey[ 66] = rotlConstant<1>(rkey[ 60] + delta[5][11]);
    rkey[ 72] = rotlConstant<1>(rkey[ 66] + delta[0][12]);
    rkey[ 78] = rotlConstant<1>(rkey[ 72] + delta[1][13]);
    rkey[ 84] = rotlConstant<1>(rkey[ 78] + delta[2][14]);
    rkey[ 90] = rotlConstant<1>(rkey[ 84] + delta[3][15]);
    rkey[ 96] = rotlConstant<1>(rkey[ 90] + delta[4][16]);
    rkey[102] = rotlConstant<1>(rkey[ 96] + delta[5][17]);
    rkey[108] = rotlConstant<1>(rkey[102] + delta[0][18]);
    rkey[114] = rotlConstant<1>(rkey[108] + delta[1][19]);
    rkey[120] = rotlConstant<1>(rkey[114] + delta[2][20]);
    rkey[126] = rotlConstant<1>(rkey[120] + delta[3][21]);
    rkey[132] = rotlConstant<1>(rkey[126] + delta[4][22]);
    rkey[138] = rotlConstant<1>(rkey[132] + delta[5][23]);
    rkey[144] = rotlConstant<1>(rkey[138] + delta[0][24]);
    rkey[150] = rotlConstant<1>(rkey[144] + delta[1][25]);
    rkey[156] = rotlConstant<1>(rkey[150] + delta[2][26]);
    rkey[162] = rotlConstant<1>(rkey[156] + delta[3][27]);

    rkey[  1] = rotlConstant<3>( key[  1] + delta[0][ 1]);
    rkey[  7] = rotlConstant<3>(rkey[  1] + delta[1][ 2]);
    rkey[ 13] = rotlConstant<3>(rkey[  7] + delta[2][ 3]);
    rkey[ 19] = rotlConstant<3>(rkey[ 13] + delta[3][ 4]);
    rkey[ 25] = rotlConstant<3>(rkey[ 19] + delta[4][ 5]);
    rkey[ 31] = rotlConstant<3>(rkey[ 25] + delta[5][ 6]);
    rkey[ 37] = rotlConstant<3>(rkey[ 31] + delta[0][ 7]);
    rkey[ 43] = rotlConstant<3>(rkey[ 37] + delta[1][ 8]);
    rkey[ 49] = rotlConstant<3>(rkey[ 43] + delta[2][ 9]);
    rkey[ 55] = rotlConstant<3>(rkey[ 49] + delta[3][10]);
    rkey[ 61] = rotlConstant<3>(rkey[ 55] + delta[4][11]);
    rkey[ 67] = rotlConstant<3>(rkey[ 61] + delta[5][12]);
    rkey[ 73] = rotlConstant<3>(rkey[ 67] + delta[0][13]);
    rkey[ 79] = rotlConstant<3>(rkey[ 73] + delta[1][14]);
    rkey[ 85] = rotlConstant<3>(rkey[ 79] + delta[2][15]);
    rkey[ 91] = rotlConstant<3>(rkey[ 85] + delta[3][16]);
    rkey[ 97] = rotlConstant<3>(rkey[ 91] + delta[4][17]);
    rkey[103] = rotlConstant<3>(rkey[ 97] + delta[5][18]);
    rkey[109] = rotlConstant<3>(rkey[103] + delta[0][19]);
    rkey[115] = rotlConstant<3>(rkey[109] + delta[1][20]);
    rkey[121] = rotlConstant<3>(rkey[115] + delta[2][21]);
    rkey[127] = rotlConstant<3>(rkey[121] + delta[3][22]);
    rkey[133] = rotlConstant<3>(rkey[127] + delta[4][23]);
    rkey[139] = rotlConstant<3>(rkey[133] + delta[5][24]);
    rkey[145] = rotlConstant<3>(rkey[139] + delta[0][25]);
    rkey[151] = rotlConstant<3>(rkey[145] + delta[1][26]);
    rkey[157] = rotlConstant<3>(rkey[151] + delta[2][27]);
    rkey[163] = rotlConstant<3>(rkey[157] + delta[3][28]);

    rkey[  2] = rotlConstant<6>( key[  2] + delta[0][ 2]);
    rkey[  8] = rotlConstant<6>(rkey[  2] + delta[1][ 3]);
    rkey[ 14] = rotlConstant<6>(rkey[  8] + delta[2][ 4]);
    rkey[ 20] = rotlConstant<6>(rkey[ 14] + delta[3][ 5]);
    rkey[ 26] = rotlConstant<6>(rkey[ 20] + delta[4][ 6]);
    rkey[ 32] = rotlConstant<6>(rkey[ 26] + delta[5][ 7]);
    rkey[ 38] = rotlConstant<6>(rkey[ 32] + delta[0][ 8]);
    rkey[ 44] = rotlConstant<6>(rkey[ 38] + delta[1][ 9]);
    rkey[ 50] = rotlConstant<6>(rkey[ 44] + delta[2][10]);
    rkey[ 56] = rotlConstant<6>(rkey[ 50] + delta[3][11]);
    rkey[ 62] = rotlConstant<6>(rkey[ 56] + delta[4][12]);
    rkey[ 68] = rotlConstant<6>(rkey[ 62] + delta[5][13]);
    rkey[ 74] = rotlConstant<6>(rkey[ 68] + delta[0][14]);
    rkey[ 80] = rotlConstant<6>(rkey[ 74] + delta[1][15]);
    rkey[ 86] = rotlConstant<6>(rkey[ 80] + delta[2][16]);
    rkey[ 92] = rotlConstant<6>(rkey[ 86] + delta[3][17]);
    rkey[ 98] = rotlConstant<6>(rkey[ 92] + delta[4][18]);
    rkey[104] = rotlConstant<6>(rkey[ 98] + delta[5][19]);
    rkey[110] = rotlConstant<6>(rkey[104] + delta[0][20]);
    rkey[116] = rotlConstant<6>(rkey[110] + delta[1][21]);
    rkey[122] = rotlConstant<6>(rkey[116] + delta[2][22]);
    rkey[128] = rotlConstant<6>(rkey[122] + delta[3][23]);
    rkey[134] = rotlConstant<6>(rkey[128] + delta[4][24]);
    rkey[140] = rotlConstant<6>(rkey[134] + delta[5][25]);
    rkey[146] = rotlConstant<6>(rkey[140] + delta[0][26]);
    rkey[152] = rotlConstant<6>(rkey[146] + delta[1][27]);
    rkey[158] = rotlConstant<6>(rkey[152] + delta[2][28]);
    rkey[164] = rotlConstant<6>(rkey[158] + delta[3][29]);

    rkey[  3] = rotlConstant<11>( key[  3] + delta[0][ 3]);
    rkey[  9] = rotlConstant<11>(rkey[  3] + delta[1][ 4]);
    rkey[ 15] = rotlConstant<11>(rkey[  9] + delta[2][ 5]);
    rkey[ 21] = rotlConstant<11>(rkey[ 15] + delta[3][ 6]);
    rkey[ 27] = rotlConstant<11>(rkey[ 21] + delta[4][ 7]);
    rkey[ 33] = rotlConstant<11>(rkey[ 27] + delta[5][ 8]);
    rkey[ 39] = rotlConstant<11>(rkey[ 33] + delta[0][ 9]);
    rkey[ 45] = rotlConstant<11>(rkey[ 39] + delta[1][10]);
    rkey[ 51] = rotlConstant<11>(rkey[ 45] + delta[2][11]);
    rkey[ 57] = rotlConstant<11>(rkey[ 51] + delta[3][12]);
    rkey[ 63] = rotlConstant<11>(rkey[ 57] + delta[4][13]);
    rkey[ 69] = rotlConstant<11>(rkey[ 63] + delta[5][14]);
    rkey[ 75] = rotlConstant<11>(rkey[ 69] + delta[0][15]);
    rkey[ 81] = rotlConstant<11>(rkey[ 75] + delta[1][16]);
    rkey[ 87] = rotlConstant<11>(rkey[ 81] + delta[2][17]);
    rkey[ 93] = rotlConstant<11>(rkey[ 87] + delta[3][18]);
    rkey[ 99] = rotlConstant<11>(rkey[ 93] + delta[4][19]);
    rkey[105] = rotlConstant<11>(rkey[ 99] + delta[5][20]);
    rkey[111] = rotlConstant<11>(rkey[105] + delta[0][21]);
    rkey[117] = rotlConstant<11>(rkey[111] + delta[1][22]);
    rkey[123] = rotlConstant<11>(rkey[117] + delta[2][23]);
    rkey[129] = rotlConstant<11>(rkey[123] + delta[3][24]);
    rkey[135] = rotlConstant<11>(rkey[129] + delta[4][25]);
    rkey[141] = rotlConstant<11>(rkey[135] + delta[5][26]);
    rkey[147] = rotlConstant<11>(rkey[141] + delta[0][27]);
    rkey[153] = rotlConstant<11>(rkey[147] + delta[1][28]);
    rkey[159] = rotlConstant<11>(rkey[153] + delta[2][29]);
    rkey[165] = rotlConstant<11>(rkey[159] + delta[3][30]);

    rkey[  4] = rotlConstant<13>( key[  4] + delta[0][ 4]);
    rkey[ 10] = rotlConstant<13>(rkey[  4] + delta[1][ 5]);
    rkey[ 16] = rotlConstant<13>(rkey[ 10] + delta[2][ 6]);
    rkey[ 22] = rotlConstant<13>(rkey[ 16] + delta[3][ 7]);
    rkey[ 28] = rotlConstant<13>(rkey[ 22] + delta[4][ 8]);
    rkey[ 34] = rotlConstant<13>(rkey[ 28] + delta[5][ 9]);
    rkey[ 40] = rotlConstant<13>(rkey[ 34] + delta[0][10]);
    rkey[ 46] = rotlConstant<13>(rkey[ 40] + delta[1][11]);
    rkey[ 52] = rotlConstant<13>(rkey[ 46] + delta[2][12]);
    rkey[ 58] = rotlConstant<13>(rkey[ 52] + delta[3][13]);
    rkey[ 64] = rotlConstant<13>(rkey[ 58] + delta[4][14]);
    rkey[ 70] = rotlConstant<13>(rkey[ 64] + delta[5][15]);
    rkey[ 76] = rotlConstant<13>(rkey[ 70] + delta[0][16]);
    rkey[ 82] = rotlConstant<13>(rkey[ 76] + delta[1][17]);
    rkey[ 88] = rotlConstant<13>(rkey[ 82] + delta[2][18]);
    rkey[ 94] = rotlConstant<13>(rkey[ 88] + delta[3][19]);
    rkey[100] = rotlConstant<13>(rkey[ 94] + delta[4][20]);
    rkey[106] = rotlConstant<13>(rkey[100] + delta[5][21]);
    rkey[112] = rotlConstant<13>(rkey[106] + delta[0][22]);
    rkey[118] = rotlConstant<13>(rkey[112] + delta[1][23]);
    rkey[124] = rotlConstant<13>(rkey[118] + delta[2][24]);
    rkey[130] = rotlConstant<13>(rkey[124] + delta[3][25]);
    rkey[136] = rotlConstant<13>(rkey[130] + delta[4][26]);
    rkey[142] = rotlConstant<13>(rkey[136] + delta[5][27]);
    rkey[148] = rotlConstant<13>(rkey[142] + delta[0][28]);
    rkey[154] = rotlConstant<13>(rkey[148] + delta[1][29]);
    rkey[160] = rotlConstant<13>(rkey[154] + delta[2][30]);
    rkey[166] = rotlConstant<13>(rkey[160] + delta[3][31]);

    rkey[  5] = rotlConstant<17>( key[  5] + delta[0][ 5]);
    rkey[ 11] = rotlConstant<17>(rkey[  5] + delta[1][ 6]);
    rkey[ 17] = rotlConstant<17>(rkey[ 11] + delta[2][ 7]);
    rkey[ 23] = rotlConstant<17>(rkey[ 17] + delta[3][ 8]);
    rkey[ 29] = rotlConstant<17>(rkey[ 23] + delta[4][ 9]);
    rkey[ 35] = rotlConstant<17>(rkey[ 29] + delta[5][10]);
    rkey[ 41] = rotlConstant<17>(rkey[ 35] + delta[0][11]);
    rkey[ 47] = rotlConstant<17>(rkey[ 41] + delta[1][12]);
    rkey[ 53] = rotlConstant<17>(rkey[ 47] + delta[2][13]);
    rkey[ 59] = rotlConstant<17>(rkey[ 53] + delta[3][14]);
    rkey[ 65] = rotlConstant<17>(rkey[ 59] + delta[4][15]);
    rkey[ 71] = rotlConstant<17>(rkey[ 65] + delta[5][16]);
    rkey[ 77] = rotlConstant<17>(rkey[ 71] + delta[0][17]);
    rkey[ 83] = rotlConstant<17>(rkey[ 77] + delta[1][18]);
    rkey[ 89] = rotlConstant<17>(rkey[ 83] + delta[2][19]);
    rkey[ 95] = rotlConstant<17>(rkey[ 89] + delta[3][20]);
    rkey[101] = rotlConstant<17>(rkey[ 95] + delta[4][21]);
    rkey[107] = rotlConstant<17>(rkey[101] + delta[5][22]);
    rkey[113] = rotlConstant<17>(rkey[107] + delta[0][23]);
    rkey[119] = rotlConstant<17>(rkey[113] + delta[1][24]);
    rkey[125] = rotlConstant<17>(rkey[119] + delta[2][25]);
    rkey[131] = rotlConstant<17>(rkey[125] + delta[3][26]);
    rkey[137] = rotlConstant<17>(rkey[131] + delta[4][27]);
    rkey[143] = rotlConstant<17>(rkey[137] + delta[5][28]);
    rkey[149] = rotlConstant<17>(rkey[143] + delta[0][29]);
    rkey[155] = rotlConstant<17>(rkey[149] + delta[1][30]);
    rkey[161] = rotlConstant<17>(rkey[155] + delta[2][31]);
    rkey[167] = rotlConstant<17>(rkey[161] + delta[3][ 0]);
}

inline void SetKey256(word32 rkey[192], const word32 key[8])
{
    rkey[  0] = rotlConstant< 1>( key[  0] + delta[0][ 0]);
    rkey[  8] = rotlConstant< 6>(rkey[  0] + delta[1][ 3]);
    rkey[ 16] = rotlConstant<13>(rkey[  8] + delta[2][ 6]);
    rkey[ 24] = rotlConstant< 1>(rkey[ 16] + delta[4][ 4]);
    rkey[ 32] = rotlConstant< 6>(rkey[ 24] + delta[5][ 7]);
    rkey[ 40] = rotlConstant<13>(rkey[ 32] + delta[6][10]);
    rkey[ 48] = rotlConstant< 1>(rkey[ 40] + delta[0][ 8]);
    rkey[ 56] = rotlConstant< 6>(rkey[ 48] + delta[1][11]);
    rkey[ 64] = rotlConstant<13>(rkey[ 56] + delta[2][14]);
    rkey[ 72] = rotlConstant< 1>(rkey[ 64] + delta[4][12]);
    rkey[ 80] = rotlConstant< 6>(rkey[ 72] + delta[5][15]);
    rkey[ 88] = rotlConstant<13>(rkey[ 80] + delta[6][18]);
    rkey[ 96] = rotlConstant< 1>(rkey[ 88] + delta[0][16]);
    rkey[104] = rotlConstant< 6>(rkey[ 96] + delta[1][19]);
    rkey[112] = rotlConstant<13>(rkey[104] + delta[2][22]);
    rkey[120] = rotlConstant< 1>(rkey[112] + delta[4][20]);
    rkey[128] = rotlConstant< 6>(rkey[120] + delta[5][23]);
    rkey[136] = rotlConstant<13>(rkey[128] + delta[6][26]);
    rkey[144] = rotlConstant< 1>(rkey[136] + delta[0][24]);
    rkey[152] = rotlConstant< 6>(rkey[144] + delta[1][27]);
    rkey[160] = rotlConstant<13>(rkey[152] + delta[2][30]);
    rkey[168] = rotlConstant< 1>(rkey[160] + delta[4][28]);
    rkey[176] = rotlConstant< 6>(rkey[168] + delta[5][31]);
    rkey[184] = rotlConstant<13>(rkey[176] + delta[6][ 2]);

    rkey[  1] = rotlConstant< 3>( key[  1] + delta[0][ 1]);
    rkey[  9] = rotlConstant<11>(rkey[  1] + delta[1][ 4]);
    rkey[ 17] = rotlConstant<17>(rkey[  9] + delta[2][ 7]);
    rkey[ 25] = rotlConstant< 3>(rkey[ 17] + delta[4][ 5]);
    rkey[ 33] = rotlConstant<11>(rkey[ 25] + delta[5][ 8]);
    rkey[ 41] = rotlConstant<17>(rkey[ 33] + delta[6][11]);
    rkey[ 49] = rotlConstant< 3>(rkey[ 41] + delta[0][ 9]);
    rkey[ 57] = rotlConstant<11>(rkey[ 49] + delta[1][12]);
    rkey[ 65] = rotlConstant<17>(rkey[ 57] + delta[2][15]);
    rkey[ 73] = rotlConstant< 3>(rkey[ 65] + delta[4][13]);
    rkey[ 81] = rotlConstant<11>(rkey[ 73] + delta[5][16]);
    rkey[ 89] = rotlConstant<17>(rkey[ 81] + delta[6][19]);
    rkey[ 97] = rotlConstant< 3>(rkey[ 89] + delta[0][17]);
    rkey[105] = rotlConstant<11>(rkey[ 97] + delta[1][20]);
    rkey[113] = rotlConstant<17>(rkey[105] + delta[2][23]);
    rkey[121] = rotlConstant< 3>(rkey[113] + delta[4][21]);
    rkey[129] = rotlConstant<11>(rkey[121] + delta[5][24]);
    rkey[137] = rotlConstant<17>(rkey[129] + delta[6][27]);
    rkey[145] = rotlConstant< 3>(rkey[137] + delta[0][25]);
    rkey[153] = rotlConstant<11>(rkey[145] + delta[1][28]);
    rkey[161] = rotlConstant<17>(rkey[153] + delta[2][31]);
    rkey[169] = rotlConstant< 3>(rkey[161] + delta[4][29]);
    rkey[177] = rotlConstant<11>(rkey[169] + delta[5][ 0]);
    rkey[185] = rotlConstant<17>(rkey[177] + delta[6][ 3]);

    rkey[  2] = rotlConstant< 6>( key[  2] + delta[0][ 2]);
    rkey[ 10] = rotlConstant<13>(rkey[  2] + delta[1][ 5]);
    rkey[ 18] = rotlConstant< 1>(rkey[ 10] + delta[3][ 3]);
    rkey[ 26] = rotlConstant< 6>(rkey[ 18] + delta[4][ 6]);
    rkey[ 34] = rotlConstant<13>(rkey[ 26] + delta[5][ 9]);
    rkey[ 42] = rotlConstant< 1>(rkey[ 34] + delta[7][ 7]);
    rkey[ 50] = rotlConstant< 6>(rkey[ 42] + delta[0][10]);
    rkey[ 58] = rotlConstant<13>(rkey[ 50] + delta[1][13]);
    rkey[ 66] = rotlConstant< 1>(rkey[ 58] + delta[3][11]);
    rkey[ 74] = rotlConstant< 6>(rkey[ 66] + delta[4][14]);
    rkey[ 82] = rotlConstant<13>(rkey[ 74] + delta[5][17]);
    rkey[ 90] = rotlConstant< 1>(rkey[ 82] + delta[7][15]);
    rkey[ 98] = rotlConstant< 6>(rkey[ 90] + delta[0][18]);
    rkey[106] = rotlConstant<13>(rkey[ 98] + delta[1][21]);
    rkey[114] = rotlConstant< 1>(rkey[106] + delta[3][19]);
    rkey[122] = rotlConstant< 6>(rkey[114] + delta[4][22]);
    rkey[130] = rotlConstant<13>(rkey[122] + delta[5][25]);
    rkey[138] = rotlConstant< 1>(rkey[130] + delta[7][23]);
    rkey[146] = rotlConstant< 6>(rkey[138] + delta[0][26]);
    rkey[154] = rotlConstant<13>(rkey[146] + delta[1][29]);
    rkey[162] = rotlConstant< 1>(rkey[154] + delta[3][27]);
    rkey[170] = rotlConstant< 6>(rkey[162] + delta[4][30]);
    rkey[178] = rotlConstant<13>(rkey[170] + delta[5][ 1]);
    rkey[186] = rotlConstant< 1>(rkey[178] + delta[7][31]);

    rkey[  3] = rotlConstant<11>( key[  3] + delta[0][ 3]);
    rkey[ 11] = rotlConstant<17>(rkey[  3] + delta[1][ 6]);
    rkey[ 19] = rotlConstant< 3>(rkey[ 11] + delta[3][ 4]);
    rkey[ 27] = rotlConstant<11>(rkey[ 19] + delta[4][ 7]);
    rkey[ 35] = rotlConstant<17>(rkey[ 27] + delta[5][10]);
    rkey[ 43] = rotlConstant< 3>(rkey[ 35] + delta[7][ 8]);
    rkey[ 51] = rotlConstant<11>(rkey[ 43] + delta[0][11]);
    rkey[ 59] = rotlConstant<17>(rkey[ 51] + delta[1][14]);
    rkey[ 67] = rotlConstant< 3>(rkey[ 59] + delta[3][12]);
    rkey[ 75] = rotlConstant<11>(rkey[ 67] + delta[4][15]);
    rkey[ 83] = rotlConstant<17>(rkey[ 75] + delta[5][18]);
    rkey[ 91] = rotlConstant< 3>(rkey[ 83] + delta[7][16]);
    rkey[ 99] = rotlConstant<11>(rkey[ 91] + delta[0][19]);
    rkey[107] = rotlConstant<17>(rkey[ 99] + delta[1][22]);
    rkey[115] = rotlConstant< 3>(rkey[107] + delta[3][20]);
    rkey[123] = rotlConstant<11>(rkey[115] + delta[4][23]);
    rkey[131] = rotlConstant<17>(rkey[123] + delta[5][26]);
    rkey[139] = rotlConstant< 3>(rkey[131] + delta[7][24]);
    rkey[147] = rotlConstant<11>(rkey[139] + delta[0][27]);
    rkey[155] = rotlConstant<17>(rkey[147] + delta[1][30]);
    rkey[163] = rotlConstant< 3>(rkey[155] + delta[3][28]);
    rkey[171] = rotlConstant<11>(rkey[163] + delta[4][31]);
    rkey[179] = rotlConstant<17>(rkey[171] + delta[5][ 2]);
    rkey[187] = rotlConstant< 3>(rkey[179] + delta[7][ 0]);

    rkey[  4] = rotlConstant<13>( key[  4] + delta[0][ 4]);
    rkey[ 12] = rotlConstant< 1>(rkey[  4] + delta[2][ 2]);
    rkey[ 20] = rotlConstant< 6>(rkey[ 12] + delta[3][ 5]);
    rkey[ 28] = rotlConstant<13>(rkey[ 20] + delta[4][ 8]);
    rkey[ 36] = rotlConstant< 1>(rkey[ 28] + delta[6][ 6]);
    rkey[ 44] = rotlConstant< 6>(rkey[ 36] + delta[7][ 9]);
    rkey[ 52] = rotlConstant<13>(rkey[ 44] + delta[0][12]);
    rkey[ 60] = rotlConstant< 1>(rkey[ 52] + delta[2][10]);
    rkey[ 68] = rotlConstant< 6>(rkey[ 60] + delta[3][13]);
    rkey[ 76] = rotlConstant<13>(rkey[ 68] + delta[4][16]);
    rkey[ 84] = rotlConstant< 1>(rkey[ 76] + delta[6][14]);
    rkey[ 92] = rotlConstant< 6>(rkey[ 84] + delta[7][17]);
    rkey[100] = rotlConstant<13>(rkey[ 92] + delta[0][20]);
    rkey[108] = rotlConstant< 1>(rkey[100] + delta[2][18]);
    rkey[116] = rotlConstant< 6>(rkey[108] + delta[3][21]);
    rkey[124] = rotlConstant<13>(rkey[116] + delta[4][24]);
    rkey[132] = rotlConstant< 1>(rkey[124] + delta[6][22]);
    rkey[140] = rotlConstant< 6>(rkey[132] + delta[7][25]);
    rkey[148] = rotlConstant<13>(rkey[140] + delta[0][28]);
    rkey[156] = rotlConstant< 1>(rkey[148] + delta[2][26]);
    rkey[164] = rotlConstant< 6>(rkey[156] + delta[3][29]);
    rkey[172] = rotlConstant<13>(rkey[164] + delta[4][ 0]);
    rkey[180] = rotlConstant< 1>(rkey[172] + delta[6][30]);
    rkey[188] = rotlConstant< 6>(rkey[180] + delta[7][ 1]);

    rkey[  5] = rotlConstant<17>( key[  5] + delta[0][ 5]);
    rkey[ 13] = rotlConstant< 3>(rkey[  5] + delta[2][ 3]);
    rkey[ 21] = rotlConstant<11>(rkey[ 13] + delta[3][ 6]);
    rkey[ 29] = rotlConstant<17>(rkey[ 21] + delta[4][ 9]);
    rkey[ 37] = rotlConstant< 3>(rkey[ 29] + delta[6][ 7]);
    rkey[ 45] = rotlConstant<11>(rkey[ 37] + delta[7][10]);
    rkey[ 53] = rotlConstant<17>(rkey[ 45] + delta[0][13]);
    rkey[ 61] = rotlConstant< 3>(rkey[ 53] + delta[2][11]);
    rkey[ 69] = rotlConstant<11>(rkey[ 61] + delta[3][14]);
    rkey[ 77] = rotlConstant<17>(rkey[ 69] + delta[4][17]);
    rkey[ 85] = rotlConstant< 3>(rkey[ 77] + delta[6][15]);
    rkey[ 93] = rotlConstant<11>(rkey[ 85] + delta[7][18]);
    rkey[101] = rotlConstant<17>(rkey[ 93] + delta[0][21]);
    rkey[109] = rotlConstant< 3>(rkey[101] + delta[2][19]);
    rkey[117] = rotlConstant<11>(rkey[109] + delta[3][22]);
    rkey[125] = rotlConstant<17>(rkey[117] + delta[4][25]);
    rkey[133] = rotlConstant< 3>(rkey[125] + delta[6][23]);
    rkey[141] = rotlConstant<11>(rkey[133] + delta[7][26]);
    rkey[149] = rotlConstant<17>(rkey[141] + delta[0][29]);
    rkey[157] = rotlConstant< 3>(rkey[149] + delta[2][27]);
    rkey[165] = rotlConstant<11>(rkey[157] + delta[3][30]);
    rkey[173] = rotlConstant<17>(rkey[165] + delta[4][ 1]);
    rkey[181] = rotlConstant< 3>(rkey[173] + delta[6][31]);
    rkey[189] = rotlConstant<11>(rkey[181] + delta[7][ 2]);

    rkey[  6] = rotlConstant< 1>( key[  6] + delta[1][ 1]);
    rkey[ 14] = rotlConstant< 6>(rkey[  6] + delta[2][ 4]);
    rkey[ 22] = rotlConstant<13>(rkey[ 14] + delta[3][ 7]);
    rkey[ 30] = rotlConstant< 1>(rkey[ 22] + delta[5][ 5]);
    rkey[ 38] = rotlConstant< 6>(rkey[ 30] + delta[6][ 8]);
    rkey[ 46] = rotlConstant<13>(rkey[ 38] + delta[7][11]);
    rkey[ 54] = rotlConstant< 1>(rkey[ 46] + delta[1][ 9]);
    rkey[ 62] = rotlConstant< 6>(rkey[ 54] + delta[2][12]);
    rkey[ 70] = rotlConstant<13>(rkey[ 62] + delta[3][15]);
    rkey[ 78] = rotlConstant< 1>(rkey[ 70] + delta[5][13]);
    rkey[ 86] = rotlConstant< 6>(rkey[ 78] + delta[6][16]);
    rkey[ 94] = rotlConstant<13>(rkey[ 86] + delta[7][19]);
    rkey[102] = rotlConstant< 1>(rkey[ 94] + delta[1][17]);
    rkey[110] = rotlConstant< 6>(rkey[102] + delta[2][20]);
    rkey[118] = rotlConstant<13>(rkey[110] + delta[3][23]);
    rkey[126] = rotlConstant< 1>(rkey[118] + delta[5][21]);
    rkey[134] = rotlConstant< 6>(rkey[126] + delta[6][24]);
    rkey[142] = rotlConstant<13>(rkey[134] + delta[7][27]);
    rkey[150] = rotlConstant< 1>(rkey[142] + delta[1][25]);
    rkey[158] = rotlConstant< 6>(rkey[150] + delta[2][28]);
    rkey[166] = rotlConstant<13>(rkey[158] + delta[3][31]);
    rkey[174] = rotlConstant< 1>(rkey[166] + delta[5][29]);
    rkey[182] = rotlConstant< 6>(rkey[174] + delta[6][ 0]);
    rkey[190] = rotlConstant<13>(rkey[182] + delta[7][ 3]);

    rkey[  7] = rotlConstant< 3>( key[  7] + delta[1][ 2]);
    rkey[ 15] = rotlConstant<11>(rkey[  7] + delta[2][ 5]);
    rkey[ 23] = rotlConstant<17>(rkey[ 15] + delta[3][ 8]);
    rkey[ 31] = rotlConstant< 3>(rkey[ 23] + delta[5][ 6]);
    rkey[ 39] = rotlConstant<11>(rkey[ 31] + delta[6][ 9]);
    rkey[ 47] = rotlConstant<17>(rkey[ 39] + delta[7][12]);
    rkey[ 55] = rotlConstant< 3>(rkey[ 47] + delta[1][10]);
    rkey[ 63] = rotlConstant<11>(rkey[ 55] + delta[2][13]);
    rkey[ 71] = rotlConstant<17>(rkey[ 63] + delta[3][16]);
    rkey[ 79] = rotlConstant< 3>(rkey[ 71] + delta[5][14]);
    rkey[ 87] = rotlConstant<11>(rkey[ 79] + delta[6][17]);
    rkey[ 95] = rotlConstant<17>(rkey[ 87] + delta[7][20]);
    rkey[103] = rotlConstant< 3>(rkey[ 95] + delta[1][18]);
    rkey[111] = rotlConstant<11>(rkey[103] + delta[2][21]);
    rkey[119] = rotlConstant<17>(rkey[111] + delta[3][24]);
    rkey[127] = rotlConstant< 3>(rkey[119] + delta[5][22]);
    rkey[135] = rotlConstant<11>(rkey[127] + delta[6][25]);
    rkey[143] = rotlConstant<17>(rkey[135] + delta[7][28]);
    rkey[151] = rotlConstant< 3>(rkey[143] + delta[1][26]);
    rkey[159] = rotlConstant<11>(rkey[151] + delta[2][29]);
    rkey[167] = rotlConstant<17>(rkey[159] + delta[3][ 0]);
    rkey[175] = rotlConstant< 3>(rkey[167] + delta[5][30]);
    rkey[183] = rotlConstant<11>(rkey[175] + delta[6][ 1]);
    rkey[191] = rotlConstant<17>(rkey[183] + delta[7][ 4]);
}

NAMESPACE_BEGIN(CryptoPP)

#if CRYPTOPP_LEA_ADVANCED_PROCESS_BLOCKS
# if defined(CRYPTOPP_SSSE3_AVAILABLE)
extern size_t LEA_Enc_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t LEA_Dec_AdvancedProcessBlocks_SSSE3(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
# endif

# if (CRYPTOPP_ARM_NEON_AVAILABLE)
extern size_t LEA_Enc_AdvancedProcessBlocks_NEON(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);

extern size_t LEA_Dec_AdvancedProcessBlocks_NEON(const word32* subKeys, size_t rounds,
    const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags);
# endif
#endif

std::string LEA::Base::AlgorithmProvider() const
{
#if (CRYPTOPP_LEA_ADVANCED_PROCESS_BLOCKS)
# if (CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3())
        return "SSSE3";
# endif
# if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return "NEON";
# endif
#endif
    return "C++";
}

void LEA::Base::UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);

    switch(keyLength)
    {
    case 16:  // 128-bit key
    {
        m_rkey.New(144); m_temp.New(4); m_rounds = 24;
        GetUserKey(LITTLE_ENDIAN_ORDER, m_temp.begin(), 4, userKey, 16);
        SetKey128(m_rkey, m_temp);
        break;
    }
    case 24:  // 192-bit key
    {
        m_rkey.New(168); m_temp.New(6); m_rounds = 28;
        GetUserKey(LITTLE_ENDIAN_ORDER, m_temp.begin(), 6, userKey, 24);
        SetKey192(m_rkey, m_temp);
        break;
    }
    case 32:  // 256-bit key
    {
        m_rkey.New(192); m_temp.New(8); m_rounds = 32;
        GetUserKey(LITTLE_ENDIAN_ORDER, m_temp.begin(), 8, userKey, 32);
        SetKey256(m_rkey, m_temp);
        break;
    }
    default:
        CRYPTOPP_ASSERT(0);;
    }
}

void LEA::Enc::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word32, LittleEndian> iblock(inBlock);
    iblock(m_temp[0])(m_temp[1])(m_temp[2])(m_temp[3]);

    m_temp[3] = rotrConstant<3>((m_temp[2] ^ m_rkey[  4]) + (m_temp[3] ^ m_rkey[  5]));
    m_temp[2] = rotrConstant<5>((m_temp[1] ^ m_rkey[  2]) + (m_temp[2] ^ m_rkey[  3]));
    m_temp[1] = rotlConstant<9>((m_temp[0] ^ m_rkey[  0]) + (m_temp[1] ^ m_rkey[  1]));
    m_temp[0] = rotrConstant<3>((m_temp[3] ^ m_rkey[ 10]) + (m_temp[0] ^ m_rkey[ 11]));
    m_temp[3] = rotrConstant<5>((m_temp[2] ^ m_rkey[  8]) + (m_temp[3] ^ m_rkey[  9]));
    m_temp[2] = rotlConstant<9>((m_temp[1] ^ m_rkey[  6]) + (m_temp[2] ^ m_rkey[  7]));
    m_temp[1] = rotrConstant<3>((m_temp[0] ^ m_rkey[ 16]) + (m_temp[1] ^ m_rkey[ 17]));
    m_temp[0] = rotrConstant<5>((m_temp[3] ^ m_rkey[ 14]) + (m_temp[0] ^ m_rkey[ 15]));
    m_temp[3] = rotlConstant<9>((m_temp[2] ^ m_rkey[ 12]) + (m_temp[3] ^ m_rkey[ 13]));
    m_temp[2] = rotrConstant<3>((m_temp[1] ^ m_rkey[ 22]) + (m_temp[2] ^ m_rkey[ 23]));
    m_temp[1] = rotrConstant<5>((m_temp[0] ^ m_rkey[ 20]) + (m_temp[1] ^ m_rkey[ 21]));
    m_temp[0] = rotlConstant<9>((m_temp[3] ^ m_rkey[ 18]) + (m_temp[0] ^ m_rkey[ 19]));

    m_temp[3] = rotrConstant<3>((m_temp[2] ^ m_rkey[ 28]) + (m_temp[3] ^ m_rkey[ 29]));
    m_temp[2] = rotrConstant<5>((m_temp[1] ^ m_rkey[ 26]) + (m_temp[2] ^ m_rkey[ 27]));
    m_temp[1] = rotlConstant<9>((m_temp[0] ^ m_rkey[ 24]) + (m_temp[1] ^ m_rkey[ 25]));
    m_temp[0] = rotrConstant<3>((m_temp[3] ^ m_rkey[ 34]) + (m_temp[0] ^ m_rkey[ 35]));
    m_temp[3] = rotrConstant<5>((m_temp[2] ^ m_rkey[ 32]) + (m_temp[3] ^ m_rkey[ 33]));
    m_temp[2] = rotlConstant<9>((m_temp[1] ^ m_rkey[ 30]) + (m_temp[2] ^ m_rkey[ 31]));
    m_temp[1] = rotrConstant<3>((m_temp[0] ^ m_rkey[ 40]) + (m_temp[1] ^ m_rkey[ 41]));
    m_temp[0] = rotrConstant<5>((m_temp[3] ^ m_rkey[ 38]) + (m_temp[0] ^ m_rkey[ 39]));
    m_temp[3] = rotlConstant<9>((m_temp[2] ^ m_rkey[ 36]) + (m_temp[3] ^ m_rkey[ 37]));
    m_temp[2] = rotrConstant<3>((m_temp[1] ^ m_rkey[ 46]) + (m_temp[2] ^ m_rkey[ 47]));
    m_temp[1] = rotrConstant<5>((m_temp[0] ^ m_rkey[ 44]) + (m_temp[1] ^ m_rkey[ 45]));
    m_temp[0] = rotlConstant<9>((m_temp[3] ^ m_rkey[ 42]) + (m_temp[0] ^ m_rkey[ 43]));

    m_temp[3] = rotrConstant<3>((m_temp[2] ^ m_rkey[ 52]) + (m_temp[3] ^ m_rkey[ 53]));
    m_temp[2] = rotrConstant<5>((m_temp[1] ^ m_rkey[ 50]) + (m_temp[2] ^ m_rkey[ 51]));
    m_temp[1] = rotlConstant<9>((m_temp[0] ^ m_rkey[ 48]) + (m_temp[1] ^ m_rkey[ 49]));
    m_temp[0] = rotrConstant<3>((m_temp[3] ^ m_rkey[ 58]) + (m_temp[0] ^ m_rkey[ 59]));
    m_temp[3] = rotrConstant<5>((m_temp[2] ^ m_rkey[ 56]) + (m_temp[3] ^ m_rkey[ 57]));
    m_temp[2] = rotlConstant<9>((m_temp[1] ^ m_rkey[ 54]) + (m_temp[2] ^ m_rkey[ 55]));
    m_temp[1] = rotrConstant<3>((m_temp[0] ^ m_rkey[ 64]) + (m_temp[1] ^ m_rkey[ 65]));
    m_temp[0] = rotrConstant<5>((m_temp[3] ^ m_rkey[ 62]) + (m_temp[0] ^ m_rkey[ 63]));
    m_temp[3] = rotlConstant<9>((m_temp[2] ^ m_rkey[ 60]) + (m_temp[3] ^ m_rkey[ 61]));
    m_temp[2] = rotrConstant<3>((m_temp[1] ^ m_rkey[ 70]) + (m_temp[2] ^ m_rkey[ 71]));
    m_temp[1] = rotrConstant<5>((m_temp[0] ^ m_rkey[ 68]) + (m_temp[1] ^ m_rkey[ 69]));
    m_temp[0] = rotlConstant<9>((m_temp[3] ^ m_rkey[ 66]) + (m_temp[0] ^ m_rkey[ 67]));

    m_temp[3] = rotrConstant<3>((m_temp[2] ^ m_rkey[ 76]) + (m_temp[3] ^ m_rkey[ 77]));
    m_temp[2] = rotrConstant<5>((m_temp[1] ^ m_rkey[ 74]) + (m_temp[2] ^ m_rkey[ 75]));
    m_temp[1] = rotlConstant<9>((m_temp[0] ^ m_rkey[ 72]) + (m_temp[1] ^ m_rkey[ 73]));
    m_temp[0] = rotrConstant<3>((m_temp[3] ^ m_rkey[ 82]) + (m_temp[0] ^ m_rkey[ 83]));
    m_temp[3] = rotrConstant<5>((m_temp[2] ^ m_rkey[ 80]) + (m_temp[3] ^ m_rkey[ 81]));
    m_temp[2] = rotlConstant<9>((m_temp[1] ^ m_rkey[ 78]) + (m_temp[2] ^ m_rkey[ 79]));
    m_temp[1] = rotrConstant<3>((m_temp[0] ^ m_rkey[ 88]) + (m_temp[1] ^ m_rkey[ 89]));
    m_temp[0] = rotrConstant<5>((m_temp[3] ^ m_rkey[ 86]) + (m_temp[0] ^ m_rkey[ 87]));
    m_temp[3] = rotlConstant<9>((m_temp[2] ^ m_rkey[ 84]) + (m_temp[3] ^ m_rkey[ 85]));
    m_temp[2] = rotrConstant<3>((m_temp[1] ^ m_rkey[ 94]) + (m_temp[2] ^ m_rkey[ 95]));
    m_temp[1] = rotrConstant<5>((m_temp[0] ^ m_rkey[ 92]) + (m_temp[1] ^ m_rkey[ 93]));
    m_temp[0] = rotlConstant<9>((m_temp[3] ^ m_rkey[ 90]) + (m_temp[0] ^ m_rkey[ 91]));

    m_temp[3] = rotrConstant<3>((m_temp[2] ^ m_rkey[100]) + (m_temp[3] ^ m_rkey[101]));
    m_temp[2] = rotrConstant<5>((m_temp[1] ^ m_rkey[ 98]) + (m_temp[2] ^ m_rkey[ 99]));
    m_temp[1] = rotlConstant<9>((m_temp[0] ^ m_rkey[ 96]) + (m_temp[1] ^ m_rkey[ 97]));
    m_temp[0] = rotrConstant<3>((m_temp[3] ^ m_rkey[106]) + (m_temp[0] ^ m_rkey[107]));
    m_temp[3] = rotrConstant<5>((m_temp[2] ^ m_rkey[104]) + (m_temp[3] ^ m_rkey[105]));
    m_temp[2] = rotlConstant<9>((m_temp[1] ^ m_rkey[102]) + (m_temp[2] ^ m_rkey[103]));
    m_temp[1] = rotrConstant<3>((m_temp[0] ^ m_rkey[112]) + (m_temp[1] ^ m_rkey[113]));
    m_temp[0] = rotrConstant<5>((m_temp[3] ^ m_rkey[110]) + (m_temp[0] ^ m_rkey[111]));
    m_temp[3] = rotlConstant<9>((m_temp[2] ^ m_rkey[108]) + (m_temp[3] ^ m_rkey[109]));
    m_temp[2] = rotrConstant<3>((m_temp[1] ^ m_rkey[118]) + (m_temp[2] ^ m_rkey[119]));
    m_temp[1] = rotrConstant<5>((m_temp[0] ^ m_rkey[116]) + (m_temp[1] ^ m_rkey[117]));
    m_temp[0] = rotlConstant<9>((m_temp[3] ^ m_rkey[114]) + (m_temp[0] ^ m_rkey[115]));

    m_temp[3] = rotrConstant<3>((m_temp[2] ^ m_rkey[124]) + (m_temp[3] ^ m_rkey[125]));
    m_temp[2] = rotrConstant<5>((m_temp[1] ^ m_rkey[122]) + (m_temp[2] ^ m_rkey[123]));
    m_temp[1] = rotlConstant<9>((m_temp[0] ^ m_rkey[120]) + (m_temp[1] ^ m_rkey[121]));
    m_temp[0] = rotrConstant<3>((m_temp[3] ^ m_rkey[130]) + (m_temp[0] ^ m_rkey[131]));
    m_temp[3] = rotrConstant<5>((m_temp[2] ^ m_rkey[128]) + (m_temp[3] ^ m_rkey[129]));
    m_temp[2] = rotlConstant<9>((m_temp[1] ^ m_rkey[126]) + (m_temp[2] ^ m_rkey[127]));
    m_temp[1] = rotrConstant<3>((m_temp[0] ^ m_rkey[136]) + (m_temp[1] ^ m_rkey[137]));
    m_temp[0] = rotrConstant<5>((m_temp[3] ^ m_rkey[134]) + (m_temp[0] ^ m_rkey[135]));
    m_temp[3] = rotlConstant<9>((m_temp[2] ^ m_rkey[132]) + (m_temp[3] ^ m_rkey[133]));
    m_temp[2] = rotrConstant<3>((m_temp[1] ^ m_rkey[142]) + (m_temp[2] ^ m_rkey[143]));
    m_temp[1] = rotrConstant<5>((m_temp[0] ^ m_rkey[140]) + (m_temp[1] ^ m_rkey[141]));
    m_temp[0] = rotlConstant<9>((m_temp[3] ^ m_rkey[138]) + (m_temp[0] ^ m_rkey[139]));

    if(m_rounds > 24)
    {
        m_temp[3] = rotrConstant<3>((m_temp[2] ^ m_rkey[148]) + (m_temp[3] ^ m_rkey[149]));
        m_temp[2] = rotrConstant<5>((m_temp[1] ^ m_rkey[146]) + (m_temp[2] ^ m_rkey[147]));
        m_temp[1] = rotlConstant<9>((m_temp[0] ^ m_rkey[144]) + (m_temp[1] ^ m_rkey[145]));
        m_temp[0] = rotrConstant<3>((m_temp[3] ^ m_rkey[154]) + (m_temp[0] ^ m_rkey[155]));
        m_temp[3] = rotrConstant<5>((m_temp[2] ^ m_rkey[152]) + (m_temp[3] ^ m_rkey[153]));
        m_temp[2] = rotlConstant<9>((m_temp[1] ^ m_rkey[150]) + (m_temp[2] ^ m_rkey[151]));
        m_temp[1] = rotrConstant<3>((m_temp[0] ^ m_rkey[160]) + (m_temp[1] ^ m_rkey[161]));
        m_temp[0] = rotrConstant<5>((m_temp[3] ^ m_rkey[158]) + (m_temp[0] ^ m_rkey[159]));
        m_temp[3] = rotlConstant<9>((m_temp[2] ^ m_rkey[156]) + (m_temp[3] ^ m_rkey[157]));
        m_temp[2] = rotrConstant<3>((m_temp[1] ^ m_rkey[166]) + (m_temp[2] ^ m_rkey[167]));
        m_temp[1] = rotrConstant<5>((m_temp[0] ^ m_rkey[164]) + (m_temp[1] ^ m_rkey[165]));
        m_temp[0] = rotlConstant<9>((m_temp[3] ^ m_rkey[162]) + (m_temp[0] ^ m_rkey[163]));
    }

    if(m_rounds > 28)
    {
        m_temp[3] = rotrConstant<3>((m_temp[2] ^ m_rkey[172]) + (m_temp[3] ^ m_rkey[173]));
        m_temp[2] = rotrConstant<5>((m_temp[1] ^ m_rkey[170]) + (m_temp[2] ^ m_rkey[171]));
        m_temp[1] = rotlConstant<9>((m_temp[0] ^ m_rkey[168]) + (m_temp[1] ^ m_rkey[169]));
        m_temp[0] = rotrConstant<3>((m_temp[3] ^ m_rkey[178]) + (m_temp[0] ^ m_rkey[179]));
        m_temp[3] = rotrConstant<5>((m_temp[2] ^ m_rkey[176]) + (m_temp[3] ^ m_rkey[177]));
        m_temp[2] = rotlConstant<9>((m_temp[1] ^ m_rkey[174]) + (m_temp[2] ^ m_rkey[175]));
        m_temp[1] = rotrConstant<3>((m_temp[0] ^ m_rkey[184]) + (m_temp[1] ^ m_rkey[185]));
        m_temp[0] = rotrConstant<5>((m_temp[3] ^ m_rkey[182]) + (m_temp[0] ^ m_rkey[183]));
        m_temp[3] = rotlConstant<9>((m_temp[2] ^ m_rkey[180]) + (m_temp[3] ^ m_rkey[181]));
        m_temp[2] = rotrConstant<3>((m_temp[1] ^ m_rkey[190]) + (m_temp[2] ^ m_rkey[191]));
        m_temp[1] = rotrConstant<5>((m_temp[0] ^ m_rkey[188]) + (m_temp[1] ^ m_rkey[189]));
        m_temp[0] = rotlConstant<9>((m_temp[3] ^ m_rkey[186]) + (m_temp[0] ^ m_rkey[187]));
    }

    PutBlock<word32, LittleEndian> oblock(xorBlock, outBlock);
    oblock(m_temp[0])(m_temp[1])(m_temp[2])(m_temp[3]);
}

void LEA::Dec::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Do not cast the buffer. It will SIGBUS on some ARM and SPARC.
    GetBlock<word32, LittleEndian> iblock(inBlock);
    iblock(m_temp[0])(m_temp[1])(m_temp[2])(m_temp[3]);

    if(m_rounds > 28)
    {
        m_temp[0] = (rotrConstant<9>(m_temp[0]) - (m_temp[3] ^ m_rkey[186])) ^ m_rkey[187];
        m_temp[1] = (rotlConstant<5>(m_temp[1]) - (m_temp[0] ^ m_rkey[188])) ^ m_rkey[189];
        m_temp[2] = (rotlConstant<3>(m_temp[2]) - (m_temp[1] ^ m_rkey[190])) ^ m_rkey[191];
        m_temp[3] = (rotrConstant<9>(m_temp[3]) - (m_temp[2] ^ m_rkey[180])) ^ m_rkey[181];
        m_temp[0] = (rotlConstant<5>(m_temp[0]) - (m_temp[3] ^ m_rkey[182])) ^ m_rkey[183];
        m_temp[1] = (rotlConstant<3>(m_temp[1]) - (m_temp[0] ^ m_rkey[184])) ^ m_rkey[185];
        m_temp[2] = (rotrConstant<9>(m_temp[2]) - (m_temp[1] ^ m_rkey[174])) ^ m_rkey[175];
        m_temp[3] = (rotlConstant<5>(m_temp[3]) - (m_temp[2] ^ m_rkey[176])) ^ m_rkey[177];
        m_temp[0] = (rotlConstant<3>(m_temp[0]) - (m_temp[3] ^ m_rkey[178])) ^ m_rkey[179];
        m_temp[1] = (rotrConstant<9>(m_temp[1]) - (m_temp[0] ^ m_rkey[168])) ^ m_rkey[169];
        m_temp[2] = (rotlConstant<5>(m_temp[2]) - (m_temp[1] ^ m_rkey[170])) ^ m_rkey[171];
        m_temp[3] = (rotlConstant<3>(m_temp[3]) - (m_temp[2] ^ m_rkey[172])) ^ m_rkey[173];
    }

    if(m_rounds > 24)
    {
        m_temp[0] = (rotrConstant<9>(m_temp[0]) - (m_temp[3] ^ m_rkey[162])) ^ m_rkey[163];
        m_temp[1] = (rotlConstant<5>(m_temp[1]) - (m_temp[0] ^ m_rkey[164])) ^ m_rkey[165];
        m_temp[2] = (rotlConstant<3>(m_temp[2]) - (m_temp[1] ^ m_rkey[166])) ^ m_rkey[167];
        m_temp[3] = (rotrConstant<9>(m_temp[3]) - (m_temp[2] ^ m_rkey[156])) ^ m_rkey[157];
        m_temp[0] = (rotlConstant<5>(m_temp[0]) - (m_temp[3] ^ m_rkey[158])) ^ m_rkey[159];
        m_temp[1] = (rotlConstant<3>(m_temp[1]) - (m_temp[0] ^ m_rkey[160])) ^ m_rkey[161];
        m_temp[2] = (rotrConstant<9>(m_temp[2]) - (m_temp[1] ^ m_rkey[150])) ^ m_rkey[151];
        m_temp[3] = (rotlConstant<5>(m_temp[3]) - (m_temp[2] ^ m_rkey[152])) ^ m_rkey[153];
        m_temp[0] = (rotlConstant<3>(m_temp[0]) - (m_temp[3] ^ m_rkey[154])) ^ m_rkey[155];
        m_temp[1] = (rotrConstant<9>(m_temp[1]) - (m_temp[0] ^ m_rkey[144])) ^ m_rkey[145];
        m_temp[2] = (rotlConstant<5>(m_temp[2]) - (m_temp[1] ^ m_rkey[146])) ^ m_rkey[147];
        m_temp[3] = (rotlConstant<3>(m_temp[3]) - (m_temp[2] ^ m_rkey[148])) ^ m_rkey[149];
    }

    m_temp[0] = (rotrConstant<9>(m_temp[0]) - (m_temp[3] ^ m_rkey[138])) ^ m_rkey[139];
    m_temp[1] = (rotlConstant<5>(m_temp[1]) - (m_temp[0] ^ m_rkey[140])) ^ m_rkey[141];
    m_temp[2] = (rotlConstant<3>(m_temp[2]) - (m_temp[1] ^ m_rkey[142])) ^ m_rkey[143];
    m_temp[3] = (rotrConstant<9>(m_temp[3]) - (m_temp[2] ^ m_rkey[132])) ^ m_rkey[133];
    m_temp[0] = (rotlConstant<5>(m_temp[0]) - (m_temp[3] ^ m_rkey[134])) ^ m_rkey[135];
    m_temp[1] = (rotlConstant<3>(m_temp[1]) - (m_temp[0] ^ m_rkey[136])) ^ m_rkey[137];
    m_temp[2] = (rotrConstant<9>(m_temp[2]) - (m_temp[1] ^ m_rkey[126])) ^ m_rkey[127];
    m_temp[3] = (rotlConstant<5>(m_temp[3]) - (m_temp[2] ^ m_rkey[128])) ^ m_rkey[129];
    m_temp[0] = (rotlConstant<3>(m_temp[0]) - (m_temp[3] ^ m_rkey[130])) ^ m_rkey[131];
    m_temp[1] = (rotrConstant<9>(m_temp[1]) - (m_temp[0] ^ m_rkey[120])) ^ m_rkey[121];
    m_temp[2] = (rotlConstant<5>(m_temp[2]) - (m_temp[1] ^ m_rkey[122])) ^ m_rkey[123];
    m_temp[3] = (rotlConstant<3>(m_temp[3]) - (m_temp[2] ^ m_rkey[124])) ^ m_rkey[125];

    m_temp[0] = (rotrConstant<9>(m_temp[0]) - (m_temp[3] ^ m_rkey[114])) ^ m_rkey[115];
    m_temp[1] = (rotlConstant<5>(m_temp[1]) - (m_temp[0] ^ m_rkey[116])) ^ m_rkey[117];
    m_temp[2] = (rotlConstant<3>(m_temp[2]) - (m_temp[1] ^ m_rkey[118])) ^ m_rkey[119];
    m_temp[3] = (rotrConstant<9>(m_temp[3]) - (m_temp[2] ^ m_rkey[108])) ^ m_rkey[109];
    m_temp[0] = (rotlConstant<5>(m_temp[0]) - (m_temp[3] ^ m_rkey[110])) ^ m_rkey[111];
    m_temp[1] = (rotlConstant<3>(m_temp[1]) - (m_temp[0] ^ m_rkey[112])) ^ m_rkey[113];
    m_temp[2] = (rotrConstant<9>(m_temp[2]) - (m_temp[1] ^ m_rkey[102])) ^ m_rkey[103];
    m_temp[3] = (rotlConstant<5>(m_temp[3]) - (m_temp[2] ^ m_rkey[104])) ^ m_rkey[105];
    m_temp[0] = (rotlConstant<3>(m_temp[0]) - (m_temp[3] ^ m_rkey[106])) ^ m_rkey[107];
    m_temp[1] = (rotrConstant<9>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 96])) ^ m_rkey[ 97];
    m_temp[2] = (rotlConstant<5>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 98])) ^ m_rkey[ 99];
    m_temp[3] = (rotlConstant<3>(m_temp[3]) - (m_temp[2] ^ m_rkey[100])) ^ m_rkey[101];

    m_temp[0] = (rotrConstant<9>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 90])) ^ m_rkey[ 91];
    m_temp[1] = (rotlConstant<5>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 92])) ^ m_rkey[ 93];
    m_temp[2] = (rotlConstant<3>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 94])) ^ m_rkey[ 95];
    m_temp[3] = (rotrConstant<9>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 84])) ^ m_rkey[ 85];
    m_temp[0] = (rotlConstant<5>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 86])) ^ m_rkey[ 87];
    m_temp[1] = (rotlConstant<3>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 88])) ^ m_rkey[ 89];
    m_temp[2] = (rotrConstant<9>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 78])) ^ m_rkey[ 79];
    m_temp[3] = (rotlConstant<5>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 80])) ^ m_rkey[ 81];
    m_temp[0] = (rotlConstant<3>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 82])) ^ m_rkey[ 83];
    m_temp[1] = (rotrConstant<9>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 72])) ^ m_rkey[ 73];
    m_temp[2] = (rotlConstant<5>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 74])) ^ m_rkey[ 75];
    m_temp[3] = (rotlConstant<3>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 76])) ^ m_rkey[ 77];

    m_temp[0] = (rotrConstant<9>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 66])) ^ m_rkey[ 67];
    m_temp[1] = (rotlConstant<5>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 68])) ^ m_rkey[ 69];
    m_temp[2] = (rotlConstant<3>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 70])) ^ m_rkey[ 71];
    m_temp[3] = (rotrConstant<9>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 60])) ^ m_rkey[ 61];
    m_temp[0] = (rotlConstant<5>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 62])) ^ m_rkey[ 63];
    m_temp[1] = (rotlConstant<3>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 64])) ^ m_rkey[ 65];
    m_temp[2] = (rotrConstant<9>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 54])) ^ m_rkey[ 55];
    m_temp[3] = (rotlConstant<5>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 56])) ^ m_rkey[ 57];
    m_temp[0] = (rotlConstant<3>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 58])) ^ m_rkey[ 59];
    m_temp[1] = (rotrConstant<9>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 48])) ^ m_rkey[ 49];
    m_temp[2] = (rotlConstant<5>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 50])) ^ m_rkey[ 51];
    m_temp[3] = (rotlConstant<3>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 52])) ^ m_rkey[ 53];

    m_temp[0] = (rotrConstant<9>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 42])) ^ m_rkey[ 43];
    m_temp[1] = (rotlConstant<5>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 44])) ^ m_rkey[ 45];
    m_temp[2] = (rotlConstant<3>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 46])) ^ m_rkey[ 47];
    m_temp[3] = (rotrConstant<9>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 36])) ^ m_rkey[ 37];
    m_temp[0] = (rotlConstant<5>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 38])) ^ m_rkey[ 39];
    m_temp[1] = (rotlConstant<3>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 40])) ^ m_rkey[ 41];
    m_temp[2] = (rotrConstant<9>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 30])) ^ m_rkey[ 31];
    m_temp[3] = (rotlConstant<5>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 32])) ^ m_rkey[ 33];
    m_temp[0] = (rotlConstant<3>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 34])) ^ m_rkey[ 35];
    m_temp[1] = (rotrConstant<9>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 24])) ^ m_rkey[ 25];
    m_temp[2] = (rotlConstant<5>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 26])) ^ m_rkey[ 27];
    m_temp[3] = (rotlConstant<3>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 28])) ^ m_rkey[ 29];

    m_temp[0] = (rotrConstant<9>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 18])) ^ m_rkey[ 19];
    m_temp[1] = (rotlConstant<5>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 20])) ^ m_rkey[ 21];
    m_temp[2] = (rotlConstant<3>(m_temp[2]) - (m_temp[1] ^ m_rkey[ 22])) ^ m_rkey[ 23];
    m_temp[3] = (rotrConstant<9>(m_temp[3]) - (m_temp[2] ^ m_rkey[ 12])) ^ m_rkey[ 13];
    m_temp[0] = (rotlConstant<5>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 14])) ^ m_rkey[ 15];
    m_temp[1] = (rotlConstant<3>(m_temp[1]) - (m_temp[0] ^ m_rkey[ 16])) ^ m_rkey[ 17];
    m_temp[2] = (rotrConstant<9>(m_temp[2]) - (m_temp[1] ^ m_rkey[  6])) ^ m_rkey[  7];
    m_temp[3] = (rotlConstant<5>(m_temp[3]) - (m_temp[2] ^ m_rkey[  8])) ^ m_rkey[  9];
    m_temp[0] = (rotlConstant<3>(m_temp[0]) - (m_temp[3] ^ m_rkey[ 10])) ^ m_rkey[ 11];
    m_temp[1] = (rotrConstant<9>(m_temp[1]) - (m_temp[0] ^ m_rkey[  0])) ^ m_rkey[  1];
    m_temp[2] = (rotlConstant<5>(m_temp[2]) - (m_temp[1] ^ m_rkey[  2])) ^ m_rkey[  3];
    m_temp[3] = (rotlConstant<3>(m_temp[3]) - (m_temp[2] ^ m_rkey[  4])) ^ m_rkey[  5];

    PutBlock<word32, LittleEndian> oblock(xorBlock, outBlock);
    oblock(m_temp[0])(m_temp[1])(m_temp[2])(m_temp[3]);
}

#if CRYPTOPP_LEA_ADVANCED_PROCESS_BLOCKS
size_t LEA::Enc::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
#if defined(CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        return LEA_Enc_AdvancedProcessBlocks_SSSE3(m_rkey, m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return LEA_Enc_AdvancedProcessBlocks_NEON(m_rkey, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}

size_t LEA::Dec::AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks,
        byte *outBlocks, size_t length, word32 flags) const
{
#if defined(CRYPTOPP_SSSE3_AVAILABLE)
    if (HasSSSE3()) {
        return LEA_Dec_AdvancedProcessBlocks_SSSE3(m_rkey, m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
    }
#endif
#if (CRYPTOPP_ARM_NEON_AVAILABLE)
    if (HasNEON())
        return LEA_Dec_AdvancedProcessBlocks_NEON(m_rkey, (size_t)m_rounds,
            inBlocks, xorBlocks, outBlocks, length, flags);
#endif
    return BlockTransformation::AdvancedProcessBlocks(inBlocks, xorBlocks, outBlocks, length, flags);
}
#endif  // CRYPTOPP_LEA_ADVANCED_PROCESS_BLOCKS

NAMESPACE_END
