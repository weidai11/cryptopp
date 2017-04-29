// aria.cpp - written and placed in the public domain by Jeffrey Walton

#include "pch.h"
#include "config.h"

#include "aria.h"
#include "misc.h"
#include "cpu.h"

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
# define CRYPTOPP_ENABLE_ARIA_SSE2_INTRINSICS 1
#endif

#if CRYPTOPP_BOOL_SSSE3_INTRINSICS_AVAILABLE
# define CRYPTOPP_ENABLE_ARIA_SSSE3_INTRINSICS 1
#endif

#if CRYPTOPP_BOOL_NEON_INTRINSICS_AVAILABLE
# define CRYPTOPP_ENABLE_ARIA_NEON_INTRINSICS 1
#endif

ANONYMOUS_NAMESPACE_BEGIN

CRYPTOPP_ALIGN_DATA(16)
const CryptoPP::word32 S1[256]={
	0x00636363,0x007c7c7c,0x00777777,0x007b7b7b,0x00f2f2f2,0x006b6b6b,0x006f6f6f,0x00c5c5c5,
	0x00303030,0x00010101,0x00676767,0x002b2b2b,0x00fefefe,0x00d7d7d7,0x00ababab,0x00767676,
	0x00cacaca,0x00828282,0x00c9c9c9,0x007d7d7d,0x00fafafa,0x00595959,0x00474747,0x00f0f0f0,
	0x00adadad,0x00d4d4d4,0x00a2a2a2,0x00afafaf,0x009c9c9c,0x00a4a4a4,0x00727272,0x00c0c0c0,
	0x00b7b7b7,0x00fdfdfd,0x00939393,0x00262626,0x00363636,0x003f3f3f,0x00f7f7f7,0x00cccccc,
	0x00343434,0x00a5a5a5,0x00e5e5e5,0x00f1f1f1,0x00717171,0x00d8d8d8,0x00313131,0x00151515,
	0x00040404,0x00c7c7c7,0x00232323,0x00c3c3c3,0x00181818,0x00969696,0x00050505,0x009a9a9a,
	0x00070707,0x00121212,0x00808080,0x00e2e2e2,0x00ebebeb,0x00272727,0x00b2b2b2,0x00757575,
	0x00090909,0x00838383,0x002c2c2c,0x001a1a1a,0x001b1b1b,0x006e6e6e,0x005a5a5a,0x00a0a0a0,
	0x00525252,0x003b3b3b,0x00d6d6d6,0x00b3b3b3,0x00292929,0x00e3e3e3,0x002f2f2f,0x00848484,
	0x00535353,0x00d1d1d1,0x00000000,0x00ededed,0x00202020,0x00fcfcfc,0x00b1b1b1,0x005b5b5b,
	0x006a6a6a,0x00cbcbcb,0x00bebebe,0x00393939,0x004a4a4a,0x004c4c4c,0x00585858,0x00cfcfcf,
	0x00d0d0d0,0x00efefef,0x00aaaaaa,0x00fbfbfb,0x00434343,0x004d4d4d,0x00333333,0x00858585,
	0x00454545,0x00f9f9f9,0x00020202,0x007f7f7f,0x00505050,0x003c3c3c,0x009f9f9f,0x00a8a8a8,
	0x00515151,0x00a3a3a3,0x00404040,0x008f8f8f,0x00929292,0x009d9d9d,0x00383838,0x00f5f5f5,
	0x00bcbcbc,0x00b6b6b6,0x00dadada,0x00212121,0x00101010,0x00ffffff,0x00f3f3f3,0x00d2d2d2,
	0x00cdcdcd,0x000c0c0c,0x00131313,0x00ececec,0x005f5f5f,0x00979797,0x00444444,0x00171717,
	0x00c4c4c4,0x00a7a7a7,0x007e7e7e,0x003d3d3d,0x00646464,0x005d5d5d,0x00191919,0x00737373,
	0x00606060,0x00818181,0x004f4f4f,0x00dcdcdc,0x00222222,0x002a2a2a,0x00909090,0x00888888,
	0x00464646,0x00eeeeee,0x00b8b8b8,0x00141414,0x00dedede,0x005e5e5e,0x000b0b0b,0x00dbdbdb,
	0x00e0e0e0,0x00323232,0x003a3a3a,0x000a0a0a,0x00494949,0x00060606,0x00242424,0x005c5c5c,
	0x00c2c2c2,0x00d3d3d3,0x00acacac,0x00626262,0x00919191,0x00959595,0x00e4e4e4,0x00797979,
	0x00e7e7e7,0x00c8c8c8,0x00373737,0x006d6d6d,0x008d8d8d,0x00d5d5d5,0x004e4e4e,0x00a9a9a9,
	0x006c6c6c,0x00565656,0x00f4f4f4,0x00eaeaea,0x00656565,0x007a7a7a,0x00aeaeae,0x00080808,
	0x00bababa,0x00787878,0x00252525,0x002e2e2e,0x001c1c1c,0x00a6a6a6,0x00b4b4b4,0x00c6c6c6,
	0x00e8e8e8,0x00dddddd,0x00747474,0x001f1f1f,0x004b4b4b,0x00bdbdbd,0x008b8b8b,0x008a8a8a,
	0x00707070,0x003e3e3e,0x00b5b5b5,0x00666666,0x00484848,0x00030303,0x00f6f6f6,0x000e0e0e,
	0x00616161,0x00353535,0x00575757,0x00b9b9b9,0x00868686,0x00c1c1c1,0x001d1d1d,0x009e9e9e,
	0x00e1e1e1,0x00f8f8f8,0x00989898,0x00111111,0x00696969,0x00d9d9d9,0x008e8e8e,0x00949494,
	0x009b9b9b,0x001e1e1e,0x00878787,0x00e9e9e9,0x00cecece,0x00555555,0x00282828,0x00dfdfdf,
	0x008c8c8c,0x00a1a1a1,0x00898989,0x000d0d0d,0x00bfbfbf,0x00e6e6e6,0x00424242,0x00686868,
	0x00414141,0x00999999,0x002d2d2d,0x000f0f0f,0x00b0b0b0,0x00545454,0x00bbbbbb,0x00161616
};

CRYPTOPP_ALIGN_DATA(16)
const CryptoPP::word32 S2[256]={
	0xe200e2e2,0x4e004e4e,0x54005454,0xfc00fcfc,0x94009494,0xc200c2c2,0x4a004a4a,0xcc00cccc,
	0x62006262,0x0d000d0d,0x6a006a6a,0x46004646,0x3c003c3c,0x4d004d4d,0x8b008b8b,0xd100d1d1,
	0x5e005e5e,0xfa00fafa,0x64006464,0xcb00cbcb,0xb400b4b4,0x97009797,0xbe00bebe,0x2b002b2b,
	0xbc00bcbc,0x77007777,0x2e002e2e,0x03000303,0xd300d3d3,0x19001919,0x59005959,0xc100c1c1,
	0x1d001d1d,0x06000606,0x41004141,0x6b006b6b,0x55005555,0xf000f0f0,0x99009999,0x69006969,
	0xea00eaea,0x9c009c9c,0x18001818,0xae00aeae,0x63006363,0xdf00dfdf,0xe700e7e7,0xbb00bbbb,
	0x00000000,0x73007373,0x66006666,0xfb00fbfb,0x96009696,0x4c004c4c,0x85008585,0xe400e4e4,
	0x3a003a3a,0x09000909,0x45004545,0xaa00aaaa,0x0f000f0f,0xee00eeee,0x10001010,0xeb00ebeb,
	0x2d002d2d,0x7f007f7f,0xf400f4f4,0x29002929,0xac00acac,0xcf00cfcf,0xad00adad,0x91009191,
	0x8d008d8d,0x78007878,0xc800c8c8,0x95009595,0xf900f9f9,0x2f002f2f,0xce00cece,0xcd00cdcd,
	0x08000808,0x7a007a7a,0x88008888,0x38003838,0x5c005c5c,0x83008383,0x2a002a2a,0x28002828,
	0x47004747,0xdb00dbdb,0xb800b8b8,0xc700c7c7,0x93009393,0xa400a4a4,0x12001212,0x53005353,
	0xff00ffff,0x87008787,0x0e000e0e,0x31003131,0x36003636,0x21002121,0x58005858,0x48004848,
	0x01000101,0x8e008e8e,0x37003737,0x74007474,0x32003232,0xca00caca,0xe900e9e9,0xb100b1b1,
	0xb700b7b7,0xab00abab,0x0c000c0c,0xd700d7d7,0xc400c4c4,0x56005656,0x42004242,0x26002626,
	0x07000707,0x98009898,0x60006060,0xd900d9d9,0xb600b6b6,0xb900b9b9,0x11001111,0x40004040,
	0xec00ecec,0x20002020,0x8c008c8c,0xbd00bdbd,0xa000a0a0,0xc900c9c9,0x84008484,0x04000404,
	0x49004949,0x23002323,0xf100f1f1,0x4f004f4f,0x50005050,0x1f001f1f,0x13001313,0xdc00dcdc,
	0xd800d8d8,0xc000c0c0,0x9e009e9e,0x57005757,0xe300e3e3,0xc300c3c3,0x7b007b7b,0x65006565,
	0x3b003b3b,0x02000202,0x8f008f8f,0x3e003e3e,0xe800e8e8,0x25002525,0x92009292,0xe500e5e5,
	0x15001515,0xdd00dddd,0xfd00fdfd,0x17001717,0xa900a9a9,0xbf00bfbf,0xd400d4d4,0x9a009a9a,
	0x7e007e7e,0xc500c5c5,0x39003939,0x67006767,0xfe00fefe,0x76007676,0x9d009d9d,0x43004343,
	0xa700a7a7,0xe100e1e1,0xd000d0d0,0xf500f5f5,0x68006868,0xf200f2f2,0x1b001b1b,0x34003434,
	0x70007070,0x05000505,0xa300a3a3,0x8a008a8a,0xd500d5d5,0x79007979,0x86008686,0xa800a8a8,
	0x30003030,0xc600c6c6,0x51005151,0x4b004b4b,0x1e001e1e,0xa600a6a6,0x27002727,0xf600f6f6,
	0x35003535,0xd200d2d2,0x6e006e6e,0x24002424,0x16001616,0x82008282,0x5f005f5f,0xda00dada,
	0xe600e6e6,0x75007575,0xa200a2a2,0xef00efef,0x2c002c2c,0xb200b2b2,0x1c001c1c,0x9f009f9f,
	0x5d005d5d,0x6f006f6f,0x80008080,0x0a000a0a,0x72007272,0x44004444,0x9b009b9b,0x6c006c6c,
	0x90009090,0x0b000b0b,0x5b005b5b,0x33003333,0x7d007d7d,0x5a005a5a,0x52005252,0xf300f3f3,
	0x61006161,0xa100a1a1,0xf700f7f7,0xb000b0b0,0xd600d6d6,0x3f003f3f,0x7c007c7c,0x6d006d6d,
	0xed00eded,0x14001414,0xe000e0e0,0xa500a5a5,0x3d003d3d,0x22002222,0xb300b3b3,0xf800f8f8,
	0x89008989,0xde00dede,0x71007171,0x1a001a1a,0xaf00afaf,0xba00baba,0xb500b5b5,0x81008181
};

CRYPTOPP_ALIGN_DATA(16)
const CryptoPP::word32 X1[256]={
	0x52520052,0x09090009,0x6a6a006a,0xd5d500d5,0x30300030,0x36360036,0xa5a500a5,0x38380038,
	0xbfbf00bf,0x40400040,0xa3a300a3,0x9e9e009e,0x81810081,0xf3f300f3,0xd7d700d7,0xfbfb00fb,
	0x7c7c007c,0xe3e300e3,0x39390039,0x82820082,0x9b9b009b,0x2f2f002f,0xffff00ff,0x87870087,
	0x34340034,0x8e8e008e,0x43430043,0x44440044,0xc4c400c4,0xdede00de,0xe9e900e9,0xcbcb00cb,
	0x54540054,0x7b7b007b,0x94940094,0x32320032,0xa6a600a6,0xc2c200c2,0x23230023,0x3d3d003d,
	0xeeee00ee,0x4c4c004c,0x95950095,0x0b0b000b,0x42420042,0xfafa00fa,0xc3c300c3,0x4e4e004e,
	0x08080008,0x2e2e002e,0xa1a100a1,0x66660066,0x28280028,0xd9d900d9,0x24240024,0xb2b200b2,
	0x76760076,0x5b5b005b,0xa2a200a2,0x49490049,0x6d6d006d,0x8b8b008b,0xd1d100d1,0x25250025,
	0x72720072,0xf8f800f8,0xf6f600f6,0x64640064,0x86860086,0x68680068,0x98980098,0x16160016,
	0xd4d400d4,0xa4a400a4,0x5c5c005c,0xcccc00cc,0x5d5d005d,0x65650065,0xb6b600b6,0x92920092,
	0x6c6c006c,0x70700070,0x48480048,0x50500050,0xfdfd00fd,0xeded00ed,0xb9b900b9,0xdada00da,
	0x5e5e005e,0x15150015,0x46460046,0x57570057,0xa7a700a7,0x8d8d008d,0x9d9d009d,0x84840084,
	0x90900090,0xd8d800d8,0xabab00ab,0x00000000,0x8c8c008c,0xbcbc00bc,0xd3d300d3,0x0a0a000a,
	0xf7f700f7,0xe4e400e4,0x58580058,0x05050005,0xb8b800b8,0xb3b300b3,0x45450045,0x06060006,
	0xd0d000d0,0x2c2c002c,0x1e1e001e,0x8f8f008f,0xcaca00ca,0x3f3f003f,0x0f0f000f,0x02020002,
	0xc1c100c1,0xafaf00af,0xbdbd00bd,0x03030003,0x01010001,0x13130013,0x8a8a008a,0x6b6b006b,
	0x3a3a003a,0x91910091,0x11110011,0x41410041,0x4f4f004f,0x67670067,0xdcdc00dc,0xeaea00ea,
	0x97970097,0xf2f200f2,0xcfcf00cf,0xcece00ce,0xf0f000f0,0xb4b400b4,0xe6e600e6,0x73730073,
	0x96960096,0xacac00ac,0x74740074,0x22220022,0xe7e700e7,0xadad00ad,0x35350035,0x85850085,
	0xe2e200e2,0xf9f900f9,0x37370037,0xe8e800e8,0x1c1c001c,0x75750075,0xdfdf00df,0x6e6e006e,
	0x47470047,0xf1f100f1,0x1a1a001a,0x71710071,0x1d1d001d,0x29290029,0xc5c500c5,0x89890089,
	0x6f6f006f,0xb7b700b7,0x62620062,0x0e0e000e,0xaaaa00aa,0x18180018,0xbebe00be,0x1b1b001b,
	0xfcfc00fc,0x56560056,0x3e3e003e,0x4b4b004b,0xc6c600c6,0xd2d200d2,0x79790079,0x20200020,
	0x9a9a009a,0xdbdb00db,0xc0c000c0,0xfefe00fe,0x78780078,0xcdcd00cd,0x5a5a005a,0xf4f400f4,
	0x1f1f001f,0xdddd00dd,0xa8a800a8,0x33330033,0x88880088,0x07070007,0xc7c700c7,0x31310031,
	0xb1b100b1,0x12120012,0x10100010,0x59590059,0x27270027,0x80800080,0xecec00ec,0x5f5f005f,
	0x60600060,0x51510051,0x7f7f007f,0xa9a900a9,0x19190019,0xb5b500b5,0x4a4a004a,0x0d0d000d,
	0x2d2d002d,0xe5e500e5,0x7a7a007a,0x9f9f009f,0x93930093,0xc9c900c9,0x9c9c009c,0xefef00ef,
	0xa0a000a0,0xe0e000e0,0x3b3b003b,0x4d4d004d,0xaeae00ae,0x2a2a002a,0xf5f500f5,0xb0b000b0,
	0xc8c800c8,0xebeb00eb,0xbbbb00bb,0x3c3c003c,0x83830083,0x53530053,0x99990099,0x61610061,
	0x17170017,0x2b2b002b,0x04040004,0x7e7e007e,0xbaba00ba,0x77770077,0xd6d600d6,0x26260026,
	0xe1e100e1,0x69690069,0x14140014,0x63630063,0x55550055,0x21210021,0x0c0c000c,0x7d7d007d
};

CRYPTOPP_ALIGN_DATA(16)
const CryptoPP::word32 X2[256]={
	0x30303000,0x68686800,0x99999900,0x1b1b1b00,0x87878700,0xb9b9b900,0x21212100,0x78787800,
	0x50505000,0x39393900,0xdbdbdb00,0xe1e1e100,0x72727200,0x09090900,0x62626200,0x3c3c3c00,
	0x3e3e3e00,0x7e7e7e00,0x5e5e5e00,0x8e8e8e00,0xf1f1f100,0xa0a0a000,0xcccccc00,0xa3a3a300,
	0x2a2a2a00,0x1d1d1d00,0xfbfbfb00,0xb6b6b600,0xd6d6d600,0x20202000,0xc4c4c400,0x8d8d8d00,
	0x81818100,0x65656500,0xf5f5f500,0x89898900,0xcbcbcb00,0x9d9d9d00,0x77777700,0xc6c6c600,
	0x57575700,0x43434300,0x56565600,0x17171700,0xd4d4d400,0x40404000,0x1a1a1a00,0x4d4d4d00,
	0xc0c0c000,0x63636300,0x6c6c6c00,0xe3e3e300,0xb7b7b700,0xc8c8c800,0x64646400,0x6a6a6a00,
	0x53535300,0xaaaaaa00,0x38383800,0x98989800,0x0c0c0c00,0xf4f4f400,0x9b9b9b00,0xededed00,
	0x7f7f7f00,0x22222200,0x76767600,0xafafaf00,0xdddddd00,0x3a3a3a00,0x0b0b0b00,0x58585800,
	0x67676700,0x88888800,0x06060600,0xc3c3c300,0x35353500,0x0d0d0d00,0x01010100,0x8b8b8b00,
	0x8c8c8c00,0xc2c2c200,0xe6e6e600,0x5f5f5f00,0x02020200,0x24242400,0x75757500,0x93939300,
	0x66666600,0x1e1e1e00,0xe5e5e500,0xe2e2e200,0x54545400,0xd8d8d800,0x10101000,0xcecece00,
	0x7a7a7a00,0xe8e8e800,0x08080800,0x2c2c2c00,0x12121200,0x97979700,0x32323200,0xababab00,
	0xb4b4b400,0x27272700,0x0a0a0a00,0x23232300,0xdfdfdf00,0xefefef00,0xcacaca00,0xd9d9d900,
	0xb8b8b800,0xfafafa00,0xdcdcdc00,0x31313100,0x6b6b6b00,0xd1d1d100,0xadadad00,0x19191900,
	0x49494900,0xbdbdbd00,0x51515100,0x96969600,0xeeeeee00,0xe4e4e400,0xa8a8a800,0x41414100,
	0xdadada00,0xffffff00,0xcdcdcd00,0x55555500,0x86868600,0x36363600,0xbebebe00,0x61616100,
	0x52525200,0xf8f8f800,0xbbbbbb00,0x0e0e0e00,0x82828200,0x48484800,0x69696900,0x9a9a9a00,
	0xe0e0e000,0x47474700,0x9e9e9e00,0x5c5c5c00,0x04040400,0x4b4b4b00,0x34343400,0x15151500,
	0x79797900,0x26262600,0xa7a7a700,0xdedede00,0x29292900,0xaeaeae00,0x92929200,0xd7d7d700,
	0x84848400,0xe9e9e900,0xd2d2d200,0xbababa00,0x5d5d5d00,0xf3f3f300,0xc5c5c500,0xb0b0b000,
	0xbfbfbf00,0xa4a4a400,0x3b3b3b00,0x71717100,0x44444400,0x46464600,0x2b2b2b00,0xfcfcfc00,
	0xebebeb00,0x6f6f6f00,0xd5d5d500,0xf6f6f600,0x14141400,0xfefefe00,0x7c7c7c00,0x70707000,
	0x5a5a5a00,0x7d7d7d00,0xfdfdfd00,0x2f2f2f00,0x18181800,0x83838300,0x16161600,0xa5a5a500,
	0x91919100,0x1f1f1f00,0x05050500,0x95959500,0x74747400,0xa9a9a900,0xc1c1c100,0x5b5b5b00,
	0x4a4a4a00,0x85858500,0x6d6d6d00,0x13131300,0x07070700,0x4f4f4f00,0x4e4e4e00,0x45454500,
	0xb2b2b200,0x0f0f0f00,0xc9c9c900,0x1c1c1c00,0xa6a6a600,0xbcbcbc00,0xececec00,0x73737300,
	0x90909000,0x7b7b7b00,0xcfcfcf00,0x59595900,0x8f8f8f00,0xa1a1a100,0xf9f9f900,0x2d2d2d00,
	0xf2f2f200,0xb1b1b100,0x00000000,0x94949400,0x37373700,0x9f9f9f00,0xd0d0d000,0x2e2e2e00,
	0x9c9c9c00,0x6e6e6e00,0x28282800,0x3f3f3f00,0x80808000,0xf0f0f000,0x3d3d3d00,0xd3d3d300,
	0x25252500,0x8a8a8a00,0xb5b5b500,0xe7e7e700,0x42424200,0xb3b3b300,0xc7c7c700,0xeaeaea00,
	0xf7f7f700,0x4c4c4c00,0x11111100,0x33333300,0x03030300,0xa2a2a200,0xacacac00,0x60606000
};

CRYPTOPP_ALIGN_DATA(16)
const CryptoPP::word32 KRK[3][4] = {
	{0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0},
	{0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0},
	{0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e}
};

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

typedef BlockGetAndPut<word32, BigEndian, false, false> BigEndianBlock;
typedef BlockGetAndPut<word32, NativeByteOrder, true, true>  NativeEndianBlock;

inline byte ARIA_BRF(const word32 x, const int y) {
	return GETBYTE(x, y);
}

// Key XOR Layer
#define ARIA_KXL {  \
    NativeEndianBlock::Put(rk, t)(t[0])(t[1])(t[2])(t[3]); \
  }

// S-Box Layer 1 + M
#define SBL1_M(T0,T1,T2,T3) {  \
    T0=S1[ARIA_BRF(T0,3)]^S2[ARIA_BRF(T0,2)]^X1[ARIA_BRF(T0,1)]^X2[ARIA_BRF(T0,0)];  \
    T1=S1[ARIA_BRF(T1,3)]^S2[ARIA_BRF(T1,2)]^X1[ARIA_BRF(T1,1)]^X2[ARIA_BRF(T1,0)];  \
    T2=S1[ARIA_BRF(T2,3)]^S2[ARIA_BRF(T2,2)]^X1[ARIA_BRF(T2,1)]^X2[ARIA_BRF(T2,0)];  \
    T3=S1[ARIA_BRF(T3,3)]^S2[ARIA_BRF(T3,2)]^X1[ARIA_BRF(T3,1)]^X2[ARIA_BRF(T3,0)];  \
  }

// S-Box Layer 2 + M
#define SBL2_M(T0,T1,T2,T3) {  \
    T0=X1[ARIA_BRF(T0,3)]^X2[ARIA_BRF(T0,2)]^S1[ARIA_BRF(T0,1)]^S2[ARIA_BRF(T0,0)];  \
    T1=X1[ARIA_BRF(T1,3)]^X2[ARIA_BRF(T1,2)]^S1[ARIA_BRF(T1,1)]^S2[ARIA_BRF(T1,0)];  \
    T2=X1[ARIA_BRF(T2,3)]^X2[ARIA_BRF(T2,2)]^S1[ARIA_BRF(T2,1)]^S2[ARIA_BRF(T2,0)];  \
    T3=X1[ARIA_BRF(T3,3)]^X2[ARIA_BRF(T3,2)]^S1[ARIA_BRF(T3,1)]^S2[ARIA_BRF(T3,0)];  \
  }

#define ARIA_P(T0,T1,T2,T3) {                                  \
    (T1) = (((T1)<< 8)&0xff00ff00) ^ (((T1)>> 8)&0x00ff00ff);  \
    (T2) = rotrFixed((T2),16);                                 \
    (T3) = ByteReverse((T3));                                  \
  }

#define ARIA_M(X,Y) {						\
    Y=(X)<<8 ^ (X)>>8 ^ (X)<<16 ^ (X)>>16 ^ (X)<<24 ^ (X)>>24;	\
  }

#define ARIA_MM(T0,T1,T2,T3) {           \
    (T1)^=(T2); (T2)^=(T3); (T0)^=(T1);  \
    (T3)^=(T1); (T2)^=(T0); (T1)^=(T2);  \
  }

#define ARIA_FO {SBL1_M(t[0],t[1],t[2],t[3]) ARIA_MM(t[0],t[1],t[2],t[3]) ARIA_P(t[0],t[1],t[2],t[3]) ARIA_MM(t[0],t[1],t[2],t[3])}
#define ARIA_FE {SBL2_M(t[0],t[1],t[2],t[3]) ARIA_MM(t[0],t[1],t[2],t[3]) ARIA_P(t[2],t[3],t[0],t[1]) ARIA_MM(t[0],t[1],t[2],t[3])}

// n-bit right shift of Y XORed to X
template <unsigned int N>
inline void ARIA_GSRK(const word32 X[4], const word32 Y[4], byte RK[16])
{
	// MSVC is not generating a "rotate immediate". Constify to help it along.
	static const unsigned int Q = 4-(N/32);
	static const unsigned int R = N % 32;
	reinterpret_cast<word32*>(RK)[0] = (X[0]) ^ ((Y[(Q  )%4])>>R) ^ ((Y[(Q+3)%4])<<(32-R));
	reinterpret_cast<word32*>(RK)[1] = (X[1]) ^ ((Y[(Q+1)%4])>>R) ^ ((Y[(Q  )%4])<<(32-R));
	reinterpret_cast<word32*>(RK)[2] = (X[2]) ^ ((Y[(Q+2)%4])>>R) ^ ((Y[(Q+1)%4])<<(32-R));
	reinterpret_cast<word32*>(RK)[3] = (X[3]) ^ ((Y[(Q+3)%4])>>R) ^ ((Y[(Q+2)%4])<<(32-R));
}

#if CRYPTOPP_ENABLE_ARIA_NEON_INTRINSICS
template <unsigned int N>
inline void ARIA_GSRK_NEON(const uint32x4_t X, const uint32x4_t Y, byte RK[16])
{
	static const unsigned int Q1 = (4-(N/32)) % 4;
	static const unsigned int Q2 = (3-(N/32)) % 4;
	static const unsigned int R = N % 32;

	vst1q_u32(reinterpret_cast<uint32_t*>(RK),
		veorq_u32(X, veorq_u32(
			vshrq_n_u32(vextq_u32(Y, Y, Q1), R),
			vshlq_n_u32(vextq_u32(Y, Y, Q2), 32-R))));
}
#endif

void ARIA::Base::UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &params)
{
	CRYPTOPP_UNUSED(params);

	const byte *mk = key;
	byte *rk = m_rk.data();
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

	// w0 has room for 32 bytes. w1-w3 each has room for 16 bytes. t and u are 16 byte temp areas.
	word32 *w0 = m_w.data(), *w1 = m_w.data()+8, *w2 = m_w.data()+12, *w3 = m_w.data()+16, *t = m_w.data()+20;

#if CRYPTOPP_ENABLE_ARIA_SSSE3_INTRINSICS
	const __m128i MASK = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
	if (HasSSSE3())
	{
		// 'mk' may be unaligned.
		const __m128i w = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(mk)), MASK);
		_mm_store_si128((__m128i*)w0, w);
		_mm_store_si128((__m128i*)t, _mm_xor_si128(w, _mm_load_si128((const __m128i*)(KRK[q]))));

		ARIA_FO;

		if (keylen == 32)
		{
			// 'mk' may be unaligned.
			_mm_store_si128(reinterpret_cast<__m128i*>(w1),
				_mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(mk+16)), MASK));
		}
		else if (keylen == 24)
		{
			BigEndianBlock::Get(mk+16)(w1[0])(w1[1]);
			w1[2] = w1[3] = 0;
		}
		else
		{
			w1[0]=w1[1]=w1[2]=w1[3]=0;
		}
	}
	else
#endif  // CRYPTOPP_ENABLE_ARIA_SSSE3_INTRINSICS
	{
		BigEndianBlock::Get(mk)(w0[0])(w0[1])(w0[2])(w0[3]);
		t[0]=w0[0]^KRK[q][0]; t[1]=w0[1]^KRK[q][1];
		t[2]=w0[2]^KRK[q][2]; t[3]=w0[3]^KRK[q][3];

		ARIA_FO;

		if (keylen == 32)
		{
			BigEndianBlock::Get(mk+16)(w1[0])(w1[1])(w1[2])(w1[3]);
		}
		else if (keylen == 24)
		{
			BigEndianBlock::Get(mk+16)(w1[0])(w1[1]);
			w1[2] = w1[3] = 0;
		}
		else
		{
			w1[0]=w1[1]=w1[2]=w1[3]=0;
		}
	}

#if CRYPTOPP_ENABLE_ARIA_SSE2_INTRINSICS
	if (HasSSE2())
	{
		const __m128i x = _mm_xor_si128(
			_mm_load_si128((const __m128i*)(w1)),
			_mm_load_si128((const __m128i*)(t)));
		_mm_store_si128((__m128i*)(w1), x);

		q = (q==2) ? 0 : (q+1);
		_mm_store_si128((__m128i*)(t), _mm_xor_si128(x,
			_mm_load_si128((const __m128i*)(KRK[q]))));

		ARIA_FE;

		const __m128i y = _mm_xor_si128(
			_mm_load_si128((const __m128i*)(w0)),
			_mm_load_si128((const __m128i*)(t)));
		_mm_store_si128((__m128i*)(w2), y);

		q = (q==2) ? 0 : (q+1);
		_mm_store_si128((__m128i*)(t), _mm_xor_si128(y,
			_mm_load_si128((const __m128i*)(KRK[q]))));

		ARIA_FO;

		_mm_store_si128((__m128i*)(w3), _mm_xor_si128(
			_mm_load_si128((const __m128i*)(w1)),
			_mm_load_si128((const __m128i*)(t))));
	}
	else
#endif  // CRYPTOPP_ENABLE_ARIA_SSE2_INTRINSICS
	{
		w1[0]^=t[0]; w1[1]^=t[1]; w1[2]^=t[2]; w1[3]^=t[3];
		::memcpy(t, w1, 16);

		q = (q==2) ? 0 : (q+1);
		t[0]^=KRK[q][0]; t[1]^=KRK[q][1]; t[2]^=KRK[q][2]; t[3]^=KRK[q][3];

		ARIA_FE;

		t[0]^=w0[0]; t[1]^=w0[1]; t[2]^=w0[2]; t[3]^=w0[3];
		::memcpy(w2, t, 16);

		q = (q==2) ? 0 : (q+1);
		t[0]^=KRK[q][0]; t[1]^=KRK[q][1]; t[2]^=KRK[q][2]; t[3]^=KRK[q][3];

		ARIA_FO;

		w3[0]=t[0]^w1[0]; w3[1]=t[1]^w1[1]; w3[2]=t[2]^w1[2]; w3[3]=t[3]^w1[3];
	}

#if CRYPTOPP_ENABLE_ARIA_NEON_INTRINSICS
	if (HasNEON())
	{
		const uint32x4_t w0 = vld1q_u32((const uint32_t*)(m_w.data()+0));
		const uint32x4_t w1 = vld1q_u32((const uint32_t*)(m_w.data()+8));
		const uint32x4_t w2 = vld1q_u32((const uint32_t*)(m_w.data()+12));
		const uint32x4_t w3 = vld1q_u32((const uint32_t*)(m_w.data()+16));

		ARIA_GSRK_NEON<19>(w0, w1, rk +   0);
		ARIA_GSRK_NEON<19>(w1, w2, rk +  16);
		ARIA_GSRK_NEON<19>(w2, w3, rk +  32);
		ARIA_GSRK_NEON<19>(w3, w0, rk +  48);
		ARIA_GSRK_NEON<31>(w0, w1, rk +  64);
		ARIA_GSRK_NEON<31>(w1, w2, rk +  80);
		ARIA_GSRK_NEON<31>(w2, w3, rk +  96);
		ARIA_GSRK_NEON<31>(w3, w0, rk + 112);
		ARIA_GSRK_NEON<67>(w0, w1, rk + 128);
		ARIA_GSRK_NEON<67>(w1, w2, rk + 144);
		ARIA_GSRK_NEON<67>(w2, w3, rk + 160);
		ARIA_GSRK_NEON<67>(w3, w0, rk + 176);
		ARIA_GSRK_NEON<97>(w0, w1, rk + 192);

		if (keylen > 16)
		{
			ARIA_GSRK_NEON<97>(w1, w2, rk + 208);
			ARIA_GSRK_NEON<97>(w2, w3, rk + 224);

			if (keylen > 24)
			{
				ARIA_GSRK_NEON< 97>(w3, w0, rk + 240);
				ARIA_GSRK_NEON<109>(w0, w1, rk + 256);
			}
		}
	}
	else
#endif  // CRYPTOPP_ENABLE_ARIA_NEON_INTRINSICS
	{
		ARIA_GSRK<19>(w0, w1, rk +   0);
		ARIA_GSRK<19>(w1, w2, rk +  16);
		ARIA_GSRK<19>(w2, w3, rk +  32);
		ARIA_GSRK<19>(w3, w0, rk +  48);
		ARIA_GSRK<31>(w0, w1, rk +  64);
		ARIA_GSRK<31>(w1, w2, rk +  80);
		ARIA_GSRK<31>(w2, w3, rk +  96);
		ARIA_GSRK<31>(w3, w0, rk + 112);
		ARIA_GSRK<67>(w0, w1, rk + 128);
		ARIA_GSRK<67>(w1, w2, rk + 144);
		ARIA_GSRK<67>(w2, w3, rk + 160);
		ARIA_GSRK<67>(w3, w0, rk + 176);
		ARIA_GSRK<97>(w0, w1, rk + 192);

		if (keylen > 16)
		{
			ARIA_GSRK<97>(w1, w2, rk + 208);
			ARIA_GSRK<97>(w2, w3, rk + 224);

			if (keylen > 24)
			{
				ARIA_GSRK< 97>(w3, w0, rk + 240);
				ARIA_GSRK<109>(w0, w1, rk + 256);
			}
		}
	}

	// Decryption operation
	if (!IsForwardTransformation())
	{
		word32 *a, *z, *s;
		rk = m_rk.data();
		r = R; q = Q;

#if CRYPTOPP_ENABLE_ARIA_SSE2_INTRINSICS
		if (HasSSE2())
		{
			a=reinterpret_cast<word32*>(rk); s=m_w.data()+24; z=a+r*4;
			_mm_store_si128((__m128i*)t, _mm_load_si128((const __m128i*)a));
			_mm_store_si128((__m128i*)a, _mm_load_si128((const __m128i*)z));
			_mm_store_si128((__m128i*)z, _mm_load_si128((const __m128i*)t));

			a+=4; z-=4;
			for (; a<z; a+=4, z-=4)
			{
				ARIA_M(a[0],t[0]); ARIA_M(a[1],t[1]); ARIA_M(a[2],t[2]); ARIA_M(a[3],t[3]);
				ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
				_mm_store_si128((__m128i*)s, _mm_load_si128((const __m128i*)t));

				ARIA_M(z[0],t[0]); ARIA_M(z[1],t[1]); ARIA_M(z[2],t[2]); ARIA_M(z[3],t[3]);
				ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
				_mm_store_si128((__m128i*)a, _mm_load_si128((const __m128i*)t));
				_mm_store_si128((__m128i*)z, _mm_load_si128((const __m128i*)s));
			}

			ARIA_M(a[0],t[0]); ARIA_M(a[1],t[1]); ARIA_M(a[2],t[2]); ARIA_M(a[3],t[3]);
			ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
			_mm_store_si128((__m128i*)z, _mm_load_si128((const __m128i*)t));
		}
		else
#endif
		{
			a=reinterpret_cast<word32*>(rk); s=m_w.data()+24; z=a+r*4;
			::memcpy(t, a, 16); ::memcpy(a, z, 16); ::memcpy(z, t, 16);

			a+=4; z-=4;
			for (; a<z; a+=4, z-=4)
			{
				ARIA_M(a[0],t[0]); ARIA_M(a[1],t[1]); ARIA_M(a[2],t[2]); ARIA_M(a[3],t[3]);
				ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
				::memcpy(s, t, 16);

				ARIA_M(z[0],t[0]); ARIA_M(z[1],t[1]); ARIA_M(z[2],t[2]); ARIA_M(z[3],t[3]);
				ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
				::memcpy(a, t, 16); ::memcpy(z, s, 16);
			}

			ARIA_M(a[0],t[0]); ARIA_M(a[1],t[1]); ARIA_M(a[2],t[2]); ARIA_M(a[3],t[3]);
			ARIA_MM(t[0],t[1],t[2],t[3]); ARIA_P(t[0],t[1],t[2],t[3]); ARIA_MM(t[0],t[1],t[2],t[3]);
			::memcpy(z, t, 16);
		}
	}
}

void ARIA::Base::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	const byte *rk = reinterpret_cast<const byte*>(m_rk.data());
	word32 *t = const_cast<word32*>(m_w.data()+20);

	// Timing attack countermeasure. See comments in Rijndael for more details.
	// We used Yun's 32-bit implementation, so we use words rather than bytes.
	const int cacheLineSize = GetCacheLineSize();
	unsigned int i;
	volatile word32 _u = 0;
	word32 u = _u;

	for (i=0; i<COUNTOF(S1); i+=cacheLineSize/(sizeof(S1[0])))
		u |= *(S1+i);
	t[0] |= u;

	BigEndianBlock::Get(inBlock)(t[0])(t[1])(t[2])(t[3]);

	if (m_rounds > 12) {
		ARIA_KXL; rk+= 16; ARIA_FO;
		ARIA_KXL; rk+= 16; ARIA_FE;
	}

	if (m_rounds > 14) {
		ARIA_KXL; rk+= 16; ARIA_FO;
		ARIA_KXL; rk+= 16; ARIA_FE;
	}

	ARIA_KXL; rk+= 16; ARIA_FO; ARIA_KXL; rk+= 16; ARIA_FE;
	ARIA_KXL; rk+= 16; ARIA_FO; ARIA_KXL; rk+= 16; ARIA_FE;
	ARIA_KXL; rk+= 16; ARIA_FO; ARIA_KXL; rk+= 16; ARIA_FE;
	ARIA_KXL; rk+= 16; ARIA_FO; ARIA_KXL; rk+= 16; ARIA_FE;
	ARIA_KXL; rk+= 16; ARIA_FO; ARIA_KXL; rk+= 16; ARIA_FE;
	ARIA_KXL; rk+= 16; ARIA_FO; ARIA_KXL; rk+= 16;

#ifdef IS_LITTLE_ENDIAN
# if CRYPTOPP_ENABLE_ARIA_SSSE3_INTRINSICS
	const __m128i MASK = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
	if (HasSSSE3())
	{
		outBlock[ 0] = (byte)(X1[ARIA_BRF(t[0],3)]   );
		outBlock[ 1] = (byte)(X2[ARIA_BRF(t[0],2)]>>8);
		outBlock[ 2] = (byte)(S1[ARIA_BRF(t[0],1)]   );
		outBlock[ 3] = (byte)(S2[ARIA_BRF(t[0],0)]   );
		outBlock[ 4] = (byte)(X1[ARIA_BRF(t[1],3)]   );
		outBlock[ 5] = (byte)(X2[ARIA_BRF(t[1],2)]>>8);
		outBlock[ 6] = (byte)(S1[ARIA_BRF(t[1],1)]   );
		outBlock[ 7] = (byte)(S2[ARIA_BRF(t[1],0)]   );
		outBlock[ 8] = (byte)(X1[ARIA_BRF(t[2],3)]   );
		outBlock[ 9] = (byte)(X2[ARIA_BRF(t[2],2)]>>8);
		outBlock[10] = (byte)(S1[ARIA_BRF(t[2],1)]   );
		outBlock[11] = (byte)(S2[ARIA_BRF(t[2],0)]   );
		outBlock[12] = (byte)(X1[ARIA_BRF(t[3],3)]   );
		outBlock[13] = (byte)(X2[ARIA_BRF(t[3],2)]>>8);
		outBlock[14] = (byte)(S1[ARIA_BRF(t[3],1)]   );
		outBlock[15] = (byte)(S2[ARIA_BRF(t[3],0)]   );

		// 'outBlock' may be unaligned.
		_mm_storeu_si128(reinterpret_cast<__m128i*>(outBlock),
			_mm_xor_si128(_mm_loadu_si128((const __m128i*)(outBlock)),
				_mm_shuffle_epi8(_mm_load_si128((const __m128i*)(rk)), MASK)));

		// 'outBlock' and 'xorBlock' may be unaligned.
		if (xorBlock != NULLPTR)
		{
			_mm_storeu_si128((__m128i*)(outBlock),
				_mm_xor_si128(
					_mm_loadu_si128((const __m128i*)(outBlock)),
					_mm_loadu_si128((const __m128i*)(xorBlock))));
		}
		return;
	}
	else
# endif  // CRYPTOPP_ENABLE_ARIA_SSSE3_INTRINSICS
	{
		outBlock[ 0] = (byte)(X1[ARIA_BRF(t[0],3)]   ) ^ rk[ 3];
		outBlock[ 1] = (byte)(X2[ARIA_BRF(t[0],2)]>>8) ^ rk[ 2];
		outBlock[ 2] = (byte)(S1[ARIA_BRF(t[0],1)]   ) ^ rk[ 1];
		outBlock[ 3] = (byte)(S2[ARIA_BRF(t[0],0)]   ) ^ rk[ 0];
		outBlock[ 4] = (byte)(X1[ARIA_BRF(t[1],3)]   ) ^ rk[ 7];
		outBlock[ 5] = (byte)(X2[ARIA_BRF(t[1],2)]>>8) ^ rk[ 6];
		outBlock[ 6] = (byte)(S1[ARIA_BRF(t[1],1)]   ) ^ rk[ 5];
		outBlock[ 7] = (byte)(S2[ARIA_BRF(t[1],0)]   ) ^ rk[ 4];
		outBlock[ 8] = (byte)(X1[ARIA_BRF(t[2],3)]   ) ^ rk[11];
		outBlock[ 9] = (byte)(X2[ARIA_BRF(t[2],2)]>>8) ^ rk[10];
		outBlock[10] = (byte)(S1[ARIA_BRF(t[2],1)]   ) ^ rk[ 9];
		outBlock[11] = (byte)(S2[ARIA_BRF(t[2],0)]   ) ^ rk[ 8];
		outBlock[12] = (byte)(X1[ARIA_BRF(t[3],3)]   ) ^ rk[15];
		outBlock[13] = (byte)(X2[ARIA_BRF(t[3],2)]>>8) ^ rk[14];
		outBlock[14] = (byte)(S1[ARIA_BRF(t[3],1)]   ) ^ rk[13];
		outBlock[15] = (byte)(S2[ARIA_BRF(t[3],0)]   ) ^ rk[12];
	}
#else
		outBlock[ 0] = (byte)(X1[ARIA_BRF(t[0],3)]   );
		outBlock[ 1] = (byte)(X2[ARIA_BRF(t[0],2)]>>8);
		outBlock[ 2] = (byte)(S1[ARIA_BRF(t[0],1)]   );
		outBlock[ 3] = (byte)(S2[ARIA_BRF(t[0],0)]   );
		outBlock[ 4] = (byte)(X1[ARIA_BRF(t[1],3)]   );
		outBlock[ 5] = (byte)(X2[ARIA_BRF(t[1],2)]>>8);
		outBlock[ 6] = (byte)(S1[ARIA_BRF(t[1],1)]   );
		outBlock[ 7] = (byte)(S2[ARIA_BRF(t[1],0)]   );
		outBlock[ 8] = (byte)(X1[ARIA_BRF(t[2],3)]   );
		outBlock[ 9] = (byte)(X2[ARIA_BRF(t[2],2)]>>8);
		outBlock[10] = (byte)(S1[ARIA_BRF(t[2],1)]   );
		outBlock[11] = (byte)(S2[ARIA_BRF(t[2],0)]   );
		outBlock[12] = (byte)(X1[ARIA_BRF(t[3],3)]   );
		outBlock[13] = (byte)(X2[ARIA_BRF(t[3],2)]>>8);
		outBlock[14] = (byte)(S1[ARIA_BRF(t[3],1)]   );
		outBlock[15] = (byte)(S2[ARIA_BRF(t[3],0)]   );

		t = reinterpret_cast<word32*>(outBlock);
		BigEndianBlock::Put(rk, t)(t[0])(t[1])(t[2])(t[3]);
#endif

#if CRYPTOPP_ENABLE_ARIA_NEON_INTRINSICS
	if (HasNEON())
	{
		if (xorBlock != NULLPTR)
		{
			vst1q_u32(reinterpret_cast<uint32_t*>(outBlock),
				veorq_u32(
					vld1q_u32((const uint32_t*)outBlock),
					vld1q_u32((const uint32_t*)xorBlock)));
		}
	}
	else
#endif  // CRYPTOPP_ENABLE_ARIA_NEON_INTRINSICS
	{
		if (xorBlock != NULLPTR)
			for (unsigned int n=0; n<16; ++n)
				outBlock[n] ^= xorBlock[n];
	}
}

NAMESPACE_END
