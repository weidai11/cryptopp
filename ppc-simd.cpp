// crc-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to AltiVec,
//    Power8 and in-core crypto instructions. A separate source file
//    is needed because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

#include "pch.h"
#include "config.h"
#include "stdcpp.h"

// We set CRYPTOPP_ALTIVEC_AVAILABLE and friends based on
// compiler version and preprocessor macros. If the compiler
// feature is not available, then we have to disable it here.
#if !defined(__ALTIVEC__)
# undef CRYPTOPP_ALTIVEC_AVAILABLE
#endif
#if !(defined(__CRYPTO__) || defined(_ARCH_PWR8) || defined(_ARCH_PWR9))
# undef CRYPTOPP_POWER8_AVAILABLE
# undef CRYPTOPP_POWER8_AES_AVAILABLE
# undef CRYPTOPP_POWER8_SHA_AVAILABLE
# undef CRYPTOPP_POWER8_CRYPTO_AVAILABLE
#endif

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include <altivec.h>
# undef vector
# undef pixel
# undef bool
#endif

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# if defined(CRYPTOPP_XLC_VERSION)
 // #include <builtins.h>
 typedef __vector unsigned char uint8x16_p8;
 typedef __vector unsigned long long uint64x2_p8;
#elif defined(CRYPTOPP_GCC_VERSION)
 typedef __vector unsigned char uint8x16_p8;
 typedef __vector unsigned long long uint64x2_p8;
 #endif
#endif

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
# include <signal.h>
# include <setjmp.h>
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
# define EXCEPTION_EXECUTE_HANDLER 1
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
extern "C" {
    typedef void (*SigHandler)(int);

	static jmp_buf s_jmpSIGILL;
	static void SigIllHandler(int)
	{
		longjmp(s_jmpSIGILL, 1);
	}
};
#endif  // Not CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)
bool CPU_ProbeAltivec()
{
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile int result = true;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpSIGILL))
		result = false;
	else
	{
		CRYPTOPP_ALIGN_DATA(16)
		const byte b1[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		CRYPTOPP_ALIGN_DATA(16)
		const byte b2[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
		CRYPTOPP_ALIGN_DATA(16) byte b3[16];
#if defined(CRYPTOPP_XLC_VERSION)
		const uint8x16_p8 v1 = vec_ld(0, b1);
		const uint8x16_p8 v2 = vec_ld(0, b2);
		const uint8x16_p8 v3 = vec_xor(v1, v2);
		vec_st(v3, 0, b3);
#elif defined(CRYPTOPP_GCC_VERSION)
		const uint64x2_p8 v1 = (uint64x2_p8)vec_ld(0, b1);
		const uint64x2_p8 v2 = (uint64x2_p8)vec_ld(0, b2);
		const uint64x2_p8 v3 = (uint64x2_p8)vec_xor(v1, v2);
		vec_st((uint8x16_p8)v3, 0, b3);
#endif
		result = (0 == std::memcmp(b2, b3, 16));
	}

	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE
}

#if 0
bool CPU_ProbePower7()
{
#if (CRYPTOPP_POWER7_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile int result = false;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpSIGILL))
		result = false;
	else
	{
		CRYPTOPP_ALIGN_DATA(16) // Non-const due to XL C/C++
		byte b1[19] = {-1, -1, -1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
		CRYPTOPP_ALIGN_DATA(16) byte b2[16];
#if defined(CRYPTOPP_XLC_VERSION)
		const uint8x16_p8 v1 = vec_xl(0, reinterpret_cast<byte*>(b1)+3);
		vec_xst(v1, 0, reinterpret_cast<byte*>(b2));
#elif defined(CRYPTOPP_GCC_VERSION)
		const uint8x16_p8 v1 = vec_vsx_ld(0, b1+3);
		vec_vsx_st(v1, 0, (byte*)b2);
#endif
		result = (0 == std::memcmp(b1+3, b2, 16));
	}

	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_POWER7_AVAILABLE
}
#endif

bool CPU_ProbePower8()
{
#if (CRYPTOPP_POWER8_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile int result = true;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpSIGILL))
		result = false;
	else
	{
		CRYPTOPP_ALIGN_DATA(16) // Non-const due to XL C/C++
		byte b1[19] = {255, 255, 255, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
		CRYPTOPP_ALIGN_DATA(16) byte b2[16];
#if defined(CRYPTOPP_XLC_VERSION)
		const uint8x16_p8 v1 = vec_xl(0, reinterpret_cast<byte*>(b1)+3);
		vec_xst(v1, 0, reinterpret_cast<byte*>(b2));
#elif defined(CRYPTOPP_GCC_VERSION)
		const uint8x16_p8 v1 = vec_vsx_ld(0, b1+3);
		vec_vsx_st(v1, 0, b2);
#endif
		result = (0 == std::memcmp(b1+3, b2, 16));
	}

	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE
}

bool CPU_ProbeAES()
{
#if (CRYPTOPP_POWER8_AES_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile int result = true;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpSIGILL))
		result = false;
	else
	{
		CRYPTOPP_ALIGN_DATA(16) // Non-const due to XL C/C++
		byte key[16] = {0xA0, 0xFA, 0xFE, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05};
		CRYPTOPP_ALIGN_DATA(16) // Non-const due to XL C/C++
		byte state[16] = {0x19, 0x3d, 0xe3, 0xb3, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08};
		CRYPTOPP_ALIGN_DATA(16) byte r[16] = {255}, z[16] = {};
#if defined(CRYPTOPP_XLC_VERSION)
		uint8x16_p8 k = vec_xl(0, reinterpret_cast<byte*>(key));
		uint8x16_p8 s = vec_xl(0, reinterpret_cast<byte*>(state));
		s = __vncipher(s, k);
		s = __vncipherlast(s, k);
		vec_xst(s, 0, reinterpret_cast<byte*>(r));
#elif defined(CRYPTOPP_GCC_VERSION)
		uint64x2_p8 k = (uint64x2_p8)vec_xl(0, key);
		uint64x2_p8 s = (uint64x2_p8)vec_xl(0, state);
		s = __builtin_crypto_vncipher(s, k);
		s = __builtin_crypto_vncipherlast(s, k);
		vec_xst((uint8x16_p8)s, 0, r);
#endif
		result = (0 != std::memcmp(r, z, 16));
	}

	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE
}

bool CPU_ProbeSHA1()
{
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile int result = false;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpSIGILL))
		result = false;
	else
	{

	}

	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE
}

bool CPU_ProbeSHA2()
{
#if (CRYPTOPP_ALTIVEC_AVAILABLE)
# if defined(CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY)

	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
	volatile int result = false;

	volatile SigHandler oldHandler = signal(SIGILL, SigIllHandler);
	if (oldHandler == SIG_ERR)
		return false;

	volatile sigset_t oldMask;
	if (sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
		return false;

	if (setjmp(s_jmpSIGILL))
		result = false;
	else
	{

	}

	sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
	signal(SIGILL, oldHandler);
	return result;
# endif
#else
	return false;
#endif  // CRYPTOPP_ALTIVEC_AVAILABLE
}
# endif  // CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64
NAMESPACE_END
