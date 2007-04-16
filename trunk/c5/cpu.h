#ifndef CRYPTOPP_CPU_H
#define CRYPTOPP_CPU_H

#include "config.h"

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_X86_ASM_AVAILABLE) || (_MSC_VER >= 1400 && CRYPTOPP_BOOL_X64)

#define CRYPTOPP_CPUID_AVAILABLE

// these should not be used directly
extern bool g_x86DetectionDone;
extern bool g_hasSSE2, g_hasMMX, g_hasSSSE3, g_isP4;
extern int g_cacheLineSize;
void DetectX86Features();

bool CpuId(word32 input, word32 *output);

#if CRYPTOPP_BOOL_X64
inline bool HasSSE2()	{return true;}
inline bool HasMMX()	{return true;}
#else

inline bool HasSSE2()
{
	if (!g_x86DetectionDone)
		DetectX86Features();
	return g_hasSSE2;
}

inline bool HasMMX()
{
	if (!g_x86DetectionDone)
		DetectX86Features();
	return g_hasMMX;
}

#endif

inline bool HasSSSE3()
{
	if (!g_x86DetectionDone)
		DetectX86Features();
	return g_hasSSSE3;
}

inline bool IsP4()
{
	if (!g_x86DetectionDone)
		DetectX86Features();
	return g_isP4;
}

inline int GetCacheLineSize()
{
	if (!g_x86DetectionDone)
		DetectX86Features();
	return g_cacheLineSize;
}

#else

inline int GetCacheLineSize()
{
	return CRYPTOPP_L1_CACHE_LINE_SIZE;
}

inline bool HasSSSE3()	{return false;}
inline bool IsP4()		{return false;}

// assume MMX and SSE2 if intrinsics are enabled
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE || CRYPTOPP_BOOL_X64
inline bool HasSSE2()	{return true;}
inline bool HasMMX()	{return true;}
#else
inline bool HasSSE2()	{return false;}
inline bool HasMMX()	{return false;}
#endif

#endif		// #ifdef CRYPTOPP_X86_ASM_AVAILABLE || _MSC_VER >= 1400

#if defined(__GNUC__)
	// define these in two steps to allow arguments to be expanded
	#define GNU_AS1(x) #x ";"
	#define GNU_AS2(x, y) #x ", " #y ";"
	#define GNU_AS3(x, y, z) #x ", " #y ", " #z ";"
	#define GNU_ASL(x) "\n" #x ":"
	#define GNU_ASJ(x, y, z) #x " " #y #z ";"
	#define AS1(x) GNU_AS1(x)
	#define AS2(x, y) GNU_AS2(x, y)
	#define AS3(x, y, z) GNU_AS3(x, y, z)
	#define ASS(x, y, a, b, c, d) #x ", " #y ", " #a "*64+" #b "*16+" #c "*4+" #d ";"
	#define ASL(x) GNU_ASL(x)
	#define ASJ(x, y, z) GNU_ASJ(x, y, z)
	#define ASC(x, y) #x " " #y ";"
#else
	#define AS1(x) __asm {x}
	#define AS2(x, y) __asm {x, y}
	#define AS3(x, y, z) __asm {x, y, z}
	#define ASS(x, y, a, b, c, d) __asm {x, y, _MM_SHUFFLE(a, b, c, d)}
	#define ASL(x) __asm {label##x:}
	#define ASJ(x, y, z) __asm {x label##y}
	#define ASC(x, y) __asm {x label##y}
#endif

// GNU assembler doesn't seem to have mod operator
#define ASM_MOD(x, y) ((x)-((x)/(y))*(y))

NAMESPACE_END

#endif
