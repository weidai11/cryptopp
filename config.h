#ifndef CRYPTOPP_CONFIG_H
#define CRYPTOPP_CONFIG_H

// ***************** Important Settings ********************

// define this if running on a big-endian CPU
#if !defined(IS_LITTLE_ENDIAN) && (defined(__BIG_ENDIAN__) || defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__mips__) || (defined(__MWERKS__) && !defined(__INTEL__)))
#	define IS_BIG_ENDIAN
#endif

// define this if running on a little-endian CPU
// big endian will be assumed if IS_LITTLE_ENDIAN is not defined
#ifndef IS_BIG_ENDIAN
#	define IS_LITTLE_ENDIAN
#endif

// define this if you want to disable all OS-dependent features,
// such as sockets and OS-provided random number generators
// #define NO_OS_DEPENDENCE

// Define this to use features provided by Microsoft's CryptoAPI.
// Currently the only feature used is random number generation.
// This macro will be ignored if NO_OS_DEPENDENCE is defined.
#define USE_MS_CRYPTOAPI

// Define this to 1 to enforce the requirement in FIPS 186-2 Change Notice 1 that only 1024 bit moduli be used
#ifndef DSA_1024_BIT_MODULUS_ONLY
#	define DSA_1024_BIT_MODULUS_ONLY 1
#endif

// ***************** Less Important Settings ***************

// define this to retain (as much as possible) old deprecated function and class names
// #define CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY

#define GZIP_OS_CODE 0

// Try this if your CPU has 256K internal cache or a slow multiply instruction
// and you want a (possibly) faster IDEA implementation using log tables
// #define IDEA_LARGECACHE

// Try this if you have a large cache or your CPU is slow manipulating
// individual bytes.
// #define DIAMOND_USE_PERMTABLE

// Define this if, for the linear congruential RNG, you want to use
// the original constants as specified in S.K. Park and K.W. Miller's
// CACM paper.
// #define LCRNG_ORIGINAL_NUMBERS

// choose which style of sockets to wrap (mostly useful for cygwin which has both)
#define PREFER_BERKELEY_STYLE_SOCKETS
// #define PREFER_WINDOWS_STYLE_SOCKETS

// ***************** Important Settings Again ********************
// But the defaults should be ok.

// namespace support is now required
#ifdef NO_NAMESPACE
#	error namespace support is now required
#endif

// Define this to workaround a Microsoft CryptoAPI bug where
// each call to CryptAcquireContext causes a 100 KB memory leak.
// Defining this will cause Crypto++ to make only one call to CryptAcquireContext.
#define WORKAROUND_MS_BUG_Q258000

// Avoid putting "CryptoPP::" in front of everything in Doxygen output
#ifdef CRYPTOPP_DOXYGEN_PROCESSING
#	define CryptoPP
#	define NAMESPACE_BEGIN(x)
#	define NAMESPACE_END
#else
#	define NAMESPACE_BEGIN(x) namespace x {
#	define NAMESPACE_END }
#endif
#define ANONYMOUS_NAMESPACE_BEGIN namespace {
#define USING_NAMESPACE(x) using namespace x;
#define DOCUMENTED_NAMESPACE_BEGIN(x) namespace x {
#define DOCUMENTED_NAMESPACE_END }

// What is the type of the third parameter to bind?
// For Unix, the new standard is ::socklen_t (typically unsigned int), and the old standard is int.
// Unfortunately there is no way to tell whether or not socklen_t is defined.
// To work around this, TYPE_OF_SOCKLEN_T is a macro so that you can change it from the makefile.
#ifndef TYPE_OF_SOCKLEN_T
#	if defined(_WIN32) || defined(__CYGWIN__) || defined(__MACH__)
#		define TYPE_OF_SOCKLEN_T int
#	else
#		define TYPE_OF_SOCKLEN_T ::socklen_t
#	endif
#endif

#if defined(__CYGWIN__) && defined(PREFER_WINDOWS_STYLE_SOCKETS)
#	define __USE_W32_SOCKETS
#endif

typedef unsigned char byte;     // moved outside namespace for Borland C++Builder 5

NAMESPACE_BEGIN(CryptoPP)

typedef unsigned short word16;
#if defined(__alpha) && !defined(_MSC_VER)
	typedef unsigned int word32;
#else
	typedef unsigned long word32;
#endif

#if defined(__GNUC__) || defined(__MWERKS__)
#	define WORD64_AVAILABLE
	typedef unsigned long long word64;
#	define W64LIT(x) x##LL
#elif defined(_MSC_VER) || defined(__BCPLUSPLUS__)
#	define WORD64_AVAILABLE
	typedef unsigned __int64 word64;
#	define W64LIT(x) x##ui64
#endif

// defined this if your CPU is not 64-bit
#if defined(WORD64_AVAILABLE) && !defined(__alpha)
#	define SLOW_WORD64
#endif

// word should have the same size as your CPU registers
// dword should be twice as big as word

#if (defined(__GNUC__) && !defined(__alpha)) || defined(__MWERKS__)
	typedef unsigned long word;
	typedef unsigned long long dword;
#elif defined(_MSC_VER) || defined(__BCPLUSPLUS__)
	typedef unsigned __int32 word;
	typedef unsigned __int64 dword;
#else
	typedef unsigned int word;
	typedef unsigned long dword;
#endif

const unsigned int WORD_SIZE = sizeof(word);
const unsigned int WORD_BITS = WORD_SIZE * 8;

#define LOW_WORD(x) (word)(x)

union dword_union
{
	dword_union (const dword &dw) : dw(dw) {}
	dword dw;
	word w[2];
};

#ifdef IS_LITTLE_ENDIAN
#	define HIGH_WORD(x) (dword_union(x).w[1])
#else
#	define HIGH_WORD(x) (dword_union(x).w[0])
#endif

// if the above HIGH_WORD macro doesn't work (if you are not sure, compile it
// and run the validation tests), try this:
// #define HIGH_WORD(x) (word)((x)>>WORD_BITS)

#if defined(_MSC_VER) || defined(__BCPLUSPLUS__)
#	define INTEL_INTRINSICS
#	define FAST_ROTATE
#elif defined(__MWERKS__) && TARGET_CPU_PPC
#	define PPC_INTRINSICS
#	define FAST_ROTATE
#elif defined(__GNUC__) && defined(__i386__)
	// GCC does peephole optimizations which should result in using rotate instructions
#	define FAST_ROTATE
#endif

NAMESPACE_END

// VC60 workaround: it doesn't allow typename in some places
#if defined(_MSC_VER) && (_MSC_VER < 1300)
#define CPP_TYPENAME
#else
#define CPP_TYPENAME typename
#endif

#ifdef _MSC_VER
	// 4250: dominance
	// 4660: explicitly instantiating a class that's already implicitly instantiated
	// 4661: no suitable definition provided for explicit template instantiation request
	// 4786: identifer was truncated in debug information
	// 4355: 'this' : used in base member initializer list
#	pragma warning(disable: 4250 4660 4661 4786 4355)
#endif

// ***************** determine availability of OS features ********************

#ifndef NO_OS_DEPENDENCE

#if defined(_WIN32) || defined(__CYGWIN__)
#define CRYPTOPP_WIN32_AVAILABLE
#endif

#if defined(__unix__) || defined(__MACH__)
#define CRYPTOPP_UNIX_AVAILABLE
#endif

#if defined(WORD64_AVAILABLE) && (defined(CRYPTOPP_WIN32_AVAILABLE) || defined(CRYPTOPP_UNIX_AVAILABLE) || defined(macintosh))
#	define HIGHRES_TIMER_AVAILABLE
#endif

#ifdef CRYPTOPP_UNIX_AVAILABLE
#	define HAS_BERKELEY_STYLE_SOCKETS
#endif

#ifdef CRYPTOPP_WIN32_AVAILABLE
#	define HAS_WINDOWS_STYLE_SOCKETS
#endif

#if defined(HIGHRES_TIMER_AVAILABLE) && (defined(HAS_BERKELEY_STYLE_SOCKETS) || defined(HAS_WINDOWS_STYLE_SOCKETS))
#	define SOCKETS_AVAILABLE
#endif

#if defined(HAS_WINDOWS_STYLE_SOCKETS) && (!defined(HAS_BERKELEY_STYLE_SOCKETS) || defined(PREFER_WINDOWS_STYLE_SOCKETS))
#	define USE_WINDOWS_STYLE_SOCKETS
#else
#	define USE_BERKELEY_STYLE_SOCKETS
#endif

#if defined(CRYPTOPP_WIN32_AVAILABLE) && !defined(USE_BERKELEY_STYLE_SOCKETS)
#	define WINDOWS_PIPES_AVAILABLE
#endif

#if defined(CRYPTOPP_WIN32_AVAILABLE) && defined(USE_MS_CRYPTOAPI)
#	define NONBLOCKING_RNG_AVAILABLE
#	define OS_RNG_AVAILABLE
#endif

#ifdef CRYPTOPP_UNIX_AVAILABLE
#	define NONBLOCKING_RNG_AVAILABLE
#	define BLOCKING_RNG_AVAILABLE
#	define OS_RNG_AVAILABLE
#	define HAS_PTHREADS
#	define THREADS_AVAILABLE
#endif

#ifdef CRYPTOPP_WIN32_AVAILABLE
#	define HAS_WINTHREADS
#	define THREADS_AVAILABLE
#endif

#endif	// NO_OS_DEPENDENCE

#endif
