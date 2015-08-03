#ifndef CRYPTOPP_MISC_H
#define CRYPTOPP_MISC_H

#include "cryptlib.h"
#include "smartptr.h"
#include "stdcpp.h"
#include "trap.h"

#ifdef _MSC_VER
	#if _MSC_VER >= 1400
		// VC2005 workaround: disable declarations that conflict with winnt.h
		#define _interlockedbittestandset CRYPTOPP_DISABLED_INTRINSIC_1
		#define _interlockedbittestandreset CRYPTOPP_DISABLED_INTRINSIC_2
		#define _interlockedbittestandset64 CRYPTOPP_DISABLED_INTRINSIC_3
		#define _interlockedbittestandreset64 CRYPTOPP_DISABLED_INTRINSIC_4
		#include <intrin.h>
		#undef _interlockedbittestandset
		#undef _interlockedbittestandreset
		#undef _interlockedbittestandset64
		#undef _interlockedbittestandreset64
		#define CRYPTOPP_FAST_ROTATE(x) 1
	#elif _MSC_VER >= 1300
		#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32 | (x) == 64)
	#else
		#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32)
	#endif
#elif (defined(__MWERKS__) && TARGET_CPU_PPC) || \
	(defined(__GNUC__) && (defined(_ARCH_PWR2) || defined(_ARCH_PWR) || defined(_ARCH_PPC) || defined(_ARCH_PPC64) || defined(_ARCH_COM)))
	#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32)
#elif defined(__GNUC__) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X86)	// depend on GCC's peephole optimization to generate rotate instructions
	#define CRYPTOPP_FAST_ROTATE(x) 1
#else
	#define CRYPTOPP_FAST_ROTATE(x) 0
#endif

#ifdef __BORLANDC__
#include <mem.h>
#endif

#if defined(__GNUC__) && defined(__linux__)
#define CRYPTOPP_BYTESWAP_AVAILABLE
#include <byteswap.h>
#endif

// Used to supress some warnings in some header and implementation files.
//   Some platforms, like CentOS and OpenBSD, use old compilers that don't understand -Wno-unknown-pragma.
//   These diagnostic blocks showed up somewhere between GCC 4.1 and 4.2, but 4.4 gets us semi-modern compilers.
//   It seems using diagnostic blocks to manage warnings is semi-broken for GCC. Just leave it in place because
//   GCC_DIAGNOSTIC_AWARE will help silence some warnings under GCC, and Clang responds to it as expected.
//   (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53431).
#define GCC_DIAGNOSTIC_AWARE ((__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)) || defined(__clang__))

// Used to manage function-level optimizations when working around compiler issues.
//   At -O3, GCC vectorizes and uses SSE instructions, even if alignment does not meet instruction requirements.
#define GCC_OPTIMIZE_AWARE ((__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)) || defined(__clang__))

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wunused-value"
# pragma GCC diagnostic ignored "-Wunused-variable"
# pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

NAMESPACE_BEGIN(CryptoPP)

// ************** compile-time assertion ***************

template <bool b>
struct CompileAssert
{
	static char dummy[2*b-1];
};

// __attribute__ ((unused)) will help silence the "unused variable warnings. Its available
//   at least as early as GCC 2.9.3 (https://gcc.gnu.org/onlinedocs/gcc-2.95.3/gcc_4.html#SEC84)
//   This also works into our -Wall -Wextra strategy for warnings.
#define CRYPTOPP_COMPILE_ASSERT(assertion) CRYPTOPP_COMPILE_ASSERT_INSTANCE(assertion, __LINE__)
#if defined(CRYPTOPP_EXPORTS) || defined(CRYPTOPP_IMPORTS)
#define CRYPTOPP_COMPILE_ASSERT_INSTANCE(assertion, instance)
#else
# if defined(__GNUC__)
#  define CRYPTOPP_COMPILE_ASSERT_INSTANCE(assertion, instance) \
			static CompileAssert<(assertion)> \
	CRYPTOPP_ASSERT_JOIN(cryptopp_assert_, instance) __attribute__ ((unused))
# else
#  define CRYPTOPP_COMPILE_ASSERT_INSTANCE(assertion, instance) \
		static CompileAssert<(assertion)> \
		CRYPTOPP_ASSERT_JOIN(cryptopp_assert_, instance)
# endif // __GNUC__
#endif
#define CRYPTOPP_ASSERT_JOIN(X, Y) CRYPTOPP_DO_ASSERT_JOIN(X, Y)
#define CRYPTOPP_DO_ASSERT_JOIN(X, Y) X##Y

// ************** unused variable suppression ***************
// Cast to void. Portable way to suppress warning
#define CRYPTOPP_UNUSED(x) ((void)x)

// ************** unused function suppression ***************
// Not portable, but nearly as old as GCC itself
#ifdef __GNUC__
# define CRYPTOPP_UNUSED_FUNCTION __attribute__ ((unused))
#else
# define CRYPTOPP_UNUSED_FUNCTION
#endif

// ************** counting elements in an array ***************
// VS2005 added _countof macro, fails on pointers
#ifndef COUNTOF
# if defined(_MSC_VER) && (_MSC_VER >= 1400)
#  define COUNTOF(x) _countof(x)
# else
#  define COUNTOF(x) (sizeof(x)/sizeof(x[0]))
# endif
#endif // COUNTOF

// ************** misc classes ***************

class CRYPTOPP_DLL Empty
{
};

//! _
template <class BASE1, class BASE2>
class CRYPTOPP_NO_VTABLE TwoBases : public BASE1, public BASE2
{
};

//! _
template <class BASE1, class BASE2, class BASE3>
class CRYPTOPP_NO_VTABLE ThreeBases : public BASE1, public BASE2, public BASE3
{
};

template <class T>
class ObjectHolder
{
protected:
	T m_object;
};

class NotCopyable
{
public:
	NotCopyable() {}
private:
	NotCopyable(const NotCopyable &);
	void operator=(const NotCopyable &);
};

template <class T>
struct NewObject
{
	T* operator()() const {return new T;}
};

/*! This function safely initializes a static object in a multithreaded environment without using locks (for portability).
	Note that if two threads call Ref() at the same time, they may get back different references, and one object 
	may end up being memory leaked. This is by design.
*/
template <class T, class F = NewObject<T>, int instance=0>
class Singleton
{
public:
	Singleton(F objectFactory = F()) : m_objectFactory(objectFactory) {}

	// prevent this function from being inlined
	CRYPTOPP_NOINLINE const T & Ref(CRYPTOPP_NOINLINE_DOTDOTDOT) const;

private:
	F m_objectFactory;
};

// Forward declaration due to circular dependency between smart_ptr.h and misc.h
template <class T> class simple_ptr;

template <class T, class F, int instance>
const T & Singleton<T, F, instance>::Ref(CRYPTOPP_NOINLINE_DOTDOTDOT) const
{
	static volatile simple_ptr<T> s_pObject;
	T *p = s_pObject.m_p;

	if (p)
		return *p;

	T *newObject = m_objectFactory();
	p = s_pObject.m_p;

	if (p)
	{
		delete newObject;
		return *p;
	}

	s_pObject.m_p = newObject;
	return *newObject;
}

// ************** misc functions ***************

#if (!__STDC_WANT_SECURE_LIB__ && !defined(_MEMORY_S_DEFINED))
inline void memcpy_s(void *dest, size_t sizeInBytes, const void *src, size_t count)
{
	// NULL pointers to memcpy is undefined behavior
	CRYPTOPP_ASSERT(dest); CRYPTOPP_ASSERT(src);

	if (count > sizeInBytes)
		throw InvalidArgument("memcpy_s: buffer overflow");

	memcpy(dest, src, count);
}

inline void memmove_s(void *dest, size_t sizeInBytes, const void *src, size_t count)
{
	// NULL pointers to memmove is undefined behavior
	CRYPTOPP_ASSERT(dest); CRYPTOPP_ASSERT(src);

	if (count > sizeInBytes)
		throw InvalidArgument("memmove_s: buffer overflow");

	memmove(dest, src, count);
}

// C++Builder 2010 workaround: can't use std::memcpy_s because it doesn't allow 0 lengths
#if __BORLANDC__ >= 0x620
# define memcpy_s CryptoPP::memcpy_s
# define memmove_s CryptoPP::memmove_s
#endif // __BORLANDC__

#endif // __STDC_WANT_SECURE_LIB__ and _MEMORY_S_DEFINED

//! Initialize an array to a value after creation. Do not use for destruction because its subject to removal by the optimizer
inline void * memset_z(void *ptr, int value, size_t num)
{
// avoid extranous warning on GCC 4.3.2 Ubuntu 8.10
#if CRYPTOPP_GCC_VERSION >= 30001
	if (__builtin_constant_p(num) && num==0)
		return ptr;
#endif
	if (!ptr) return NULL;
	if (!num) return ptr;
	return memset(ptr, value, num);
}

// can't use std::min or std::max in MSVC60 or Cygwin 1.1.0
template <class T> inline const T& STDMIN(const T& a, const T& b)
{
	return b < a ? b : a;
}

template <class T1, class T2> inline const T1 UnsignedMin(const T1& a, const T2& b)
{
	CRYPTOPP_COMPILE_ASSERT((sizeof(T1)<=sizeof(T2) && T2(-1)>0) || (sizeof(T1)>sizeof(T2) && T1(-1)>0));

	if (sizeof(T1)<=sizeof(T2))
		return b < (T2)a ? (T1)b : a;
	else
		return (T1)b < a ? (T1)b : a;
}

template <class T> inline const T& STDMAX(const T& a, const T& b)
{
	return a < b ? b : a;
}

#define RETURN_IF_NONZERO(x) size_t returnedValue = x; if (returnedValue) return returnedValue

// this version of the macro is fastest on Pentium 3 and Pentium 4 with MSVC 6 SP5 w/ Processor Pack
#define GETBYTE(x, y) (unsigned int)byte((x)>>(8*(y)))
// these may be faster on other CPUs/compilers
// #define GETBYTE(x, y) (unsigned int)(((x)>>(8*(y)))&255)
// #define GETBYTE(x, y) (((byte *)&(x))[y])

#define CRYPTOPP_GET_BYTE_AS_BYTE(x, y) byte((x)>>(8*(y)))

// Signed-ness
template<bool B, class T, class F>
struct Conditional { typedef T type; };
template<class T, class F>
struct Conditional<false, T, F> { typedef F type; };
template <typename T>
struct Signedness { typedef typename Conditional<T(-1)<T(0),int,unsigned int>::type type; };

template <class T>
unsigned int Parity(T value)
{
	for (unsigned int i=8*sizeof(value)/2; i>0; i/=2)
		value ^= value >> i;
	return (unsigned int)value&1;
}

template <class T>
unsigned int BytePrecision(const T &value)
{
	if (!value)
		return 0;

	unsigned int l=0, h=8*sizeof(value);

	while (h-l > 8)
	{
		unsigned int t = (l+h)/2;
		if (value >> t)
			l = t;
		else
			h = t;
	}

	return h/8;
}

template <class T>
unsigned int BitPrecision(const T &value)
{
	if (!value)
		return 0;

	unsigned int l=0, h=8*sizeof(value);

	while (h-l > 1)
	{
		unsigned int t = (l+h)/2;
		if (value >> t)
			l = t;
		else
			h = t;
	}

	return h;
}

inline unsigned int TrailingZeros(word32 v)
{
#if defined(__GNUC__) && CRYPTOPP_GCC_VERSION >= 30400
	return static_cast<unsigned int>(__builtin_ctz(v));
#elif defined(_MSC_VER) && _MSC_VER >= 1400
	unsigned long result;
	_BitScanForward(&result, v);
	return result;
#else
	// from http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightMultLookup
	static const int MultiplyDeBruijnBitPosition[32] = 
	{
	  0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8, 
	  31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
	};
	return MultiplyDeBruijnBitPosition[((word32)((v & -v) * 0x077CB531U)) >> 27];
#endif
}

inline unsigned int TrailingZeros(word64 v)
{
#if defined(__GNUC__) && CRYPTOPP_GCC_VERSION >= 30400
	return static_cast<unsigned int>(__builtin_ctzll(v));
#elif defined(_MSC_VER) && _MSC_VER >= 1400 && (defined(_M_X64) || defined(_M_IA64))
	unsigned long result;
	_BitScanForward64(&result, v);
	return result;
#else
	return word32(v) ? TrailingZeros(word32(v)) : 32 + TrailingZeros(word32(v>>32));
#endif
}

template <class T>
inline T Crop(T value, size_t size)
{
	if (size < 8*sizeof(value))
		return T(value & ((T(1) << size) - 1));
	else
		return value;
}

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wsign-compare"
#endif

template <class T1, class T2>
inline bool SafeConvert(T1 from, T2 &to)
{
	to = (T2)from;
	if (from != to || (from > 0) != (to > 0))
	{
		// This will assert about 35 times under the test program
		CRYPTOPP_ASSERT(false);
		return false;
	}

	return true;
}

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic pop
#endif

inline size_t BitsToBytes(size_t bitCount)
{
	return ((bitCount+7)/(8));
}

inline size_t BytesToWords(size_t byteCount)
{
	return ((byteCount+WORD_SIZE-1)/WORD_SIZE);
}

inline size_t BitsToWords(size_t bitCount)
{
	return ((bitCount+WORD_BITS-1)/(WORD_BITS));
}

inline size_t BitsToDwords(size_t bitCount)
{
	return ((bitCount+2*WORD_BITS-1)/(2*WORD_BITS));
}

CRYPTOPP_DLL void CRYPTOPP_API xorbuf(byte *buf, const byte *mask, size_t count);
CRYPTOPP_DLL void CRYPTOPP_API xorbuf(byte *output, const byte *input, const byte *mask, size_t count);

CRYPTOPP_DLL bool CRYPTOPP_API VerifyBufsEqual(const byte *buf1, const byte *buf2, size_t count);

template <class T>
inline bool IsPowerOf2(const T &n)
{
	return n > 0 && (n & (n-1)) == 0;
}

template <class T1, class T2>
inline T2 ModPowerOf2(const T1 &a, const T2 &b)
{
	CRYPTOPP_ASSERT(IsPowerOf2(b));
	return T2(a) & (b-1);
}

template <class T1, class T2>
inline T1 RoundDownToMultipleOf(const T1 &n, const T2 &m)
{
	if (IsPowerOf2(m))
		return n - ModPowerOf2(n, m);
	else
		return n - n%m;
}

template <class T1, class T2>
inline T1 RoundUpToMultipleOf(const T1 &n, const T2 &m)
{
	const size_t limit = std::numeric_limits<T1>::max();
	if (n > limit-m)
		throw InvalidArgument("RoundUpToMultipleOf: integer overflow");
	return RoundDownToMultipleOf(n+m-1, m);
}

// Influenced by CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS; may cause
//   problems at -O3 and GCC vectorization.
template <class T>
inline unsigned int GetAlignmentOf(T *dummy=NULL)	// VC60 workaround
{
#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	if (sizeof(T) < 16)
		return 1;
#endif

#if (_MSC_VER >= 1300)
	return __alignof(T);
#elif defined(__clang__)
	return __alignof(T);
#elif defined(__GNUC__)
	return __alignof__(T);
#elif CRYPTOPP_BOOL_SLOW_WORD64
	return UnsignedMin(4U, sizeof(T));
#else
	return sizeof(T);
#endif
}

// Not influenced by CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS; will not
//   cause problems with -O3 and GCC vectorization.
template <class T>
inline unsigned int GetStrictAlignmentOf(T *dummy=NULL)	// VC60 workaround
{
#if (_MSC_VER >= 1300)
	return __alignof(T);
#elif defined(__clang__)
	return __alignof(T);
#elif defined(__GNUC__)
	return __alignof__(T);
#else
	return sizeof(T);
#endif
}

inline bool IsAlignedOn(const void *p, unsigned int alignment)
{
	return alignment==1 || (IsPowerOf2(alignment) ? ModPowerOf2((size_t)p, alignment) == 0 : (size_t)p % alignment == 0);
}

// Influenced by CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS; may cause
//   problems at -O3 and GCC vectorization.
template <class T>
inline bool IsAligned(const void *p, T *dummy=NULL)	// VC60 workaround
{
	return IsAlignedOn(p, GetAlignmentOf<T>());
}

// Not influenced by CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS; will not
//   cause problems with -O3 and GCC vectorization.
template <class T>
inline bool IsStrictAligned(const void *p, T *dummy=NULL)	// VC60 workaround
{
	return IsAlignedOn(p, GetStrictAlignmentOf<T>());
}

#ifdef IS_LITTLE_ENDIAN
	typedef LittleEndian NativeByteOrder;
#else
	typedef BigEndian NativeByteOrder;
#endif

inline ByteOrder GetNativeByteOrder()
{
	return NativeByteOrder::ToEnum();
}

inline bool NativeByteOrderIs(ByteOrder order)
{
	return order == GetNativeByteOrder();
}

template <class T>
std::string IntToString(T a, unsigned int base = 10)
{
	typename Signedness<T>::type b = static_cast<typename Signedness<T>::type>(base);

	if (a == 0)
		return "0";
	bool negate = false;
	if (a < 0)
	{
		negate = true;
		a = 0-a;	// VC .NET does not like -a
	}
	std::string result;
	while (a > 0)
	{
		T digit = a % b;
		result = char((digit < 10 ? '0' : ('a' - 10)) + digit) + result;
		a /= b;
	}
	if (negate)
		result = "-" + result;
	return result;
}

template <class T1, class T2>
inline T1 SaturatingSubtract(const T1 &a, const T2 &b)
{
	return T1((a > b) ? (a - b) : 0);
}

template <class T>
inline CipherDir GetCipherDir(const T &obj)
{
	return obj.IsForwardTransformation() ? ENCRYPTION : DECRYPTION;
}

CRYPTOPP_DLL void CRYPTOPP_API CallNewHandler();

inline void IncrementCounterByOne(byte *inout, unsigned int s)
{
	for (int i=static_cast<int>(s)-1, carry=1; i>=0 && carry; i--)
		carry = !++inout[i];
}

inline void IncrementCounterByOne(byte *output, const byte *input, unsigned int s)
{
	int i, carry;
	for (i=static_cast<int>(s)-1, carry=1; i>=0 && carry; i--)
		carry = ((output[i] = input[i]+1) == 0);
	memcpy_s(output, s, input, static_cast<size_t>(i)+1);
}

template <class T>
inline void ConditionalSwap(bool c, T &a, T &b)
{
	T t = c * (a ^ b);
	a ^= t;
	b ^= t;
}

template <class T>
inline void ConditionalSwapPointers(bool c, T &a, T &b)
{
	ptrdiff_t t = c * (a - b);
	a -= t;
	b += t;
}

// see http://www.dwheeler.com/secure-programs/Secure-Programs-HOWTO/protect-secrets.html
// and https://www.securecoding.cert.org/confluence/display/cplusplus/MSC06-CPP.+Be+aware+of+compiler+optimization+when+dealing+with+sensitive+data
template <class T>
void SecureWipeBuffer(T *buf, size_t n)
{
	// GCC 4.3.2 on Cygwin optimizes away the first store if this loop is done in the forward direction
	volatile T *p = buf+n;
	while (n--)
		*(--p) = 0;
}

#if (_MSC_VER >= 1400 || defined(__GNUC__)) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X86)

template<> inline void SecureWipeBuffer(byte *buf, size_t n)
{
	volatile byte *p = buf;
#ifdef __GNUC__
	asm volatile("rep stosb" : "+c"(n), "+D"(p) : "a"(0) : "memory");
#else
	__stosb((byte *)(size_t)p, 0, n);
#endif
}

template<> inline void SecureWipeBuffer(word16 *buf, size_t n)
{
	volatile word16 *p = buf;
#ifdef __GNUC__
	asm volatile("rep stosw" : "+c"(n), "+D"(p) : "a"(0) : "memory");
#else
	__stosw((word16 *)(size_t)p, 0, n);
#endif
}

template<> inline void SecureWipeBuffer(word32 *buf, size_t n)
{
	volatile word32 *p = buf;
#ifdef __GNUC__
	asm volatile("rep stosl" : "+c"(n), "+D"(p) : "a"(0) : "memory");
#else
	__stosd((unsigned long *)(size_t)p, 0, n);
#endif
}

template<> inline void SecureWipeBuffer(word64 *buf, size_t n)
{
#if CRYPTOPP_BOOL_X64
	volatile word64 *p = buf;
#ifdef __GNUC__
	asm volatile("rep stosq" : "+c"(n), "+D"(p) : "a"(0) : "memory");
#else
	__stosq((word64 *)(size_t)p, 0, n);
#endif
#else
	SecureWipeBuffer((word32 *)buf, 2*n);
#endif
}

#endif	// #if (_MSC_VER >= 1400 || defined(__GNUC__)) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X86)

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-align"
#endif

template <class T>
inline void SecureWipeArray(T *buf, size_t n)
{
	if (sizeof(T) % 8 == 0 && GetAlignmentOf<T>() % GetAlignmentOf<word64>() == 0)
		SecureWipeBuffer((word64 *)buf, n * (sizeof(T)/8));
	else if (sizeof(T) % 4 == 0 && GetAlignmentOf<T>() % GetAlignmentOf<word32>() == 0)
		SecureWipeBuffer((word32 *)buf, n * (sizeof(T)/4));
	else if (sizeof(T) % 2 == 0 && GetAlignmentOf<T>() % GetAlignmentOf<word16>() == 0)
		SecureWipeBuffer((word16 *)buf, n * (sizeof(T)/2));
	else
		SecureWipeBuffer((byte *)buf, n * sizeof(T));
}

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic pop
#endif

// this function uses wcstombs(), which assumes that setlocale() has been called
static inline std::string StringNarrow(const wchar_t *str, bool throwOnError = true)
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)	//  'wcstombs': This function or variable may be unsafe.
#endif
	size_t size = wcstombs(NULL, str, 0);
	if (size == size_t(0)-1)
	{
		if (throwOnError)
			throw InvalidArgument("StringNarrow: wcstombs() call failed");
		else
			return std::string();
	}
	std::string result(size, 0);
	wcstombs(&result[0], str, size);
	return result;
#ifdef _MSC_VER
#pragma warning(pop)
#endif
}

#if CRYPTOPP_BOOL_ALIGN16_ENABLED
CRYPTOPP_DLL void * CRYPTOPP_API AlignedAllocate(size_t size);
CRYPTOPP_DLL void CRYPTOPP_API AlignedDeallocate(void *p);
#endif

CRYPTOPP_DLL void * CRYPTOPP_API UnalignedAllocate(size_t size);
CRYPTOPP_DLL void CRYPTOPP_API UnalignedDeallocate(void *p);

// ************** rotate functions ***************

// There are two families of rotate - one for left and one for right. Each family
// has three variants denoted with a suffix - Fixed, Variable or Mod. The two
// families with three variants produce six concrete functions - rotlFixed,
// rotrFixed, rotlVariable, rotrVariable, rotlMod and rotrMod.
//
// Fixed, or rotlFixed and rotrFixed, are intended to be used with a constant or
// immediate. Variable, or rotlVariable and rotrVariable, are intended to be used when
// the rotate amount is not constant and passed through a variable. Finally, Mod, or
// rotlMod and rotrMod, are intended to provide an intrinsic that has special
// requirements on x86/x64. On x86/x64, the CPU instruction only shifts by an 8-bit
// value (the value is an immediate-8 or placed in the CL register), so the effect is
// a modular reduction when using it.
//
// For trouble free C/C++ code, attempt to use rotlMod and rotrMod. They are near
// constant time, they are free from C/C++ undefined behavior, and they utilize a
// compiler intrinsic or inline assembly when available.
//
// If the Fixed or Variable variants are used, then the caller is responsible for
// ensuring the rotate amount is smaller than the register size in bits. For example.
// for a 32-bit register, the rotate amount must be [0,31] inclusive. If this is
// not honored, then the result is undefined behavior. To help ensure well defined
// behavior for callers, Fixed and Variable assert in Debug builds in an attempt to
// alert of potential problems.
//
// There are also specializations of the functions that depend on the compiler
// and/or platform. For example, on Microsoft platforms, when using the Mod variant,
// the compiler intrinsics _lrotl or _lrotr are utilized. For GCC under the Mod
// variant, inline assembly is used.
//
// For Microsoft platforms, there are four instrinsics, and they are rotl8, rotl16,
// rotr8 and rotr16. Microsoft does not provide 32 and 64 bit variants, so the
// variants that operate on 32-bit and 64-bit data types assert to alert of
// potential undefined behavior. See
// https://msdn.microsoft.com/en-us/library/hh977022.aspx and
// https://msdn.microsoft.com/en-us/library/hh977023.aspx.
//
// Finally, if a specialization avoids the undefined behavior, then it
// does not assert.

// Well defined if y in [0,31], non-constant time due to branch
template <class T> inline T rotlFixed(T x, unsigned int y)
{
	static const unsigned int THIS_SIZE = sizeof(T)*8;
	CRYPTOPP_ASSERT(y < THIS_SIZE);
	return y ? T((x<<y) | (x>>(THIS_SIZE-y))) : x;
}

// Well defined if y in [0,31], non-constant time due to branch
template <class T> inline T rotrFixed(T x, unsigned int y)
{
	static const unsigned int THIS_SIZE = sizeof(T)*8;
	CRYPTOPP_ASSERT(y < THIS_SIZE);
	return y ? T((x>>y) | (x<<(THIS_SIZE-y))) : x;
}

// Well defined for nearly all y except 0 (y in [1,..]), near constant time
template <class T> inline T rotlVariable(T x, unsigned int y)
{
	static const unsigned int THIS_SIZE = sizeof(T)*8;
	CRYPTOPP_ASSERT(y > 0 && y < THIS_SIZE);
	y %= THIS_SIZE;
	return T((x<<y) | (x>>(THIS_SIZE-y)));
}

// Well defined for nearly all y except 0 (y in [1,..]),  near constant time
template <class T> inline T rotrVariable(T x, unsigned int y)
{
	static const unsigned int THIS_SIZE = sizeof(T)*8;
	CRYPTOPP_ASSERT(y > 0 && y < THIS_SIZE);
	y %= THIS_SIZE;
	return T((x>>y) | (x<<(THIS_SIZE-y)));
}

// Well defined for all y, near constant time
template <class T> inline T rotlMod(T x, unsigned int y)
{
	static const unsigned int THIS_SIZE = sizeof(T)*8;
	y %= THIS_SIZE;
	return T((x<<y) | (x>>((THIS_SIZE-y) % THIS_SIZE)));
}

// Well defined for all y, near constant time
template <class T> inline T rotrMod(T x, unsigned int y)
{
	static const unsigned int THIS_SIZE = sizeof(T)*8;
	y %= THIS_SIZE;
	return T((x>>y) | (x<<((THIS_SIZE-y) % THIS_SIZE)));
}

#ifdef _MSC_VER

template<> inline word32 rotlFixed<word32>(word32 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return y ? _lrotl(x, y) : x;
}

template<> inline word32 rotrFixed<word32>(word32 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return y ? _lrotr(x, y) : x;
}

template<> inline word32 rotlVariable<word32>(word32 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return _lrotl(x, y);
}

template<> inline word32 rotrVariable<word32>(word32 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return _lrotr(x, y);
}

template<> inline word32 rotlMod<word32>(word32 x, unsigned int y)
{
	return _lrotl(x, y);
}

template<> inline word32 rotrMod<word32>(word32 x, unsigned int y)
{
	return _lrotr(x, y);
}

#endif // #ifdef _MSC_VER

#if _MSC_VER >= 1300 && !defined(__INTEL_COMPILER)
// Intel C++ Compiler 10.0 calls a function instead of using the rotate instruction when using these instructions

template<> inline word64 rotlFixed<word64>(word64 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return y ? _rotl64(x, y) : x;
}

template<> inline word64 rotrFixed<word64>(word64 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return y ? _rotr64(x, y) : x;
}

template<> inline word64 rotlVariable<word64>(word64 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return _rotl64(x, y);
}

template<> inline word64 rotrVariable<word64>(word64 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return _rotr64(x, y);
}

template<> inline word64 rotlMod<word64>(word64 x, unsigned int y)
{
	return _rotl64(x, y);
}

template<> inline word64 rotrMod<word64>(word64 x, unsigned int y)
{
	return _rotr64(x, y);
}

#endif // #if _MSC_VER >= 1310

#if _MSC_VER >= 1400 && !defined(__INTEL_COMPILER)
// Intel C++ Compiler 10.0 gives undefined externals with these

template<> inline word16 rotlFixed<word16>(word16 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return y ? _rotl16(x, static_cast<byte>(y)) : x;
}

template<> inline word16 rotrFixed<word16>(word16 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return y ? _rotr16(x, static_cast<byte>(y)) : x;
}

template<> inline word16 rotlVariable<word16>(word16 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return _rotl16(x, static_cast<byte>(y));
}

template<> inline word16 rotrVariable<word16>(word16 x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return _rotr16(x, static_cast<byte>(y));
}

template<> inline word16 rotlMod<word16>(word16 x, unsigned int y)
{
	return _rotl16(x, static_cast<byte>(y));
}

template<> inline word16 rotrMod<word16>(word16 x, unsigned int y)
{
	return _rotr16(x, static_cast<byte>(y));
}

template<> inline byte rotlFixed<byte>(byte x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return y ? _rotl8(x, static_cast<byte>(y)) : x;
}

template<> inline byte rotrFixed<byte>(byte x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return y ? _rotr8(x, static_cast<byte>(y)) : x;
}

template<> inline byte rotlVariable<byte>(byte x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return _rotl8(x, static_cast<byte>(y));
}

template<> inline byte rotrVariable<byte>(byte x, unsigned int y)
{
	CRYPTOPP_ASSERT(y < 8*sizeof(x));
	return _rotr8(x, static_cast<byte>(y));
}

template<> inline byte rotlMod<byte>(byte x, unsigned int y)
{
	return _rotl8(x, static_cast<byte>(y));
}

template<> inline byte rotrMod<byte>(byte x, unsigned int y)
{
	return _rotr8(x, static_cast<byte>(y));
}

#endif // #if _MSC_VER >= 1400

#if (defined(__MWERKS__) && TARGET_CPU_PPC)

template<> inline word32 rotlFixed<word32>(word32 x, unsigned int y)
{
	return (__rlwinm(x,y,0,31));
}

template<> inline word32 rotrFixed<word32>(word32 x, unsigned int y)
{
	return (__rlwinm(x,32-y,0,31));
}

template<> inline word32 rotlVariable<word32>(word32 x, unsigned int y)
{
	return (__rlwnm(x,y,0,31));
}

template<> inline word32 rotrVariable<word32>(word32 x, unsigned int y)
{
	return (__rlwnm(x,32-y,0,31));
}

template<> inline word32 rotlMod<word32>(word32 x, unsigned int y)
{
	return (__rlwnm(x,y,0,31));
}

template<> inline word32 rotrMod<word32>(word32 x, unsigned int y)
{
	return (__rlwnm(x,32-y,0,31));
}

#endif // #if (defined(__MWERKS__) && TARGET_CPU_PPC)

#if !defined(CRYPTOPP_DISABLE_ASM)
#if  defined(__GNUC__)
#if  defined(__i386__) || defined(__x86_64__)

// For the operand constraints, see
// https://gcc.gnu.org/onlinedocs/gcc/Simple-Constraints.html#Simple-Constraints
// and https://gcc.gnu.org/onlinedocs/gcc/Machine-Constraints.html#Machine-Constraints

// Clang does not proagate the constant.
//   See LLVM Bug 24226 (https://llvm.org/bugs/show_bug.cgi?id=24226)
#if !defined (__clang__)
template<> inline byte rotlFixed<byte>(byte x, unsigned int y)
{
	// The I constraint ensures we use the immediate-8 variant of the
	// rotate amount y. However, y must be in [0, 31] inclusive. We
	// rely on the constant being propagated and the modular reduction
	// being performed early so the assembler generates the instruction.
	__asm__ ("rolb %1, %0" : "+mq" (x) : "I" ((unsigned char)(y%8)));
	return x;
}

template<> inline byte rotrFixed<byte>(byte x, unsigned int y)
{
	// The I constraint ensures we use the immediate-8 variant of the
	// rotate amount y. However, y must be in [0, 31] inclusive. We
	// rely on the constant being propagated and the modular reduction
	// being performed early so the assembler generates the instruction.
	__asm__ ("rorb %1, %0" : "+mq" (x) : "I" ((unsigned char)(y%8)));
	return x;
}
#endif

template<> inline byte rotlVariable<byte>(byte x, unsigned int y)
{
	// The cI constraint ensures we use either (1) the CL variant or
	// (2) the immediate-8 variant of the rotate amount y. The cast
	// effectively performs a modular reduction on the rotate amount
	// to ensure the CL variant can be used.
	__asm__ ("rolb %1, %0" : "+mq" (x) : "cI" ((unsigned char)(y)));
	return x;
}

template<> inline byte rotrVariable<byte>(byte x, unsigned int y)
{
	// The cI constraint ensures we use either (1) the CL variant or
	// (2) the immediate-8 variant of the rotate amount y. The cast
	// effectively performs a modular reduction on the rotate amount
	// to ensure the CL variant can be used.
	__asm__ ("rorb %1, %0" : "+mq" (x) : "cI" ((unsigned char)(y)));
	return x;
}

template<> inline byte rotlMod<byte>(byte x, unsigned int y)
{
	__asm__ ("rolb %1, %0" : "+mq" (x) : "cI" ((unsigned char)(y)));
	return x;
}

template<> inline byte rotrMod<byte>(byte x, unsigned int y)
{
	__asm__ ("rorb %1, %0" : "+mq" (x) : "cI" ((unsigned char)(y)));
	return x;
}

// Clang does not proagate the constant.
//   See LLVM Bug 24226 (https://llvm.org/bugs/show_bug.cgi?id=24226)
#if !defined (__clang__)
template<> inline word16 rotlFixed<word16>(word16 x, unsigned int y)
{
	__asm__ ("rolw %1, %0" : "+g" (x) : "I" ((unsigned char)(y%16)));
	return x;
}

template<> inline word16 rotrFixed<word16>(word16 x, unsigned int y)
{
	__asm__ ("rorw %1, %0" : "+g" (x) : "I" ((unsigned char)(y%16)));
	return x;
}
#endif

template<> inline word16 rotlVariable<word16>(word16 x, unsigned int y)
{
	__asm__ ("rolw %1, %0" : "+g" (x) : "cI" ((unsigned char)y));
	return x;
}

template<> inline word16 rotrVariable<word16>(word16 x, unsigned int y)
{
	__asm__ ("rorw %1, %0" : "+g" (x) : "cI" ((unsigned char)y));
	return x;
}

template<> inline word16 rotlMod<word16>(word16 x, unsigned int y)
{
	__asm__ ("rolw %1, %0" : "+g" (x) : "cI" ((unsigned char)y));
	return x;
}

template<> inline word16 rotrMod<word16>(word16 x, unsigned int y)
{
	__asm__ ("rorw %1, %0" : "+g" (x) : "cI" ((unsigned char)y));
	return x;
}

// Clang does not proagate the constant.
//   See LLVM Bug 24226 (https://llvm.org/bugs/show_bug.cgi?id=24226)
#if !defined (__clang__)
template<> inline word32 rotlFixed<word32>(word32 x, unsigned int y)
{
	__asm__ ("roll %1, %0" : "+g" (x) : "I" ((unsigned char)(y%32)));
	return x;
}

template<> inline word32 rotrFixed<word32>(word32 x, unsigned int y)
{
	__asm__ ("rorl %1, %0" : "+g" (x) : "I" ((unsigned char)(y%32)));
	return x;
}
#endif

template<> inline word32 rotlVariable<word32>(word32 x, unsigned int y)
{
	__asm__ ("roll %1, %0" : "+g" (x) : "cI" ((unsigned char)y));
	return x;
}

template<> inline word32 rotrVariable<word32>(word32 x, unsigned int y)
{
	__asm__ ("rorl %1, %0" : "+g" (x) : "cI" ((unsigned char)y));
	return x;
}

template<> inline word32 rotlMod<word32>(word32 x, unsigned int y)
{
	__asm__ ("roll %1, %0" : "+g" (x) : "cI" ((unsigned char)y));
	return x;
}

template<> inline word32 rotrMod<word32>(word32 x, unsigned int y)
{
	__asm__ ("rorl %1, %0" : "+g" (x) : "cI" ((unsigned char)y));
	return x;
}

#if defined(__x86_64__)

// Clang does not proagate the constant.
//   See LLVM Bug 24226 (https://llvm.org/bugs/show_bug.cgi?id=24226)
#if !defined (__clang__)
template<> inline word64 rotlFixed<word64>(word64 x, unsigned int y)
{
	// The J constraint ensures we use the immediate-8 variant of the
	// rotate amount y. However, y must be in [0, 63] inclusive. We
	// rely on the constant being propagated and the modular reduction
	// being performed early so the assembler generates the instruction.
	__asm__ ("rolq %1, %0" : "+g" (x) : "J" ((unsigned char)(y%64)));
	return x;
}

template<> inline word64 rotrFixed<word64>(word64 x, unsigned int y)
{
	// The J constraint ensures we use the immediate-8 variant of the
	// rotate amount y. However, y must be in [0, 63] inclusive. We
	// rely on the constant being propagated and the modular reduction
	// being performed early so the assembler generates the instruction.
	__asm__ ("rorq %1, %0" : "+g" (x) : "J" ((unsigned char)(y%64)));
	return x;
}
#endif

template<> inline word64 rotlVariable<word64>(word64 x, unsigned int y)
{
	__asm__ ("rolq %1, %0" : "+g" (x) : "cJ" ((unsigned char)y));
	return x;
}

template<> inline word64 rotrVariable<word64>(word64 x, unsigned int y)
{
	__asm__ ("rorq %1, %0" : "+g" (x) : "cJ" ((unsigned char)y));
	return x;
}

template<> inline word64 rotlMod<word64>(word64 x, unsigned int y)
{
	__asm__ ("rolq %1, %0" : "+g" (x) : "cJ" ((unsigned char)y));
	return x;
}

template<> inline word64 rotrMod<word64>(word64 x, unsigned int y)
{
	__asm__ ("rorq %1, %0" : "+g" (x) : "cJ" ((unsigned char)y));
	return x;
}

#endif // x86_64 only
#endif // i386 and x86_64
#endif // __GNUC__
#endif // CRYPTOPP_DISABLE_ASM

// ************** endian reversal ***************

template <class T>
inline unsigned int GetByte(ByteOrder order, T value, unsigned int index)
{
	if (order == LITTLE_ENDIAN_ORDER)
		return GETBYTE(value, index);
	else
		return GETBYTE(value, sizeof(T)-index-1);
}

inline byte ByteReverse(byte value)
{
	return value;
}

inline word16 ByteReverse(word16 value)
{
#ifdef CRYPTOPP_BYTESWAP_AVAILABLE
	return bswap_16(value);
#elif defined(_MSC_VER) && _MSC_VER >= 1300
	return _byteswap_ushort(value);
#else
	return rotlFixed(value, 8U);
#endif
}

inline word32 ByteReverse(word32 value)
{
#if defined(__GNUC__) && defined(CRYPTOPP_X86_ASM_AVAILABLE)
	__asm__ ("bswap %0" : "=r" (value) : "0" (value));
	return value;
#elif defined(CRYPTOPP_BYTESWAP_AVAILABLE)
	return bswap_32(value);
#elif defined(__MWERKS__) && TARGET_CPU_PPC
	return (word32)__lwbrx(&value,0);
#elif _MSC_VER >= 1400 || (_MSC_VER >= 1300 && !defined(_DLL))
	return _byteswap_ulong(value);
#elif CRYPTOPP_FAST_ROTATE(32)
	// 5 instructions with rotate instruction, 9 without
	return (rotrFixed(value, 8U) & 0xff00ff00) | (rotlFixed(value, 8U) & 0x00ff00ff);
#else
	// 6 instructions with rotate instruction, 8 without
	value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
	return rotlFixed(value, 16U);
#endif
}

inline word64 ByteReverse(word64 value)
{
#if defined(__GNUC__) && defined(CRYPTOPP_X86_ASM_AVAILABLE) && defined(__x86_64__)
	__asm__ ("bswap %0" : "=r" (value) : "0" (value));
	return value;
#elif defined(CRYPTOPP_BYTESWAP_AVAILABLE)
	return bswap_64(value);
#elif defined(_MSC_VER) && _MSC_VER >= 1300
	return _byteswap_uint64(value);
#elif CRYPTOPP_BOOL_SLOW_WORD64
	return (word64(ByteReverse(word32(value))) << 32) | ByteReverse(word32(value>>32));
#else
	value = ((value & W64LIT(0xFF00FF00FF00FF00)) >> 8) | ((value & W64LIT(0x00FF00FF00FF00FF)) << 8);
	value = ((value & W64LIT(0xFFFF0000FFFF0000)) >> 16) | ((value & W64LIT(0x0000FFFF0000FFFF)) << 16);
	return rotlFixed(value, 32U);
#endif
}

inline byte BitReverse(byte value)
{
	value = ((value & 0xAA) >> 1) | ((value & 0x55) << 1);
	value = ((value & 0xCC) >> 2) | ((value & 0x33) << 2);
	return rotlFixed(value, 4U);
}

inline word16 BitReverse(word16 value)
{
	value = ((value & 0xAAAA) >> 1) | ((value & 0x5555) << 1);
	value = ((value & 0xCCCC) >> 2) | ((value & 0x3333) << 2);
	value = ((value & 0xF0F0) >> 4) | ((value & 0x0F0F) << 4);
	return ByteReverse(value);
}

inline word32 BitReverse(word32 value)
{
	value = ((value & 0xAAAAAAAA) >> 1) | ((value & 0x55555555) << 1);
	value = ((value & 0xCCCCCCCC) >> 2) | ((value & 0x33333333) << 2);
	value = ((value & 0xF0F0F0F0) >> 4) | ((value & 0x0F0F0F0F) << 4);
	return ByteReverse(value);
}

inline word64 BitReverse(word64 value)
{
#if CRYPTOPP_BOOL_SLOW_WORD64
	return (word64(BitReverse(word32(value))) << 32) | BitReverse(word32(value>>32));
#else
	value = ((value & W64LIT(0xAAAAAAAAAAAAAAAA)) >> 1) | ((value & W64LIT(0x5555555555555555)) << 1);
	value = ((value & W64LIT(0xCCCCCCCCCCCCCCCC)) >> 2) | ((value & W64LIT(0x3333333333333333)) << 2);
	value = ((value & W64LIT(0xF0F0F0F0F0F0F0F0)) >> 4) | ((value & W64LIT(0x0F0F0F0F0F0F0F0F)) << 4);
	return ByteReverse(value);
#endif
}

template <class T>
inline T BitReverse(T value)
{
	if (sizeof(T) == 1)
		return (T)BitReverse((byte)value);
	else if (sizeof(T) == 2)
		return (T)BitReverse((word16)value);
	else if (sizeof(T) == 4)
		return (T)BitReverse((word32)value);
	else
	{
		CRYPTOPP_ASSERT(sizeof(T) == 8);
		return (T)BitReverse((word64)value);
	}
}

template <class T>
inline T ConditionalByteReverse(ByteOrder order, T value)
{
	return NativeByteOrderIs(order) ? value : ByteReverse(value);
}

template <class T>
void ByteReverse(T *out, const T *in, size_t byteCount)
{
	CRYPTOPP_ASSERT(byteCount % sizeof(T) == 0);
	size_t count = byteCount/sizeof(T);
	for (size_t i=0; i<count; i++)
		out[i] = ByteReverse(in[i]);
}

template <class T>
inline void ConditionalByteReverse(ByteOrder order, T *out, const T *in, size_t byteCount)
{
	if (!NativeByteOrderIs(order))
		ByteReverse(out, in, byteCount);
	else if (in != out)
		memcpy_s(out, byteCount, in, byteCount);
}

template <class T>
inline void GetUserKey(ByteOrder order, T *out, size_t outlen, const byte *in, size_t inlen)
{
	const size_t U = sizeof(T);
	CRYPTOPP_ASSERT(inlen <= outlen*U);
	memcpy_s(out, outlen*U, in, inlen);
	memset_z((byte *)out+inlen, 0, outlen*U-inlen);
	ConditionalByteReverse(order, out, out, RoundUpToMultipleOf(inlen, U));
}

#ifndef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
inline byte UnalignedGetWordNonTemplate(ByteOrder order, const byte *block, const byte *)
{
	return block[0];
}

inline word16 UnalignedGetWordNonTemplate(ByteOrder order, const byte *block, const word16 *)
{
	return (order == BIG_ENDIAN_ORDER)
		? block[1] | (block[0] << 8)
		: block[0] | (block[1] << 8);
}

inline word32 UnalignedGetWordNonTemplate(ByteOrder order, const byte *block, const word32 *)
{
	return (order == BIG_ENDIAN_ORDER)
		? word32(block[3]) | (word32(block[2]) << 8) | (word32(block[1]) << 16) | (word32(block[0]) << 24)
		: word32(block[0]) | (word32(block[1]) << 8) | (word32(block[2]) << 16) | (word32(block[3]) << 24);
}

inline word64 UnalignedGetWordNonTemplate(ByteOrder order, const byte *block, const word64 *)
{
	return (order == BIG_ENDIAN_ORDER)
		?
		(word64(block[7]) |
		(word64(block[6]) <<  8) |
		(word64(block[5]) << 16) |
		(word64(block[4]) << 24) |
		(word64(block[3]) << 32) |
		(word64(block[2]) << 40) |
		(word64(block[1]) << 48) |
		(word64(block[0]) << 56))
		:
		(word64(block[0]) |
		(word64(block[1]) <<  8) |
		(word64(block[2]) << 16) |
		(word64(block[3]) << 24) |
		(word64(block[4]) << 32) |
		(word64(block[5]) << 40) |
		(word64(block[6]) << 48) |
		(word64(block[7]) << 56));
}

inline void UnalignedPutWordNonTemplate(ByteOrder order, byte *block, byte value, const byte *xorBlock)
{
	block[0] = xorBlock ? (value ^ xorBlock[0]) : value;
}

inline void UnalignedPutWordNonTemplate(ByteOrder order, byte *block, word16 value, const byte *xorBlock)
{
	if (order == BIG_ENDIAN_ORDER)
	{
		if (xorBlock)
		{
			block[0] = xorBlock[0] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[1] = xorBlock[1] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
		}
		else
		{
			block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
		}
	}
	else
	{
		if (xorBlock)
		{
			block[0] = xorBlock[0] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
			block[1] = xorBlock[1] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
		}
		else
		{
			block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
			block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
		}
	}
}

inline void UnalignedPutWordNonTemplate(ByteOrder order, byte *block, word32 value, const byte *xorBlock)
{
	if (order == BIG_ENDIAN_ORDER)
	{
		if (xorBlock)
		{
			block[0] = xorBlock[0] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
			block[1] = xorBlock[1] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
			block[2] = xorBlock[2] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[3] = xorBlock[3] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
		}
		else
		{
			block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
			block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
			block[2] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[3] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
		}
	}
	else
	{
		if (xorBlock)
		{
			block[0] = xorBlock[0] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
			block[1] = xorBlock[1] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[2] = xorBlock[2] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
			block[3] = xorBlock[3] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
		}
		else
		{
			block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
			block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[2] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
			block[3] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
		}
	}
}

inline void UnalignedPutWordNonTemplate(ByteOrder order, byte *block, word64 value, const byte *xorBlock)
{
	if (order == BIG_ENDIAN_ORDER)
	{
		if (xorBlock)
		{
			block[0] = xorBlock[0] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 7);
			block[1] = xorBlock[1] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 6);
			block[2] = xorBlock[2] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 5);
			block[3] = xorBlock[3] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 4);
			block[4] = xorBlock[4] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
			block[5] = xorBlock[5] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
			block[6] = xorBlock[6] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[7] = xorBlock[7] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
		}
		else
		{
			block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 7);
			block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 6);
			block[2] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 5);
			block[3] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 4);
			block[4] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
			block[5] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
			block[6] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[7] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
		}
	}
	else
	{
		if (xorBlock)
		{
			block[0] = xorBlock[0] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
			block[1] = xorBlock[1] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[2] = xorBlock[2] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
			block[3] = xorBlock[3] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
			block[4] = xorBlock[4] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 4);
			block[5] = xorBlock[5] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 5);
			block[6] = xorBlock[6] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 6);
			block[7] = xorBlock[7] ^ CRYPTOPP_GET_BYTE_AS_BYTE(value, 7);
		}
		else
		{
			block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
			block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
			block[2] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
			block[3] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
			block[4] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 4);
			block[5] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 5);
			block[6] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 6);
			block[7] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 7);
		}
	}
}
#endif	// #ifndef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS

template <class T>
inline T GetWord(bool assumeAligned, ByteOrder order, const byte *block)
{
// #ifndef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
//	if (!assumeAligned)
//		return UnalignedGetWordNonTemplate(order, block, (T*)NULL);
//	CRYPTOPP_ASSERT(IsAligned<T>(block));
// #endif
//	return ConditionalByteReverse(order, *reinterpret_cast<const T *>(block));

	T temp;
	memmove(&temp, block, sizeof(temp));
	return ConditionalByteReverse(order, temp);
}

template <class T>
inline void GetWord(bool assumeAligned, ByteOrder order, T &result, const byte *block)
{
	result = GetWord<T>(assumeAligned, order, block);
}

template <class T>
inline void PutWord(bool assumeAligned, ByteOrder order, byte *block, T value, const byte *xorBlock = NULL)
{
// #ifndef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
//	if (!assumeAligned)
//		return UnalignedPutWordNonTemplate(order, block, value, xorBlock);
//	CRYPTOPP_ASSERT(IsAligned<T>(block));
//	CRYPTOPP_ASSERT(IsAligned<T>(xorBlock));
//#endif
//	*reinterpret_cast<T *>(block) = ConditionalByteReverse(order, value) ^ (xorBlock ? *reinterpret_cast<const T *>(xorBlock) : 0);

	T t1, t2 = 0;
	t1 = ConditionalByteReverse(order, value);
	if (xorBlock) memmove(&t2, xorBlock, sizeof(T));
	memmove(block, &(t1 ^= t2), sizeof(T));
}

template <class T, class B, bool A=false>
class GetBlock
{
public:
	GetBlock(const void *block)
		: m_block((const byte *)block) {}

	template <class U>
	inline GetBlock<T, B, A> & operator()(U &x)
	{
		CRYPTOPP_COMPILE_ASSERT(sizeof(U) >= sizeof(T));
		x = GetWord<T>(A, B::ToEnum(), m_block);
		m_block += sizeof(T);
		return *this;
	}

private:
	const byte *m_block;
};

template <class T, class B, bool A=false>
class PutBlock
{
public:
	PutBlock(const void *xorBlock, void *block)
		: m_xorBlock((const byte *)xorBlock), m_block((byte *)block) {}

	template <class U>
	inline PutBlock<T, B, A> & operator()(U x)
	{
		PutWord(A, B::ToEnum(), m_block, (T)x, m_xorBlock);
		m_block += sizeof(T);
		if (m_xorBlock)
			m_xorBlock += sizeof(T);
		return *this;
	}

private:
	const byte *m_xorBlock;
	byte *m_block;
};

template <class T, class B, bool GA=false, bool PA=false>
struct BlockGetAndPut
{
	// function needed because of C++ grammatical ambiguity between expression-statements and declarations
	static inline GetBlock<T, B, GA> Get(const void *block) {return GetBlock<T, B, GA>(block);}
	typedef PutBlock<T, B, PA> Put;
};

template <class T>
std::string WordToString(T value, ByteOrder order = BIG_ENDIAN_ORDER)
{
	if (!NativeByteOrderIs(order))
		value = ByteReverse(value);

	return std::string((char *)&value, sizeof(value));
}

template <class T>
T StringToWord(const std::string &str, ByteOrder order = BIG_ENDIAN_ORDER)
{
	T value = 0;
	memcpy_s(&value, sizeof(value), str.data(), UnsignedMin(str.size(), sizeof(value)));
	return NativeByteOrderIs(order) ? value : ByteReverse(value);
}

// ************** help remove warning on g++ ***************

template <bool overflow> struct SafeShifter;

template<> struct SafeShifter<true>
{
	template <class T>
	static inline T RightShift(T value, unsigned int bits)
	{
		return 0;
	}

	template <class T>
	static inline T LeftShift(T value, unsigned int bits)
	{
		return 0;
	}
};

template<> struct SafeShifter<false>
{
	template <class T>
	static inline T RightShift(T value, unsigned int bits)
	{
		CRYPTOPP_ASSERT(bits < sizeof(T)*8);
		return value >> bits;
	}

	template <class T>
	static inline T LeftShift(T value, unsigned int bits)
	{
		CRYPTOPP_ASSERT(bits < sizeof(T)*8);
		return value << bits;
	}
};

template <unsigned int bits, class T>
inline T SafeRightShift(T value)
{
	return SafeShifter<(bits>=(8*sizeof(T)))>::RightShift(value, bits);
}

template <unsigned int bits, class T>
inline T SafeLeftShift(T value)
{
	return SafeShifter<(bits>=(8*sizeof(T)))>::LeftShift(value, bits);
}

// ************** use one buffer for multiple data members ***************

#define CRYPTOPP_BLOCK_1(n, t, s) t* m_##n() {return (t *)(m_aggregate+0);}	 size_t SS1() {return	   sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_2(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS1());} size_t SS2() {return SS1()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_3(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS2());} size_t SS3() {return SS2()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_4(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS3());} size_t SS4() {return SS3()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_5(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS4());} size_t SS5() {return SS4()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_6(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS5());} size_t SS6() {return SS5()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_7(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS6());} size_t SS7() {return SS6()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCK_8(n, t, s) t* m_##n() {return (t *)(m_aggregate+SS7());} size_t SS8() {return SS7()+sizeof(t)*(s);} size_t m_##n##Size() {return (s);}
#define CRYPTOPP_BLOCKS_END(i) size_t SST() {return SS##i();} void AllocateBlocks() {m_aggregate.New(SST());} AlignedSecByteBlock m_aggregate;

NAMESPACE_END

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic pop
#endif

#endif
