#ifndef CRYPTOPP_MISC_H
#define CRYPTOPP_MISC_H

#include "cryptlib.h"
#include "smartptr.h"

#ifdef INTEL_INTRINSICS
#include <stdlib.h>
#endif

#ifdef __BORLANDC__
#include <mem.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

// ************** compile-time assertion ***************

template <bool b>
struct CompileAssert
{
	static char dummy[2*b-1];
};

#define CRYPTOPP_COMPILE_ASSERT(assertion) CRYPTOPP_COMPILE_ASSERT_INSTANCE(assertion, __LINE__)
#if defined(CRYPTOPP_EXPORTS) || defined(CRYPTOPP_IMPORTS)
#define CRYPTOPP_COMPILE_ASSERT_INSTANCE(assertion, instance)
#else
#define CRYPTOPP_COMPILE_ASSERT_INSTANCE(assertion, instance) static CompileAssert<(assertion)> CRYPTOPP_ASSERT_JOIN(cryptopp_assert_, instance)
#endif
#define CRYPTOPP_ASSERT_JOIN(X, Y) CRYPTOPP_DO_ASSERT_JOIN(X, Y)
#define CRYPTOPP_DO_ASSERT_JOIN(X, Y) X##Y

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

/*! This function safely initializes a static object in a multithreaded environment without using locks.
	It may leak memory when two threads try to initialize the static object at the same time
	but this should be acceptable since each static object is only initialized once per session.
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

template <class T, class F, int instance>
const T & Singleton<T, F, instance>::Ref(CRYPTOPP_NOINLINE_DOTDOTDOT) const
{
	static simple_ptr<T> s_pObject;
	static char s_objectState = 0;

retry:
	switch (s_objectState)
	{
	case 0:
		s_objectState = 1;
		try
		{
			s_pObject.m_p = m_objectFactory();
		}
		catch(...)
		{
			s_objectState = 0;
			throw;
		}
		s_objectState = 2;
		break;
	case 1:
		goto retry;
	default:
		break;
	}
	return *s_pObject.m_p;
}

// ************** misc functions ***************

#if (!__STDC_WANT_SECURE_LIB__)
inline void memcpy_s(void *dest, size_t sizeInBytes, const void *src, size_t count)
{
	if (count > sizeInBytes)
		throw InvalidArgument("memcpy_s: buffer overflow");
	memcpy(dest, src, count);
}

inline void memmove_s(void *dest, size_t sizeInBytes, const void *src, size_t count)
{
	if (count > sizeInBytes)
		throw InvalidArgument("memmove_s: buffer overflow");
	memmove(dest, src, count);
}
#endif

// can't use std::min or std::max in MSVC60 or Cygwin 1.1.0
template <class T> inline const T& STDMIN(const T& a, const T& b)
{
	return b < a ? b : a;
}

template <class T1, class T2> inline const T1 UnsignedMin(const T1& a, const T2& b)
{
	CRYPTOPP_COMPILE_ASSERT((sizeof(T1)<=sizeof(T2) && T2(-1)>0) || (sizeof(T1)>sizeof(T2) && T1(-1)>0));
	assert(a==0 || a>0);	// GCC workaround: get rid of the warning "comparison is always true due to limited range of data type"
	assert(b>=0);

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

template <class T>
inline T Crop(T value, size_t size)
{
	if (size < 8*sizeof(value))
    	return T(value & ((T(1) << size) - 1));
	else
		return value;
}

template <class T1, class T2>
inline bool SafeConvert(T1 from, T2 &to)
{
	to = (T2)from;
	if (from != to || (from > 0) != (to > 0))
		return false;
	return true;
}

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

template <class T>
inline bool IsPowerOf2(const T &n)
{
	return n > 0 && (n & (n-1)) == 0;
}

template <class T1, class T2>
inline T2 ModPowerOf2(const T1 &a, const T2 &b)
{
	assert(IsPowerOf2(b));
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
	if (n+m-1 < n)
		throw InvalidArgument("RoundUpToMultipleOf: integer overflow");
	return RoundDownToMultipleOf(n+m-1, m);
}

template <class T>
inline unsigned int GetAlignment(T *dummy=NULL)	// VC60 workaround
{
#if (_MSC_VER >= 1300)
	return __alignof(T);
#elif defined(__GNUC__)
	return __alignof__(T);
#elif defined(CRYPTOPP_SLOW_WORD64)
	return UnsignedMin(4U, sizeof(T));
#else
	return sizeof(T);
#endif
}

inline bool IsAlignedOn(const void *p, unsigned int alignment)
{
	return IsPowerOf2(alignment) ? ModPowerOf2((size_t)p, alignment) == 0 : (size_t)p % alignment == 0;
}

template <class T>
inline bool IsAligned(const void *p, T *dummy=NULL)	// VC60 workaround
{
	return IsAlignedOn(p, GetAlignment<T>());
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
		T digit = a % base;
		result = char((digit < 10 ? '0' : ('a' - 10)) + digit) + result;
		a /= base;
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

void CallNewHandler();

inline void IncrementCounterByOne(byte *inout, unsigned int s)
{
	for (int i=s-1, carry=1; i>=0 && carry; i--)
		carry = !++inout[i];
}

inline void IncrementCounterByOne(byte *output, const byte *input, unsigned int s)
{
	int i, carry;
	for (i=s-1, carry=1; i>=0 && carry; i--)
		carry = ((output[i] = input[i]+1) == 0);
	memcpy_s(output, s, input, i+1);
}

// ************** rotate functions ***************

template <class T> inline T rotlFixed(T x, unsigned int y)
{
	assert(y < sizeof(T)*8);
	return T((x<<y) | (x>>(sizeof(T)*8-y)));
}

template <class T> inline T rotrFixed(T x, unsigned int y)
{
	assert(y < sizeof(T)*8);
	return T((x>>y) | (x<<(sizeof(T)*8-y)));
}

template <class T> inline T rotlVariable(T x, unsigned int y)
{
	assert(y < sizeof(T)*8);
	return T((x<<y) | (x>>(sizeof(T)*8-y)));
}

template <class T> inline T rotrVariable(T x, unsigned int y)
{
	assert(y < sizeof(T)*8);
	return T((x>>y) | (x<<(sizeof(T)*8-y)));
}

template <class T> inline T rotlMod(T x, unsigned int y)
{
	y %= sizeof(T)*8;
	return T((x<<y) | (x>>(sizeof(T)*8-y)));
}

template <class T> inline T rotrMod(T x, unsigned int y)
{
	y %= sizeof(T)*8;
	return T((x>>y) | (x<<(sizeof(T)*8-y)));
}

#ifdef INTEL_INTRINSICS

#pragma intrinsic(_lrotl, _lrotr)

template<> inline word32 rotlFixed<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return y ? _lrotl(x, y) : x;
}

template<> inline word32 rotrFixed<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return y ? _lrotr(x, y) : x;
}

template<> inline word32 rotlVariable<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return _lrotl(x, y);
}

template<> inline word32 rotrVariable<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
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

#endif // #ifdef INTEL_INTRINSICS

#ifdef PPC_INTRINSICS

template<> inline word32 rotlFixed<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return y ? __rlwinm(x,y,0,31) : x;
}

template<> inline word32 rotrFixed<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return y ? __rlwinm(x,32-y,0,31) : x;
}

template<> inline word32 rotlVariable<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return (__rlwnm(x,y,0,31));
}

template<> inline word32 rotrVariable<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
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

#endif // #ifdef PPC_INTRINSICS

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
	return rotlFixed(value, 8U);
}

inline word32 ByteReverse(word32 value)
{
#ifdef PPC_INTRINSICS
	// PPC: load reverse indexed instruction
	return (word32)__lwbrx(&value,0);
#elif defined(FAST_ROTATE)
	// 5 instructions with rotate instruction, 9 without
	return (rotrFixed(value, 8U) & 0xff00ff00) | (rotlFixed(value, 8U) & 0x00ff00ff);
#else
	// 6 instructions with rotate instruction, 8 without
	value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
	return rotlFixed(value, 16U);
#endif
}

#ifdef WORD64_AVAILABLE
inline word64 ByteReverse(word64 value)
{
#ifdef CRYPTOPP_SLOW_WORD64
	return (word64(ByteReverse(word32(value))) << 32) | ByteReverse(word32(value>>32));
#else
	value = ((value & W64LIT(0xFF00FF00FF00FF00)) >> 8) | ((value & W64LIT(0x00FF00FF00FF00FF)) << 8);
	value = ((value & W64LIT(0xFFFF0000FFFF0000)) >> 16) | ((value & W64LIT(0x0000FFFF0000FFFF)) << 16);
	return rotlFixed(value, 32U);
#endif
}
#endif

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

#ifdef WORD64_AVAILABLE
inline word64 BitReverse(word64 value)
{
#ifdef CRYPTOPP_SLOW_WORD64
	return (word64(BitReverse(word32(value))) << 32) | BitReverse(word32(value>>32));
#else
	value = ((value & W64LIT(0xAAAAAAAAAAAAAAAA)) >> 1) | ((value & W64LIT(0x5555555555555555)) << 1);
	value = ((value & W64LIT(0xCCCCCCCCCCCCCCCC)) >> 2) | ((value & W64LIT(0x3333333333333333)) << 2);
	value = ((value & W64LIT(0xF0F0F0F0F0F0F0F0)) >> 4) | ((value & W64LIT(0x0F0F0F0F0F0F0F0F)) << 4);
	return ByteReverse(value);
#endif
}
#endif

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
#ifdef WORD64_AVAILABLE
		assert(sizeof(T) == 8);
		return (T)BitReverse((word64)value);
#else
		assert(false);
		return 0;
#endif
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
	assert(byteCount % sizeof(T) == 0);
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
	assert(inlen <= outlen*U);
	memcpy(out, in, inlen);
	memset((byte *)out+inlen, 0, outlen*U-inlen);
	ConditionalByteReverse(order, out, out, RoundUpToMultipleOf(inlen, U));
}

inline byte UnalignedGetWordNonTemplate(ByteOrder order, const byte *block, byte*)
{
	return block[0];
}

inline word16 UnalignedGetWordNonTemplate(ByteOrder order, const byte *block, word16*)
{
	return (order == BIG_ENDIAN_ORDER)
		? block[1] | (block[0] << 8)
		: block[0] | (block[1] << 8);
}

inline word32 UnalignedGetWordNonTemplate(ByteOrder order, const byte *block, word32*)
{
	return (order == BIG_ENDIAN_ORDER)
		? word32(block[3]) | (word32(block[2]) << 8) | (word32(block[1]) << 16) | (word32(block[0]) << 24)
		: word32(block[0]) | (word32(block[1]) << 8) | (word32(block[2]) << 16) | (word32(block[3]) << 24);
}

#ifdef WORD64_AVAILABLE
inline word64 UnalignedGetWordNonTemplate(ByteOrder order, const byte *block, word64*)
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
#endif

template <class T>
inline T UnalignedGetWord(ByteOrder order, const byte *block, T*dummy=NULL)
{
	return UnalignedGetWordNonTemplate(order, block, dummy);
}

inline void UnalignedPutWord(ByteOrder order, byte *block, byte value, const byte *xorBlock = NULL)
{
	block[0] = xorBlock ? (value ^ xorBlock[0]) : value;
}

inline void UnalignedPutWord(ByteOrder order, byte *block, word16 value, const byte *xorBlock = NULL)
{
	if (order == BIG_ENDIAN_ORDER)
	{
		block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
		block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
	}
	else
	{
		block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
		block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
	}

	if (xorBlock)
	{
		block[0] ^= xorBlock[0];
		block[1] ^= xorBlock[1];
	}
}

inline void UnalignedPutWord(ByteOrder order, byte *block, word32 value, const byte *xorBlock = NULL)
{
	if (order == BIG_ENDIAN_ORDER)
	{
		block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
		block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
		block[2] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
		block[3] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
	}
	else
	{
		block[0] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 0);
		block[1] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 1);
		block[2] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 2);
		block[3] = CRYPTOPP_GET_BYTE_AS_BYTE(value, 3);
	}

	if (xorBlock)
	{
		block[0] ^= xorBlock[0];
		block[1] ^= xorBlock[1];
		block[2] ^= xorBlock[2];
		block[3] ^= xorBlock[3];
	}
}

#ifdef WORD64_AVAILABLE
inline void UnalignedPutWord(ByteOrder order, byte *block, word64 value, const byte *xorBlock = NULL)
{
	if (order == BIG_ENDIAN_ORDER)
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

	if (xorBlock)
	{
		block[0] ^= xorBlock[0];
		block[1] ^= xorBlock[1];
		block[2] ^= xorBlock[2];
		block[3] ^= xorBlock[3];
		block[4] ^= xorBlock[4];
		block[5] ^= xorBlock[5];
		block[6] ^= xorBlock[6];
		block[7] ^= xorBlock[7];
	}
}
#endif

template <class T>
inline T GetWord(bool assumeAligned, ByteOrder order, const byte *block)
{
	if (assumeAligned)
	{
		assert(IsAligned<T>(block));
		return ConditionalByteReverse(order, *reinterpret_cast<const T *>(block));
	}
	else
		return UnalignedGetWord<T>(order, block);
}

template <class T>
inline void GetWord(bool assumeAligned, ByteOrder order, T &result, const byte *block)
{
	result = GetWord<T>(assumeAligned, order, block);
}

template <class T>
inline void PutWord(bool assumeAligned, ByteOrder order, byte *block, T value, const byte *xorBlock = NULL)
{
	if (assumeAligned)
	{
		assert(IsAligned<T>(block));
		assert(IsAligned<T>(xorBlock));
		if (xorBlock)
			*reinterpret_cast<T *>(block) = ConditionalByteReverse(order, value) ^ *reinterpret_cast<const T *>(xorBlock);
		else
			*reinterpret_cast<T *>(block) = ConditionalByteReverse(order, value);
	}
	else
		UnalignedPutWord(order, block, value, xorBlock);
}

template <class T, class B, bool A=true>
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

template <class T, class B, bool A=true>
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

template <class T, class B, bool A=true>
struct BlockGetAndPut
{
	// function needed because of C++ grammatical ambiguity between expression-statements and declarations
	static inline GetBlock<T, B, A> Get(const void *block) {return GetBlock<T, B, A>(block);}
	typedef PutBlock<T, B, A> Put;
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
		return value >> bits;
	}

	template <class T>
	static inline T LeftShift(T value, unsigned int bits)
	{
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

NAMESPACE_END

#endif // MISC_H
