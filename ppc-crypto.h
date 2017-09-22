// vec-p8.h - written and placed in public domain by Jeffrey Walton

//! \file vec-p8.h
//! \brief Support functions for PowerPC and Power8 vector operations
//! \details This header provides an agnostic interface into GCC and
//!   IBM XL C/C++ compilers modulo their different built-in functions
//!   for accessing vector intructions.
//! \since Crypto++ 6.0

#ifndef CRYPTOPP_P8_VECTOR_H
#define CRYPTOPP_P8_VECTOR_H

#include "config.h"

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include <altivec.h>
# undef vector
# undef pixel
# undef bool
#endif

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)

typedef __vector unsigned char      uint8x16_p8;
typedef __vector unsigned int       uint32x4_p8;
typedef __vector unsigned long long uint64x2_p8;

#if defined(CRYPTOPP_XLC_VERSION)
typedef uint8x16_p8 VectorType;
#elif defined(CRYPTOPP_GCC_VERSION)
typedef uint64x2_p8 VectorType;
#endif

void ReverseByteArrayLE(byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION) && defined(IS_LITTLE_ENDIAN)
	vec_st(vec_reve(vec_ld(0, src)), 0, src);
#elif defined(IS_LITTLE_ENDIAN)
	const uint8x16_p8 mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
	const uint8x16_p8 zero = {0};
	vec_vsx_st(vec_perm(vec_vsx_ld(0, src), zero, mask), 0, src);
#endif
}

template <class T1>
static inline T1 Reverse(const T1& src)
{
	const uint8x16_p8 mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
	const uint8x16_p8 zero = {0};
	return vec_perm(src, zero, mask);
}

static inline VectorType VectorLoadBE(const uint8_t src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (VectorType)vec_xl_be(0, (uint8_t*)src);
#else
# if defined(IS_LITTLE_ENDIAN)
	return (VectorType)Reverse(vec_vsx_ld(0, (uint8_t*)src));
# else
	return (VectorType)vec_vsx_ld(0, (uint8_t*)src);
# endif
#endif
}

static inline VectorType VectorLoadBE(int off, const uint8_t src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (VectorType)vec_xl_be(off, (uint8_t*)src);
#else
# if defined(IS_LITTLE_ENDIAN)
	return (VectorType)Reverse(vec_vsx_ld(off, (uint8_t*)src));
# else
	return (VectorType)vec_vsx_ld(off, (uint8_t*)src);
# endif
#endif
}

template <class T1>
static inline void VectorStoreBE(const T1& src, uint8_t dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
	vec_xst_be((uint8x16_p8)src, 0, (uint8_t*)dest);
#else
# if defined(IS_LITTLE_ENDIAN)
	vec_vsx_st(Reverse((uint8x16_p8)src), 0, (uint8_t*)dest);
# else
	vec_vsx_st((uint8x16_p8)src, 0, (uint8_t*)dest);
# endif
#endif
}

//////////////////////////////////////////////////////////////////

// Loads a mis-aligned byte array, performs an endian conversion.
static inline VectorType VectorLoad(const byte src[16])
{
	return (VectorType)VectorLoadBE((uint8_t*)src);
}

// Loads a mis-aligned byte array, performs an endian conversion.
static inline VectorType VectorLoad(int off, const byte src[16])
{
	return (VectorType)VectorLoadBE(off, (uint8_t*)src);
}

// Loads a byte array, does not perform an endian conversion.
//  This function presumes the subkey table is correct endianess.
static inline VectorType VectorLoadKey(const byte src[16])
{
	return (VectorType)vec_vsx_ld(0, (uint8_t*)src);
}

// Loads a byte array, does not perform an endian conversion.
//  This function presumes the subkey table is correct endianess.
static inline VectorType VectorLoadKey(const word32 src[4])
{
	return (VectorType)vec_vsx_ld(0, (uint8_t*)src);
}

// Loads a byte array, does not perform an endian conversion.
//  This function presumes the subkey table is correct endianess.
static inline VectorType VectorLoadKey(int off, const byte src[16])
{
	return (VectorType)vec_vsx_ld(off, (uint8_t*)src);
}

// Stores to a mis-aligned byte array, performs an endian conversion.
template<class T1>
static inline void VectorStore(const T1& src, byte dest[16])
{
	return VectorStoreBE(src, (uint8_t*)dest);
}

template <class T1, class T2>
static inline T1 VectorPermute(const T1& vec1, const T1& vec2, const T2& mask)
{
	return (T1)vec_perm(vec1, vec2, (uint8x16_p8)mask);
}

template <class T1, class T2>
static inline T1 VectorXor(const T1& vec1, const T2& vec2)
{
	return (T1)vec_xor(vec1, (T1)vec2);
}

template <class T1, class T2>
static inline T1 VectorAdd(const T1& vec1, const T2& vec2)
{
	return (T1)vec_add(vec1, (T1)vec2);
}

template <int C, class T1, class T2>
static inline T1 VectorShiftLeft(const T1& vec1, const T2& vec2)
{
#if defined(IS_LITTLE_ENDIAN)
	return (T1)vec_sld((uint8x16_p8)vec2, (uint8x16_p8)vec1, 16-C);
#else
	return (T1)vec_sld((uint8x16_p8)vec1, (uint8x16_p8)vec2, C);
#endif
}

template <class T1, class T2>
static inline T1 VectorEncrypt(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (T1)__vcipher((VectorType)state, (VectorType)key);
#elif defined(CRYPTOPP_GCC_VERSION)
	return (T1)__builtin_crypto_vcipher((VectorType)state, (VectorType)key);
#else
	CRYPTOPP_ASSERT(0);
#endif
}

template <class T1, class T2>
static inline T1 VectorEncryptLast(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (T1)__vcipherlast((VectorType)state, (VectorType)key);
#elif defined(CRYPTOPP_GCC_VERSION)
	return (T1)__builtin_crypto_vcipherlast((VectorType)state, (VectorType)key);
#else
	CRYPTOPP_ASSERT(0);
#endif
}

template <class T1, class T2>
static inline T1 VectorDecrypt(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (T1)__vncipher((VectorType)state, (VectorType)key);
#elif defined(CRYPTOPP_GCC_VERSION)
	return (T1)__builtin_crypto_vncipher((VectorType)state, (VectorType)key);
#else
	CRYPTOPP_ASSERT(0);
#endif
}

template <class T1, class T2>
static inline T1 VectorDecryptLast(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
	return (T1)__vncipherlast((VectorType)state, (VectorType)key);
#elif defined(CRYPTOPP_GCC_VERSION)
	return (T1)__builtin_crypto_vncipherlast((VectorType)state, (VectorType)key);
#else
	CRYPTOPP_ASSERT(0);
#endif
}

#endif // CRYPTOPP_ALTIVEC_AVAILABLE

NAMESPACE_END

#endif  // CRYPTOPP_P8_VECTOR_H
