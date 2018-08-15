// ppc-simd.h - written and placed in public domain by Jeffrey Walton

/// \file ppc-simd.h
/// \brief Support functions for PowerPC and vector operations
/// \details This header provides an agnostic interface into GCC and
///   IBM XL C/C++ compilers modulo their different built-in functions
///   for accessing vector intructions.
/// \details The abstractions are necesssary to support back to GCC 4.8.
///   GCC 4.8 and 4.9 are still popular, and they are the default
///   compiler for GCC112, GCC118 and others on the compile farm. Older
///   IBM XL C/C++ compilers also experience it due to lack of
///   <tt>vec_xl_be</tt> support on some platforms. Modern compilers
///   provide best support and don't need many of the little hacks below.
/// \since Crypto++ 6.0

#ifndef CRYPTOPP_PPC_CRYPTO_H
#define CRYPTOPP_PPC_CRYPTO_H

#include "config.h"
#include "misc.h"

// We are boxed into undefining macros like CRYPTOPP_POWER8_AVAILABLE.
// We set CRYPTOPP_POWER8_AVAILABLE based on compiler versions because
// we needed them for the SIMD and non-SIMD files. When the SIMD file is
// compiled it may only get -mcpu=power4 or -mcpu=power7, so the POWER7
// or POWER8 stuff is not actually available when this header is included.
#if !defined(__ALTIVEC__)
# undef CRYPTOPP_ALTIVEC_AVAILABLE
#endif

#if !defined(_ARCH_PWR7)
# undef CRYPTOPP_POWER7_AVAILABLE
#endif

#if !(defined(_ARCH_PWR8) || defined(_ARCH_PWR9) || defined(__CRYPTO) || defined(__CRYPTO__))
# undef CRYPTOPP_POWER8_AVAILABLE
# undef CRYPTOPP_POWER8_AES_AVAILABLE
# undef CRYPTOPP_POWER8_VMULL_AVAILABLE
# undef CRYPTOPP_POWER8_SHA_AVAILABLE
#endif

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)
# include <altivec.h>
# undef vector
# undef pixel
# undef bool
#endif

NAMESPACE_BEGIN(CryptoPP)

// Datatypes
#if defined(CRYPTOPP_ALTIVEC_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)
typedef __vector unsigned char   uint8x16_p;
typedef __vector unsigned short  uint16x8_p;
typedef __vector unsigned int    uint32x4_p;
#if defined(CRYPTOPP_POWER8_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)
typedef __vector unsigned long long uint64x2_p;
#endif  // POWER8 datatypes
#endif  // ALTIVEC datatypes

// Applies to all POWER machines
#if defined(CRYPTOPP_ALTIVEC_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)

/// \brief Reverse a vector
/// \tparam T vector type
/// \param src the vector
/// \returns vector
/// \details Reverse() endian swaps the bytes in a vector
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
template <class T>
inline T Reverse(const T& src)
{
    const uint8x16_p mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
    return (T)vec_perm(src, src, mask);
}

/// \brief Permutes two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \param mask vector mask
/// \returns vector
/// \details VectorPermute returns a new vector from vec1 and vec2
///   based on mask. mask is an uint8x16_p type vector. The return
///   vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorPermute(const T1& vec1, const T1& vec2, const T2& mask)
{
    return (T1)vec_perm(vec1, vec2, (uint8x16_p)mask);
}

/// \brief Permutes a vector
/// \tparam T vector type
/// \param vec the vector
/// \param mask vector mask
/// \returns vector
/// \details VectorPermute returns a new vector from vec based on
///   mask. mask is an uint8x16_p type vector. The return
///   vector is the same type as vec.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorPermute(const T1& vec, const T2& mask)
{
    return (T1)vec_perm(vec, vec, (uint8x16_p)mask);
}

/// \brief AND two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \returns vector
/// \details VectorAnd returns a new vector from vec1 and vec2. The return
///   vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorAnd(const T1& vec1, const T2& vec2)
{
    return (T1)vec_and(vec1, (T1)vec2);
}

/// \brief OR two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \returns vector
/// \details VectorOr returns a new vector from vec1 and vec2. The return
///   vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorOr(const T1& vec1, const T2& vec2)
{
    return (T1)vec_or(vec1, (T1)vec2);
}

/// \brief XOR two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \returns vector
/// \details VectorXor returns a new vector from vec1 and vec2. The return
///   vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorXor(const T1& vec1, const T2& vec2)
{
    return (T1)vec_xor(vec1, (T1)vec2);
}

/// \brief Add two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \returns vector
/// \details VectorAdd returns a new vector from vec1 and vec2.
///   vec2 is cast to the same type as vec1. The return vector
///   is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorAdd(const T1& vec1, const T2& vec2)
{
    return (T1)vec_add(vec1, (T1)vec2);
}

/// \brief Subtract two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \details VectorSub returns a new vector from vec1 and vec2.
///   vec2 is cast to the same type as vec1. The return vector
///   is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorSub(const T1& vec1, const T2& vec2)
{
    return (T1)vec_sub(vec1, (T1)vec2);
}

/// \brief Shift a vector left
/// \tparam C shift byte count
/// \tparam T vector type
/// \param vec the vector
/// \returns vector
/// \details VectorShiftLeft() returns a new vector after shifting the
///   concatenation of the zero vector and the source vector by the specified
///   number of bytes. The return vector is the same type as vec.
/// \details On big endian machines VectorShiftLeft() is <tt>vec_sld(a, z,
///   c)</tt>. On little endian machines VectorShiftLeft() is translated to
///   <tt>vec_sld(z, a, 16-c)</tt>. You should always call the function as
///   if on a big endian machine as shown below.
/// <pre>
///    uint8x16_p r1 = VectorLoad(ptr);
///    uint8x16_p r5 = VectorShiftLeft<12>(r1);
/// </pre>
/// \sa <A HREF="https://stackoverflow.com/q/46341923/608639">Is vec_sld
///   endian sensitive?</A> on Stack Overflow
/// \since Crypto++ 6.0
template <unsigned int C, class T>
inline T VectorShiftLeft(const T& vec)
{
    const T zero = {0};
    if (C >= 16)
    {
        // Out of range
        return zero;
    }
    else if (C == 0)
    {
        // Noop
        return vec;
    }
    else
    {
#if CRYPTOPP_BIG_ENDIAN
    return (T)vec_sld((uint8x16_p)vec, (uint8x16_p)zero, C);
#else
    return (T)vec_sld((uint8x16_p)zero, (uint8x16_p)vec, 16-C);
#endif
    }
}

/// \brief Shift a vector right
/// \tparam C shift byte count
/// \tparam T vector type
/// \param vec the vector
/// \returns vector
/// \details VectorShiftRight() returns a new vector after shifting the
///   concatenation of the zero vector and the source vector by the specified
///   number of bytes. The return vector is the same type as vec.
/// \details On big endian machines VectorShiftRight() is <tt>vec_sld(a, z,
///   c)</tt>. On little endian machines VectorShiftRight() is translated to
///   <tt>vec_sld(z, a, 16-c)</tt>. You should always call the function as
///   if on a big endian machine as shown below.
/// <pre>
///    uint8x16_p r1 = VectorLoad(ptr);
///    uint8x16_p r5 = VectorShiftRight<12>(r1);
/// </pre>
/// \sa <A HREF="https://stackoverflow.com/q/46341923/608639">Is vec_sld
///   endian sensitive?</A> on Stack Overflow
/// \since Crypto++ 6.0
template <unsigned int C, class T>
inline T VectorShiftRight(const T& vec)
{
    const T zero = {0};
    if (C >= 16)
    {
        // Out of range
        return zero;
    }
    else if (C == 0)
    {
        // Noop
        return vec;
    }
    else
    {
#if CRYPTOPP_BIG_ENDIAN
    return (T)vec_sld((uint8x16_p)zero, (uint8x16_p)vec, 16-C);
#else
    return (T)vec_sld((uint8x16_p)vec, (uint8x16_p)zero, C);
#endif
    }
}

/// \brief Rotate a vector left
/// \tparam C shift byte count
/// \tparam T vector type
/// \param vec the vector
/// \returns vector
/// \details VectorRotateLeft() returns a new vector after rotating the
///   concatenation of the source vector with itself by the specified
///   number of bytes. The return vector is the same type as vec.
/// \sa <A HREF="https://stackoverflow.com/q/46341923/608639">Is vec_sld
///   endian sensitive?</A> on Stack Overflow
/// \since Crypto++ 6.0
template <unsigned int C, class T>
inline T VectorRotateLeft(const T& vec)
{
    enum { R = C&0xf };
#if CRYPTOPP_BIG_ENDIAN
    return (T)vec_sld((uint8x16_p)vec, (uint8x16_p)vec, R);
#else
    return (T)vec_sld((uint8x16_p)vec, (uint8x16_p)vec, 16-R);
#endif
}

/// \brief Rotate a vector right
/// \tparam C shift byte count
/// \tparam T vector type
/// \param vec the vector
/// \returns vector
/// \details VectorRotateRight() returns a new vector after rotating the
///   concatenation of the source vector with itself by the specified
///   number of bytes. The return vector is the same type as vec.
/// \sa <A HREF="https://stackoverflow.com/q/46341923/608639">Is vec_sld
///   endian sensitive?</A> on Stack Overflow
/// \since Crypto++ 6.0
template <unsigned int C, class T>
inline T VectorRotateRight(const T& vec)
{
    enum { R = C&0xf };
#if CRYPTOPP_BIG_ENDIAN
    return (T)vec_sld((uint8x16_p)vec, (uint8x16_p)vec, 16-R);
#else
    return (T)vec_sld((uint8x16_p)vec, (uint8x16_p)vec, R);
#endif
}

/// \brief Exchange high and low double words
/// \tparam T vector type
/// \param vec the vector
/// \returns vector
/// \since Crypto++ 7.0
template <class T>
inline T VectorSwapWords(const T& vec)
{
    return (T)vec_sld((uint8x16_p)vec, (uint8x16_p)vec, 8);
}

/// \brief Extract a dword from a vector
/// \tparam T vector type
/// \param val the vector
/// \returns vector created from low dword
/// \details VectorGetLow() extracts the low dword from a vector. The low dword
///   is composed of the least significant bits and occupies bytes 8 through 15
///   when viewed as a big endian array. The return vector is the same type as
///   the original vector and padded with 0's in the most significant bit positions.
template <class T>
inline T VectorGetLow(const T& val)
{
    //const T zero = {0};
    //const uint8x16_p mask = {16,16,16,16, 16,16,16,16, 8,9,10,11, 12,13,14,15 };
    //return (T)vec_perm(val, zero, mask);
    return VectorShiftRight<8>(VectorShiftLeft<8>(val));
}

/// \brief Extract a dword from a vector
/// \tparam T vector type
/// \param val the vector
/// \returns vector created from high dword
/// \details VectorGetHigh() extracts the high dword from a vector. The high dword
///   is composed of the most significant bits and occupies bytes 0 through 7
///   when viewed as a big endian array. The return vector is the same type as
///   the original vector and padded with 0's in the most significant bit positions.
template <class T>
inline T VectorGetHigh(const T& val)
{
    //const T zero = {0};
    //const uint8x16_p mask = {16,16,16,16, 16,16,16,16, 0,1,2,3, 4,5,6,7 };
    //return (T)vec_perm(val, zero, mask);
    return VectorShiftRight<8>(val);
}

/// \brief Compare two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \returns true if vec1 equals vec2, false otherwise
template <class T1, class T2>
inline bool VectorEqual(const T1& vec1, const T2& vec2)
{
    return 1 == vec_all_eq((uint32x4_p)vec1, (uint32x4_p)vec2);
}

/// \brief Compare two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \returns true if vec1 does not equal vec2, false otherwise
template <class T1, class T2>
inline bool VectorNotEqual(const T1& vec1, const T2& vec2)
{
    return 0 == vec_all_eq((uint32x4_p)vec1, (uint32x4_p)vec2);
}

#endif  // POWER4 and above

// POWER7/POWER4 load and store
#if defined(CRYPTOPP_POWER7_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \details Loads a vector in big endian format from a byte array.
///   VectorLoadBE will swap endianess on little endian systems.
/// \note VectorLoadBE() does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoadBE(const byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl_be(0, (byte*)src);
#else
# if defined(CRYPTOPP_BIG_ENDIAN)
    return (uint32x4_p)vec_vsx_ld(0, src);
# else
    return (uint32x4_p)Reverse(vec_vsx_ld(0, src));
# endif
#endif
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \param off offset into the src byte array
/// \details Loads a vector in big endian format from a byte array.
///   VectorLoadBE will swap endianess on little endian systems.
/// \note VectorLoadBE does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoadBE(int off, const byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl_be(off, (byte*)src);
#else
# if defined(CRYPTOPP_BIG_ENDIAN)
    return (uint32x4_p)vec_vsx_ld(off, (byte*)src);
# else
    return (uint32x4_p)Reverse(vec_vsx_ld(off, (byte*)src));
# endif
#endif
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \details Loads a vector in native endian format from a byte array.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(const byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl(0, (byte*)src);
#else
    return (uint32x4_p)vec_vsx_ld(0, (byte*)src);
#endif
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \param off offset into the src byte array
/// \details Loads a vector in native endian format from a byte array.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(int off, const byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl(off, (byte*)src);
#else
    return (uint32x4_p)vec_vsx_ld(off, (byte*)src);
#endif
}

/// \brief Loads a vector from a word array
/// \param src the word array
/// \details Loads a vector in native endian format from a word array.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(const word32 src[4])
{
    return VectorLoad((const byte*)src);
}

/// \brief Loads a vector from a word array
/// \param src the word array
/// \param off offset into the src word array
/// \details Loads a vector in native endian format from a word array.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(int off, const word32 src[4])
{
    return VectorLoad(off, (const byte*)src);
}

/// \brief Stores a vector to a byte array
/// \tparam T vector type
/// \param src the vector
/// \param dest the byte array
/// \details Stores a vector in big endian format to a byte array.
///   VectorStoreBE will swap endianess on little endian systems.
/// \note VectorStoreBE does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
template <class T>
inline void VectorStoreBE(const T& src, byte dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    vec_xst_be((uint8x16_p)src, 0, (byte*)dest);
#else
# if defined(CRYPTOPP_BIG_ENDIAN)
    vec_vsx_st((uint8x16_p)src, 0, (byte*)dest);
# else
    vec_vsx_st((uint8x16_p)Reverse(src), 0, (byte*)dest);
# endif
#endif
}

/// \brief Stores a vector to a byte array
/// \tparam T vector type
/// \param src the vector
/// \param off offset into the dest byte array
/// \param dest the byte array
/// \details Stores a vector in big endian format to a byte array.
///   VectorStoreBE will swap endianess on little endian systems.
/// \note VectorStoreBE does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
template <class T>
inline void VectorStoreBE(const T& src, int off, byte dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    vec_xst_be((uint8x16_p)src, off, (byte*)dest);
#else
# if defined(CRYPTOPP_BIG_ENDIAN)
    vec_vsx_st((uint8x16_p)src, off, (byte*)dest);
# else
    vec_vsx_st((uint8x16_p)Reverse(src), off, (byte*)dest);
# endif
#endif
}

/// \brief Stores a vector to a byte array
/// \tparam T vector type
/// \param src the vector
/// \param dest the byte array
/// \details Stores a vector in native endian format to a byte array.
/// \note VectorStore does not require an aligned array.
/// \since Crypto++ 6.0
template<class T>
inline void VectorStore(const T& src, byte dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    vec_xst((uint8x16_p)src, 0, (byte*)dest);
#else
    vec_vsx_st((uint8x16_p)src, 0, (byte*)dest);
#endif
}

/// \brief Stores a vector to a byte array
/// \tparam T vector type
/// \param src the vector
/// \param off offset into the dest byte array
/// \param dest the byte array
/// \details Stores a vector in native endian format to a byte array.
/// \note VectorStore does not require an aligned array.
/// \since Crypto++ 6.0
template<class T>
inline void VectorStore(const T& src, int off, byte dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    vec_xst((uint8x16_p)src, off, (byte*)dest);
#else
    vec_vsx_st((uint8x16_p)src, off, (byte*)dest);
#endif
}

#else  // ########## Not CRYPTOPP_POWER7_AVAILABLE ##########

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \details Loads a vector in native endian format from a byte array.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(const byte src[16])
{
    if (IsAlignedOn(src, 16))
    {
        return (uint32x4_p)vec_ld(0, src);
    }
    else
    {
        // http://www.nxp.com/docs/en/reference-manual/ALTIVECPEM.pdf
        const uint8x16_p perm = vec_lvsl(0, src);
        const uint8x16_p low = vec_ld(0, src);
        const uint8x16_p high = vec_ld(15, src);
        return (uint32x4_p)vec_perm(low, high, perm);
    }
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \param off offset into the src byte array
/// \details Loads a vector in native endian format from a byte array.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(int off, const byte src[16])
{
    if (IsAlignedOn(src, 16))
    {
        return (uint32x4_p)vec_ld(off, src);
    }
    else
    {
        // http://www.nxp.com/docs/en/reference-manual/ALTIVECPEM.pdf
        const uint8x16_p perm = vec_lvsl(off, src);
        const uint8x16_p low = vec_ld(off, src);
        const uint8x16_p high = vec_ld(15, src);
        return (uint32x4_p)vec_perm(low, high, perm);
    }
}

/// \brief Loads a vector from a word array
/// \param src the word array
/// \details Loads a vector in native endian format from a word array.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(const word32 src[4])
{
    return VectorLoad((const byte*)src);
}

/// \brief Loads a vector from a word array
/// \param src the word array
/// \param off offset into the src word array
/// \details Loads a vector in native endian format from a word array.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(int off, const word32 src[4])
{
    return VectorLoad(off, (const byte*)src);
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \details Loads a vector in big endian format from a byte array.
///   VectorLoadBE will swap endianess on little endian systems.
/// \note VectorLoadBE() does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoadBE(const byte src[16])
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    return (uint32x4_p)VectorLoad(src);
#else
    return (uint32x4_p)Reverse(VectorLoad(src));
#endif
}

template<class T>
inline void VectorStore(const T& data, byte dest[16])
{
    if (IsAlignedOn(dest, 16))
    {
        vec_st((uint8x16_p)data, 0,  dest);
    }
    else
    {
        // http://www.nxp.com/docs/en/reference-manual/ALTIVECPEM.pdf
        uint8x16_p perm = (uint8x16_p)vec_perm(data, data, vec_lvsr(0, dest));
        vec_ste((uint8x16_p) perm,  0, (unsigned char*) dest);
        vec_ste((uint16x8_p) perm,  1, (unsigned short*)dest);
        vec_ste((uint32x4_p) perm,  3, (unsigned int*)  dest);
        vec_ste((uint32x4_p) perm,  4, (unsigned int*)  dest);
        vec_ste((uint32x4_p) perm,  8, (unsigned int*)  dest);
        vec_ste((uint32x4_p) perm, 12, (unsigned int*)  dest);
        vec_ste((uint16x8_p) perm, 14, (unsigned short*)dest);
        vec_ste((uint8x16_p) perm, 15, (unsigned char*) dest);
    }
}

/// \brief Stores a vector to a byte array
/// \tparam T vector type
/// \param src the vector
/// \param dest the byte array
/// \details Stores a vector in big endian format to a byte array.
///   VectorStoreBE will swap endianess on little endian systems.
/// \note VectorStoreBE does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad()
/// \since Crypto++ 6.0
template <class T>
inline void VectorStoreBE(const T& src, byte dest[16])
{
#if defined(CRYPTOPP_BIG_ENDIAN)
    VectorStore(src, dest);
#else
    VectorStore(Reverse(src), dest);
#endif
}

#endif  // POWER4/POWER7 load and store

// POWER8 crypto
#if defined(CRYPTOPP_POWER8_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)

/// \brief One round of AES encryption
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param state the state vector
/// \param key the subkey vector
/// \details VectorEncrypt performs one round of AES encryption of state
///   using subkey key. The return vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorEncrypt(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (T1)__vcipher((uint8x16_p)state, (uint8x16_p)key);
#elif defined(CRYPTOPP_GCC_VERSION)
    return (T1)__builtin_crypto_vcipher((uint64x2_p)state, (uint64x2_p)key);
#else
    CRYPTOPP_ASSERT(0);
#endif
}

/// \brief Final round of AES encryption
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param state the state vector
/// \param key the subkey vector
/// \details VectorEncryptLast performs the final round of AES encryption
///   of state using subkey key. The return vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorEncryptLast(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (T1)__vcipherlast((uint8x16_p)state, (uint8x16_p)key);
#elif defined(CRYPTOPP_GCC_VERSION)
    return (T1)__builtin_crypto_vcipherlast((uint64x2_p)state, (uint64x2_p)key);
#else
    CRYPTOPP_ASSERT(0);
#endif
}

/// \brief One round of AES decryption
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param state the state vector
/// \param key the subkey vector
/// \details VectorDecrypt performs one round of AES decryption of state
///   using subkey key. The return vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorDecrypt(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (T1)__vncipher((uint8x16_p)state, (uint8x16_p)key);
#elif defined(CRYPTOPP_GCC_VERSION)
    return (T1)__builtin_crypto_vncipher((uint64x2_p)state, (uint64x2_p)key);
#else
    CRYPTOPP_ASSERT(0);
#endif
}

/// \brief Final round of AES decryption
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param state the state vector
/// \param key the subkey vector
/// \details VectorDecryptLast performs the final round of AES decryption
///   of state using subkey key. The return vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorDecryptLast(const T1& state, const T2& key)
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (T1)__vncipherlast((uint8x16_p)state, (uint8x16_p)key);
#elif defined(CRYPTOPP_GCC_VERSION)
    return (T1)__builtin_crypto_vncipherlast((uint64x2_p)state, (uint64x2_p)key);
#else
    CRYPTOPP_ASSERT(0);
#endif
}

#endif  // POWER8 crypto

#if defined(CRYPTOPP_POWER8_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)

/// \brief SHA256 Sigma functions
/// \tparam func function
/// \tparam subfunc sub-function
/// \tparam T vector type
/// \param vec the block to transform
/// \details VectorSHA256 selects sigma0, sigma1, Sigma0, Sigma1 based on
///   func and subfunc. The return vector is the same type as vec.
/// \since Crypto++ 6.0
template <int func, int subfunc, class T>
inline T VectorSHA256(const T& vec)
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (T)__vshasigmaw((uint32x4_p)vec, func, subfunc);
#elif defined(CRYPTOPP_GCC_VERSION)
    return (T)__builtin_crypto_vshasigmaw((uint32x4_p)vec, func, subfunc);
#else
    CRYPTOPP_ASSERT(0);
#endif
}

/// \brief SHA512 Sigma functions
/// \tparam func function
/// \tparam subfunc sub-function
/// \tparam T vector type
/// \param vec the block to transform
/// \details VectorSHA512 selects sigma0, sigma1, Sigma0, Sigma1 based on
///   func and subfunc. The return vector is the same type as vec.
/// \since Crypto++ 6.0
template <int func, int subfunc, class T>
inline T VectorSHA512(const T& vec)
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (T)__vshasigmad((uint64x2_p)vec, func, subfunc);
#elif defined(CRYPTOPP_GCC_VERSION)
    return (T)__builtin_crypto_vshasigmad((uint64x2_p)vec, func, subfunc);
#else
    CRYPTOPP_ASSERT(0);
#endif
}

#endif  // POWER8 crypto

NAMESPACE_END

#endif  // CRYPTOPP_PPC_CRYPTO_H
