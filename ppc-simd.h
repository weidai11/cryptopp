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

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)
# include <altivec.h>
# undef vector
# undef pixel
# undef bool
#endif

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)

typedef __vector unsigned char   uint8x16_p;
typedef __vector unsigned short  uint16x8_p;
typedef __vector unsigned int    uint32x4_p;

#if defined(CRYPTOPP_POWER8_AVAILABLE)
typedef __vector unsigned long long uint64x2_p;
#endif

#endif  // CRYPTOPP_ALTIVEC_AVAILABLE

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE) && !defined(CRYPTOPP_POWER7_AVAILABLE)

inline uint32x4_p VectorLoad(const byte src[16])
{
    uint8x16_p data;
    if (IsAlignedOn(src, 16))
    {
        data = vec_ld(0, src);
    }
    else
    {
        // http://www.nxp.com/docs/en/reference-manual/ALTIVECPEM.pdf
        const uint8x16_p perm = vec_lvsl(0, src);
        const uint8x16_p low = vec_ld(0, src);
        const uint8x16_p high = vec_ld(15, src);
        data = vec_perm(low, high, perm);
    }

#if defined(CRYPTOPP_BIG_ENDIAN)
    return (uint32x4_p)data;
#else
    const uint8x16_p mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
    return (uint32x4_p)vec_perm(data, data, mask);
#endif
}

inline void VectorStore(const uint32x4_p data, byte dest[16])
{
#if defined(CRYPTOPP_LITTLE_ENDIAN)
    const uint8x16_p mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
    const uint8x16_p t1 = (uint8x16_p)vec_perm(data, data, mask);
#else
    const uint8x16_p t1 = (uint8x16_p)data;
#endif

    if (IsAlignedOn(dest, 16))
    {
        vec_st(t1, 0,  dest);
    }
    else
    {
        // http://www.nxp.com/docs/en/reference-manual/ALTIVECPEM.pdf
        const uint8x16_p t2 = vec_perm(t1, t1, vec_lvsr(0, dest));
        vec_ste((uint8x16_p) t2,  0, (unsigned char*) dest);
        vec_ste((uint16x8_p) t2,  1, (unsigned short*)dest);
        vec_ste((uint32x4_p) t2,  3, (unsigned int*)  dest);
        vec_ste((uint32x4_p) t2,  4, (unsigned int*)  dest);
        vec_ste((uint32x4_p) t2,  8, (unsigned int*)  dest);
        vec_ste((uint32x4_p) t2, 12, (unsigned int*)  dest);
        vec_ste((uint16x8_p) t2, 14, (unsigned short*)dest);
        vec_ste((uint8x16_p) t2, 15, (unsigned char*) dest);
    }
}

inline uint32x4_p VectorXor(const uint32x4_p vec1, const uint32x4_p vec2)
{
    return vec_xor(vec1, vec2);
}

inline uint32x4_p VectorAdd(const uint32x4_p vec1, const uint32x4_p vec2)
{
    return vec_add(vec1, vec2);
}

#endif

#if defined(CRYPTOPP_POWER7_AVAILABLE) || defined(CRYPTOPP_DOXYGEN_PROCESSING)

/// \brief Reverse a 16-byte array
/// \param src the byte array
/// \details ReverseByteArrayLE reverses a 16-byte array on a little endian
///   system. It does nothing on a big endian system.
/// \since Crypto++ 6.0
inline void ReverseByteArrayLE(byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION) && defined(CRYPTOPP_LITTLE_ENDIAN)
    vec_st(vec_reve(vec_ld(0, src)), 0, src);
#elif defined(CRYPTOPP_LITTLE_ENDIAN)
    const uint8x16_p mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
    const uint8x16_p zero = {0};
    vec_vsx_st(vec_perm(vec_vsx_ld(0, src), zero, mask), 0, src);
#endif
}

/// \brief Reverse a vector
/// \tparam T vector type
/// \param src the vector
/// \details Reverse() endian swaps the bytes in a vector
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
template <class T>
inline T Reverse(const T& src)
{
    const uint8x16_p mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
    return vec_perm(src, src, mask);
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \details Loads a vector in big endian format from a byte array.
///   VectorLoadBE will swap endianess on little endian systems.
/// \note VectorLoadBE() does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoadBE(const uint8_t src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl_be(0, src);
#else
# if defined(CRYPTOPP_LITTLE_ENDIAN)
    return (uint32x4_p)Reverse(vec_vsx_ld(0, src));
# else
    return (uint32x4_p)vec_vsx_ld(0, src);
# endif
#endif
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \param off offset into the src byte array
/// \details Loads a vector in big endian format from a byte array.
///   VectorLoadBE will swap endianess on little endian systems.
/// \note VectorLoadBE does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoadBE(int off, const uint8_t src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl_be(off, src);
#else
# if defined(CRYPTOPP_LITTLE_ENDIAN)
    return (uint32x4_p)Reverse(vec_vsx_ld(off, src));
# else
    return (uint32x4_p)vec_vsx_ld(off, src);
# endif
#endif
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \details Loads a vector in big endian format from a byte array.
///   VectorLoad will swap endianess on little endian systems.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(const byte src[16])
{
    return (uint32x4_p)VectorLoadBE(src);
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \param off offset into the src byte array
/// \details Loads a vector in big endian format from a byte array.
///   VectorLoad will swap endianess on little endian systems.
/// \note VectorLoad does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoad(int off, const byte src[16])
{
    return (uint32x4_p)VectorLoadBE(off, src);
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \details Loads a vector from a byte array.
///   VectorLoadKey does not swap endianess on little endian systems.
/// \note VectorLoadKey does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoadKey(const byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl(0, src);
#else
    return (uint32x4_p)vec_vsx_ld(0, src);
#endif
}

/// \brief Loads a vector from a 32-bit word array
/// \param src the 32-bit word array
/// \details Loads a vector from a 32-bit word array.
///   VectorLoadKey does not swap endianess on little endian systems.
/// \note VectorLoadKey does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoadKey(const word32 src[4])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl(0, src);
#else
    return (uint32x4_p)vec_vsx_ld(0, src);
#endif
}

/// \brief Loads a vector from a byte array
/// \param src the byte array
/// \param off offset into the src byte array
/// \details Loads a vector from a byte array.
///   VectorLoadKey does not swap endianess on little endian systems.
/// \note VectorLoadKey does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
inline uint32x4_p VectorLoadKey(int off, const byte src[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    return (uint32x4_p)vec_xl(off, src);
#else
    return (uint32x4_p)vec_vsx_ld(off, src);
#endif
}

/// \brief Stores a vector to a byte array
/// \tparam T vector type
/// \param src the vector
/// \param dest the byte array
/// \details Stores a vector in big endian format to a byte array.
///   VectorStoreBE will swap endianess on little endian systems.
/// \note VectorStoreBE does not require an aligned array.
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
template <class T>
inline void VectorStoreBE(const T& src, uint8_t dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    vec_xst_be((uint8x16_p)src, 0, dest);
#else
# if defined(CRYPTOPP_LITTLE_ENDIAN)
    vec_vsx_st(Reverse((uint8x16_p)src), 0, dest);
# else
    vec_vsx_st((uint8x16_p)src, 0, dest);
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
/// \sa Reverse(), VectorLoadBE(), VectorLoad(), VectorLoadKey()
/// \since Crypto++ 6.0
template <class T>
inline void VectorStoreBE(const T& src, int off, uint8_t dest[16])
{
#if defined(CRYPTOPP_XLC_VERSION)
    vec_xst_be((uint8x16_p)src, off, dest);
#else
# if defined(CRYPTOPP_LITTLE_ENDIAN)
    vec_vsx_st(Reverse((uint8x16_p)src), off, dest);
# else
    vec_vsx_st((uint8x16_p)src, off, dest);
# endif
#endif
}

/// \brief Stores a vector to a byte array
/// \tparam T vector type
/// \param src the vector
/// \param dest the byte array
/// \details Stores a vector in big endian format to a byte array.
///   VectorStore will swap endianess on little endian systems.
/// \note VectorStore does not require an aligned array.
/// \since Crypto++ 6.0
template<class T>
inline void VectorStore(const T& src, byte dest[16])
{
    // Do not call VectorStoreBE. It slows us down by about 0.5 cpb on LE.
#if defined(CRYPTOPP_XLC_VERSION)
    vec_xst_be((uint8x16_p)src, 0, dest);
#else
# if defined(CRYPTOPP_LITTLE_ENDIAN)
    vec_vsx_st(Reverse((uint8x16_p)src), 0, dest);
# else
    vec_vsx_st((uint8x16_p)src, 0, dest);
# endif
#endif
}

/// \brief Stores a vector to a byte array
/// \tparam T vector type
/// \param src the vector
/// \param off offset into the dest byte array
/// \param dest the byte array
/// \details Stores a vector in big endian format to a byte array.
///   VectorStore will swap endianess on little endian systems.
/// \note VectorStore does not require an aligned array.
/// \since Crypto++ 6.0
template<class T>
inline void VectorStore(const T& src, int off, byte dest[16])
{
    // Do not call VectorStoreBE. It slows us down by about 0.5 cpb on LE.
#if defined(CRYPTOPP_XLC_VERSION)
    vec_xst_be((uint8x16_p)src, off, dest);
#else
# if defined(CRYPTOPP_LITTLE_ENDIAN)
    vec_vsx_st(Reverse((uint8x16_p)src), off, dest);
# else
    vec_vsx_st((uint8x16_p)src, off, dest);
# endif
#endif
}

/// \brief Permutes two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \param mask vector mask
/// \details VectorPermute returns a new vector from vec1 and vec2
///   based on mask. mask is an uint8x16_p type vector. The return
///   vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorPermute(const T1& vec1, const T1& vec2, const T2& mask)
{
    return (T1)vec_perm(vec1, vec2, (uint8x16_p)mask);
}

/// \brief XOR two vectors
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \details VectorXor returns a new vector from vec1 and vec2. The return
///   vector is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorXor(const T1& vec1, const T2& vec2)
{
    return (T1)vec_xor(vec1, (T1)vec2);
}

/// \brief Add two vector
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \details VectorAdd returns a new vector from vec1 and vec2.
///   vec2 is cast to the same type as vec1. The return vector
///   is the same type as vec1.
/// \since Crypto++ 6.0
template <class T1, class T2>
inline T1 VectorAdd(const T1& vec1, const T2& vec2)
{
    return (T1)vec_add(vec1, (T1)vec2);
}

/// \brief Shift two vectors left
/// \tparam C shift byte count
/// \tparam T1 vector type
/// \tparam T2 vector type
/// \param vec1 the first vector
/// \param vec2 the second vector
/// \details VectorShiftLeft() concatenates vec1 and vec2 and returns a
///   new vector after shifting the concatenation by the specified number
///   of bytes. Both vec1 and vec2 are cast to uint8x16_p. The return
///   vector is the same type as vec1.
/// \details On big endian machines VectorShiftLeft() is <tt>vec_sld(a, b,
///   c)</tt>. On little endian machines VectorShiftLeft() is translated to
///   <tt>vec_sld(b, a, 16-c)</tt>. You should always call the function as
///   if on a big endian machine as shown below.
/// <pre>
///    uint8x16_p r0 = {0};
///    uint8x16_p r1 = VectorLoad(ptr);
///    uint8x16_p r5 = VectorShiftLeft<12>(r0, r1);
/// </pre>
/// \sa <A HREF="https://stackoverflow.com/q/46341923/608639">Is vec_sld
///   endian sensitive?</A> on Stack Overflow
/// \since Crypto++ 6.0
template <unsigned int C, class T1, class T2>
inline T1 VectorShiftLeft(const T1& vec1, const T2& vec2)
{
#if defined(CRYPTOPP_LITTLE_ENDIAN)
    return (T1)vec_sld((uint8x16_p)vec2, (uint8x16_p)vec1, 16-C);
#else
    return (T1)vec_sld((uint8x16_p)vec1, (uint8x16_p)vec2, C);
#endif
}

#endif  // CRYPTOPP_POWER7_AVAILABLE

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

#endif  // CRYPTOPP_POWER8_AVAILABLE

NAMESPACE_END

#endif  // CRYPTOPP_PPC_CRYPTO_H
