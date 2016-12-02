// sha.h - written and placed in the public domain by Wei Dai

//! \file sha.h
//! \brief Classes for SHA-1 and SHA-2 family of message digests
//! \since SHA1 since Crypto++ 1.0, SHA2 since Crypto++ 4.0, Intel SHA extensions since Crypto++ 5.7

#ifndef CRYPTOPP_SHA_H
#define CRYPTOPP_SHA_H

#include "config.h"
#include "iterhash.h"

// Clang 3.3 integrated assembler crash on Linux
//  http://github.com/weidai11/cryptopp/issues/264
#if defined(CRYPTOPP_LLVM_CLANG_VERSION) && (CRYPTOPP_LLVM_CLANG_VERSION < 30400)
# define CRYPTOPP_DISABLE_SHA_ASM
#endif

NAMESPACE_BEGIN(CryptoPP)

//! \class SHA1
//! \brief SHA-1 message digest
//! \sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-1">SHA-1</a>
//! \since Crypto++ 1.0, Intel SHA extensions since Crypto++ 5.7
class CRYPTOPP_DLL SHA1 : public IteratedHashWithStaticTransform<word32, BigEndian, 64, 20, SHA1>
{
public:
	static void CRYPTOPP_API InitState(HashWordType *state);
	static void CRYPTOPP_API Transform(word32 *digest, const word32 *data);
	CRYPTOPP_STATIC_CONSTEXPR const char* CRYPTOPP_API StaticAlgorithmName() {return "SHA-1";}
};

typedef SHA1 SHA;	// for backwards compatibility

//! \class SHA256
//! \brief SHA-256 message digest
//! \sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-256">SHA-256</a>
//! \since Crypto++ 4.0, Intel SHA extensions since Crypto++ 5.7
class CRYPTOPP_DLL SHA256 : public IteratedHashWithStaticTransform<word32, BigEndian, 64, 32, SHA256, 32, true>
{
public:
#if (defined(CRYPTOPP_X86_ASM_AVAILABLE) || defined(CRYPTOPP_X32_ASM_AVAILABLE) || defined(CRYPTOPP_X64_MASM_AVAILABLE)) && !defined(CRYPTOPP_DISABLE_SHA_ASM)
	size_t HashMultipleBlocks(const word32 *input, size_t length);
#endif
	static void CRYPTOPP_API InitState(HashWordType *state);
	static void CRYPTOPP_API Transform(word32 *digest, const word32 *data);
	CRYPTOPP_STATIC_CONSTEXPR const char* CRYPTOPP_API StaticAlgorithmName() {return "SHA-256";}
};

//! \class SHA224
//! \brief SHA-224 message digest
//! \sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-224">SHA-224</a>
//! \since Crypto++ 4.0, Intel SHA extensions since Crypto++ 5.7
class CRYPTOPP_DLL SHA224 : public IteratedHashWithStaticTransform<word32, BigEndian, 64, 32, SHA224, 28, true>
{
public:
#if (defined(CRYPTOPP_X86_ASM_AVAILABLE) || defined(CRYPTOPP_X32_ASM_AVAILABLE) || defined(CRYPTOPP_X64_MASM_AVAILABLE)) && !defined(CRYPTOPP_DISABLE_SHA_ASM)
	size_t HashMultipleBlocks(const word32 *input, size_t length);
#endif
	static void CRYPTOPP_API InitState(HashWordType *state);
	static void CRYPTOPP_API Transform(word32 *digest, const word32 *data) {SHA256::Transform(digest, data);}
	CRYPTOPP_STATIC_CONSTEXPR const char* CRYPTOPP_API StaticAlgorithmName() {return "SHA-224";}
};

//! \class SHA512
//! \brief SHA-512 message digest
//! \sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-512">SHA-512</a>
//! \since Crypto++ 4.0
class CRYPTOPP_DLL SHA512 : public IteratedHashWithStaticTransform<word64, BigEndian, 128, 64, SHA512, 64, (CRYPTOPP_BOOL_X86|CRYPTOPP_BOOL_X32)>
{
public:
	static void CRYPTOPP_API InitState(HashWordType *state);
	static void CRYPTOPP_API Transform(word64 *digest, const word64 *data);
	CRYPTOPP_STATIC_CONSTEXPR const char* CRYPTOPP_API StaticAlgorithmName() {return "SHA-512";}
};

//! \class SHA384
//! \brief SHA-384 message digest
//! \sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-384">SHA-384</a>
//! \since Crypto++ 4.0
class CRYPTOPP_DLL SHA384 : public IteratedHashWithStaticTransform<word64, BigEndian, 128, 64, SHA384, 48, (CRYPTOPP_BOOL_X86|CRYPTOPP_BOOL_X32)>
{
public:
	static void CRYPTOPP_API InitState(HashWordType *state);
	static void CRYPTOPP_API Transform(word64 *digest, const word64 *data) {SHA512::Transform(digest, data);}
	CRYPTOPP_STATIC_CONSTEXPR const char* CRYPTOPP_API StaticAlgorithmName() {return "SHA-384";}
};

NAMESPACE_END

#endif
