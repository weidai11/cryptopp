#ifndef CRYPTOPP_SHA_H
#define CRYPTOPP_SHA_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

/// <a href="http://www.weidai.com/scan-mirror/md.html#SHA-1">SHA-1</a>
class CRYPTOPP_DLL SHA : public IteratedHashWithStaticTransform<word32, BigEndian, 64, 20, SHA>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word32 *digest, const word32 *data);
	static const char *StaticAlgorithmName() {return "SHA-1";}
};

typedef SHA SHA1;

//! implements the SHA-256 standard
class SHA256 : public IteratedHashWithStaticTransform<word32, BigEndian, 64, 32, SHA256>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word32 *digest, const word32 *data);
	static const char *StaticAlgorithmName() {return "SHA-256";}

protected:
	static const word32 K[64];
};

#ifdef WORD64_AVAILABLE

//! implements the SHA-512 standard
class SHA512 : public IteratedHashWithStaticTransform<word64, BigEndian, 128, 64, SHA512>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word64 *digest, const word64 *data);
	static const char *StaticAlgorithmName() {return "SHA-512";}

protected:
	static const word64 K[80];
};

//! implements the SHA-384 standard
class SHA384 : public IteratedHashWithStaticTransform<word64, BigEndian, 128, 64, SHA384, 48>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word64 *digest, const word64 *data) {SHA512::Transform(digest, data);}
	static const char *StaticAlgorithmName() {return "SHA-384";}
};

#endif

NAMESPACE_END

#endif
