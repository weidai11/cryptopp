#ifndef CRYPTOPP_SHA_H
#define CRYPTOPP_SHA_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

/// <a href="http://www.weidai.com/scan-mirror/md.html#SHA-1">SHA-1</a>
class SHA : public IteratedHashWithStaticTransform<word32, BigEndian, 64, SHA>
{
public:
	enum {DIGESTSIZE = 20};
	SHA() : IteratedHashWithStaticTransform<word32, BigEndian, 64, SHA>(DIGESTSIZE) {Init();}
	static void Transform(word32 *digest, const word32 *data);
	static const char *StaticAlgorithmName() {return "SHA-1";}

protected:
	void Init();
};

typedef SHA SHA1;

//! implements the SHA-256 standard
class SHA256 : public IteratedHashWithStaticTransform<word32, BigEndian, 64, SHA256>
{
public:
	enum {DIGESTSIZE = 32};
	SHA256() : IteratedHashWithStaticTransform<word32, BigEndian, 64, SHA256>(DIGESTSIZE) {Init();}
	static void Transform(word32 *digest, const word32 *data);
	static const char *StaticAlgorithmName() {return "SHA-256";}

protected:
	void Init();

	static const word32 K[64];
};

#ifdef WORD64_AVAILABLE

//! implements the SHA-512 standard
class SHA512 : public IteratedHashWithStaticTransform<word64, BigEndian, 128, SHA512>
{
public:
	enum {DIGESTSIZE = 64};
	SHA512() : IteratedHashWithStaticTransform<word64, BigEndian, 128, SHA512>(DIGESTSIZE) {Init();}
	static void Transform(word64 *digest, const word64 *data);
	static const char *StaticAlgorithmName() {return "SHA-512";}

protected:
	void Init();

	static const word64 K[80];
};

//! implements the SHA-384 standard
class SHA384 : public IteratedHashWithStaticTransform<word64, BigEndian, 128, SHA512>
{
public:
	enum {DIGESTSIZE = 48};
	SHA384() : IteratedHashWithStaticTransform<word64, BigEndian, 128, SHA512>(64) {Init();}
	unsigned int DigestSize() const {return DIGESTSIZE;};
	static const char *StaticAlgorithmName() {return "SHA-384";}

protected:
	void Init();
};

#endif

NAMESPACE_END

#endif
