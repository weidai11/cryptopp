#ifndef CRYPTOPP_RIPEMD_H
#define CRYPTOPP_RIPEMD_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

//! <a href="http://www.weidai.com/scan-mirror/md.html#RIPEMD-160">RIPEMD-160</a>
/*! Digest Length = 160 bits */
class RIPEMD160 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD160>
{
public:
	enum {DIGESTSIZE = 20};
	RIPEMD160() : IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD160>(DIGESTSIZE) {Init();}
	static void Transform(word32 *digest, const word32 *data);
	static const char * StaticAlgorithmName() {return "RIPEMD-160";}

protected:
	void Init();
};

/*! Digest Length = 320 bits, Security = 160 bits */
class RIPEMD320 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD320>
{
public:
	enum {DIGESTSIZE = 40};
	RIPEMD320() : IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD320>(DIGESTSIZE) {Init();}
	static void Transform(word32 *digest, const word32 *data);
	static const char * StaticAlgorithmName() {return "RIPEMD-320";}

protected:
	void Init();
};

/*! Digest Length = 128 bits */
class RIPEMD128 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD128>
{
public:
	enum {DIGESTSIZE = 16};
	RIPEMD128() : IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD128>(DIGESTSIZE) {Init();}
	static void Transform(word32 *digest, const word32 *data);
	static const char * StaticAlgorithmName() {return "RIPEMD-128";}

protected:
	void Init();
};

/*! Digest Length = 256 bits, Security = 128 bits */
class RIPEMD256 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD256>
{
public:
	enum {DIGESTSIZE = 32};
	RIPEMD256() : IteratedHashWithStaticTransform<word32, LittleEndian, 64, RIPEMD256>(DIGESTSIZE) {Init();}
	static void Transform(word32 *digest, const word32 *data);
	static const char * StaticAlgorithmName() {return "RIPEMD-256";}

protected:
	void Init();
};

NAMESPACE_END

#endif
