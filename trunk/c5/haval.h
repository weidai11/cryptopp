#ifndef CRYPTOPP_HAVAL_H
#define CRYPTOPP_HAVAL_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

/// <a href="http://www.weidai.com/scan-mirror/md.html#HAVAL">HAVAL</a>
/*! \warning HAVAL with 128-bit or 160-bit output is considered insecure, and should not be used
	unless you absolutely need it for compatibility. */
class HAVAL : public IteratedHash<word32, LittleEndian, 128>
{
public:
	enum {DIGESTSIZE = 32, HAVAL_VERSION = 1};

	/// digestSize can be 16, 20, 24, 28, or 32 (Default=32)<br>
	/// pass can be 3, 4 or 5 (Default=3)
	HAVAL(unsigned int digestSize=DIGESTSIZE, unsigned int passes=3);
	void TruncatedFinal(byte *hash, unsigned int size);
	unsigned int DigestSize() const {return digestSize;}

	static const char * StaticAlgorithmName() {return "HAVAL";}
	std::string AlgorithmName() const {return std::string("HAVAL(") + IntToString(digestSize) + "," + IntToString(pass) + ")";}

protected:
	static const unsigned int wi2[32], wi3[32], wi4[32], wi5[32];
	static const word32 mc2[32], mc3[32], mc4[32], mc5[32];

	void Init();
	void Tailor(unsigned int FPTLEN);
	void HashEndianCorrectedBlock(const word32 *in);

	const unsigned int digestSize, pass;
};

/// <a href="http://www.weidai.com/scan-mirror/md.html#HAVAL">HAVAL</a> with 3 passes
class HAVAL3 : public HAVAL
{
public:
	HAVAL3(unsigned int digestSize=DIGESTSIZE) : HAVAL(digestSize, 3) {}
	static void Transform(word32 *buf, const word32 *in);
};

/// <a href="http://www.weidai.com/scan-mirror/md.html#HAVAL">HAVAL</a> with 4 passes
class HAVAL4 : public HAVAL
{
public:
	HAVAL4(unsigned int digestSize=DIGESTSIZE) : HAVAL(digestSize, 4) {}
	static void Transform(word32 *buf, const word32 *in);
};

/// <a href="http://www.weidai.com/scan-mirror/md.html#HAVAL">HAVAL</a> with 5 passes
class HAVAL5 : public HAVAL
{
public:
	HAVAL5(unsigned int digestSize=DIGESTSIZE) : HAVAL(digestSize, 5) {}
	static void Transform(word32 *buf, const word32 *in);
};

NAMESPACE_END

#endif
