// simple.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "simple.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

void HashTransformationWithDefaultTruncation::TruncatedFinal(byte *digest, unsigned int digestSize)
{
	ThrowIfInvalidTruncatedSize(digestSize);
	unsigned int fullDigestSize = DigestSize();
	if (digestSize == fullDigestSize)
		Final(digest);
	else
	{
		SecByteBlock buffer(fullDigestSize);
		Final(buffer);
		memcpy(digest, buffer, digestSize);
	}
}

NAMESPACE_END
