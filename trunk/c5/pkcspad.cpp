// pkcspad.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "pkcspad.h"
#include <assert.h>

NAMESPACE_BEGIN(CryptoPP)

template<> const byte PKCS_DigestDecoration<SHA>::decoration[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
template<> const unsigned int PKCS_DigestDecoration<SHA>::length = sizeof(PKCS_DigestDecoration<SHA>::decoration);

template<> const byte PKCS_DigestDecoration<MD2>::decoration[] = {0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x02,0x05,0x00,0x04,0x10};
template<> const unsigned int PKCS_DigestDecoration<MD2>::length = sizeof(PKCS_DigestDecoration<MD2>::decoration);

template<> const byte PKCS_DigestDecoration<MD5>::decoration[] = {0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10};
template<> const unsigned int PKCS_DigestDecoration<MD5>::length = sizeof(PKCS_DigestDecoration<MD5>::decoration);

template<> const byte PKCS_DigestDecoration<RIPEMD160>::decoration[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x24,0x03,0x02,0x01,0x05,0x00,0x04,0x14};
template<> const unsigned int PKCS_DigestDecoration<RIPEMD160>::length = sizeof(PKCS_DigestDecoration<RIPEMD160>::decoration);

template<> const byte PKCS_DigestDecoration<SHA256>::decoration[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
template<> const unsigned int PKCS_DigestDecoration<SHA256>::length = sizeof(PKCS_DigestDecoration<SHA256>::decoration);

template<> const byte PKCS_DigestDecoration<SHA384>::decoration[] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
template<> const unsigned int PKCS_DigestDecoration<SHA384>::length = sizeof(PKCS_DigestDecoration<SHA384>::decoration);

template<> const byte PKCS_DigestDecoration<SHA512>::decoration[] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};
template<> const unsigned int PKCS_DigestDecoration<SHA512>::length = sizeof(PKCS_DigestDecoration<SHA512>::decoration);



unsigned int PKCS_EncryptionPaddingScheme::MaxUnpaddedLength(unsigned int paddedLength) const
{
	return paddedLength/8 > 10 ? paddedLength/8-10 : 0;
}

void PKCS_EncryptionPaddingScheme::Pad(RandomNumberGenerator &rng, const byte *input, unsigned int inputLen, byte *pkcsBlock, unsigned int pkcsBlockLen) const
{
	assert (inputLen <= MaxUnpaddedLength(pkcsBlockLen));	// this should be checked by caller

	// convert from bit length to byte length
	if (pkcsBlockLen % 8 != 0)
	{
		pkcsBlock[0] = 0;
		pkcsBlock++;
	}
	pkcsBlockLen /= 8;

	pkcsBlock[0] = 2;  // block type 2

	// pad with non-zero random bytes
	for (unsigned i = 1; i < pkcsBlockLen-inputLen-1; i++)
		pkcsBlock[i] = (byte)rng.GenerateWord32(1, 0xff);

	pkcsBlock[pkcsBlockLen-inputLen-1] = 0;     // separator
	memcpy(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);
}

DecodingResult PKCS_EncryptionPaddingScheme::Unpad(const byte *pkcsBlock, unsigned int pkcsBlockLen, byte *output) const
{
	bool invalid = false;
	unsigned int maxOutputLen = MaxUnpaddedLength(pkcsBlockLen);

	// convert from bit length to byte length
	if (pkcsBlockLen % 8 != 0)
	{
		invalid = (pkcsBlock[0] != 0) || invalid;
		pkcsBlock++;
	}
	pkcsBlockLen /= 8;

	// Require block type 2.
	invalid = (pkcsBlock[0] != 2) || invalid;

	// skip past the padding until we find the seperator
	unsigned i=1;
	while (i<pkcsBlockLen && pkcsBlock[i++]) { // null body
		}
	assert(i==pkcsBlockLen || pkcsBlock[i-1]==0);

	unsigned int outputLen = pkcsBlockLen - i;
	invalid = (outputLen > maxOutputLen) || invalid;

	if (invalid)
		return DecodingResult();

	memcpy (output, pkcsBlock+i, outputLen);
	return DecodingResult(outputLen);
}

// ********************************************************

unsigned int PKCS_SignaturePaddingScheme::MaxUnpaddedLength(unsigned int paddedLength) const
{
	return paddedLength/8 > 10 ? paddedLength/8-10 : 0;
}

void PKCS_SignaturePaddingScheme::Pad(RandomNumberGenerator &, const byte *input, unsigned int inputLen, byte *pkcsBlock, unsigned int pkcsBlockLen) const
{
	assert (inputLen <= MaxUnpaddedLength(pkcsBlockLen));	// this should be checked by caller

	// convert from bit length to byte length
	if (pkcsBlockLen % 8 != 0)
	{
		pkcsBlock[0] = 0;
		pkcsBlock++;
	}
	pkcsBlockLen /= 8;

	pkcsBlock[0] = 1;   // block type 1

	// padd with 0xff
	memset(pkcsBlock+1, 0xff, pkcsBlockLen-inputLen-2);

	pkcsBlock[pkcsBlockLen-inputLen-1] = 0;               // separator
	memcpy(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);
}

DecodingResult PKCS_SignaturePaddingScheme::Unpad(const byte *pkcsBlock, unsigned int pkcsBlockLen, byte *output) const
{
	unsigned int maxOutputLen = MaxUnpaddedLength(pkcsBlockLen);

	// convert from bit length to byte length
	if (pkcsBlockLen % 8 != 0)
	{
		if (pkcsBlock[0] != 0)
			return DecodingResult();
		pkcsBlock++;
	}
	pkcsBlockLen /= 8;

	// Require block type 1.
	if (pkcsBlock[0] != 1)
		return DecodingResult();

	// skip past the padding until we find the seperator
	unsigned i=1;
	while (i<pkcsBlockLen && pkcsBlock[i++])
		if (pkcsBlock[i-1] != 0xff)     // not valid padding
			return DecodingResult();
	assert(i==pkcsBlockLen || pkcsBlock[i-1]==0);

	unsigned int outputLen = pkcsBlockLen - i;
	if (outputLen > maxOutputLen)
		return DecodingResult();

	memcpy (output, pkcsBlock+i, outputLen);
	return DecodingResult(outputLen);
}

NAMESPACE_END
