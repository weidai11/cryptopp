// dsa.h - written and placed in the public domain by Wei Dai

//! \file
//! \headerfile dsa.h
//! \brief Classes for DSA signature algorithm

#ifndef CRYPTOPP_DSA_H
#define CRYPTOPP_DSA_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

/*! The DSA signature format used by Crypto++ is as defined by IEEE P1363.
  Java uses the DER format, and OpenPGP uses the OpenPGP format. */
enum DSASignatureFormat {DSA_P1363, DSA_DER, DSA_OPENPGP};
/** This function converts between these formats, and returns length of signature in the target format.
	If toFormat == DSA_P1363, bufferSize must equal publicKey.SignatureLength() */
size_t DSAConvertSignatureFormat(byte *buffer, size_t bufferSize, DSASignatureFormat toFormat, 
	const byte *signature, size_t signatureLen, DSASignatureFormat fromFormat);

NAMESPACE_END

#endif
