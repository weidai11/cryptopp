#ifndef CRYPTOPP_AES_H
#define CRYPTOPP_AES_H

/** \file
	AES winner announced on 10/2/2000
*/

#include "rijndael.h"

NAMESPACE_BEGIN(CryptoPP)

#ifdef CRYPTOPP_DOXYGEN_PROCESSING	// Use inheritance instead of typedef to get a seperate API reference page for AES
//! AES
class AES : public Rijndael {};
#else
typedef Rijndael AES;
#endif

typedef RijndaelEncryption AESEncryption;
typedef RijndaelDecryption AESDecryption;

NAMESPACE_END

#endif
