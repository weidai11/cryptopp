#ifndef CRYPTOPP_AES_H
#define CRYPTOPP_AES_H

#include "rijndael.h"

NAMESPACE_BEGIN(CryptoPP)

//! AES winner, announced on 10/2/2000
DOCUMENTED_TYPEDEF(Rijndael, AES);

typedef RijndaelEncryption AESEncryption;
typedef RijndaelDecryption AESDecryption;

NAMESPACE_END

#endif
