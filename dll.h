// dll.h - originally written and placed in the public domain by Wei Dai

/// \file dll.h
/// \brief Functions and definitions required for building the FIPS-140 DLL on Windows

#ifndef CRYPTOPP_DLL_H
#define CRYPTOPP_DLL_H

#if !defined(CRYPTOPP_IMPORTS) && !defined(CRYPTOPP_EXPORTS) && !defined(CRYPTOPP_DEFAULT_NO_DLL)
#ifdef CRYPTOPP_CONFIG_H
#error To use the DLL version of Crypto++, this file must be included before any other Crypto++ header files.
#endif
#define CRYPTOPP_IMPORTS
#endif

#include <cryptopp/aes.h>
#include <cryptopp/cbcmac.h>
#include <cryptopp/ccm.h>
#include <cryptopp/cmac.h>
#include <cryptopp/channels.h>
#include <cryptopp/des.h>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include <cryptopp/ec2n.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include "files.h"
#include <cryptopp/fips140.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/modes.h>
#include <cryptopp/mqueue.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pkcspad.h>
#include <cryptopp/pssr.h>
#include <cryptopp/randpool.h>
#include <cryptopp/rsa.h>
#include <cryptopp/rw.h>
#include <cryptopp/sha.h>
#include <cryptopp/skipjack.h>

#ifdef CRYPTOPP_IMPORTS

#ifdef _DLL
// cause CRT DLL to be initialized before Crypto++ so that we can use malloc and free during DllMain()
#ifdef CRYPTOPP_DEBUG
# pragma comment(lib, "msvcrtd")
# pragma comment(lib, "cryptopp")
#else
# pragma comment(lib, "msvcrt")
# pragma comment(lib, "cryptopp")
#endif
#endif

#endif		// #ifdef CRYPTOPP_IMPORTS

#include <new>	// for new_handler

NAMESPACE_BEGIN(CryptoPP)

typedef void * (CRYPTOPP_API * PNew)(size_t);
typedef void (CRYPTOPP_API * PDelete)(void *);
typedef void (CRYPTOPP_API * PGetNewAndDelete)(PNew &, PDelete &);
typedef std::new_handler (CRYPTOPP_API * PSetNewHandler)(std::new_handler);
typedef void (CRYPTOPP_API * PSetNewAndDelete)(PNew, PDelete, PSetNewHandler);

NAMESPACE_END

#endif
