#ifndef CRYPTOPP_EMSA2_H
#define CRYPTOPP_EMSA2_H

/** \file
	This file contains various padding schemes for public key algorithms.
*/

#include "cryptlib.h"
#include "pubkey.h"

#ifdef CRYPTOPP_IS_DLL
#include "sha.h"
#endif

NAMESPACE_BEGIN(CryptoPP)

template <class H> class EMSA2HashId
{
public:
	static const byte id;
};

template <class BASE>
class EMSA2HashIdLookup : public BASE
{
public:
	struct HashIdentifierLookup
	{
		template <class H> struct HashIdentifierLookup2
		{
			static HashIdentifier Lookup()
			{
				return HashIdentifier(&EMSA2HashId<H>::id, 1);
			}
		};
	};
};

// EMSA2HashId can be instantiated with the following classes.
class SHA1;
class RIPEMD160;
class RIPEMD128;
class SHA256;
class SHA384;
class SHA512;
class Whirlpool;
class SHA224;
// end of list

#ifdef CRYPTOPP_IS_DLL
CRYPTOPP_DLL_TEMPLATE_CLASS EMSA2HashId<SHA1>;
CRYPTOPP_DLL_TEMPLATE_CLASS EMSA2HashId<SHA224>;
CRYPTOPP_DLL_TEMPLATE_CLASS EMSA2HashId<SHA256>;
CRYPTOPP_DLL_TEMPLATE_CLASS EMSA2HashId<SHA384>;
CRYPTOPP_DLL_TEMPLATE_CLASS EMSA2HashId<SHA512>;
#endif

//! _
class CRYPTOPP_DLL EMSA2Pad : public EMSA2HashIdLookup<PK_DeterministicSignatureMessageEncodingMethod>
{
public:
	static const char * CRYPTOPP_API StaticAlgorithmName() {return "EMSA2";}
	
	unsigned int MinRepresentativeBitLength(unsigned int hashIdentifierLength, unsigned int digestLength) const
		{return 8*digestLength + 31;}

	void ComputeMessageRepresentative(RandomNumberGenerator &rng, 
		const byte *recoverableMessage, unsigned int recoverableMessageLength,
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const;
};

//! EMSA2, for use with RWSS and RSA_ISO
/*! Only the following hash functions are supported by this signature standard:
	\dontinclude emsa2.h
	\skip EMSA2HashId can be instantiated
	\until end of list
*/
struct P1363_EMSA2 : public SignatureStandard
{
	typedef EMSA2Pad SignatureMessageEncodingMethod;
};

NAMESPACE_END

#endif
