#ifndef CRYPTOPP_PSSR_H
#define CRYPTOPP_PSSR_H

#include "pubkey.h"
#include <functional>

NAMESPACE_BEGIN(CryptoPP)

class PSSR_MEM_Base : public PK_RecoverableSignatureMessageEncodingMethod
{
	virtual bool AllowRecovery() const =0;
	virtual unsigned int SaltLen(unsigned int hashLen) const =0;
	virtual unsigned int MinPadLen(unsigned int hashLen) const =0;
	virtual const MaskGeneratingFunction & GetMGF() const =0;

public:
	unsigned int MaxRecoverableLength(unsigned int representativeBitLength, unsigned int hashIdentifierLength, unsigned int digestLength) const;
	bool IsProbabilistic() const;
	bool AllowNonrecoverablePart() const;
	bool RecoverablePartFirst() const;
	void ComputeMessageRepresentative(RandomNumberGenerator &rng, 
		const byte *recoverableMessage, unsigned int recoverableMessageLength,
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength) const;
	DecodingResult RecoverMessageFromRepresentative(
		HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
		byte *representative, unsigned int representativeBitLength,
		byte *recoverableMessage) const;
};

template <class H> struct EMSA2HashId
{
	static const byte id;
};

// EMSA2HashId can be instantiated with the following classes.
class SHA;
class RIPEMD160;
class RIPEMD128;
class SHA256;
class SHA384;
class SHA512;
class Whirlpool;
// end of list

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

template <bool USE_HASH_ID> class PSSR_MEM_BaseWithHashId;
template<> class PSSR_MEM_BaseWithHashId<true> : public EMSA2HashIdLookup<PSSR_MEM_Base> {};
template<> class PSSR_MEM_BaseWithHashId<false> : public PSSR_MEM_Base {};

template <bool ALLOW_RECOVERY, class MGF=P1363_MGF1, int SALT_LEN=-1, int MIN_PAD_LEN=0, bool USE_HASH_ID=false>
class PSSR_MEM : public PSSR_MEM_BaseWithHashId<USE_HASH_ID>
{
	virtual bool AllowRecovery() const {return ALLOW_RECOVERY;}
	virtual unsigned int SaltLen(unsigned int hashLen) const {return SALT_LEN < 0 ? hashLen : SALT_LEN;}
	virtual unsigned int MinPadLen(unsigned int hashLen) const {return MIN_PAD_LEN < 0 ? hashLen : MIN_PAD_LEN;}
	virtual const MaskGeneratingFunction & GetMGF() const {static MGF mgf; return mgf;}

public:
	static std::string StaticAlgorithmName() {return std::string(ALLOW_RECOVERY ? "PSSR-" : "PSS-") + MGF::StaticAlgorithmName();}
};

//! <a href="http://www.weidai.com/scan-mirror/sig.html#sem_PSSR-MGF1">PSSR-MGF1</a>
struct PSSR : public SignatureStandard
{
	typedef PSSR_MEM<true> SignatureMessageEncodingMethod;
};

//! <a href="http://www.weidai.com/scan-mirror/sig.html#sem_PSS-MGF1">PSS-MGF1</a>
struct PSS : public SignatureStandard
{
	typedef PSSR_MEM<false> SignatureMessageEncodingMethod;
};

NAMESPACE_END

#endif
