#ifndef CRYPTOPP_WAKE_H
#define CRYPTOPP_WAKE_H

#include "seckey.h"
#include "secblock.h"
#include "strciphr.h"

NAMESPACE_BEGIN(CryptoPP)

template <class B = BigEndian>
struct WAKE_Info : public FixedKeyLength<32>
{
	static const char *StaticAlgorithmName() {return B::ToEnum() == LITTLE_ENDIAN_ORDER ? "WAKE-CFB-LE" : "WAKE-CFB-BE";}
};

class WAKE_Base
{
protected:
	word32 M(word32 x, word32 y);
	void GenKey(word32 k0, word32 k1, word32 k2, word32 k3);

	word32 t[257];
	word32 r3, r4, r5, r6;
};

template <class B = BigEndian>
class WAKE_Policy : public WAKE_Info<B>
				, public CFB_CipherConcretePolicy<word32, 1>
				, public AdditiveCipherConcretePolicy<word32, 1, 64>
				, protected WAKE_Base
{
protected:
	void CipherSetKey(const NameValuePairs &params, const byte *key, unsigned int length);
	// CFB
	byte * GetRegisterBegin() {return (byte *)&r6;}
	void Iterate(byte *output, const byte *input, CipherDir dir, unsigned int iterationCount);
	// OFB
	void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, unsigned int iterationCount);
	bool IsRandomAccess() const {return false;}
};

//! <a href="http://www.weidai.com/scan-mirror/cs.html#WAKE-CFB-BE">WAKE-CFB-BE</a>
template <class B = BigEndian>
struct WAKE_CFB : public WAKE_Info<B>, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinalTemplate<ConcretePolicyHolder<WAKE_Policy<B>, CFB_EncryptionTemplate<> > > Encryption;
	typedef SymmetricCipherFinalTemplate<ConcretePolicyHolder<WAKE_Policy<B>, CFB_DecryptionTemplate<> > > Decryption;
};

//! WAKE-OFB
template <class B = BigEndian>
struct WAKE_OFB : public WAKE_Info<B>, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinalTemplate<ConcretePolicyHolder<WAKE_Policy<B>, AdditiveCipherTemplate<> > > Encryption;
	typedef Encryption Decryption;
};

/*
template <class B = BigEndian>
class WAKE_ROFB_Policy : public WAKE_Policy<B>
{
protected:
	void Iterate(KeystreamOperation operation, byte *output, const byte *input, unsigned int iterationCount);
};

template <class B = BigEndian>
struct WAKE_ROFB : public WAKE_Info<B>
{
	typedef SymmetricCipherTemplate<ConcretePolicyHolder<AdditiveCipherTemplate<>, WAKE_ROFB_Policy<B> > > Encryption;
	typedef Encryption Decryption;
};
*/

NAMESPACE_END

#endif
