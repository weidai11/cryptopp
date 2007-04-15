#ifndef CRYPTOPP_WAKE_H
#define CRYPTOPP_WAKE_H

#include "seckey.h"
#include "secblock.h"
#include "strciphr.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
template <class B = BigEndian>
struct WAKE_CFB_Info : public FixedKeyLength<32>
{
	static const char *StaticAlgorithmName() {return B::ToEnum() == LITTLE_ENDIAN_ORDER ? "WAKE-CFB-LE" : "WAKE-CFB-BE";}
};

//! _
template <class B = BigEndian>
struct WAKE_OFB_Info : public FixedKeyLength<32>
{
	static const char *StaticAlgorithmName() {return B::ToEnum() == LITTLE_ENDIAN_ORDER ? "WAKE-OFB-LE" : "WAKE-OFB-BE";}
};

class CRYPTOPP_NO_VTABLE WAKE_Base
{
protected:
	word32 M(word32 x, word32 y);
	void GenKey(word32 k0, word32 k1, word32 k2, word32 k3);

	word32 t[257];
	word32 r3, r4, r5, r6;
};

template <class B = BigEndian>
class CRYPTOPP_NO_VTABLE WAKE_Policy
				: public CFB_CipherConcretePolicy<word32, 1>
				, public AdditiveCipherConcretePolicy<word32, 1, 64>
				, protected WAKE_Base
{
protected:
	void CipherSetKey(const NameValuePairs &params, const byte *key, size_t length);
	// CFB
	byte * GetRegisterBegin() {return (byte *)&r6;}
	void Iterate(byte *output, const byte *input, CipherDir dir, size_t iterationCount);
	// OFB
	void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount);
	bool IsRandomAccess() const {return false;}
};

namespace Weak {
//! <a href="http://www.cryptolounge.org/wiki/WAKE">WAKE-CFB-BE</a>
template <class B = BigEndian>
struct WAKE_CFB : public WAKE_CFB_Info<B>, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<WAKE_Policy<B>, CFB_EncryptionTemplate<> >,  WAKE_CFB_Info<B> > Encryption;
	typedef SymmetricCipherFinal<ConcretePolicyHolder<WAKE_Policy<B>, CFB_DecryptionTemplate<> >,  WAKE_CFB_Info<B> > Decryption;
};
}

//! WAKE-OFB
template <class B = BigEndian>
struct WAKE_OFB : public WAKE_OFB_Info<B>, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<WAKE_Policy<B>, AdditiveCipherTemplate<> >,  WAKE_OFB_Info<B> > Encryption;
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
