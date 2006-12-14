// salsa.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_SALSA_H
#define CRYPTOPP_SALSA_H

#include "strciphr.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
struct Salsa20_Info : public VariableKeyLength<32, 16, 32, 16, SimpleKeyingInterface::STRUCTURED_IV, 8>
{
	static const char *StaticAlgorithmName() {return "Salsa20";}
};

class CRYPTOPP_NO_VTABLE Salsa20_Policy : public AdditiveCipherConcretePolicy<word32, 16>, public Salsa20_Info
{
protected:
	void CipherSetKey(const NameValuePairs &params, const byte *key, size_t length);
	void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount);
	void CipherGetNextIV(byte *IV);
	void CipherResynchronize(byte *keystreamBuffer, const byte *IV);
	bool IsRandomAccess() const {return true;}
	void SeekToIteration(lword iterationCount);

private:
	int m_rounds;
	FixedSizeSecBlock<word32, 16> m_state;
};

//! Salsa20, variable rounds: 8, 12 or 20 (default 20)
struct Salsa20 : public Salsa20_Info, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<Salsa20_Policy, AdditiveCipherTemplate<> >, Salsa20_Info> Encryption;
	typedef Encryption Decryption;
};

NAMESPACE_END

#endif
