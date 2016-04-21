// chacha.h - written and placed in the public domain by Jeffrey Walton.
//            Copyright assigned to the Crypto++ project.
//            Based on Wei Dai's Salsa20 and Bernstein's reference ChaCha 
//            family implementation at http://cr.yp.to/chacha.html.

//! \file chacha.h
//! \brief Classes for the ChaCha family of stream ciphers

#ifndef CRYPTOPP_CHACHA_H
#define CRYPTOPP_CHACHA_H

#include "strciphr.h"
#include "secblock.h"
#include "algparam.h" // for MakeParameters()

NAMESPACE_BEGIN(CryptoPP)

//! \class ChaCha_Info
//! \brief ChaCha stream cipher information
struct ChaCha_Info : public VariableKeyLength<32, 16, 32, 16, SimpleKeyingInterface::UNIQUE_IV, 8>
{
	static const char *StaticAlgorithmName() {static const std::string name = "ChaCha"; return name.c_str();}
};

//! \class ChaChaFR_Info
//! \brief ChaCha stream cipher information for compile-time fixed rounds
template<unsigned int R>
struct ChaChaFR_Info : public VariableKeyLength<32, 16, 32, 16, SimpleKeyingInterface::UNIQUE_IV, 8>, public FixedRounds<R>
{
	static const char *StaticAlgorithmName() { static const std::string name = "ChaCha" + IntToString(R); return name.c_str(); }
};

//! \class ChaCha_Policy
//! \brief ChaCha stream cipher implementation
class CRYPTOPP_NO_VTABLE ChaCha_Policy : public AdditiveCipherConcretePolicy<word32, 16>
{
protected:
	void CipherSetKey(const NameValuePairs &params, const byte *key, size_t length);
	void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount);
	void CipherResynchronize(byte *keystreamBuffer, const byte *IV, size_t length);
	bool CipherIsRandomAccess() const {return false;} // TODO
	void SeekToIteration(lword iterationCount);
	unsigned int GetAlignment() const;
	unsigned int GetOptimalBlockSize() const;

	FixedSizeAlignedSecBlock<word32, 16> m_state;
	unsigned int m_rounds;
};

//! \class ChaCha_Policy
//! \brief ChaCha stream cipher implementation for fixed rounds
template<unsigned int R>
class CRYPTOPP_NO_VTABLE ChaChaFR_Policy : public ChaCha_Policy
{
protected:
	CRYPTOPP_CONSTANT(ROUNDS = FixedRounds<R>::ROUNDS);

	void CipherSetKey(const NameValuePairs &params, const byte *key, size_t length) { CRYPTOPP_UNUSED(params); ChaCha_Policy::CipherSetKey(MakeParameters(Name::Rounds(), ROUNDS), key, length); }
};

//! \class ChaCha8
//! \brief ChaCha8 stream cipher
//! \sa <a href="http://cr.yp.to/chacha/chacha-20080128.pdf">ChaCha, a variant of Salsa20</a> (2008.01.28).
struct ChaCha8 : public ChaChaFR_Info<8>, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<ChaChaFR_Policy<8>, AdditiveCipherTemplate<> >, ChaChaFR_Info<8> > Encryption;
	typedef Encryption Decryption;
};

//! \class ChaCha12
//! \brief ChaCha12 stream cipher
//! \sa <a href="http://cr.yp.to/chacha/chacha-20080128.pdf">ChaCha, a variant of Salsa20</a> (2008.01.28).
struct ChaCha12 : public ChaChaFR_Info<12>, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<ChaChaFR_Policy<12>, AdditiveCipherTemplate<> >, ChaChaFR_Info<12> > Encryption;
	typedef Encryption Decryption;
};

//! \class ChaCha20
//! \brief ChaCha20 stream cipher
//! \sa <a href="http://cr.yp.to/chacha/chacha-20080128.pdf">ChaCha, a variant of Salsa20</a> (2008.01.28).
struct ChaCha20 : public ChaChaFR_Info<20>, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<ChaChaFR_Policy<20>, AdditiveCipherTemplate<> >, ChaChaFR_Info<20> > Encryption;
	typedef Encryption Decryption;
};

//! \class ChaCha
//! \brief ChaCha stream cipher
//! \sa <a href="http://cr.yp.to/chacha/chacha-20080128.pdf">ChaCha, a variant of Salsa20</a> (2008.01.28).
struct ChaCha : public ChaCha_Info, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<ChaCha_Policy, AdditiveCipherTemplate<> >, ChaCha_Info > Encryption;
	typedef Encryption Decryption;
};

NAMESPACE_END

#endif  // CRYPTOPP_CHACHA_H
