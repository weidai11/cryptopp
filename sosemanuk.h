// sosemanuk.h - written and placed in the public domain by Wei Dai

//! \file sosemanuk.h
//! \brief Classes for Sosemanuk stream cipher
//! \since Crypto++ 5.5

#ifndef CRYPTOPP_SOSEMANUK_H
#define CRYPTOPP_SOSEMANUK_H

#include "strciphr.h"
#include "secblock.h"

// Clang due to "Inline assembly operands don't work with .intel_syntax"
//   https://llvm.org/bugs/show_bug.cgi?id=24232
#if CRYPTOPP_BOOL_X32 || defined(CRYPTOPP_DISABLE_INTEL_ASM)
# define CRYPTOPP_DISABLE_SOSEMANUK_ASM
#endif

NAMESPACE_BEGIN(CryptoPP)

//! \class SosemanukInfo
//! \brief Sosemanuk stream cipher information
	//! \since Crypto++ 5.5
struct SosemanukInfo : public VariableKeyLength<16, 1, 32, 1, SimpleKeyingInterface::UNIQUE_IV, 16>
{
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "Sosemanuk";}
};

//! \class SosemanukPolicy
//! \brief Sosemanuk stream cipher implementation
//! \since Crypto++ 5.5
class SosemanukPolicy : public AdditiveCipherConcretePolicy<word32, 20>, public SosemanukInfo
{
protected:
	void CipherSetKey(const NameValuePairs &params, const byte *key, size_t length);
	void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount);
	void CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length);
	bool CipherIsRandomAccess() const {return false;}
#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64) && !defined(CRYPTOPP_DISABLE_SOSEMANUK_ASM)
	unsigned int GetAlignment() const;
	unsigned int GetOptimalBlockSize() const;
#endif

	FixedSizeSecBlock<word32, 25*4> m_key;
	FixedSizeAlignedSecBlock<word32, 12> m_state;
};

//! \class Sosemanuk
//! \brief Sosemanuk stream cipher
//! \details is a stream cipher developed by Come Berbain, Olivier Billet, Anne Canteaut, Nicolas Courtois,
//!   Henri Gilbert, Louis Goubin, Aline Gouget, Louis Granboulan, Cédric Lauradoux, Marine Minier, Thomas
//!   Pornin and Hervé Sibert. Sosemanuk is one of the final four Profile 1 (software) ciphers selected for
//!   the eSTREAM Portfolio.
//! \sa <a href="http://www.cryptolounge.org/wiki/Sosemanuk">Sosemanuk</a>
//! \since Crypto++ 5.5
struct Sosemanuk : public SosemanukInfo, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<SosemanukPolicy, AdditiveCipherTemplate<> >, SosemanukInfo> Encryption;
	typedef Encryption Decryption;
};

NAMESPACE_END

#endif
