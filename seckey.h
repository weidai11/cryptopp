// seckey.h - written and placed in the public domain by Wei Dai

// This file contains helper classes/functions for implementing secret key algorithms.

#ifndef CRYPTOPP_SECKEY_H
#define CRYPTOPP_SECKEY_H

#include "cryptlib.h"
#include "misc.h"
#include "simple.h"

NAMESPACE_BEGIN(CryptoPP)

inline CipherDir ReverseCipherDir(CipherDir dir)
{
	return (dir == ENCRYPTION) ? DECRYPTION : ENCRYPTION;
}

//! to be inherited by block ciphers with fixed block size
template <unsigned int N>
class FixedBlockSize
{
public:
	enum {BLOCKSIZE = N};
};

// ************** rounds ***************

//! to be inherited by ciphers with fixed number of rounds
template <unsigned int R>
class FixedRounds
{
public:
	enum {ROUNDS = R};

protected:
	template <class T>
	static inline void CheckedSetKey(T *obj, CipherDir dir, const byte *key, unsigned int length, const NameValuePairs &param)
	{
		obj->ThrowIfInvalidKeyLength(length);
		int rounds = param.GetIntValueWithDefault("Rounds", ROUNDS);
		if (rounds != ROUNDS)
			throw InvalidRounds(obj->StaticAlgorithmName(), rounds);
		obj->UncheckedSetKey(dir, key, length);
	}
};

//! to be inherited by ciphers with variable number of rounds
template <unsigned int D, unsigned int N=1, unsigned int M=INT_MAX>		// use INT_MAX here because enums are treated as signed ints
class VariableRounds
{
public:
	enum {DEFAULT_ROUNDS = D, MIN_ROUNDS = N, MAX_ROUNDS = M};
	static unsigned int StaticGetDefaultRounds(unsigned int keylength) {return DEFAULT_ROUNDS;}

protected:
	static inline void AssertValidRounds(unsigned int rounds)
	{
		assert(rounds >= (unsigned int)MIN_ROUNDS && rounds <= (unsigned int)MAX_ROUNDS);
	}

	template <class T>
	static inline void CheckedSetKey(T *obj, CipherDir dir, const byte *key, unsigned int length, const NameValuePairs &param)
	{
		obj->ThrowIfInvalidKeyLength(length);
		int rounds = param.GetIntValueWithDefault("Rounds", obj->StaticGetDefaultRounds(length));
		if (rounds < (int)MIN_ROUNDS || rounds > (int)MAX_ROUNDS)
			throw InvalidRounds(obj->AlgorithmName(), rounds);
		obj->UncheckedSetKey(dir, key, length, rounds);
	}
};

// ************** key length ***************

//! to be inherited by keyed algorithms with fixed key length
template <unsigned int N, unsigned int IV_REQ = SimpleKeyingInterface::NOT_RESYNCHRONIZABLE>
class FixedKeyLength
{
public:
	enum {KEYLENGTH=N, MIN_KEYLENGTH=N, MAX_KEYLENGTH=N, DEFAULT_KEYLENGTH=N};
	enum {IV_REQUIREMENT = IV_REQ};
	static unsigned int CRYPTOPP_API StaticGetValidKeyLength(unsigned int) {return KEYLENGTH;}
};

/// support query of variable key length, template parameters are default, min, max, multiple (default multiple 1)
template <unsigned int D, unsigned int N, unsigned int M, unsigned int Q = 1, unsigned int IV_REQ = SimpleKeyingInterface::NOT_RESYNCHRONIZABLE>
class VariableKeyLength
{
	// make these private to avoid Doxygen documenting them in all derived classes
	CRYPTOPP_COMPILE_ASSERT(Q > 0);
	CRYPTOPP_COMPILE_ASSERT(N % Q == 0);
	CRYPTOPP_COMPILE_ASSERT(M % Q == 0);
	CRYPTOPP_COMPILE_ASSERT(N < M);
	CRYPTOPP_COMPILE_ASSERT(D >= N && M >= D);

public:
	enum {MIN_KEYLENGTH=N, MAX_KEYLENGTH=M, DEFAULT_KEYLENGTH=D, KEYLENGTH_MULTIPLE=Q};
	enum {IV_REQUIREMENT = IV_REQ};
	static unsigned int CRYPTOPP_API StaticGetValidKeyLength(unsigned int n)
	{
		if (n < (unsigned int)MIN_KEYLENGTH)
			return MIN_KEYLENGTH;
		else if (n > (unsigned int)MAX_KEYLENGTH)
			return (unsigned int)MAX_KEYLENGTH;
		else
		{
			n += KEYLENGTH_MULTIPLE-1;
			return n - n%KEYLENGTH_MULTIPLE;
		}
	}
};

/// support query of key length that's the same as another class
template <class T>
class SameKeyLengthAs
{
public:
	enum {MIN_KEYLENGTH=T::MIN_KEYLENGTH, MAX_KEYLENGTH=T::MAX_KEYLENGTH, DEFAULT_KEYLENGTH=T::DEFAULT_KEYLENGTH};
	enum {IV_REQUIREMENT = T::IV_REQUIREMENT};
	static unsigned int CRYPTOPP_API StaticGetValidKeyLength(unsigned int keylength)
		{return T::StaticGetValidKeyLength(keylength);}
};

// ************** implementation helper for SimpledKeyed ***************

template <class T>
static inline void CheckedSetKey(T *obj, Empty empty, const byte *key, unsigned int length, const NameValuePairs &param)
{
	obj->ThrowIfInvalidKeyLength(length);
	obj->UncheckedSetKey(key, length);
}

template <class T>
static inline void CheckedSetKey(T *obj, CipherDir dir, const byte *key, unsigned int length, const NameValuePairs &param)
{
	obj->ThrowIfInvalidKeyLength(length);
	obj->UncheckedSetKey(dir, key, length);
}

//! _
template <class BASE, class INFO = BASE>
class CRYPTOPP_NO_VTABLE SimpleKeyingInterfaceImpl : public BASE
{
public:
	unsigned int MinKeyLength() const {return INFO::MIN_KEYLENGTH;}
	unsigned int MaxKeyLength() const {return (unsigned int)INFO::MAX_KEYLENGTH;}
	unsigned int DefaultKeyLength() const {return INFO::DEFAULT_KEYLENGTH;}
	unsigned int GetValidKeyLength(unsigned int n) const {return INFO::StaticGetValidKeyLength(n);}
	typename BASE::IV_Requirement IVRequirement() const {return (typename BASE::IV_Requirement)INFO::IV_REQUIREMENT;}

protected:
	void AssertValidKeyLength(unsigned int length) {assert(GetValidKeyLength(length) == length);}
};

template <class INFO, class BASE = BlockCipher>
class CRYPTOPP_NO_VTABLE BlockCipherImpl : public AlgorithmImpl<SimpleKeyingInterfaceImpl<TwoBases<BASE, INFO> > >
{
public:
	unsigned int BlockSize() const {return this->BLOCKSIZE;}
};

//! _
template <CipherDir DIR, class BASE>
class BlockCipherFinal : public ClonableImpl<BlockCipherFinal<DIR, BASE>, BASE>
{
public:
 	BlockCipherFinal() {}
	BlockCipherFinal(const byte *key)
		{SetKey(key, this->DEFAULT_KEYLENGTH);}
	BlockCipherFinal(const byte *key, unsigned int length)
		{SetKey(key, length);}
	BlockCipherFinal(const byte *key, unsigned int length, unsigned int rounds)
		{this->SetKeyWithRounds(key, length, rounds);}

	bool IsForwardTransformation() const {return DIR == ENCRYPTION;}

	void SetKey(const byte *key, unsigned int length, const NameValuePairs &param = g_nullNameValuePairs)
	{
		CheckedSetKey(this, DIR, key, length, param);
	}
};

//! _
template <class BASE, class INFO = BASE>
class MessageAuthenticationCodeImpl : public AlgorithmImpl<SimpleKeyingInterfaceImpl<BASE, INFO>, INFO>
{
public:
	void SetKey(const byte *key, unsigned int length, const NameValuePairs &params = g_nullNameValuePairs)
	{
		CheckedSetKey(this, Empty(), key, length, params);
	}
};

//! _
template <class BASE>
class MessageAuthenticationCodeFinal : public ClonableImpl<MessageAuthenticationCodeFinal<BASE>, MessageAuthenticationCodeImpl<BASE> >
{
public:
 	MessageAuthenticationCodeFinal() {}
	MessageAuthenticationCodeFinal(const byte *key)
		{SetKey(key, this->DEFAULT_KEYLENGTH);}
	MessageAuthenticationCodeFinal(const byte *key, unsigned int length)
		{this->SetKey(key, length);}
};

// ************** documentation ***************

//! These objects usually should not be used directly. See CipherModeDocumentation instead.
/*! Each class derived from this one defines two types, Encryption and Decryption, 
	both of which implement the BlockCipher interface. */
struct BlockCipherDocumentation
{
	//! implements the BlockCipher interface
	typedef BlockCipher Encryption;
	//! implements the BlockCipher interface
	typedef BlockCipher Decryption;
};

/*! \brief Each class derived from this one defines two types, Encryption and Decryption, 
	both of which implement the SymmetricCipher interface. Two types of classes derive
	from this class: stream ciphers and block cipher modes. Stream ciphers can be used
	alone, cipher mode classes need to be used with a block cipher. See CipherModeDocumentation
	for more for information about using cipher modes and block ciphers. */
struct SymmetricCipherDocumentation
{
	//! implements the SymmetricCipher interface
	typedef SymmetricCipher Encryption;
	//! implements the SymmetricCipher interface
	typedef SymmetricCipher Decryption;
};

NAMESPACE_END

#endif
