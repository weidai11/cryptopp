/*! \file
 	This file contains helper classes for implementing stream ciphers.

	All this infrastructure may look very complex compared to what's in Crypto++ 4.x,
	but stream ciphers implementations now support a lot of new functionality,
	including better performance (minimizing copying), resetting of keys and IVs, and methods to
	query which features are supported by a cipher.

	Here's an explanation of these classes. The word "policy" is used here to mean a class with a
	set of methods that must be implemented by individual stream cipher implementations.
	This is usually much simpler than the full stream cipher API, which is implemented by
	either AdditiveCipherTemplate or CFB_CipherTemplate using the policy. So for example, an
	implementation of SEAL only needs to implement the AdditiveCipherAbstractPolicy interface
	(since it's an additive cipher, i.e., it xors a keystream into the plaintext).
	See this line in seal.h:

	typedef SymmetricCipherFinal\<ConcretePolicyHolder\<SEAL_Policy\<B\>, AdditiveCipherTemplate\<\> \> \> Encryption;

	AdditiveCipherTemplate and CFB_CipherTemplate are designed so that they don't need
	to take a policy class as a template parameter (although this is allowed), so that
	their code is not duplicated for each new cipher. Instead they each
	get a reference to an abstract policy interface by calling AccessPolicy() on itself, so
	AccessPolicy() must be overriden to return the actual policy reference. This is done
	by the ConceretePolicyHolder class. Finally, SymmetricCipherFinal implements the constructors and
	other functions that must be implemented by the most derived class.
*/

#ifndef CRYPTOPP_STRCIPHR_H
#define CRYPTOPP_STRCIPHR_H

#include "seckey.h"
#include "secblock.h"
#include "argnames.h"

NAMESPACE_BEGIN(CryptoPP)

template <class POLICY_INTERFACE, class BASE = Empty>
class CRYPTOPP_NO_VTABLE AbstractPolicyHolder : public BASE
{
public:
	typedef POLICY_INTERFACE PolicyInterface;

protected:
	virtual const POLICY_INTERFACE & GetPolicy() const =0;
	virtual POLICY_INTERFACE & AccessPolicy() =0;
};

template <class POLICY, class BASE, class POLICY_INTERFACE = CPP_TYPENAME BASE::PolicyInterface>
class ConcretePolicyHolder : public BASE, protected POLICY
{
protected:
	const POLICY_INTERFACE & GetPolicy() const {return *this;}
	POLICY_INTERFACE & AccessPolicy() {return *this;}
};

enum KeystreamOperation {WRITE_KEYSTREAM, XOR_KEYSTREAM, XOR_KEYSTREAM_INPLACE};

struct CRYPTOPP_DLL CRYPTOPP_NO_VTABLE AdditiveCipherAbstractPolicy
{
	virtual unsigned int GetAlignment() const =0;
	virtual unsigned int GetBytesPerIteration() const =0;
	virtual unsigned int GetIterationsToBuffer() const =0;
	virtual void WriteKeystream(byte *keystreamBuffer, unsigned int iterationCount) =0;
	virtual bool CanOperateKeystream() const {return false;}
	virtual void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, unsigned int iterationCount) {assert(false);}
	virtual void CipherSetKey(const NameValuePairs &params, const byte *key, unsigned int length) =0;
	virtual void CipherResynchronize(byte *keystreamBuffer, const byte *iv) {throw NotImplemented("StreamTransformation: this object doesn't support resynchronization");}
	virtual bool IsRandomAccess() const =0;
	virtual void SeekToIteration(lword iterationCount) {assert(!IsRandomAccess()); throw NotImplemented("StreamTransformation: this object doesn't support random access");}
};

template <typename WT, unsigned int W, unsigned int X = 1, class BASE = AdditiveCipherAbstractPolicy>
struct CRYPTOPP_NO_VTABLE AdditiveCipherConcretePolicy : public BASE
{
	typedef WT WordType;

	unsigned int GetAlignment() const {return sizeof(WordType);}
	unsigned int GetBytesPerIteration() const {return sizeof(WordType) * W;}
	unsigned int GetIterationsToBuffer() const {return X;}
	void WriteKeystream(byte *buffer, unsigned int iterationCount)
		{OperateKeystream(WRITE_KEYSTREAM, buffer, NULL, iterationCount);}
	bool CanOperateKeystream() const {return true;}
	virtual void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, unsigned int iterationCount) =0;

	template <class B>
	struct KeystreamOutput
	{
		KeystreamOutput(KeystreamOperation operation, byte *output, const byte *input)
			: m_operation(operation), m_output(output), m_input(input) {}

		inline KeystreamOutput & operator()(WordType keystreamWord)
		{
			assert(IsAligned<WordType>(m_input));
			assert(IsAligned<WordType>(m_output));

			if (!NativeByteOrderIs(B::ToEnum()))
				keystreamWord = ByteReverse(keystreamWord);

			if (m_operation == WRITE_KEYSTREAM)
				*(WordType*)m_output = keystreamWord;
			else if (m_operation == XOR_KEYSTREAM)
			{
				*(WordType*)m_output = keystreamWord ^ *(WordType*)m_input;
				m_input += sizeof(WordType);
			}
			else if (m_operation == XOR_KEYSTREAM_INPLACE)
				*(WordType*)m_output ^= keystreamWord;

			m_output += sizeof(WordType);

			return *this;
		}

		KeystreamOperation m_operation;
		byte *m_output;
		const byte *m_input;
	};
};

template <class BASE = AbstractPolicyHolder<AdditiveCipherAbstractPolicy, TwoBases<SymmetricCipher, RandomNumberGenerator> > >
class CRYPTOPP_NO_VTABLE AdditiveCipherTemplate : public BASE
{
public:
    byte GenerateByte();
    void ProcessData(byte *outString, const byte *inString, unsigned int length);
	void Resynchronize(const byte *iv);
	unsigned int OptimalBlockSize() const {return this->GetPolicy().GetBytesPerIteration();}
	unsigned int GetOptimalNextBlockSize() const {return this->m_leftOver;}
	unsigned int OptimalDataAlignment() const {return this->GetPolicy().GetAlignment();}
	bool IsSelfInverting() const {return true;}
	bool IsForwardTransformation() const {return true;}
	bool IsRandomAccess() const {return this->GetPolicy().IsRandomAccess();}
	void Seek(lword position);

	typedef typename BASE::PolicyInterface PolicyInterface;

protected:
	void UncheckedSetKey(const NameValuePairs &params, const byte *key, unsigned int length, const byte *iv);

	unsigned int GetBufferByteSize(const PolicyInterface &policy) const {return policy.GetBytesPerIteration() * policy.GetIterationsToBuffer();}

	inline byte * KeystreamBufferBegin() {return this->m_buffer.data();}
	inline byte * KeystreamBufferEnd() {return (this->m_buffer.data() + this->m_buffer.size());}

	SecByteBlock m_buffer;
	unsigned int m_leftOver;
};

CRYPTOPP_DLL_TEMPLATE_CLASS TwoBases<SymmetricCipher, RandomNumberGenerator>;
CRYPTOPP_DLL_TEMPLATE_CLASS AbstractPolicyHolder<AdditiveCipherAbstractPolicy, TwoBases<SymmetricCipher, RandomNumberGenerator> >;
CRYPTOPP_DLL_TEMPLATE_CLASS AdditiveCipherTemplate<>;

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CFB_CipherAbstractPolicy
{
public:
	virtual unsigned int GetAlignment() const =0;
	virtual unsigned int GetBytesPerIteration() const =0;
	virtual byte * GetRegisterBegin() =0;
	virtual void TransformRegister() =0;
	virtual bool CanIterate() const {return false;}
	virtual void Iterate(byte *output, const byte *input, CipherDir dir, unsigned int iterationCount) {assert(false);}
	virtual void CipherSetKey(const NameValuePairs &params, const byte *key, unsigned int length) =0;
	virtual void CipherResynchronize(const byte *iv) {throw NotImplemented("StreamTransformation: this object doesn't support resynchronization");}
};

template <typename WT, unsigned int W, class BASE = CFB_CipherAbstractPolicy>
struct CRYPTOPP_NO_VTABLE CFB_CipherConcretePolicy : public BASE
{
	typedef WT WordType;

	unsigned int GetAlignment() const {return sizeof(WordType);}
	unsigned int GetBytesPerIteration() const {return sizeof(WordType) * W;}
	bool CanIterate() const {return true;}
	void TransformRegister() {this->Iterate(NULL, NULL, ENCRYPTION, 1);}

	template <class B>
	struct RegisterOutput
	{
		RegisterOutput(byte *output, const byte *input, CipherDir dir)
			: m_output(output), m_input(input), m_dir(dir) {}

		inline RegisterOutput& operator()(WordType &registerWord)
		{
			assert(IsAligned<WordType>(m_output));
			assert(IsAligned<WordType>(m_input));

			if (!NativeByteOrderIs(B::ToEnum()))
				registerWord = ByteReverse(registerWord);

			if (m_dir == ENCRYPTION)
			{
				if (m_input == NULL)
					assert(m_output == NULL);
				else
				{
					WordType ct = *(const WordType *)m_input ^ registerWord;
					registerWord = ct;
					*(WordType*)m_output = ct;
					m_input += sizeof(WordType);
					m_output += sizeof(WordType);
				}
			}
			else
			{
				WordType ct = *(const WordType *)m_input;
				*(WordType*)m_output = registerWord ^ ct;
				registerWord = ct;
				m_input += sizeof(WordType);
				m_output += sizeof(WordType);
			}

			// registerWord is left unreversed so it can be xor-ed with further input

			return *this;
		}

		byte *m_output;
		const byte *m_input;
		CipherDir m_dir;
	};
};

template <class BASE>
class CRYPTOPP_NO_VTABLE CFB_CipherTemplate : public BASE
{
public:
	void ProcessData(byte *outString, const byte *inString, unsigned int length);
	void Resynchronize(const byte *iv);
	unsigned int OptimalBlockSize() const {return this->GetPolicy().GetBytesPerIteration();}
	unsigned int GetOptimalNextBlockSize() const {return m_leftOver;}
	unsigned int OptimalDataAlignment() const {return this->GetPolicy().GetAlignment();}
	bool IsRandomAccess() const {return false;}
	bool IsSelfInverting() const {return false;}

	typedef typename BASE::PolicyInterface PolicyInterface;

protected:
	virtual void CombineMessageAndShiftRegister(byte *output, byte *reg, const byte *message, unsigned int length) =0;

	void UncheckedSetKey(const NameValuePairs &params, const byte *key, unsigned int length, const byte *iv);

	unsigned int m_leftOver;
};

template <class BASE = AbstractPolicyHolder<CFB_CipherAbstractPolicy, SymmetricCipher> >
class CRYPTOPP_NO_VTABLE CFB_EncryptionTemplate : public CFB_CipherTemplate<BASE>
{
	bool IsForwardTransformation() const {return true;}
	void CombineMessageAndShiftRegister(byte *output, byte *reg, const byte *message, unsigned int length);
};

template <class BASE = AbstractPolicyHolder<CFB_CipherAbstractPolicy, SymmetricCipher> >
class CRYPTOPP_NO_VTABLE CFB_DecryptionTemplate : public CFB_CipherTemplate<BASE>
{
	bool IsForwardTransformation() const {return false;}
	void CombineMessageAndShiftRegister(byte *output, byte *reg, const byte *message, unsigned int length);
};

template <class BASE>
class CFB_RequireFullDataBlocks : public BASE
{
public:
	unsigned int MandatoryBlockSize() const {return this->OptimalBlockSize();}
};

// for Darwin
CRYPTOPP_DLL_TEMPLATE_CLASS CFB_CipherTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy, SymmetricCipher> >;
CRYPTOPP_DLL_TEMPLATE_CLASS CFB_EncryptionTemplate<>;
CRYPTOPP_DLL_TEMPLATE_CLASS CFB_DecryptionTemplate<>;

//! _
template <class BASE, class INFO = BASE>
class SymmetricCipherFinal : public AlgorithmImpl<SimpleKeyingInterfaceImpl<BASE, INFO>, INFO>
{
public:
 	SymmetricCipherFinal() {}
	SymmetricCipherFinal(const byte *key)
		{SetKey(key, this->DEFAULT_KEYLENGTH);}
	SymmetricCipherFinal(const byte *key, unsigned int length)
		{SetKey(key, length);}
	SymmetricCipherFinal(const byte *key, unsigned int length, const byte *iv)
		{this->SetKeyWithIV(key, length, iv);}

	void SetKey(const byte *key, unsigned int length, const NameValuePairs &params = g_nullNameValuePairs)
	{
		this->ThrowIfInvalidKeyLength(length);
		this->UncheckedSetKey(params, key, length, this->GetIVAndThrowIfInvalid(params));
	}

	Clonable * Clone() const {return static_cast<SymmetricCipher *>(new SymmetricCipherFinal<BASE, INFO>(*this));}
};

template <class S>
void AdditiveCipherTemplate<S>::UncheckedSetKey(const NameValuePairs &params, const byte *key, unsigned int length, const byte *iv)
{
	PolicyInterface &policy = this->AccessPolicy();
	policy.CipherSetKey(params, key, length);
	m_leftOver = 0;
	m_buffer.New(GetBufferByteSize(policy));

	if (this->IsResynchronizable())
		policy.CipherResynchronize(m_buffer, iv);
}

template <class BASE>
void CFB_CipherTemplate<BASE>::UncheckedSetKey(const NameValuePairs &params, const byte *key, unsigned int length, const byte *iv)
{
	PolicyInterface &policy = this->AccessPolicy();
	policy.CipherSetKey(params, key, length);

	if (this->IsResynchronizable())
		policy.CipherResynchronize(iv);

	m_leftOver = policy.GetBytesPerIteration();
}

NAMESPACE_END

#endif
