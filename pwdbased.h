// pwdbased.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_PWDBASED_H
#define CRYPTOPP_PWDBASED_H

#include "cryptlib.h"
#include "hmac.h"

NAMESPACE_BEGIN(CryptoPP)

class PasswordBasedKeyDerivationFunction
{
public:
	virtual unsigned int MaxDerivedKeyLength() const =0;
	virtual void GeneralDeriveKey(byte *derived, unsigned int derivedLen, byte purpose, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations) const =0;
};

//! PBKDF1 from PKCS #5, T should be a HashTransformation class
template <class T>
class PKCS5_PBKDF1 : public PasswordBasedKeyDerivationFunction
{
public:
	unsigned int MaxDerivedKeyLength() const {return T::DIGESTSIZE;}
	// PKCS #5 says PBKDF1 should only take 8-byte salts. This implementation allows salts of any length.
	void GeneralDeriveKey(byte *derived, unsigned int derivedLen, byte ignored, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations) const
		{DeriveKey(derived, derivedLen, password, passwordLen, salt, saltLen, iterations);}
	void DeriveKey(byte *derived, unsigned int derivedLen, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen=8, unsigned int iterations=1000) const;
};

//! PBKDF2 from PKCS #5, T should be a HashTransformation class
template <class T>
class PKCS5_PBKDF2_HMAC : public PasswordBasedKeyDerivationFunction
{
public:
	unsigned int MaxDerivedKeyLength() const {return 0xffffffffU;}	// should multiply by T::DIGESTSIZE, but gets overflow that way
	void GeneralDeriveKey(byte *derived, unsigned int derivedLen, byte ignored, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations) const
		{DeriveKey(derived, derivedLen, password, passwordLen, salt, saltLen, iterations);}
	void DeriveKey(byte *derived, unsigned int derivedLen, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations=1000) const;
};

/*
class PBKDF2Params
{
public:
	SecByteBlock m_salt;
	unsigned int m_interationCount;
	ASNOptional<ASNUnsignedWrapper<word32> > m_keyLength;
};
*/

template <class T>
void PKCS5_PBKDF1<T>::DeriveKey(byte *derived, unsigned int derivedLen, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations) const
{
	assert(derivedLen <= MaxDerivedKeyLength());
	assert(iterations > 0);

	T hash;
	hash.Update(password, passwordLen);
	hash.Update(salt, saltLen);

	SecByteBlock buffer(hash.DigestSize());
	hash.Final(buffer);

	for (unsigned int i=1; i<iterations; i++)
		hash.CalculateDigest(buffer, buffer, buffer.size());

	memcpy(derived, buffer, derivedLen);
}

template <class T>
void PKCS5_PBKDF2_HMAC<T>::DeriveKey(byte *derived, unsigned int derivedLen, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations) const
{
	assert(derivedLen <= MaxDerivedKeyLength());
	assert(iterations > 0);

	HMAC<T> hmac(password, passwordLen);
	SecByteBlock buffer(hmac.DigestSize());

	unsigned int i=1;
	while (derivedLen > 0)
	{
		hmac.Update(salt, saltLen);
		unsigned int j;
		for (j=0; j<4; j++)
		{
			byte b = i >> ((3-j)*8);
			hmac.Update(&b, 1);
		}
		hmac.Final(buffer);

		unsigned int segmentLen = STDMIN(derivedLen, (unsigned int)buffer.size());
		memcpy(derived, buffer, segmentLen);

		for (j=1; j<iterations; j++)
		{
			hmac.CalculateDigest(buffer, buffer, buffer.size());
			xorbuf(derived, buffer, segmentLen);
		}

		derived += segmentLen;
		derivedLen -= segmentLen;
		i++;
	}
}

//! PBKDF from PKCS #12, appendix B, T should be a HashTransformation class
template <class T>
class PKCS12_PBKDF : public PasswordBasedKeyDerivationFunction
{
public:
	unsigned int MaxDerivedKeyLength() const {return UINT_MAX;}
	void GeneralDeriveKey(byte *derived, unsigned int derivedLen, byte purpose, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations) const
		{DeriveKey(derived, derivedLen, purpose, password, passwordLen, salt, saltLen, iterations);}
	void DeriveKey(byte *derived, unsigned int derivedLen, byte ID, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations=1000) const;
};

template <class T>
void PKCS12_PBKDF<T>::DeriveKey(byte *derived, unsigned int derivedLen, byte ID, const byte *password, unsigned int passwordLen, const byte *salt, unsigned int saltLen, unsigned int iterations) const
{
	assert(derivedLen <= MaxDerivedKeyLength());
	assert(iterations > 0);

	const unsigned int v = T::BLOCKSIZE;	// v is in bytes rather than bits as in PKCS #12
	const unsigned int DLen = v, SLen = RoundUpToMultipleOf(saltLen, v);
	const unsigned int PLen = RoundUpToMultipleOf(passwordLen, v), ILen = SLen + PLen;
	SecByteBlock buffer(DLen + SLen + PLen);
	byte *D = buffer, *S = buffer+DLen, *P = buffer+DLen+SLen, *I = S;

	memset(D, ID, DLen);
	unsigned int i;
	for (i=0; i<SLen; i++)
		S[i] = salt[i % saltLen];
	for (i=0; i<PLen; i++)
		P[i] = password[i % passwordLen];


	T hash;
	SecByteBlock Ai(T::DIGESTSIZE), B(v);

	while (derivedLen > 0)
	{
		hash.CalculateDigest(Ai, buffer, buffer.size());
		for (i=1; i<iterations; i++)
			hash.CalculateDigest(Ai, Ai, Ai.size());
		for (i=0; i<B.size(); i++)
			B[i] = Ai[i % Ai.size()];

		Integer B1(B, B.size());
		++B1;
		for (i=0; i<ILen; i+=v)
			(Integer(I+i, v) + B1).Encode(I+i, v);

		unsigned int segmentLen = STDMIN(derivedLen, (unsigned int)Ai.size());
		memcpy(derived, Ai, segmentLen);
		derived += segmentLen;
		derivedLen -= segmentLen;
	}
}

NAMESPACE_END

#endif
