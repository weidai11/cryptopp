// default.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "config.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4127 4189)
#endif

#include "cryptlib.h"
#include "filters.h"
#include "smartptr.h"
#include "default.h"
#include "queue.h"

#include <time.h>
#include <memory>

NAMESPACE_BEGIN(CryptoPP)

// The purpose of this function Mash() is to take an arbitrary length input
// string and *deterministicly* produce an arbitrary length output string such
// that (1) it looks random, (2) no information about the input is
// deducible from it, and (3) it contains as much entropy as it can hold, or
// the amount of entropy in the input string, whichever is smaller.

template <class H>
static void Mash(const byte *in, size_t inLen, byte *out, size_t outLen, int iterations)
{
	if (BytePrecision(outLen) > 2)
		throw InvalidArgument("Mash: output legnth too large");

	size_t bufSize = RoundUpToMultipleOf(outLen, (size_t)H::DIGESTSIZE);
	byte b[2];
	SecByteBlock buf(bufSize);
	SecByteBlock outBuf(bufSize);
	H hash;

	unsigned int i;
	for(i=0; i<outLen; i+=H::DIGESTSIZE)
	{
		b[0] = (byte) (i >> 8);
		b[1] = (byte) i;
		hash.Update(b, 2);
		hash.Update(in, inLen);
		hash.Final(outBuf+i);
	}

	while (iterations-- > 1)
	{
		memcpy(buf, outBuf, bufSize);
		for (i=0; i<bufSize; i+=H::DIGESTSIZE)
		{
			b[0] = (byte) (i >> 8);
			b[1] = (byte) i;
			hash.Update(b, 2);
			hash.Update(buf, bufSize);
			hash.Final(outBuf+i);
		}
	}

	memcpy(out, outBuf, outLen);
}

template <class BC, class H, class Info>
static void GenerateKeyIV(const byte *passphrase, size_t passphraseLength, const byte *salt, size_t saltLength, unsigned int iterations, byte *key, byte *IV)
{
	SecByteBlock temp(passphraseLength+saltLength);
	memcpy(temp, passphrase, passphraseLength);
	memcpy(temp+passphraseLength, salt, saltLength);
	SecByteBlock keyIV(Info::KEYLENGTH+Info::BLOCKSIZE);
	Mash<H>(temp, passphraseLength + saltLength, keyIV, Info::KEYLENGTH+Info::BLOCKSIZE, iterations);
	memcpy(key, keyIV, Info::KEYLENGTH);
	memcpy(IV, keyIV+Info::KEYLENGTH, Info::BLOCKSIZE);
}

// ********************************************************

template <class BC, class H, class Info>
DataEncryptor<BC,H,Info>::DataEncryptor(const char *passphrase, BufferedTransformation *attachment)
	: ProxyFilter(NULL, 0, 0, attachment), m_passphrase((const byte *)passphrase, strlen(passphrase))
{
	CRYPTOPP_COMPILE_ASSERT(SALTLENGTH <= DIGESTSIZE);
	CRYPTOPP_COMPILE_ASSERT(BLOCKSIZE <= DIGESTSIZE);
}

template <class BC, class H, class Info>
DataEncryptor<BC,H,Info>::DataEncryptor(const byte *passphrase, size_t passphraseLength, BufferedTransformation *attachment)
	: ProxyFilter(NULL, 0, 0, attachment), m_passphrase(passphrase, passphraseLength)
{
	CRYPTOPP_COMPILE_ASSERT(SALTLENGTH <= DIGESTSIZE);
	CRYPTOPP_COMPILE_ASSERT(BLOCKSIZE <= DIGESTSIZE);
}

template <class BC, class H, class Info>
void DataEncryptor<BC,H,Info>::FirstPut(const byte *)
{
	SecByteBlock salt(DIGESTSIZE), keyCheck(DIGESTSIZE);
	H hash;

	// use hash(passphrase | time | clock) as salt
	hash.Update(m_passphrase, m_passphrase.size());
	time_t t=time(0);
	hash.Update((byte *)&t, sizeof(t));
	clock_t c=clock();
	hash.Update((byte *)&c, sizeof(c));
	hash.Final(salt);

	// use hash(passphrase | salt) as key check
	hash.Update(m_passphrase, m_passphrase.size());
	hash.Update(salt, SALTLENGTH);
	hash.Final(keyCheck);

	AttachedTransformation()->Put(salt, SALTLENGTH);

	// mash passphrase and salt together into key and IV
	SecByteBlock key(KEYLENGTH);
	SecByteBlock IV(BLOCKSIZE);
	GenerateKeyIV<BC,H,Info>(m_passphrase, m_passphrase.size(), salt, SALTLENGTH, ITERATIONS, key, IV);

	m_cipher.SetKeyWithIV(key, key.size(), IV);
	SetFilter(new StreamTransformationFilter(m_cipher));

	m_filter->Put(keyCheck, BLOCKSIZE);
}

template <class BC, class H, class Info>
void DataEncryptor<BC,H,Info>::LastPut(const byte *inString, size_t length)
{
	CRYPTOPP_UNUSED(inString); CRYPTOPP_UNUSED(length);
	m_filter->MessageEnd();
}

// ********************************************************

template <class BC, class H, class Info>
DataDecryptor<BC,H,Info>::DataDecryptor(const char *p, BufferedTransformation *attachment, bool throwException)
	: ProxyFilter(NULL, SALTLENGTH+BLOCKSIZE, 0, attachment)
	, m_state(WAITING_FOR_KEYCHECK)
	, m_passphrase((const byte *)p, strlen(p))
	, m_throwException(throwException)
{
	CRYPTOPP_COMPILE_ASSERT(SALTLENGTH <= DIGESTSIZE);
	CRYPTOPP_COMPILE_ASSERT(BLOCKSIZE <= DIGESTSIZE);
}

template <class BC, class H, class Info>
DataDecryptor<BC,H,Info>::DataDecryptor(const byte *passphrase, size_t passphraseLength, BufferedTransformation *attachment, bool throwException)
	: ProxyFilter(NULL, SALTLENGTH+BLOCKSIZE, 0, attachment)
	, m_state(WAITING_FOR_KEYCHECK)
	, m_passphrase(passphrase, passphraseLength)
	, m_throwException(throwException)
{
	CRYPTOPP_COMPILE_ASSERT(SALTLENGTH <= DIGESTSIZE);
	CRYPTOPP_COMPILE_ASSERT(BLOCKSIZE <= DIGESTSIZE);
}

template <class BC, class H, class Info>
void DataDecryptor<BC,H,Info>::FirstPut(const byte *inString)
{
	CheckKey(inString, inString+SALTLENGTH);
}

template <class BC, class H, class Info>
void DataDecryptor<BC,H,Info>::LastPut(const byte *inString, size_t length)
{
	CRYPTOPP_UNUSED(inString); CRYPTOPP_UNUSED(length);
	if (m_filter.get() == NULL)
	{
		m_state = KEY_BAD;
		if (m_throwException)
			throw KeyBadErr();
	}
	else
	{
		m_filter->MessageEnd();
		m_state = WAITING_FOR_KEYCHECK;
	}
}

template <class BC, class H, class Info>
void DataDecryptor<BC,H,Info>::CheckKey(const byte *salt, const byte *keyCheck)
{
	SecByteBlock check(STDMAX((unsigned int)2*BLOCKSIZE, (unsigned int)DIGESTSIZE));

	H hash;
	hash.Update(m_passphrase, m_passphrase.size());
	hash.Update(salt, SALTLENGTH);
	hash.Final(check);

	SecByteBlock key(KEYLENGTH);
	SecByteBlock IV(BLOCKSIZE);
	GenerateKeyIV<BC,H,Info>(m_passphrase, m_passphrase.size(), salt, SALTLENGTH, ITERATIONS, key, IV);

	m_cipher.SetKeyWithIV(key, key.size(), IV);
	member_ptr<StreamTransformationFilter> decryptor(new StreamTransformationFilter(m_cipher));

	decryptor->Put(keyCheck, BLOCKSIZE);
	decryptor->ForceNextPut();
	decryptor->Get(check+BLOCKSIZE, BLOCKSIZE);

	SetFilter(decryptor.release());

	if (!VerifyBufsEqual(check, check+BLOCKSIZE, BLOCKSIZE))
	{
		m_state = KEY_BAD;
		if (m_throwException)
			throw KeyBadErr();
	}
	else
		m_state = KEY_GOOD;
}

// ********************************************************

template <class H, class MAC>
static MAC* NewDataEncryptorMAC(const byte *passphrase, size_t passphraseLength)
{
	size_t macKeyLength = MAC::StaticGetValidKeyLength(16);
	SecByteBlock macKey(macKeyLength);
	// since the MAC is encrypted there is no reason to mash the passphrase for many iterations
	Mash<H>(passphrase, passphraseLength, macKey, macKeyLength, 1);
	return new MAC(macKey, macKeyLength);
}

template <class BC, class H, class MAC, class Info>
DataEncryptorWithMAC<BC,H,MAC,Info>::DataEncryptorWithMAC(const char *passphrase, BufferedTransformation *attachment)
	: ProxyFilter(NULL, 0, 0, attachment)
	, m_mac(NewDataEncryptorMAC<H,MAC>((const byte *)passphrase, strlen(passphrase)))
{
	SetFilter(new HashFilter(*m_mac, new DataEncryptor<BC,H,Info>(passphrase), true));
}

template <class BC, class H, class MAC, class Info>
DataEncryptorWithMAC<BC,H,MAC,Info>::DataEncryptorWithMAC(const byte *passphrase, size_t passphraseLength, BufferedTransformation *attachment)
	: ProxyFilter(NULL, 0, 0, attachment)
	, m_mac(NewDataEncryptorMAC<H,MAC>(passphrase, passphraseLength))
{
	SetFilter(new HashFilter(*m_mac, new DataEncryptor<BC,H,Info>(passphrase, passphraseLength), true));
}

template <class BC, class H, class MAC, class Info>
void DataEncryptorWithMAC<BC,H,MAC,Info>::LastPut(const byte *inString, size_t length)
{
	CRYPTOPP_UNUSED(inString); CRYPTOPP_UNUSED(length);
	m_filter->MessageEnd();
}

// ********************************************************

template <class BC, class H, class MAC, class Info>
DataDecryptorWithMAC<BC,H,MAC,Info>::DataDecryptorWithMAC(const char *passphrase, BufferedTransformation *attachment, bool throwException)
	: ProxyFilter(NULL, 0, 0, attachment)
	, m_mac(NewDataEncryptorMAC<H,MAC>((const byte *)passphrase, strlen(passphrase)))
	, m_throwException(throwException)
{
	SetFilter(new DataDecryptor<BC,H,Info>(passphrase, m_hashVerifier=new HashVerificationFilter(*m_mac, NULL, HashVerificationFilter::PUT_MESSAGE), throwException));
}

template <class BC, class H, class MAC, class Info>
DataDecryptorWithMAC<BC,H,MAC,Info>::DataDecryptorWithMAC(const byte *passphrase, size_t passphraseLength, BufferedTransformation *attachment, bool throwException)
	: ProxyFilter(NULL, 0, 0, attachment)
	, m_mac(NewDataEncryptorMAC<H,MAC>(passphrase, passphraseLength))
	, m_throwException(throwException)
{
	SetFilter(new DataDecryptor<BC,H,Info>(passphrase, passphraseLength, m_hashVerifier=new HashVerificationFilter(*m_mac, NULL, HashVerificationFilter::PUT_MESSAGE), throwException));
}

template <class BC, class H, class MAC, class Info>
typename DataDecryptor<BC,H,Info>::State DataDecryptorWithMAC<BC,H,MAC,Info>::CurrentState() const
{
	return static_cast<const DataDecryptor<BC,H,Info> *>(m_filter.get())->CurrentState();
}

template <class BC, class H, class MAC, class Info>
bool DataDecryptorWithMAC<BC,H,MAC,Info>::CheckLastMAC() const
{
	return m_hashVerifier->GetLastResult();
}

template <class BC, class H, class MAC, class Info>
void DataDecryptorWithMAC<BC,H,MAC,Info>::LastPut(const byte *inString, size_t length)
{
	CRYPTOPP_UNUSED(inString); CRYPTOPP_UNUSED(length);
	m_filter->MessageEnd();
	if (m_throwException && !CheckLastMAC())
		throw MACBadErr();
}

template struct DataParametersInfo<LegacyBlockCipher::BLOCKSIZE, LegacyBlockCipher::DEFAULT_KEYLENGTH, LegacyHashModule::DIGESTSIZE, 8, 200>;
template struct DataParametersInfo<DefaultBlockCipher::BLOCKSIZE, DefaultBlockCipher::DEFAULT_KEYLENGTH, DefaultHashModule::DIGESTSIZE, 8, 2500>;

template class DataEncryptor<LegacyBlockCipher,LegacyHashModule,LegacyParametersInfo>;
template class DataDecryptor<LegacyBlockCipher,LegacyHashModule,LegacyParametersInfo>;
template class DataEncryptor<DefaultBlockCipher,DefaultHashModule,DefaultParametersInfo>;
template class DataDecryptor<DefaultBlockCipher,DefaultHashModule,DefaultParametersInfo>;
template class DataEncryptorWithMAC<LegacyBlockCipher,LegacyHashModule,DefaultMAC,LegacyParametersInfo>;
template class DataDecryptorWithMAC<LegacyBlockCipher,LegacyHashModule,DefaultMAC,LegacyParametersInfo>;
template class DataEncryptorWithMAC<DefaultBlockCipher,DefaultHashModule,DefaultMAC,DefaultParametersInfo>;
template class DataDecryptorWithMAC<DefaultBlockCipher,DefaultHashModule,DefaultMAC,DefaultParametersInfo>;

NAMESPACE_END
