// chachapoly.cpp - written and placed in the public domain by Jeffrey Walton
//                  RFC 8439, Section 2.8, AEAD Construction, http://tools.ietf.org/html/rfc8439

#include "pch.h"
#include "chachapoly.h"
#include "algparam.h"
#include "misc.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4244)
#endif

NAMESPACE_BEGIN(CryptoPP)

////////////////////////////// IETF ChaChaTLS //////////////////////////////

// RekeyCipherAndMac is heavier-weight than we like. The Authenc framework was
// predicated on BlockCiphers, where the key and key schedule could be
// calculated independent of the IV being used. However, the ChaCha and
// ChaCha20Poly1305 construction combines key setup and IV. That is, both are
// needed to key or rekey the cipher. Even a simple Resync() requires us to
// regenerate the initial state for both ChaCha20 and Poly1305.
void ChaCha20Poly1305_Base::RekeyCipherAndMac(const byte *userKey, size_t keylength, const NameValuePairs &params)
{
	// Derive MAC key
	AlgorithmParameters block0 = MakeParameters("InitialBlock", (word64)0, true);
	AccessSymmetricCipher().SetKey(userKey, keylength, CombinedNameValuePairs(params, block0));

	// Only the first 256-bits are used to key the MAC
	SecByteBlock derived(NULLPTR, 32);
	AccessSymmetricCipher().ProcessString(derived, derived.size());

	// Key the Poly1305 MAC
	AccessMAC().SetKey(derived, derived.size(), params);

	// Key the ChaCha20 cipher
	AlgorithmParameters block1 = MakeParameters("InitialBlock", (word64)1, true);
	AccessSymmetricCipher().SetKey(userKey, keylength, CombinedNameValuePairs(params, block1));
}

void ChaCha20Poly1305_Base::SetKeyWithoutResync(const byte *userKey, size_t userKeyLength, const NameValuePairs &params)
{
	CRYPTOPP_ASSERT(userKey && userKeyLength == 32);
	m_userKey.Assign(userKey, userKeyLength);

	// ChaCha/Poly1305 initial state depends on both the key and IV. The
	// IV may or may not be present during the call to SetKeyWithoutResync.
	// If the IV is present, the framework will call SetKeyWithoutResync
	// followed by Resynchronize which calls Resync. In this case we defer
	// calculating the initial state until the call to Resynchronize.
	// If the IV is not present, it avoids calling ChaCha's SetKey without
	// an IV, which results in an exception. In this case the user will need
	// to call Resynchronize to key ChaCha and Poly1305.
	// RekeyCipherAndMac(userKey, userKeyLength, params);
	CRYPTOPP_UNUSED(params);
}

void ChaCha20Poly1305_Base::Resync(const byte *iv, size_t len)
{
	CRYPTOPP_ASSERT(iv && len == 12);
	RekeyCipherAndMac(m_userKey, m_userKey.SizeInBytes(),
		MakeParameters(Name::IV(), ConstByteArrayParameter(iv,len)));
}

size_t ChaCha20Poly1305_Base::AuthenticateBlocks(const byte *data, size_t len)
{
	AccessMAC().Update(data, len);
	return 0;
}

void ChaCha20Poly1305_Base::AuthenticateLastHeaderBlock()
{
	// Pad to a multiple of 16 or 0
	const byte zero[16] = {0};
	size_t pad = (16U - (m_totalHeaderLength % 16)) % 16;
	AccessMAC().Update(zero, pad);
}

void ChaCha20Poly1305_Base::AuthenticateLastConfidentialBlock()
{
	// Pad to a multiple of 16 or 0
	const byte zero[16] = {0};
	size_t pad = (16U - (m_totalMessageLength % 16)) % 16;
	AccessMAC().Update(zero, pad);
}

void ChaCha20Poly1305_Base::AuthenticateLastFooterBlock(byte *mac, size_t macSize)
{
	CRYPTOPP_ALIGN_DATA(8) byte length[2*sizeof(word64)];
	PutWord(true, LITTLE_ENDIAN_ORDER, length+0, m_totalHeaderLength);
	PutWord(true, LITTLE_ENDIAN_ORDER, length+8, m_totalMessageLength);
	AccessMAC().Update(length, sizeof(length));
	AccessMAC().TruncatedFinal(mac, macSize);
	m_state = State_KeySet;
}

void ChaCha20Poly1305_Base::EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize, const byte *iv, int ivLength, const byte *aad, size_t aadLength, const byte *message, size_t messageLength)
{
	Resynchronize(iv, ivLength);
	Update(aad, aadLength);
	ProcessString(ciphertext, message, messageLength);
	TruncatedFinal(mac, macSize);
}

bool ChaCha20Poly1305_Base::DecryptAndVerify(byte *message, const byte *mac, size_t macLength, const byte *iv, int ivLength, const byte *aad, size_t aadLength, const byte *ciphertext, size_t ciphertextLength)
{
	Resynchronize(iv, ivLength);
	Update(aad, aadLength);
	ProcessString(message, ciphertext, ciphertextLength);
	return TruncatedVerify(mac, macLength);
}

////////////////////////////// IETF XChaCha20 draft //////////////////////////////

// RekeyCipherAndMac is heavier-weight than we like. The Authenc framework was
// predicated on BlockCiphers, where the key and key schedule could be
// calculated independent of the IV being used. However, the ChaCha and
// ChaCha20Poly1305 construction combines key setup and IV. That is, both are
// needed to key or rekey the cipher. Even a simple Resync() requires us to
// regenerate the initial state for both ChaCha20 and Poly1305.
void XChaCha20Poly1305_Base::RekeyCipherAndMac(const byte *userKey, size_t keylength, const NameValuePairs &params)
{
	// Derive MAC key
	AlgorithmParameters block0 = MakeParameters("InitialBlock", (word64)0, true);
	AccessSymmetricCipher().SetKey(userKey, keylength, CombinedNameValuePairs(params, block0));

	// Only the first 256-bits are used to key the MAC
	SecByteBlock derived(NULLPTR, 32);
	AccessSymmetricCipher().ProcessString(derived, derived.size());

	// Key the Poly1305 MAC
	AccessMAC().SetKey(derived, derived.size(), params);

	// Key the ChaCha20 cipher
	AlgorithmParameters block1 = MakeParameters("InitialBlock", (word64)1, true);
	AccessSymmetricCipher().SetKey(userKey, keylength, CombinedNameValuePairs(params, block1));
}

void XChaCha20Poly1305_Base::SetKeyWithoutResync(const byte *userKey, size_t userKeyLength, const NameValuePairs &params)
{
	CRYPTOPP_ASSERT(userKey && userKeyLength == 32);
	m_userKey.Assign(userKey, userKeyLength);

	// XChaCha20/Poly1305 initial state depends on both the key and IV. The
	// IV may or may not be present during the call to SetKeyWithoutResync.
	// If the IV is present, the framework will call SetKeyWithoutResync
	// followed by Resynchronize which calls Resync. In this case we defer
	// calculating the initial state until the call to Resynchronize.
	// If the IV is not present, it avoids calling ChaCha's SetKey without
	// an IV, which results in an exception. In this case the user will need
	// to call Resynchronize to key ChaCha and Poly1305.
	// RekeyCipherAndMac(userKey, userKeyLength, params);
	CRYPTOPP_UNUSED(params);
}

void XChaCha20Poly1305_Base::Resync(const byte *iv, size_t len)
{
	CRYPTOPP_ASSERT(iv && len == 24);
	RekeyCipherAndMac(m_userKey, m_userKey.SizeInBytes(),
		MakeParameters(Name::IV(), ConstByteArrayParameter(iv,len)));
}

size_t XChaCha20Poly1305_Base::AuthenticateBlocks(const byte *data, size_t len)
{
	AccessMAC().Update(data, len);
	return 0;
}

void XChaCha20Poly1305_Base::AuthenticateLastHeaderBlock()
{
	// Pad to a multiple of 16 or 0
	const byte zero[16] = {0};
	size_t pad = (16 - (m_totalHeaderLength % 16)) % 16;
	AccessMAC().Update(zero, pad);
}

void XChaCha20Poly1305_Base::AuthenticateLastConfidentialBlock()
{
	// Pad to a multiple of 16 or 0
	const byte zero[16] = {0};
	size_t pad = (16 - (m_totalMessageLength % 16)) % 16;
	AccessMAC().Update(zero, pad);
}

void XChaCha20Poly1305_Base::AuthenticateLastFooterBlock(byte *mac, size_t macSize)
{
	CRYPTOPP_ALIGN_DATA(8) byte length[2*sizeof(word64)];
	PutWord(true, LITTLE_ENDIAN_ORDER, length+0, m_totalHeaderLength);
	PutWord(true, LITTLE_ENDIAN_ORDER, length+8, m_totalMessageLength);
	AccessMAC().Update(length, sizeof(length));
	AccessMAC().TruncatedFinal(mac, macSize);
	m_state = State_KeySet;
}

void XChaCha20Poly1305_Base::EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize, const byte *iv, int ivLength, const byte *aad, size_t aadLength, const byte *message, size_t messageLength)
{
	Resynchronize(iv, ivLength);
	Update(aad, aadLength);
	ProcessString(ciphertext, message, messageLength);
	TruncatedFinal(mac, macSize);
}

bool XChaCha20Poly1305_Base::DecryptAndVerify(byte *message, const byte *mac, size_t macLength, const byte *iv, int ivLength, const byte *aad, size_t aadLength, const byte *ciphertext, size_t ciphertextLength)
{
	Resynchronize(iv, ivLength);
	Update(aad, aadLength);
	ProcessString(message, ciphertext, ciphertextLength);
	return TruncatedVerify(mac, macLength);
}

NAMESPACE_END
