#ifndef CRYPTOPP_PANAMA_H
#define CRYPTOPP_PANAMA_H

#include "seckey.h"
#include "secblock.h"
#include "iterhash.h"
#include "strciphr.h"

NAMESPACE_BEGIN(CryptoPP)

/// base class, do not use directly
template <class B>
class CRYPTOPP_NO_VTABLE Panama
{
public:
	void Reset();
	void Iterate(unsigned int count, const word32 *p=NULL, word32 *z=NULL, const word32 *y=NULL);

protected:
	typedef word32 Stage[8];
	enum {STAGES = 32};

	FixedSizeSecBlock<word32, 17*2 + STAGES*sizeof(Stage)> m_state;
	unsigned int m_bstart;
};

/// <a href="http://www.weidai.com/scan-mirror/md.html#Panama">Panama Hash</a>
template <class B = LittleEndian>
class PanamaHash : protected Panama<B>, public AlgorithmImpl<IteratedHash<word32, NativeByteOrder, 32>, PanamaHash<B> >
{
public:
	enum {DIGESTSIZE = 32};
	PanamaHash() {Panama<B>::Reset();}
	unsigned int DigestSize() const {return DIGESTSIZE;}
	void TruncatedFinal(byte *hash, unsigned int size);
	static const char * StaticAlgorithmName() {return B::ToEnum() == BIG_ENDIAN_ORDER ? "Panama-BE" : "Panama-LE";}

protected:
	void Init() {Panama<B>::Reset();}
	void HashEndianCorrectedBlock(const word32 *data) {this->Iterate(1, data);}	// push
	unsigned int HashMultipleBlocks(const word32 *input, unsigned int length);
};

//! MAC construction using a hermetic hash function
template <class T_Hash, class T_Info = T_Hash>
class HermeticHashFunctionMAC : public AlgorithmImpl<SimpleKeyingInterfaceImpl<TwoBases<MessageAuthenticationCode, VariableKeyLength<32, 0, UINT_MAX> > >, T_Info>
{
public:
	void SetKey(const byte *key, unsigned int length, const NameValuePairs &params = g_nullNameValuePairs)
	{
		m_key.Assign(key, length);
		Restart();
	}

	void Restart()
	{
		m_hash.Restart();
		m_keyed = false;
	}

	void Update(const byte *input, unsigned int length)
	{
		if (!m_keyed)
			KeyHash();
		m_hash.Update(input, length);
	}

	void TruncatedFinal(byte *digest, unsigned int digestSize)
	{
		if (!m_keyed)
			KeyHash();
		m_hash.TruncatedFinal(digest, digestSize);
		m_keyed = false;
	}

	unsigned int DigestSize() const
		{return m_hash.DigestSize();}
	unsigned int BlockSize() const
		{return m_hash.BlockSize();}
	unsigned int OptimalBlockSize() const
		{return m_hash.OptimalBlockSize();}
	unsigned int OptimalDataAlignment() const
		{return m_hash.OptimalDataAlignment();}

protected:
	void KeyHash()
	{
		m_hash.Update(m_key, m_key.size());
		m_keyed = true;
	}

	T_Hash m_hash;
	bool m_keyed;
	SecByteBlock m_key;
};

/// Panama MAC
template <class B = LittleEndian>
class PanamaMAC : public HermeticHashFunctionMAC<PanamaHash<B> >
{
public:
 	PanamaMAC() {}
	PanamaMAC(const byte *key, unsigned int length)
		{this->SetKey(key, length);}
};

//! algorithm info
template <class B>
struct PanamaCipherInfo : public VariableKeyLength<32, 32, 64, 32, SimpleKeyingInterface::NOT_RESYNCHRONIZABLE>
{
	static const char * StaticAlgorithmName() {return B::ToEnum() == BIG_ENDIAN_ORDER ? "Panama-BE" : "Panama-LE";}
};

//! _
template <class B>
class PanamaCipherPolicy : public AdditiveCipherConcretePolicy<word32, 8>, 
							public PanamaCipherInfo<B>,
							protected Panama<B>
{
protected:
	void CipherSetKey(const NameValuePairs &params, const byte *key, unsigned int length);
	void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, unsigned int iterationCount);
	bool IsRandomAccess() const {return false;}
};

//! <a href="http://www.weidai.com/scan-mirror/cs.html#Panama">Panama Stream Cipher</a>
template <class B = LittleEndian>
struct PanamaCipher : public PanamaCipherInfo<B>, public SymmetricCipherDocumentation
{
	typedef SymmetricCipherFinal<ConcretePolicyHolder<PanamaCipherPolicy<B>, AdditiveCipherTemplate<> > > Encryption;
	typedef Encryption Decryption;
};

NAMESPACE_END

#endif
