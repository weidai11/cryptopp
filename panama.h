#ifndef CRYPTOPP_PANAMA_H
#define CRYPTOPP_PANAMA_H

#include "seckey.h"
#include "secblock.h"
#include "iterhash.h"
#include "strciphr.h"

NAMESPACE_BEGIN(CryptoPP)

/// base class, do not use directly
template <class B>
class Panama
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
class PanamaHash : protected Panama<B>, public IteratedHash<word32, NativeByteOrder, 32>
{
public:
	enum {DIGESTSIZE = 32};
	PanamaHash() : IteratedHash<word32, NativeByteOrder, 32>(0) {Panama<B>::Reset();}
	unsigned int DigestSize() const {return DIGESTSIZE;}
	void TruncatedFinal(byte *hash, unsigned int size);

protected:
	void Init() {Panama<B>::Reset();}
	void vTransform(const word32 *data) {Iterate(1, data);}	// push
	unsigned int HashMultipleBlocks(const word32 *input, unsigned int length);
};

//! .
template <class B = LittleEndian>
class PanamaMAC_Base : public PanamaHash<B>, public VariableKeyLength<32, 0, UINT_MAX>, public MessageAuthenticationCode
{
public:
	void UncheckedSetKey(const byte *userKey, unsigned int keylength)
	{
		m_key.Assign(userKey, keylength);
		Restart();
	}

	static const char * StaticAlgorithmName() {return B::ToEnum() == BIG_ENDIAN ? "Panama-BE" : "Panama-LE";}

protected:
	void Init()
	{
		PanamaHash<B>::Init();
		Update(m_key, m_key.size());
	}

	SecByteBlock m_key;
};

/// Panama MAC
template <class B = LittleEndian>
class PanamaMAC : public MessageAuthenticationCodeTemplate<PanamaMAC_Base<B> >
{
public:
 	PanamaMAC() {}
	PanamaMAC(const byte *key, unsigned int length=PanamaMAC_Base<B>::DEFAULT_KEYLENGTH)
		{SetKey(key, length);}
};

//! .
template <class B>
struct PanamaCipherInfo : public VariableKeyLength<32, 32, 64, 32, SimpleKeyingInterface::NOT_RESYNCHRONIZABLE>
{
	static const char * StaticAlgorithmName() {return B::ToEnum() == BIG_ENDIAN_ORDER ? "Panama-BE" : "Panama-LE";}
};

//! .
template <class B>
class PanamaCipherPolicy : public AdditiveCipherConcretePolicy<word32, 32>, 
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
	typedef SymmetricCipherFinalTemplate<ConcretePolicyHolder<PanamaCipherPolicy<B>, AdditiveCipherTemplate<> > > Encryption;
	typedef Encryption Decryption;
};

NAMESPACE_END

#endif
