#ifndef	CRYPTOPP_MODES_H
#define	CRYPTOPP_MODES_H

/*!	\file
*/

#include "cryptlib.h"
#include "secblock.h"
#include "misc.h"
#include "strciphr.h"
#include "argnames.h"

NAMESPACE_BEGIN(CryptoPP)

//!	Cipher mode	documentation. See NIST	SP 800-38A for definitions of these	modes.

/*!	Each class derived from	this one defines two types,	Encryption and Decryption, 
	both of	which implement	the	SymmetricCipher	interface.
	For	each mode there	are	two	classes, one of	which is a template	class,
	and	the	other one has a	name that ends in "_ExternalCipher".
	The	"external cipher" mode objects hold	a reference	to the underlying block	cipher,
	instead	of holding an instance of it. The reference	must be	passed in to the constructor.
	For	the	"cipher	holder"	classes, the CIPHER	template parameter should be a class
	derived	from BlockCipherDocumentation, for example DES or AES.
*/
struct CipherModeDocumentation : public	SymmetricCipherDocumentation
{
};

class CipherModeBase : public SymmetricCipher
{
public:
	unsigned int MinKeyLength()	const {return m_cipher->MinKeyLength();}
	unsigned int MaxKeyLength()	const {return m_cipher->MaxKeyLength();}
	unsigned int DefaultKeyLength()	const {return m_cipher->DefaultKeyLength();}
	unsigned int GetValidKeyLength(unsigned	int	n) const {return m_cipher->GetValidKeyLength(n);}
	bool IsValidKeyLength(unsigned int n) const	{return	m_cipher->IsValidKeyLength(n);}

	void SetKey(const byte *key, unsigned int length, const	NameValuePairs &params = g_nullNameValuePairs);

	unsigned int OptimalDataAlignment()	const {return BlockSize();}

	unsigned int IVSize() const	{return	BlockSize();}
	void GetNextIV(byte	*IV);
	virtual	IV_Requirement IVRequirement() const =0;

protected:
	inline unsigned	int	BlockSize()	const {assert(m_register.size()	> 0); return m_register.size();}
	void SetIV(const byte *iv);
	virtual	void SetFeedbackSize(unsigned int feedbackSize)
	{
		if (!(feedbackSize == 0	|| feedbackSize	== BlockSize()))
			throw InvalidArgument("CipherModeBase: feedback	size cannot	be specified for this cipher mode");
	}
	virtual	void ResizeBuffers()
	{
		m_register.New(m_cipher->BlockSize());
	}
	virtual	void UncheckedSetKey(const NameValuePairs &params, const byte *key,	unsigned int length) =0;

	BlockCipher	*m_cipher;
	SecByteBlock m_register;
};

template <class	POLICY_INTERFACE>
class ModePolicyCommonTemplate : public	CipherModeBase,	public POLICY_INTERFACE
{
	unsigned int GetAlignment()	const {return m_cipher->BlockAlignment();}
	void CipherSetKey(const	NameValuePairs &params,	const byte *key, unsigned int length)
	{
		m_cipher->SetKey(key, length, params);
		ResizeBuffers();
		int	feedbackSize = params.GetIntValueWithDefault(Name::FeedbackSize(), 0);
		SetFeedbackSize(feedbackSize);
		const byte *iv = params.GetValueWithDefault(Name::IV(),	(const byte	*)NULL);
		SetIV(iv);
	}
};

class CFB_ModePolicy : public ModePolicyCommonTemplate<CFB_CipherAbstractPolicy>
{
public:
	IV_Requirement IVRequirement() const {return RANDOM_IV;}

protected:
	unsigned int GetBytesPerIteration()	const {return m_feedbackSize;}
	byte * GetRegisterBegin() {return m_register + BlockSize() - m_feedbackSize;}
	void TransformRegister()
	{
		m_cipher->ProcessBlock(m_register, m_temp);
		memmove(m_register,	m_register+m_feedbackSize, BlockSize()-m_feedbackSize);
		memcpy(m_register+BlockSize()-m_feedbackSize, m_temp, m_feedbackSize);
	}
	void CipherResynchronize(const byte	*iv)
	{
		memcpy(m_register, iv, BlockSize());
		TransformRegister();
	}
	void SetFeedbackSize(unsigned int feedbackSize)
	{
		if (feedbackSize > BlockSize())
			throw InvalidArgument("CFB_Mode: invalid feedback size");
		m_feedbackSize = feedbackSize ?	feedbackSize : BlockSize();
	}
	void ResizeBuffers()
	{
		CipherModeBase::ResizeBuffers();
		m_temp.New(BlockSize());
	}

	SecByteBlock m_temp;
	unsigned int m_feedbackSize;
};

class OFB_ModePolicy : public ModePolicyCommonTemplate<AdditiveCipherAbstractPolicy>
{
	unsigned int GetBytesPerIteration()	const {return BlockSize();}
	unsigned int GetIterationsToBuffer() const {return 1;}
	void WriteKeystream(byte *keystreamBuffer, unsigned	int	iterationCount)
	{
		assert(iterationCount == 1);
		m_cipher->ProcessBlock(keystreamBuffer);
	}
	void CipherResynchronize(byte *keystreamBuffer,	const byte *iv)
	{
		memcpy(keystreamBuffer,	iv,	BlockSize());
	}
	bool IsRandomAccess() const	{return	false;}
	IV_Requirement IVRequirement() const {return STRUCTURED_IV;}
};

class CTR_ModePolicy : public ModePolicyCommonTemplate<AdditiveCipherAbstractPolicy>
{
	unsigned int GetBytesPerIteration()	const {return BlockSize();}
	unsigned int GetIterationsToBuffer() const {return m_cipher->OptimalNumberOfParallelBlocks();}
	void WriteKeystream(byte *buffer, unsigned int iterationCount)
		{OperateKeystream(WRITE_KEYSTREAM, buffer, NULL, iterationCount);}
	bool CanOperateKeystream() const {return true;}
	void OperateKeystream(KeystreamOperation operation,	byte *output, const	byte *input, unsigned int iterationCount);
	void CipherResynchronize(byte *keystreamBuffer,	const byte *iv);
	bool IsRandomAccess() const	{return	true;}
	void SeekToIteration(dword iterationCount);
	IV_Requirement IVRequirement() const {return STRUCTURED_IV;}

	static inline void IncrementCounterByOne(byte *output, const byte *input, unsigned int s)
	{
		for	(int i=s-1,	carry=1; i>=0; i--)
			carry =	!(output[i]	= input[i]+1);
	}
	inline void	ProcessMultipleBlocks(byte *output,	const byte *input, unsigned	int	n)
	{
		unsigned int s = BlockSize(), j	= 0;
		for	(unsigned int i=1; i<n;	i++, j+=s)
			IncrementCounterByOne(m_counterArray + j + s, m_counterArray + j, s);
		m_cipher->ProcessAndXorMultipleBlocks(m_counterArray, input, output, n);
		IncrementCounterByOne(m_counterArray, m_counterArray + s*(n-1),	s);
	}

	SecByteBlock m_counterArray;
};

class BlockOrientedCipherModeBase :	public CipherModeBase
{
public:
	void UncheckedSetKey(const NameValuePairs &params, const byte *key,	unsigned int length);
	unsigned int MandatoryBlockSize() const	{return	BlockSize();}
	bool IsRandomAccess() const	{return	false;}
	bool IsSelfInverting() const {return false;}
	bool IsForwardTransformation() const {return m_cipher->IsForwardTransformation();}
	void Resynchronize(const byte *iv) {memcpy(m_register, iv, BlockSize());}
	void ProcessData(byte *outString, const	byte *inString,	unsigned int length);

protected:
	bool RequireAlignedInput() const {return true;}
	virtual	void ProcessBlocks(byte	*outString,	const byte *inString, unsigned int numberOfBlocks) =0;
	void ResizeBuffers()
	{
		CipherModeBase::ResizeBuffers();
		m_buffer.New(BlockSize());
	}

	SecByteBlock m_buffer;
};

class ECB_OneWay : public BlockOrientedCipherModeBase
{
public:
	IV_Requirement IVRequirement() const {return NOT_RESYNCHRONIZABLE;}
	unsigned int OptimalBlockSize()	const {return BlockSize() *	m_cipher->OptimalNumberOfParallelBlocks();}
	void ProcessBlocks(byte	*outString,	const byte *inString, unsigned int numberOfBlocks)
		{m_cipher->ProcessAndXorMultipleBlocks(inString, NULL, outString, numberOfBlocks);}
};

class CBC_ModeBase : public	BlockOrientedCipherModeBase
{
public:
	IV_Requirement IVRequirement() const {return UNPREDICTABLE_RANDOM_IV;}
	bool RequireAlignedInput() const {return false;}
	unsigned int MinLastBlockSize()	const {return 0;}
};

class CBC_Encryption : public CBC_ModeBase
{
public:
	void ProcessBlocks(byte	*outString,	const byte *inString, unsigned int numberOfBlocks);
};

class CBC_CTS_Encryption : public CBC_Encryption
{
public:
	void SetStolenIV(byte *iv) {m_stolenIV = iv;}

protected:
	void UncheckedSetKey(const NameValuePairs &params, const byte *key,	unsigned int length)
	{
		CBC_Encryption::UncheckedSetKey(params,	key, length);
		m_stolenIV = params.GetValueWithDefault(Name::StolenIV(), (byte	*)NULL);
	}
	unsigned int MinLastBlockSize()	const {return BlockSize()+1;}
	void ProcessLastBlock(byte *outString, const byte *inString, unsigned int length);

	byte *m_stolenIV;
};

class CBC_Decryption : public CBC_ModeBase
{
public:
	void ProcessBlocks(byte	*outString,	const byte *inString, unsigned int numberOfBlocks);
	
protected:
	void ResizeBuffers()
	{
		BlockOrientedCipherModeBase::ResizeBuffers();
		m_temp.New(BlockSize());
	}
	SecByteBlock m_temp;
};

class CBC_CTS_Decryption : public CBC_Decryption
{
	unsigned int MinLastBlockSize()	const {return BlockSize()+1;}
	void ProcessLastBlock(byte *outString, const byte *inString, unsigned int length);
};

//!	.
template <class	CIPHER,	class BASE>
class CipherModeFinalTemplate_CipherHolder : public	ObjectHolder<CIPHER>, public BASE
{
public:
	CipherModeFinalTemplate_CipherHolder()
	{
		m_cipher = &m_object;
		ResizeBuffers();
	}
	CipherModeFinalTemplate_CipherHolder(const byte	*key, unsigned int length)
	{
		m_cipher = &m_object;
		SetKey(key,	length);
	}
	CipherModeFinalTemplate_CipherHolder(const byte	*key, unsigned int length, const byte *iv, int feedbackSize	= 0)
	{
		m_cipher = &m_object;
		SetKey(key,	length,	MakeParameters("IV", iv)("FeedbackSize", feedbackSize));
	}
};

//!	.
template <class	BASE>
class CipherModeFinalTemplate_ExternalCipher : public BASE
{
public:
	CipherModeFinalTemplate_ExternalCipher(BlockCipher &cipher,	const byte *iv = NULL, int feedbackSize	= 0)
	{
		m_cipher = &cipher;
		ResizeBuffers();
		SetFeedbackSize(feedbackSize);
		SetIV(iv);
	}
};

//!	CFB	mode
template <class	CIPHER>
struct CFB_Mode	: public CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Encryption, ConcretePolicyHolder<Empty, CFB_EncryptionTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy,	CFB_ModePolicy>	> >	> Encryption;
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Encryption, ConcretePolicyHolder<Empty, CFB_DecryptionTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy,	CFB_ModePolicy>	> >	> Decryption;
};

//!	CFB	mode, external cipher
struct CFB_Mode_ExternalCipher : public	CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_ExternalCipher<ConcretePolicyHolder<Empty, CFB_EncryptionTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy, CFB_ModePolicy> > > > Encryption;
	typedef	CipherModeFinalTemplate_ExternalCipher<ConcretePolicyHolder<Empty, CFB_DecryptionTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy, CFB_ModePolicy> > > > Decryption;
};

//!	OFB	mode
template <class	CIPHER>
struct OFB_Mode	: public CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Encryption, ConcretePolicyHolder<Empty, AdditiveCipherTemplate<AbstractPolicyHolder<AdditiveCipherAbstractPolicy,	OFB_ModePolicy>	> >	> Encryption;
	typedef	Encryption Decryption;
};

//!	OFB	mode, external cipher
struct OFB_Mode_ExternalCipher : public	CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_ExternalCipher<ConcretePolicyHolder<Empty, AdditiveCipherTemplate<AbstractPolicyHolder<AdditiveCipherAbstractPolicy, OFB_ModePolicy> > > > Encryption;
	typedef	Encryption Decryption;
};

//!	CTR	mode
template <class	CIPHER>
struct CTR_Mode	: public CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Encryption, ConcretePolicyHolder<Empty, AdditiveCipherTemplate<AbstractPolicyHolder<AdditiveCipherAbstractPolicy,	CTR_ModePolicy>	> >	> Encryption;
	typedef	Encryption Decryption;
};

//!	CTR	mode, external cipher
struct CTR_Mode_ExternalCipher : public	CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_ExternalCipher<ConcretePolicyHolder<Empty, AdditiveCipherTemplate<AbstractPolicyHolder<AdditiveCipherAbstractPolicy, CTR_ModePolicy> > > > Encryption;
	typedef	Encryption Decryption;
};

//!	ECB	mode
template <class	CIPHER>
struct ECB_Mode	: public CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Encryption, ECB_OneWay> Encryption;
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Decryption, ECB_OneWay> Decryption;
};

//!	ECB	mode, external cipher
struct ECB_Mode_ExternalCipher : public	CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_ExternalCipher<ECB_OneWay> Encryption;
	typedef	Encryption Decryption;
};

//!	CBC	mode
template <class	CIPHER>
struct CBC_Mode	: public CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Encryption, CBC_Encryption> Encryption;
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Decryption, CBC_Decryption> Decryption;
};

//!	CBC	mode, external cipher
struct CBC_Mode_ExternalCipher : public	CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_ExternalCipher<CBC_Encryption> Encryption;
	typedef	CipherModeFinalTemplate_ExternalCipher<CBC_Decryption> Decryption;
};

//!	CBC	mode with ciphertext stealing
template <class	CIPHER>
struct CBC_CTS_Mode	: public CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Encryption, CBC_CTS_Encryption> Encryption;
	typedef	CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Decryption, CBC_CTS_Decryption> Decryption;
};

//!	CBC	mode with ciphertext stealing, external	cipher
struct CBC_CTS_Mode_ExternalCipher : public	CipherModeDocumentation
{
	typedef	CipherModeFinalTemplate_ExternalCipher<CBC_CTS_Encryption> Encryption;
	typedef	CipherModeFinalTemplate_ExternalCipher<CBC_CTS_Decryption> Decryption;
};

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
typedef	CFB_Mode_ExternalCipher::Encryption	CFBEncryption;
typedef	CFB_Mode_ExternalCipher::Decryption	CFBDecryption;
typedef	OFB_Mode_ExternalCipher::Encryption	OFB;
typedef	OFB_Mode_ExternalCipher::Encryption	CounterMode;
#endif

NAMESPACE_END

#endif
