// modes.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "modes.h"

#include "des.h"

#include "strciphr.cpp"

NAMESPACE_BEGIN(CryptoPP)

void Modes_TestInstantiations()
{
	CFB_Mode<DES>::Encryption m0;
	CFB_Mode<DES>::Decryption m1;
	OFB_Mode<DES>::Encryption m2;
	CTR_Mode<DES>::Encryption m3;
	ECB_Mode<DES>::Encryption m4;
	CBC_Mode<DES>::Encryption m5;
}

// explicit instantiations for Darwin gcc-932.1
template class CFB_CipherTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy, SymmetricCipher> >;
template class CFB_EncryptionTemplate<>;
template class CFB_DecryptionTemplate<>;
template class AdditiveCipherTemplate<>;
template class CFB_CipherTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy, CFB_ModePolicy> >;
template class CFB_EncryptionTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy, CFB_ModePolicy> >;
template class CFB_DecryptionTemplate<AbstractPolicyHolder<CFB_CipherAbstractPolicy, CFB_ModePolicy> >;
template class AdditiveCipherTemplate<AbstractPolicyHolder<AdditiveCipherAbstractPolicy, OFB_ModePolicy> >;
template class AdditiveCipherTemplate<AbstractPolicyHolder<AdditiveCipherAbstractPolicy, CTR_ModePolicy> >;

void CipherModeBase::SetKey(const byte *key, unsigned int length, const NameValuePairs &params)
{
	UncheckedSetKey(params, key, length);	// the underlying cipher will check the key length
}

void CipherModeBase::GetNextIV(byte *IV)
{
	if (!IsForwardTransformation())
		throw NotImplemented("CipherModeBase: GetNextIV() must be called on an encryption object");

	m_cipher->ProcessBlock(m_register);
	memcpy(IV, m_register, BlockSize());
}

void CipherModeBase::SetIV(const byte *iv)
{
	if (iv)
		Resynchronize(iv);
	else if (IsResynchronizable())
	{
		if (!CanUseStructuredIVs())
			throw InvalidArgument("CipherModeBase: this cipher mode cannot use a null IV");

		// use all zeros as default IV
		SecByteBlock iv(BlockSize());
		memset(iv, 0, iv.size());
		Resynchronize(iv);
	}
}

void CTR_ModePolicy::SeekToIteration(dword iterationCount)
{
	int carry=0;
	for (int i=BlockSize()-1; i>=0 && (iterationCount || carry); i--)
	{
		unsigned int sum = m_counterArray[i] + byte(iterationCount) + carry;
		m_counterArray[i] = (byte) sum;
		carry = sum >> 8;
		iterationCount >>= 8;
	}
}

void CTR_ModePolicy::OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, unsigned int iterationCount)
{
	unsigned int maxBlocks = m_cipher->OptimalNumberOfParallelBlocks();
	unsigned int sizeIncrement = maxBlocks * m_cipher->BlockSize();
	while (iterationCount >= maxBlocks)
	{
		ProcessMultipleBlocks(output, input, maxBlocks);
		output += sizeIncrement;
		input += sizeIncrement;
		iterationCount -= maxBlocks;
	}
	if (iterationCount > 0)
		ProcessMultipleBlocks(output, input, iterationCount);
}
void CTR_ModePolicy::CipherResynchronize(byte *keystreamBuffer, const byte *iv)
{
	unsigned int s = BlockSize();
	memcpy(m_register, iv, s);
	m_counterArray.New(s * m_cipher->OptimalNumberOfParallelBlocks());
	memcpy(m_counterArray, iv, s);
}

void BlockOrientedCipherModeBase::UncheckedSetKey(const NameValuePairs &params, const byte *key, unsigned int length)
{
	m_cipher->SetKey(key, length, params);
	ResizeBuffers();
	const byte *iv = params.GetValueWithDefault(Name::IV(), (const byte *)NULL);
	SetIV(iv);
}

void BlockOrientedCipherModeBase::ProcessData(byte *outString, const byte *inString, unsigned int length)
{
	unsigned int s = BlockSize();
	assert(length % s == 0);
	unsigned int alignment = m_cipher->BlockAlignment();
	bool requireAlignedInput = RequireAlignedInput();

	if (IsAlignedOn(outString, alignment))
	{
		if (!requireAlignedInput || IsAlignedOn(inString, alignment))
			ProcessBlocks(outString, inString, length / s);
		else
		{
			memcpy(outString, inString, length);
			ProcessBlocks(outString, outString, length / s);
		}
	}
	else
	{
		while (length)
		{
			if (!requireAlignedInput || IsAlignedOn(inString, alignment))
				ProcessBlocks(m_buffer, inString, 1);
			else
			{
				memcpy(m_buffer, inString, s);
				ProcessBlocks(m_buffer, m_buffer, 1);
			}
			memcpy(outString, m_buffer, s);
			length -= s;
		}
	}
}

void CBC_Encryption::ProcessBlocks(byte *outString, const byte *inString, unsigned int numberOfBlocks)
{
	unsigned int blockSize = BlockSize();
	while (numberOfBlocks--)
	{
		xorbuf(m_register, inString, blockSize);
		m_cipher->ProcessBlock(m_register);
		memcpy(outString, m_register, blockSize);
		inString += blockSize;
		outString += blockSize;
	}
}

void CBC_CTS_Encryption::ProcessLastBlock(byte *outString, const byte *inString, unsigned int length)
{
	if (length <= BlockSize())
	{
		if (!m_stolenIV)
			throw InvalidArgument("CBC_Encryption: message is too short for ciphertext stealing");

		// steal from IV
		memcpy(outString, m_register, length);
		outString = m_stolenIV;
	}
	else
	{
		// steal from next to last block
		xorbuf(m_register, inString, BlockSize());
		m_cipher->ProcessBlock(m_register);
		inString += BlockSize();
		length -= BlockSize();
		memcpy(outString+BlockSize(), m_register, length);
	}

	// output last full ciphertext block
	xorbuf(m_register, inString, length);
	m_cipher->ProcessBlock(m_register);
	memcpy(outString, m_register, BlockSize());
}

void CBC_Decryption::ProcessBlocks(byte *outString, const byte *inString, unsigned int numberOfBlocks)
{
	unsigned int blockSize = BlockSize();
	while (numberOfBlocks--)
	{
		memcpy(m_temp, inString, blockSize);
		m_cipher->ProcessBlock(m_temp, outString);
		xorbuf(outString, m_register, blockSize);
		m_register.swap(m_temp);
		inString += blockSize;
		outString += blockSize;
	}
}

void CBC_CTS_Decryption::ProcessLastBlock(byte *outString, const byte *inString, unsigned int length)
{
	const byte *pn, *pn1;
	bool stealIV = length <= BlockSize();

	if (stealIV)
	{
		pn = inString;
		pn1 = m_register;
	}
	else
	{
		pn = inString + BlockSize();
		pn1 = inString;
		length -= BlockSize();
	}

	// decrypt last partial plaintext block
	memcpy(m_temp, pn1, BlockSize());
	m_cipher->ProcessBlock(m_temp);
	xorbuf(m_temp, pn, length);

	if (stealIV)
		memcpy(outString, m_temp, length);
	else
	{
		memcpy(outString+BlockSize(), m_temp, length);
		// decrypt next to last plaintext block
		memcpy(m_temp, pn, length);
		m_cipher->ProcessBlock(m_temp);
		xorbuf(outString, m_temp, m_register, BlockSize());
	}
}

NAMESPACE_END
