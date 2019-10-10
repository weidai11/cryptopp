// xts.h - written and placed in the public domain by Jeffrey Walton

/// \file xts.h
/// \brief Classes for XTS block cipher mode of operation

#ifndef CRYPTOPP_XTS_MODE_H
#define CRYPTOPP_XTS_MODE_H

#include "cryptlib.h"
#include "secblock.h"
#include "modes.h"
#include "misc.h"

/// \brief Enable XTS and wide block ciphers
/// \details XTS is only defined for AES. The library can support wide
///  block ciphers like Kaylna and Threefish since we know the polynomials.
#ifndef CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS
# define CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS 1
#endif  // CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS

NAMESPACE_BEGIN(CryptoPP)

/// \brief XTS block cipher mode of operation default implementation
/// \since Crypto++ 8.3
class CRYPTOPP_NO_VTABLE XTS_ModeBase : public BlockOrientedCipherModeBase
{
public:
    std::string AlgorithmName() const
        {return GetEncryptionCipher().AlgorithmName() + "/XTS";}
    std::string AlgorithmProvider() const
        {return GetEncryptionCipher().AlgorithmProvider();}

    size_t MinKeyLength() const
        {return GetEncryptionCipher().MinKeyLength()*2;}
    size_t MaxKeyLength() const
        {return GetEncryptionCipher().MaxKeyLength()*2;}
    size_t DefaultKeyLength() const
        {return GetEncryptionCipher().DefaultKeyLength()*2;}
    size_t GetValidKeyLength(size_t n) const
        {return GetEncryptionCipher().GetValidKeyLength(n/2);}
    bool IsValidKeyLength(size_t n) const
        {return GetEncryptionCipher().IsValidKeyLength(n/2);}

    unsigned int BlockSize() const
        {return GetEncryptionCipher().BlockSize();}
    unsigned int MinLastBlockSize() const
        {return GetEncryptionCipher().BlockSize()+1;}
    unsigned int OptimalDataAlignment() const
        {return GetEncryptionCipher().OptimalDataAlignment();}

    void SetKey(const byte *key, size_t length, const NameValuePairs &params = g_nullNameValuePairs);
    IV_Requirement IVRequirement() const {return UNIQUE_IV;}
    void ProcessData(byte *outString, const byte *inString, size_t length);
    size_t ProcessLastBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength);

protected:
    virtual void ResizeBuffers();

    virtual BlockCipher& AccessEncryptionCipher() = 0;
    virtual BlockCipher& AccessTweakCipher() = 0;

    const BlockCipher& GetEncryptionCipher() const
        {return const_cast<XTS_ModeBase*>(this)->AccessEncryptionCipher();}
    const BlockCipher& GetTweakCipher() const
        {return const_cast<XTS_ModeBase*>(this)->AccessTweakCipher();}

    SecByteBlock m_workspace;
};

/// \brief XTS block cipher mode of operation implementation details
/// tparam CIPHER, 128-bit BlockCipher derived class or type
/// tparam DATA_UNIT data unit size, in bytes
/// \since Crypto++ 8.3
template <class CIPHER>
class CRYPTOPP_NO_VTABLE XTS_Final : public XTS_ModeBase
{
public:
    CRYPTOPP_STATIC_CONSTEXPR std::string CRYPTOPP_API StaticAlgorithmName()
        {return std::string(CIPHER::StaticAlgorithmName()) + "/XTS";}

protected:
    BlockCipher& AccessEncryptionCipher()
        {return *m_cipher;}
    BlockCipher& AccessTweakCipher()
        {return m_tweaker;}

protected:
    typename CIPHER::Encryption m_tweaker;
};

/// \brief XTS block cipher mode of operation
/// tparam CIPHER, 128-bit BlockCipher derived class or type
/// tparam DATA_UNIT data unit size, in bytes
/// \since Crypto++ 8.3
/// \details The data unit size shall be at least 128 bits. Data unit should be divided
///  into 128-bit blocks... The number of 128-bit blocks should not exceed 2^20.
/// \sa <A HREF="http://www.cryptopp.com/wiki/Modes_of_Operation">Modes of Operation</A>
///   on the Crypto++ wiki.
template <class CIPHER>
struct XTS : public CipherModeDocumentation
{
    typedef CipherModeFinalTemplate_CipherHolder<typename CIPHER::Encryption, XTS_Final<CIPHER> > Encryption;
    typedef CipherModeFinalTemplate_CipherHolder<typename CIPHER::Decryption, XTS_Final<CIPHER> > Decryption;
};

NAMESPACE_END

#endif  // CRYPTOPP_XTS_MODE_H
