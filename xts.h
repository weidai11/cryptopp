// xts.h - written and placed in the public domain by Jeffrey Walton

/// \file xts.h
/// \brief Classes for XTS block cipher mode of operation
/// \details XTS mode is a wide block mode defined by IEEE P1619-2008. NIST
///  SP-800-38E approves the mode for storage devices citing IEEE 1619-2007.
///  IEEE 1619-2007 provides both a reference implementation and test vectors.
///  The IEEE reference implementation fails to arrive at the expected result
///  for some test vectors.
/// \sa <A HREF="http://www.cryptopp.com/wiki/Modes_of_Operation">Modes of
///  Operation</A> on the Crypto++ wiki, <A
///  HREF="https://web.cs.ucdavis.edu/~rogaway/papers/modes.pdf"> Evaluation of Some
///  Blockcipher Modes of Operation</A>, <A
///  HREF="https://csrc.nist.gov/publications/detail/sp/800-38e/final">Recommendation
///  for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on
///  Storage Devices</A>, <A
///  HREF="http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf">IEEE P1619-2007</A>
///  and <A HREF="https://crypto.stackexchange.com/q/74925/10496">IEEE P1619/XTS,
///  inconsistent reference implementation and test vectors</A>.
/// \since Crypto++ 8.3

#ifndef CRYPTOPP_XTS_MODE_H
#define CRYPTOPP_XTS_MODE_H

#include "cryptlib.h"
#include "secblock.h"
#include "modes.h"
#include "misc.h"

/// \brief Enable XTS for wide block ciphers
/// \details XTS is only defined for AES. The library can support wide
///  block ciphers like Kaylna and Threefish since we know the polynomials.
///  To enable wide block ciphers define <tt>CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS</tt>
///  to non-zero. Note this is a library compile time define.
// \details There is risk involved with using XTS with wider block ciphers.
///  According to Phillip Rogaway, "The narrow width of the underlying PRP and
///  the poor treatment of fractional final blocks are problems."
/// \sa <A HREF="https://web.cs.ucdavis.edu/~rogaway/papers/modes.pdf">Evaluation
///  of Some Blockcipher Modes of Operation</A>
/// \since Crypto++ 8.3
#ifndef CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS
# define CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS 0
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
        {return GetEncryptionCipher().GetValidKeyLength((n+1)/2);}
    bool IsValidKeyLength(size_t keylength) const
        {return keylength == GetValidKeyLength(keylength);}

    unsigned int BlockSize() const
        {return GetEncryptionCipher().BlockSize();}
    unsigned int MinLastBlockSize() const
        {return GetEncryptionCipher().BlockSize()+1;}
    unsigned int OptimalDataAlignment() const
        {return GetEncryptionCipher().OptimalDataAlignment();}

    void SetKey(const byte *key, size_t length, const NameValuePairs &params = g_nullNameValuePairs);
    IV_Requirement IVRequirement() const {return UNIQUE_IV;}
    void Resynchronize(const byte *iv, int ivLength=-1);
    void ProcessData(byte *outString, const byte *inString, size_t length);
    size_t ProcessLastBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength);

protected:
    virtual void ResizeBuffers();

    inline size_t ProcessLastPlainBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength);
    inline size_t ProcessLastCipherBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength);

    virtual BlockCipher& AccessEncryptionCipher() = 0;
    virtual BlockCipher& AccessTweakCipher() = 0;

    const BlockCipher& GetEncryptionCipher() const
        {return const_cast<XTS_ModeBase*>(this)->AccessEncryptionCipher();}
    const BlockCipher& GetTweakCipher() const
        {return const_cast<XTS_ModeBase*>(this)->AccessTweakCipher();}

    SecByteBlock m_workspace;
};

/// \brief XTS block cipher mode of operation implementation details
/// \tparam CIPHER BlockCipher derived class or type
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
/// \tparam CIPHER BlockCipher derived class or type
/// \details XTS mode is a wide block mode defined by IEEE P1619-2008. NIST
///  SP-800-38E approves the mode for storage devices citing IEEE 1619-2007.
///  IEEE 1619-2007 provides both a reference implementation and test vectors.
///  The IEEE reference implementation fails to arrive at the expected result
///  for some test vectors.
/// \details XTS is only defined for AES. The library can support wide
///  block ciphers like Kaylna and Threefish since we know the polynomials.
///  There is risk involved with using XTS with wider block ciphers.
///  According to Phillip Rogaway, "The narrow width of the underlying PRP and
///  the poor treatment of fractional final blocks are problems." To enable
///  wide block cipher support define <tt>CRYPTOPP_XTS_WIDE_BLOCK_CIPHERS</tt> to
///  non-zero.
/// \sa <A HREF="http://www.cryptopp.com/wiki/Modes_of_Operation">Modes of
///  Operation</A> on the Crypto++ wiki, <A
///  HREF="https://web.cs.ucdavis.edu/~rogaway/papers/modes.pdf"> Evaluation of Some
///  Blockcipher Modes of Operation</A>, <A
///  HREF="https://csrc.nist.gov/publications/detail/sp/800-38e/final">Recommendation
///  for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on
///  Storage Devices</A>, <A
///  HREF="http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf">IEEE P1619-2007</A>
///  and <A HREF="https://crypto.stackexchange.com/q/74925/10496">IEEE P1619/XTS,
///  inconsistent reference implementation and test vectors</A>.
/// \since Crypto++ 8.3
template <class CIPHER>
struct XTS : public CipherModeDocumentation
{
    typedef CipherModeFinalTemplate_CipherHolder<typename CIPHER::Encryption, XTS_Final<CIPHER> > Encryption;
    typedef CipherModeFinalTemplate_CipherHolder<typename CIPHER::Decryption, XTS_Final<CIPHER> > Decryption;
};

// C++03 lacks the mechanics to typedef a template
#define XTS_Mode XTS

NAMESPACE_END

#endif  // CRYPTOPP_XTS_MODE_H
