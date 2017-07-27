// threefish.h - written and placed in the public domain by Jeffrey Walton
//               Based on public domain code by Keru Kuro. Kuro's code is
//               available at http://cppcrypto.sourceforge.net/.

//! \file Threefish.h
//! \brief Classes for the Threefish block cipher
//! \since Crypto++ 6.0

#ifndef CRYPTOPP_THREEFISH_H
#define CRYPTOPP_THREEFISH_H

#include "config.h"
#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class Threefish_Info
//! \brief Threefish block cipher information
//! \note Crypto++ provides a byte oriented implementation
//! \since Crypto++ 6.0
struct Threefish_Info : public VariableBlockSize<32, 32, 128>
{
    CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "Threefish";}

    //! \brief The minimum key length used by the algorithm provided as a constant
    //! \details MIN_KEYLENGTH is provided in bytes, not bits
    CRYPTOPP_CONSTANT(MIN_KEYLENGTH=32)
    //! \brief The maximum key length used by the algorithm provided as a constant
    //! \details MIN_KEYLENGTH is provided in bytes, not bits
    CRYPTOPP_CONSTANT(MAX_KEYLENGTH=128)
    //! \brief The default key length used by the algorithm provided as a constant
    //! \details MIN_KEYLENGTH is provided in bytes, not bits
    CRYPTOPP_CONSTANT(DEFAULT_KEYLENGTH=32)
    //! \brief The default IV requirements for the algorithm provided as a constant
    //! \details The default value is NOT_RESYNCHRONIZABLE. See IV_Requirement
    //!  in cryptlib.h for allowed values.
    CRYPTOPP_CONSTANT(IV_REQUIREMENT=SimpleKeyingInterface::UNIQUE_IV)
    //! \brief The default initialization vector length for the algorithm provided as a constant
    //! \details IV_LENGTH is provided in bytes, not bits.
    CRYPTOPP_CONSTANT(IV_LENGTH=32)
    //! \brief Provides a valid key length for the algorithm provided by a static function.
    //! \param keylength the size of the key, in bytes
    //! \details Threefish uses 256, 512 and 1024-bit keys. The block size follows key length.
    CRYPTOPP_STATIC_CONSTEXPR size_t CRYPTOPP_API StaticGetValidKeyLength(size_t keylength)
    {
        // Valid key lengths are 256, 512 and 1024 bits
        return (keylength >= 128) ? 128 :
            (keylength >= 64) ? 64 : 32;
    }

    CRYPTOPP_STATIC_CONSTEXPR size_t CRYPTOPP_API StaticGetValidBlockSize(size_t keylength)
    {
        return (keylength >= 128) ? 128 :
            (keylength >= 64) ? 64 : 32;
    }
};

//! \class Threefish1024
//! \brief Threefish-1024 block cipher
//! \sa <a href="http://www.weidai.com/scan-mirror/cs.html#Threefish">Threefish</a>
//! \since Crypto++ 6.0
class Threefish : public Threefish_Info, public BlockCipherDocumentation
{
public:
    class CRYPTOPP_NO_VTABLE Base : public VariableBlockCipherImpl<Threefish_Info>
    {
    public:
        std::string AlgorithmName() const {
            // Key length is the same as blocksize
            return m_blocksize ? "Threefish-" + IntToString(m_blocksize*8) : StaticAlgorithmName();
        }

        unsigned int OptimalDataAlignment() const {
            return GetAlignmentOf<word64>();
        }

    protected:
        void UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &params);

        typedef SecBlock<word64, AllocatorWithCleanup<word64, true> > AlignedSecBlock64;
        mutable AlignedSecBlock64 m_wspace;   // workspace
        AlignedSecBlock64         m_rkey;     // keys
        AlignedSecBlock64         m_tweak;
    };

    class CRYPTOPP_NO_VTABLE Enc : public Base
    {
    protected:
        void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

        void ProcessAndXorBlock_256(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
        void ProcessAndXorBlock_512(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
        void ProcessAndXorBlock_1024(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
    };

    class CRYPTOPP_NO_VTABLE Dec : public Base
    {
    protected:
        void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

        void ProcessAndXorBlock_256(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
        void ProcessAndXorBlock_512(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
        void ProcessAndXorBlock_1024(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
    };

public:
    typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
    typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

typedef Threefish::Encryption ThreefishEncryption;
typedef Threefish::Decryption ThreefishDecryption;

NAMESPACE_END

#endif  // CRYPTOPP_THREEFISH_H
