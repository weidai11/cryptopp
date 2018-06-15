// cham.h - written and placed in the public domain by Kim Sung Hee and Jeffrey Walton
//          Based on "CHAM: A Family of Lightweight Block Ciphers for
//          Resource-Constrained Devices" by Bonwook Koo, Dongyoung Roh,
//          Hyeonjin Kim, Younghoon Jung, Dong-Geon Lee, and Daesung Kwon

/// \file cham.h
/// \brief Classes for the CHAM block cipher
/// \since Crypto++ 7.1

#ifndef CRYPTOPP_CHAM_H
#define CRYPTOPP_CHAM_H

#include "config.h"
#include "seckey.h"
#include "secblock.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief CHAM block cipher information
/// \since Crypto++ 7.1
struct CHAM64_Info : public FixedBlockSize<8>, FixedKeyLength<16>
{
    static const std::string StaticAlgorithmName()
    {
        // Format is Cipher-Blocksize
        return "CHAM-64";
    }
};

/// \brief CHAM block cipher information
/// \since Crypto++ 7.1
struct CHAM128_Info : public FixedBlockSize<16>, VariableKeyLength<16,16,32,16>
{
    static const std::string StaticAlgorithmName()
    {
        // Format is Cipher-Blocksize
        return "CHAM-128";
    }
};

/// \brief CHAM 64-bit block cipher
/// \details CHAM64 provides 64-bit block size. The valid key size is 128-bit.
/// \note Crypto++ provides a byte oriented implementation
/// \sa CHAM128, <a href="http://www.cryptopp.com/wiki/CHAM">CHAM</a>, <a href=
///   "https://pdfs.semanticscholar.org/2f57/61b5c2614cffd58a09cc83c375a2b32a2ed3.pdf">
///   CHAM: A Family of Lightweight Block Ciphers for Resource-Constrained Devices</a>
/// \since Crypto++ 7.1
class CRYPTOPP_NO_VTABLE CHAM64 : public CHAM64_Info, public BlockCipherDocumentation
{
public:
    /// \brief CHAM block cipher transformation functions
    /// \details Provides implementation common to encryption and decryption
    /// \since Crypto++ 7.1
    class CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<CHAM64_Info>
    {
    protected:
        void UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params);

        SecBlock<word16> m_rk;
        mutable FixedSizeSecBlock<word16, 4> m_x;
        unsigned int m_kw;
    };

    /// \brief Provides implementation for encryption transformation
    /// \details Enc provides implementation for encryption transformation. All key and block
    ///   sizes are supported.
    /// \since Crypto++ 7.1
    class CRYPTOPP_NO_VTABLE Enc : public Base
    {
    public:
        void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
    };

    /// \brief Provides implementation for encryption transformation
    /// \details Dec provides implementation for decryption transformation. All key and block
    ///   sizes are supported.
    /// \since Crypto++ 7.1
    class CRYPTOPP_NO_VTABLE Dec : public Base
    {
    public:
        void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
    };

    typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
    typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

typedef CHAM64::Encryption CHAM64Encryption;
typedef CHAM64::Decryption CHAM64Decryption;

/// \brief CHAM 128-bit block cipher
/// \details CHAM128 provides 128-bit block size. The valid key size is 128-bit and 256-bit.
/// \note Crypto++ provides a byte oriented implementation
/// \sa CHAM128, <a href="http://www.cryptopp.com/wiki/CHAM">CHAM</a>, <a href=
///   "https://pdfs.semanticscholar.org/2f57/61b5c2614cffd58a09cc83c375a2b32a2ed3.pdf">
///   CHAM: A Family of Lightweight Block Ciphers for Resource-Constrained Devices</a>
/// \since Crypto++ 7.1
class CRYPTOPP_NO_VTABLE CHAM128 : public CHAM128_Info, public BlockCipherDocumentation
{
public:
    /// \brief CHAM block cipher transformation functions
    /// \details Provides implementation common to encryption and decryption
    /// \since Crypto++ 7.1
    class CRYPTOPP_NO_VTABLE Base : public BlockCipherImpl<CHAM128_Info>
    {
    protected:
        void UncheckedSetKey(const byte *userKey, unsigned int keyLength, const NameValuePairs &params);

        SecBlock<word32> m_rk;
        mutable FixedSizeSecBlock<word32, 4> m_x;
        unsigned int m_kw;
    };

    /// \brief Provides implementation for encryption transformation
    /// \details Enc provides implementation for encryption transformation. All key and block
    ///   sizes are supported.
    /// \since Crypto++ 7.1
    class CRYPTOPP_NO_VTABLE Enc : public Base
    {
    public:
        void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
    };

    /// \brief Provides implementation for encryption transformation
    /// \details Dec provides implementation for decryption transformation. All key and block
    ///   sizes are supported.
    /// \since Crypto++ 7.1
    class CRYPTOPP_NO_VTABLE Dec : public Base
    {
    public:
        void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;
    };

    typedef BlockCipherFinal<ENCRYPTION, Enc> Encryption;
    typedef BlockCipherFinal<DECRYPTION, Dec> Decryption;
};

typedef CHAM128::Encryption CHAM128Encryption;
typedef CHAM128::Decryption CHAM128Decryption;

NAMESPACE_END

#endif  // CRYPTOPP_CHAM_H
