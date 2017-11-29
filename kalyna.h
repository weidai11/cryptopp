// kalyna.h - written and placed in the public domain by Jeffrey Walton
//            Based on public domain code by Keru Kuro.

/// \file kalyna.h
/// \brief Classes for the Kalyna block cipher
/// \details The Crypto++ implementation relied upon three sources. First was Oliynykov, Gorbenko, Kazymyrov,
///   Ruzhentsev, Kuznetsov, Gorbenko, Dyrda, Dolgov, Pushkaryov, Mordvinov and Kaidalov's "A New Encryption
///   Standard of Ukraine: The Kalyna Block Cipher" (http://eprint.iacr.org/2015/650.pdf). Second was Roman
///   Oliynykov and Oleksandr Kazymyrov's GitHub with the reference implementation
///   (http://github.com/Roman-Oliynykov/Kalyna-reference). The third resource was Keru Kuro's implementation
///   of Kalyna in CppCrypto (http://sourceforge.net/projects/cppcrypto/). Kuro has an outstanding
///   implementation that performed better than the reference implementation and our initial attempts.

#ifndef CRYPTOPP_KALYNA_H
#define CRYPTOPP_KALYNA_H

#include "config.h"
#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// \class Kalyna_Info
/// \brief Kalyna block cipher information
/// \details Kalyna key sizes and block sizes do not fit well into the library. Rather
///   than using VariableKeyLength (which is wrong) or using a GeometricKeyLength
///   (a new class), we just unroll it here. Note that the step size, Q, is still
///   wrong for this implementation.
/// \since Crypto++ 6.0
struct Kalyna_Info : public VariableBlockSize<16, 16, 64>
{
    CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "Kalyna";}

    /// \brief The minimum key length used by the algorithm provided as a constant
    /// \details MIN_KEYLENGTH is provided in bytes, not bits
    CRYPTOPP_CONSTANT(MIN_KEYLENGTH=16)
    /// \brief The maximum key length used by the algorithm provided as a constant
    /// \details MIN_KEYLENGTH is provided in bytes, not bits
    CRYPTOPP_CONSTANT(MAX_KEYLENGTH=64)
    /// \brief The default key length used by the algorithm provided as a constant
    /// \details MIN_KEYLENGTH is provided in bytes, not bits
    CRYPTOPP_CONSTANT(DEFAULT_KEYLENGTH=16)
    /// \brief The default IV requirements for the algorithm provided as a constant
    /// \details The default value is NOT_RESYNCHRONIZABLE. See IV_Requirement
    ///  in cryptlib.h for allowed values.
    CRYPTOPP_CONSTANT(IV_REQUIREMENT=SimpleKeyingInterface::UNIQUE_IV)
    /// \brief The default initialization vector length for the algorithm provided as a constant
    /// \details IV_LENGTH is provided in bytes, not bits. Kalyna has two different block sizes for
    ///   each key length. This function returns the default block size for the defult key length.
    CRYPTOPP_CONSTANT(IV_LENGTH=16)
    /// \brief Provides a valid key length for the algorithm provided by a static function.
    /// \param keylength the size of the key, in bytes
    /// \details The key length depends on the block size. For each block size, 128, 256 and 512,
    ///   the key length can be either the block size or twice the block size. That means the
    ///   valid key lengths are 126, 256, 512 and 1024. Additionally, it means a key length of,
    ///   say, 32 could be used with either 128-block size or 256-block size.
    CRYPTOPP_STATIC_CONSTEXPR size_t CRYPTOPP_API StaticGetValidKeyLength(size_t keylength)
    {
        return (keylength >= 64) ? 64 :
            (keylength >= 32) ? 32 : 16;
    }

    /// \brief Validates the blocksize for Kalyna.
    /// \param blocksize the candidate blocksize
    /// \param alg an Algorithm object used if the blocksize is invalid
    /// \throws InvalidBlockSize if the blocksize is invalid
    /// \details ThrowIfInvalidBlockSize() validates the blocksize and throws if invalid.
    inline void ThrowIfInvalidBlockSize(int blocksize, const Algorithm *alg)
    {
        if ( blocksize != 16 &&  blocksize != 32 && blocksize != 64)
            throw InvalidBlockSize(alg ? alg->AlgorithmName() : std::string("VariableBlockSize"), blocksize);
    }

    /// \brief Validates the blocksize for Kalyna.
    /// \param keylength the key length of the cipher
    /// \param blocksize the candidate blocksize
    /// \param alg an Algorithm object used if the blocksize is invalid
    /// \throws InvalidBlockSize if the blocksize is invalid
    /// \details ThrowIfInvalidBlockSize() validates the blocksize under a key and throws if invalid.
    inline void ThrowIfInvalidBlockSize(int keylength, int blocksize, const Algorithm *alg)
    {
        if ( ((keylength == 16) && (blocksize != 16)) ||
                ((keylength == 32) && (blocksize != 32 && blocksize != 64)) ||
                ((keylength == 64) && (blocksize != 32 && blocksize != 64)) )
        {
            throw InvalidBlockSize(alg ? alg->AlgorithmName() : std::string("VariableBlockSize"), blocksize);
        }
    }
};

/// \class Kalyna
/// \brief Kalyna block cipher
/// \since Crypto++ 6.0
class Kalyna : public Kalyna_Info, public BlockCipherDocumentation
{
public:
    class CRYPTOPP_NO_VTABLE Base : public VariableBlockCipherImpl<Kalyna_Info>
    {
    public:
        /// \brief Provides the name of this algorithm
        /// \return the standard algorithm name
        /// \details If the object is unkeyed, then the generic name "Kalyna" is returned
        ///   to the caller. If the algorithm is keyed, then a two or three part name is
        ///   returned to the caller. The name follows DSTU 7624:2014, where block size is
        ///   provided first and then key length. The library uses a dash to identify block size
        ///   and parenthesis to identify key length. For example, Kalyna-128(256) is Kalyna
        ///   with a 128-bit block size and a 256-bit key length. If a mode is associated
        ///   with the object, then it follows as expected. For example, Kalyna-128(256)/ECB.
        ///   DSTU is a little more complex with more parameters, dashes, underscores, but the
        ///   library does not use the delimiters or full convention.
        std::string AlgorithmName() const {
            return m_blocksize ? "Kalyna-" + IntToString(m_blocksize*8) + "(" + IntToString(m_kl*8) + ")" : StaticAlgorithmName();
        }

        unsigned int OptimalDataAlignment() const {
            return GetAlignmentOf<word64>();
        }

    protected:
        void UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &params);
        void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const;

    protected:
        // Visual Studio and C2910: 'Kalyna::Base::SetKey_Template': cannot be explicitly specialized
        //template <unsigned int NB, unsigned int NK>
        //  void SetKey_Template(const word64 key[NK]);
        void SetKey_22(const word64 key[2]);
        void SetKey_24(const word64 key[4]);
        void SetKey_44(const word64 key[4]);
        void SetKey_48(const word64 key[8]);
        void SetKey_88(const word64 key[8]);

        // Visual Studio and C2910: 'Kalyna::Base::ProcessBlock_Template': cannot be explicitly specialized
        //template <unsigned int NB, unsigned int NK>
        //  void ProcessBlock_Template(const word64 inBlock[NB], const word64 outBlock[NB]) const;
        void ProcessBlock_22(const word64 inBlock[2], const word64 xorBlock[2], word64 outBlock[2]) const;
        void ProcessBlock_24(const word64 inBlock[2], const word64 xorBlock[2] ,word64 outBlock[2]) const;
        void ProcessBlock_44(const word64 inBlock[4], const word64 xorBlock[4], word64 outBlock[4]) const;
        void ProcessBlock_48(const word64 inBlock[4], const word64 xorBlock[4], word64 outBlock[4]) const;
        void ProcessBlock_88(const word64 inBlock[8], const word64 xorBlock[8], word64 outBlock[8]) const;

    private:
        typedef SecBlock<word64, AllocatorWithCleanup<word64, true> > AlignedSecBlock64;
        mutable AlignedSecBlock64 m_wspace;  // work space
        AlignedSecBlock64         m_mkey;    // master key
        AlignedSecBlock64         m_rkeys;   // round keys
        unsigned int     m_kl, m_nb, m_nk;   // key length, number 64-bit blocks and keys
    };

    typedef BlockCipherFinal<ENCRYPTION, Base> Encryption;
    typedef BlockCipherFinal<DECRYPTION, Base> Decryption;
};

typedef Kalyna::Encryption KalynaEncryption;
typedef Kalyna::Decryption KalynaDecryption;

NAMESPACE_END

#endif  // CRYPTOPP_KALYNA_H
