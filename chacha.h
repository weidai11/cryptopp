// chacha.h - written and placed in the public domain by Jeffrey Walton.
//            Based on Wei Dai's Salsa20, Botan's SSE2 implementation,
//            and Bernstein's reference ChaCha family implementation at
//            http://cr.yp.to/chacha.html.

/// \file chacha.h
/// \brief Classes for ChaCha8, ChaCha12 and ChaCha20 stream ciphers
/// \details Crypto++ provides Bernstein and ECRYPT's ChaCha from <a href="http://cr.yp.to/chacha/chacha-20080128.pdf">ChaCha,
///   a variant of Salsa20</a> (2008.01.28). Bernstein's implementation is _slightly_ different from the TLS working group's
///   implementation for cipher suites <tt>TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256</tt>,
///   <tt>TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256</tt>, and <tt>TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256</tt>.
/// \since Crypto++ 5.6.4

#ifndef CRYPTOPP_CHACHA_H
#define CRYPTOPP_CHACHA_H

#include "strciphr.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief ChaCha stream cipher information
/// \since Crypto++ 5.6.4
struct ChaCha_Info : public VariableKeyLength<32, 16, 32, 16, SimpleKeyingInterface::UNIQUE_IV, 8>
{
    /// \brief The algorithm name
    /// \returns the algorithm name
    /// \details StaticAlgorithmName returns the algorithm's name as a static
    ///   member function.
    /// \details Bernstein named the cipher variants ChaCha8, ChaCha12 and
    ///   ChaCha20. More generally, Bernstein called the family ChaCha{r}.
    ///   AlgorithmName() provides the exact name once rounds are set.
    static const char* StaticAlgorithmName() {
        return "ChaCha";
    }
};

/// \brief ChaCha stream cipher implementation
/// \since Crypto++ 5.6.4
class CRYPTOPP_NO_VTABLE ChaCha_Policy : public AdditiveCipherConcretePolicy<word32, 16>
{
public:
	~ChaCha_Policy() {}
	ChaCha_Policy() : m_rounds(0) {}

protected:
    void CipherSetKey(const NameValuePairs &params, const byte *key, size_t length);
    void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount);
    void CipherResynchronize(byte *keystreamBuffer, const byte *IV, size_t length);
    bool CipherIsRandomAccess() const {return true;}
    void SeekToIteration(lword iterationCount);
    unsigned int GetAlignment() const;
    unsigned int GetOptimalBlockSize() const;

    std::string AlgorithmName() const;
    std::string AlgorithmProvider() const;

    // MultiBlockSafe detects a condition that can arise in the SIMD
    // implementations where we overflow one of the 32-bit state words
    // during addition in an intermediate result. Conditions to trigger
    // issue include a user seeks to around 2^32 blocks (256 GB of data).
    // https://github.com/weidai11/cryptopp/issues/732
    inline bool MultiBlockSafe(unsigned int blocks) const;

    FixedSizeAlignedSecBlock<word32, 16> m_state;
    unsigned int m_rounds;
};

/// \brief ChaCha stream cipher
/// \details Bernstein and ECRYPT's ChaCha is _slightly_ different from the TLS working
///   group's implementation for cipher suites
///   <tt>TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256</tt>,
///   <tt>TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256</tt>, and
///   <tt>TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256</tt>.
/// \sa <a href="http://cr.yp.to/chacha/chacha-20080208.pdf">ChaCha, a variant of Salsa20</a> (2008.01.28).
/// \since Crypto++ 5.6.4
struct ChaCha : public ChaCha_Info, public SymmetricCipherDocumentation
{
    typedef SymmetricCipherFinal<ConcretePolicyHolder<ChaCha_Policy, AdditiveCipherTemplate<> >, ChaCha_Info > Encryption;
    typedef Encryption Decryption;
};

NAMESPACE_END

#endif  // CRYPTOPP_CHACHA_H
