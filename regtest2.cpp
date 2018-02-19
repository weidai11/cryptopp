// regtest2.cpp - originally written and placed in the public domain by Wei Dai
//                regtest.cpp split into 3 files due to OOM kills by JW in April 2017

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "factory.h"
#include "bench.h"
#include "cpu.h"

#include "modes.h"
#include "seal.h"
#include "ttmac.h"
#include "aria.h"
#include "camellia.h"
#include "shacal2.h"
#include "tea.h"
#include "aes.h"
#include "salsa.h"
#include "chacha.h"
#include "vmac.h"
#include "tiger.h"
#include "sosemanuk.h"
#include "arc4.h"
#include "ccm.h"
#include "gcm.h"
#include "eax.h"
#include "twofish.h"
#include "serpent.h"
#include "cast.h"
#include "rc6.h"
#include "mars.h"
#include "kalyna.h"
#include "threefish.h"
#include "simon.h"
#include "speck.h"
#include "sm4.h"
#include "des.h"
#include "idea.h"
#include "rc5.h"
#include "tea.h"
#include "skipjack.h"
#include "cmac.h"
#include "dmac.h"
#include "blowfish.h"
#include "seed.h"
#include "wake.h"
#include "hkdf.h"

// For HMAC's
#include "md5.h"
#include "keccak.h"
#include "sha.h"
#include "sha3.h"
#include "blake2.h"
#include "ripemd.h"
#include "poly1305.h"
#include "siphash.h"
#include "whrlpool.h"
#include "panama.h"

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

USING_NAMESPACE(CryptoPP)

// Shared key ciphers
void RegisterFactories2()
{
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<Weak::MD5> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<RIPEMD160> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA1> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA224> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA256> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA384> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA512> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, TTMAC>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, VMAC<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, VMAC<AES, 64> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, Weak::PanamaMAC<LittleEndian> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, Weak::PanamaMAC<BigEndian> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, CMAC<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, DMAC<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, Poly1305<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, CMAC<DES_EDE3> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, BLAKE2s>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, BLAKE2b>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, SipHash<2,4> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, SipHash<4,8> >();

	RegisterSymmetricCipherDefaultFactories<SEAL<> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SHACAL2> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<ARIA> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Camellia> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<TEA> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<XTEA> >();
	RegisterSymmetricCipherDefaultFactories<PanamaCipher<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<PanamaCipher<BigEndian> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<AES> >();
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<AES> >();
	RegisterSymmetricCipherDefaultFactories<CFB_Mode<AES> >();
	RegisterSymmetricCipherDefaultFactories<OFB_Mode<AES> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<AES> >();
	RegisterSymmetricCipherDefaultFactories<Salsa20>();
	RegisterSymmetricCipherDefaultFactories<XSalsa20>();
	RegisterSymmetricCipherDefaultFactories<ChaCha8>();
	RegisterSymmetricCipherDefaultFactories<ChaCha12>();
	RegisterSymmetricCipherDefaultFactories<ChaCha20>();
	RegisterSymmetricCipherDefaultFactories<Sosemanuk>();
	RegisterSymmetricCipherDefaultFactories<Weak::MARC4>();
	RegisterSymmetricCipherDefaultFactories<WAKE_OFB<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<WAKE_OFB<BigEndian> >();
	RegisterSymmetricCipherDefaultFactories<SEAL<LittleEndian> >();
	RegisterAuthenticatedSymmetricCipherDefaultFactories<CCM<AES> >();
	RegisterAuthenticatedSymmetricCipherDefaultFactories<GCM<AES> >();
	RegisterAuthenticatedSymmetricCipherDefaultFactories<EAX<AES> >();
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<ARIA> >();  // For test vectors
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<ARIA> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Camellia> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Twofish> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Serpent> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<CAST256> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<RC6> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<MARS> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<MARS> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<SHACAL2> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<DES> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<DES_XEX3> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<DES_EDE3> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<IDEA> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<RC5> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<TEA> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<XTEA> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<CAST128> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<SKIPJACK> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Blowfish> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SEED> >();
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<SEED> >();

	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Kalyna128> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<Kalyna128> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Kalyna256> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<Kalyna256> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Kalyna512> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<Kalyna512> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Kalyna128> >();  // Benchmarks
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Kalyna256> >();  // Benchmarks
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Kalyna512> >();  // Benchmarks

	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Threefish256> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<Threefish256> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Threefish512> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<Threefish512> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Threefish1024> >(); // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<Threefish1024> >(); // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Threefish256> >();  // Benchmarks
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Threefish512> >();  // Benchmarks
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<Threefish1024> >(); // Benchmarks

	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SIMON64> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<SIMON64> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SIMON128> >(); // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<SIMON128> >(); // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<SIMON64> >();  // Benchmarks
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<SIMON128> >();  // Benchmarks

	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SPECK64> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<SPECK64> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SPECK128> >(); // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<SPECK128> >(); // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<SPECK64> >();  // Benchmarks
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<SPECK128> >(); // Benchmarks

	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SM4> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CBC_Mode<SM4> >();  // Test Vectors
	RegisterSymmetricCipherDefaultFactories<CTR_Mode<SM4> >();  // Benchmarks

	RegisterDefaultFactoryFor<KeyDerivationFunction, HKDF<SHA1> >();
	RegisterDefaultFactoryFor<KeyDerivationFunction, HKDF<SHA256> >();
	RegisterDefaultFactoryFor<KeyDerivationFunction, HKDF<SHA512> >();
	RegisterDefaultFactoryFor<KeyDerivationFunction, HKDF<Whirlpool> >();
}
