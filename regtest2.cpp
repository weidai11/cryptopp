// regtest2.cpp - originally written and placed in the public domain by Wei Dai
//                regtest.cpp split into 3 files due to OOM kills by JW
//                in April 2017. A second split occured in July 2018.

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/cryptlib.h>
#include "factory.h"
#include "bench.h"
#include "cpu.h"

// For MAC's
#include <cryptopp/hmac.h>
#include <cryptopp/cmac.h>
#include <cryptopp/dmac.h>
#include <cryptopp/vmac.h>
#include <cryptopp/ttmac.h>

// Ciphers
#include <cryptopp/md5.h>
#include <cryptopp/keccak.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/blake2.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/poly1305.h>
#include <cryptopp/siphash.h>
#include <cryptopp/panama.h>

// Stream ciphers
#include <cryptopp/arc4.h>
#include <cryptopp/seal.h>
#include <cryptopp/wake.h>
#include <cryptopp/chacha.h>
#include <cryptopp/salsa.h>
#include <cryptopp/rabbit.h>
#include <cryptopp/hc128.h>
#include <cryptopp/hc256.h>
#include <cryptopp/panama.h>
#include <cryptopp/sosemanuk.h>

// Block for CMAC
#include <cryptopp/aes.h>
#include <cryptopp/des.h>

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

USING_NAMESPACE(CryptoPP)

// MAC ciphers
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
}

// Stream ciphers
void RegisterFactories3()
{
	RegisterSymmetricCipherDefaultFactories<Weak::MARC4>();
	RegisterSymmetricCipherDefaultFactories<SEAL<> >();
	RegisterSymmetricCipherDefaultFactories<SEAL<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<WAKE_OFB<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<WAKE_OFB<BigEndian> >();
	RegisterSymmetricCipherDefaultFactories<PanamaCipher<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<PanamaCipher<BigEndian> >();

	RegisterSymmetricCipherDefaultFactories<Salsa20>();
	RegisterSymmetricCipherDefaultFactories<XSalsa20>();
	RegisterSymmetricCipherDefaultFactories<ChaCha>();
	RegisterSymmetricCipherDefaultFactories<Sosemanuk>();
	RegisterSymmetricCipherDefaultFactories<Rabbit>();
	RegisterSymmetricCipherDefaultFactories<RabbitWithIV>();
	RegisterSymmetricCipherDefaultFactories<HC128>();
	RegisterSymmetricCipherDefaultFactories<HC256>();
}
