#include "factory.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "modes.h"
#include "dh.h"
#include "esign.h"
#include "md2.h"
#include "rw.h"
#include "md5.h"
#include "rsa.h"
#include "ripemd.h"
#include "dsa.h"
#include "seal.h"
#include "whrlpool.h"
#include "ttmac.h"
#include "camellia.h"
#include "shacal2.h"
#include "tea.h"
#include "panama.h"
#include "pssr.h"
#include "aes.h"
#include "salsa.h"
#include "vmac.h"
#include "tiger.h"
#include "md5.h"
#include "sosemanuk.h"
#include "arc4.h"

USING_NAMESPACE(CryptoPP)

void RegisterFactories()
{
	static bool s_registered = false;
	if (s_registered)
		return;

	RegisterDefaultFactoryFor<SimpleKeyAgreementDomain, DH>();
	RegisterDefaultFactoryFor<HashTransformation, Weak::MD5>();
	RegisterDefaultFactoryFor<HashTransformation, SHA1>();
	RegisterDefaultFactoryFor<HashTransformation, SHA224>();
	RegisterDefaultFactoryFor<HashTransformation, SHA256>();
#ifdef WORD64_AVAILABLE
	RegisterDefaultFactoryFor<HashTransformation, SHA384>();
	RegisterDefaultFactoryFor<HashTransformation, SHA512>();
	RegisterDefaultFactoryFor<HashTransformation, Whirlpool>();
	RegisterDefaultFactoryFor<HashTransformation, Tiger>();
#endif
	RegisterDefaultFactoryFor<HashTransformation, RIPEMD160>();
	RegisterDefaultFactoryFor<HashTransformation, RIPEMD320>();
	RegisterDefaultFactoryFor<HashTransformation, RIPEMD128>();
	RegisterDefaultFactoryFor<HashTransformation, RIPEMD256>();
	RegisterDefaultFactoryFor<HashTransformation, Weak::PanamaHash<LittleEndian> >();
	RegisterDefaultFactoryFor<HashTransformation, Weak::PanamaHash<BigEndian> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<Weak::MD5> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA1> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<RIPEMD160> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, TTMAC>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, VMAC<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, VMAC<AES, 64> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, Weak::PanamaMAC<LittleEndian> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, Weak::PanamaMAC<BigEndian> >();
	RegisterAsymmetricCipherDefaultFactories<RSAES<OAEP<SHA1> > >("RSA/OAEP-MGF1(SHA-1)");
	RegisterAsymmetricCipherDefaultFactories<DLIES<> >("DLIES(NoCofactorMultiplication, KDF2(SHA-1), XOR, HMAC(SHA-1), DHAES)");
	RegisterSignatureSchemeDefaultFactories<DSA>("DSA(1363)");
	RegisterSignatureSchemeDefaultFactories<NR<SHA1> >("NR(1363)/EMSA1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<GDSA<SHA1> >("DSA-1363/EMSA1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<RSASS<PKCS1v15, Weak::MD2> >("RSA/PKCS1-1.5(MD2)");
	RegisterSignatureSchemeDefaultFactories<RSASS<PKCS1v15, SHA1> >("RSA/PKCS1-1.5(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<ESIGN<SHA1> >("ESIGN/EMSA5-MGF1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<RWSS<P1363_EMSA2, SHA1> >("RW/EMSA2(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<RSASS<PSS, SHA1> >("RSA/PSS-MGF1(SHA-1)");
	RegisterSymmetricCipherDefaultFactories<SEAL<> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SHACAL2> >();
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
	RegisterSymmetricCipherDefaultFactories<Sosemanuk>();
	RegisterSymmetricCipherDefaultFactories<Weak::MARC4>();

	s_registered = true;
}
