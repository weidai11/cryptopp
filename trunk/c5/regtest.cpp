#include "factory.h"

#include "modes.h"
#include "dh.h"
#include "esign.h"
#include "md2.h"
#include "trunhash.h"
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

USING_NAMESPACE(CryptoPP)

void RegisterFactories()
{
	RegisterDefaultFactoryFor<SimpleKeyAgreementDomain, DH>("DH");
	RegisterDefaultFactoryFor<HashTransformation, SHA1>("SHA-1");
	RegisterDefaultFactoryFor<HashTransformation, SHA256>("SHA-256");
#ifdef WORD64_AVAILABLE
	RegisterDefaultFactoryFor<HashTransformation, SHA384>("SHA-384");
	RegisterDefaultFactoryFor<HashTransformation, SHA512>("SHA-512");
#endif
	RegisterDefaultFactoryFor<HashTransformation, Whirlpool>("Whirlpool");
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<MD5> >("HMAC(MD5)");
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA1> >("HMAC(SHA-1)");
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<RIPEMD160> >("HMAC(RIPEMD-160)");
	RegisterDefaultFactoryFor<MessageAuthenticationCode, TTMAC >("Two-Track-MAC");
	RegisterAsymmetricCipherDefaultFactories<RSAES<OAEP<SHA1> > >("RSA/OAEP-MGF1(SHA-1)");
	RegisterAsymmetricCipherDefaultFactories<DLIES<> >("DLIES(NoCofactorMultiplication, KDF2(SHA-1), XOR, HMAC(SHA-1), DHAES)");
	RegisterSignatureSchemeDefaultFactories<DSA>("DSA(1363)");
	RegisterSignatureSchemeDefaultFactories<NR<SHA1> >("NR(1363)/EMSA1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<GDSA<SHA1> >("DSA-1363/EMSA1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<RSASS<PKCS1v15, MD2> >("RSA/PKCS1-1.5(MD2)");
	RegisterSignatureSchemeDefaultFactories<RSASS<PKCS1v15, SHA1> >("RSA/PKCS1-1.5(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<ESIGN<SHA1> >("ESIGN/EMSA5-MGF1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<RWSS<P1363_EMSA2, SHA1> >("RW/EMSA2(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<RSASS<PSS, SHA1> >("RSA/PSS-MGF1(SHA-1)");
	RegisterSymmetricCipherDefaultFactories<SEAL<> >("SEAL-3.0-BE");
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SHACAL2> >("SHACAL-2(ECB)");
#ifdef WORD64_AVAILABLE
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Camellia> >("Camellia(ECB)");
#endif
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<TEA> >("TEA(ECB)");
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<XTEA> >("XTEA(ECB)");
}
