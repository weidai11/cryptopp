#include "factory.h"

#include "dh.h"
#include "esign.h"
#include "md2.h"
#include "trunhash.h"
#include "rw.h"
#include "md5.h"
#include "rsa.h"
#include "ripemd.h"
#include "dsa.h"

USING_NAMESPACE(CryptoPP)

void RegisterFactories()
{
	RegisterDefaultFactoryFor<SimpleKeyAgreementDomain, DH>("DH");
	RegisterDefaultFactoryFor<HashTransformation, SHA1>("SHA-1");
	RegisterDefaultFactoryFor<HashTransformation, SHA256>("SHA-256");
	RegisterDefaultFactoryFor<HashTransformation, SHA384>("SHA-384");
	RegisterDefaultFactoryFor<HashTransformation, SHA512>("SHA-512");
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<MD5> >("HMAC(MD5)");
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA1> >("HMAC(SHA-1)");
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<RIPEMD160> >("HMAC(RIPEMD-160)");
	RegisterPublicKeyCryptoSystemDefaultFactories<RSAES<OAEP<SHA1> > >("RSA/OAEP-MGF1(SHA-1)");
	RegisterPublicKeyCryptoSystemDefaultFactories<DLIES<> >("DLIES(NoCofactorMultiplication, KDF2(SHA-1), XOR, HMAC(SHA-1), DHAES)");
	RegisterSignatureSchemeDefaultFactories<DSA>("DSA(1363)");
	RegisterSignatureSchemeDefaultFactories<NR<SHA1> >("NR(1363)/EMSA1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<GDSA<SHA1> >("DSA-1363/EMSA1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<RSASSA<PKCS1v15, MD2> >("RSA/PKCS1-1.5(MD2)");
	RegisterSignatureSchemeDefaultFactories<RSASSA<PKCS1v15, SHA1> >("RSA/PKCS1-1.5(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<ESIGN<SHA1> >("ESIGN/EMSA5-MGF1(SHA-1)");
	RegisterSignatureSchemeDefaultFactories<RWSSA<SHA1> >("RW/EMSA2(SHA-1)");
}
