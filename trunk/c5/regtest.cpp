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
#include "panama.h"
#include "pssr.h"

USING_NAMESPACE(CryptoPP)

void RegisterFactories()
{
	static bool s_registered = false;
	if (s_registered)
		return;

	RegisterDefaultFactoryFor<SimpleKeyAgreementDomain, DH>();
	RegisterDefaultFactoryFor<HashTransformation, SHA1>();
	RegisterDefaultFactoryFor<HashTransformation, SHA224>();
	RegisterDefaultFactoryFor<HashTransformation, SHA256>();
#ifdef WORD64_AVAILABLE
	RegisterDefaultFactoryFor<HashTransformation, SHA384>();
	RegisterDefaultFactoryFor<HashTransformation, SHA512>();
	RegisterDefaultFactoryFor<HashTransformation, Whirlpool>();
#endif
	RegisterDefaultFactoryFor<HashTransformation, PanamaHash<LittleEndian> >();
	RegisterDefaultFactoryFor<HashTransformation, PanamaHash<BigEndian> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<MD5> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA1> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<RIPEMD160> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, TTMAC>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, PanamaMAC<LittleEndian> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, PanamaMAC<BigEndian> >();
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
	RegisterSymmetricCipherDefaultFactories<SEAL<> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<SHACAL2> >();
#ifdef WORD64_AVAILABLE
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<Camellia> >();
#endif
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<TEA> >();
	RegisterSymmetricCipherDefaultFactories<ECB_Mode<XTEA> >();
	RegisterSymmetricCipherDefaultFactories<PanamaCipher<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<PanamaCipher<BigEndian> >();

	s_registered = true;
}
