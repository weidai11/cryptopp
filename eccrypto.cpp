// eccrypto.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"

#include "config.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(push)
# pragma warning(disable: 4127 4189 4505)
#endif

#if CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wunused-function"
#endif

#ifndef CRYPTOPP_IMPORTS

#include "eccrypto.h"
#include "integer.h"
#include "nbtheory.h"
#include "filters.h"
#include "argnames.h"
#include "smartptr.h"
#include "oids.h"
#include "asn.h"
#include "hex.h"
#include "ec2n.h"
#include "misc.h"

#include <iostream>
#include <sstream>

// Squash MS LNK4221 and libtool warnings
#ifndef CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
extern const char ECCRYPTO_FNAME[] = __FILE__;
#endif

NAMESPACE_BEGIN(CryptoPP)

#if 0
#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
static void ECDSA_TestInstantiations()
{
	ECDSA<EC2N>::Signer t1;
	ECDSA<EC2N>::Verifier t2(t1);
	ECNR<ECP>::Signer t3;
	ECNR<ECP>::Verifier t4(t3);
	ECIES<ECP>::Encryptor t5;
	ECIES<EC2N>::Decryptor t6;
	ECDH<ECP>::Domain t7;
	ECMQV<ECP>::Domain t8;
}
#endif
#endif

ANONYMOUS_NAMESPACE_BEGIN
inline Integer ConvertToInteger(const PolynomialMod2 &x)
{
	unsigned int l = x.ByteCount();
	SecByteBlock temp(l);
	x.Encode(temp, l);
	return Integer(temp, l);
}

inline Integer ConvertToInteger(const Integer &x)
{
	return x;
}

inline bool CheckMOVCondition(const Integer &q, const Integer &r)
{
	// see "Updated standards for validating elliptic curves", http://eprint.iacr.org/2007/343
	Integer t = 1;
	unsigned int n = q.IsEven() ? 1 : q.BitCount(), m = r.BitCount();

	for (unsigned int i=n; DiscreteLogWorkFactor(i)<m/2; i+=n)
	{
		if (q.IsEven())
			t = (t+t)%r;
		else
			t = (t*q)%r;
		if (t == 1)
			return false;
	}
	return true;
}
ANONYMOUS_NAMESPACE_END

// ******************************************************************

template <class T> struct EcRecommendedParameters;

template<> struct EcRecommendedParameters<EC2N>
{
	EcRecommendedParameters(const OID &oid, unsigned int t2, unsigned int t3, unsigned int t4, const char *a, const char *b, const char *g, const char *n, unsigned int h)
		: oid(oid), a(a), b(b), g(g), n(n), h(h), t0(0), t1(0), t2(t2), t3(t3), t4(t4) {}
	EcRecommendedParameters(const OID &oid, unsigned int t0, unsigned int t1, unsigned int t2, unsigned int t3, unsigned int t4, const char *a, const char *b, const char *g, const char *n, unsigned int h)
		: oid(oid), a(a), b(b), g(g), n(n), h(h), t0(t0), t1(t1), t2(t2), t3(t3), t4(t4) {}
	EC2N *NewEC() const
	{
		StringSource ssA(a, true, new HexDecoder);
		StringSource ssB(b, true, new HexDecoder);
		if (t0 == 0)
		{
			if (t2 == 233 && t3 == 74 && t4 == 0)
				return new EC2N(GF2NT233(233, 74, 0), EC2N::FieldElement(ssA, (size_t)ssA.MaxRetrievable()), EC2N::FieldElement(ssB, (size_t)ssB.MaxRetrievable()));
			else
				return new EC2N(GF2NT(t2, t3, t4), EC2N::FieldElement(ssA, (size_t)ssA.MaxRetrievable()), EC2N::FieldElement(ssB, (size_t)ssB.MaxRetrievable()));
		}
		else
			return new EC2N(GF2NPP(t0, t1, t2, t3, t4), EC2N::FieldElement(ssA, (size_t)ssA.MaxRetrievable()), EC2N::FieldElement(ssB, (size_t)ssB.MaxRetrievable()));
	};

	OID oid;
	const char *a, *b, *g, *n;
	unsigned int h, t0, t1, t2, t3, t4;
};

template<> struct EcRecommendedParameters<ECP>
{
	EcRecommendedParameters(const OID &oid, const char *p, const char *a, const char *b, const char *g, const char *n, unsigned int h)
		: oid(oid), p(p), a(a), b(b), g(g), n(n), h(h) {}
	ECP *NewEC() const
	{
		StringSource ssP(p, true, new HexDecoder);
		StringSource ssA(a, true, new HexDecoder);
		StringSource ssB(b, true, new HexDecoder);
		return new ECP(Integer(ssP, (size_t)ssP.MaxRetrievable()), ECP::FieldElement(ssA, (size_t)ssA.MaxRetrievable()), ECP::FieldElement(ssB, (size_t)ssB.MaxRetrievable()));
	};

	OID oid;
	const char *p, *a, *b, *g, *n;
	unsigned int h;
};

struct OIDLessThan
{
	template <typename T>
	inline bool operator()(const EcRecommendedParameters<T>& a, const OID& b) {return a.oid < b;}
	template <typename T>
	inline bool operator()(const OID& a, const EcRecommendedParameters<T>& b) {return a < b.oid;}
	template <typename T>
	inline bool operator()(const EcRecommendedParameters<T>& a, const EcRecommendedParameters<T>& b) {return a.oid < b.oid;}
};

static void GetRecommendedParameters(const EcRecommendedParameters<EC2N> *&begin, const EcRecommendedParameters<EC2N> *&end)
{
	// this array must be sorted by OID
	static const EcRecommendedParameters<EC2N> rec[] = {
		EcRecommendedParameters<EC2N>(ASN1::sect163k1(),
			163, 7, 6, 3, 0,
			"000000000000000000000000000000000000000001",
			"000000000000000000000000000000000000000001",
			"0402FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE80289070FB05D38FF58321F2E800536D538CCDAA3D9",
			"04000000000000000000020108A2E0CC0D99F8A5EF",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect163r1(),
			163, 7, 6, 3, 0,
			"07B6882CAAEFA84F9554FF8428BD88E246D2782AE2",
			"0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9",
			"040369979697AB43897789566789567F787A7876A65400435EDB42EFAFB2989D51FEFCE3C80988F41FF883",
			"03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect239k1(),
			239, 158, 0,
			"000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000001",
			"0429A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA",
			"2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5",
			4),
		EcRecommendedParameters<EC2N>(ASN1::sect113r1(),
			113, 9, 0,
			"003088250CA6E7C7FE649CE85820F7",
			"00E8BEE4D3E2260744188BE0E9C723",
			"04009D73616F35F4AB1407D73562C10F00A52830277958EE84D1315ED31886",
			"0100000000000000D9CCEC8A39E56F",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect113r2(),
			113, 9, 0,
			"00689918DBEC7E5A0DD6DFC0AA55C7",
			"0095E9A9EC9B297BD4BF36E059184F",
			"0401A57A6A7B26CA5EF52FCDB816479700B3ADC94ED1FE674C06E695BABA1D",
			"010000000000000108789B2496AF93",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect163r2(),
			163, 7, 6, 3, 0,
			"000000000000000000000000000000000000000001",
			"020A601907B8C953CA1481EB10512F78744A3205FD",
			"0403F0EBA16286A2D57EA0991168D4994637E8343E3600D51FBC6C71A0094FA2CDD545B11C5C0C797324F1",
			"040000000000000000000292FE77E70C12A4234C33",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect283k1(),
			283, 12, 7, 5, 0,
			"000000000000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000000000000000001",
			"040503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC245849283601CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259",
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61",
			4),
		EcRecommendedParameters<EC2N>(ASN1::sect283r1(),
			283, 12, 7, 5, 0,
			"000000000000000000000000000000000000000000000000000000000000000000000001",
			"027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5",
			"0405F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B1205303676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4",
			"03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect131r1(),
			131, 8, 3, 2, 0,
			"07A11B09A76B562144418FF3FF8C2570B8",
			"0217C05610884B63B9C6C7291678F9D341",
			"040081BAF91FDF9833C40F9C181343638399078C6E7EA38C001F73C8134B1B4EF9E150",
			"0400000000000000023123953A9464B54D",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect131r2(),
			131, 8, 3, 2, 0,
			"03E5A88919D7CAFCBF415F07C2176573B2",
			"04B8266A46C55657AC734CE38F018F2192",
			"040356DCD8F2F95031AD652D23951BB366A80648F06D867940A5366D9E265DE9EB240F",
			"0400000000000000016954A233049BA98F",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect193r1(),
			193, 15, 0,
			"0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01",
			"00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814",
			"0401F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E10025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05",
			"01000000000000000000000000C7F34A778F443ACC920EBA49",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect193r2(),
			193, 15, 0,
			"0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B",
			"00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE",
			"0400D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C",
			"010000000000000000000000015AAB561B005413CCD4EE99D5",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect233k1(),
			233, 74, 0,
			"000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000001",
			"04017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD612601DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3",
			"8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF",
			4),
		EcRecommendedParameters<EC2N>(ASN1::sect233r1(),
			233, 74, 0,
			"000000000000000000000000000000000000000000000000000000000001",
			"0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD",
			"0400FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052",
			"01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect409k1(),
			409, 87, 0,
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
			"040060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE902374601E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B",
			"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
			4),
		EcRecommendedParameters<EC2N>(ASN1::sect409r1(),
			409, 87, 0,
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
			"0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F",
			"04015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A70061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706",
			"010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173",
			2),
		EcRecommendedParameters<EC2N>(ASN1::sect571k1(),
			571, 10, 5, 2, 0,
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
			"04026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C89720349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3",
			"020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001",
			4),
		EcRecommendedParameters<EC2N>(ASN1::sect571r1(),
			571, 10, 5, 2, 0,
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
			"02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A",
			"040303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B",
			"03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47",
			2),
	};
	begin = rec;
	end = rec + sizeof(rec)/sizeof(rec[0]);
}

// See https://www.cryptopp.com/wiki/SM2 for details on sm2p256v1 and sm2encrypt_recommendedParameters
static void GetRecommendedParameters(const EcRecommendedParameters<ECP> *&begin, const EcRecommendedParameters<ECP> *&end)
{
	// this array must be sorted by OID
	static const EcRecommendedParameters<ECP> rec[] = {
		EcRecommendedParameters<ECP>(ASN1::sm2p256v1(),
			"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF",
			"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC",
			"28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93",
			"04" "32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7"
			     "BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0",
			"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123",
			1),
		EcRecommendedParameters<ECP>(ASN1::sm2encrypt_recommendedParameters(),
			"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF",
			"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC",
			"28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93",
			"04" "32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7"
			     "BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0",
			"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp192r1(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
			"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
			"04188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF101207192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
			"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp256r1(),
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
			"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
			"046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
			"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
			1),
		EcRecommendedParameters<ECP>(ASN1::brainpoolP160r1(),
			"E95E4A5F737059DC60DFC7AD95B3D8139515620F",
			"340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
			"1E589A8595423412134FAA2DBDEC95C8D8675E58",
			"04BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC31667CB477A1A8EC338F94741669C976316DA6321",
			"E95E4A5F737059DC60DF5991D45029409E60FC09",
			1),
		EcRecommendedParameters<ECP>(ASN1::brainpoolP192r1(),
			"C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
			"6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
			"469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
			"04C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD614B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
			"C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1",
			1),
		EcRecommendedParameters<ECP>(ASN1::brainpoolP224r1(),
			"D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
			"68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
			"2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
			"040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
			"D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F",
			1),
		EcRecommendedParameters<ECP>(ASN1::brainpoolP256r1(),
			"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
			"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
			"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
			"048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
			"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
			1),
		EcRecommendedParameters<ECP>(ASN1::brainpoolP320r1(),
			"D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
			"3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
			"520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
			"0443BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E2061114FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
			"D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",
			1),
		EcRecommendedParameters<ECP>(ASN1::brainpoolP384r1(),
			"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
			"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
			"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
			"041D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
			"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
			1),
		EcRecommendedParameters<ECP>(ASN1::brainpoolP512r1(),
			"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
			"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
			"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
			"0481AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F8227DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
			"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp112r1(),
			"DB7C2ABF62E35E668076BEAD208B",
			"DB7C2ABF62E35E668076BEAD2088",
			"659EF8BA043916EEDE8911702B22",
			"0409487239995A5EE76B55F9C2F098A89CE5AF8724C0A23E0E0FF77500",
			"DB7C2ABF62E35E7628DFAC6561C5",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp112r2(),
			"DB7C2ABF62E35E668076BEAD208B",
			"6127C24C05F38A0AAAF65C0EF02C",
			"51DEF1815DB5ED74FCC34C85D709",
			"044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97",
			"36DF0AAFD8B8D7597CA10520D04B",
			4),
		EcRecommendedParameters<ECP>(ASN1::secp160r1(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
			"1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
			"044A96B5688EF573284664698968C38BB913CBFC8223A628553168947D59DCC912042351377AC5FB32",
			"0100000000000000000001F4C8F927AED3CA752257",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp160k1(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
			"0000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000007",
			"043B4C382CE37AA192A4019E763036F4F5DD4D7EBB938CF935318FDCED6BC28286531733C3F03C4FEE",
			"0100000000000000000001B8FA16DFAB9ACA16B6B3",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp256k1(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000007",
			"0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp128r1(),
			"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
			"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC",
			"E87579C11079F43DD824993C2CEE5ED3",
			"04161FF7528B899B2D0C28607CA52C5B86CF5AC8395BAFEB13C02DA292DDED7A83",
			"FFFFFFFE0000000075A30D1B9038A115",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp128r2(),
			"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
			"D6031998D1B3BBFEBF59CC9BBFF9AEE1",
			"5EEEFCA380D02919DC2C6558BB6D8A5D",
			"047B6AA5D85E572983E6FB32A7CDEBC14027B6916A894D3AEE7106FE805FC34B44",
			"3FFFFFFF7FFFFFFFBE0024720613B5A3",
			4),
		EcRecommendedParameters<ECP>(ASN1::secp160r2(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70",
			"B4E134D3FB59EB8BAB57274904664D5AF50388BA",
			"0452DCB034293A117E1F4FF11B30F7199D3144CE6DFEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E",
			"0100000000000000000000351EE786A818F3A1A16B",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp192k1(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
			"000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000003",
			"04DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D",
			"FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp224k1(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
			"00000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000000000000000000000000005",
			"04A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
			"010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp224r1(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
			"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
			"04B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp384r1(),
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
			"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
			"04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
			1),
		EcRecommendedParameters<ECP>(ASN1::secp521r1(),
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
			"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
			"0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
			1),
	};
	begin = rec;
	end = rec + sizeof(rec)/sizeof(rec[0]);
}

template <class EC> OID DL_GroupParameters_EC<EC>::GetNextRecommendedParametersOID(const OID &oid)
{
	const EcRecommendedParameters<EllipticCurve> *begin, *end;
	GetRecommendedParameters(begin, end);
	const EcRecommendedParameters<EllipticCurve> *it = std::upper_bound(begin, end, oid, OIDLessThan());
	return (it == end ? OID() : it->oid);
}

template <class EC> void DL_GroupParameters_EC<EC>::Initialize(const OID &oid)
{
	const EcRecommendedParameters<EllipticCurve> *begin, *end;
	GetRecommendedParameters(begin, end);
	const EcRecommendedParameters<EllipticCurve> *it = std::lower_bound(begin, end, oid, OIDLessThan());
	if (it == end || it->oid != oid)
		throw UnknownOID();

	const EcRecommendedParameters<EllipticCurve> &param = *it;
	m_oid = oid;
	member_ptr<EllipticCurve> ec(param.NewEC());
	this->m_groupPrecomputation.SetCurve(*ec);

	StringSource ssG(param.g, true, new HexDecoder);
	Element G;
	bool result = GetCurve().DecodePoint(G, ssG, (size_t)ssG.MaxRetrievable());
	this->SetSubgroupGenerator(G);

	// TODO: this fails in practice. Should it throw?
	CRYPTOPP_UNUSED(result); CRYPTOPP_ASSERT(result);

	StringSource ssN(param.n, true, new HexDecoder);
	m_n.Decode(ssN, (size_t)ssN.MaxRetrievable());
	m_k = param.h;
}

template <class EC>
bool DL_GroupParameters_EC<EC>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
	if (strcmp(name, Name::GroupOID()) == 0)
	{
		if (m_oid.Empty())
			return false;

		this->ThrowIfTypeMismatch(name, typeid(OID), valueType);
		*reinterpret_cast<OID *>(pValue) = m_oid;
		return true;
	}
	else
		return GetValueHelper<DL_GroupParameters<Element> >(this, name, valueType, pValue).Assignable()
			CRYPTOPP_GET_FUNCTION_ENTRY(Curve);
}

template <class EC>
void DL_GroupParameters_EC<EC>::AssignFrom(const NameValuePairs &source)
{
	OID oid;
	if (source.GetValue(Name::GroupOID(), oid))
		Initialize(oid);
	else
	{
		EllipticCurve ec;
		Point G;
		Integer n;

		source.GetRequiredParameter("DL_GroupParameters_EC<EC>", Name::Curve(), ec);
		source.GetRequiredParameter("DL_GroupParameters_EC<EC>", Name::SubgroupGenerator(), G);
		source.GetRequiredParameter("DL_GroupParameters_EC<EC>", Name::SubgroupOrder(), n);
		Integer k = source.GetValueWithDefault(Name::Cofactor(), Integer::Zero());

		Initialize(ec, G, n, k);
	}
}

template <class EC>
void DL_GroupParameters_EC<EC>::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg)
{
	try
	{
		CRYPTOPP_UNUSED(rng);
		AssignFrom(alg);
	}
	catch (InvalidArgument &)
	{
		throw NotImplemented("DL_GroupParameters_EC<EC>: curve generation is not implemented yet");
	}
}

template <class EC>
void DL_GroupParameters_EC<EC>::BERDecode(BufferedTransformation &bt)
{
	byte b;
	if (!bt.Peek(b))
		BERDecodeError();
	if (b == OBJECT_IDENTIFIER)
		Initialize(OID(bt));
	else
	{
		BERSequenceDecoder seq(bt);
			word32 version;
			BERDecodeUnsigned<word32>(seq, version, INTEGER, 1, 1);	// check version
			EllipticCurve ec(seq);
			Point G = ec.BERDecodePoint(seq);
			Integer n(seq);
			Integer k;
			bool cofactorPresent = !seq.EndReached();
			if (cofactorPresent)
				k.BERDecode(seq);
			else
				k = Integer::Zero();
		seq.MessageEnd();

		Initialize(ec, G, n, k);
	}
}

template <class EC>
void DL_GroupParameters_EC<EC>::DEREncode(BufferedTransformation &bt) const
{
	if (m_encodeAsOID && !m_oid.Empty())
		m_oid.DEREncode(bt);
	else
	{
		DERSequenceEncoder seq(bt);
		DEREncodeUnsigned<word32>(seq, 1);	// version
		GetCurve().DEREncode(seq);
		GetCurve().DEREncodePoint(seq, this->GetSubgroupGenerator(), m_compress);
		m_n.DEREncode(seq);
		if (m_k.NotZero())
			m_k.DEREncode(seq);
		seq.MessageEnd();
	}
}

template <class EC>
Integer DL_GroupParameters_EC<EC>::GetCofactor() const
{
	if (!m_k)
	{
		Integer q = GetCurve().FieldSize();
		Integer qSqrt = q.SquareRoot();
		m_k = (q+2*qSqrt+1)/m_n;
	}

	return m_k;
}

template <class EC>
Integer DL_GroupParameters_EC<EC>::ConvertElementToInteger(const Element &element) const
{
	return ConvertToInteger(element.x);
}

template <class EC>
bool DL_GroupParameters_EC<EC>::ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const
{
	bool pass = GetCurve().ValidateParameters(rng, level);
	CRYPTOPP_ASSERT(pass);

	Integer q = GetCurve().FieldSize();
	pass = pass && m_n!=q;
	CRYPTOPP_ASSERT(pass);

	if (level >= 2)
	{
		Integer qSqrt = q.SquareRoot();
		pass = pass && m_n>4*qSqrt;
		CRYPTOPP_ASSERT(pass);
		pass = pass && VerifyPrime(rng, m_n, level-2);
		CRYPTOPP_ASSERT(pass);
		pass = pass && (m_k.IsZero() || m_k == (q+2*qSqrt+1)/m_n);
		CRYPTOPP_ASSERT(pass);
		pass = pass && CheckMOVCondition(q, m_n);
		CRYPTOPP_ASSERT(pass);
	}

	return pass;
}

template <class EC>
bool DL_GroupParameters_EC<EC>::ValidateElement(unsigned int level, const Element &g, const DL_FixedBasePrecomputation<Element> *gpc) const
{
	bool pass = !IsIdentity(g);
	CRYPTOPP_ASSERT(pass);
	pass = pass && GetCurve().VerifyPoint(g);
	CRYPTOPP_ASSERT(pass);

	if (level >= 1)
	{
		if (gpc)
		{
			pass = pass && gpc->Exponentiate(this->GetGroupPrecomputation(), Integer::One()) == g;
			CRYPTOPP_ASSERT(pass);
		}
	}
	if (level >= 2 && pass)
	{
		const Integer &q = GetSubgroupOrder();
		Element gq = gpc ? gpc->Exponentiate(this->GetGroupPrecomputation(), q) : this->ExponentiateElement(g, q);
		pass = pass && IsIdentity(gq);
		CRYPTOPP_ASSERT(pass);
	}
	return pass;
}

template <class EC>
void DL_GroupParameters_EC<EC>::SimultaneousExponentiate(Element *results, const Element &base, const Integer *exponents, unsigned int exponentsCount) const
{
	GetCurve().SimultaneousMultiply(results, base, exponents, exponentsCount);
}

template <class EC>
typename DL_GroupParameters_EC<EC>::Element DL_GroupParameters_EC<EC>::MultiplyElements(const Element &a, const Element &b) const
{
	return GetCurve().Add(a, b);
}

template <class EC>
typename DL_GroupParameters_EC<EC>::Element DL_GroupParameters_EC<EC>::CascadeExponentiate(const Element &element1, const Integer &exponent1, const Element &element2, const Integer &exponent2) const
{
	return GetCurve().CascadeMultiply(exponent1, element1, exponent2, element2);
}

template <class EC>
OID DL_GroupParameters_EC<EC>::GetAlgorithmID() const
{
	return ASN1::id_ecPublicKey();
}

std::ostream& operator<<(std::ostream& os, const DL_GroupParameters_EC<ECP>::Element& obj)
{
	std::ostringstream oss;
	oss << "(" << std::hex << obj.x << ", " << std::hex  << obj.y << ")";
	return os << oss.str();
}

// ******************************************************************

template <class EC>
void DL_PublicKey_EC<EC>::BERDecodePublicKey(BufferedTransformation &bt, bool parametersPresent, size_t size)
{
	CRYPTOPP_UNUSED(parametersPresent);

	typename EC::Point P;
	if (!this->GetGroupParameters().GetCurve().DecodePoint(P, bt, size))
		BERDecodeError();
	this->SetPublicElement(P);
}

template <class EC>
void DL_PublicKey_EC<EC>::DEREncodePublicKey(BufferedTransformation &bt) const
{
	this->GetGroupParameters().GetCurve().EncodePoint(bt, this->GetPublicElement(), this->GetGroupParameters().GetPointCompression());
}

// ******************************************************************

template <class EC>
void DL_PrivateKey_EC<EC>::BERDecodePrivateKey(BufferedTransformation &bt, bool parametersPresent, size_t size)
{
	CRYPTOPP_UNUSED(size);
	BERSequenceDecoder seq(bt);
		word32 version;
		BERDecodeUnsigned<word32>(seq, version, INTEGER, 1, 1);	// check version

		BERGeneralDecoder dec(seq, OCTET_STRING);
		if (!dec.IsDefiniteLength())
			BERDecodeError();
		Integer x;
		x.Decode(dec, (size_t)dec.RemainingLength());
		dec.MessageEnd();
		if (!parametersPresent && seq.PeekByte() != (CONTEXT_SPECIFIC | CONSTRUCTED | 0))
			BERDecodeError();
		if (!seq.EndReached() && seq.PeekByte() == (CONTEXT_SPECIFIC | CONSTRUCTED | 0))
		{
			BERGeneralDecoder parameters(seq, CONTEXT_SPECIFIC | CONSTRUCTED | 0);
			this->AccessGroupParameters().BERDecode(parameters);
			parameters.MessageEnd();
		}
		if (!seq.EndReached())
		{
			// skip over the public element
			SecByteBlock subjectPublicKey;
			unsigned int unusedBits;
			BERGeneralDecoder publicKey(seq, CONTEXT_SPECIFIC | CONSTRUCTED | 1);
			BERDecodeBitString(publicKey, subjectPublicKey, unusedBits);
			publicKey.MessageEnd();
			Element Q;
			if (!(unusedBits == 0 && this->GetGroupParameters().GetCurve().DecodePoint(Q, subjectPublicKey, subjectPublicKey.size())))
				BERDecodeError();
		}
	seq.MessageEnd();

	this->SetPrivateExponent(x);
}

template <class EC>
void DL_PrivateKey_EC<EC>::DEREncodePrivateKey(BufferedTransformation &bt) const
{
	DERSequenceEncoder privateKey(bt);
		DEREncodeUnsigned<word32>(privateKey, 1);	// version
		// SEC 1 ver 1.0 says privateKey (m_d) has the same length as order of the curve
		// this will be changed to order of base point in a future version
		this->GetPrivateExponent().DEREncodeAsOctetString(privateKey, this->GetGroupParameters().GetSubgroupOrder().ByteCount());
	privateKey.MessageEnd();
}

// ******************************************************************

template <class EC>
void DL_PublicKey_ECGDSA<EC>::BERDecodePublicKey(BufferedTransformation &bt, bool parametersPresent, size_t size)
{
	CRYPTOPP_UNUSED(parametersPresent);

	typename EC::Point P;
	if (!this->GetGroupParameters().GetCurve().DecodePoint(P, bt, size))
		BERDecodeError();
	this->SetPublicElement(P);
}

template <class EC>
void DL_PublicKey_ECGDSA<EC>::DEREncodePublicKey(BufferedTransformation &bt) const
{
	this->GetGroupParameters().GetCurve().EncodePoint(bt, this->GetPublicElement(), this->GetGroupParameters().GetPointCompression());
}

// ******************************************************************

template <class EC>
void DL_PrivateKey_ECGDSA<EC>::BERDecodePrivateKey(BufferedTransformation &bt, bool parametersPresent, size_t size)
{
	CRYPTOPP_UNUSED(size);
	BERSequenceDecoder seq(bt);
		word32 version;
		BERDecodeUnsigned<word32>(seq, version, INTEGER, 1, 1);	// check version

		BERGeneralDecoder dec(seq, OCTET_STRING);
		if (!dec.IsDefiniteLength())
			BERDecodeError();
		Integer x;
		x.Decode(dec, (size_t)dec.RemainingLength());
		dec.MessageEnd();
		if (!parametersPresent && seq.PeekByte() != (CONTEXT_SPECIFIC | CONSTRUCTED | 0))
			BERDecodeError();
		if (!seq.EndReached() && seq.PeekByte() == (CONTEXT_SPECIFIC | CONSTRUCTED | 0))
		{
			BERGeneralDecoder parameters(seq, CONTEXT_SPECIFIC | CONSTRUCTED | 0);
			this->AccessGroupParameters().BERDecode(parameters);
			parameters.MessageEnd();
		}
		if (!seq.EndReached())
		{
			// skip over the public element
			SecByteBlock subjectPublicKey;
			unsigned int unusedBits;
			BERGeneralDecoder publicKey(seq, CONTEXT_SPECIFIC | CONSTRUCTED | 1);
			BERDecodeBitString(publicKey, subjectPublicKey, unusedBits);
			publicKey.MessageEnd();
			Element Q;
			if (!(unusedBits == 0 && this->GetGroupParameters().GetCurve().DecodePoint(Q, subjectPublicKey, subjectPublicKey.size())))
				BERDecodeError();
		}
	seq.MessageEnd();

	this->SetPrivateExponent(x);
}

template <class EC>
void DL_PrivateKey_ECGDSA<EC>::DEREncodePrivateKey(BufferedTransformation &bt) const
{
	DERSequenceEncoder privateKey(bt);
		DEREncodeUnsigned<word32>(privateKey, 1);	// version
		// SEC 1 ver 1.0 says privateKey (m_d) has the same length as order of the curve
		// this will be changed to order of base point in a future version
		this->GetPrivateExponent().DEREncodeAsOctetString(privateKey, this->GetGroupParameters().GetSubgroupOrder().ByteCount());
	privateKey.MessageEnd();
}

NAMESPACE_END

#endif
