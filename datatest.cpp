// datatest.cpp - originally written and placed in the public domain by Wei Dai
//                CryptoPP::Test namespace added by JW in February 2017

#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "factory.h"
#include "integer.h"
#include "filters.h"
#include "randpool.h"
#include "files.h"
#include "trunhash.h"
#include "queue.h"
#include "smartptr.h"
#include "validate.h"
#include "stdcpp.h"
#include "misc.h"
#include "hex.h"
#include "trap.h"

#include <iostream>
#include <sstream>
#include <cerrno>

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

#ifdef _MSC_VER
# define STRTOUL64 _strtoui64
#else
# define STRTOUL64 strtoull
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

typedef std::map<std::string, std::string> TestData;
static bool s_thorough = false;

class TestFailure : public Exception
{
public:
	TestFailure() : Exception(OTHER_ERROR, "Validation test failed") {}
};

static const TestData *s_currentTestData = NULLPTR;

std::string TrimSpace(std::string str)
{
	if (str.empty()) return "";

	const std::string whitespace(" \r\t\n");
	std::string::size_type beg = str.find_first_not_of(whitespace);
	std::string::size_type end = str.find_last_not_of(whitespace);

	if (beg != std::string::npos && end != std::string::npos)
		return str.substr(beg, end+1);
	else if (beg != std::string::npos)
		return str.substr(beg);
	else
		return "";
}

std::string TrimComment(std::string str)
{
	if (str.empty()) return "";

	std::string::size_type first = str.find("#");

	if (first != std::string::npos)
		return TrimSpace(str.substr(0, first));
	else
		return TrimSpace(str);
}

static void OutputTestData(const TestData &v)
{
	std::cerr << "\n";
	for (TestData::const_iterator i = v.begin(); i != v.end(); ++i)
	{
		std::cerr << i->first << ": " << i->second << std::endl;
	}
}

static void SignalTestFailure()
{
	OutputTestData(*s_currentTestData);
	throw TestFailure();
}

static void SignalUnknownAlgorithmError(const std::string& algType)
{
	OutputTestData(*s_currentTestData);
	throw Exception(Exception::OTHER_ERROR, "Unknown algorithm " + algType + " during validation test");
}

static void SignalTestError(const char* msg = NULLPTR)
{
	OutputTestData(*s_currentTestData);

	if (msg)
		throw Exception(Exception::OTHER_ERROR, msg);
	else
		throw Exception(Exception::OTHER_ERROR, "Unexpected error during validation test");
}

bool DataExists(const TestData &data, const char *name)
{
	TestData::const_iterator i = data.find(name);
	return (i != data.end());
}

const std::string & GetRequiredDatum(const TestData &data, const char *name)
{
	TestData::const_iterator i = data.find(name);
	if (i == data.end())
	{
		std::string msg("Required datum \"" + std::string(name) + "\" missing");
		SignalTestError(msg.c_str());
	}
	return i->second;
}

void RandomizedTransfer(BufferedTransformation &source, BufferedTransformation &target, bool finish, const std::string &channel=DEFAULT_CHANNEL)
{
	while (source.MaxRetrievable() > (finish ? 0 : 4096))
	{
		byte buf[4096+64];
		size_t start = Test::GlobalRNG().GenerateWord32(0, 63);
		size_t len = Test::GlobalRNG().GenerateWord32(1, UnsignedMin(4096U, 3*source.MaxRetrievable()/2));
		len = source.Get(buf+start, len);
		target.ChannelPut(channel, buf+start, len);
	}
}

void PutDecodedDatumInto(const TestData &data, const char *name, BufferedTransformation &target)
{
	std::string s1 = GetRequiredDatum(data, name), s2;
	ByteQueue q;

	while (!s1.empty())
	{
		while (s1[0] == ' ')
		{
			s1 = s1.substr(1);
			if (s1.empty())
				goto end;	// avoid invalid read if s1 is empty
		}

		int repeat = 1;
		if (s1[0] == 'r')
		{
			s1 = s1.erase(0, 1);
			repeat = ::atoi(s1.c_str());
			s1 = s1.substr(s1.find(' ')+1);
		}

		// Convert word32 or word64 to little endian order. Some algorithm test vectors are
		// presented in the format. We probably should have named them word32le and word64le.
		if (s1.length() >= 6 && (s1.substr(0,6) == "word32" || s1.substr(0,6) == "word64"))
		{
			std::istringstream iss(s1.substr(6));
			if (s1.substr(0,6) == "word64")
			{
				word64 value;
				while (iss >> std::skipws >> std::hex >> value)
				{
					value = ConditionalByteReverse(LITTLE_ENDIAN_ORDER, value);
					q.Put(reinterpret_cast<const byte *>(&value), 8);
				}
			}
			else
			{
				word32 value;
				while (iss >> std::skipws >> std::hex >> value)
				{
					value = ConditionalByteReverse(LITTLE_ENDIAN_ORDER, value);
					q.Put(reinterpret_cast<const byte *>(&value), 4);
				}
			}
			goto end;
		}

		s2.clear();
		if (s1[0] == '\"')
		{
			s2 = s1.substr(1, s1.find('\"', 1)-1);
			s1 = s1.substr(s2.length() + 2);
		}
		else if (s1.substr(0, 2) == "0x")
		{
			std::string::size_type pos = s1.find(' ');
			StringSource(s1.substr(2, pos), true, new HexDecoder(new StringSink(s2)));
			s1 = s1.substr(STDMIN(pos, s1.length()));
		}
		else
		{
			std::string::size_type pos = s1.find(' ');
			StringSource(s1.substr(0, pos), true, new HexDecoder(new StringSink(s2)));
			s1 = s1.substr(STDMIN(pos, s1.length()));
		}

		while (repeat--)
		{
			q.Put(ConstBytePtr(s2), BytePtrSize(s2));
			RandomizedTransfer(q, target, false);
		}
	}

end:
	RandomizedTransfer(q, target, true);
}

std::string GetDecodedDatum(const TestData &data, const char *name)
{
	std::string s;
	PutDecodedDatumInto(data, name, StringSink(s).Ref());
	return s;
}

std::string GetOptionalDecodedDatum(const TestData &data, const char *name)
{
	std::string s;
	if (DataExists(data, name))
		PutDecodedDatumInto(data, name, StringSink(s).Ref());
	return s;
}

class TestDataNameValuePairs : public NameValuePairs
{
public:
	TestDataNameValuePairs(const TestData &data) : m_data(data) {}

	virtual bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		TestData::const_iterator i = m_data.find(name);
		if (i == m_data.end())
		{
			if (std::string(name) == Name::DigestSize() && valueType == typeid(int))
			{
				i = m_data.find("MAC");
				if (i == m_data.end())
					i = m_data.find("Digest");
				if (i == m_data.end())
					return false;

				m_temp.clear();
				PutDecodedDatumInto(m_data, i->first.c_str(), StringSink(m_temp).Ref());
				*reinterpret_cast<int *>(pValue) = (int)m_temp.size();
				return true;
			}
			else
				return false;
		}

		const std::string &value = i->second;

		if (valueType == typeid(int))
			*reinterpret_cast<int *>(pValue) = atoi(value.c_str());
		else if (valueType == typeid(word64))
		{
			std::string x(value.empty() ? "0" : value);
			const char* beg = &x[0];
			char* end = &x[0] + value.size();

			errno = 0;
			*reinterpret_cast<word64*>(pValue) = STRTOUL64(beg, &end, 0);
			if (errno != 0)
				return false;
		}
		else if (valueType == typeid(Integer))
			*reinterpret_cast<Integer *>(pValue) = Integer((std::string(value) + "h").c_str());
		else if (valueType == typeid(ConstByteArrayParameter))
		{
			m_temp.clear();
			PutDecodedDatumInto(m_data, name, StringSink(m_temp).Ref());
			reinterpret_cast<ConstByteArrayParameter *>(pValue)->Assign(ConstBytePtr(m_temp), BytePtrSize(m_temp), false);
		}
		else
			throw ValueTypeMismatch(name, typeid(std::string), valueType);

		return true;
	}

private:
	const TestData &m_data;
	mutable std::string m_temp;
};

void TestKeyPairValidAndConsistent(CryptoMaterial &pub, const CryptoMaterial &priv)
{
	if (!pub.Validate(Test::GlobalRNG(), 2U+!!s_thorough))
		SignalTestFailure();
	if (!priv.Validate(Test::GlobalRNG(), 2U+!!s_thorough))
		SignalTestFailure();

	ByteQueue bq1, bq2;
	pub.Save(bq1);
	pub.AssignFrom(priv);
	pub.Save(bq2);
	if (bq1 != bq2)
		SignalTestFailure();
}

void TestSignatureScheme(TestData &v)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");

	member_ptr<PK_Signer> signer(ObjectFactoryRegistry<PK_Signer>::Registry().CreateObject(name.c_str()));
	member_ptr<PK_Verifier> verifier(ObjectFactoryRegistry<PK_Verifier>::Registry().CreateObject(name.c_str()));

	// Code coverage
	(void)signer->AlgorithmName();
	(void)verifier->AlgorithmName();
	(void)signer->AlgorithmProvider();
	(void)verifier->AlgorithmProvider();

	TestDataNameValuePairs pairs(v);

	if (test == "GenerateKey")
	{
		signer->AccessPrivateKey().GenerateRandom(Test::GlobalRNG(), pairs);
		verifier->AccessPublicKey().AssignFrom(signer->AccessPrivateKey());
	}
	else
	{
		std::string keyFormat = GetRequiredDatum(v, "KeyFormat");

		if (keyFormat == "DER")
			verifier->AccessMaterial().Load(StringStore(GetDecodedDatum(v, "PublicKey")).Ref());
		else if (keyFormat == "Component")
			verifier->AccessMaterial().AssignFrom(pairs);

		if (test == "Verify" || test == "NotVerify")
		{
			SignatureVerificationFilter verifierFilter(*verifier, NULLPTR, SignatureVerificationFilter::SIGNATURE_AT_BEGIN);
			PutDecodedDatumInto(v, "Signature", verifierFilter);
			PutDecodedDatumInto(v, "Message", verifierFilter);
			verifierFilter.MessageEnd();
			if (verifierFilter.GetLastResult() == (test == "NotVerify"))
				SignalTestFailure();
			return;
		}
		else if (test == "PublicKeyValid")
		{
			if (!verifier->GetMaterial().Validate(Test::GlobalRNG(), 3))
				SignalTestFailure();
			return;
		}

		if (keyFormat == "DER")
			signer->AccessMaterial().Load(StringStore(GetDecodedDatum(v, "PrivateKey")).Ref());
		else if (keyFormat == "Component")
			signer->AccessMaterial().AssignFrom(pairs);
	}

	if (test == "GenerateKey" || test == "KeyPairValidAndConsistent")
	{
		TestKeyPairValidAndConsistent(verifier->AccessMaterial(), signer->GetMaterial());
		SignatureVerificationFilter verifierFilter(*verifier, NULLPTR, SignatureVerificationFilter::THROW_EXCEPTION);
		const byte msg[3] = {'a', 'b', 'c'};
		verifierFilter.Put(msg, sizeof(msg));
		StringSource ss(msg, sizeof(msg), true, new SignerFilter(Test::GlobalRNG(), *signer, new Redirector(verifierFilter)));
	}
	else if (test == "Sign")
	{
		SignerFilter f(Test::GlobalRNG(), *signer, new HexEncoder(new FileSink(std::cout)));
		StringSource ss(GetDecodedDatum(v, "Message"), true, new Redirector(f));
		SignalTestFailure();
	}
	else if (test == "DeterministicSign")
	{
		// This test is specialized for RFC 6979. The RFC is a drop-in replacement
		// for DSA and ECDSA, and access to the seed or secret is not needed. If
		// additional determinsitic signatures are added, then the test harness will
		// likely need to be extended.
		std::string signature;
		SignerFilter f(Test::GlobalRNG(), *signer, new StringSink(signature));
		StringSource ss(GetDecodedDatum(v, "Message"), true, new Redirector(f));

		if (GetDecodedDatum(v, "Signature") != signature)
			SignalTestFailure();

		return;
	}
	else
	{
		std::string msg("Unknown signature test \"" + test + "\"");
		SignalTestError(msg.c_str());
		CRYPTOPP_ASSERT(false);
	}
}

void TestAsymmetricCipher(TestData &v)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");

	member_ptr<PK_Encryptor> encryptor(ObjectFactoryRegistry<PK_Encryptor>::Registry().CreateObject(name.c_str()));
	member_ptr<PK_Decryptor> decryptor(ObjectFactoryRegistry<PK_Decryptor>::Registry().CreateObject(name.c_str()));

	// Code coverage
	(void)encryptor->AlgorithmName();
	(void)decryptor->AlgorithmName();
	(void)encryptor->AlgorithmProvider();
	(void)decryptor->AlgorithmProvider();

	std::string keyFormat = GetRequiredDatum(v, "KeyFormat");

	if (keyFormat == "DER")
	{
		decryptor->AccessMaterial().Load(StringStore(GetDecodedDatum(v, "PrivateKey")).Ref());
		encryptor->AccessMaterial().Load(StringStore(GetDecodedDatum(v, "PublicKey")).Ref());
	}
	else if (keyFormat == "Component")
	{
		TestDataNameValuePairs pairs(v);
		decryptor->AccessMaterial().AssignFrom(pairs);
		encryptor->AccessMaterial().AssignFrom(pairs);
	}

	if (test == "DecryptMatch")
	{
		std::string decrypted, expected = GetDecodedDatum(v, "Plaintext");
		StringSource ss(GetDecodedDatum(v, "Ciphertext"), true, new PK_DecryptorFilter(Test::GlobalRNG(), *decryptor, new StringSink(decrypted)));
		if (decrypted != expected)
			SignalTestFailure();
	}
	else if (test == "KeyPairValidAndConsistent")
	{
		TestKeyPairValidAndConsistent(encryptor->AccessMaterial(), decryptor->GetMaterial());
	}
	else
	{
		std::string msg("Unknown asymmetric cipher test \"" + test + "\"");
		SignalTestError(msg.c_str());
		CRYPTOPP_ASSERT(false);
	}
}

void TestSymmetricCipher(TestData &v, const NameValuePairs &overrideParameters)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");

	std::string key = GetDecodedDatum(v, "Key");
	std::string plaintext = GetDecodedDatum(v, "Plaintext");

	TestDataNameValuePairs testDataPairs(v);
	CombinedNameValuePairs pairs(overrideParameters, testDataPairs);

	if (test == "Encrypt" || test == "EncryptXorDigest" || test == "Resync" || test == "EncryptionMCT" || test == "DecryptionMCT")
	{
		static member_ptr<SymmetricCipher> encryptor, decryptor;
		static std::string lastName;

		if (name != lastName)
		{
			encryptor.reset(ObjectFactoryRegistry<SymmetricCipher, ENCRYPTION>::Registry().CreateObject(name.c_str()));
			decryptor.reset(ObjectFactoryRegistry<SymmetricCipher, DECRYPTION>::Registry().CreateObject(name.c_str()));
			lastName = name;

			// Code coverage
			(void)encryptor->AlgorithmName();
			(void)decryptor->AlgorithmName();
			(void)encryptor->AlgorithmProvider();
			(void)decryptor->AlgorithmProvider();
			(void)encryptor->MinKeyLength();
			(void)decryptor->MinKeyLength();
			(void)encryptor->MaxKeyLength();
			(void)decryptor->MaxKeyLength();
			(void)encryptor->DefaultKeyLength();
			(void)decryptor->DefaultKeyLength();
		}

		// Most block ciphers don't specify BlockPaddingScheme. Kalyna uses it in test vectors.
		// 0 is NoPadding, 1 is ZerosPadding, 2 is PkcsPadding, 3 is OneAndZerosPadding, etc
		// Note: The machinery is wired such that paddingScheme is effectively latched. An
		//   old paddingScheme may be unintentionally used in a subsequent test.
		int paddingScheme = pairs.GetIntValueWithDefault(Name::BlockPaddingScheme(), 0);

		ConstByteArrayParameter iv;
		if (pairs.GetValue(Name::IV(), iv) && iv.size() != encryptor->IVSize())
			SignalTestFailure();

		if (test == "Resync")
		{
			encryptor->Resynchronize(iv.begin(), (int)iv.size());
			decryptor->Resynchronize(iv.begin(), (int)iv.size());
		}
		else
		{
			encryptor->SetKey(ConstBytePtr(key), BytePtrSize(key), pairs);
			decryptor->SetKey(ConstBytePtr(key), BytePtrSize(key), pairs);
		}

		word64 seek64 = pairs.GetWord64ValueWithDefault("Seek64", 0);
		if (seek64)
		{
			encryptor->Seek(seek64);
			decryptor->Seek(seek64);
		}
		else
		{
			int seek = pairs.GetIntValueWithDefault("Seek", 0);
			if (seek)
			{
				encryptor->Seek(seek);
				decryptor->Seek(seek);
			}
		}

		// If a per-test vector parameter was set for a test, like BlockPadding,
		// BlockSize or Tweak, then it becomes latched in testDataPairs. The old
		// value is used in subsequent tests, and it could cause a self test
		// failure in the next test. The behavior surfaced under Kalyna and
		// Threefish. The Kalyna test vectors use NO_PADDING for all tests excpet
		// one. For Threefish, using (and not using) a Tweak caused problems as
		// we marched through test vectors. For BlockPadding, BlockSize or Tweak,
		// unlatch them now, after the key has been set and NameValuePairs have
		// been processed. Also note we only unlatch from testDataPairs. If
		// overrideParameters are specified, the caller is responsible for
		// managing the parameter.
		v.erase("Tweak"); v.erase("InitialBlock"); v.erase("BlockSize"); v.erase("BlockPaddingScheme");

		std::string encrypted, xorDigest, ciphertext, ciphertextXorDigest;
		if (test == "EncryptionMCT" || test == "DecryptionMCT")
		{
			SymmetricCipher *cipher = encryptor.get();
			std::string buf(plaintext), keybuf(key);

			if (test == "DecryptionMCT")
			{
				cipher = decryptor.get();
				ciphertext = GetDecodedDatum(v, "Ciphertext");
				buf.assign(ciphertext.begin(), ciphertext.end());
			}

			for (int i=0; i<400; i++)
			{
				encrypted.reserve(10000 * plaintext.size());
				for (int j=0; j<10000; j++)
				{
					cipher->ProcessString(BytePtr(buf), BytePtrSize(buf));
					encrypted.append(buf.begin(), buf.end());
				}

				encrypted.erase(0, encrypted.size() - keybuf.size());
				xorbuf(BytePtr(keybuf), BytePtr(encrypted), BytePtrSize(keybuf));
				cipher->SetKey(BytePtr(keybuf), BytePtrSize(keybuf));
			}

			encrypted.assign(buf.begin(), buf.end());
			ciphertext = GetDecodedDatum(v, test == "EncryptionMCT" ? "Ciphertext" : "Plaintext");
			if (encrypted != ciphertext)
			{
				std::cout << "\nincorrectly encrypted: ";
				StringSource xx(encrypted, false, new HexEncoder(new FileSink(std::cout)));
				xx.Pump(256); xx.Flush(false);
				std::cout << "\n";
				SignalTestFailure();
			}
			return;
		}

		StreamTransformationFilter encFilter(*encryptor, new StringSink(encrypted),
				static_cast<BlockPaddingSchemeDef::BlockPaddingScheme>(paddingScheme));

		StringStore pstore(plaintext);
		RandomizedTransfer(pstore, encFilter, true);
		encFilter.MessageEnd();

		if (test != "EncryptXorDigest")
		{
			ciphertext = GetDecodedDatum(v, "Ciphertext");
		}
		else
		{
			ciphertextXorDigest = GetDecodedDatum(v, "CiphertextXorDigest");
			xorDigest.append(encrypted, 0, 64);
			for (size_t i=64; i<encrypted.size(); i++)
				xorDigest[i%64] = static_cast<char>(xorDigest[i%64] ^ encrypted[i]);
		}
		if (test != "EncryptXorDigest" ? encrypted != ciphertext : xorDigest != ciphertextXorDigest)
		{
			std::cout << "\nincorrectly encrypted: ";
			StringSource xx(encrypted, false, new HexEncoder(new FileSink(std::cout)));
			xx.Pump(2048); xx.Flush(false);
			std::cout << "\n";
			SignalTestFailure();
		}

		std::string decrypted;
		StreamTransformationFilter decFilter(*decryptor, new StringSink(decrypted),
				static_cast<BlockPaddingSchemeDef::BlockPaddingScheme>(paddingScheme));

		StringStore cstore(encrypted);
		RandomizedTransfer(cstore, decFilter, true);
		decFilter.MessageEnd();

		if (decrypted != plaintext)
		{
			std::cout << "\nincorrectly decrypted: ";
			StringSource xx(decrypted, false, new HexEncoder(new FileSink(std::cout)));
			xx.Pump(256); xx.Flush(false);
			std::cout << "\n";
			SignalTestFailure();
		}
	}
	else
	{
		std::string msg("Unknown symmetric cipher test \"" + test + "\"");
		SignalTestError(msg.c_str());
	}
}

void TestAuthenticatedSymmetricCipher(TestData &v, const NameValuePairs &overrideParameters)
{
	std::string type = GetRequiredDatum(v, "AlgorithmType");
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");
	std::string key = GetDecodedDatum(v, "Key");

	std::string plaintext = GetOptionalDecodedDatum(v, "Plaintext");
	std::string ciphertext = GetOptionalDecodedDatum(v, "Ciphertext");
	std::string header = GetOptionalDecodedDatum(v, "Header");
	std::string footer = GetOptionalDecodedDatum(v, "Footer");
	std::string mac = GetOptionalDecodedDatum(v, "MAC");

	TestDataNameValuePairs testDataPairs(v);
	CombinedNameValuePairs pairs(overrideParameters, testDataPairs);

	if (test == "Encrypt" || test == "EncryptXorDigest" || test == "NotVerify")
	{
		member_ptr<AuthenticatedSymmetricCipher> encryptor, decryptor;
		encryptor.reset(ObjectFactoryRegistry<AuthenticatedSymmetricCipher, ENCRYPTION>::Registry().CreateObject(name.c_str()));
		decryptor.reset(ObjectFactoryRegistry<AuthenticatedSymmetricCipher, DECRYPTION>::Registry().CreateObject(name.c_str()));
		encryptor->SetKey(ConstBytePtr(key), BytePtrSize(key), pairs);
		decryptor->SetKey(ConstBytePtr(key), BytePtrSize(key), pairs);

		// Code coverage
		(void)encryptor->AlgorithmName();
		(void)decryptor->AlgorithmName();

		std::string encrypted, decrypted;
		AuthenticatedEncryptionFilter ef(*encryptor, new StringSink(encrypted));
		bool macAtBegin = !mac.empty() && !Test::GlobalRNG().GenerateBit();	// test both ways randomly
		AuthenticatedDecryptionFilter df(*decryptor, new StringSink(decrypted), macAtBegin ? AuthenticatedDecryptionFilter::MAC_AT_BEGIN : 0);

		if (encryptor->NeedsPrespecifiedDataLengths())
		{
			encryptor->SpecifyDataLengths(header.size(), plaintext.size(), footer.size());
			decryptor->SpecifyDataLengths(header.size(), plaintext.size(), footer.size());
		}

		StringStore sh(header), sp(plaintext), sc(ciphertext), sf(footer), sm(mac);

		if (macAtBegin)
			RandomizedTransfer(sm, df, true);
		sh.CopyTo(df, LWORD_MAX, AAD_CHANNEL);
		RandomizedTransfer(sc, df, true);
		sf.CopyTo(df, LWORD_MAX, AAD_CHANNEL);
		if (!macAtBegin)
			RandomizedTransfer(sm, df, true);
		df.MessageEnd();

		RandomizedTransfer(sh, ef, true, AAD_CHANNEL);
		RandomizedTransfer(sp, ef, true);
		RandomizedTransfer(sf, ef, true, AAD_CHANNEL);
		ef.MessageEnd();

		if (test == "Encrypt" && encrypted != ciphertext+mac)
		{
			std::cout << "\nincorrectly encrypted: ";
			StringSource xx(encrypted, false, new HexEncoder(new FileSink(std::cout)));
			xx.Pump(2048); xx.Flush(false);
			std::cout << "\n";
			SignalTestFailure();
		}
		if (test == "Encrypt" && decrypted != plaintext)
		{
			std::cout << "\nincorrectly decrypted: ";
			StringSource xx(decrypted, false, new HexEncoder(new FileSink(std::cout)));
			xx.Pump(256); xx.Flush(false);
			std::cout << "\n";
			SignalTestFailure();
		}

		if (ciphertext.size()+mac.size()-plaintext.size() != encryptor->DigestSize())
		{
			std::cout << "\nbad MAC size\n";
			SignalTestFailure();
		}
		if (df.GetLastResult() != (test == "Encrypt"))
		{
			std::cout << "\nMAC incorrectly verified\n";
			SignalTestFailure();
		}
	}
	else
	{
		std::string msg("Unknown authenticated symmetric cipher test \"" + test + "\"");
		SignalTestError(msg.c_str());
	}
}

void TestDigestOrMAC(TestData &v, bool testDigest)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");
	const char *digestName = testDigest ? "Digest" : "MAC";

	member_ptr<MessageAuthenticationCode> mac;
	member_ptr<HashTransformation> hash;
	HashTransformation *pHash = NULLPTR;

	TestDataNameValuePairs pairs(v);

	if (testDigest)
	{
		hash.reset(ObjectFactoryRegistry<HashTransformation>::Registry().CreateObject(name.c_str()));
		pHash = hash.get();

		// Code coverage
		(void)hash->AlgorithmName();
		(void)hash->AlgorithmProvider();
	}
	else
	{
		mac.reset(ObjectFactoryRegistry<MessageAuthenticationCode>::Registry().CreateObject(name.c_str()));
		pHash = mac.get();
		std::string key = GetDecodedDatum(v, "Key");
		mac->SetKey(ConstBytePtr(key), BytePtrSize(key), pairs);

		// Code coverage
		(void)mac->AlgorithmName();
		(void)mac->AlgorithmProvider();
	}

	if (test == "Verify" || test == "VerifyTruncated" || test == "NotVerify")
	{
		int digestSize = -1;
		if (test == "VerifyTruncated")
			digestSize = pairs.GetIntValueWithDefault(Name::DigestSize(), digestSize);
		HashVerificationFilter verifierFilter(*pHash, NULLPTR, HashVerificationFilter::HASH_AT_BEGIN, digestSize);
		PutDecodedDatumInto(v, digestName, verifierFilter);
		PutDecodedDatumInto(v, "Message", verifierFilter);
		verifierFilter.MessageEnd();
		if (verifierFilter.GetLastResult() == (test == "NotVerify"))
			SignalTestFailure();
	}
	else
	{
		std::string msg("Unknown digest or mac test \"" + test + "\"");
		SignalTestError(msg.c_str());
	}
}

void TestKeyDerivationFunction(TestData &v)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");

	if(test == "Skip") return;
	CRYPTOPP_ASSERT(test == "Verify");

	std::string secret = GetDecodedDatum(v, "Secret");
	std::string expected = GetDecodedDatum(v, "DerivedKey");

	TestDataNameValuePairs pairs(v);

	member_ptr<KeyDerivationFunction> kdf;
	kdf.reset(ObjectFactoryRegistry<KeyDerivationFunction>::Registry().CreateObject(name.c_str()));

	std::string calculated; calculated.resize(expected.size());
	kdf->DeriveKey(BytePtr(calculated), BytePtrSize(calculated), BytePtr(secret), BytePtrSize(secret), pairs);

	if(calculated != expected)
	{
		std::cerr << "Calculated: ";
		StringSource(calculated, true, new HexEncoder(new FileSink(std::cerr)));
		std::cerr << std::endl;

		SignalTestFailure();
	}
}

inline char FirstChar(const std::string& str) {
	if (str.empty()) return 0;
	return str[0];
}

inline char LastChar(const std::string& str) {
	if (str.empty()) return 0;
	return str[str.length()-1];
}

// GetField parses the name/value pairs. The tricky part is the insertion operator
// because Unix&Linux uses LF, OS X uses CR, and Windows uses CRLF. If this function
// is modified, then run 'cryptest.exe tv rsa_pkcs1_1_5' as a test. Its the parser
// file from hell. If it can be parsed without error, then things are likely OK.
// For istream.fail() see https://stackoverflow.com/q/34395801/608639.
bool GetField(std::istream &is, std::string &name, std::string &value)
{
	std::string line;
	name.clear(); value.clear();

	// ***** Name *****
	while (is >> std::ws && std::getline(is, line))
	{
		// Eat whitespace and comments gracefully
		if (line.empty() || line[0] == '#')
			continue;

		std::string::size_type pos = line.find(':');
		if (pos == std::string::npos)
			SignalTestError("Unable to parse name/value pair");

		name = TrimSpace(line.substr(0, pos));
		line = TrimSpace(line.substr(pos + 1));

		// Empty name is bad
		if (name.empty())
			return false;

		// Empty value is ok
		if (line.empty())
			return true;

		break;
	}

	// ***** Value *****
	bool continueLine = true;

	do
	{
		// Trim leading and trailing whitespace, including OS X and Windows
		// new lines. Don't parse comments here because there may be a line
		// continuation at the end.
		line = TrimSpace(line);

		continueLine = false;
		if (line.empty())
			continue;

		// Early out for immediate line continuation
		if (line[0] == '\\') {
			continueLine = true;
			continue;
		}
		// Check end of line. It must be last character
		if (LastChar(line) == '\\') {
			continueLine = true;
			line.erase(line.end()-1);
			line = TrimSpace(line);
		}

		// Re-trim after parsing
		line = TrimComment(line);

		if (line.empty())
			continue;

		// Finally... the value
		value += line;

		if (continueLine)
			value += ' ';
	}
	while (continueLine && is >> std::ws && std::getline(is, line));

	return true;
}

void OutputPair(const NameValuePairs &v, const char *name)
{
	Integer x;
	bool b = v.GetValue(name, x);
	CRYPTOPP_UNUSED(b); CRYPTOPP_ASSERT(b);
	std::cout << name << ": \\\n    ";
	x.Encode(HexEncoder(new FileSink(std::cout), false, 64, "\\\n    ").Ref(), x.MinEncodedSize());
	std::cout << std::endl;
}

void OutputNameValuePairs(const NameValuePairs &v)
{
	std::string names = v.GetValueNames();
	std::string::size_type i = 0;
	while (i < names.size())
	{
		std::string::size_type j = names.find_first_of (';', i);

		if (j == std::string::npos)
			return;
		else
		{
			std::string name = names.substr(i, j-i);
			if (name.find(':') == std::string::npos)
				OutputPair(v, name.c_str());
		}

		i = j + 1;
	}
}

void TestDataFile(std::string filename, const NameValuePairs &overrideParameters, unsigned int &totalTests, unsigned int &failedTests)
{
	filename = DataDir(filename);
	std::ifstream file(filename.c_str());
	if (!file.good())
		throw Exception(Exception::OTHER_ERROR, "Can not open file " + filename + " for reading");

	TestData v;
	s_currentTestData = &v;
	std::string name, value, lastAlgName;

	while (file)
	{
		if (!GetField(file, name, value))
			break;

		if (name == "AlgorithmType")
			v.clear();

		// Can't assert value. Plaintext is sometimes empty.
		// CRYPTOPP_ASSERT(!value.empty());
		v[name] = value;

		if (name == "Test" && (s_thorough || v["SlowTest"] != "1"))
		{
			bool failed = true;
			std::string algType = GetRequiredDatum(v, "AlgorithmType");

			if (lastAlgName != GetRequiredDatum(v, "Name"))
			{
				lastAlgName = GetRequiredDatum(v, "Name");
				std::cout << "\nTesting " << algType.c_str() << " algorithm " << lastAlgName.c_str() << ".\n";
			}

			try
			{
				if (algType == "Signature")
					TestSignatureScheme(v);
				else if (algType == "SymmetricCipher")
					TestSymmetricCipher(v, overrideParameters);
				else if (algType == "AuthenticatedSymmetricCipher")
					TestAuthenticatedSymmetricCipher(v, overrideParameters);
				else if (algType == "AsymmetricCipher")
					TestAsymmetricCipher(v);
				else if (algType == "MessageDigest")
					TestDigestOrMAC(v, true);
				else if (algType == "MAC")
					TestDigestOrMAC(v, false);
				else if (algType == "KDF")
					TestKeyDerivationFunction(v);
				else if (algType == "FileList")
					TestDataFile(GetRequiredDatum(v, "Test"), g_nullNameValuePairs, totalTests, failedTests);
				else
					SignalUnknownAlgorithmError(algType);
				failed = false;
			}
			catch (const TestFailure &)
			{
				std::cout << "\nTest FAILED.\n";
			}
			catch (const CryptoPP::Exception &e)
			{
				std::cout << "\nCryptoPP::Exception caught: " << e.what() << std::endl;
			}
			catch (const std::exception &e)
			{
				std::cout << "\nstd::exception caught: " << e.what() << std::endl;
			}

			if (failed)
			{
				std::cout << "Skipping to next test.\n";
				failedTests++;
			}
			else
				std::cout << "." << std::flush;

			totalTests++;
		}
	}
}

bool RunTestDataFile(const char *filename, const NameValuePairs &overrideParameters, bool thorough)
{
	s_thorough = thorough;
	unsigned int totalTests = 0, failedTests = 0;
	TestDataFile((filename ? filename : ""), overrideParameters, totalTests, failedTests);

	std::cout << std::dec << "\nTests complete. Total tests = " << totalTests << ". Failed tests = " << failedTests << "." << std::endl;
	if (failedTests != 0)
		std::cout << "SOME TESTS FAILED!\n";

	CRYPTOPP_ASSERT(failedTests == 0);
	return failedTests == 0;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
