#include "factory.h"
#include "integer.h"
#include "filters.h"
#include "hex.h"
#include "randpool.h"
#include "files.h"
#include "trunhash.h"
#include "queue.h"
#include "validate.h"
#include <iostream>
#include <memory>

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

typedef std::map<std::string, std::string> TestData;

class TestFailure : public Exception
{
public:
	TestFailure() : Exception(OTHER_ERROR, "Validation test failed") {}
};

static const TestData *s_currentTestData = NULL;

static void OutputTestData(const TestData &v)
{
	for (TestData::const_iterator i = v.begin(); i != v.end(); ++i)
	{
		cerr << i->first << ": " << i->second << endl;
	}
}

static void SignalTestFailure()
{
	OutputTestData(*s_currentTestData);
	throw TestFailure();
}

static void SignalTestError()
{
	OutputTestData(*s_currentTestData);
	throw Exception(Exception::OTHER_ERROR, "Unexpected error during validation test");
}

const std::string & GetRequiredDatum(const TestData &data, const char *name)
{
	TestData::const_iterator i = data.find(name);
	if (i == data.end())
		SignalTestError();
	return i->second;
}

void PutDecodedDatumInto(const TestData &data, const char *name, BufferedTransformation &target)
{
	std::string s1 = GetRequiredDatum(data, name), s2;

	while (!s1.empty())
	{
		while (s1[0] == ' ')
			s1 = s1.substr(1);

		int repeat = 1;
		if (s1[0] == 'r')
		{
			repeat = atoi(s1.c_str()+1);
			s1 = s1.substr(s1.find(' ')+1);
		}
		
		s2 = ""; // MSVC 6 doesn't have clear();

		if (s1[0] == '\"')
		{
			s2 = s1.substr(1, s1.find('\"', 1)-1);
			s1 = s1.substr(s2.length() + 2);
		}
		else if (s1.substr(0, 2) == "0x")
		{
			StringSource(s1.substr(2, s1.find(' ')), true, new HexDecoder(new StringSink(s2)));
			s1 = s1.substr(STDMIN(s1.find(' '), s1.length()));
		}
		else
		{
			StringSource(s1.substr(0, s1.find(' ')), true, new HexDecoder(new StringSink(s2)));
			s1 = s1.substr(STDMIN(s1.find(' '), s1.length()));
		}

		ByteQueue q;
		while (repeat--)
		{
			q.Put((const byte *)s2.data(), s2.size());
			if (q.MaxRetrievable() > 4*1024 || repeat == 0)
				q.TransferTo(target);
		}
	}
}

std::string GetDecodedDatum(const TestData &data, const char *name)
{
	std::string s;
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
			return false;
		
		const std::string &value = i->second;
		
		if (valueType == typeid(int))
			*reinterpret_cast<int *>(pValue) = atoi(value.c_str());
		else if (valueType == typeid(Integer))
			*reinterpret_cast<Integer *>(pValue) = Integer((std::string(value) + "h").c_str());
		else if (valueType == typeid(ConstByteArrayParameter))
		{
			m_temp.resize(0);
			PutDecodedDatumInto(m_data, name, StringSink(m_temp).Ref());
			reinterpret_cast<ConstByteArrayParameter *>(pValue)->Assign((const byte *)m_temp.data(), m_temp.size(), true);
		}
		else if (valueType == typeid(const byte *))
		{
			m_temp.resize(0);
			PutDecodedDatumInto(m_data, name, StringSink(m_temp).Ref());
			*reinterpret_cast<const byte * *>(pValue) = (const byte *)m_temp.data();
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
	if (!pub.Validate(GlobalRNG(), 3))
		SignalTestFailure();
	if (!priv.Validate(GlobalRNG(), 3))
		SignalTestFailure();

/*	EqualityComparisonFilter comparison;
	pub.Save(ChannelSwitch(comparison, "0"));
	pub.AssignFrom(priv);
	pub.Save(ChannelSwitch(comparison, "1"));
	comparison.ChannelMessageSeriesEnd("0");
	comparison.ChannelMessageSeriesEnd("1");
*/
}

void TestSignatureScheme(TestData &v)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");

	std::auto_ptr<PK_Signer> signer(ObjectFactoryRegistry<PK_Signer>::Registry().CreateObject(name.c_str()));
	std::auto_ptr<PK_Verifier> verifier(ObjectFactoryRegistry<PK_Verifier>::Registry().CreateObject(name.c_str()));

	TestDataNameValuePairs pairs(v);
	std::string keyFormat = GetRequiredDatum(v, "KeyFormat");

	if (keyFormat == "DER")
		verifier->AccessMaterial().Load(StringStore(GetDecodedDatum(v, "PublicKey")).Ref());
	else if (keyFormat == "Component")
		verifier->AccessMaterial().AssignFrom(pairs);

	if (test == "Verify" || test == "NotVerify")
	{
		VerifierFilter verifierFilter(*verifier, NULL, VerifierFilter::SIGNATURE_AT_BEGIN);
		PutDecodedDatumInto(v, "Signature", verifierFilter);
		PutDecodedDatumInto(v, "Message", verifierFilter);
		verifierFilter.MessageEnd();
		if (verifierFilter.GetLastResult() == (test == "NotVerify"))
			SignalTestFailure();
	}
	else if (test == "PublicKeyValid")
	{
		if (!verifier->GetMaterial().Validate(GlobalRNG(), 3))
			SignalTestFailure();
	}
	else
		goto privateKeyTests;

	return;

privateKeyTests:
	if (keyFormat == "DER")
		signer->AccessMaterial().Load(StringStore(GetDecodedDatum(v, "PrivateKey")).Ref());
	else if (keyFormat == "Component")
		signer->AccessMaterial().AssignFrom(pairs);
	
	if (test == "KeyPairValidAndConsistent")
	{
		TestKeyPairValidAndConsistent(verifier->AccessMaterial(), signer->GetMaterial());
	}
	else if (test == "Sign")
	{
		SignerFilter f(GlobalRNG(), *signer, new HexEncoder(new FileSink(cout)));
		StringSource ss(GetDecodedDatum(v, "Message"), true, new Redirector(f));
		SignalTestFailure();
	}
	else if (test == "DeterministicSign")
	{
		SignalTestError();
		assert(false);	// TODO: implement
	}
	else if (test == "RandomSign")
	{
		SignalTestError();
		assert(false);	// TODO: implement
	}
	else if (test == "GenerateKey")
	{
		SignalTestError();
		assert(false);
	}
	else
	{
		SignalTestError();
		assert(false);
	}
}

void TestAsymmetricCipher(TestData &v)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");

	std::auto_ptr<PK_Encryptor> encryptor(ObjectFactoryRegistry<PK_Encryptor>::Registry().CreateObject(name.c_str()));
	std::auto_ptr<PK_Decryptor> decryptor(ObjectFactoryRegistry<PK_Decryptor>::Registry().CreateObject(name.c_str()));

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
		StringSource ss(GetDecodedDatum(v, "Ciphertext"), true, new PK_DecryptorFilter(GlobalRNG(), *decryptor, new StringSink(decrypted)));
		if (decrypted != expected)
			SignalTestFailure();
	}
	else if (test == "KeyPairValidAndConsistent")
	{
		TestKeyPairValidAndConsistent(encryptor->AccessMaterial(), decryptor->GetMaterial());
	}
	else
	{
		SignalTestError();
		assert(false);
	}
}

void TestSymmetricCipher(TestData &v)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");

	std::string key = GetDecodedDatum(v, "Key");
	std::string plaintext = GetDecodedDatum(v, "Plaintext");

	TestDataNameValuePairs pairs(v);

	if (test == "Encrypt" || test == "EncryptXorDigest")
	{
		std::auto_ptr<SymmetricCipher> encryptor(ObjectFactoryRegistry<SymmetricCipher, ENCRYPTION>::Registry().CreateObject(name.c_str()));
		std::auto_ptr<SymmetricCipher> decryptor(ObjectFactoryRegistry<SymmetricCipher, DECRYPTION>::Registry().CreateObject(name.c_str()));
		ConstByteArrayParameter iv;
		if (pairs.GetValue(Name::IV(), iv) && iv.size() != encryptor->IVSize())
			SignalTestFailure();
		encryptor->SetKey((const byte *)key.data(), key.size(), pairs);
		decryptor->SetKey((const byte *)key.data(), key.size(), pairs);
		int seek = pairs.GetIntValueWithDefault("Seek", 0);
		if (seek)
		{
			encryptor->Seek(seek);
			decryptor->Seek(seek);
		}
		std::string encrypted, xorDigest, ciphertext, ciphertextXorDigest;
		StringSource ss(plaintext, false, new StreamTransformationFilter(*encryptor, new StringSink(encrypted), StreamTransformationFilter::NO_PADDING));
		ss.Pump(plaintext.size()/2 + 1);
		ss.PumpAll();
		/*{
			std::string z;
			encryptor->Seek(seek);
			StringSource ss(plaintext, false, new StreamTransformationFilter(*encryptor, new StringSink(z), StreamTransformationFilter::NO_PADDING));
			while (ss.Pump(64)) {}
			ss.PumpAll();
			for (int i=0; i<z.length(); i++)
				assert(encrypted[i] == z[i]);
		}*/
		if (test == "Encrypt")
			ciphertext = GetDecodedDatum(v, "Ciphertext");
		else
		{
			ciphertextXorDigest = GetDecodedDatum(v, "CiphertextXorDigest");
			xorDigest.append(encrypted, 0, 64);
			for (size_t i=64; i<encrypted.size(); i++)
				xorDigest[i%64] ^= encrypted[i];
		}
		if (test == "Encrypt" ? encrypted != ciphertext : xorDigest != ciphertextXorDigest)
		{
			std::cout << "incorrectly encrypted: ";
			StringSource xx(encrypted, false, new HexEncoder(new FileSink(std::cout)));
			xx.Pump(256); xx.Flush(false);
			std::cout << "\n";
			SignalTestFailure();
		}
		std::string decrypted;
		StringSource dd(encrypted, false, new StreamTransformationFilter(*decryptor, new StringSink(decrypted), StreamTransformationFilter::NO_PADDING));
		dd.Pump(plaintext.size()/2 + 1);
		dd.PumpAll();
		if (decrypted != plaintext)
		{
			std::cout << "incorrectly decrypted: ";
			StringSource xx(decrypted, false, new HexEncoder(new FileSink(std::cout)));
			xx.Pump(256); xx.Flush(false);
			std::cout << "\n";
			SignalTestFailure();
		}
	}
	else if (test == "Decrypt")
	{
	}
	else
	{
		SignalTestError();
		assert(false);
	}
}

void TestDigestOrMAC(TestData &v, bool testDigest)
{
	std::string name = GetRequiredDatum(v, "Name");
	std::string test = GetRequiredDatum(v, "Test");

	member_ptr<MessageAuthenticationCode> mac;
	member_ptr<HashTransformation> hash;
	HashTransformation *pHash = NULL;

	TestDataNameValuePairs pairs(v);

	if (testDigest)
	{
		hash.reset(ObjectFactoryRegistry<HashTransformation>::Registry().CreateObject(name.c_str()));
		pHash = hash.get();
	}
	else
	{
		mac.reset(ObjectFactoryRegistry<MessageAuthenticationCode>::Registry().CreateObject(name.c_str()));
		pHash = mac.get();
		ConstByteArrayParameter iv;
		if (pairs.GetValue(Name::IV(), iv) && iv.size() != mac->IVSize())
			SignalTestFailure();
		std::string key = GetDecodedDatum(v, "Key");
		mac->SetKey((const byte *)key.c_str(), key.size(), pairs);
	}

	if (test == "Verify" || test == "VerifyTruncated" || test == "NotVerify")
	{
		int digestSize = pHash->DigestSize();
		if (test == "VerifyTruncated")
			digestSize = atoi(GetRequiredDatum(v, "TruncatedSize").c_str());
		TruncatedHashModule thash(*pHash, digestSize);
		HashVerificationFilter verifierFilter(thash, NULL, HashVerificationFilter::HASH_AT_BEGIN);
		PutDecodedDatumInto(v, "Digest", verifierFilter);
		PutDecodedDatumInto(v, "Message", verifierFilter);
		verifierFilter.MessageEnd();
		if (verifierFilter.GetLastResult() == (test == "NotVerify"))
			SignalTestFailure();
	}
	else
	{
		SignalTestError();
		assert(false);
	}
}

bool GetField(std::istream &is, std::string &name, std::string &value)
{
	name.resize(0);		// GCC workaround: 2.95.3 doesn't have clear()
	is >> name;
	if (name.empty())
		return false;

	if (name[name.size()-1] != ':')
		SignalTestError();
	name.erase(name.size()-1);

	while (is.peek() == ' ')
		is.ignore(1);

	// VC60 workaround: getline bug
	char buffer[128];
	value.resize(0);	// GCC workaround: 2.95.3 doesn't have clear()
	bool continueLine;

	do
	{
		do
		{
			is.get(buffer, sizeof(buffer));
			value += buffer;
		}
		while (buffer[0] != 0);
		is.clear();
		is.ignore();

		if (!value.empty() && value[value.size()-1] == '\r')
			value.resize(value.size()-1);

		if (!value.empty() && value[value.size()-1] == '\\')
		{
			value.resize(value.size()-1);
			continueLine = true;
		}
		else
			continueLine = false;

		std::string::size_type i = value.find('#');
		if (i != std::string::npos)
			value.erase(i);
	}
	while (continueLine);

	return true;
}

void OutputPair(const NameValuePairs &v, const char *name)
{
	Integer x;
	bool b = v.GetValue(name, x);
	assert(b);
	cout << name << ": \\\n    ";
	x.Encode(HexEncoder(new FileSink(cout), false, 64, "\\\n    ").Ref(), x.MinEncodedSize());
	cout << endl;
}

void OutputNameValuePairs(const NameValuePairs &v)
{
	std::string names = v.GetValueNames();
	string::size_type i = 0;
	while (i < names.size())
	{
		string::size_type j = names.find_first_of (';', i);

		if (j == string::npos)
			return;
		else
		{
			std::string name = names.substr(i, j-i);
			if (name.find(':') == string::npos)
				OutputPair(v, name.c_str());
		}

		i = j + 1;
	}
}

void TestDataFile(const std::string &filename, unsigned int &totalTests, unsigned int &failedTests)
{
	std::ifstream file(filename.c_str());
	if (!file.good())
		throw Exception(Exception::OTHER_ERROR, "Can not open file " + filename + " for reading");
	TestData v;
	s_currentTestData = &v;
	std::string name, value, lastAlgName;

	while (file)
	{
		while (file.peek() == '#')
			file.ignore(INT_MAX, '\n');

		if (file.peek() == '\n')
			v.clear();

		if (!GetField(file, name, value))
			break;
		v[name] = value;

		if (name == "Test")
		{
			bool failed = true;
			std::string algType = GetRequiredDatum(v, "AlgorithmType");

			if (lastAlgName != GetRequiredDatum(v, "Name"))
			{
				lastAlgName = GetRequiredDatum(v, "Name");
				cout << "\nTesting " << algType.c_str() << " algorithm " << lastAlgName.c_str() << ".\n";
			}

			try
			{
				if (algType == "Signature")
					TestSignatureScheme(v);
				else if (algType == "SymmetricCipher")
					TestSymmetricCipher(v);
				else if (algType == "AsymmetricCipher")
					TestAsymmetricCipher(v);
				else if (algType == "MessageDigest")
					TestDigestOrMAC(v, true);
				else if (algType == "MAC")
					TestDigestOrMAC(v, false);
				else if (algType == "FileList")
					TestDataFile(GetRequiredDatum(v, "Test"), totalTests, failedTests);
				else
					SignalTestError();
				failed = false;
			}
			catch (TestFailure &)
			{
				cout << "\nTest failed.\n";
			}
			catch (CryptoPP::Exception &e)
			{
				cout << "\nCryptoPP::Exception caught: " << e.what() << endl;
			}
			catch (std::exception &e)
			{
				cout << "\nstd::exception caught: " << e.what() << endl;
			}

			if (failed)
			{
				cout << "Skipping to next test.\n";
				failedTests++;
			}
			else
				cout << "." << flush;

			totalTests++;
		}
	}
}

bool RunTestDataFile(const char *filename)
{
	unsigned int totalTests = 0, failedTests = 0;
	TestDataFile(filename, totalTests, failedTests);
	cout << "\nTests complete. Total tests = " << totalTests << ". Failed tests = " << failedTests << ".\n";
	if (failedTests != 0)
		cout << "SOME TESTS FAILED!\n";
	return failedTests == 0;
}
