// fipsalgt.cpp - written and placed in the public domain by Wei Dai

// This file implements the various algorithm tests needed to pass FIPS 140 validation.
// They're preserved here (commented out) in case Crypto++ needs to be revalidated.

/*
class LineBreakParser : public AutoSignaling<Bufferless<Filter> >
{
public:
	LineBreakParser(BufferedTransformation *attachment=NULL, byte lineEnd='\n')
		: AutoSignaling<Bufferless<Filter> >(attachment), m_lineEnd(lineEnd) {}

	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
	{
		if (!blocking)
			throw BlockingInputOnly("LineBreakParser");
		
		unsigned int i, last = 0;
		for (i=0; i<length; i++)
		{
			if (begin[i] == m_lineEnd)
			{
				AttachedTransformation()->Put2(begin+last, i-last, GetAutoSignalPropagation(), blocking);
				last = i+1;
			}
		}
		if (last != i)
			AttachedTransformation()->Put2(begin+last, i-last, 0, blocking);

		if (messageEnd && GetAutoSignalPropagation())
		{
			AttachedTransformation()->MessageEnd(GetAutoSignalPropagation()-1, blocking);
			AttachedTransformation()->MessageSeriesEnd(GetAutoSignalPropagation()-1, blocking);
		}

		return 0;
	}

private:
	byte m_lineEnd;
};

class TestDataParser : public Unflushable<FilterWithInputQueue>
{
public:
	enum DataType {OTHER, COUNT, KEY_T, IV, INPUT, OUTPUT};

	TestDataParser(std::string algorithm, std::string test, std::string mode, unsigned int feedbackSize, bool encrypt, BufferedTransformation *attachment)
		: Unflushable<FilterWithInputQueue>(attachment)
		, m_algorithm(algorithm), m_test(test), m_mode(mode), m_feedbackSize(feedbackSize)
		, m_firstLine(true), m_blankLineTransition(0)
	{
		m_nameToType["COUNT"] = COUNT;
		m_nameToType["KEY"] = KEY_T;
		m_nameToType["KEYs"] = KEY_T;
		m_nameToType["key"] = KEY_T;
		m_nameToType["IV"] = IV;
		m_nameToType["IV1"] = IV;
		m_nameToType["CV"] = IV;
		m_nameToType["CV1"] = IV;
		m_nameToType["IB"] = IV;
		m_nameToType["TEXT"] = INPUT;
		m_nameToType["RESULT"] = OUTPUT;
		SetEncrypt(encrypt);

		if (m_algorithm == "DSS")
		{
			if (m_test == "prime")
				m_trigger = "Prime";
			else if (m_test == "pqg")
				m_trigger = "N";
			else if (m_test == "xy")
				m_trigger = "G";
			else if (m_test == "gensig")
				m_trigger = "Msg";
			else if (m_test == "versig")
				m_trigger = "Sig";
			else if (m_test == "verpqg")
				m_trigger = "c";
		}
	}

	void SetEncrypt(bool encrypt)
	{
		m_encrypt = encrypt;
		if (encrypt)
		{
			m_nameToType["PLAINTEXT"] = INPUT;
			m_nameToType["CIPHERTEXT"] = OUTPUT;
			m_nameToType["PT"] = INPUT;
			m_nameToType["CT"] = OUTPUT;
		}
		else
		{
			m_nameToType["PLAINTEXT"] = OUTPUT;
			m_nameToType["CIPHERTEXT"] = INPUT;
			m_nameToType["PT"] = OUTPUT;
			m_nameToType["CT"] = INPUT;
		}
	}

protected:
	void OutputData(std::string &output, const std::string &key, const std::string &data)
	{
		output += key;
		output += "= ";
		output += data;
		output += "\n";
	}

	void OutputData(std::string &output, const std::string &key, int data)
	{
		OutputData(output, key, IntToString(data));
	}

	void OutputData(std::string &output, const std::string &key, const SecByteBlock &data)
	{
		output += key;
		output += "= ";
		HexEncoder(new StringSink(output), false).Put(data, data.size());
		output += "\n";
	}

	void OutputData(std::string &output, const std::string &key, const Integer &data)
	{
		SecByteBlock s(data.MinEncodedSize());
		data.Encode(s, s.size());
		OutputData(output, key, s);
	}

	void OutputData(std::string &output, DataType t, const std::string &data)
	{
		if (m_algorithm == "SKIPJACK")
		{
			if (m_test == "KAT")
			{
				if (t == OUTPUT)
					output = m_line + data + "\n";
			}
			else
			{
				if (t != COUNT)
				{
					output += m_typeToName[t];
					output += "=";
				}
				output += data;
				output += t == OUTPUT ? "\n" : "  ";
			}
		}
		else if (m_algorithm == "TDES" && t == KEY_T && m_typeToName[KEY_T].empty())
		{
			output += "KEY1 = ";
			output += data.substr(0, 16);
			output += "\nKEY2 = ";
			output += data.size() > 16 ? data.substr(16, 16) : data.substr(0, 16);
			output += "\nKEY3 = ";
			output += data.size() > 32 ? data.substr(32, 16) : data.substr(0, 16);
			output += "\n";
		}
		else
		{
			output += m_typeToName[t];
			output += " = ";
			output += data;
			output += "\n";
		}
	}

	void OutputData(std::string &output, DataType t, int i)
	{
		OutputData(output, t, IntToString(i));
	}

	void OutputData(std::string &output, DataType t, const SecByteBlock &data)
	{
		std::string hexData;
		StringSource(data, true, new HexEncoder(new StringSink(hexData), false));
		OutputData(output, t, hexData);
	}

	void OutputGivenData(std::string &output, DataType t, bool optional = false)
	{
		if (m_data.find(m_typeToName[t]) == m_data.end())
		{
			if (optional)
				return;
			throw Exception(Exception::OTHER_ERROR, "TestDataParser: key not found: " + m_typeToName[t]);
		}

		OutputData(output, t, m_data[m_typeToName[t]]);
	}

	template <class T>
		BlockCipher * NewBT(T *)
	{
		if (!m_encrypt && (m_mode == "ECB" || m_mode == "CBC"))
			return new typename T::Decryption;
		else
			return new typename T::Encryption;
	}

	template <class T>
		SymmetricCipher * NewMode(T *, BlockCipher &bt, const byte *iv)
	{
		if (!m_encrypt)
			return new typename T::Decryption(bt, iv, m_feedbackSize/8);
		else
			return new typename T::Encryption(bt, iv, m_feedbackSize/8);
	}

	static inline void Xor(SecByteBlock &z, const SecByteBlock &x, const SecByteBlock &y)
	{
		assert(x.size() == y.size());
		z.resize(x.size());
		xorbuf(z, x, y, x.size());
	}

	SecByteBlock UpdateKey(SecByteBlock key, const SecByteBlock *text)
	{
		unsigned int innerCount = (m_algorithm == "AES") ? 1000 : 10000;
		int keySize = key.size(), blockSize = text[0].size();
		SecByteBlock x(keySize);
		for (int k=0; k<keySize;)
		{
			int pos = innerCount * blockSize - keySize + k;
			memcpy(x + k, text[pos / blockSize] + pos % blockSize, blockSize - pos % blockSize);
			k += blockSize - pos % blockSize;
		}

		if (m_algorithm == "TDES" || m_algorithm == "DES")
		{
			for (int i=0; i<keySize; i+=8)
			{
				xorbuf(key+i, x+keySize-8-i, 8);
				DES::CorrectKeyParityBits(key+i);
			}
		}
		else
			xorbuf(key, x, keySize);

		return key;
	}

	static inline void AssignLeftMostBits(SecByteBlock &z, const SecByteBlock &x, unsigned int K)
	{
		z.Assign(x, K/8);
	}

	virtual void DoTest()
	{
		std::string output;

		if (m_algorithm == "DSS")
		{
			if (m_test == "sha")
			{
				assert(m_compactString.size() >= 2);
				assert(m_compactString[0] == m_compactString.size()-2);
				bool b = !!m_compactString[1];
				Integer m;
				unsigned int bitLength = 0;

				for (unsigned int j = 2; j < m_compactString.size(); j++)
				{
					m <<= m_compactString[j];
					for (unsigned int k = 0; k < m_compactString[j]; k++)
						m.SetBit(k, b);
					bitLength += m_compactString[j];
					b = !b;
				}
				m_compactString.clear();
				assert(bitLength % 8 == 0);

				SecByteBlock message(bitLength / 8);
				m.Encode(message, message.size());
				SHA sha;

				if (m_bracketString == "SHS Type 3 Strings")
				{
					SecByteBlock m1;
					for (int j = 0; j < 100; j++)
					{
						for (word32 i = 1; i <= 50000; i++)
						{
							m1.resize(message.size() + j/4 + 3 + 4);
							memcpy(m1, message, message.size());
							memset(m1 + message.size(), 0, j/4 + 3);
							PutWord(false, BIG_ENDIAN_ORDER, m1 + m1.size() - 4, i);
							message.resize(sha.DigestSize());
							sha.CalculateDigest(message, m1, m1.size());
						}
						StringSource(message, message.size(), true, new HexEncoder(new StringSink(output)));
						output += " ^\n";
						AttachedTransformation()->Put((byte *)output.data(), output.size());
						output.resize(0);
					}
				}
				else
				{
					StringSource(message, message.size(), true, new HashFilter(sha, new HexEncoder(new StringSink(output))));
					output += " ^\n";
					AttachedTransformation()->Put((byte *)output.data(), output.size());
				}
			}
			else if (m_test == "prime")
			{
				Integer p((m_data["Prime"] + "h").c_str());
				OutputData(output, "result", VerifyPrime(m_rng, p, 2) ? "P" : "F");
				AttachedTransformation()->Put((byte *)output.data(), output.size());
				output.resize(0);
			}
			else if (m_test == "pqg")
			{
				int n = atol(m_data["N"].c_str());
				for (int i=0; i<n; i++)
				{
					Integer p, q, h, g;
					int counter;
					
					SecByteBlock seed(SHA::DIGESTSIZE);
					do
					{
						m_rng.GenerateBlock(seed, seed.size());
					}
					while (!DSA::GeneratePrimes(seed, seed.size()*8, counter, p, 1024, q));
					h.Randomize(m_rng, 2, p-2);
					g = a_exp_b_mod_c(h, (p-1)/q, p);

					OutputData(output, "P", p);
					OutputData(output, "Q", q);
					OutputData(output, "G", g);
					OutputData(output, "Seed", seed);
					OutputData(output, "H", h);
					OutputData(output, "c", counter);
					AttachedTransformation()->Put((byte *)output.data(), output.size());
					output.resize(0);
				}
			}
			else if (m_test == "xy")
			{
				Integer p((m_data["P"] + "h").c_str());
				Integer	q((m_data["Q"] + "h").c_str());
				Integer g((m_data["G"] + "h").c_str());

				for (int i=0; i<10; i++)
				{
					DSA::Signer priv(m_rng, p, q, g);
					DSA::Verifier pub(priv);

					OutputData(output, "X", priv.GetKey().GetPrivateExponent());
					OutputData(output, "Y", pub.GetKey().GetPublicElement());
					AttachedTransformation()->Put((byte *)output.data(), output.size());
					output.resize(0);
				}
			}
			else if (m_test == "gensig")
			{
				Integer p((m_data["P"] + "h").c_str());
				Integer	q((m_data["Q"] + "h").c_str());
				Integer g((m_data["G"] + "h").c_str());
				Integer x((m_data["X"] + "h").c_str());
				DSA::Signer signer(p, q, g, x);

				SecByteBlock sig(signer.SignatureLength());
				StringSource(m_data["Msg"], true, new HexDecoder(new SignerFilter(m_rng, signer, new ArraySink(sig, sig.size()))));
				OutputData(output, "Sig", sig);
				AttachedTransformation()->Put((byte *)output.data(), output.size());
				output.resize(0);
			}
			else if (m_test == "versig")
			{
				Integer p((m_data["P"] + "h").c_str());
				Integer	q((m_data["Q"] + "h").c_str());
				Integer g((m_data["G"] + "h").c_str());
				Integer y((m_data["Y"] + "h").c_str());
				DSA::Verifier verifier(p, q, g, y);

				HexDecoder filter(new SignatureVerificationFilter(verifier));
				StringSource(m_data["Sig"], true, new Redirector(filter, false));
				StringSource(m_data["Msg"], true, new Redirector(filter, false));
				filter.MessageEnd();
				byte b;
				filter.Get(b);
				OutputData(output, "result", b ? "P" : "F");
				AttachedTransformation()->Put((byte *)output.data(), output.size());
				output.resize(0);
			}
			else if (m_test == "verpqg")
			{
				Integer p((m_data["P"] + "h").c_str());
				Integer	q((m_data["Q"] + "h").c_str());
				Integer g((m_data["G"] + "h").c_str());
				Integer h((m_data["H"] + "h").c_str());
				int c = atol(m_data["c"].c_str());
				SecByteBlock seed(m_data["Seed"].size()/2);
				StringSource(m_data["Seed"], true, new HexDecoder(new ArraySink(seed, seed.size())));

				Integer p1, q1;
				bool result = DSA::GeneratePrimes(seed, seed.size()*8, c, p1, 1024, q1, true);
				result = result && (p1 == p && q1 == q);
				result = result && g == a_exp_b_mod_c(h, (p-1)/q, p);

				OutputData(output, "result", result ? "P" : "F");
				AttachedTransformation()->Put((byte *)output.data(), output.size());
				output.resize(0);
			}

			return;
		}

		SecByteBlock &key = m_data2[KEY_T];

		if (m_algorithm == "TDES")
		{
			if (!m_data["KEY1"].empty())
			{
				const std::string keys[3] = {m_data["KEY1"], m_data["KEY2"], m_data["KEY3"]};
				key.resize(24);
				HexDecoder hexDec(new ArraySink(key, key.size()));
				for (int i=0; i<3; i++)
					hexDec.Put((byte *)keys[i].data(), keys[i].size());

				if (keys[0] == keys[2])
				{
					if (keys[0] == keys[1])
						key.resize(8);
					else
						key.resize(16);
				}
				else
					key.resize(24);
			}
		}

		member_ptr<BlockCipher> pBT;
		if (m_algorithm == "DES")
			pBT.reset(NewBT((DES*)0));
		else if (m_algorithm == "TDES")
		{
			if (key.size() == 8)
				pBT.reset(NewBT((DES*)0));
			else if (key.size() == 16)
				pBT.reset(NewBT((DES_EDE2*)0));
			else
				pBT.reset(NewBT((DES_EDE3*)0));
		}
		else if (m_algorithm == "SKIPJACK")
			pBT.reset(NewBT((SKIPJACK*)0));
		else if (m_algorithm == "AES")
			pBT.reset(NewBT((AES*)0));
		else
			throw Exception(Exception::OTHER_ERROR, "TestDataParser: unexpected algorithm: " + m_algorithm);

		if (!pBT->IsValidKeyLength(key.size()))
			key.CleanNew(pBT->DefaultKeyLength());	// for Scbcvrct
		pBT->SetKey(key.data(), key.size());

		SecByteBlock &iv = m_data2[IV];
		if (iv.empty())
			iv.CleanNew(pBT->BlockSize());

		member_ptr<SymmetricCipher> pCipher;
		unsigned int K = m_feedbackSize;

		if (m_mode == "ECB")
			pCipher.reset(NewMode((ECB_Mode_ExternalCipher*)0, *pBT, iv));
		else if (m_mode == "CBC")
			pCipher.reset(NewMode((CBC_Mode_ExternalCipher*)0, *pBT, iv));
		else if (m_mode == "CFB")
			pCipher.reset(NewMode((CFB_Mode_ExternalCipher*)0, *pBT, iv));
		else if (m_mode == "OFB")
			pCipher.reset(NewMode((OFB_Mode_ExternalCipher*)0, *pBT, iv));
		else
			throw Exception(Exception::OTHER_ERROR, "TestDataParser: unexpected mode: " + m_mode);

		bool encrypt = m_encrypt;

		if (m_test == "MONTE")
		{
			SecByteBlock KEY[401];
			KEY[0] = key;
			int keySize = key.size();
			int blockSize = pBT->BlockSize();

			SecByteBlock IB[10001], OB[10001], PT[10001], CT[10001], RESULT[10001], TXT[10001], CV[10001];
			PT[0] = GetData("PLAINTEXT");
			CT[0] = GetData("CIPHERTEXT");
			CV[0] = IB[0] = iv;
			TXT[0] = GetData("TEXT");

			unsigned int outerCount = (m_algorithm == "AES") ? 100 : 400;
			unsigned int innerCount = (m_algorithm == "AES") ? 1000 : 10000;

			for (int i=0; i<outerCount; i++)
			{
				pBT->SetKey(KEY[i], keySize);

				for (int j=0; j<innerCount; j++)
				{
					if (m_mode == "ECB")
					{
						if (encrypt)
						{
							IB[j] = PT[j];
							CT[j].resize(blockSize);
							pBT->ProcessBlock(IB[j], CT[j]);
							PT[j+1] = CT[j];
						}
						else
						{
							IB[j] = CT[j];
							PT[j].resize(blockSize);
							pBT->ProcessBlock(IB[j], PT[j]);
							CT[j+1] = PT[j];
						}
					}
					else if (m_mode == "OFB")
					{
						OB[j].resize(blockSize);
						pBT->ProcessBlock(IB[j], OB[j]);
						Xor(RESULT[j], OB[j], TXT[j]);
						TXT[j+1] = IB[j];
						IB[j+1] = OB[j];
					}
					else if (m_mode == "CBC")
					{
						if (encrypt)
						{
							Xor(IB[j], PT[j], CV[j]);
							CT[j].resize(blockSize);
							pBT->ProcessBlock(IB[j], CT[j]);
							PT[j+1] = CV[j];
							CV[j+1] = CT[j];
						}
						else
						{
							IB[j] = CT[j];
							OB[j].resize(blockSize);
							pBT->ProcessBlock(IB[j], OB[j]);
							Xor(PT[j], OB[j], CV[j]);
							CV[j+1] = CT[j];
							CT[j+1] = PT[j];
						}
					}
					else if (m_mode == "CFB")
					{
						if (encrypt)
						{
							OB[j].resize(blockSize);
							pBT->ProcessBlock(IB[j], OB[j]);
							AssignLeftMostBits(CT[j], OB[j], K);
							Xor(CT[j], CT[j], PT[j]);
							AssignLeftMostBits(PT[j+1], IB[j], K);
							IB[j+1].resize(blockSize);
							memcpy(IB[j+1], IB[j]+K/8, blockSize-K/8);
							memcpy(IB[j+1]+blockSize-K/8, CT[j], K/8);
						}
						else
						{
							OB[j].resize(blockSize);
							pBT->ProcessBlock(IB[j], OB[j]);
							AssignLeftMostBits(PT[j], OB[j], K);
							Xor(PT[j], PT[j], CT[j]);
							IB[j+1].resize(blockSize);
							memcpy(IB[j+1], IB[j]+K/8, blockSize-K/8);
							memcpy(IB[j+1]+blockSize-K/8, CT[j], K/8);
							AssignLeftMostBits(CT[j+1], OB[j], K);
						}
					}
					else
						throw Exception(Exception::OTHER_ERROR, "TestDataParser: unexpected mode: " + m_mode);
				}

				OutputData(output, COUNT, i);
				OutputData(output, KEY_T, KEY[i]);
				if (m_mode == "CBC")
					OutputData(output, IV, CV[0]);
				if (m_mode == "OFB" || m_mode == "CFB")
					OutputData(output, IV, IB[0]);
				if (m_mode == "ECB" || m_mode == "CBC" || m_mode == "CFB")
				{
					if (encrypt)
					{
						OutputData(output, INPUT, PT[0]);
						OutputData(output, OUTPUT, CT[innerCount-1]);
						KEY[i+1] = UpdateKey(KEY[i], CT);
					}
					else
					{
						OutputData(output, INPUT, CT[0]);
						OutputData(output, OUTPUT, PT[innerCount-1]);
						KEY[i+1] = UpdateKey(KEY[i], PT);
					}
					PT[0] = PT[innerCount];
					IB[0] = IB[innerCount];
					CV[0] = CV[innerCount];
					CT[0] = CT[innerCount];
				}
				else if (m_mode == "OFB")
				{
					OutputData(output, INPUT, TXT[0]);
					OutputData(output, OUTPUT, RESULT[innerCount-1]);
					KEY[i+1] = UpdateKey(KEY[i], RESULT);
					Xor(TXT[0], TXT[0], IB[innerCount-1]);
					IB[0] = OB[innerCount-1];
				}
				output += "\n";
				AttachedTransformation()->Put((byte *)output.data(), output.size());
				output.resize(0);
			}
		}
		else if (m_test == "MCT")
		{
			SecByteBlock KEY[101];
			KEY[0] = key;
			int keySize = key.size();
			int blockSize = pBT->BlockSize();

			SecByteBlock ivs[101], inputs[1001], outputs[1001];
			ivs[0] = iv;
			inputs[0] = m_data2[INPUT];

			for (int i=0; i<100; i++)
			{
				pCipher->SetKey(KEY[i], keySize, MakeParameters(Name::IV(), (const byte *)ivs[i])(Name::FeedbackSize(), (int)K/8));

				for (int j=0; j<1000; j++)
				{
					outputs[j] = inputs[j];
					pCipher->ProcessString(outputs[j], outputs[j].size());
					if (K==8 && m_mode == "CFB")
					{
						if (j<16)
							inputs[j+1].Assign(ivs[i]+j, 1);
						else
							inputs[j+1] = outputs[j-16];
					}
					else if (m_mode == "ECB")
						inputs[j+1] = outputs[j];
					else if (j == 0)
						inputs[j+1] = ivs[i];
					else
						inputs[j+1] = outputs[j-1];
				}

				OutputData(output, KEY_T, KEY[i]);
				if (m_mode != "ECB")
					OutputData(output, IV, ivs[i]);
				OutputData(output, INPUT, inputs[0]);
				OutputData(output, OUTPUT, outputs[999]);
				output += "\n";
				AttachedTransformation()->Put((byte *)output.data(), output.size());
				output.resize(0);

				KEY[i+1] = UpdateKey(KEY[i], outputs);
				ivs[i+1].CleanNew(pCipher->IVSize());
				ivs[i+1] = UpdateKey(ivs[i+1], outputs);
				if (K==8 && m_mode == "CFB")
					inputs[0] = outputs[999-16];
				else if (m_mode == "ECB")
					inputs[0] = outputs[999];
				else
					inputs[0] = outputs[998];
			}
		}
		else
		{
			assert(m_test == "KAT");

			SecByteBlock &input = m_data2[INPUT];
			SecByteBlock result(input.size());
			member_ptr<Filter> pFilter(new StreamTransformationFilter(*pCipher, new ArraySink(result, result.size()), StreamTransformationFilter::NO_PADDING));
			StringSource(input.data(), input.size(), true, pFilter.release());

			OutputGivenData(output, COUNT, true);
			OutputData(output, KEY_T, key);
			OutputGivenData(output, IV, true);
			OutputGivenData(output, INPUT);
			OutputData(output, OUTPUT, result);
			output += "\n";
			AttachedTransformation()->Put((byte *)output.data(), output.size());
		}
	}

	std::vector<std::string> Tokenize(const std::string &line)
	{
		std::vector<std::string> result;
		std::string s;
		for (int i=0; i<line.size(); i++)
		{
			if (isalnum(line[i]) || line[i] == '^')
				s += line[i];
			else if (!s.empty())
			{
				result.push_back(s);
				s = "";
			}
			if (line[i] == '=')
				result.push_back("=");
		}
		result.push_back(s);
		return result;
	}

	bool IsolatedMessageEnd(bool blocking)
	{
		if (!blocking)
			throw BlockingInputOnly("TestDataParser");

		m_line.resize(0);
		m_inQueue.TransferTo(StringSink(m_line).Ref());

		if (m_line[0] == '#')
			return false;

		bool copyLine = false;

		if (m_line[0] == '[')
		{
			m_bracketString = m_line.substr(1, m_line.size()-2);
			if (m_bracketString == "ENCRYPT")
				SetEncrypt(true);
			if (m_bracketString == "DECRYPT")
				SetEncrypt(false);
			copyLine = true;
		}

		if (m_line.substr(0, 2) == "H>")
		{
			assert(m_test == "sha");
			m_bracketString = m_line.substr(2, m_line.size()-4);
			m_line = m_line.substr(0, 13) + "Hashes<H";
			copyLine = true;
		}

		if (m_line == "D>")
			copyLine = true;

		if (m_line == "<D")
		{
			m_line += "\n";
			copyLine = true;
		}

		if (copyLine)
		{
			m_line += '\n';
			AttachedTransformation()->Put((byte *)m_line.data(), m_line.size(), blocking);
			return false;
		}

		std::vector<std::string> tokens = Tokenize(m_line);

		if (m_algorithm == "DSS" && m_test == "sha")
		{
			for (int i = 0; i < tokens.size(); i++)
			{
				if (tokens[i] == "^")
					DoTest();
				else if (tokens[i] != "")
					m_compactString.push_back(atol(tokens[i].c_str()));
			}
		}
		else
		{
			if (!m_line.empty() && m_algorithm == "DSS" && m_test != "pqg")
			{
				std::string output = m_line + '\n';
				AttachedTransformation()->Put((byte *)output.data(), output.size());
			}

			for (int i = 0; i < tokens.size(); i++)
			{
				if (m_firstLine && m_algorithm != "DSS")
				{
					if (tokens[i] == "Encrypt" || tokens[i] == "OFB")
						SetEncrypt(true);
					else if (tokens[i] == "Decrypt")
						SetEncrypt(false);
					else if (tokens[i] == "Modes")
						m_test = "MONTE";
				}
				else
				{
					if (tokens[i] != "=")
						continue;

					if (i == 0)
						throw Exception(Exception::OTHER_ERROR, "TestDataParser: unexpected data: " + m_line);

					const std::string &key = tokens[i-1];
					std::string &data = m_data[key];
					data = tokens[i+1];
					DataType t = m_nameToType[key];
					m_typeToName[t] = key;
					SecByteBlock data2(data.size() / 2);
					StringSource(data, true, new HexDecoder(new ArraySink(data2, data2.size())));
					m_data2[t] = data2;

					if (key == m_trigger || (t == OUTPUT && !m_data2[INPUT].empty()))
						DoTest();
				}
			}
		}

		m_firstLine = false;

		return false;
	}

	inline const SecByteBlock & GetData(const std::string &key)
	{
		return m_data2[m_nameToType[key]];
	}

	std::string m_algorithm, m_test, m_mode, m_line, m_bracketString, m_trigger;
	unsigned int m_feedbackSize, m_blankLineTransition;
	bool m_encrypt, m_firstLine;

	typedef std::map<std::string, DataType> NameToTypeMap;
	NameToTypeMap m_nameToType;
	typedef std::map<DataType, std::string> TypeToNameMap;
	TypeToNameMap m_typeToName;

	typedef std::map<std::string, std::string> Map;
	Map m_data;		// raw data
	typedef std::map<DataType, SecByteBlock> Map2;
	Map2 m_data2;

	AutoSeededX917RNG<DES_EDE3> m_rng;
	std::vector<unsigned int> m_compactString;
};
*/

/*
int main (int argc, char **argv)
{
	std::string algorithm = argv[1];
	std::string pathname = argv[2];
	i = pathname.find_last_of("\\/");
	std::string filename = pathname.substr(i == std::string::npos ? 0 : i+1);
	std::string mode;
	if (filename[0] == 'S' || filename[0] == 'T')
		mode = filename.substr(1, 3);
	else
		mode = filename.substr(0, 3);
	for (i = 0; i<mode.size(); i++)
		mode[i] = toupper(mode[i]);
	unsigned int feedbackSize = mode == "CFB" ? atoi(filename.substr(filename.find_first_of("0123456789")).c_str()) : 0;
	std::string test;
	if (algorithm == "DSS")
		test = filename.substr(0, filename.size() - 4);
	else if (filename.find("Monte") != std::string::npos)
		test = "MONTE";
	else if (filename.find("MCT") != std::string::npos)
		test = "MCT";
	else
		test = "KAT";
	bool encrypt = (filename.find("vrct") == std::string::npos);

	BufferedTransformation *pSink = NULL;

	if (argc > 3)
	{
		std::string outDir = argv[3];
		if (*outDir.rbegin() != '\\' && *outDir.rbegin() != '/')
			outDir += '/';
		std::string outPathname = outDir + filename.substr(0, filename.size() - 3) + "rsp";
		pSink = new FileSink(outPathname.c_str(), false);
	}
	else
		pSink = new FileSink(cout);

	FileSource(pathname.c_str(), true, new LineBreakParser(new TestDataParser(algorithm, test, mode, feedbackSize, encrypt, pSink)), false);
}
*/
