#ifndef CRYPTOPP_ARC4_H
#define CRYPTOPP_ARC4_H

#include "strciphr.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
class CRYPTOPP_NO_VTABLE ARC4_Base : public VariableKeyLength<16, 1, 256>, public RandomNumberGenerator, public SymmetricCipher, public SymmetricCipherDocumentation
{
public:
	~ARC4_Base();

	static const char *StaticAlgorithmName() {return "ARC4";}

    byte GenerateByte();
	void DiscardBytes(unsigned int n);

    void ProcessData(byte *outString, const byte *inString, unsigned int length);
	
	bool IsRandomAccess() const {return false;}
	bool IsSelfInverting() const {return true;}
	bool IsForwardTransformation() const {return true;}

	typedef SymmetricCipherFinal<ARC4_Base> Encryption;
	typedef SymmetricCipherFinal<ARC4_Base> Decryption;

protected:
	void UncheckedSetKey(const NameValuePairs &params, const byte *key, unsigned int length, const byte *iv);
	virtual unsigned int GetDefaultDiscardBytes() const {return 0;}

    FixedSizeSecBlock<byte, 256> m_state;
    byte m_x, m_y;
};

//! <a href="http://www.weidai.com/scan-mirror/cs.html#RC4">Alleged RC4</a>
DOCUMENTED_TYPEDEF(SymmetricCipherFinal<ARC4_Base>, ARC4)

//! _
class CRYPTOPP_NO_VTABLE MARC4_Base : public ARC4_Base
{
public:
	static const char *StaticAlgorithmName() {return "MARC4";}

	typedef SymmetricCipherFinal<MARC4_Base> Encryption;
	typedef SymmetricCipherFinal<MARC4_Base> Decryption;

protected:
	unsigned int GetDefaultDiscardBytes() const {return 256;}
};

//! Modified ARC4: it discards the first 256 bytes of keystream which may be weaker than the rest
DOCUMENTED_TYPEDEF(SymmetricCipherFinal<MARC4_Base>, MARC4)

NAMESPACE_END

#endif
