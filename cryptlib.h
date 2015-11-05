// cryptlib.h - written and placed in the public domain by Wei Dai

//! \file
//! Abstract base classes that provide a uniform interface to this library.

/*!	\mainpage Crypto++ Library 5.6.3 API Reference
<dl>
<dt>Abstract Base Classes<dd>
	cryptlib.h
<dt>Authenticated Encryption<dd>
	AuthenticatedSymmetricCipherDocumentation
<dt>Symmetric Ciphers<dd>
	SymmetricCipherDocumentation
<dt>Hash Functions<dd>
	SHA1, SHA224, SHA256, SHA384, SHA512, Tiger, Whirlpool, RIPEMD160, RIPEMD320, RIPEMD128, RIPEMD256, Weak1::MD2, Weak1::MD4, Weak1::MD5
<dt>Non-Cryptographic Checksums<dd>
	CRC32, Adler32
<dt>Message Authentication Codes<dd>
	VMAC, HMAC, CBC_MAC, CMAC, DMAC, TTMAC, GCM (GMAC)
<dt>Random Number Generators<dd>
	NullRNG(), LC_RNG, RandomPool, BlockingRng, NonblockingRng, AutoSeededRandomPool, AutoSeededX917RNG, DefaultAutoSeededRNG
<dt>Key Derivation<dd>
	HKDF
<dt>Password-based Cryptography<dd>
	PasswordBasedKeyDerivationFunction
<dt>Public Key Cryptosystems<dd>
	DLIES, ECIES, LUCES, RSAES, RabinES, LUC_IES
<dt>Public Key Signature Schemes<dd>
	DSA2, GDSA, ECDSA, NR, ECNR, LUCSS, RSASS, RSASS_ISO, RabinSS, RWSS, ESIGN
<dt>Key Agreement<dd>
	DH, DH2, MQV, ECDH, ECMQV, XTR_DH
<dt>Algebraic Structures<dd>
	Integer, PolynomialMod2, PolynomialOver, RingOfPolynomialsOver,
	ModularArithmetic, MontgomeryRepresentation, GFP2_ONB,
	GF2NP, GF256, GF2_32, EC2N, ECP
<dt>Secret Sharing and Information Dispersal<dd>
	SecretSharing, SecretRecovery, InformationDispersal, InformationRecovery
<dt>Compression<dd>
	Deflator, Inflator, Gzip, Gunzip, ZlibCompressor, ZlibDecompressor
<dt>Input Source Classes<dd>
	StringSource, ArraySource, FileSource, SocketSource, WindowsPipeSource, RandomNumberSource
<dt>Output Sink Classes<dd>
	StringSinkTemplate, ArraySink, FileSink, SocketSink, WindowsPipeSink, RandomNumberSink
<dt>Filter Wrappers<dd>
	StreamTransformationFilter, HashFilter, HashVerificationFilter, SignerFilter, SignatureVerificationFilter
<dt>Binary to Text Encoders and Decoders<dd>
	HexEncoder, HexDecoder, Base64Encoder, Base64Decoder, Base32Encoder, Base32Decoder
<dt>Wrappers for OS features<dd>
	Timer, Socket, WindowsHandle, ThreadLocalStorage, ThreadUserTimer
<dt>FIPS 140 related<dd>
	fips140.h
</dl>

In the DLL version of Crypto++, only the following implementation class are available.
<dl>
<dt>Block Ciphers<dd>
	AES, DES_EDE2, DES_EDE3, SKIPJACK
<dt>Cipher Modes (replace template parameter BC with one of the block ciphers above)<dd>
	ECB_Mode\<BC\>, CTR_Mode\<BC\>, CBC_Mode\<BC\>, CFB_FIPS_Mode\<BC\>, OFB_Mode\<BC\>, GCM\<AES\>
<dt>Hash Functions<dd>
	SHA1, SHA224, SHA256, SHA384, SHA512
<dt>Public Key Signature Schemes (replace template parameter H with one of the hash functions above)<dd>
	RSASS\<PKCS1v15, H\>, RSASS\<PSS, H\>, RSASS_ISO\<H\>, RWSS\<P1363_EMSA2, H\>, DSA, ECDSA\<ECP, H\>, ECDSA\<EC2N, H\>
<dt>Message Authentication Codes (replace template parameter H with one of the hash functions above)<dd>
	HMAC\<H\>, CBC_MAC\<DES_EDE2\>, CBC_MAC\<DES_EDE3\>, GCM\<AES\>
<dt>Random Number Generators<dd>
	DefaultAutoSeededRNG (AutoSeededX917RNG\<AES\>)
<dt>Key Agreement<dd>
	DH, DH2
<dt>Public Key Cryptosystems<dd>
	RSAES\<OAEP\<SHA1\> \>
</dl>

<p>This reference manual is a work in progress. Some classes are lack detailed descriptions.
<p>Click <a href="CryptoPPRef.zip">here</a> to download a zip archive containing this manual.
<p>Thanks to Ryan Phillips for providing the Doxygen configuration file
and getting us started on the manual.
*/

#ifndef CRYPTOPP_CRYPTLIB_H
#define CRYPTOPP_CRYPTLIB_H

#include "config.h"
#include "stdcpp.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(push)
# pragma warning(disable: 4127 4189 4702)
#endif

NAMESPACE_BEGIN(CryptoPP)

// forward declarations
class Integer;
class RandomNumberGenerator;
class BufferedTransformation;

//! \brief Specifies a direction for a cipher to operate
enum CipherDir {ENCRYPTION, DECRYPTION};

//! \brief Represents infinite time
const unsigned long INFINITE_TIME = ULONG_MAX;

// VC60 workaround: using enums as template parameters causes problems
//! \brief Converts a typename to an enumerated value
template <typename ENUM_TYPE, int VALUE>
struct EnumToType
{
	static ENUM_TYPE ToEnum() {return (ENUM_TYPE)VALUE;}
};

//! \brief Provides the byte ordering
enum ByteOrder {LITTLE_ENDIAN_ORDER = 0, BIG_ENDIAN_ORDER = 1};
//! \typedef Provides a constant for \p LittleEndian
typedef EnumToType<ByteOrder, LITTLE_ENDIAN_ORDER> LittleEndian;
//! \typedef Provides a constant for \p BigEndian
typedef EnumToType<ByteOrder, BIG_ENDIAN_ORDER> BigEndian;

//! \class Exception
//! \brief Base class for all exceptions thrown by Crypto++
class CRYPTOPP_DLL Exception : public std::exception
{
public:
	//! error types
	enum ErrorType {
		//! \brief A method was called which was not implemented
		NOT_IMPLEMENTED,
		//! \brief An invalid argument was detected
		INVALID_ARGUMENT,
		//! \brief \p BufferedTransformation received a Flush(true) signal but can't flush buffers
		CANNOT_FLUSH,
		//! \brief Data integerity check, such as CRC or MAC, failed
		DATA_INTEGRITY_CHECK_FAILED,
		//! \brief Input data was received that did not conform to expected format
		INVALID_DATA_FORMAT,
		//! \brief Error reading from input device or writing to output device
		IO_ERROR,
		//! \brief Some other error occurred not belong to any of the above categories
		OTHER_ERROR
	};

	//! \brief Construct a new \p Exception
	explicit Exception(ErrorType errorType, const std::string &s) : m_errorType(errorType), m_what(s) {}
	virtual ~Exception() throw() {}
	
	//! \brief Retrieves a C-string describing the exception
	const char *what() const throw() {return (m_what.c_str());}
	//! \brief Retrieves a \p string describing the exception
	const std::string &GetWhat() const {return m_what;}
	//! \brief Sets the error \p string for the exception
	void SetWhat(const std::string &s) {m_what = s;}
	//! \brief Retrieves the error type for the exception
	ErrorType GetErrorType() const {return m_errorType;}
	//! \brief Sets the error type for the exceptions
	void SetErrorType(ErrorType errorType) {m_errorType = errorType;}

private:
	ErrorType m_errorType;
	std::string m_what;
};

//! \brief An invalid argument was detected
class CRYPTOPP_DLL InvalidArgument : public Exception
{
public:
	explicit InvalidArgument(const std::string &s) : Exception(INVALID_ARGUMENT, s) {}
};

//! \brief Input data was received that did not conform to expected format
class CRYPTOPP_DLL InvalidDataFormat : public Exception
{
public:
	explicit InvalidDataFormat(const std::string &s) : Exception(INVALID_DATA_FORMAT, s) {}
};

//! \brief A decryption filter encountered invalid ciphertext
class CRYPTOPP_DLL InvalidCiphertext : public InvalidDataFormat
{
public:
	explicit InvalidCiphertext(const std::string &s) : InvalidDataFormat(s) {}
};

//! \brief A method was called which was not implemented
class CRYPTOPP_DLL NotImplemented : public Exception
{
public:
	explicit NotImplemented(const std::string &s) : Exception(NOT_IMPLEMENTED, s) {}
};

//! \brief Flush(true) was called but it can't completely flush its buffers
class CRYPTOPP_DLL CannotFlush : public Exception
{
public:
	explicit CannotFlush(const std::string &s) : Exception(CANNOT_FLUSH, s) {}
};

//! \brief The operating system reported an error
class CRYPTOPP_DLL OS_Error : public Exception
{
public:
	OS_Error(ErrorType errorType, const std::string &s, const std::string& operation, int errorCode)
		: Exception(errorType, s), m_operation(operation), m_errorCode(errorCode) {}
	~OS_Error() throw() {}

	//! \brief Retrieve the operating system API that reported the error
	const std::string & GetOperation() const {return m_operation;}
	//! \brief Retrieve the error code returned by the operating system
	int GetErrorCode() const {return m_errorCode;}

protected:
	std::string m_operation;
	int m_errorCode;
};

//! \class DecodingResult
//! \brief Returns a decoding results
struct CRYPTOPP_DLL DecodingResult
{
	//! \brief Constructs a \p DecodingResult
	explicit DecodingResult() : isValidCoding(false), messageLength(0) {}
	//! \brief Constructs a \p DecodingResult
	explicit DecodingResult(size_t len) : isValidCoding(true), messageLength(len) {}

	bool operator==(const DecodingResult &rhs) const {return isValidCoding == rhs.isValidCoding && messageLength == rhs.messageLength;}
	bool operator!=(const DecodingResult &rhs) const {return !operator==(rhs);}

	bool isValidCoding;
	size_t messageLength;

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	operator size_t() const {return isValidCoding ? messageLength : 0;}
#endif
};

//! \class NameValuePairs
//! \brief Interface for retrieving values given their names
//! \details This class is used to safely pass a variable number of arbitrarily typed arguments to functions
//!   and to read values from keys and crypto parameters.
//! \details To obtain an object that implements NameValuePairs for the purpose of parameter
//!   passing, use the MakeParameters() function.
//! \details To get a value from NameValuePairs, you need to know the name and the type of the value. 
//!   Call \p GetValueNames on a NameValuePairs object to obtain a list of value names that it supports.
//!   then look at the Name namespace documentation to see what the type of each value is, or
//!   alternatively, call GetIntValue() with the value name, and if the type is not int, a
//!   \p ValueTypeMismatch exception will be thrown and you can get the actual type from the exception object.
class CRYPTOPP_NO_VTABLE NameValuePairs
{
public:
	virtual ~NameValuePairs() {}

	//! \class ValueTypeMismatch
	//! \brief Thrown when an unexpected type is encountered
	//! \details Exception thrown when trying to retrieve a value using a different type than expected
	class CRYPTOPP_DLL ValueTypeMismatch : public InvalidArgument
	{
	public:
		//! \brief Construct a ValueTypeMismatch
		//! \param name the name of the value
		//! \param stored the \a actual type of the value stored
		//! \param retrieving the \a presumed type of the value retrieved
		ValueTypeMismatch(const std::string &name, const std::type_info &stored, const std::type_info &retrieving)
			: InvalidArgument("NameValuePairs: type mismatch for '" + name + "', stored '" + stored.name() + "', trying to retrieve '" + retrieving.name() + "'")
			, m_stored(stored), m_retrieving(retrieving) {}

		//! \brief Provides the stored type
		//! \returns the C++ mangled name of the type
		const std::type_info & GetStoredTypeInfo() const {return m_stored;}
		
		//! \brief Provides the retrieveing type
		//! \returns the C++ mangled name of the type
		const std::type_info & GetRetrievingTypeInfo() const {return m_retrieving;}

	private:
		const std::type_info &m_stored;
		const std::type_info &m_retrieving;
	};

	//! \brief Get a copy of this object or subobject
	//! \tparam T class or type
	//! \param object reference to a variable that receives the value
	template <class T>
	bool GetThisObject(T &object) const
	{
		return GetValue((std::string("ThisObject:")+typeid(T).name()).c_str(), object);
	}

	//! \brief Get a pointer to this object
	//! \tparam T class or type
	//! \param ptr reference to a pointer to a variable that receives the value
	template <class T>
	bool GetThisPointer(T *&ptr) const
	{
		return GetValue((std::string("ThisPointer:")+typeid(T).name()).c_str(), ptr);
	}

	//! \brief Get a named value, returns true if the name exists
	//! \tparam T class or type
	//! \param name the name of the object or value to retrieve
	//! \param value reference to a variable that receives the value
	//! \returns \p true if the value was retrieved, \p false otherwise
	template <class T>
	bool GetValue(const char *name, T &value) const
	{
		return GetVoidValue(name, typeid(T), &value);
	}

	//! \brief Get a named value
	//! \tparam T class or type
	//! \param name the name of the object or value to retrieve
	//! \param defaultValue the default value of the class or type if it does not exist
	//! \returns the object or value
	template <class T>
	T GetValueWithDefault(const char *name, T defaultValue) const
	{
		GetValue(name, defaultValue);
		return defaultValue;
	}

	//! \brief Get a list of value names that can be retrieved
	//! \returns a list of names available to retrieve
	//! \details the items in the list are delimited with a colon.
	CRYPTOPP_DLL std::string GetValueNames() const
		{std::string result; GetValue("ValueNames", result); return result;}

	//! \brief Get a named value with type int
	//! \param name the name of the value to retrieve
	//! \param value the value retrieved upon success
	//! \details Used to ensure we don't accidentally try to get an unsigned int
	//!   or some other type when we mean int (which is the most common case)
	CRYPTOPP_DLL bool GetIntValue(const char *name, int &value) const
		{return GetValue(name, value);}

	//! \brief Get a named value with type int, with default
	//! \param name the name of the value to retrieve
	//! \param defaultValue the default value if the name does not exist
	//! \returns the value retrieved or the default value
	CRYPTOPP_DLL int GetIntValueWithDefault(const char *name, int defaultValue) const
		{return GetValueWithDefault(name, defaultValue);}

	//! \brief Ensures an expected name and type is present
	//! \param name the name of the value
	//! \param stored the type that was stored for the name
	//! \param retrieving the type that is being retrieved for the name
	//! \throws ValueTypeMismatch
	//! \details \p ThrowIfTypeMismatch() effectively performs a type safety check.
	//!   \p stored and \p retrieving are C++ mangled names for the type.
	CRYPTOPP_DLL static void CRYPTOPP_API ThrowIfTypeMismatch(const char *name, const std::type_info &stored, const std::type_info &retrieving)
		{if (stored != retrieving) throw ValueTypeMismatch(name, stored, retrieving);}

	//! \brief Retrieves a required name/value pair
	//! \tparam T class or type
	//! \param className the name of the class
	//! \param name the name of the value
	//! \param value reference to a variable to receive the value
	//! \throws InvalidArgument
	//! \details \p GetRequiredParameter() throws \p InvalidArgument if the \p name
	//!   is not present or not of the expected type \p T.
	template <class T>
	void GetRequiredParameter(const char *className, const char *name, T &value) const
	{
		if (!GetValue(name, value))
			throw InvalidArgument(std::string(className) + ": missing required parameter '" + name + "'");
	}

	//! \brief Retrieves a required name/value pair
	//! \param className the name of the class
	//! \param name the name of the value
	//! \param value reference to a variable to receive the value
	//! \throws InvalidArgument
	//! \details \p GetRequiredParameter() throws \p InvalidArgument if the \p name
	//!   is not present or not of the expected type \p T.
	CRYPTOPP_DLL void GetRequiredIntParameter(const char *className, const char *name, int &value) const
	{
		if (!GetIntValue(name, value))
			throw InvalidArgument(std::string(className) + ": missing required parameter '" + name + "'");
	}

	//! to be implemented by derived classes, users should use one of the above functions instead
	CRYPTOPP_DLL virtual bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const =0;
};
	
//! \brief Namespace containing value name definitions
/*!	\details value names, types and semantics:

	ThisObject:ClassName (ClassName, copy of this object or a subobject)
	ThisPointer:ClassName (const ClassName *, pointer to this object or a subobject)
*/
DOCUMENTED_NAMESPACE_BEGIN(Name)
// more names defined in argnames.h
DOCUMENTED_NAMESPACE_END

//! \brief Namespace containing weak and wounded algorithms
DOCUMENTED_NAMESPACE_BEGIN(Weak)
// weak and wounded algorithms
DOCUMENTED_NAMESPACE_END

//! \brief An empty set of name-value pairs
extern CRYPTOPP_DLL const NameValuePairs &g_nullNameValuePairs;

// ********************************************************

//! \class Clonable
//! \brief Interface for cloning objects
//! \note this is \a not implemented by most classes
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE Clonable
{
public:
	virtual ~Clonable() {}
	
	//! \brief Copies \p this object
	//! \returns a copy of this object
	//! \throws NotImplemented
	//! \note this is \a not implemented by most classes
	virtual Clonable* Clone() const {throw NotImplemented("Clone() is not implemented yet.");}	// TODO: make this =0
};

//! \class Algorithm
//! \brief Interface for all crypto algorithms
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE Algorithm : public Clonable
{
public:
	//! \brief Interface for all crypto algorithms
	//! \param checkSelfTestStatus determines whether the object can proceed if the self
	//!   tests have not been run or failed.
	//! \details When FIPS 140-2 compliance is enabled and checkSelfTestStatus == true,
	//!   this constructor throws SelfTestFailure if the self test hasn't been run or fails.
	//! \details FIPS 140-2 compliance is disabled by default. It is only used by certain
	//!   versions of the library when the library is built as a DLL on Windows. Also see
	//!   \p CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2 in \headerfile config.h.
	Algorithm(bool checkSelfTestStatus = true);
	
	//! \brief Provides the name of this algorithm
	//! \returns the standard algorithm name
	//! \details The standard algorithm name can be a name like \a AES or \a AES/GCM. Some algorithms
	//!   do not have standard names yet. For example, there is no standard algorithm name for
	//!   Shoup's \p ECIES.
	//! \note \p AlgorithmName is not universally implemented yet
	virtual std::string AlgorithmName() const {return "unknown";}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~Algorithm() {}
#endif
};

//! \class SimpleKeyingInterface
//! Interface for algorithms that take byte strings as keys
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE SimpleKeyingInterface
{
public:
	virtual ~SimpleKeyingInterface() {}

	//! \brief Returns smallest valid key length in bytes
	virtual size_t MinKeyLength() const =0;
	//! \brief Returns largest valid key length in bytes
	virtual size_t MaxKeyLength() const =0;
	//! \brief Returns default (recommended) key length in bytes
	virtual size_t DefaultKeyLength() const =0;

	//! \brief
	//! \returns the smallest valid key length in bytes that is greater than or equal to <tt>min(n, GetMaxKeyLength())</tt>
	virtual size_t GetValidKeyLength(size_t n) const =0;

	//! \brief Returns whether \p keylength is a valid key length
	//! \details Internally the function calls \p GetValidKeyLength()
	virtual bool IsValidKeyLength(size_t keylength) const
		{return keylength == GetValidKeyLength(keylength);}

	//! \brief Sets or reset the key of this object
	//! \param key the key to use when keying the object
	//! \param length the size of the key, in bytes
	//! \param params additional initialization parameters that cannot be passed
	//!   directly through the constructor
	virtual void SetKey(const byte *key, size_t length, const NameValuePairs &params = g_nullNameValuePairs);

	//! \brief Sets or reset the key of this object
	//! \param key the key to use when keying the object
	//! \param length the size of the key, in bytes
	//! \param rounds the number of rounds to apply the transformation function,
	//!    if applicable
	//! \details \p SetKeyWithRounds calls \p SetKey with an \p NameValuePairs
	//!   object that just specifies \p rounds. \p rounds is an integer parameter,
	//!   and <tt>-1</tt> means use the default number of rounds.
	void SetKeyWithRounds(const byte *key, size_t length, int rounds);

	//! \brief Sets or reset the key of this object
	//! \param key the key to use when keying the object
	//! \param length the size of the key, in bytes
	//! \param iv the intiialization vector to use when keying the object
	//! \param ivLength the size of the iv, in bytes
	//! \details \p SetKeyWithIV calls \p SetKey with an \p NameValuePairs object
	//!   that just specifies \p iv. \p iv is a \p byte array with size \p ivLength.
	void SetKeyWithIV(const byte *key, size_t length, const byte *iv, size_t ivLength);

	//! \brief Sets or reset the key of this object
	//! \param key the key to use when keying the object
	//! \param length the size of the key, in bytes
	//! \param iv the intiialization vector to use when keying the object
	//! \details \p SetKeyWithIV calls \p SetKey with an \p NameValuePairs object
	//!   that just specifies \p iv. \p iv is a \p byte array, and it must have
	//!   a size \p IVSize.
	void SetKeyWithIV(const byte *key, size_t length, const byte *iv)
		{SetKeyWithIV(key, length, iv, IVSize());}

	//! \brief Provides IV requirements as an enumerated value.
	enum IV_Requirement {
		//! \brief The IV must be unique
		UNIQUE_IV = 0,
		//! \brief The IV must be random
		RANDOM_IV,
		//! \brief The IV must be unpredictable
		UNPREDICTABLE_RANDOM_IV,
		//! \brief The IV is set by the object
		INTERNALLY_GENERATED_IV,
		//! \brief The object does not use an IV
		NOT_RESYNCHRONIZABLE
	};

	//! returns the minimal requirement for secure IVs
	virtual IV_Requirement IVRequirement() const =0;

	//! returns whether the object can be resynchronized (i.e. supports initialization vectors)
	/*! If this function returns true, and no IV is passed to SetKey() and CanUseStructuredIVs()==true, an IV of all 0's will be assumed. */
	bool IsResynchronizable() const {return IVRequirement() < NOT_RESYNCHRONIZABLE;}
	//! returns whether the object can use random IVs (in addition to ones returned by GetNextIV)
	bool CanUseRandomIVs() const {return IVRequirement() <= UNPREDICTABLE_RANDOM_IV;}
	//! returns whether the object can use random but possibly predictable IVs (in addition to ones returned by GetNextIV)
	bool CanUsePredictableIVs() const {return IVRequirement() <= RANDOM_IV;}
	//! returns whether the object can use structured IVs, for example a counter (in addition to ones returned by GetNextIV)
	bool CanUseStructuredIVs() const {return IVRequirement() <= UNIQUE_IV;}

	//! \brief Returns length of the IV accepted by this object
	//! \details The default implementation throws \p NotImplemented
	virtual unsigned int IVSize() const
		{throw NotImplemented(GetAlgorithm().AlgorithmName() + ": this object doesn't support resynchronization");}
	//! returns default length of IVs accepted by this object
	unsigned int DefaultIVLength() const {return IVSize();}
	//! returns minimal length of IVs accepted by this object
	virtual unsigned int MinIVLength() const {return IVSize();}
	//! returns maximal length of IVs accepted by this object
	virtual unsigned int MaxIVLength() const {return IVSize();}
	//! resynchronize with an IV. ivLength=-1 means use IVSize()
	virtual void Resynchronize(const byte *iv, int ivLength=-1) {
		CRYPTOPP_UNUSED(iv); CRYPTOPP_UNUSED(ivLength);
		throw NotImplemented(GetAlgorithm().AlgorithmName() + ": this object doesn't support resynchronization");
	}

	//! \brief Gets a secure IV for the next message
	//! \param rng a \p RandomNumberGenerator to produce keying material
	//! \param iv a block of bytes to receive the IV
	//! \details This method should be called after you finish encrypting one message and are ready
	//!    to start the next one. After calling it, you must call \p SetKey() or \p Resynchronize()
	//!    before using this object again. 
	//! \details \p key must be at least \p IVSize() in length.
	//! \note This method is not implemented on decryption objects.
	virtual void GetNextIV(RandomNumberGenerator &rng, byte *iv);

protected:
	//! \brief Returns the base class \p Algorithm
	//! \returns the base class \p Algorithm
	virtual const Algorithm & GetAlgorithm() const =0;
	
	//! \brief Sets the key for this object without performing parameter validation
	//! \param key a byte array used to key the cipher
	//! \param length the length of the byte array
	//! \param params additional parameters passed as \p NameValuePairs
	//! \details \p key must be at least \p DEFAULT_KEYLENGTH in length.
	virtual void UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params) =0;
	
	//! \brief Validates the key length
	//! \param length the size of the keying material, in bytes
	//! \throws InvalidKeyLength if the key length is invalid
	void ThrowIfInvalidKeyLength(size_t length);
	
	//! \brief Validates the object
	//! \throws InvalidArgument if the IV is present
	//! \details Internally, the default implementation calls \p IsResynchronizable() and throws 
	//!   \p InvalidArgument if the function returns \p true.
	//! \note called when no IV is passed
	void ThrowIfResynchronizable();
	
	//! \brief Validates the IV
	//! \param iv the IV with a length of \p IVSize, in bytes
	//! \throws InvalidArgument on failure
	//! \details Internally, the default implementation checks the \p iv. If \p iv is not \p NULL,
	//!   then the function succeeds. If \p iv is \p NULL, then \p IVRequirement is checked against
	//!   \p UNPREDICTABLE_RANDOM_IV. If \p IVRequirement is \p UNPREDICTABLE_RANDOM_IV, then
	//!   then the function succeeds. Otherwise, an exception is thrown.
	void ThrowIfInvalidIV(const byte *iv);
	
	//! \brief Validates the IV length
	//! \param length the size of the IV, in bytes
	//! \throws InvalidArgument if the number of \p rounds are invalid
	size_t ThrowIfInvalidIVLength(int length);
	
	//! \brief retrieves and validates the IV
	//! \param params \p NameValuePairs with the IV supplied as a \p ConstByteArrayParameter
	//! \param size the length of the IV, in bytes
	//! \returns a pointer to the first byte of the \p IV
	//! \throws InvalidArgument if the number of \p rounds are invalid
	const byte * GetIVAndThrowIfInvalid(const NameValuePairs &params, size_t &size);
	
	//! \brief Validates the key length
	//! \param length the size of the keying material, in bytes
	inline void AssertValidKeyLength(size_t length) const
		{CRYPTOPP_UNUSED(length); assert(IsValidKeyLength(length));}
};

//! \brief Interface for the data processing part of block ciphers

/*! Classes derived from BlockTransformation are block ciphers
	in ECB mode (for example the DES::Encryption class), which are stateless.
	These classes should not be used directly, but only in combination with
	a mode class (see CipherModeDocumentation in modes.h).
*/
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE BlockTransformation : public Algorithm
{
public:
	//! encrypt or decrypt inBlock, xor with xorBlock, and write to outBlock
	virtual void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const =0;

	//! encrypt or decrypt one block
	/*! \pre size of inBlock and outBlock == BlockSize() */
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{ProcessAndXorBlock(inBlock, NULL, outBlock);}

	//! encrypt or decrypt one block in place
	void ProcessBlock(byte *inoutBlock) const
		{ProcessAndXorBlock(inoutBlock, NULL, inoutBlock);}

	//! block size of the cipher in bytes
	virtual unsigned int BlockSize() const =0;

	//! returns how inputs and outputs should be aligned for optimal performance
	virtual unsigned int OptimalDataAlignment() const;

	//! returns true if this is a permutation (i.e. there is an inverse transformation)
	virtual bool IsPermutation() const {return true;}

	//! returns true if this is an encryption object
	virtual bool IsForwardTransformation() const =0;

	//! return number of blocks that can be processed in parallel, for bit-slicing implementations
	virtual unsigned int OptimalNumberOfParallelBlocks() const {return 1;}

	enum {BT_InBlockIsCounter=1, BT_DontIncrementInOutPointers=2, BT_XorInput=4, BT_ReverseDirection=8, BT_AllowParallel=16} FlagsForAdvancedProcessBlocks;

	//! encrypt and xor blocks according to flags (see FlagsForAdvancedProcessBlocks)
	/*! /note If BT_InBlockIsCounter is set, then the last byte of inBlocks may be modified. */
	virtual size_t AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags) const;

	inline CipherDir GetCipherDirection() const {return IsForwardTransformation() ? ENCRYPTION : DECRYPTION;}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~BlockTransformation() {}
#endif
};

//! \brief Interface for the data processing portion of stream ciphers
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE StreamTransformation : public Algorithm
{
public:
	//! \brief Return a reference to this object
	//! \details Useful for passing a temporary object to a function that takes a non-const reference
	StreamTransformation& Ref() {return *this;}

	//! \brief returns block size, if input must be processed in blocks, otherwise 1
	virtual unsigned int MandatoryBlockSize() const {return 1;}

	//! \brief returns the input block size that is most efficient for this cipher
	/*! \note optimal input length is n * OptimalBlockSize() - GetOptimalBlockSizeUsed() for any n > 0 */
	virtual unsigned int OptimalBlockSize() const {return MandatoryBlockSize();}
	//! \brief returns how much of the current block is used up
	virtual unsigned int GetOptimalBlockSizeUsed() const {return 0;}

	//! \brief returns how input should be aligned for optimal performance
	virtual unsigned int OptimalDataAlignment() const;

	//! \brief encrypt or decrypt an array of bytes of specified length
	//! \note either inString == outString, or they don't overlap
	virtual void ProcessData(byte *outString, const byte *inString, size_t length) =0;

	//! \brief Encrypt or decrypt the last block of data for ciphers where the last block of data is special
	//! For now the only use of this function is for CBC-CTS mode.
	virtual void ProcessLastBlock(byte *outString, const byte *inString, size_t length);
	//! returns the minimum size of the last block, 0 indicating the last block is not special
	virtual unsigned int MinLastBlockSize() const {return 0;}

	//! same as ProcessData(inoutString, inoutString, length)
	inline void ProcessString(byte *inoutString, size_t length)
		{ProcessData(inoutString, inoutString, length);}
	//! same as ProcessData(outString, inString, length)
	inline void ProcessString(byte *outString, const byte *inString, size_t length)
		{ProcessData(outString, inString, length);}
	//! implemented as {ProcessData(&input, &input, 1); return input;}
	inline byte ProcessByte(byte input)
		{ProcessData(&input, &input, 1); return input;}

	//! returns whether this cipher supports random access
	virtual bool IsRandomAccess() const =0;
	//! for random access ciphers, seek to an absolute position
	virtual void Seek(lword n)
	{
		CRYPTOPP_UNUSED(n);
		assert(!IsRandomAccess());
		throw NotImplemented("StreamTransformation: this object doesn't support random access");
	}

	//! returns whether this transformation is self-inverting (e.g. xor with a keystream)
	virtual bool IsSelfInverting() const =0;
	//! returns whether this is an encryption object
	virtual bool IsForwardTransformation() const =0;
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~StreamTransformation() {}
#endif
};

//! \brief Interface for hash functions and data processing part of MACs
/*! HashTransformation objects are stateful.  They are created in an initial state,
	change state as Update() is called, and return to the initial
	state when Final() is called.  This interface allows a large message to
	be hashed in pieces by calling Update() on each piece followed by
	calling Final().
*/
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE HashTransformation : public Algorithm
{
public:
	//! \brief Return a reference to this object
	//! \details Useful for passing a temporary object to a function that takes a non-const reference
	HashTransformation& Ref() {return *this;}

	//! process more input
	virtual void Update(const byte *input, size_t length) =0;

	//! request space to write input into
	virtual byte * CreateUpdateSpace(size_t &size) {size=0; return NULL;}

	//! compute hash for current message, then restart for a new message
	/*!	\pre size of digest == DigestSize(). */
	virtual void Final(byte *digest)
		{TruncatedFinal(digest, DigestSize());}

	//! discard the current state, and restart with a new message
	virtual void Restart()
		{TruncatedFinal(NULL, 0);}

	//! size of the hash/digest/MAC returned by Final()
	virtual unsigned int DigestSize() const =0;

	//! same as DigestSize()
	unsigned int TagSize() const {return DigestSize();}


	//! block size of underlying compression function, or 0 if not block based
	virtual unsigned int BlockSize() const {return 0;}

	//! input to Update() should have length a multiple of this for optimal speed
	virtual unsigned int OptimalBlockSize() const {return 1;}

	//! returns how input should be aligned for optimal performance
	virtual unsigned int OptimalDataAlignment() const;

	//! use this if your input is in one piece and you don't want to call Update() and Final() separately
	virtual void CalculateDigest(byte *digest, const byte *input, size_t length)
		{Update(input, length); Final(digest);}

	//! verify that digest is a valid digest for the current message, then reinitialize the object
	/*! Default implementation is to call Final() and do a bitwise comparison
		between its output and digest. */
	virtual bool Verify(const byte *digest)
		{return TruncatedVerify(digest, DigestSize());}

	//! use this if your input is in one piece and you don't want to call Update() and Verify() separately
	virtual bool VerifyDigest(const byte *digest, const byte *input, size_t length)
		{Update(input, length); return Verify(digest);}

	//! truncated version of Final()
	virtual void TruncatedFinal(byte *digest, size_t digestSize) =0;

	//! truncated version of CalculateDigest()
	virtual void CalculateTruncatedDigest(byte *digest, size_t digestSize, const byte *input, size_t length)
		{Update(input, length); TruncatedFinal(digest, digestSize);}

	//! truncated version of Verify()
	virtual bool TruncatedVerify(const byte *digest, size_t digestLength);

	//! truncated version of VerifyDigest()
	virtual bool VerifyTruncatedDigest(const byte *digest, size_t digestLength, const byte *input, size_t length)
		{Update(input, length); return TruncatedVerify(digest, digestLength);}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~HashTransformation() {}
#endif

protected:
	void ThrowIfInvalidTruncatedSize(size_t size) const;
};

typedef HashTransformation HashFunction;

//! \brief Interface for one direction (encryption or decryption) of a block cipher
/*! \note These objects usually should not be used directly. See BlockTransformation for more details. */
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE BlockCipher : public SimpleKeyingInterface, public BlockTransformation
{
protected:
	const Algorithm & GetAlgorithm() const {return *this;}
};

//! \brief Interface for one direction (encryption or decryption) of a stream cipher or cipher mode
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE SymmetricCipher : public SimpleKeyingInterface, public StreamTransformation
{
protected:
	const Algorithm & GetAlgorithm() const {return *this;}
};

//! \brief Interface for message authentication codes
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE MessageAuthenticationCode : public SimpleKeyingInterface, public HashTransformation
{
protected:
	const Algorithm & GetAlgorithm() const {return *this;}
};

//! \brief Interface for for one direction (encryption or decryption) of a stream cipher or block cipher mode with authentication
/*! The StreamTransformation part of this interface is used to encrypt/decrypt the data, and the MessageAuthenticationCode part of this
	interface is used to input additional authenticated data (AAD, which is MAC'ed but not encrypted), and to generate/verify the MAC. */
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE AuthenticatedSymmetricCipher : public MessageAuthenticationCode, public StreamTransformation
{
public:
	//! this indicates that a member function was called in the wrong state, for example trying to encrypt a message before having set the key or IV
	class BadState : public Exception
	{
	public:
		explicit BadState(const std::string &name, const char *message) : Exception(OTHER_ERROR, name + ": " + message) {}
		explicit BadState(const std::string &name, const char *function, const char *state) : Exception(OTHER_ERROR, name + ": " + function + " was called before " + state) {}
	};

	//! the maximum length of AAD that can be input before the encrypted data
	virtual lword MaxHeaderLength() const =0;
	//! the maximum length of encrypted data
	virtual lword MaxMessageLength() const =0;
	//! the maximum length of AAD that can be input after the encrypted data
	virtual lword MaxFooterLength() const {return 0;}
	//! if this function returns true, SpecifyDataLengths() must be called before attempting to input data
	/*! This is the case for some schemes, such as CCM. */
	virtual bool NeedsPrespecifiedDataLengths() const {return false;}
	//! this function only needs to be called if NeedsPrespecifiedDataLengths() returns true
	void SpecifyDataLengths(lword headerLength, lword messageLength, lword footerLength=0);
	//! encrypt and generate MAC in one call. will truncate MAC if macSize < TagSize()
	virtual void EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *message, size_t messageLength);
	//! decrypt and verify MAC in one call, returning true iff MAC is valid. will assume MAC is truncated if macLength < TagSize()
	virtual bool DecryptAndVerify(byte *message, const byte *mac, size_t macLength, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *ciphertext, size_t ciphertextLength);

	// redeclare this to avoid compiler ambiguity errors
	virtual std::string AlgorithmName() const =0;
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~AuthenticatedSymmetricCipher() {}
#endif

protected:
	const Algorithm & GetAlgorithm() const
		{return *static_cast<const MessageAuthenticationCode *>(this);}
	virtual void UncheckedSpecifyDataLengths(lword headerLength, lword messageLength, lword footerLength)
		{CRYPTOPP_UNUSED(headerLength); CRYPTOPP_UNUSED(messageLength); CRYPTOPP_UNUSED(footerLength);}
};

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
typedef SymmetricCipher StreamCipher;
#endif

//! \class RandomNumberGenerator
//! \brief Interface for random number generators
//! \details The library provides a number of random number generators, from software based to hardware based generators.
//! \details All return values are uniformly distributed over the range specified.
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE RandomNumberGenerator : public Algorithm
{
public:
	//! \brief Update RNG state with additional unpredictable values
	//! \param input the entropy to add to the generator
	//! \param length the size of the input buffer 
	//! \throws NotImplemented
	//! \details A generator may or may not accept additional entropy. Call \p CanIncorporateEntropy to test for the
	//!   ability to use additional entropy.
	//! \details If a derived class does not override \p IncorporateEntropy, then the base class throws
	//!   \p NotImplemented.
	virtual void IncorporateEntropy(const byte *input, size_t length)
	{
		CRYPTOPP_UNUSED(input); CRYPTOPP_UNUSED(length);
		throw NotImplemented("RandomNumberGenerator: IncorporateEntropy not implemented");
	}

	//! \brief Determines if a generator can accept additional entropy
	//! \returns true if IncorporateEntropy is implemented
	virtual bool CanIncorporateEntropy() const {return false;}

	//! \brief Generate new random byte and return it
	//! \details default implementation is to call GenerateBlock() with one byte
	virtual byte GenerateByte();

	//! \brief Generate new random bit and return it
	//! \returns a random bit
	//! \details The default implementation calls GenerateByte() and return its lowest bit.
	virtual unsigned int GenerateBit();

	//! \brief Generate a random 32 bit word in the range min to max, inclusive
	//! \param min the lower bound of the range
	//! \param max the upper bound of the range
	//! \returns a random 32-bit word
	//! \details The default implementation calls \p Crop on the difference between \p max and
	//!   \p min, and then returns the result added to \p min.
	virtual word32 GenerateWord32(word32 min=0, word32 max=0xffffffffL);

	//! \brief Generate random array of bytes
	//! \param output the byte buffer
	//! \param size the length of the buffer, in bytes
	//! \note A derived generator \a must override either \p GenerateBlock or
	//!   \p GenerateIntoBufferedTransformation. They can override both, or have one call the other.
	virtual void GenerateBlock(byte *output, size_t size);

	//! \brief Generate random bytes into a BufferedTransformation
	//! \param target the BufferedTransformation object which receives the bytes
	//! \param channel the channel on which the bytes should be pumped
	//! \param length the number of bytes to generate
	//! \details The default implementation calls \p GenerateBlock() and pumps the result into
	//!   the \p DEFAULT_CHANNEL of the target.
	//! \note A derived generator \a must override either \p GenerateBlock or
	//!   \p GenerateIntoBufferedTransformation. They can override both, or have one call the other.
	virtual void GenerateIntoBufferedTransformation(BufferedTransformation &target, const std::string &channel, lword length);

	//! \brief Generate and discard \p n bytes
	//! \param n the number of bytes to generate and discard
	virtual void DiscardBytes(size_t n);

	//! \brief Randomly shuffle the specified array
	//! \param begin an iterator to the first element in the array
	//! \param end an iterator beyond the last element in the array
	//! \details The resulting permutation is uniformly distributed.
	template <class IT> void Shuffle(IT begin, IT end)
	{
		// TODO: What happens if there are more than 2^32 elements?
		for (; begin != end; ++begin)
			std::iter_swap(begin, begin + GenerateWord32(0, end-begin-1));
	}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~RandomNumberGenerator() {}
#endif

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	byte GetByte() {return GenerateByte();}
	unsigned int GetBit() {return GenerateBit();}
	word32 GetLong(word32 a=0, word32 b=0xffffffffL) {return GenerateWord32(a, b);}
	word16 GetShort(word16 a=0, word16 b=0xffff) {return (word16)GenerateWord32(a, b);}
	void GetBlock(byte *output, size_t size) {GenerateBlock(output, size);}
#endif
};

//! returns a reference that can be passed to functions that ask for a RNG but doesn't actually use it
CRYPTOPP_DLL RandomNumberGenerator & CRYPTOPP_API NullRNG();

//! \brief Interface for checking device state
//! \details Generally speaking, this class attempts to provide four states: (1) not available/not present,
//!   (2) available/present, (3) offline/not ready, and (4) online/ready. 
//!   If a device is Available, then it generally means its present at the time of the call. For example,
//!   a 2012 Ivy Bridge processor will return \a Available for RDRAND, and a Broadwell processor will return
//!   \a Available for and RDSEED. 
//! \details If a device is Not Available, then it could be missing. For example, RDRAND and RDSEED are not
//!   present on a 2000 era X86 CPU, so it should never be Available. Or a Smartcard or YubiKey may not be
//!   plugged into a computer. 
//! \details If a device is Ready, then it can service requests at the time of the call. For example, a
//!   2012 Ivy Bridge processor will return \a Ready for RDRAND, and a Broadwell processor will return
//!   \a Ready for and RDSEED. 
//! \details If a device is Not Ready, then it could uninitialized or locked. For example, a Smartcard or YubiKey
//!   may be present but unitiialized or locked. The device may be waiting on a driver to be installed,
//!   may be waiting to be intialized, or may be waiting for a PIN or Passcode to unlock it, etc. 
//! \details Ready should always follow Available; however, the converse is not true. That is, a device that
//!   is Not Ready does not mean that its Not Available. Not Ready only indicates the device is offline
//!   at the time of the call. 
//! \details A not-so-apparent use case is a software implementation. For example, you can have a Crypto++
//!   wrapper around Microsoft's CryptoNG or Apple's CommonCrypto for FIPS 140-2 validated cryptography.
//!   The \p DeviceState could provide the standard interface to query the relevant Crypto++ implementation
//!   for the feature.
class CRYPTOPP_NO_VTABLE DeviceState
{
public:
	//! \enum State
	//! \brief Enumeration of potential device states.
	//! \details The library reserves the lower 8 bits. Derived classes are free to use the 24 unallocated bits.
	enum State {
		//! \brief the device is available or present
		AVAILABLE = 1,
		//! \brief the device is available or present
		PRESENT = 1,
		//! \brief the device is ready or online
		READY = 2,
		//! \brief the device is ready or online
		ONLINE = 2,
		//! \brief mask for Available and Ready bits
		AR_MASK = 0x3,
		//! \brief mask for bits reserved by the library
		LIB_MASK= 0xff,
		//! \brief mask for bits available for derived classes
		USER_MASK = 0xffffff00
	};
		
	//! \var NO_EXTENDED_INFO
	//! \brief Distinguished value to indicate \p extendedInfo is not available
	//! \details The value is \a not -1 to avoid conflicts with user values.
	static const word64 NO_EXTENDED_INFO;

	//! \fn virtual bool Available(word64& extendedInfo) const
	//! \brief Determines the availability of a device.
	//! \param extendedInfo extended information for Availability status, if available.
	//! \returns true if the device is present at the time of the call, false otherwise.
	//! \details Derived classes can set \p extendedInfo to a meaningful code. There's no
	//!   guarantee a derived class will set it for either success and failure. Derived
	//!   classes should set \p extendedInfo to \p NO_EXTENDED_INFO if its not available.
	//! \details Must be implemented by derived classes. See the class documentation for
	//!   \p DeviceState for semantics.
	virtual bool Available(word64& extendedInfo) const = 0;
	
	//! \fn virtual bool Available() const
	//! \brief Determines the availability of a device.
	//! \returns true if the device is present at the time of the call, false otherwise.
	//! \details Must be implemented by derived classes. See the class documentation for
	//!   \p DeviceState for semantics.
	virtual bool Available() const = 0;
	
	//! \fn virtual bool Ready(word64& extendedInfo) const
	//! \brief Determines the readiness of a device.
	//! \param extendedInfo extended information for Ready status, if available.
	//! \returns true if the device can service a request at the time of the call, false otherwise.
	//! \details Derived classes can set \p extendedInfo to a meaningful code. There's no guarantee
	//!   a derived class will set it for either success and failure. Derived classes should set
	//!   \p extendedInfo to \p NO_EXTENDED_INFO if its not available.
	//! \details Must be implemented by derived classes. See the class documentation for
	//!   \p DeviceState for semantics.
	virtual bool Ready(word64& extendedInfo) const = 0;

	//! \fn virtual bool Ready() const
	//! \brief Determines the readiness of a device.
	//! \returns true if the device can service a request at the time of the call, false otherwise.
	//! \details Must be implemented by derived classes. See the class documentation for
	//!   \p DeviceState for semantics.
	virtual bool Ready() const = 0;
	
	virtual ~DeviceState() {}
};

//! \class WaitObjectContainer
class WaitObjectContainer;
//! \class CallStack
class CallStack;

//! \brief Interface for objects that can be waited on.
class CRYPTOPP_NO_VTABLE Waitable
{
public:
	virtual ~Waitable() {}

	//! \brief Maximum number of wait objects that this object can return
	virtual unsigned int GetMaxWaitObjectCount() const =0;

	//! \brief Retrieves waitable objects
	//! \param container the wait container to receive the references to the objects.
	//! \param callStack \p CallStack object used to select waitable objects
	//! \details \p GetWaitObjects is usually called in one of two ways. First, it can
	//!   be called like <tt>something.GetWaitObjects(c, CallStack("my func after X", 0));</tt>.
	//!   Second, if in an outer \p GetWaitObjects() method that itself takes a callStack
	//!   parameter, it can be called like
	//!   <tt>innerThing.GetWaitObjects(c, CallStack("MyClass::GetWaitObjects at X", &callStack));</tt>.
	virtual void GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack) =0;

	//! wait on this object
	/*! same as creating an empty container, calling GetWaitObjects(), and calling Wait() on the container */
	bool Wait(unsigned long milliseconds, CallStack const& callStack);
};

//! \brief Default channel for \p BufferedTransformation
//! \details \p DEFAULT_CHANNEL is equal to an empty \p string
extern CRYPTOPP_DLL const std::string DEFAULT_CHANNEL;

//! \brief Channel for additional authenticated data
//! \details \p AAD_CHANNEL is equal to "AAD"
extern CRYPTOPP_DLL const std::string AAD_CHANNEL;

//! \brief Interface for buffered transformations
//! \details \p BufferedTransformation is a generalization of \p BlockTransformation,
//!   \p StreamTransformation and \p HashTransformation.
//! \details A buffered transformation is an object that takes a stream of bytes as input (this may
//!   be done in stages), does some computation on them, and then places the result into an internal
//!   buffer for later retrieval. Any partial result already in the output buffer is not modified
//!   by further input.
//! \details If a method takes a "blocking" parameter, and you pass \p false for it, then the method
//!   will return before all input has been processed if the input cannot be processed without waiting
//!   (for network buffers to become available, for example). In this case the method will return true
//!   or a non-zero integer value. When this happens you must continue to call the method with the same
//!   parameters until it returns false or zero, before calling any other method on it or attached
//!   /p BufferedTransformation. The integer return value in this case is approximately
//!   the number of bytes left to be processed, and can be used to implement a progress bar.
//! \details For functions that take a "propagation" parameter, <tt>propagation != 0</tt> means pass on
//!   the signal to attached \p BufferedTransformation objects, with propagation decremented at each
//!   step until it reaches <tt>0</tt>. <tt>-1</tt> means unlimited propagation.
//! \details \a All of the retrieval functions, like \p Get and \p GetWord32, return the actual
//!   number of bytes retrieved, which is the lesser of the request number and \p MaxRetrievable().
//! \details \a Most of the input functions, like \p Put and \p PutWord32, return the number of
//!   bytes remaining to be processed. A 0 value means all bytes were processed, and a non-0 value
//!   means bytes remain to be processed.
//! \nosubgrouping
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE BufferedTransformation : public Algorithm, public Waitable
{
public:
	// placed up here for CW8
	static const std::string &NULL_CHANNEL;	// same as DEFAULT_CHANNEL, for backwards compatibility

	BufferedTransformation() : Algorithm(false) {}

	//! \brief Provides a reference to this object
	//! \returns a reference to this object
	//! \details Useful for passing a temporary object to a function that takes a non-const reference
	BufferedTransformation& Ref() {return *this;}

	//!	\name INPUT
	//@{

		//! \brief Input a byte for processing
		//! \param inByte the 8-bit byte (octet) to be processed.
		//! \param blocking specifies whether the object should block when processing input.
		//! \returns the number of bytes that remain in the block (i.e., bytes not processed)
		//! \details <tt>Put(byte)</tt> calls <tt>Put(byte*, size_t)</tt>.
		size_t Put(byte inByte, bool blocking=true)
			{return Put(&inByte, 1, blocking);}

		//! \brief Input a byte array for processing
		//! \param inString the byte array to process
		//! \param length the size of the string, in bytes
		//! \param blocking specifies whether the object should block when processing input
		//! \returns the number of bytes that remain in the block (i.e., bytes not processed)
		//! \details Internally, \p Put() calls \p Put2().
		size_t Put(const byte *inString, size_t length, bool blocking=true)
			{return Put2(inString, length, 0, blocking);}

		//! Input a 16-bit word for processing.
		//! \param value the 16-bit value to be processed
		//! \param order the \p ByteOrder in which the word should be processed
		//! \param blocking specifies whether the object should block when processing input
		//! \returns the number of bytes that remain in the block (i.e., bytes not processed)
		size_t PutWord16(word16 value, ByteOrder order=BIG_ENDIAN_ORDER, bool blocking=true);
		
		//! Input a 32-bit word for processing.
		//! \param value the 32-bit value to be processed.
		//! \param order the \p ByteOrder in which the word should be processed.
		//! \param blocking specifies whether the object should block when processing input.
		//! \returns the number of bytes that remain in the block (i.e., bytes not processed)
		size_t PutWord32(word32 value, ByteOrder order=BIG_ENDIAN_ORDER, bool blocking=true);

		//! \brief Request space which can be written into by the caller, and then used as input to \p Put
		//! \param size the requested size of the buffer
		//! \details The purpose of this method is to help avoid extra memory allocations.
		//! \details \p size is an \a IN and \a OUT parameter and used as a hint. When the call is made,
		//!   \p size is the requested size of the buffer. When the call returns, \p size is the size of
		//!   the array returned to the caller.
		//! \details The base class implementation sets \p size to 0 and returns \p NULL.
		//! \note Some objects, like \p ArraySink, cannot create a space because its fixed. In the case of
		//! an \p ArraySink, the pointer to the array is returned and the \p size is remaining size.
		virtual byte * CreatePutSpace(size_t &size)
			{size=0; return NULL;}

		//! \brief Determines whether input can be modifed by the callee
		//! \returns true if input can be modified, false otherwise
		//! \details The base class implementation returns \p false.
		virtual bool CanModifyInput() const
			{return false;}

		//! \brief Input multiple bytes that may be modified by callee.
		//! \param inString the byte array to process
		//! \param length the size of the string, in bytes
		//! \param blocking specifies whether the object should block when processing input
		//! \returns 0 indicates all bytes were processed during the call. Non-0 indicates the
		//!   number of bytes that were \a not processed
		size_t PutModifiable(byte *inString, size_t length, bool blocking=true)
			{return PutModifiable2(inString, length, 0, blocking);}

		//! \brief Signals the end of messages to the object
		//! \param propagation the number of attached transformations the \p MessageEnd() signal should be passed
		//! \param blocking specifies whether the object should block when processing input
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		bool MessageEnd(int propagation=-1, bool blocking=true)
			{return !!Put2(NULL, 0, propagation < 0 ? -1 : propagation+1, blocking);}

		//! \brief Input multiple bytes for processing and signal the end of a message
		//! \param inString the byte array to process
		//! \param length the size of the string, in bytes
		//! \param propagation the number of attached transformations the \p MessageEnd() signal should be passed
		//! \param blocking specifies whether the object should block when processing input
		//! \details Internally, \p PutMessageEnd() calls \p Put2() with a modified \p propagation to
		//!    ensure all attached transformations finish processing the message.
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		size_t PutMessageEnd(const byte *inString, size_t length, int propagation=-1, bool blocking=true)
			{return Put2(inString, length, propagation < 0 ? -1 : propagation+1, blocking);}

		//! \brief Input multiple bytes for processing.
		//! \param inString the byte array to process.
		//! \param length the size of the string, in bytes.
		//! \param messageEnd means how many filters to signal \p MessageEnd to, including this one.
		//! \param blocking specifies whether the object should block when processing input.
		//! \details Derived classes must implement \p Put2.
		virtual size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking) =0;

		//! \brief Input multiple bytes that may be modified by callee.
		//! \param inString the byte array to process.
		//! \param length the size of the string, in bytes.
		//! \param messageEnd means how many filters to signal \p MessageEnd to, including this one.
		//! \param blocking specifies whether the object should block when processing input.
		//! \details Internally, \p PutModifiable2() calls \p Put2().
		virtual size_t PutModifiable2(byte *inString, size_t length, int messageEnd, bool blocking)
			{return Put2(inString, length, messageEnd, blocking);}

		//! \brief thrown by objects that have not implemented nonblocking input processing
		struct BlockingInputOnly : public NotImplemented
			{BlockingInputOnly(const std::string &s) : NotImplemented(s + ": Nonblocking input is not implemented by this object.") {}};
	//@}

	//! \section
	//!	\name WAITING
	//@{
		//! \brief Retrieves the maximum number of waitable objects
		unsigned int GetMaxWaitObjectCount() const;

		//! \brief Retrieves waitable objects
		//! \param container the wait container to receive the references to the objects.
		//! \param callStack \p CallStack object used to select waitable objects
		//! \details \p GetWaitObjects is usually called in one of two ways. First, it can
		//!    be called like <tt>something.GetWaitObjects(c, CallStack("my func after X", 0));</tt>.
		//!    Second, if in an outer \p GetWaitObjects() method that itself takes a callStack
		//!    parameter, it can be called like
		//!    <tt>innerThing.GetWaitObjects(c, CallStack("MyClass::GetWaitObjects at X", &callStack));</tt>.
		void GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack);
	//@} // WAITING

	//!	\name SIGNALS
	//@{
		
		//! \brief Initialize or reinitialize this object, without signal propagation
		//! \param parameters a set of \p NameValuePairs used to initialize this object
		//! \throws NotImplemented
		//! \details \p IsolatedInitialize is used to initialize or reinitialize an object using a variable
		//!   number of  arbitrarily typed arguments. The function avoids the need for multiple constuctors providing
		//!   all possible combintations of configurable parameters.
		//! \details \p IsolatedInitialize does not call \p Initialize on attached transformations. If initialization
		//!   should be propagated, then use the \p Initialize function.
		//! \details Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		//! \details If a derived class does not override \p IsolatedInitialize, then the base class throws
		//!   \p NotImplemented.
		virtual void IsolatedInitialize(const NameValuePairs &parameters) {
			CRYPTOPP_UNUSED(parameters);
			throw NotImplemented("BufferedTransformation: this object can't be reinitialized");
		}
		
		//! \brief Flushes data buffered by this object, without signal propagation
		//! \param hardFlush indicates whether all data should be flushed
		//! \param blocking specifies whether the object should block when processing input
		//! \note \p hardFlush must be used with care
		virtual bool IsolatedFlush(bool hardFlush, bool blocking) =0;
		
		//! \brief Marks the end of a series of messages, without signal propagation
		//! \param blocking specifies whether the object should block when completing the processing on
		//!    the current series of messages
		virtual bool IsolatedMessageSeriesEnd(bool blocking)
			{CRYPTOPP_UNUSED(blocking); return false;}

		//! \brief Initialize or reinitialize this object, with signal propagation
		//! \param parameters a set of \p NameValuePairs used to initialize or reinitialize this object
		//!   and attached transformations
		//! \param propagation the number of attached transformations the \p Initialize() signal should be passed
		//! \details \p Initialize is used to initialize or reinitialize an object using a variable number of 
		//!   arbitrarily typed arguments. The function avoids the need for multiple constuctors providing
		//!   all possible combintations of configurable parameters.
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		virtual void Initialize(const NameValuePairs &parameters=g_nullNameValuePairs, int propagation=-1);

		//! \brief Flush buffered input and/or output, with signal propagation
		//! \param hardFlush is used to indicate whether all data should be flushed
		//! \param propagation the number of attached transformations the \p Flush() signal should be passed
		//! \param blocking specifies whether the object should block when processing input
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		//! \note Hard flushes must be used with care. It means try to process and output everything, even if
		//!   there may not be enough data to complete the action. For example, hard flushing a \p HexDecoder
		//!   would cause an error if you do it after inputing an odd number of hex encoded characters.
		//! \note For some types of filters, like \p ZlibDecompressor, hard flushes can only
		//!   be done at "synchronization points". These synchronization points are positions in the data
		//!   stream that are created by hard flushes on the corresponding reverse filters, in this
		//!   example ZlibCompressor. This is useful when zlib compressed data is moved across a
		//!   network in packets and compression state is preserved across packets, as in the SSH2 protocol.
		virtual bool Flush(bool hardFlush, int propagation=-1, bool blocking=true);

		//! \brief Marks the end of a series of messages, with signal propagation
		//! \param propagation the number of attached transformations the \p MessageSeriesEnd() signal should be passed
		//! \param blocking specifies whether the object should block when processing input
		//! \details Each object that receives the signal will perform its processing, decrement
		//!   \p propagation, and then pass the signal on to attached transformations if the value is not 0.
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		//! \note There should be a \p MessageEnd immediately before \p MessageSeriesEnd.
		virtual bool MessageSeriesEnd(int propagation=-1, bool blocking=true);

		//! \brief Set propagation of automatically generated and transferred signals
		//! \param propagation then new value 
		//! \details Setting \p propagation to <tt>0</tt> means do not automaticly generate signals. Setting
		//!   \p propagation to <tt>-1</tt> means unlimited propagation.
		virtual void SetAutoSignalPropagation(int propagation)
			{CRYPTOPP_UNUSED(propagation);}

		//! \brief Retrieve automatic signal propagation value
		virtual int GetAutoSignalPropagation() const {return 0;}
public:

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
		void Close() {MessageEnd();}
#endif
	//@}

	//!	\name RETRIEVAL OF ONE MESSAGE
	//@{

		//! \brief Provides the number of bytes ready for retrieval
		//! \returns the number of bytes ready for retrieval
		//! \details All retrieval functions return the actual number of bytes retrieved, which is
		//!   the lesser of the request number and \p MaxRetrievable()
		virtual lword MaxRetrievable() const;

		//! \brief Determines whether bytes are ready for retrieval
		//! \returns \p true if bytes are available for retrieval, false otherwise
		virtual bool AnyRetrievable() const;

		//! \brief Retrieve a 8-bit byte
		//! \param outByte the 8-bit value to be retrieved
		//! \returns the number of bytes consumed during the call.
		//! \details Use the return value of \p Get to detect short reads.
		virtual size_t Get(byte &outByte);
		
		//! \brief Retrieve a block of bytes
		//! \param outString a block of bytes
		//! \param getMax the number of bytes to \p Get
		//! \returns the number of bytes consumed during the call.
		//! \details Use the return value of \p Get to detect short reads.
		virtual size_t Get(byte *outString, size_t getMax);

		//! \brief Peek a 8-bit byte
		//! \param outByte the 8-bit value to be retrieved
		//! \returns the number of bytes read during the call.
		//! \details \p Peek does not remove bytes from the object. Use the return value of
		//!    \p Get to detect short reads.
		virtual size_t Peek(byte &outByte) const;
		
		//! \brief Peek a block of bytes
		//! \param outString a block of bytes
		//! \param peekMax the number of bytes to \p Peek
		//! \returns the number of bytes read during the call.
		//! \details \p Peek does not remove bytes from the object. Use the return value of
		//!    \p Get to detect short reads.
		virtual size_t Peek(byte *outString, size_t peekMax) const;

		//! \brief Retrieve a 16-bit word
		//! \param value the 16-bit value to be retrieved
		//! \param order the \p ByteOrder in which the word should be retrieved
		//! \returns the number of bytes consumed during the call.
		//! \details Use the return value of \p GetWord16 to detect short reads.
		size_t GetWord16(word16 &value, ByteOrder order=BIG_ENDIAN_ORDER);

		//! \brief Retrieve a 32-bit word
		//! \param value the 32-bit value to be retrieved
		//! \param order the \p ByteOrder in which the word should be retrieved
		//! \returns the number of bytes consumed during the call.
		//! \details Use the return value of \p GetWord16 to detect short reads.
		size_t GetWord32(word32 &value, ByteOrder order=BIG_ENDIAN_ORDER);

		//! \brief Peek a 16-bit word
		//! \param value the 16-bit value to be retrieved
		//! \param order the \p ByteOrder in which the word should be retrieved
		//! \returns the number of bytes consumed during the call.
		//! \details \p Peek does not consume bytes in the stream. Use the return value
		//!    of \p GetWord16 to detect short reads.
		size_t PeekWord16(word16 &value, ByteOrder order=BIG_ENDIAN_ORDER) const;

		//! \brief Peek a 32-bit word
		//! \param value the 32-bit value to be retrieved
		//! \param order the \p ByteOrder in which the word should be retrieved
		//! \returns the number of bytes consumed during the call.
		//! \details \p Peek does not consume bytes in the stream. Use the return value
		//!    of \p GetWord16 to detect short reads.
		size_t PeekWord32(word32 &value, ByteOrder order=BIG_ENDIAN_ORDER) const;

		//! move transferMax bytes of the buffered output to target as input
		
		//! \brief Transfer bytes from this object to another \p BufferedTransformation
		//! \param target the destination \p BufferedTransformation
		//! \param transferMax the number of bytes to transfer
		//! \param channel the channel on which the transfer should occur
		//! \returns the number of bytes transferred during the call.
		//! \details \p TransferTo removes bytes from this object and moves them to the destination.
		//! \details The function always returns \p transferMax. If an accurate count is needed, then use \p TransferTo2.
		lword TransferTo(BufferedTransformation &target, lword transferMax=LWORD_MAX, const std::string &channel=DEFAULT_CHANNEL)
			{TransferTo2(target, transferMax, channel); return transferMax;}

		//! \brief Discard \p skipMax bytes from the output buffer
		//! \param skipMax the number of bytes to discard
		//! \details \p Skip always returns \p skipMax.
		virtual lword Skip(lword skipMax=LWORD_MAX);

		//! copy copyMax bytes of the buffered output to target as input
		
		//! \brief Copy bytes from this object to another \p BufferedTransformation
		//! \param target the destination \p BufferedTransformation
		//! \param copyMax the number of bytes to copy
		//! \param channel the channel on which the transfer should occur
		//! \returns the number of bytes copied during the call.
		//! \details \p CopyTo copies bytes from this object to the destination. The bytes are not removed from this object.
		//! \details The function always returns \p copyMax. If an accurate count is needed, then use \p CopyRangeTo2.
		lword CopyTo(BufferedTransformation &target, lword copyMax=LWORD_MAX, const std::string &channel=DEFAULT_CHANNEL) const
			{return CopyRangeTo(target, 0, copyMax, channel);}
		
		//! \brief Copy bytes from this object using an index to another \p BufferedTransformation
		//! \param target the destination \p BufferedTransformation
		//! \param position the 0-based index of the byte stream to begin the copying
		//! \param copyMax the number of bytes to copy
		//! \param channel the channel on which the transfer should occur
		//! \returns the number of bytes copied during the call.
		//! \details \p CopyTo copies bytes from this object to the destination. The bytes remain in this
		//!   object. Copying begins at the index position in the current stream, and not from an absolute
		//!   position in the stream.
		//! \details The function returns the new position in the stream after transferring the bytes starting at the index.
		lword CopyRangeTo(BufferedTransformation &target, lword position, lword copyMax=LWORD_MAX, const std::string &channel=DEFAULT_CHANNEL) const
			{lword i = position; CopyRangeTo2(target, i, i+copyMax, channel); return i-position;}

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
		unsigned long MaxRetrieveable() const {return MaxRetrievable();}
#endif
	//@}

	//!	\name RETRIEVAL OF MULTIPLE MESSAGES
	//@{

		//! \brief Provides the number of bytes ready for retrieval
		//! \returns the number of bytes ready for retrieval
		virtual lword TotalBytesRetrievable() const;
		
		//! \brief Provides the number of meesages processed by this object
		//! \returns the number of meesages processed by this object
		//! \details \p NumberOfMessages returns number of times \p MessageEnd() has been
		//!    received minus messages retrieved or skipped
		virtual unsigned int NumberOfMessages() const;

		//! \brief Determines if any messages are available for retrieval
		//! \returns \p true if <tt>NumberOfMessages() &gt; 0</tt>, \p false otherwise
		//! \details \p AnyMessages returns true if <tt>NumberOfMessages() &gt; 0</tt>
		virtual bool AnyMessages() const;

		//! start retrieving the next message
		/*!
			Returns false if no more messages exist or this message 
			is not completely retrieved.
		*/
		virtual bool GetNextMessage();
		//! skip count number of messages
		virtual unsigned int SkipMessages(unsigned int count=UINT_MAX);
		//!
		unsigned int TransferMessagesTo(BufferedTransformation &target, unsigned int count=UINT_MAX, const std::string &channel=DEFAULT_CHANNEL)
			{TransferMessagesTo2(target, count, channel); return count;}
		//!
		unsigned int CopyMessagesTo(BufferedTransformation &target, unsigned int count=UINT_MAX, const std::string &channel=DEFAULT_CHANNEL) const;

		//!
		virtual void SkipAll();
		//!
		void TransferAllTo(BufferedTransformation &target, const std::string &channel=DEFAULT_CHANNEL)
			{TransferAllTo2(target, channel);}
		//!
		void CopyAllTo(BufferedTransformation &target, const std::string &channel=DEFAULT_CHANNEL) const;

		virtual bool GetNextMessageSeries() {return false;}
		virtual unsigned int NumberOfMessagesInThisSeries() const {return NumberOfMessages();}
		virtual unsigned int NumberOfMessageSeries() const {return 0;}
	//@}

	//!	\name NON-BLOCKING TRANSFER OF OUTPUT
	//@{
		
		// upon return, byteCount contains number of bytes that have finished being transfered,
		// and returns the number of bytes left in the current transfer block
		
		//! \brief Transfer bytes from this object to another \p BufferedTransformation
		//! \param target the destination \p BufferedTransformation
		//! \param byteCount the number of bytes to transfer
		//! \param channel the channel on which the transfer should occur
		//! \param blocking specifies whether the object should block when processing input
		//! \returns the number of bytes that remain in the transfer block (i.e., bytes not transferred)
		//! \details \p TransferTo removes bytes from this object and moves them to the destination.
		//!   Transfer begins at the index position in the current stream, and not from an absolute
		//!   position in the stream.
		//! \details \p byteCount is an \a IN and \a OUT parameter. When the call is made,
		//!   \p byteCount is the requested size of the transfer. When the call returns, \p byteCount is
		//!   the number of bytes that were transferred.
		virtual size_t TransferTo2(BufferedTransformation &target, lword &byteCount, const std::string &channel=DEFAULT_CHANNEL, bool blocking=true) =0;
		
		// upon return, begin contains the start position of data yet to be finished copying,
		// and returns the number of bytes left in the current transfer block
	
		//! \brief Copy bytes from this object to another \p BufferedTransformation
		//! \param target the destination \p BufferedTransformation
		//! \param begin the 0-based index of the first byte to copy in the stream
		//! \param end the 0-based index of the last byte to copy in the stream
		//! \param channel the channel on which the transfer should occur
		//! \param blocking specifies whether the object should block when processing input
		//! \returns the number of bytes that remain in the copy block (i.e., bytes not copied)
		//! \details \p CopyRangeTo2 copies bytes from this object to the destination. The bytes are not
		//!   removed from this object. Copying begins at the index position in the current stream, and
		//!   not from an absolute position in the stream.
		//! \details \p begin is an \a IN and \a OUT parameter. When the call is made, \p begin is the
		//!   starting position of the copy. When the call returns, \p begin is the position of the first
		//!   byte that was \a not copied (which may be different tahn \p end). \p begin can be used for
		//!   subsequent calls to \p CopyRangeTo2.
		virtual size_t CopyRangeTo2(BufferedTransformation &target, lword &begin, lword end=LWORD_MAX, const std::string &channel=DEFAULT_CHANNEL, bool blocking=true) const =0;
		
		// upon return, messageCount contains number of messages that have finished being transfered,
		// and returns the number of bytes left in the current transfer block

		//! \brief Transfer messages from this object to another \p BufferedTransformation
		//! \param target the destination \p BufferedTransformation
		//! \param messageCount the number of messages to transfer
		//! \param channel the channel on which the transfer should occur
		//! \param blocking specifies whether the object should block when processing input
		//! \returns the number of bytes that remain in the current transfer block (i.e., bytes not transferred)
		//! \details \p TransferMessagesTo2 removes messages from this object and moves them to the destination.
		size_t TransferMessagesTo2(BufferedTransformation &target, unsigned int &messageCount, const std::string &channel=DEFAULT_CHANNEL, bool blocking=true);
		
		// returns the number of bytes left in the current transfer block
		
		//! \brief Transfer all bytes from this object to another \p BufferedTransformation
		//! \param target the destination \p BufferedTransformation
		//! \param channel the channel on which the transfer should occur
		//! \param blocking specifies whether the object should block when processing input
		//! \returns the number of bytes that remain in the current transfer block (i.e., bytes not transferred)
		//! \details \p TransferMessagesTo2 removes messages from this object and moves them to the destination.
		size_t TransferAllTo2(BufferedTransformation &target, const std::string &channel=DEFAULT_CHANNEL, bool blocking=true);
	//@}

	//!	\name CHANNELS
	//@{
		//! \brief Exception thrown when a filter does not support named channels
		struct NoChannelSupport : public NotImplemented
			{NoChannelSupport(const std::string &name) : NotImplemented(name + ": this object doesn't support multiple channels") {}};
		//! \brief Exception thrown when a filter does not recognize a named channel
		struct InvalidChannelName : public InvalidArgument
			{InvalidChannelName(const std::string &name, const std::string &channel) : InvalidArgument(name + ": unexpected channel name \"" + channel + "\"") {}};

		//! \brief Input a byte for processing on a channel
		//! \param channel the channel to process the data.
		//! \param inByte the 8-bit byte (octet) to be processed.
		//! \param blocking specifies whether the object should block when processing input.
		//! \returns 0 indicates all bytes were processed during the call. Non-0 indicates the
		//!   number of bytes that were \a not processed.
		size_t ChannelPut(const std::string &channel, byte inByte, bool blocking=true)
			{return ChannelPut(channel, &inByte, 1, blocking);}

		//! \brief Input a byte array for processing on a channel
		//! \param channel the channel to process the data
		//! \param inString the byte array to process
		//! \param length the size of the string, in bytes
		//! \param blocking specifies whether the object should block when processing input
		//! \returns 0 indicates all bytes were processed during the call. Non-0 indicates the
		//!   number of bytes that were \a not processed.
		size_t ChannelPut(const std::string &channel, const byte *inString, size_t length, bool blocking=true)
			{return ChannelPut2(channel, inString, length, 0, blocking);}

		//! \brief Input multiple bytes that may be modified by callee on a channel
		//! \param channel the channel to process the data.
		//! \param inString the byte array to process
		//! \param length the size of the string, in bytes
		//! \param blocking specifies whether the object should block when processing input
		//! \returns 0 indicates all bytes were processed during the call. Non-0 indicates the
		//!   number of bytes that were \a not processed.
		size_t ChannelPutModifiable(const std::string &channel, byte *inString, size_t length, bool blocking=true)
			{return ChannelPutModifiable2(channel, inString, length, 0, blocking);}

		//! \brief Input a 16-bit word for processing on a channel.
		//! \param channel the channel to process the data.
		//! \param value the 16-bit value to be processed.
		//! \param order the \p ByteOrder in which the word should be processed.
		//! \param blocking specifies whether the object should block when processing input.
		//! \returns 0 indicates all bytes were processed during the call. Non-0 indicates the
		//!   number of bytes that were \a not processed.
		size_t ChannelPutWord16(const std::string &channel, word16 value, ByteOrder order=BIG_ENDIAN_ORDER, bool blocking=true);
		
		//! \brief Input a 32-bit word for processing on a channel.
		//! \param channel the channel to process the data.
		//! \param value the 32-bit value to be processed.
		//! \param order the \p ByteOrder in which the word should be processed.
		//! \param blocking specifies whether the object should block when processing input.
		//! \returns 0 indicates all bytes were processed during the call. Non-0 indicates the
		//!   number of bytes that were \a not processed.
		size_t ChannelPutWord32(const std::string &channel, word32 value, ByteOrder order=BIG_ENDIAN_ORDER, bool blocking=true);

		//! \brief Signal the end of a message
		//! \param channel the channel to process the data.
		//! \param propagation the number of attached transformations the \p ChannelMessageEnd() signal should be passed
		//! \param blocking specifies whether the object should block when processing input
		//! \returns 0 indicates all bytes were processed during the call. Non-0 indicates the
		//!   number of bytes that were \a not processed.
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		bool ChannelMessageEnd(const std::string &channel, int propagation=-1, bool blocking=true)
			{return !!ChannelPut2(channel, NULL, 0, propagation < 0 ? -1 : propagation+1, blocking);}
		
		//! \brief Input multiple bytes for processing and signal the end of a message
		//! \param channel the channel to process the data.
		//! \param inString the byte array to process
		//! \param length the size of the string, in bytes
		//! \param propagation the number of attached transformations the \p ChannelPutMessageEnd() signal should be passed
		//! \param blocking specifies whether the object should block when processing input
		//! \returns 0 indicates all bytes were processed during the call. Non-0 indicates the
		//!   number of bytes that were \a not processed.
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		size_t ChannelPutMessageEnd(const std::string &channel, const byte *inString, size_t length, int propagation=-1, bool blocking=true)
			{return ChannelPut2(channel, inString, length, propagation < 0 ? -1 : propagation+1, blocking);}

		//! \brief Request space which can be written into by the caller, and then used as input to \p Put
		//! \param channel the channel to process the data
		//! \param size the requested size of the buffer
		//! \details The purpose of this method is to help avoid extra memory allocations.
		//! \details \p size is an \a IN and \a OUT parameter and used as a hint. When the call is made,
		//!   \p size is the requested size of the buffer. When the call returns, \p size is the size of
		//!   the array returned to the caller.
		//! \details The base class implementation sets \p size to 0 and returns \p NULL.
		//! \note Some objects, like \p ArraySink, cannot create a space because its fixed. In the case of
		//! an \p ArraySink, the pointer to the array is returned and the \p size is remaining size.
		virtual byte * ChannelCreatePutSpace(const std::string &channel, size_t &size);

		//! \brief Input multiple bytes for processing on a channel.
		//! \param channel the channel to process the data.
		//! \param inString the byte array to process.
		//! \param length the size of the string, in bytes.
		//! \param messageEnd means how many filters to signal \p MessageEnd to, including this one.
		//! \param blocking specifies whether the object should block when processing input.
		virtual size_t ChannelPut2(const std::string &channel, const byte *inString, size_t length, int messageEnd, bool blocking);
		
		//! \brief Input multiple bytes that may be modified by callee on a channel
		//! \param channel the channel to process the data
		//! \param inString the byte array to process
		//! \param length the size of the string, in bytes
		//! \param messageEnd means how many filters to signal \p MessageEnd to, including this one
		//! \param blocking specifies whether the object should block when processing input.
		virtual size_t ChannelPutModifiable2(const std::string &channel, byte *inString, size_t length, int messageEnd, bool blocking);

		//! \brief Flush buffered input and/or output on a channel
		//! \param channel the channel to flush the data
		//! \param hardFlush is used to indicate whether all data should be flushed
		//! \param propagation the number of attached transformations the \p ChannelFlush() signal should be passed
		//! \param blocking specifies whether the object should block when processing input
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		virtual bool ChannelFlush(const std::string &channel, bool hardFlush, int propagation=-1, bool blocking=true);

		//! \brief Marks the end of a series of messages on a channel
		//! \param channel the channel to signal the end of a series of messages
		//! \param propagation the number of attached transformations the \p ChannelMessageSeriesEnd() signal should be passed
		//! \param blocking specifies whether the object should block when processing input
		//! \details Each object that receives the signal will perform its processing, decrement
		//!    \p propagation, and then pass the signal on to attached transformations if the value is not 0.
		//! \details \p propagation count includes this object. Setting \p propagation to <tt>1</tt> means this
		//!   object only. Setting \p propagation to <tt>-1</tt> means unlimited propagation.
		//! \note There should be a \p MessageEnd immediately before \p MessageSeriesEnd.
		virtual bool ChannelMessageSeriesEnd(const std::string &channel, int propagation=-1, bool blocking=true);

		//! \brief Sets the default retrieval channel
		//! \param channel the channel to signal the end of a series of messages
		//! \note this function may not be implemented in all objects that should support it.
		virtual void SetRetrievalChannel(const std::string &channel);
	//@}

	//!	\name ATTACHMENT
	/*! Some \p BufferedTransformation objects (e.g. Filter objects)
		allow other \p BufferedTransformation objects to be attached. When
		this is done, the first object instead of buffering its output,
		sends that output to the attached object as input. The entire
		attachment chain is deleted when the anchor object is destructed.
	*/
	//@{
		//! \brief Determines whether the object allows attachment
		//! \returns true if the object allows an attachment, false otherwise
		//! \details \p Sources and \p Filters will return \p true, while \p Sinks and other objects will return \p false.
		virtual bool Attachable() {return false;}
		
		//! \brief Returns the object immediately attached to this object
		//! \details \p AttachedTransformation returns \p NULL if there is no attachment
		virtual BufferedTransformation *AttachedTransformation() {assert(!Attachable()); return 0;}
		
		//! \brief Returns the object immediately attached to this object
		//! \details \p AttachedTransformation returns \p NULL if there is no attachment
		virtual const BufferedTransformation *AttachedTransformation() const
			{return const_cast<BufferedTransformation *>(this)->AttachedTransformation();}

		//! \brief Delete the current attachment chain and attach a new one
		//! \param newAttachment the new \p BufferedTransformation to attach
		//! \throws NotImplemented
		//! \details \p Detach delete the current attachment chain and replace it with an optional \p newAttachment
		//! \details If a derived class does not override \p Detach, then the base class throws
		//!   \p NotImplemented.
		virtual void Detach(BufferedTransformation *newAttachment = 0) {
			CRYPTOPP_UNUSED(newAttachment); assert(!Attachable());
			throw NotImplemented("BufferedTransformation: this object is not attachable");
		}
		//! add newAttachment to the end of attachment chain
		virtual void Attach(BufferedTransformation *newAttachment);
	//@}
		
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~BufferedTransformation() {}
#endif

protected:
	//! \brief Decrements the propagation count while clamping at 0
	//! \returns the decremented \p propagation or 0
	static int DecrementPropagation(int propagation)
		{return propagation != 0 ? propagation - 1 : 0;}

private:
	byte m_buf[4];	// for ChannelPutWord16 and ChannelPutWord32, to ensure buffer isn't deallocated before non-blocking operation completes
};

//! \brief An input discarding \p BufferedTransformation
//! \returns a reference to a BufferedTransformation object that discards all input
CRYPTOPP_DLL BufferedTransformation & TheBitBucket();

//! \class CryptoMaterial
//! \brief Interface for crypto material, such as public and private keys, and crypto parameters
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CryptoMaterial : public NameValuePairs
{
public:
	//! exception thrown when invalid crypto material is detected
	class CRYPTOPP_DLL InvalidMaterial : public InvalidDataFormat
	{
	public:
		explicit InvalidMaterial(const std::string &s) : InvalidDataFormat(s) {}
	};

	//! \brief Assign values to this object
	/*! \details This function can be used to create a public key from a private key. */
	virtual void AssignFrom(const NameValuePairs &source) =0;

	//! \brief Check this object for errors
	//! \param rng a \p RandomNumberGenerator for objects which use randominzed testing
	//! \param level the level of thoroughness
	//! \returns \p true if the tests succeed, \p false otherwise
	//! \details There are four levels of thoroughness:
	//!   <ul>
	//!   <li>0 - using this object won't cause a crash or exception
	//!   <li>1 - this object will probably function, and encrypt, sign, other operations correctly
	//!   <li>2 - ensure this object will function correctly, and perform reasonable security checks
	//!   <li>3 - perform reasonable security checks, and do checks that may take a long time
	//!   </ul>
	//! \details Level 0 does not require a \p RandomNumberGenerator. A \p NullRNG () can be used for level 0.
	//! \details Level 1 may not check for weak keys and such.
	//! \details Levels 2 and 3 are recommended.
	virtual bool Validate(RandomNumberGenerator &rng, unsigned int level) const =0;

	//! \brief Check this object for errors
	//! \param rng a \p RandomNumberGenerator for objects which use randominzed testing
	//! \param level the level of thoroughness
	//! \throws InvalidMaterial
	//! \details Internally, \p ThrowIfInvalid() calls \p Validate() and throws \p InvalidMaterial if validation fails.
	virtual void ThrowIfInvalid(RandomNumberGenerator &rng, unsigned int level) const
		{if (!Validate(rng, level)) throw InvalidMaterial("CryptoMaterial: this object contains invalid values");}

	//! \brief Saves a key to a \p BufferedTransformation
	//! \param bt the destination \p BufferedTransformation
	//! \throws NotImplemented
	//! \details \p Save writes the material to a \p BufferedTransformation.
	//! \details If the material is a key, then the key is written with ASN.1 DER encoding. The key
	//!   includes an object identifier with an algorthm id, like a \p subjectPublicKeyInfo.
	//! \details A "raw" key without the "key info" can be saved using a key's \p DEREncode method.
	//! \details If a derived class does not override \p Save, then the base class throws
	//!   \p NotImplemented.
	virtual void Save(BufferedTransformation &bt) const
		{CRYPTOPP_UNUSED(bt); throw NotImplemented("CryptoMaterial: this object does not support saving");}

	//! \brief Loads a key from a \p BufferedTransformation
	//! \param bt the source \p BufferedTransformation
	//! \throws KeyingErr
	//! \details \p Load attempts to read material from a \p BufferedTransformation. If the
	//!   material is a key that was generated outside the library, then the following
	//!   usually applies:
	//!   <ul>
	//!   <li>the key should be ASN.1 BER encoded
	//!   <li>the key should be a "key info"
	//!   </ul>
	//! \details "key info" means the key should have an object identifier with an algorthm id,
	//!   like a \p subjectPublicKeyInfo.
	//! \details To read a "raw" key without the "key info", then call the key's \p BERDecode method.
	//! \note \p Load generally does not check that the key is valid. Call Validate(), if needed.
	virtual void Load(BufferedTransformation &bt)
		{CRYPTOPP_UNUSED(bt); throw NotImplemented("CryptoMaterial: this object does not support loading");}

	//! \brief Determines whether the object supports precomputation
	//! \returns true if the object supports precomputation, false otherwise
	virtual bool SupportsPrecomputation() const {return false;}

	//! \brief Perform precomputation
	//! \param precomputationStorage the suggested number of objects for the precompute table
	//! \throws NotImplemented
	//! \details The exact semantics of \p Precompute() varies, but it typically means calculate
	//!   a table of \p n objects that can be used later to speed up computation.
	//! \details If a derived class does not override \p Precompute, then the base class throws
	//!   \p NotImplemented.
	virtual void Precompute(unsigned int precomputationStorage) {
		CRYPTOPP_UNUSED(precomputationStorage); assert(!SupportsPrecomputation());
		throw NotImplemented("CryptoMaterial: this object does not support precomputation");
	}

	//! retrieve previously saved precomputation
	virtual void LoadPrecomputation(BufferedTransformation &storedPrecomputation)
		{CRYPTOPP_UNUSED(storedPrecomputation); assert(!SupportsPrecomputation()); throw NotImplemented("CryptoMaterial: this object does not support precomputation");}
	//! save precomputation for later use
	virtual void SavePrecomputation(BufferedTransformation &storedPrecomputation) const
		{CRYPTOPP_UNUSED(storedPrecomputation); assert(!SupportsPrecomputation()); throw NotImplemented("CryptoMaterial: this object does not support precomputation");}

	// for internal library use
	void DoQuickSanityCheck() const	{ThrowIfInvalid(NullRNG(), 0);}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~CryptoMaterial() {}
#endif

#if (defined(__SUNPRO_CC) && __SUNPRO_CC < 0x590)
	// Sun Studio 11/CC 5.8 workaround: it generates incorrect code when casting to an empty virtual base class
	char m_sunCCworkaround;
#endif
};

//! \class GeneratableCryptoMaterial
//! \brief Interface for generatable crypto material, such as private keys and crypto parameters
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE GeneratableCryptoMaterial : virtual public CryptoMaterial
{
public:

	//! \brief Generate a random key or crypto parameters
	//! \param rng a \p RandomNumberGenerator to produce keying material
	//! \param params additional initialization parameters
	//! \throws KeyingErr if a key can't be generated or algorithm parameters are invalid
	//! \details If a derived class does not override \p GenerateRandom, then the base class throws
	//!    \p NotImplemented.
	virtual void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params = g_nullNameValuePairs) {
		CRYPTOPP_UNUSED(rng); CRYPTOPP_UNUSED(params);
		throw NotImplemented("GeneratableCryptoMaterial: this object does not support key/parameter generation");
	}

	//! \brief Generate a random key or crypto parameters
	//! \param rng a \p RandomNumberGenerator to produce keying material
	//! \param keySize the size of the key, in bits
	//! \throws KeyingErr if a key can't be generated or algorithm parameters are invalid	
	//! \details \p GenerateRandomWithKeySize calls \p GenerateRandom with a \p NameValuePairs
	//!    object with only "KeySize"
	void GenerateRandomWithKeySize(RandomNumberGenerator &rng, unsigned int keySize);
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~GeneratableCryptoMaterial() {}
#endif
};

//! \brief Interface for public keys

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PublicKey : virtual public CryptoMaterial
{
};

//! \brief Interface for private keys

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PrivateKey : public GeneratableCryptoMaterial
{
};

//! \brief Interface for crypto prameters

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CryptoParameters : public GeneratableCryptoMaterial
{
};

//! \brief Interface for asymmetric algorithms

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE AsymmetricAlgorithm : public Algorithm
{
public:
	//! returns a reference to the crypto material used by this object
	virtual CryptoMaterial & AccessMaterial() =0;
	//! returns a const reference to the crypto material used by this object
	virtual const CryptoMaterial & GetMaterial() const =0;

	//! for backwards compatibility, calls AccessMaterial().Load(bt)
	void BERDecode(BufferedTransformation &bt)
		{AccessMaterial().Load(bt);}
	//! for backwards compatibility, calls GetMaterial().Save(bt)
	void DEREncode(BufferedTransformation &bt) const
		{GetMaterial().Save(bt);}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~AsymmetricAlgorithm() {}
#endif
};

//! \brief Interface for asymmetric algorithms using public keys

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PublicKeyAlgorithm : public AsymmetricAlgorithm
{
public:
	// VC60 workaround: no co-variant return type
	CryptoMaterial & AccessMaterial() {return AccessPublicKey();}
	const CryptoMaterial & GetMaterial() const {return GetPublicKey();}

	virtual PublicKey & AccessPublicKey() =0;
	virtual const PublicKey & GetPublicKey() const {return const_cast<PublicKeyAlgorithm *>(this)->AccessPublicKey();}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~PublicKeyAlgorithm() {}
#endif
};

//! \brief Interface for asymmetric algorithms using private keys

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PrivateKeyAlgorithm : public AsymmetricAlgorithm
{
public:
	CryptoMaterial & AccessMaterial() {return AccessPrivateKey();}
	const CryptoMaterial & GetMaterial() const {return GetPrivateKey();}

	virtual PrivateKey & AccessPrivateKey() =0;
	virtual const PrivateKey & GetPrivateKey() const {return const_cast<PrivateKeyAlgorithm *>(this)->AccessPrivateKey();}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~PrivateKeyAlgorithm() {}
#endif
};

//! \brief Interface for key agreement algorithms

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE KeyAgreementAlgorithm : public AsymmetricAlgorithm
{
public:
	CryptoMaterial & AccessMaterial() {return AccessCryptoParameters();}
	const CryptoMaterial & GetMaterial() const {return GetCryptoParameters();}

	virtual CryptoParameters & AccessCryptoParameters() =0;
	virtual const CryptoParameters & GetCryptoParameters() const {return const_cast<KeyAgreementAlgorithm *>(this)->AccessCryptoParameters();}
	
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~KeyAgreementAlgorithm() {}
#endif
};

//! \brief Interface for public-key encryptors and decryptors

/*! This class provides an interface common to encryptors and decryptors
	for querying their plaintext and ciphertext lengths.
*/
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_CryptoSystem
{
public:
	virtual ~PK_CryptoSystem() {}

	//! maximum length of plaintext for a given ciphertext length
	/*! \note This function returns 0 if ciphertextLength is not valid (too long or too short). */
	virtual size_t MaxPlaintextLength(size_t ciphertextLength) const =0;

	//! calculate length of ciphertext given length of plaintext
	/*! \note This function returns 0 if plaintextLength is not valid (too long). */
	virtual size_t CiphertextLength(size_t plaintextLength) const =0;

	//! this object supports the use of the parameter with the given name
	/*! some possible parameter names: EncodingParameters, KeyDerivationParameters */
	virtual bool ParameterSupported(const char *name) const =0;

	//! return fixed ciphertext length, if one exists, otherwise return 0
	/*! \note "Fixed" here means length of ciphertext does not depend on length of plaintext.
		It usually does depend on the key length. */
	virtual size_t FixedCiphertextLength() const {return 0;}

	//! return maximum plaintext length given the fixed ciphertext length, if one exists, otherwise return 0
	virtual size_t FixedMaxPlaintextLength() const {return 0;}

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	size_t MaxPlainTextLength(size_t cipherTextLength) const {return MaxPlaintextLength(cipherTextLength);}
	size_t CipherTextLength(size_t plainTextLength) const {return CiphertextLength(plainTextLength);}
#endif
};

//! \brief Interface for public-key encryptors
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_Encryptor : public PK_CryptoSystem, public PublicKeyAlgorithm
{
public:
	//! exception thrown when trying to encrypt plaintext of invalid length
	class CRYPTOPP_DLL InvalidPlaintextLength : public Exception
	{
	public:
		InvalidPlaintextLength() : Exception(OTHER_ERROR, "PK_Encryptor: invalid plaintext length") {}
	};

	//! encrypt a byte string
	/*! \pre CiphertextLength(plaintextLength) != 0 (i.e., plaintext isn't too long)
		\pre size of ciphertext == CiphertextLength(plaintextLength)
	*/
	virtual void Encrypt(RandomNumberGenerator &rng, 
		const byte *plaintext, size_t plaintextLength, 
		byte *ciphertext, const NameValuePairs &parameters = g_nullNameValuePairs) const =0;

	//! create a new encryption filter
	/*! \note The caller is responsible for deleting the returned pointer.
		\note Encoding parameters should be passed in the "EP" channel.
	*/
	virtual BufferedTransformation * CreateEncryptionFilter(RandomNumberGenerator &rng, 
		BufferedTransformation *attachment=NULL, const NameValuePairs &parameters = g_nullNameValuePairs) const;
};

//! \brief Interface for public-key decryptors

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_Decryptor : public PK_CryptoSystem, public PrivateKeyAlgorithm
{
public:
	//! decrypt a byte string, and return the length of plaintext
	/*! \pre size of plaintext == MaxPlaintextLength(ciphertextLength) bytes.
		\returns the actual length of the plaintext, indication that decryption failed.
	*/
	virtual DecodingResult Decrypt(RandomNumberGenerator &rng, 
		const byte *ciphertext, size_t ciphertextLength, 
		byte *plaintext, const NameValuePairs &parameters = g_nullNameValuePairs) const =0;

	//! create a new decryption filter
	/*! \note caller is responsible for deleting the returned pointer
	*/
	virtual BufferedTransformation * CreateDecryptionFilter(RandomNumberGenerator &rng, 
		BufferedTransformation *attachment=NULL, const NameValuePairs &parameters = g_nullNameValuePairs) const;

	//! decrypt a fixed size ciphertext
	DecodingResult FixedLengthDecrypt(RandomNumberGenerator &rng, const byte *ciphertext, byte *plaintext, const NameValuePairs &parameters = g_nullNameValuePairs) const
		{return Decrypt(rng, ciphertext, FixedCiphertextLength(), plaintext, parameters);}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~PK_Decryptor() {}
#endif
};

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
typedef PK_CryptoSystem PK_FixedLengthCryptoSystem;
typedef PK_Encryptor PK_FixedLengthEncryptor;
typedef PK_Decryptor PK_FixedLengthDecryptor;
#endif

//! \brief Interface for public-key signers and verifiers

/*! This class provides an interface common to signers and verifiers
	for querying scheme properties.
*/
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_SignatureScheme
{
public:
	//! invalid key exception, may be thrown by any function in this class if the private or public key has a length that can't be used
	class CRYPTOPP_DLL InvalidKeyLength : public Exception
	{
	public:
		InvalidKeyLength(const std::string &message) : Exception(OTHER_ERROR, message) {}
	};

	//! key too short exception, may be thrown by any function in this class if the private or public key is too short to sign or verify anything
	class CRYPTOPP_DLL KeyTooShort : public InvalidKeyLength
	{
	public:
		KeyTooShort() : InvalidKeyLength("PK_Signer: key too short for this signature scheme") {}
	};

	virtual ~PK_SignatureScheme() {}

	//! signature length if it only depends on the key, otherwise 0
	virtual size_t SignatureLength() const =0;

	//! maximum signature length produced for a given length of recoverable message part
	virtual size_t MaxSignatureLength(size_t recoverablePartLength = 0) const
	{CRYPTOPP_UNUSED(recoverablePartLength); return SignatureLength();}

	//! length of longest message that can be recovered, or 0 if this signature scheme does not support message recovery
	virtual size_t MaxRecoverableLength() const =0;

	//! length of longest message that can be recovered from a signature of given length, or 0 if this signature scheme does not support message recovery
	virtual size_t MaxRecoverableLengthFromSignatureLength(size_t signatureLength) const =0;

	//! requires a random number generator to sign
	/*! if this returns false, NullRNG() can be passed to functions that take RandomNumberGenerator & */
	virtual bool IsProbabilistic() const =0;

	//! whether or not a non-recoverable message part can be signed
	virtual bool AllowNonrecoverablePart() const =0;

	//! if this function returns true, during verification you must input the signature before the message, otherwise you can input it at anytime */
	virtual bool SignatureUpfront() const {return false;}

	//! whether you must input the recoverable part before the non-recoverable part during signing
	virtual bool RecoverablePartFirst() const =0;
};

//! \brief Interface for accumulating messages to be signed or verified
/*! Only Update() should be called
	on this class. No other functions inherited from HashTransformation should be called.
*/
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_MessageAccumulator : public HashTransformation
{
public:
	//! should not be called on PK_MessageAccumulator
	unsigned int DigestSize() const
		{throw NotImplemented("PK_MessageAccumulator: DigestSize() should not be called");}

	//! should not be called on PK_MessageAccumulator
	void TruncatedFinal(byte *digest, size_t digestSize) 
	{
		CRYPTOPP_UNUSED(digest); CRYPTOPP_UNUSED(digestSize);
		throw NotImplemented("PK_MessageAccumulator: TruncatedFinal() should not be called");
	}
};

//! \brief Interface for public-key signers

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_Signer : public PK_SignatureScheme, public PrivateKeyAlgorithm
{
public:
	//! create a new HashTransformation to accumulate the message to be signed
	virtual PK_MessageAccumulator * NewSignatureAccumulator(RandomNumberGenerator &rng) const =0;

	virtual void InputRecoverableMessage(PK_MessageAccumulator &messageAccumulator, const byte *recoverableMessage, size_t recoverableMessageLength) const =0;

	//! sign and delete messageAccumulator (even in case of exception thrown)
	/*! \pre size of signature == MaxSignatureLength()
		\returns actual signature length
	*/
	virtual size_t Sign(RandomNumberGenerator &rng, PK_MessageAccumulator *messageAccumulator, byte *signature) const;

	//! sign and restart messageAccumulator
	/*! \pre size of signature == MaxSignatureLength()
		\returns actual signature length
	*/
	virtual size_t SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart=true) const =0;

	//! sign a message
	/*! \pre size of signature == MaxSignatureLength()
		\returns actual signature length
	*/
	virtual size_t SignMessage(RandomNumberGenerator &rng, const byte *message, size_t messageLen, byte *signature) const;

	//! sign a recoverable message
	/*! \pre size of signature == MaxSignatureLength(recoverableMessageLength)
		\returns actual signature length
	*/
	virtual size_t SignMessageWithRecovery(RandomNumberGenerator &rng, const byte *recoverableMessage, size_t recoverableMessageLength, 
		const byte *nonrecoverableMessage, size_t nonrecoverableMessageLength, byte *signature) const;
		
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~PK_Signer() {}
#endif
};

//! \brief Interface for public-key signature verifiers
/*! The Recover* functions throw NotImplemented if the signature scheme does not support
	message recovery.
	The Verify* functions throw InvalidDataFormat if the scheme does support message
	recovery and the signature contains a non-empty recoverable message part. The
	Recovery* functions should be used in that case.
*/
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_Verifier : public PK_SignatureScheme, public PublicKeyAlgorithm
{
public:
	//! create a new HashTransformation to accumulate the message to be verified
	virtual PK_MessageAccumulator * NewVerificationAccumulator() const =0;

	//! input signature into a message accumulator
	virtual void InputSignature(PK_MessageAccumulator &messageAccumulator, const byte *signature, size_t signatureLength) const =0;

	//! check whether messageAccumulator contains a valid signature and message, and delete messageAccumulator (even in case of exception thrown)
	virtual bool Verify(PK_MessageAccumulator *messageAccumulator) const;

	//! check whether messageAccumulator contains a valid signature and message, and restart messageAccumulator
	virtual bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const =0;

	//! check whether input signature is a valid signature for input message
	virtual bool VerifyMessage(const byte *message, size_t messageLen, 
		const byte *signature, size_t signatureLength) const;

	//! recover a message from its signature
	/*! \pre size of recoveredMessage == MaxRecoverableLengthFromSignatureLength(signatureLength)
	*/
	virtual DecodingResult Recover(byte *recoveredMessage, PK_MessageAccumulator *messageAccumulator) const;

	//! recover a message from its signature
	/*! \pre size of recoveredMessage == MaxRecoverableLengthFromSignatureLength(signatureLength)
	*/
	virtual DecodingResult RecoverAndRestart(byte *recoveredMessage, PK_MessageAccumulator &messageAccumulator) const =0;

	//! recover a message from its signature
	/*! \pre size of recoveredMessage == MaxRecoverableLengthFromSignatureLength(signatureLength)
	*/
	virtual DecodingResult RecoverMessage(byte *recoveredMessage, 
		const byte *nonrecoverableMessage, size_t nonrecoverableMessageLength, 
		const byte *signature, size_t signatureLength) const;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~PK_Verifier() {}
#endif
};

//! \brief Interface for domains of simple key agreement protocols

/*! A key agreement domain is a set of parameters that must be shared
	by two parties in a key agreement protocol, along with the algorithms
	for generating key pairs and deriving agreed values.
*/
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE SimpleKeyAgreementDomain : public KeyAgreementAlgorithm
{
public:
	//! return length of agreed value produced
	virtual unsigned int AgreedValueLength() const =0;
	//! return length of private keys in this domain
	virtual unsigned int PrivateKeyLength() const =0;
	//! return length of public keys in this domain
	virtual unsigned int PublicKeyLength() const =0;
	//! generate private key
	/*! \pre size of privateKey == PrivateKeyLength() */
	virtual void GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const =0;
	//! generate public key
	/*!	\pre size of publicKey == PublicKeyLength() */
	virtual void GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const =0;
	//! generate private/public key pair
	/*! \note equivalent to calling GeneratePrivateKey() and then GeneratePublicKey() */
	virtual void GenerateKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;
	//! derive agreed value from your private key and couterparty's public key, return false in case of failure
	/*! \note If you have previously validated the public key, use validateOtherPublicKey=false to save time.
		\pre size of agreedValue == AgreedValueLength()
		\pre length of privateKey == PrivateKeyLength()
		\pre length of otherPublicKey == PublicKeyLength()
	*/
	virtual bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const =0;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~SimpleKeyAgreementDomain() {}
#endif

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	bool ValidateDomainParameters(RandomNumberGenerator &rng) const
		{return GetCryptoParameters().Validate(rng, 2);}
#endif
};

//! \brief Interface for domains of authenticated key agreement protocols

/*! In an authenticated key agreement protocol, each party has two
	key pairs. The long-lived key pair is called the static key pair,
	and the short-lived key pair is called the ephemeral key pair.
*/
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE AuthenticatedKeyAgreementDomain : public KeyAgreementAlgorithm
{
public:
	//! return length of agreed value produced
	virtual unsigned int AgreedValueLength() const =0;

	//! return length of static private keys in this domain
	virtual unsigned int StaticPrivateKeyLength() const =0;
	//! return length of static public keys in this domain
	virtual unsigned int StaticPublicKeyLength() const =0;
	//! generate static private key
	/*! \pre size of privateKey == PrivateStaticKeyLength() */
	virtual void GenerateStaticPrivateKey(RandomNumberGenerator &rng, byte *privateKey) const =0;
	//! generate static public key
	/*!	\pre size of publicKey == PublicStaticKeyLength() */
	virtual void GenerateStaticPublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const =0;
	//! generate private/public key pair
	/*! \note equivalent to calling GenerateStaticPrivateKey() and then GenerateStaticPublicKey() */
	virtual void GenerateStaticKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	//! return length of ephemeral private keys in this domain
	virtual unsigned int EphemeralPrivateKeyLength() const =0;
	//! return length of ephemeral public keys in this domain
	virtual unsigned int EphemeralPublicKeyLength() const =0;
	//! generate ephemeral private key
	/*! \pre size of privateKey == PrivateEphemeralKeyLength() */
	virtual void GenerateEphemeralPrivateKey(RandomNumberGenerator &rng, byte *privateKey) const =0;
	//! generate ephemeral public key
	/*!	\pre size of publicKey == PublicEphemeralKeyLength() */
	virtual void GenerateEphemeralPublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const =0;
	//! generate private/public key pair
	/*! \note equivalent to calling GenerateEphemeralPrivateKey() and then GenerateEphemeralPublicKey() */
	virtual void GenerateEphemeralKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	//! derive agreed value from your private keys and couterparty's public keys, return false in case of failure
	/*! \note The ephemeral public key will always be validated.
		      If you have previously validated the static public key, use validateStaticOtherPublicKey=false to save time.
		\pre size of agreedValue == AgreedValueLength()
		\pre length of staticPrivateKey == StaticPrivateKeyLength()
		\pre length of ephemeralPrivateKey == EphemeralPrivateKeyLength()
		\pre length of staticOtherPublicKey == StaticPublicKeyLength()
		\pre length of ephemeralOtherPublicKey == EphemeralPublicKeyLength()
	*/
	virtual bool Agree(byte *agreedValue,
		const byte *staticPrivateKey, const byte *ephemeralPrivateKey,
		const byte *staticOtherPublicKey, const byte *ephemeralOtherPublicKey,
		bool validateStaticOtherPublicKey=true) const =0;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~AuthenticatedKeyAgreementDomain() {}
#endif

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	bool ValidateDomainParameters(RandomNumberGenerator &rng) const
		{return GetCryptoParameters().Validate(rng, 2);}
#endif
};

// interface for password authenticated key agreement protocols, not implemented yet
#if 0
//! \brief Interface for protocol sessions
/*! The methods should be called in the following order:

	InitializeSession(rng, parameters);	// or call initialize method in derived class
	while (true)
	{
		if (OutgoingMessageAvailable())
		{
			length = GetOutgoingMessageLength();
			GetOutgoingMessage(message);
			; // send outgoing message
		}

		if (LastMessageProcessed())
			break;

		; // receive incoming message
		ProcessIncomingMessage(message);
	}
	; // call methods in derived class to obtain result of protocol session
*/
class ProtocolSession
{
public:
	//! exception thrown when an invalid protocol message is processed
	class ProtocolError : public Exception
	{
	public:
		ProtocolError(ErrorType errorType, const std::string &s) : Exception(errorType, s) {}
	};

	//! exception thrown when a function is called unexpectedly
	/*! for example calling ProcessIncomingMessage() when ProcessedLastMessage() == true */
	class UnexpectedMethodCall : public Exception
	{
	public:
		UnexpectedMethodCall(const std::string &s) : Exception(OTHER_ERROR, s) {}
	};

	ProtocolSession() : m_rng(NULL), m_throwOnProtocolError(true), m_validState(false) {}
	virtual ~ProtocolSession() {}

	virtual void InitializeSession(RandomNumberGenerator &rng, const NameValuePairs &parameters) =0;

	bool GetThrowOnProtocolError() const {return m_throwOnProtocolError;}
	void SetThrowOnProtocolError(bool throwOnProtocolError) {m_throwOnProtocolError = throwOnProtocolError;}

	bool HasValidState() const {return m_validState;}

	virtual bool OutgoingMessageAvailable() const =0;
	virtual unsigned int GetOutgoingMessageLength() const =0;
	virtual void GetOutgoingMessage(byte *message) =0;

	virtual bool LastMessageProcessed() const =0;
	virtual void ProcessIncomingMessage(const byte *message, unsigned int messageLength) =0;

protected:
	void HandleProtocolError(Exception::ErrorType errorType, const std::string &s) const;
	void CheckAndHandleInvalidState() const;
	void SetValidState(bool valid) {m_validState = valid;}

	RandomNumberGenerator *m_rng;

private:
	bool m_throwOnProtocolError, m_validState;
};

class KeyAgreementSession : public ProtocolSession
{
public:
	virtual unsigned int GetAgreedValueLength() const =0;
	virtual void GetAgreedValue(byte *agreedValue) const =0;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~KeyAgreementSession() {}
#endif
};

class PasswordAuthenticatedKeyAgreementSession : public KeyAgreementSession
{
public:
	void InitializePasswordAuthenticatedKeyAgreementSession(RandomNumberGenerator &rng, 
		const byte *myId, unsigned int myIdLength, 
		const byte *counterPartyId, unsigned int counterPartyIdLength, 
		const byte *passwordOrVerifier, unsigned int passwordOrVerifierLength);

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~PasswordAuthenticatedKeyAgreementSession() {}
#endif
};

class PasswordAuthenticatedKeyAgreementDomain : public KeyAgreementAlgorithm
{
public:
	//! return whether the domain parameters stored in this object are valid
	virtual bool ValidateDomainParameters(RandomNumberGenerator &rng) const
		{return GetCryptoParameters().Validate(rng, 2);}

	virtual unsigned int GetPasswordVerifierLength(const byte *password, unsigned int passwordLength) const =0;
	virtual void GeneratePasswordVerifier(RandomNumberGenerator &rng, const byte *userId, unsigned int userIdLength, const byte *password, unsigned int passwordLength, byte *verifier) const =0;

	enum RoleFlags {CLIENT=1, SERVER=2, INITIATOR=4, RESPONDER=8};

	virtual bool IsValidRole(unsigned int role) =0;
	virtual PasswordAuthenticatedKeyAgreementSession * CreateProtocolSession(unsigned int role) const =0;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~PasswordAuthenticatedKeyAgreementDomain() {}
#endif
};
#endif

//! BER Decode Exception Class, may be thrown during an ASN1 BER decode operation
class CRYPTOPP_DLL BERDecodeErr : public InvalidArgument
{
public: 
	BERDecodeErr() : InvalidArgument("BER decode error") {}
	BERDecodeErr(const std::string &s) : InvalidArgument(s) {}
};

//! \brief Interface for encoding and decoding ASN1 objects
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE ASN1Object
{
public:
	virtual ~ASN1Object() {}
	//! decode this object from a BufferedTransformation, using BER (Basic Encoding Rules)
	virtual void BERDecode(BufferedTransformation &bt) =0;
	//! encode this object into a BufferedTransformation, using DER (Distinguished Encoding Rules)
	virtual void DEREncode(BufferedTransformation &bt) const =0;
	//! encode this object into a BufferedTransformation, using BER
	/*! this may be useful if DEREncode() would be too inefficient */
	virtual void BEREncode(BufferedTransformation &bt) const {DEREncode(bt);}
};

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
typedef PK_SignatureScheme PK_SignatureSystem;
typedef SimpleKeyAgreementDomain PK_SimpleKeyAgreementDomain;
typedef AuthenticatedKeyAgreementDomain PK_AuthenticatedKeyAgreementDomain;
#endif

NAMESPACE_END

#if CRYPTOPP_MSC_VERSION
# pragma warning(pop)
#endif

#endif
