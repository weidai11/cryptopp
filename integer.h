// integer.h - originally written and placed in the public domain by Wei Dai

//! \file integer.h
//! \brief Multiple precision integer with arithmetic operations
//! \details The Integer class can represent positive and negative integers
//!   with absolute value less than (256**sizeof(word))<sup>(256**sizeof(int))</sup>.
//! \details Internally, the library uses a sign magnitude representation, and the class
//!   has two data members. The first is a IntegerSecBlock (a SecBlock<word>) and it is
//!   used to hold the representation. The second is a Sign (an enumeration), and it is
//!   used to track the sign of the Integer.
//! \details For details on how the Integer class initializes its function pointers using
//!   InitializeInteger and how it creates Integer::Zero(), Integer::One(), and
//!   Integer::Two(), then see the comments at the top of <tt>integer.cpp</tt>.
//! \since Crypto++ 1.0

#ifndef CRYPTOPP_INTEGER_H
#define CRYPTOPP_INTEGER_H

#include "cryptlib.h"
#include "secblock.h"
#include "stdcpp.h"

#include <iosfwd>

NAMESPACE_BEGIN(CryptoPP)

//! \struct InitializeInteger
//! \brief Performs static initialization of the Integer class
struct InitializeInteger
{
	InitializeInteger();
};

// Always align, http://github.com/weidai11/cryptopp/issues/256
typedef SecBlock<word, AllocatorWithCleanup<word, true> > IntegerSecBlock;

//! \brief Multiple precision integer with arithmetic operations
//! \details The Integer class can represent positive and negative integers
//!   with absolute value less than (256**sizeof(word))<sup>(256**sizeof(int))</sup>.
//! \details Internally, the library uses a sign magnitude representation, and the class
//!   has two data members. The first is a IntegerSecBlock (a SecBlock<word>) and it is
//!   used to hold the representation. The second is a Sign (an enumeration), and it is
//!   used to track the sign of the Integer.
//! \details For details on how the Integer class initializes its function pointers using
//!   InitializeInteger and how it creates Integer::Zero(), Integer::One(), and
//!   Integer::Two(), then see the comments at the top of <tt>integer.cpp</tt>.
//! \since Crypto++ 1.0
//! \nosubgrouping
class CRYPTOPP_DLL Integer : private InitializeInteger, public ASN1Object
{
public:
	//! \name ENUMS, EXCEPTIONS, and TYPEDEFS
	//@{
		//! \brief Exception thrown when division by 0 is encountered
		class DivideByZero : public Exception
		{
		public:
			DivideByZero() : Exception(OTHER_ERROR, "Integer: division by zero") {}
		};

		//! \brief Exception thrown when a random number cannot be found that
		//!   satisfies the condition
		class RandomNumberNotFound : public Exception
		{
		public:
			RandomNumberNotFound() : Exception(OTHER_ERROR, "Integer: no integer satisfies the given parameters") {}
		};

		//! \enum Sign
		//! \brief Used internally to represent the integer
		//! \details Sign is used internally to represent the integer. It is also used in a few API functions.
		//! \sa SetPositive(), SetNegative(), Signedness
		enum Sign {
			//! \brief the value is positive or 0
			POSITIVE=0,
			//! \brief the value is negative
			NEGATIVE=1};

		//! \enum Signedness
		//! \brief Used when importing and exporting integers
		//! \details Signedness is usually used in API functions.
		//! \sa Sign
		enum Signedness {
			//! \brief an unsigned value
			UNSIGNED,
			//! \brief a signed value
			SIGNED};

		//! \enum RandomNumberType
		//! \brief Properties of a random integer
		enum RandomNumberType {
			//! \brief a number with no special properties
			ANY,
			//! \brief a number which is probabilistically prime
			PRIME};
	//@}

	//! \name CREATORS
	//@{
		//! \brief Creates the zero integer
		Integer();

		//! copy constructor
		Integer(const Integer& t);

		//! \brief Convert from signed long
		Integer(signed long value);

		//! \brief Convert from lword
		//! \param sign enumeration indicating Sign
		//! \param value the long word
		Integer(Sign sign, lword value);

		//! \brief Convert from two words
		//! \param sign enumeration indicating Sign
		//! \param highWord the high word
		//! \param lowWord the low word
		Integer(Sign sign, word highWord, word lowWord);

		//! \brief Convert from a C-string
		//! \param str C-string value
		//! \param order the ByteOrder of the string to be processed
		//! \details \p str can be in base 2, 8, 10, or 16. Base is determined by a case
		//!   insensitive suffix of 'h', 'o', or 'b'.  No suffix means base 10.
		//! \details Byte order was added at Crypto++ 5.7 to allow use of little-endian
		//!   integers with curve25519, Poly1305 and Microsoft CAPI.
		explicit Integer(const char *str, ByteOrder order = BIG_ENDIAN_ORDER);

		//! \brief Convert from a wide C-string
		//! \param str wide C-string value
		//! \param order the ByteOrder of the string to be processed
		//! \details \p str can be in base 2, 8, 10, or 16. Base is determined by a case
		//!   insensitive suffix of 'h', 'o', or 'b'.  No suffix means base 10.
		//! \details Byte order was added at Crypto++ 5.7 to allow use of little-endian
		//!   integers with curve25519, Poly1305 and Microsoft CAPI.
		explicit Integer(const wchar_t *str, ByteOrder order = BIG_ENDIAN_ORDER);

		//! \brief Convert from a big-endian byte array
		//! \param encodedInteger big-endian byte array
		//! \param byteCount length of the byte array
		//! \param sign enumeration indicating Signedness
		//! \param order the ByteOrder of the array to be processed
		//! \details Byte order was added at Crypto++ 5.7 to allow use of little-endian
		//!   integers with curve25519, Poly1305 and Microsoft CAPI.
		Integer(const ::byte *encodedInteger, size_t byteCount, Signedness sign=UNSIGNED, ByteOrder order = BIG_ENDIAN_ORDER);

		//! \brief Convert from a big-endian array
		//! \param bt BufferedTransformation object with big-endian byte array
		//! \param byteCount length of the byte array
		//! \param sign enumeration indicating Signedness
		//! \param order the ByteOrder of the data to be processed
		//! \details Byte order was added at Crypto++ 5.7 to allow use of little-endian
		//!   integers with curve25519, Poly1305 and Microsoft CAPI.
		Integer(BufferedTransformation &bt, size_t byteCount, Signedness sign=UNSIGNED, ByteOrder order = BIG_ENDIAN_ORDER);

		//! \brief Convert from a BER encoded byte array
		//! \param bt BufferedTransformation object with BER encoded byte array
		explicit Integer(BufferedTransformation &bt);

		//! \brief Create a random integer
		//! \param rng RandomNumberGenerator used to generate material
		//! \param bitCount the number of bits in the resulting integer
		//! \details The random integer created is uniformly distributed over <tt>[0, 2<sup>bitCount</sup>]</tt>.
		Integer(RandomNumberGenerator &rng, size_t bitCount);

		//! \brief Integer representing 0
		//! \returns an Integer representing 0
		//! \details Zero() avoids calling constructors for frequently used integers
		static const Integer & CRYPTOPP_API Zero();
		//! \brief Integer representing 1
		//! \returns an Integer representing 1
		//! \details One() avoids calling constructors for frequently used integers
		static const Integer & CRYPTOPP_API One();
		//! \brief Integer representing 2
		//! \returns an Integer representing 2
		//! \details Two() avoids calling constructors for frequently used integers
		static const Integer & CRYPTOPP_API Two();

		//! \brief Create a random integer of special form
		//! \param rng RandomNumberGenerator used to generate material
		//! \param min the minimum value
		//! \param max the maximum value
		//! \param rnType RandomNumberType to specify the type
		//! \param equiv the equivalence class based on the parameter \p mod
		//! \param mod the modulus used to reduce the equivalence class
		//! \throw RandomNumberNotFound if the set is empty.
		//! \details Ideally, the random integer created should be uniformly distributed
		//!   over <tt>{x | min \<= x \<= max</tt> and \p x is of rnType and <tt>x \% mod == equiv}</tt>.
		//!   However the actual distribution may not be uniform because sequential
		//!   search is used to find an appropriate number from a random starting
		//!   point.
		//! \details May return (with very small probability) a pseudoprime when a prime
		//!   is requested and <tt>max \> lastSmallPrime*lastSmallPrime</tt>. \p lastSmallPrime
		//!   is declared in nbtheory.h.
		Integer(RandomNumberGenerator &rng, const Integer &min, const Integer &max, RandomNumberType rnType=ANY, const Integer &equiv=Zero(), const Integer &mod=One());

		//! \brief Exponentiates to a power of 2
		//! \returns the Integer 2<sup>e</sup>
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		static Integer CRYPTOPP_API Power2(size_t e);
	//@}

	//! \name ENCODE/DECODE
	//@{
		//! \brief Minimum number of bytes to encode this integer
		//! \param sign enumeration indicating Signedness
		//! \note The MinEncodedSize() of 0 is 1.
		size_t MinEncodedSize(Signedness sign=UNSIGNED) const;

		//! \brief Encode in big-endian format
		//! \param output big-endian byte array
		//! \param outputLen length of the byte array
		//! \param sign enumeration indicating Signedness
		//! \details Unsigned means encode absolute value, signed means encode two's complement if negative.
		//! \details outputLen can be used to ensure an Integer is encoded to an exact size (rather than a
		//!   minimum size). An exact size is useful, for example, when encoding to a field element size.
		void Encode(::byte *output, size_t outputLen, Signedness sign=UNSIGNED) const;

		//! \brief Encode in big-endian format
		//! \param bt BufferedTransformation object
		//! \param outputLen length of the encoding
		//! \param sign enumeration indicating Signedness
		//! \details Unsigned means encode absolute value, signed means encode two's complement if negative.
		//! \details outputLen can be used to ensure an Integer is encoded to an exact size (rather than a
		//!   minimum size). An exact size is useful, for example, when encoding to a field element size.
		void Encode(BufferedTransformation &bt, size_t outputLen, Signedness sign=UNSIGNED) const;

		//! \brief Encode in DER format
		//! \param bt BufferedTransformation object
		//! \details Encodes the Integer using Distinguished Encoding Rules
		//!   The result is placed into a BufferedTransformation object
		void DEREncode(BufferedTransformation &bt) const;

		//! \brief Encode absolute value as big-endian octet string
		//! \param bt BufferedTransformation object
		//! \param length the number of mytes to decode
		void DEREncodeAsOctetString(BufferedTransformation &bt, size_t length) const;

		//! \brief Encode absolute value in OpenPGP format
		//! \param output big-endian byte array
		//! \param bufferSize length of the byte array
		//! \returns length of the output
		//! \details OpenPGPEncode places result into the buffer and returns the
		//!   number of bytes used for the encoding
		size_t OpenPGPEncode(::byte *output, size_t bufferSize) const;

		//! \brief Encode absolute value in OpenPGP format
		//! \param bt BufferedTransformation object
		//! \returns length of the output
		//! \details OpenPGPEncode places result into a BufferedTransformation object and returns the
		//!   number of bytes used for the encoding
		size_t OpenPGPEncode(BufferedTransformation &bt) const;

		//! \brief Decode from big-endian byte array
		//! \param input big-endian byte array
		//! \param inputLen length of the byte array
		//! \param sign enumeration indicating Signedness
		void Decode(const ::byte *input, size_t inputLen, Signedness sign=UNSIGNED);

		//! \brief Decode nonnegative value from big-endian byte array
		//! \param bt BufferedTransformation object
		//! \param inputLen length of the byte array
		//! \param sign enumeration indicating Signedness
		//! \note <tt>bt.MaxRetrievable() \>= inputLen</tt>.
		void Decode(BufferedTransformation &bt, size_t inputLen, Signedness sign=UNSIGNED);

		//! \brief Decode from BER format
		//! \param input big-endian byte array
		//! \param inputLen length of the byte array
		void BERDecode(const ::byte *input, size_t inputLen);

		//! \brief Decode from BER format
		//! \param bt BufferedTransformation object
		void BERDecode(BufferedTransformation &bt);

		//! \brief Decode nonnegative value from big-endian octet string
		//! \param bt BufferedTransformation object
		//! \param length length of the byte array
		void BERDecodeAsOctetString(BufferedTransformation &bt, size_t length);

		//! \brief Exception thrown when an error is encountered decoding an OpenPGP integer
		class OpenPGPDecodeErr : public Exception
		{
		public:
			OpenPGPDecodeErr() : Exception(INVALID_DATA_FORMAT, "OpenPGP decode error") {}
		};

		//! \brief Decode from OpenPGP format
		//! \param input big-endian byte array
		//! \param inputLen length of the byte array
		void OpenPGPDecode(const ::byte *input, size_t inputLen);
		//! \brief Decode from OpenPGP format
		//! \param bt BufferedTransformation object
		void OpenPGPDecode(BufferedTransformation &bt);
	//@}

	//! \name ACCESSORS
	//@{
		//! \brief Determines if the Integer is convertable to Long
		//! \returns true if *this can be represented as a signed long
		//! \sa ConvertToLong()
		bool IsConvertableToLong() const;
		//! \brief Convert the Integer to Long
		//! \return equivalent signed long if possible, otherwise undefined
		//! \sa IsConvertableToLong()
		signed long ConvertToLong() const;

		//! \brief Determines the number of bits required to represent the Integer
		//! \returns number of significant bits = floor(log2(abs(*this))) + 1
		unsigned int BitCount() const;
		//! \brief Determines the number of bytes required to represent the Integer
		//! \returns number of significant bytes = ceiling(BitCount()/8)
		unsigned int ByteCount() const;
		//! \brief Determines the number of words required to represent the Integer
		//! \returns number of significant words = ceiling(ByteCount()/sizeof(word))
		unsigned int WordCount() const;

		//! \brief Provides the i-th bit of the Integer
		//! \returns the i-th bit, i=0 being the least significant bit
		bool GetBit(size_t i) const;
		//! \brief Provides the i-th byte of the Integer
		//! \returns the i-th byte
		::byte GetByte(size_t i) const;
		//! \brief Provides the low order bits of the Integer
		//! \returns n lowest bits of *this >> i
		lword GetBits(size_t i, size_t n) const;

		//! \brief Determines if the Integer is 0
		//! \returns true if the Integer is 0, false otherwise
		bool IsZero() const {return !*this;}
		//! \brief Determines if the Integer is non-0
		//! \returns true if the Integer is non-0, false otherwise
		bool NotZero() const {return !IsZero();}
		//! \brief Determines if the Integer is negative
		//! \returns true if the Integer is negative, false otherwise
		bool IsNegative() const {return sign == NEGATIVE;}
		//! \brief Determines if the Integer is non-negative
		//! \returns true if the Integer is non-negative, false otherwise
		bool NotNegative() const {return !IsNegative();}
		//! \brief Determines if the Integer is positive
		//! \returns true if the Integer is positive, false otherwise
		bool IsPositive() const {return NotNegative() && NotZero();}
		//! \brief Determines if the Integer is non-positive
		//! \returns true if the Integer is non-positive, false otherwise
		bool NotPositive() const {return !IsPositive();}
		//! \brief Determines if the Integer is even parity
		//! \returns true if the Integer is even, false otherwise
		bool IsEven() const {return GetBit(0) == 0;}
		//! \brief Determines if the Integer is odd parity
		//! \returns true if the Integer is odd, false otherwise
		bool IsOdd() const	{return GetBit(0) == 1;}
	//@}

	//! \name MANIPULATORS
	//@{
		//! \brief Assignment
		Integer&  operator=(const Integer& t);

		//! \brief Addition Assignment
		Integer&  operator+=(const Integer& t);
		//! \brief Subtraction Assignment
		Integer&  operator-=(const Integer& t);
		//! \brief Multiplication Assignment
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		Integer&  operator*=(const Integer& t)	{return *this = Times(t);}
		//! \brief Division Assignment
		Integer&  operator/=(const Integer& t)	{return *this = DividedBy(t);}
		//! \brief Remainder Assignment
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		Integer&  operator%=(const Integer& t)	{return *this = Modulo(t);}
		//! \brief Division Assignment
		Integer&  operator/=(word t)  {return *this = DividedBy(t);}
		//! \brief Remainder Assignment
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		Integer&  operator%=(word t)  {return *this = Integer(POSITIVE, 0, Modulo(t));}

		//! \brief Left-shift Assignment
		Integer&  operator<<=(size_t n);
		//! \brief Right-shift Assignment
		Integer&  operator>>=(size_t n);

		//! \brief Bitwise AND Assignment
		//! \param t the other Integer
		//! \returns the result of *this & t
		//! \details operator&=() performs a bitwise AND on *this. Missing bits are truncated
		//!   at the most significant bit positions, so the result is as small as the
		//!   smaller of the operands.
		//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
		//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
		//!   the integer should be converted to a 2's compliment representation before performing
		//!   the operation.
		//! \since Crypto++ 6.0
		Integer& operator&=(const Integer& t);
		//! \brief Bitwise OR Assignment
		//! \param t the second Integer
		//! \returns the result of *this | t
		//! \details operator|=() performs a bitwise OR on *this. Missing bits are shifted in
		//!   at the most significant bit positions, so the result is as large as the
		//!   larger of the operands.
		//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
		//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
		//!   the integer should be converted to a 2's compliment representation before performing
		//!   the operation.
		//! \since Crypto++ 6.0
		Integer& operator|=(const Integer& t);
		//! \brief Bitwise XOR Assignment
		//! \param t the other Integer
		//! \returns the result of *this ^ t
		//! \details operator^=() performs a bitwise XOR on *this. Missing bits are shifted
		//!   in at the most significant bit positions, so the result is as large as the
		//!   larger of the operands.
		//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
		//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
		//!   the integer should be converted to a 2's compliment representation before performing
		//!   the operation.
		//! \since Crypto++ 6.0
		Integer& operator^=(const Integer& t);

		//! \brief Set this Integer to random integer
		//! \param rng RandomNumberGenerator used to generate material
		//! \param bitCount the number of bits in the resulting integer
		//! \details The random integer created is uniformly distributed over <tt>[0, 2<sup>bitCount</sup>]</tt>.
		void Randomize(RandomNumberGenerator &rng, size_t bitCount);

		//! \brief Set this Integer to random integer
		//! \param rng RandomNumberGenerator used to generate material
		//! \param min the minimum value
		//! \param max the maximum value
		//! \details The random integer created is uniformly distributed over <tt>[min, max]</tt>.
		void Randomize(RandomNumberGenerator &rng, const Integer &min, const Integer &max);

		//! \brief Set this Integer to random integer of special form
		//! \param rng RandomNumberGenerator used to generate material
		//! \param min the minimum value
		//! \param max the maximum value
		//! \param rnType RandomNumberType to specify the type
		//! \param equiv the equivalence class based on the parameter \p mod
		//! \param mod the modulus used to reduce the equivalence class
		//! \throw RandomNumberNotFound if the set is empty.
		//! \details Ideally, the random integer created should be uniformly distributed
		//!   over <tt>{x | min \<= x \<= max</tt> and \p x is of rnType and <tt>x \% mod == equiv}</tt>.
		//!   However the actual distribution may not be uniform because sequential
		//!   search is used to find an appropriate number from a random starting
		//!   point.
		//! \details May return (with very small probability) a pseudoprime when a prime
		//!   is requested and <tt>max \> lastSmallPrime*lastSmallPrime</tt>. \p lastSmallPrime
		//!   is declared in nbtheory.h.
		bool Randomize(RandomNumberGenerator &rng, const Integer &min, const Integer &max, RandomNumberType rnType, const Integer &equiv=Zero(), const Integer &mod=One());

		bool GenerateRandomNoThrow(RandomNumberGenerator &rng, const NameValuePairs &params = g_nullNameValuePairs);
		void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params = g_nullNameValuePairs)
		{
			if (!GenerateRandomNoThrow(rng, params))
				throw RandomNumberNotFound();
		}

		//! \brief Set the n-th bit to value
		//! \details 0-based numbering.
		void SetBit(size_t n, bool value=1);

		//! \brief Set the n-th byte to value
		//! \details 0-based numbering.
		void SetByte(size_t n, ::byte value);

		//! \brief Reverse the Sign of the Integer
		void Negate();

		//! \brief Sets the Integer to positive
		void SetPositive() {sign = POSITIVE;}

		//! \brief Sets the Integer to negative
		void SetNegative() {if (!!(*this)) sign = NEGATIVE;}

		//! \brief Swaps this Integer with another Integer
		void swap(Integer &a);
	//@}

	//! \name UNARY OPERATORS
	//@{
		//! \brief Negation
		bool		operator!() const;
		//! \brief Addition
		Integer 	operator+() const {return *this;}
		//! \brief Subtraction
		Integer 	operator-() const;
		//! \brief Pre-increment
		Integer&	operator++();
		//! \brief Pre-decrement
		Integer&	operator--();
		//! \brief Post-increment
		Integer 	operator++(int) {Integer temp = *this; ++*this; return temp;}
		//! \brief Post-decrement
		Integer 	operator--(int) {Integer temp = *this; --*this; return temp;}
	//@}

	//! \name BINARY OPERATORS
	//@{
		//! \brief Perform signed comparison
		//! \param a the Integer to comapre
		//!   \retval -1 if <tt>*this < a</tt>
		//!   \retval  0 if <tt>*this = a</tt>
		//!   \retval  1 if <tt>*this > a</tt>
		int Compare(const Integer& a) const;

		//! \brief Addition
		Integer Plus(const Integer &b) const;
		//! \brief Subtraction
		Integer Minus(const Integer &b) const;
		//! \brief Multiplication
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		Integer Times(const Integer &b) const;
		//! \brief Division
		Integer DividedBy(const Integer &b) const;
		//! \brief Remainder
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		Integer Modulo(const Integer &b) const;
		//! \brief Division
		Integer DividedBy(word b) const;
		//! \brief Remainder
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		word Modulo(word b) const;

		//! \brief Bitwise AND
		//! \param t the other Integer
		//! \returns the result of <tt>*this & t</tt>
		//! \details And() performs a bitwise AND on the operands. Missing bits are truncated
		//!   at the most significant bit positions, so the result is as small as the
		//!   smaller of the operands.
		//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
		//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
		//!   the integer should be converted to a 2's compliment representation before performing
		//!   the operation.
		//! \since Crypto++ 6.0
		Integer And(const Integer&) const;

		//! \brief Bitwise OR
		//! \param t the other Integer
		//! \returns the result of <tt>*this | t</tt>
		//! \details Or() performs a bitwise OR on the operands. Missing bits are shifted in
		//!   at the most significant bit positions, so the result is as large as the
		//!   larger of the operands.
		//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
		//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
		//!   the integer should be converted to a 2's compliment representation before performing
		//!   the operation.
		//! \since Crypto++ 6.0
		Integer Or(const Integer&) const;

		//! \brief Bitwise XOR
		//! \param t the other Integer
		//! \returns the result of <tt>*this ^ t</tt>
		//! \details Xor() performs a bitwise XOR on the operands. Missing bits are shifted in
		//!   at the most significant bit positions, so the result is as large as the
		//!   larger of the operands.
		//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
		//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
		//!   the integer should be converted to a 2's compliment representation before performing
		//!   the operation.
		//! \since Crypto++ 6.0
		Integer Xor(const Integer&) const;

		//! \brief Right-shift
		Integer operator>>(size_t n) const	{return Integer(*this)>>=n;}
		//! \brief Left-shift
		Integer operator<<(size_t n) const	{return Integer(*this)<<=n;}
	//@}

	//! \name OTHER ARITHMETIC FUNCTIONS
	//@{
		//! \brief Retrieve the absolute value of this integer
		Integer AbsoluteValue() const;
		//! \brief Add this integer to itself
		Integer Doubled() const {return Plus(*this);}
		//! \brief Multiply this integer by itself
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		Integer Squared() const {return Times(*this);}
		//! \brief Extract square root
		//! \details if negative return 0, else return floor of square root
		Integer SquareRoot() const;
		//! \brief Determine whether this integer is a perfect square
		bool IsSquare() const;

		//! is 1 or -1
		bool IsUnit() const;
		//! return inverse if 1 or -1, otherwise return 0
		Integer MultiplicativeInverse() const;

		//! \brief calculate r and q such that (a == d*q + r) && (0 <= r < abs(d))
		static void CRYPTOPP_API Divide(Integer &r, Integer &q, const Integer &a, const Integer &d);
		//! \brief use a faster division algorithm when divisor is short
		static void CRYPTOPP_API Divide(word &r, Integer &q, const Integer &a, word d);

		//! \brief returns same result as Divide(r, q, a, Power2(n)), but faster
		static void CRYPTOPP_API DivideByPowerOf2(Integer &r, Integer &q, const Integer &a, unsigned int n);

		//! greatest common divisor
		static Integer CRYPTOPP_API Gcd(const Integer &a, const Integer &n);
		//! \brief calculate multiplicative inverse of *this mod n
		Integer InverseMod(const Integer &n) const;
		//!
		//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
		word InverseMod(word n) const;
	//@}

	//! \name INPUT/OUTPUT
	//@{
		//! \brief Extraction operator
		//! \param in a reference to a std::istream
		//! \param a a reference to an Integer
		//! \returns a reference to a std::istream reference
		friend CRYPTOPP_DLL std::istream& CRYPTOPP_API operator>>(std::istream& in, Integer &a);
		//!
		//! \brief Insertion operator
		//! \param out a reference to a std::ostream
		//! \param a a constant reference to an Integer
		//! \returns a reference to a std::ostream reference
		//! \details The output integer responds to std::hex, std::oct, std::hex, std::upper and
		//!   std::lower. The output includes the suffix \a \b h (for hex), \a \b . (\a \b dot, for dec)
		//!   and \a \b o (for octal). There is currently no way to suppress the suffix.
		//! \details If you want to print an Integer without the suffix or using an arbitrary base, then
		//!   use IntToString<Integer>().
		//! \sa IntToString<Integer>
		friend CRYPTOPP_DLL std::ostream& CRYPTOPP_API operator<<(std::ostream& out, const Integer &a);
	//@}

#ifndef CRYPTOPP_DOXYGEN_PROCESSING
	//! modular multiplication
	CRYPTOPP_DLL friend Integer CRYPTOPP_API a_times_b_mod_c(const Integer &x, const Integer& y, const Integer& m);
	//! modular exponentiation
	CRYPTOPP_DLL friend Integer CRYPTOPP_API a_exp_b_mod_c(const Integer &x, const Integer& e, const Integer& m);
#endif

private:

	Integer(word value, size_t length);
	int PositiveCompare(const Integer &t) const;

	IntegerSecBlock reg;
	Sign sign;

#ifndef CRYPTOPP_DOXYGEN_PROCESSING
	friend class ModularArithmetic;
	friend class MontgomeryRepresentation;
	friend class HalfMontgomeryRepresentation;

	friend void PositiveAdd(Integer &sum, const Integer &a, const Integer &b);
	friend void PositiveSubtract(Integer &diff, const Integer &a, const Integer &b);
	friend void PositiveMultiply(Integer &product, const Integer &a, const Integer &b);
	friend void PositiveDivide(Integer &remainder, Integer &quotient, const Integer &dividend, const Integer &divisor);
#endif
};

//! \brief Comparison
inline bool operator==(const CryptoPP::Integer& a, const CryptoPP::Integer& b) {return a.Compare(b)==0;}
//! \brief Comparison
inline bool operator!=(const CryptoPP::Integer& a, const CryptoPP::Integer& b) {return a.Compare(b)!=0;}
//! \brief Comparison
inline bool operator> (const CryptoPP::Integer& a, const CryptoPP::Integer& b) {return a.Compare(b)> 0;}
//! \brief Comparison
inline bool operator>=(const CryptoPP::Integer& a, const CryptoPP::Integer& b) {return a.Compare(b)>=0;}
//! \brief Comparison
inline bool operator< (const CryptoPP::Integer& a, const CryptoPP::Integer& b) {return a.Compare(b)< 0;}
//! \brief Comparison
inline bool operator<=(const CryptoPP::Integer& a, const CryptoPP::Integer& b) {return a.Compare(b)<=0;}
//! \brief Addition
inline CryptoPP::Integer operator+(const CryptoPP::Integer &a, const CryptoPP::Integer &b) {return a.Plus(b);}
//! \brief Subtraction
inline CryptoPP::Integer operator-(const CryptoPP::Integer &a, const CryptoPP::Integer &b) {return a.Minus(b);}
//! \brief Multiplication
//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
inline CryptoPP::Integer operator*(const CryptoPP::Integer &a, const CryptoPP::Integer &b) {return a.Times(b);}
//! \brief Division
inline CryptoPP::Integer operator/(const CryptoPP::Integer &a, const CryptoPP::Integer &b) {return a.DividedBy(b);}
//! \brief Remainder
//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
inline CryptoPP::Integer operator%(const CryptoPP::Integer &a, const CryptoPP::Integer &b) {return a.Modulo(b);}
//! \brief Division
inline CryptoPP::Integer operator/(const CryptoPP::Integer &a, CryptoPP::word b) {return a.DividedBy(b);}
//! \brief Remainder
//! \sa a_times_b_mod_c() and a_exp_b_mod_c()
inline CryptoPP::word    operator%(const CryptoPP::Integer &a, CryptoPP::word b) {return a.Modulo(b);}

//! \brief Bitwise AND
//! \param a the first Integer
//! \param b the second Integer
//! \returns the result of a & b
//! \details operator&() performs a bitwise AND on the operands. Missing bits are truncated
//!   at the most significant bit positions, so the result is as small as the
//!   smaller of the operands.
//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
//!   the integer should be converted to a 2's compliment representation before performing
//!   the operation.
//! \since Crypto++ 6.0
inline CryptoPP::Integer operator&(const CryptoPP::Integer &a, const CryptoPP::Integer &b) {return a.And(b);}

//! \brief Bitwise OR
//! \param a the first Integer
//! \param b the second Integer
//! \returns the result of a | b
//! \details operator|() performs a bitwise OR on the operands. Missing bits are shifted in
//!   at the most significant bit positions, so the result is as large as the
//!   larger of the operands.
//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
//!   the integer should be converted to a 2's compliment representation before performing
//!   the operation.
//! \since Crypto++ 6.0
inline CryptoPP::Integer operator|(const CryptoPP::Integer &a, const CryptoPP::Integer &b) {return a.Or(b);}

//! \brief Bitwise XOR
//! \param a the first Integer
//! \param b the second Integer
//! \returns the result of a ^ b
//! \details operator^() performs a bitwise XOR on the operands. Missing bits are shifted
//!   in at the most significant bit positions, so the result is as large as the
//!   larger of the operands.
//! \details Internally, Crypto++ uses a sign-magnitude representation. The library
//!   does not attempt to interpret bits, and the result is always POSITIVE. If needed,
//!   the integer should be converted to a 2's compliment representation before performing
//!   the operation.
//! \since Crypto++ 6.0
inline CryptoPP::Integer operator^(const CryptoPP::Integer &a, const CryptoPP::Integer &b) {return a.Xor(b);}

NAMESPACE_END

#ifndef __BORLANDC__
NAMESPACE_BEGIN(std)
inline void swap(CryptoPP::Integer &a, CryptoPP::Integer &b)
{
	a.swap(b);
}
NAMESPACE_END
#endif

#endif
