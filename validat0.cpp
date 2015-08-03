// validat0.cpp - written and placed in the public domain by Wei Dai and Jeffrey Walton

#include "pch.h"

#include "config.h"
#include "stdcpp.h"
#include "misc.h"
#include "integer.h"

#include "validate.h"

#include <iostream>

USING_NAMESPACE(CryptoPP)

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic ignored "-Wunused-value"
#endif

bool TestSettings()
{
	bool pass = true;

	std::cout << "\nTesting Settings...\n\n";

	word32 w;
	memcpy_s(&w, sizeof(w), "\x01\x02\x03\x04", 4);

	if (w == 0x04030201L)
	{
#ifdef IS_LITTLE_ENDIAN
		std::cout << "passed:  ";
#else
		std::cout << "FAILED:  ";
		pass = false;
#endif
		std::cout << "Your machine is little endian.\n";
	}
	else if (w == 0x01020304L)
	{
#ifndef IS_LITTLE_ENDIAN
		std::cout << "passed:  ";
#else
		std::cout << "FAILED:  ";
		pass = false;
#endif
		std::cout << "Your machine is big endian.\n";
	}
	else
	{
		std::cout << "FAILED:  Your machine is neither big endian nor little endian.\n";
		pass = false;
	}

#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	byte testvals[10] = {1,2,2,3,3,3,3,2,2,1};
	if (*(word32 *)(testvals+3) == 0x03030303 && *(word64 *)(testvals+1) == W64LIT(0x0202030303030202))
		std::cout << "passed:  Your machine allows unaligned data access.\n";
	else
	{
		std::cout << "FAILED:  Unaligned data access gave incorrect results.\n";
		pass = false;
	}
#else
	std::cout << "passed:  CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS is not defined. Will restrict to aligned data access.\n";
#endif

	if (sizeof(byte) == 1)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(byte) == " << sizeof(byte) << std::endl;

	if (sizeof(word16) == 2)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(word16) == " << sizeof(word16) << std::endl;

	if (sizeof(word32) == 4)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(word32) == " << sizeof(word32) << std::endl;
	
	if (sizeof(word64) == 8)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(word64) == " << sizeof(word64) << std::endl;
	
#ifdef CRYPTOPP_WORD128_AVAILABLE
	if (sizeof(word128) == 16)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(word128) == " << sizeof(word128) << std::endl;
#endif
	
	if (sizeof(word) == 2*sizeof(hword)
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
		&& sizeof(dword) == 2*sizeof(word)
#endif
		)
		std::cout << "passed:  ";
	else
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	std::cout << "sizeof(hword) == " << sizeof(hword) << ", sizeof(word) == " << sizeof(word);
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
	std::cout << ", sizeof(dword) == " << sizeof(dword);
#endif
	std::cout << std::endl;

#ifdef CRYPTOPP_CPUID_AVAILABLE
	bool hasMMX = HasMMX();
	bool hasISSE = HasSSE();
	bool hasSSE2 = HasSSE2();
	bool hasSSSE3 = HasSSSE3();
	bool isP4 = IsP4();
	int cacheLineSize = GetCacheLineSize();

	if ((isP4 && (!hasMMX || !hasSSE2)) || (hasSSE2 && !hasMMX) || (cacheLineSize < 16 || cacheLineSize > 256 || !IsPowerOf2(cacheLineSize)))
	{
		std::cout << "FAILED:  ";
		pass = false;
	}
	else
		std::cout << "passed:  ";

	std::cout << "hasMMX == " << hasMMX << ", hasISSE == " << hasISSE << ", hasSSE2 == " << hasSSE2 << ", hasSSSE3 == " << hasSSSE3 << ", hasAESNI == " << HasAESNI() << ", hasCLMUL == " << HasCLMUL() << ", isP4 == " << isP4 << ", cacheLineSize == " << cacheLineSize;
	std::cout << ", AESNI_INTRINSICS == " << CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE << std::endl;
#endif

	if (!pass)
	{
		std::cout << "Some critical setting in config.h is in error.  Please fix it and recompile." << std::endl;
		abort();
	}
	return pass;
}

bool TestRotate()
{
	bool pass = true;

	std::cout << "\nTesting rotate...\n\n";
	std::cout << (!pass ? "FAILED" : "passed") << "   left rotate" << std::endl;
	std::cout << (!pass ? "FAILED" : "passed") << "   right rotate" << std::endl;

	return pass;
}

bool TestConversion()
{
	bool pass = true;

	std::cout << "\nTesting conversions...\n\n";

	/********** signed char **********/
	{
		signed char v1, v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<signed char>::min();	  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<signed char>::min() + 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<signed char>::max();	  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<signed char>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   signed char" << std::endl;
		pass &= p;
	}

	/********** signed char overflow **********/
	{
		signed char v; bool p = true;
		{
			signed short v1 = std::numeric_limits<signed short>::min();     p = !SafeConvert(v1, v) && p;
			signed short v2 = std::numeric_limits<signed short>::max();     p = !SafeConvert(v2, v) && p;
			unsigned short v3 = std::numeric_limits<unsigned short>::max(); p = !SafeConvert(v3, v) && p;
		}
		{
			signed int v1 = std::numeric_limits<signed int>::min();     p = !SafeConvert(v1, v) && p;
			signed int v2 = std::numeric_limits<signed int>::max();     p = !SafeConvert(v2, v) && p;
			unsigned int v3 = std::numeric_limits<unsigned int>::max(); p = !SafeConvert(v3, v) && p;
		}
		
		{
			signed long v1 = std::numeric_limits<signed long>::min();     p = !SafeConvert(v1, v) && p;
			signed long v2 = std::numeric_limits<signed long>::max();     p = !SafeConvert(v2, v) && p;
			unsigned long v3 = std::numeric_limits<unsigned long>::max(); p = !SafeConvert(v3, v) && p;
		}
		{
			signed long long v1 = std::numeric_limits<signed long long>::min();     p = !SafeConvert(v1, v) && p;
			signed long long v2 = std::numeric_limits<signed long long>::max();     p = !SafeConvert(v2, v) && p;
			unsigned long long v3 = std::numeric_limits<unsigned long long>::max(); p = !SafeConvert(v3, v) && p;
		}
		
		std::cout << (!p ? "FAILED" : "passed") << "   signed char overflow" << std::endl;
		pass &= p;
	}
	
	/********** unsigned char **********/
	{
		unsigned char v1, v2; bool p = true;
		v1 = 0; p = SafeConvert(v1, v2) && p;
		v1 = 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned char>::max();	    p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned char>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   unsigned char" << std::endl;
		pass &= p;
	}
	
	/********** unsigned char overflow **********/
	{
		unsigned char v; bool p = true;
		{
			unsigned short v1 = std::numeric_limits<unsigned short>::max(); p = !SafeConvert(v1, v) && p;
		}
		{
			unsigned int v1 = std::numeric_limits<unsigned int>::max(); p = !SafeConvert(v1, v) && p;
		}
		{
			unsigned long v1 = std::numeric_limits<unsigned long>::max(); p = !SafeConvert(v1, v) && p;
		}
		{
			unsigned long long v1 = std::numeric_limits<unsigned long long>::max(); p = !SafeConvert(v1, v) && p;
		}
		
		std::cout << (!p ? "FAILED" : "passed") << "   unsigned char overflow" << std::endl;
		pass &= p;
	}

	/********** signed short **********/
	{
		signed short v1, v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<short>::min();	    p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<short>::min() + 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<short>::max();	    p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<short>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   signed short" << std::endl;
		pass &= p;
	}

	/********** signed short overflow **********/
	{
		signed short v; bool p = true;
		{
			signed int v1 = std::numeric_limits<signed int>::min();     p = !SafeConvert(v1, v) && p;
			signed int v2 = std::numeric_limits<signed int>::max();     p = !SafeConvert(v2, v) && p;
			unsigned int v3 = std::numeric_limits<unsigned int>::max(); p = !SafeConvert(v3, v) && p;
		}
		{
			signed long v1 = std::numeric_limits<signed long>::min();     p = !SafeConvert(v1, v) && p;
			signed long v2 = std::numeric_limits<signed long>::max();     p = !SafeConvert(v2, v) && p;
			unsigned long v3 = std::numeric_limits<unsigned long>::max(); p = !SafeConvert(v3, v) && p;
		}
		{
			signed long long v1 = std::numeric_limits<signed long long>::min();     p = !SafeConvert(v1, v) && p;
			signed long long v2 = std::numeric_limits<signed long long>::max();     p = !SafeConvert(v2, v) && p;
			unsigned long long v3 = std::numeric_limits<unsigned long long>::max(); p = !SafeConvert(v3, v) && p;
		}
		
		std::cout << (!p ? "FAILED" : "passed") << "   signed short overflow" << std::endl;
		pass &= p;
	}

	/********** unsigned short **********/
	{
		unsigned short v1, v2; bool p = true;
		v1 = 0; p = SafeConvert(v1, v2) && p;
		v1 = 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned short>::max();	 p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned short>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   unsigned short" << std::endl;
		pass &= p;
	}

	/********** unsigned short overflow **********/
	{
		unsigned short v; bool p = true;
		{
			unsigned int v1 = std::numeric_limits<unsigned int>::max(); p = !SafeConvert(v1, v) && p;
		}
		{
			unsigned long v1 = std::numeric_limits<unsigned long>::max(); p = !SafeConvert(v1, v) && p;
		}
		{
			unsigned long long v1 = std::numeric_limits<unsigned long long>::max(); p = !SafeConvert(v1, v) && p;
		}
		
		std::cout << (!p ? "FAILED" : "passed") << "   unsigned short overflow" << std::endl;
		pass &= p;
	}

	/********** signed int **********/
	{
		signed int v1, v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<int>::min();	  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<int>::min() + 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<int>::max();	  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<int>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   signed int" << std::endl;
		pass &= p;
	}

	/********** signed int overflow **********/
	{
		signed int v; bool p = true;
		{
			// Guard i686 collision of type sizes
			if (sizeof(signed int) != sizeof(signed long))
			{
				signed long v1 = std::numeric_limits<signed long>::min();     p = !SafeConvert(v1, v) && p;
				signed long v2 = std::numeric_limits<signed long>::max();     p = !SafeConvert(v2, v) && p;
				unsigned long v3 = std::numeric_limits<unsigned long>::max(); p = !SafeConvert(v3, v) && p;
			}
			// Guard i686 collision of type sizes
			if (sizeof(signed int) != sizeof(signed long long))
			{
				signed long long v1 = std::numeric_limits<signed long long>::min();     p = !SafeConvert(v1, v) && p;
				signed long long v2 = std::numeric_limits<signed long long>::max();     p = !SafeConvert(v2, v) && p;
				unsigned long long v3 = std::numeric_limits<unsigned long long>::max(); p = !SafeConvert(v3, v) && p;
			}

			std::cout << (!p ? "FAILED" : "passed") << "   signed int overflow" << std::endl;
			pass &= p;
		}
	}

	/********** unsigned int **********/
	{
		unsigned int v1, v2; bool p = true;
		v1 = 0; p = SafeConvert(v1, v2) && p;
		v1 = 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned int>::max();	   p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned int>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   unsigned int" << std::endl;
		pass &= p;
	}

	/********** unsigned int overflow **********/
	{
		unsigned int v; bool p = true;
		{
			// Guard i686 collision of type sizes
			if (sizeof(unsigned int) != sizeof(unsigned long))
			{
				unsigned long v1 = std::numeric_limits<unsigned long>::max(); p = !SafeConvert(v1, v) && p;
			}
			// Guard i686 collision of type sizes
			if (sizeof(unsigned int) != sizeof(unsigned long long))
			{
				unsigned long long v1 = std::numeric_limits<unsigned long long>::max(); p = !SafeConvert(v1, v) && p;
			}

			std::cout << (!p ? "FAILED" : "passed") << "   unsigned int overflow" << std::endl;
			pass &= p;
		}
	}

	/********** signed long **********/
	{
		signed long v1, v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<long>::min();	   p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<long>::min() + 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<long>::max();	   p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<long>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   signed long" << std::endl;
		pass &= p;
	}

	/********** signed long overflow **********/
	{
		// Guard x86_64 collision of type sizes
		if (sizeof(signed long) != sizeof(signed long long))
		{
			signed long v; bool p = true;
			{
				signed long long v1 = std::numeric_limits<signed long long>::min();     p = !SafeConvert(v1, v) && p;
				signed long long v2 = std::numeric_limits<signed long long>::max();     p = !SafeConvert(v2, v) && p;
				unsigned long long v3 = std::numeric_limits<unsigned long long>::max(); p = !SafeConvert(v3, v) && p;
			}
			
			std::cout << (!p ? "FAILED" : "passed") << "   signed long overflow" << std::endl;
			pass &= p;
		}
		else
		{
			std::cout << "passed   signed long overflow (skipped due to range of types)" << std::endl;
		}
	}

	/********** unsigned long **********/
	{
		unsigned long v1, v2; bool p = true;
		v1 = 0; p = SafeConvert(v1, v2) && p;
		v1 = 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned long>::max();	    p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned long>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   unsigned long" << std::endl;
		pass &= p;
	}

	/********** unsigned long overflow **********/
	{
		// Guard x86_64 collision of type sizes
		if (sizeof(unsigned long) != sizeof(unsigned long long))
		{
			unsigned long v; bool p = true;
			{
				unsigned long long v1 = std::numeric_limits<unsigned long long>::max(); p = !SafeConvert(v1, v) && p;
			}
			
			std::cout << (!p ? "FAILED" : "passed") << "   unsigned long overflow" << std::endl;
			pass &= p;
		}
		else
		{
			std::cout << "passed   unsigned long overflow (skipped due to range of types)" << std::endl;
		}
	}

	/********** signed long long **********/
	{
		signed long long v1, v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<long long>::min();	    p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<long long>::min() + 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<long long>::max();	    p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<long long>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   signed long long" << std::endl;
		pass &= p;
	}

	/********** unsigned long long **********/
	{
		unsigned long long v1, v2; bool p = true;
		v1 = 0; p = SafeConvert(v1, v2) && p;
		v1 = 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned long long>::max();	 p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<unsigned long long>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   unsigned long long" << std::endl;
		pass &= p;
	}

	/********** ssize_t **********/
	{
		ssize_t v1, v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<ssize_t>::min();	  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<ssize_t>::min() + 1;  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<ssize_t>::max();	  p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<ssize_t>::max() - 1;  p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   ssize_t" << std::endl;
		pass &= p;
	}

	/********** size_t **********/
	{
		size_t v1, v2; bool p = true;
		v1 = 0; p = SafeConvert(v1, v2) && p;
		v1 = 1; p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<size_t>::max();	 p = SafeConvert(v1, v2) && p;
		v1 = std::numeric_limits<size_t>::max() - 1; p = SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   size_t" << std::endl;
		pass &= p;
	}

#if 0
	{
		Integer v1; signed char v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<char>::min());	 p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<char>::min()) + 1; p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<char>::min()) - 1; p = !SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<char>::max());	 p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<char>::max()) - 1; p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<char>::max()) + 1; p = !SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to signed char" << std::endl;
		pass &= p;
	}

	{
		Integer v1; unsigned char v2; bool p = true;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<unsigned char>::max());	 p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<unsigned char>::max()) - 1; p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<unsigned char>::max()) + 1; p = !SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to unsigned char" << std::endl;
		pass &= p;
	}

	{
		Integer v1; signed short v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<short>::min());	 p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<short>::min()) + 1; p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<short>::min()) - 1; p = !SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<short>::max());	 p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<short>::max()) - 1; p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<short>::max()) + 1; p = !SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to signed short" << std::endl;
		pass &= p;
	}

	{
		Integer v1; unsigned short v2; bool p = true;
		v1 = 0;  p = SafeConvert(v1, v2) && p;
		v1 = 1;  p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<unsigned short>::max());	 p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<unsigned short>::max()) - 1; p = SafeConvert(v1, v2) && p;
		v1 = Integer((signed long)std::numeric_limits<unsigned short>::max()) + 1; p = !SafeConvert(v1, v2) && p;
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to unsigned short" << std::endl;
		pass &= p;
	}

	{
		Integer v1; signed int v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 0;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 1;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<int>::min());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		std::cout << "Limit: " << (int) std::numeric_limits<int>::min() << std::endl;
		std::cout << "Digits: " << (int) std::numeric_limits<int>::digits << std::endl;
		std::cout << "Value: " << v1 << std::endl;
		std::cout << "BitCount: " << v1.BitCount() << std::endl;
		
		v1 = Integer((signed long)std::numeric_limits<int>::min()) + 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<int>::min()) - 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<int>::max());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<int>::max()) - 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<int>::max()) + 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to signed int" << std::endl;
		pass &= p;
	}

	{
		Integer v1; unsigned int v2; bool p = true;
		v1 = 0;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 1;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<unsigned int>::max());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<unsigned int>::max()) - 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<unsigned int>::max()) + 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to unsigned int" << std::endl;
		pass &= p;
	}

	{
		Integer v1; signed long v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 0;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 1;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<signed long>::min());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<signed long>::min()) + 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<signed long>::min()) - 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<signed long>::max());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<signed long>::max()) - 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<signed long>::max()) + 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to signed long" << std::endl;
		pass &= p;
	}

	{
		Integer v1; unsigned long v2; bool p = true;
		v1 = 0;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 1;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<unsigned long>::max());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<unsigned long>::max()) - 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<unsigned long>::max()) + 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to signed long" << std::endl;
		pass &= p;
	}

	{
		Integer v1; ssize_t v2; bool p = true;
		v1 = -1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 0;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 1;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<ssize_t>::min());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<ssize_t>::min()) + 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<ssize_t>::min()) - 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<ssize_t>::max());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<ssize_t>::max()) - 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((signed long)std::numeric_limits<ssize_t>::max()) + 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to signed ssize_t" << std::endl;
		pass &= p;
	}

	{
		Integer v1; size_t v2; bool p = true;
		v1 = 0;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 1;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<size_t>::max());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<size_t>::max()) - 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<size_t>::max()) + 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to size_t" << std::endl;
		pass &= p;
	}

	{
		CRYPTOPP_COMPILE_ASSERT(sizeof(word64) >= sizeof(unsigned long long));
		Integer v1; unsigned long long v2; bool p = true;
		v1 = 0;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = 1;  p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<unsigned long long>::max());	 p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<unsigned long long>::max()) - 1; p = SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		v1 = Integer((word64)std::numeric_limits<unsigned long long>::max()) + 1; p = !SafeConvert(v1, v2) && p; CRYPTOPP_ASSERT(p);
		
		std::cout << (!p ? "FAILED" : "passed") << "   Integer to unsigned long long" << std::endl;
		pass &= p;
	}
#endif
	
	return pass;
}
