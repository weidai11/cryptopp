// misc.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "config.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4189)
# if (CRYPTOPP_MSC_VERSION >= 1400)
#  pragma warning(disable: 6237)
# endif
#endif

#ifndef CRYPTOPP_IMPORTS

#include "misc.h"
#include "trap.h"
#include "words.h"
#include "stdcpp.h"
#include "integer.h"
#include "secblock.h"

// Hack for OpenBSD and GCC 4.2.1. I believe they are stuck at 4.2.1 due to GPLv3.
#if defined(__OpenBSD__)
# if defined (CRYPTOPP_GCC_VERSION) && (CRYPTOPP_GCC_VERSION < 43000)
#  undef  CRYPTOPP_DISABLE_ASM
#  define CRYPTOPP_DISABLE_ASM 1
# endif
#endif

#ifndef CRYPTOPP_DISABLE_ASM
# if defined(__SSE2__)
#  include <emmintrin.h>
# endif
# if defined(__AVX__)
#  include <immintrin.h>
# endif

# if defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
#  if (CRYPTOPP_ARM_NEON_HEADER) || (CRYPTOPP_ARM_ASIMD_AVAILABLE)
#   include <arm_neon.h>
#  endif
# endif
#endif  // CRYPTOPP_DISABLE_ASM

NAMESPACE_BEGIN(CryptoPP)

byte* BytePtr(SecByteBlock& str)
{
	// Caller wants a writeable pointer
	CRYPTOPP_ASSERT(str.empty() == false);

	if (str.empty())
		return NULLPTR;
	return reinterpret_cast<byte*>(str.data());
}

const byte* ConstBytePtr(const SecByteBlock& str)
{
	if (str.empty())
		return NULLPTR;
	return reinterpret_cast<const byte*>(str.data());
}

size_t BytePtrSize(const SecByteBlock& str)
{
	return str.size();
}

// xorbuf simplified at https://github.com/weidai11/cryptopp/issues/1020
void xorbuf(byte *buf, const byte *mask, size_t count)
{
	CRYPTOPP_ASSERT(buf != NULLPTR);
	CRYPTOPP_ASSERT(mask != NULLPTR);
	CRYPTOPP_ASSERT(count > 0);

#ifndef CRYPTOPP_DISABLE_ASM
# if defined(__AVX__)
	while (count >= 32)
	{
		__m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buf));
		__m256i m = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(mask));
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(buf), _mm256_castps_si256(
			_mm256_xor_ps(_mm256_castsi256_ps(b), _mm256_castsi256_ps(m))));
		buf += 32; mask += 32; count -= 32;
	}
	// https://software.intel.com/en-us/articles/avoiding-avx-sse-transition-penalties
	_mm256_zeroupper();
# endif
# if defined(__SSE2__)
	while (count >= 16)
	{
		__m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf));
		__m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(mask));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(buf), _mm_castps_si128(
			_mm_xor_ps(_mm_castsi128_ps(b), _mm_castsi128_ps(m))));
		buf += 16; mask += 16; count -= 16;
	}
# endif
# if defined(__aarch64__) || defined(__aarch32__) || defined(_M_ARM64)
	while (count >= 16)
	{
		vst1q_u8(buf, veorq_u8(vld1q_u8(buf), vld1q_u8(mask)));
		buf += 16; mask += 16; count -= 16;
	}
# endif
#endif  // CRYPTOPP_DISABLE_ASM

#if CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64
	// word64 and stride of 8 slows things down on x86_64.
	// word64 and stride of 8 makes no difference on ARM.
	// word64 and stride of 16 benefits PowerPC.
	while (count >= 16)
	{
		word64 r[2], b[2], m[2];
		std::memcpy(&b, buf, 16); std::memcpy(&m, mask, 16);

		r[0] = b[0] ^ m[0];
		r[1] = b[1] ^ m[1];
		std::memcpy(buf, &r, 16);

		buf += 16; mask += 16; count -= 16;
	}
#endif

	// One of the arch specific xor's may have cleared the request
	if (count == 0) return;

	while (count >= 4)
	{
		word32 r, b, m;
		std::memcpy(&b, buf, 4); std::memcpy(&m, mask, 4);

		r = b ^ m;
		std::memcpy(buf, &r, 4);

		buf += 4; mask += 4; count -= 4;
	}

	for (size_t i=0; i<count; i++)
		buf[i] ^= mask[i];
}

// xorbuf simplified at https://github.com/weidai11/cryptopp/issues/1020
void xorbuf(byte *output, const byte *input, const byte *mask, size_t count)
{
	CRYPTOPP_ASSERT(output != NULLPTR);
	CRYPTOPP_ASSERT(input != NULLPTR);
	CRYPTOPP_ASSERT(count > 0);

#ifndef CRYPTOPP_DISABLE_ASM
# if defined(__AVX__)
	while (count >= 32)
	{
		__m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input));
		__m256i m = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(mask));
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(output), _mm256_castps_si256(
			_mm256_xor_ps(_mm256_castsi256_ps(b), _mm256_castsi256_ps(m))));
		output += 32; input += 32; mask += 32; count -= 32;
	}
	// https://software.intel.com/en-us/articles/avoiding-avx-sse-transition-penalties
	_mm256_zeroupper();
# endif
# if defined(__SSE2__)
	while (count >= 16)
	{
		__m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input));
		__m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(mask));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(output), _mm_castps_si128(
			_mm_xor_ps(_mm_castsi128_ps(b), _mm_castsi128_ps(m))));
		output += 16; input += 16; mask += 16; count -= 16;
	}
# endif
# if defined(__aarch64__) || defined(__aarch32__) || defined(_M_ARM64)
	while (count >= 16)
	{
		vst1q_u8(output, veorq_u8(vld1q_u8(input), vld1q_u8(mask)));
		output += 16; input += 16; mask += 16; count -= 16;
	}
# endif
#endif  // CRYPTOPP_DISABLE_ASM

#if CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64
	// word64 and stride of 8 slows things down on x86_64.
	// word64 and stride of 8 makes no difference on ARM.
	// word64 and stride of 16 benefits PowerPC.
	while (count >= 16)
	{
		word64 b[2], m[2], r[2];
		std::memcpy(&b, input, 16); std::memcpy(&m, mask, 16);

		r[0] = b[0] ^ m[0];
		r[1] = b[1] ^ m[1];
		std::memcpy(output, &r, 16);

		output += 16; input += 16; mask += 16; count -= 16;
	}
#endif

	// One of the arch specific xor's may have cleared the request
	if (count == 0) return;

	while (count >= 4)
	{
		word32 b, m, r;
		std::memcpy(&b, input, 4); std::memcpy(&m, mask, 4);

		r = b ^ m;
		std::memcpy(output, &r, 4);

		output += 4; input += 4; mask += 4; count -= 4;
	}

	for (size_t i=0; i<count; i++)
		output[i] = input[i] ^ mask[i];
}

// VerifyBufsEqual simplified at https://github.com/weidai11/cryptopp/issues/1020
bool VerifyBufsEqual(const byte *buf, const byte *mask, size_t count)
{
	CRYPTOPP_ASSERT(buf != NULLPTR);
	CRYPTOPP_ASSERT(mask != NULLPTR);
	// CRYPTOPP_ASSERT(count > 0);

#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_ARM64 || CRYPTOPP_BOOL_PPC64 || CRYPTOPP_BOOL_MIPS64 || CRYPTOPP_BOOL_SPARC64
	word64 acc64 = 0;
	while (count >= 8)
	{
		word64 b, m;
		std::memcpy(&b, buf, 8); std::memcpy(&m, mask, 8);
		acc64 |= b ^ m;

		buf += 8; mask += 8; count -= 8;
	}

	word32 acc8 = (acc64 >> 32) | (acc64 & 0xffffffff);
	acc8 = static_cast<byte>(acc8) | static_cast<byte>(acc8 >> 8) |
		static_cast<byte>(acc8 >> 16) | static_cast<byte>(acc8 >> 24);
#else
	word32 acc32 = 0;
	while (count >= 4)
	{
		word32 b, m;
		std::memcpy(&b, buf, 4); std::memcpy(&m, mask, 4);
		acc32 |= b ^ m;

		buf += 4; mask += 4; count -= 4;
	}

	word32 acc8 = acc32;
	acc8 = static_cast<byte>(acc8) | static_cast<byte>(acc8 >> 8) |
		static_cast<byte>(acc8 >> 16) | static_cast<byte>(acc8 >> 24);
#endif

	for (size_t i=0; i<count; i++)
		acc8 |= buf[i] ^ mask[i];

	// word32 results in this tail code on x86:
	//   33a:  85 c0     test  %eax, %eax
	//   33c:  0f 94 c0  sete  %al
	//   33f:  c3        ret
	return acc8 == 0;
}

std::string StringNarrow(const wchar_t *str, bool throwOnError)
{
	CRYPTOPP_ASSERT(str);
	std::string result;

	// Safer functions on Windows for C&A, https://github.com/weidai11/cryptopp/issues/55
#if (CRYPTOPP_MSC_VERSION >= 1400)
	size_t len=0, size=0;
	errno_t err = 0;

	//const wchar_t* ptr = str;
	//while (*ptr++) len++;
	len = wcslen(str)+1;

	err = wcstombs_s(&size, NULLPTR, 0, str, len*sizeof(wchar_t));
	CRYPTOPP_ASSERT(err == 0);
	if (err != 0)
	{
		if (throwOnError)
			throw InvalidArgument("StringNarrow: wcstombs_s() failed with error " + IntToString(err));
		else
			return std::string();
	}

	result.resize(size);
	err = wcstombs_s(&size, &result[0], size, str, len*sizeof(wchar_t));
	CRYPTOPP_ASSERT(err == 0);
	if (err != 0)
	{
		if (throwOnError)
			throw InvalidArgument("StringNarrow: wcstombs_s() failed with error " + IntToString(err));
		else
			return std::string();
	}

	// The safe routine's size includes the NULL.
	if (!result.empty() && result[size - 1] == '\0')
		result.erase(size - 1);
#else
	size_t size = wcstombs(NULLPTR, str, 0);
	CRYPTOPP_ASSERT(size != (size_t)-1);
	if (size == (size_t)-1)
	{
		if (throwOnError)
			throw InvalidArgument("StringNarrow: wcstombs() failed");
		else
			return std::string();
	}

	result.resize(size);
	size = wcstombs(&result[0], str, size);
	CRYPTOPP_ASSERT(size != (size_t)-1);
	if (size == (size_t)-1)
	{
		if (throwOnError)
			throw InvalidArgument("StringNarrow: wcstombs() failed");
		else
			return std::string();
	}
#endif

	return result;
}

std::wstring StringWiden(const char *str, bool throwOnError)
{
	CRYPTOPP_ASSERT(str);
	std::wstring result;

	// Safer functions on Windows for C&A, https://github.com/weidai11/cryptopp/issues/55
#if (CRYPTOPP_MSC_VERSION >= 1400)
	size_t len=0, size=0;
	errno_t err = 0;

	//const char* ptr = str;
	//while (*ptr++) len++;
	len = std::strlen(str)+1;

	err = mbstowcs_s(&size, NULLPTR, 0, str, len);
	CRYPTOPP_ASSERT(err == 0);
	if (err != 0)
	{
		if (throwOnError)
			throw InvalidArgument("StringWiden: wcstombs_s() failed with error " + IntToString(err));
		else
			return std::wstring();
	}

	result.resize(size);
	err = mbstowcs_s(&size, &result[0], size, str, len);
	CRYPTOPP_ASSERT(err == 0);
	if (err != 0)
	{
		if (throwOnError)
			throw InvalidArgument("StringWiden: wcstombs_s() failed with error " + IntToString(err));
		else
			return std::wstring();
	}

	// The safe routine's size includes the NULL.
	if (!result.empty() && result[size - 1] == '\0')
		result.erase(size - 1);
#else
	size_t size = mbstowcs(NULLPTR, str, 0);
	CRYPTOPP_ASSERT(size != (size_t)-1);
	if (size == (size_t)-1)
	{
		if (throwOnError)
			throw InvalidArgument("StringWiden: mbstowcs() failed");
		else
			return std::wstring();
	}

	result.resize(size);
	size = mbstowcs(&result[0], str, size);
	CRYPTOPP_ASSERT(size != (size_t)-1);
	if (size == (size_t)-1)
	{
		if (throwOnError)
			throw InvalidArgument("StringWiden: mbstowcs() failed");
		else
			return std::wstring();
	}
#endif

	return result;
}

NAMESPACE_END

#endif
