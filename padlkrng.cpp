// via-rng.cpp - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.

#include "pch.h"
#include "config.h"
#include "cryptlib.h"
#include "secblock.h"
#include "padlkrng.h"
#include "cpu.h"

// The Padlock Security Engine RNG has a few items to be aware of. You can
// find copies  of the Programmer's manual, Cryptography Research Inc audit
// report, and other goodies at http://www.cryptopp.com/wiki/VIA_Padlock.

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4702)
#endif

NAMESPACE_BEGIN(CryptoPP)

std::string PadlockRNG::AlgorithmProvider() const
{
    return "Padlock";
}

PadlockRNG::PadlockRNG(word32 divisor)
	: m_divisor(DivisorHelper(divisor)), m_msr(0)
{
#if defined(CRYPTOPP_X86_ASM_AVAILABLE)
	if (!HasPadlockRNG())
#endif
		throw PadlockRNG_Err("PadlockRNG", "PadlockRNG generator not available");
}

void PadlockRNG::GenerateBlock(byte *output, size_t size)
{
	CRYPTOPP_UNUSED(output); CRYPTOPP_UNUSED(size);
#if defined(CRYPTOPP_X86_ASM_AVAILABLE) && defined(__GNUC__)
	while (size)
	{
		__asm__ __volatile__
		(
#if (CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
			"mov  %1, %%rdi          ;\n"
			"movl %2, %%edx          ;\n"
#else
			"mov  %1, %%edi          ;\n"
			"movl %2, %%edx          ;\n"
#endif

			".byte 0x0f, 0xa7, 0xc0  ;\n"
			"movl %%eax, %0          ;\n"

			: "=g" (m_msr) : "g" (m_buffer.data()), "g" (m_divisor)
#if (CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
			: "rax", "rdx", "rdi", "cc"
#else
			: "eax", "edx", "edi", "cc"
#endif
		);

		const size_t ret = m_msr & 0x1f;
		const size_t rem = STDMIN<size_t>(ret, STDMIN<size_t>(size, 16U /*buffer size*/));
		std::memcpy(output, m_buffer, rem);
		size -= rem; output += rem;
	}
#elif defined(CRYPTOPP_X86_ASM_AVAILABLE) && defined(_MSC_VER) && defined(_M_IX86)
	while (size)
	{
		word32 result, divisor = m_divisor;
		byte *buffer = reinterpret_cast<byte*>(m_buffer.data());
		__asm {
			mov edi, buffer
			mov edx, divisor
			_emit 0x0f
			_emit 0xa7
			_emit 0xc0
			mov result, eax
		}

		const size_t ret = (m_msr = result) & 0x1f;
		const size_t rem = STDMIN<size_t>(ret, STDMIN<size_t>(size, 16U /*buffer size*/));
		std::memcpy(output, buffer, rem);
		size -= rem; output += rem;
	}
#else
	throw PadlockRNG_Err("GenerateBlock", "PadlockRNG generator not available");
#endif  // CRYPTOPP_X86_ASM_AVAILABLE
}

void PadlockRNG::DiscardBytes(size_t n)
{
	FixedSizeSecBlock<word32, 4> discard;
	n = RoundUpToMultipleOf(n, sizeof(word32));

	size_t count = STDMIN(n, discard.SizeInBytes());
	while (count)
	{
		GenerateBlock(discard.BytePtr(), count);
		n -= count;
		count = STDMIN(n, discard.SizeInBytes());
	}
}

NAMESPACE_END
