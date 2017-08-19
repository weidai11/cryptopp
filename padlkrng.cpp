// via-rng.cpp - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.

#include "pch.h"
#include "config.h"
#include "cryptlib.h"
#include "secblock.h"
#include "padlkrng.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

PadlockRNG::PadlockRNG()
{
#if CRYPTOPP_BOOL_X86
    if (!HasPadlockRNG())
		throw PadlockRNG_Err("HasPadlockRNG");
#else
	throw PadlockRNG_Err("HasPadlockRNG");
#endif
}

void PadlockRNG::GenerateBlock(byte *output, size_t size)
{
	CRYPTOPP_UNUSED(output); CRYPTOPP_UNUSED(size);
#if CRYPTOPP_BOOL_X86
	while (size)
	{
# if defined(__GNUC__)

		word32 result;
		__asm__ __volatile__
		(
			"movl %1, %%edi          ;\n"
			"movl $1, %%edx          ;\n"
			".byte 0x0f, 0xa7, 0xc0  ;\n"
			"andl $31, %%eax         ;\n"
			"movl %%eax, %0          ;\n"

			: "=g" (result) : "g" (m_buffer.begin()) : "eax", "edx", "edi", "cc"
		);

		const size_t rem = STDMIN(result, STDMIN(size, m_buffer.SizeInBytes()));
		std::memcpy(output, m_buffer, rem);
		size -= rem; output += rem;

# elif defined(_MSC_VER)

		word32 result;
		byte* buffer = reinterpret_cast<byte*>(m_buffer.begin());

		__asm {
			mov edi, buffer
			mov edx, 0x01
			_emit 0x0f
			_emit 0xa7
			_emit 0xc0
			and eax, 31
			mov result, eax
		}

		const size_t rem = STDMIN(result, STDMIN(size, m_buffer.SizeInBytes()));
		std::memcpy(output, m_buffer, rem);
		size -= rem; output += rem;

# else
		throw NotImplemented("PadlockRNG::GenerateBlock");
# endif
	}
#endif  // CRYPTOPP_BOOL_X86
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
