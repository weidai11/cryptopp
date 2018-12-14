// darn.cpp - written and placed in public domain by Jeffrey Walton

#include "pch.h"
#include "config.h"
#include "cryptlib.h"
#include "secblock.h"
#include "darn.h"
#include "cpu.h"

// At the moment only GCC 7.0 (and above) seems to support __builtin_darn()
// and __builtin_darn_32(). Clang 7.0 does not provide them, but it does
// support assembly instructions. XLC is unknown, but there are no hits when
// searching IBM's site. To cover more platforms we provide GCC inline
// assembly like we do with RDRAND and RDSEED. Platforms that don't support
// GCC inline assembly or the builtin will fail the compile.

// Inline assembler available in GCC 3.2 or above. For practical
// purposes we check for GCC 4.0 or above. GCC imposters claim
// to be GCC 4.2.1 so it will capture them, too. We exclude the
// Apple machines because they are not Power9 and use a slightly
// different syntax in their assembler.
#if ((__GNUC__ >= 4) || defined(__IBM_GCC_ASM)) && !defined(__APPLE__)
# define GCC_DARN_ASM_AVAILABLE 1
#endif

// warning C4702: unreachable code
#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4702)
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

#if (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)

// *************************** 32-bit *************************** //

#if (CRYPTOPP_BOOL_PPC32)

// Fills 4 bytes, buffer must be aligned
inline void DARN32(void* output)
{
    CRYPTOPP_ASSERT(IsAlignedOn(output, GetAlignmentOf<word32>()));
    word32* ptr = reinterpret_cast<word32*>(output);

#if defined(GCC_DARN_ASM_AVAILABLE)
    // This is "darn r3, 0". When L=0 a 32-bit conditioned word
    // is returned. On failure 0xffffffffffffffff is returned.
    // The Power manual recommends only checking the low 32-bit
    // word for this case. See Power ISA 3.0 specification, p. 78.
    do
    {
        __asm__ __volatile__ (
            #if (CRYPTOPP_BIG_ENDIAN)
            ".byte 0x7c, 0x60, 0x05, 0xe6  \n\t"  // r3 = darn 3, 0
            "mr %0, 3                      \n\t"  // val = r3
            #else
            ".byte 0xe6, 0x05, 0x60, 0x7c  \n\t"  // r3 = darn 3, 0
            "mr %0, 3                      \n\t"  // val = r3
            #endif
            : "=r" (*ptr) : : "r3"
        );
    } while (*ptr == 0xFFFFFFFFu);
#elif defined(_ARCH_PWR9)
    // This is probably going to break some platforms.
    // We will deal with them as we encounter them.
    *ptr = __builtin_darn_32();
#elif defined(__APPLE__)
    // Nop. Apple G4 and G5 machines are too old. They will
    // avoid this code path because HasPower9() returns false.
    CRYPTOPP_ASSERT(0);
#else
    // Catch other compile breaks
    int XXX[-1];
#endif
}
#endif  // PPC32

// *************************** 64-bit *************************** //

#if (CRYPTOPP_BOOL_PPC64)

// Fills 8 bytes, buffer must be aligned
inline void DARN64(void* output)
{
    CRYPTOPP_ASSERT(IsAlignedOn(output, GetAlignmentOf<word64>()));
    word64* ptr = reinterpret_cast<word64*>(output);

#if defined(GCC_DARN_ASM_AVAILABLE)
    // This is "darn r3, 1". When L=1 a 64-bit conditioned word
    // is returned. On failure 0xffffffffffffffff is returned.
    // See Power ISA 3.0 specification, p. 78.
    do
    {
        __asm__ __volatile__ (
            #if (CRYPTOPP_BIG_ENDIAN)
            ".byte 0x7c, 0x61, 0x05, 0xe6  \n\t"  // r3 = darn 3, 1
            "mr %0, 3                      \n\t"  // val = r3
            #else
            ".byte 0xe6, 0x05, 0x61, 0x7c  \n\t"  // r3 = darn 3, 1
            "mr %0, 3                      \n\t"  // val = r3
            #endif
            : "=r" (*ptr) : : "r3"
        );
    } while (*ptr == 0xFFFFFFFFFFFFFFFFull);
#elif defined(_ARCH_PWR9)
    // This is probably going to break some platforms.
    // We will deal with them as we encounter them.
    *ptr = __builtin_darn();
#elif defined(__APPLE__)
    // Nop. Apple G4 and G5 machines are too old. They will
    // avoid this code path because HasPower9() returns false.
    CRYPTOPP_ASSERT(0);
#else
    // Catch other compile breaks
    int XXX[-1];
#endif
}
#endif  // PPC64

// ************************ Standard C++ ************************ //

DARN::DARN()
{
    if (!HasDARN())
        throw DARN_Err("HasDARN");

    // Scratch buffer in case user buffers are unaligned.
    m_temp.New(8);
}

void DARN::GenerateBlock(byte *output, size_t size)
{
    CRYPTOPP_ASSERT((output && size) || !(output || size));
    if (size == 0) return;
    size_t i = 0;

#if (CRYPTOPP_BOOL_PPC64)

    // Check alignment
    i = reinterpret_cast<uintptr_t>(output) & 0x7;
    if (i != 0)
    {
        DARN64(m_temp);
        std::memcpy(output, m_temp, i);

        output += i;
        size -= i;
    }

    // Output is aligned
    for (i = 0; i < size/8; i++)
        DARN64(output+i*8);

    output += i*8;
    size -= i*8;

    if (size)
    {
        DARN64(m_temp);
        std::memcpy(output, m_temp, size);
    }

#elif (CRYPTOPP_BOOL_PPC32)

    // Check alignment
    i = reinterpret_cast<uintptr_t>(output) & 0x3;
    if (i != 0)
    {
        DARN32(m_temp);
        std::memcpy(output, m_temp, i);

        output += i;
        size -= i;
    }

    for (i = 0; i < size/4; i++)
        DARN32(output+i*4);

    output += 4;
    size -= 4;

    if (size)
    {
        DARN32(m_temp);
        std::memcpy(output, m_temp, size);
    }

#else
    // No suitable compiler found
    CRYPTOPP_UNUSED(output);
    throw NotImplemented("DARN: failed to find a suitable implementation");
#endif
}

void DARN::DiscardBytes(size_t n)
{
    // RoundUpToMultipleOf is used because a full word is read, and its cheaper
    //   to discard full words. There's no sense in dealing with tail bytes.
    FixedSizeSecBlock<word64, 16> discard;
    n = RoundUpToMultipleOf(n, sizeof(word64));

    size_t count = STDMIN(n, discard.SizeInBytes());
    while (count)
    {
        GenerateBlock(discard.BytePtr(), count);
        n -= count;
        count = STDMIN(n, discard.SizeInBytes());
    }
}

#else  // not PPC32 or PPC64

DARN::DARN()
{
    throw DARN_Err("HasDARN");
}

void DARN::GenerateBlock(byte *output, size_t size)
{
    // Constructor will throw, should not get here
    CRYPTOPP_UNUSED(output); CRYPTOPP_UNUSED(size);
}

void DARN::DiscardBytes(size_t n)
{
    // Constructor will throw, should not get here
    CRYPTOPP_UNUSED(n);
}

#endif  // PPC32 or PPC64

NAMESPACE_END
