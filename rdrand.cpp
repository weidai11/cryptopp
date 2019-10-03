// rdrand.cpp - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.

#include "pch.h"
#include "config.h"
#include "cryptlib.h"
#include "secblock.h"
#include "rdrand.h"
#include "cpu.h"

// This file (and friends) provides both RDRAND and RDSEED. They were added
//   at Crypto++ 5.6.3. At compile time, it uses CRYPTOPP_BOOL_{X86|X32|X64}
//   to select an implementation or throws "NotImplemented". Users of the
//   classes should call HasRDRAND() or HasRDSEED() to determine if a
//   generator is available at runtime.
// The original classes accepted a retry count. Retries were superflous for
//   RDRAND, and RDSEED encountered a failure about 1 in 256 bytes depending
//   on the processor. Retries were removed at Crypto++ 6.0 because
//   GenerateBlock unconditionally retries and always fulfills the request.
// Intel recommends using a retry count in case RDRAND or RDSEED circuit
//   is bad. This implemenation does not follow the advice and requires
//   good silicon. If the circuit or processor is bad then the user has
//   bigger problems than generating random numbers.

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4702)
#endif

#if defined(CRYPTOPP_RDRAND_AVAILABLE)
# if defined(CRYPTOPP_MSC_VERSION)
#   define MASM_RDRAND_ASM_AVAILABLE 1
# endif
# if (__SUNPRO_CC >= 0x5100) || (CRYPTOPP_APPLE_CLANG_VERSION >= 30000) || \
     (CRYPTOPP_LLVM_CLANG_VERSION >= 20800) || (CRYPTOPP_GCC_VERSION >= 30200)
#   define GCC_RDRAND_ASM_AVAILABLE 1
# endif
#endif  // CRYPTOPP_RDRAND_AVAILABLE

#if defined(CRYPTOPP_RDSEED_AVAILABLE)
# if defined(CRYPTOPP_MSC_VERSION)
#   define MASM_RDSEED_ASM_AVAILABLE 1
# endif
# if (__SUNPRO_CC >= 0x5100) || (CRYPTOPP_APPLE_CLANG_VERSION >= 30000) || \
     (CRYPTOPP_LLVM_CLANG_VERSION >= 20800) || (CRYPTOPP_GCC_VERSION >= 30200)
#   define GCC_RDSEED_ASM_AVAILABLE 1
# endif
#endif  // CRYPTOPP_RDSEED_AVAILABLE

typedef unsigned char byte;

#if MASM_RDRAND_ASM_AVAILABLE
extern "C" void CRYPTOPP_FASTCALL MASM_RDRAND_GenerateBlock(byte*, size_t);
#endif

#if MASM_RDSEED_ASM_AVAILABLE
extern "C" void CRYPTOPP_FASTCALL MASM_RDSEED_GenerateBlock(byte*, size_t);
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_RDRAND_AVAILABLE)

// Fills 4 bytes
inline void RDRAND32(void* output)
{
    CRYPTOPP_UNUSED(output);  // MSC warning
#if defined(GCC_RDRAND_ASM_AVAILABLE)
    __asm__ __volatile__
    (
        "1:\n"
        ".byte 0x0f, 0xc7, 0xf0;\n"
        "jnc 1b;\n"
        : "=a" (*reinterpret_cast<word32*>(output))
        : : "cc"
    );
#endif
}

#if (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32)
// Fills 8 bytes
inline void RDRAND64(void* output)
{
    CRYPTOPP_UNUSED(output);  // MSC warning
#if defined(GCC_RDRAND_ASM_AVAILABLE)
    __asm__ __volatile__
    (
        "1:\n"
        ".byte 0x48, 0x0f, 0xc7, 0xf0;\n"
        "jnc 1b;\n"
        : "=a" (*reinterpret_cast<word64*>(output))
        : : "cc"
    );
#endif
}
#endif  // RDRAND64

RDRAND::RDRAND()
{
    if (!HasRDRAND())
        throw RDRAND_Err("HasRDRAND");
}

void RDRAND::GenerateBlock(byte *output, size_t size)
{
    CRYPTOPP_ASSERT((output && size) || !(output || size));
    if (size == 0) return;

#if defined(MASM_RDRAND_ASM_AVAILABLE)

    MASM_RDRAND_GenerateBlock(output, size);

#elif defined(GCC_RDRAND_ASM_AVAILABLE)

#   if (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32)
    size_t i = 0;
    for (i = 0; i < size/8; i++)
        RDRAND64(output+i*8);

    output += i*8;
    size -= i*8;

    if (size)
    {
        word64 val;
        RDRAND64(&val);
        std::memcpy(output, &val, size);
    }
#   else
    size_t i = 0;
    for (i = 0; i < size/4; i++)
        RDRAND32(output+i*4);

    output += i*4;
    size -= i*4;

    if (size)
    {
        word32 val;
        RDRAND32(&val);
        std::memcpy(output, &val, size);
    }
#   endif
#else
    // No suitable compiler found
    CRYPTOPP_UNUSED(output);
    throw NotImplemented("RDRAND: failed to find a suitable implementation");
#endif
}

void RDRAND::DiscardBytes(size_t n)
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

#endif  // CRYPTOPP_RDRAND_AVAILABLE

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

#if defined(CRYPTOPP_RDSEED_AVAILABLE)

// Fills 4 bytes
inline void RDSEED32(void* output)
{
    CRYPTOPP_UNUSED(output);  // MSC warning
#if defined(GCC_RDSEED_ASM_AVAILABLE)
    __asm__ __volatile__
    (
        "1:\n"
        ".byte 0x0f, 0xc7, 0xf8;\n"
        "jnc 1b;\n"
        : "=a" (*reinterpret_cast<word32*>(output))
        : : "cc"
    );
#endif
}

#if (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32)
// Fills 8 bytes
inline void RDSEED64(void* output)
{
    CRYPTOPP_UNUSED(output);  // MSC warning
#if defined(GCC_RDSEED_ASM_AVAILABLE)
    __asm__ __volatile__
    (
        "1:\n"
        ".byte 0x48, 0x0f, 0xc7, 0xf8;\n"
        "jnc 1b;\n"
        : "=a" (*reinterpret_cast<word64*>(output))
        : : "cc"
    );
#endif
}
#endif  // RDSEED64

RDSEED::RDSEED()
{
    if (!HasRDSEED())
        throw RDSEED_Err("HasRDSEED");
}

void RDSEED::GenerateBlock(byte *output, size_t size)
{
    CRYPTOPP_ASSERT((output && size) || !(output || size));
    if (size == 0) return;

#if defined(MASM_RDSEED_ASM_AVAILABLE)

    MASM_RDSEED_GenerateBlock(output, size);

#elif defined(GCC_RDSEED_ASM_AVAILABLE)
#   if (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32)
    size_t i = 0;
    for (i = 0; i < size/8; i++)
        RDSEED64(output+i*8);

    output += i*8;
    size -= i*8;

    if (size)
    {
        word64 val;
        RDSEED64(&val);
        std::memcpy(output, &val, size);
    }
#   else
    size_t i = 0;
    for (i = 0; i < size/4; i++)
        RDSEED32(output+i*4);

    output += i*4;
    size -= i*4;

    if (size)
    {
        word32 val;
        RDSEED32(&val);
        std::memcpy(output, &val, size);
    }
#   endif
#else
    // No suitable compiler found
    CRYPTOPP_UNUSED(output);
    throw NotImplemented("RDSEED: failed to find a suitable implementation");
#endif  // RDSEED64
}

void RDSEED::DiscardBytes(size_t n)
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

#else  // not CRYPTOPP_CPUID_AVAILABLE

RDRAND::RDRAND()
{
    throw RDRAND_Err("HasRDRAND");
}

void RDRAND::GenerateBlock(byte *output, size_t size)
{
    // Constructor will throw, should not get here
    CRYPTOPP_UNUSED(output); CRYPTOPP_UNUSED(size);
}

void RDRAND::DiscardBytes(size_t n)
{
    // Constructor will throw, should not get here
    CRYPTOPP_UNUSED(n);
}

RDSEED::RDSEED()
{
    throw RDSEED_Err("HasRDSEED");
}

void RDSEED::GenerateBlock(byte *output, size_t size)
{
    // Constructor will throw, should not get here
    CRYPTOPP_UNUSED(output); CRYPTOPP_UNUSED(size);
}

void RDSEED::DiscardBytes(size_t n)
{
    // Constructor will throw, should not get here
    CRYPTOPP_UNUSED(n);
}

#endif  // CRYPTOPP_CPUID_AVAILABLE

NAMESPACE_END
