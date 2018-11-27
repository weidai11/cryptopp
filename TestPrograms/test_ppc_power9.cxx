// The problem we have here is, it appears only GCC 7.0 and above
// support Power9 builtins. Clang 7.0 has support for some (all?)
// assembly instructions but we don't see builtin support. We can't
// determine the state of XLC. Searching IBM's website for
// terms like 'darn' 'random number' is returning irrelevant hits.
// Searching with Google from the outside returns 0 hits.
//
// The support disconnect means we may report Power9 as unavailable
// and support DARN at the same time. We get into that state because
// we use inline asm to detect DARN availablity in the compiler.
// Also see cpu.cpp and the two query functions; and ppc_power9.cpp
// and the two probe functions.

#include <altivec.h>
int main(int argc, char* argv[])
{
#if 0
	const unsigned char b = (unsigned char)argc;
	const unsigned int r = (0xf << 24) | (0x3 << 16) | (0xf << 8) | (0x3 << 0);
#if defined(__clang__)
	bool x = __builtin_altivec_byte_in_range(b, r);
#elif defined(__GNUC__)
	bool x = __builtin_byte_in_range(b, r);
#else
	int XXX[-1];
#endif
#endif

#if defined(__GNUC__) || defined(__IBM_GCC_ASM)
	unsigned int y = __builtin_darn_32();
#else
	int XXX[-1];
#endif

	return 0;
}
