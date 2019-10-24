#define GNUC_VERSION (__GNUC__*1000 + __GNUC_MAJOR__*10)
#if (GNUC_VERSION >= 4060) || defined(__clang__)
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

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
