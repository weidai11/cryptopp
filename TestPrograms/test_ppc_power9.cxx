#include <altivec.h>
int main(int argc, char* argv[])
{
	const unsigned char b = (unsigned char)argc;
	const unsigned int r = (0xf << 24) | (0x3 << 16) | (0xf << 8) | (0x3 << 0);
#if defined(__clang__)
	bool x = __builtin_altivec_byte_in_range(b, r);
#elif defined(__GNUC__)
	bool x = __builtin_byte_in_range(b, r);
#else
	int XXX[-1];
#endif

#if UINTPTR_MAX == 0xffffffffffffffffULL
#  if defined(__clang__)
	unsigned long long y = __builtin_altivec_darn();
#  elif defined(__GNUC__)
	unsigned long long y = __builtin_darn();
#  else
	int XXX[-1];
#  endif
#else
#  if defined(__clang__)
	unsigned int y = __builtin_altivec_darn_32();
#  elif defined(__GNUC__)
	unsigned int y = __builtin_darn_32();
#  else
	int XXX[-1];
#  endif
#endif

	return 0;
}
