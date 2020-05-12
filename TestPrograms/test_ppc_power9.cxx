#define GNUC_VERSION (__GNUC__*1000 + __GNUC_MAJOR__*10)
#if (GNUC_VERSION >= 4060) || defined(__clang__)
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(_ARCH_PWR9)
    __vector unsigned int v = vec_xl_be(0, (unsigned int*)argv[0]);
#else
	int XXX[-1];
#endif

#if defined(__GNUC__) || defined(__IBM_GCC_ASM)
	unsigned int y = __builtin_darn_32();
#else
	int XXX[-1];
#endif

	return 0;
}
