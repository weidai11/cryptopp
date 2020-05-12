#include <altivec.h>
int main(int argc, char* argv[])
{
	__vector unsigned long x = {1,2};
	__vector unsigned long y = {3,4};

#if defined(__ibmxl__) || (defined(_AIX) && defined(__xlC__))
	__vector unsigned long z=__vpmsumd(x,y);
#elif defined(__clang__)
	__vector unsigned long z=__builtin_altivec_crypto_vpmsumd(x,y);
#elif defined(__GNUC__)
	__vector unsigned long z=__builtin_crypto_vpmsumd(x,y);
#else
	int XXX[-1];
#endif
	return 0;
}
