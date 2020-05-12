#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(__ibmxl__) || (defined(_AIX) && defined(__xlC__))
	__vector unsigned int x = {1,2,3,4};
    x=__vshasigmaw(x, 0, 0);
	__vector unsigned long long y = {1,2};
    y=__vshasigmad(y, 0, 0);
#elif defined(__clang__)
	__vector unsigned int x = {1,2,3,4};
    x=__builtin_altivec_crypto_vshasigmaw(x, 0, 0);
	__vector unsigned long long y = {1,2};
    y=__builtin_altivec_crypto_vshasigmad(y, 0, 0);
#elif defined(__GNUC__)
	__vector unsigned int x = {1,2,3,4};
    x=__builtin_crypto_vshasigmaw(x, 0, 0);
	__vector unsigned long long y = {1,2};
    y=__builtin_crypto_vshasigmad(y, 0, 0);
#else
    int XXX[-1];
#endif
	return 0;
}
