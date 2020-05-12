#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(__ibmxl__) || (defined(_AIX) && defined(__xlC__))
	__vector unsigned char x = {1,2,3,4,5,6,7,8};
	x=__vcipher(x,x);
	x=__vcipherlast(x,x);
	x=__vncipher(x,x);
	x=__vncipherlast(x,x);
#elif defined(__clang__)
	__vector unsigned long long x = {1,2};
	x=__builtin_altivec_crypto_vcipher(x,x);
	x=__builtin_altivec_crypto_vcipherlast(x,x);
	x=__builtin_altivec_crypto_vncipher(x,x);
	x=__builtin_altivec_crypto_vncipherlast(x,x);
#elif defined(__GNUC__)
	__vector unsigned long long x = {1,2};
	x=__builtin_crypto_vcipher(x,x);
	x=__builtin_crypto_vcipherlast(x,x);
	x=__builtin_crypto_vncipher(x,x);
	x=__builtin_crypto_vncipherlast(x,x);
#else
	int XXX[-1];
#endif
	return 0;
}
