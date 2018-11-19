#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(__ibmxl__)
	__vector unsigned char x;
	x=__vcipher(x,x);
	x=__vcipherlast(x,x);
	x=__vncipher(x,x);
	x=__vncipherlast(x,x);
#elif defined(__clang__)
	__vector unsigned long long x;
	x=__builtin_altivec_crypto_vcipher(x,x);
	x=__builtin_altivec_crypto_vcipherlast(x,x);
	x=__builtin_altivec_crypto_vncipher(x,x);
	x=__builtin_altivec_crypto_vncipherlast(x,x);
#elif defined(__GNUC__)
	__vector unsigned long long x;
	x=__builtin_crypto_vcipher(x,x);
	x=__builtin_crypto_vcipherlast(x,x);
	x=__builtin_crypto_vncipher(x,x);
	x=__builtin_crypto_vncipherlast(x,x);
#else
	int XXX[-1];
#endif
	return 0;
}
