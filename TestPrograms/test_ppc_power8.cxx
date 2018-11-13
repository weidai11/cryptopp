#include <altivec.h>
int main(int argc, char* argv[])
{
	__vector unsigned long long z;
#if defined(__xlc__) || defined(__xlC__) || defined(__clang__)
	__vector unsigned char x;
	x=__vcipher(x,x);
	x=__vcipherlast(x,x);
	x=__vncipher(x,x);
	x=__vncipherlast(x,x);
#elif defined(__GNUC__)
	__vector unsigned long long x;
	x=__builtin_crypto_vcipher(x,x);
	x=__builtin_crypto_vcipherlast(x,x);
	x=__builtin_crypto_vncipher(x,x);
	x=__builtin_crypto_vncipherlast(x,x);
#endif
	return 0;
}
