#include <altivec.h>
int main(int argc, char* argv[])
{
	__vector unsigned long long z = {1, 2};
	z=vec_add(z,z);
	return 0;
}
