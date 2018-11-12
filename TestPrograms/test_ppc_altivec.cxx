#include <altivec.h>
int main(int argc, char* argv[])
{
	__vector unsigned char x;
	x=vec_ld(0, (unsigned char*)argv[0]);
	x=vec_add(x,x);
	return 0;
}
