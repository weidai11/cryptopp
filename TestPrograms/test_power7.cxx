#include <altivec.h>
int main(int argc, char* argv[])
{
	__vector unsigned int z;
#if defined(__xlc__) || defined(__xlC__) || defined(__clang__)
	__vector unsigned char x;
	x=vec_xl(0, (unsigned char*)argv[0]);
	x=vec_add(x,x);
#else
	__vector unsigned char x;
	x=vec_vsx_ld(0, (unsigned char*)argv[0]);
	x=vec_add(x,x);
#endif
	return 0;
}
