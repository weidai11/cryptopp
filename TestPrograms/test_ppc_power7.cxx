#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(_ARCH_PWR7)
    __vector unsigned int x = {1, 2};
    __vector unsigned int y = vec_add(x, vec_ld(0, (__vector unsigned int*)argv[0]));
#  if defined(__VSX__)
	__vector unsigned long long xx = (__vector unsigned long long)x;
	__vector unsigned long long yy = (__vector unsigned long long)y;
	__vector unsigned long long zz = vec_xor(xx, yy);
#  endif
#else
    int x[-1];
#endif
    return 0;
}
