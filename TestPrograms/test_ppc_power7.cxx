#ifdef __GNUC__
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(_ARCH_PWR7)
    __vector unsigned int a = {1,2,3,4};
    __vector unsigned int b = vec_ld(0, (__vector unsigned int*)argv[0]);
    __vector unsigned int c = vec_xor(a, b);

    __vector unsigned int x = {5,6,7,8};
    __vector unsigned int y = vec_xl(0, (__vector unsigned int*)argv[0]);
    __vector unsigned int z = vec_xor(x, y);
#  if defined(__VSX__)
    __vector unsigned long long xx = {1,2};
    __vector unsigned long long yy = vec_xl(0, (__vector unsigned long long*)argv[0]);
    __vector unsigned long long zz = vec_xor(xx, yy);
#  endif
#else
    int x[-1];
#endif
    return 0;
}
