#define GNUC_VERSION (__GNUC__*1000 + __GNUC_MAJOR__*10)
#if (GNUC_VERSION >= 4060) || defined(__clang__)
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(_ARCH_PWR7) && defined(__VSX__)
    // PWR7
    __vector unsigned int a = {1,2,3,4};
    __vector unsigned int b = vec_ld(0, (unsigned int*)argv[0]);
    __vector unsigned int c = vec_xor(a, b);

    // VSX
    __vector unsigned int x = {5,6,7,8};
    __vector unsigned int y = vec_xl(0, (unsigned int*)argv[0]);
    __vector unsigned int z = vec_xor(x, y);
    __vector unsigned long long xx = {1,2};
    __vector unsigned long long yy = (__vector unsigned long long)y;
#else
    int x[-1];
#endif
    return 0;
}
