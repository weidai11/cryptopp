#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(_ARCH_PWR7)
    __vector unsigned long long z = {1, 2};
    z=vec_add(z, vec_xl(0, (unsigned long long*)argv[0]));
#else
    int x[-1];
#endif
    return 0;
}
