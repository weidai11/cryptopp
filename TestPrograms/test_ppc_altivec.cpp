#define GNUC_VERSION (__GNUC__*1000 + __GNUC_MAJOR__*10)
#if (GNUC_VERSION >= 4060) || defined(__clang__)
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

#include <altivec.h>
int main(int argc, char* argv[])
{
    __vector unsigned char x;
    x=vec_ld(0, (unsigned char*)argv[0]);
    x=vec_add(x,x);
    return 0;
}
