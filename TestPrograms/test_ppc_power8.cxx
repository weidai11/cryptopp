#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(_ARCH_PWR8)
    __vector unsigned long long x = {1, 2};
    __vector unsigned long long y = vec_xl(0, (unsigned long long*)argv[0]);
#  if defined(__ibmxl__) || (defined(_AIX) && defined(__xlC__))
    __vector unsigned long long z = __vpmsumd (x, y);
#  elif defined(__clang__)
    __vector unsigned long long z = __builtin_altivec_crypto_vpmsumd (x, y);
#  else
    __vector unsigned long long z = __builtin_crypto_vpmsumd (x, y);
#  endif
#else
    int x[-1];
#endif
    return 0;
}
