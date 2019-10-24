#define GNUC_VERSION (__GNUC__*1000 + __GNUC_MAJOR__*10)
#if (GNUC_VERSION >= 4060) || defined(__clang__)
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(_ARCH_PWR8)
    __vector unsigned long long r = {1, 2};
    __vector unsigned int s = vec_xl(0, (unsigned int*)argv[0]);  // Power7
    __vector unsigned long long w = (__vector unsigned long long)r;
    __vector unsigned long long x = (__vector unsigned long long)s;
    __vector unsigned long long y = vec_xor(w, x);
    __vector unsigned long long z = vec_add(y, vec_add(w, x));
#  if defined(__ibmxl__) || (defined(_AIX) && defined(__xlC__))
    __vector unsigned long long u = __vpmsumd (y, z);
#  elif defined(__clang__)
    __vector unsigned long long u = __builtin_altivec_crypto_vpmsumd (y, z);
#  else
    __vector unsigned long long u = __builtin_crypto_vpmsumd (y, z);
#  endif
#else
    int x[-1];
#endif
    return 0;
}
