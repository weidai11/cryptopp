#if defined(__GNUC__)
# define GNUC_VERSION (__GNUC__*1000 + __GNUC_MINOR__*10)
#endif

#if defined(__clang__) && defined(__apple_build_version__)
# undef GNUC_VERSION
# define APPLE_VERSION (__clang_major__*1000 + __clang_minor__*10)
#elif defined(__clang__)
# undef GNUC_VERSION
# define LLVM_VERSION (__clang_major__*1000 + __clang_minor__*10)
#endif

#if (GNUC_VERSION >= 4060) || (LLVM_VERSION >= 1070) || (APPLE_VERSION >= 2000)
# pragma GCC diagnostic ignored "-Wdeprecated"
#endif

// XL C++ on AIX does not define CRYPTO and does not
// provide an option to set it. We have to set it
// for the code below. This define must stay in
// sync with the define in test_ppc_power8.cpp
#if defined(_AIX) && defined(_ARCH_PWR8) && defined(__xlC__)
# define __CRYPTO__ 1
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
