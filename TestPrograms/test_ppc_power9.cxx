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

#include <altivec.h>
int main(int argc, char* argv[])
{
#if defined(_ARCH_PWR9)
    __vector unsigned int v = vec_xl_be(0, (unsigned int*)argv[0]);
#else
    int XXX[-1];
#endif

#if defined(__GNUC__) || defined(__IBM_GCC_ASM)
    unsigned int y = __builtin_darn_32();
#else
    int XXX[-1];
#endif

    return 0;
}
