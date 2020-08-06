#define GNUC_VERSION (__GNUC__*1000 + __GNUC_MAJOR__*10)

#if defined(__apple_build_version__)
# define APPLE_VERSION (__clang_major__*1000 + __clang_minor__*10)
#else
# define LLVM_VERSION (__clang_major__*1000 + __clang_minor__*10)
#endif

#if (GNUC_VERSION >= 4060) || (LLVM_VERSION >= 1070) || (APPLE_VERSION >= 10000)
# pragma GCC diagnostic ignored "-Wterminate"
#endif

#include <stdexcept>

void f(int n) noexcept(false)
{
    if (n > 2)
        throw std::runtime_error("Oops");
}

int main(int argc, char* argv[])
{
    f(argc);
    return 0;
}
