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

#if (GNUC_VERSION >= 7030)
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
