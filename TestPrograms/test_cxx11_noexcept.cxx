#define GNUC_VERSION (__GNUC__*1000 + __GNUC_MAJOR__*10)
#if (GNUC_VERSION >= 4060) || defined(__clang__)
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
