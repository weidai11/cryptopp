// https://en.cppreference.com/w/cpp/feature_test
#include <exception>
int main(int argc, char* argv[])
{
#if __cpp_lib_uncaught_exceptions >= 201411L
    int x = std::uncaught_exceptions();
#else
    int x[-1];
#endif
    return 0;
}
