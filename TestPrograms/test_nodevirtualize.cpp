#include <string>

// https://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

int main(int argc, char* argv[])
{
    // GCC 12 is removing live code. We don't know why.
    // https://github.com/weidai11/cryptopp/issues/1134 and
    // https://github.com/weidai11/cryptopp/issues/1141
#if defined(__linux__) && (GCC_VERSION >= 120000)
    // On successful compile -fno-devirtualize will be used
    // to work around the problem.
    ;;
#else
    int x[-1];
#endif
    return 0;
}
