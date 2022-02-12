#include <stdint.h>

int main(int argc, char* argv[])
{
#if __ARM_ARCH >= 7
  // Do nothing
#elif __ARM_ARCH_7A__
  // Do nothing
#else
    int n[-1];
#endif
    return 0;
}
