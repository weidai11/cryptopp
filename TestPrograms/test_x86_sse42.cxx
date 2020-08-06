#include <nmmintrin.h>
int main(int argc, char* argv[])
{
    unsigned int x=32;
    x=_mm_crc32_u8(x,4);
    return 0;
}
