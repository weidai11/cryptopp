#include <stdint.h>
#ifdef CRYPTOPP_ARM_NEON_HEADER
# include <arm_neon.h>
#endif
#ifdef CRYPTOPP_ARM_ACLE_HEADER
# include <arm_acle.h>
#endif

int main(int argc, char* argv[])
{
    uint32_t w=0xffffffff;

    w = __crc32w(w,w);
    w = __crc32h(w,w);
    w = __crc32b(w,w);
    w = __crc32cw(w,w);
    w = __crc32ch(w,w);
    w = __crc32cb(w,w);

    return 0;
}
