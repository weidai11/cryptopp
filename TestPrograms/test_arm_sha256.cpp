#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

int main(int argc, char* argv[])
{
    uint32x4_t y = {0};
    y=vsha256hq_u32(y, y, y);
    y=vsha256h2q_u32(y, y, y);
    y=vsha256su1q_u32(y, y, y);
    return 0;
}
