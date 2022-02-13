#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

int main(int argc, char* argv[])
{
    uint32x4_t x={0};
    x=veorq_u32(x,x);
    return 0;
}
