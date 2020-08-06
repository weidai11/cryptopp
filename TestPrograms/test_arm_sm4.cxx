#include <stdint.h>
#ifdef CRYPTOPP_ARM_NEON_HEADER
# include <arm_neon.h>
#endif
#ifdef CRYPTOPP_ARM_ACLE_HEADER
# include <arm_acle.h>
#endif

int main(int argc, char* argv[])
{
    // SM4 block cipher
    uint32x4_t x;
    x=vsm4ekeyq_u32(x,x);
    x=vsm4eq_u32(x,x);
    return 0;
}
