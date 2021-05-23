#include <stdint.h>
#ifdef CRYPTOPP_ARM_NEON_HEADER
# include <arm_neon.h>
#endif

int main(int argc, char* argv[])
{
    // SM3 hash
    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics?search=SM3
    uint32x4_t y;
    y=vsm3ss1q_u32(x,y,y);
    y=vsm3tt1aq_u32(x,y,y,3);
    y=vsm3tt1bq_u32(x,y,y,1);
    y=vsm3tt2aq_u32(x,y,y,2);
    y=vsm3tt2bq_u32(x,y,y,3);
    y=vsm3partw1q_u32(x,y,y);
    y=vsm3partw2q_u32(x,y,y);
    return 0;
}
