#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

int main(int argc, char* argv[])
{
    // SM3 hash
    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics?search=SM3
    uint32x4_t x={1}, y={2}, z={3};
    y=vsm3ss1q_u32(x,y,z);
    y=vsm3tt1aq_u32(x,y,z,3);
    y=vsm3tt1bq_u32(x,y,z,1);
    y=vsm3tt2aq_u32(x,y,z,2);
    y=vsm3tt2bq_u32(x,y,z,3);
    y=vsm3partw1q_u32(x,y,z);
    y=vsm3partw2q_u32(x,y,z);
    return 0;
}
