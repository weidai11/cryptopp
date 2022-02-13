#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

int main(int argc, char* argv[])
{
    // SHA512 hash
    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics?search=SHA512
    uint32x4_t w={0}, x={0}, y={0}, z={0};
    w=vsha512hq_u64(x,y,z);
    w=vsha512h2q_u64(x,y);
    w=vsha512su0q_u64(x,y);
    w=vsha512su1q_u64 (x,y,z);

    return 0;
}
