#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

int main(int argc, char* argv[])
{
    // SM4 block cipher
    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics?search=SM4
    uint32x4_t x={0}, y={1}, z={2};
    x=vsm4ekeyq_u32(y,z);
    x=vsm4eq_u32(y,z);

    return 0;
}
