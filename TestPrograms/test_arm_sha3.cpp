#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

// Keep sync'd with arm_simd.h
#include "arm_simd.h"

int main(int argc, char* argv[])
{
    // SHA3 intrinsics are merely ARMv8.2 instructions.
    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics
    uint32x4_t x={0}, y={1}, z={2};
    x=VEOR3(x,y,z);
    x=VXAR(y,z,6);
    x=VRAX1(y,z);

    return 0;
}
