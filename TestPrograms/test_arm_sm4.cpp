#include <stdint.h>
#ifdef CRYPTOPP_ARM_NEON_HEADER
# include <arm_neon.h>
#endif

int main(int argc, char* argv[])
{
    // SM4 block cipher
    uint32x4_t x, y={1}, z={2};
    x=vsm4ekeyq_u32(y,z);
    x=vsm4eq_u32(y,z);

    return 0;
}
