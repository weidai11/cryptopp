#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

int main(int argc, char* argv[])
{
    uint8x16_t x={0};
    x=vaeseq_u8(x,x);
    x=vaesmcq_u8(x);
    x=vaesdq_u8(x,x);
    x=vaesimcq_u8(x);
    return 0;
}
