#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif
#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

// Keep sync'd with arm_simd.h
#include "arm_simd.h"

int main(int argc, char* argv[])
{
    uint32_t w=0xffffffff;

    w = CRC32B(w,w);
    w = CRC32W(w,w);
    w = CRC32CB(w,w);
    w = CRC32CW(w,w);

    return 0;
}
