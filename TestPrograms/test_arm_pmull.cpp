#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

// Keep sync'd with arm_simd.h
#include "arm_simd.h"

int main(int argc, char* argv[])
{
    // Linaro is missing a lot of pmull gear. Also see http://github.com/weidai11/cryptopp/issues/233.
    const uint64_t wa1[]={0,0x9090909090909090}, wb1[]={0,0xb0b0b0b0b0b0b0b0};
    const uint64x2_t a1=vld1q_u64(wa1), b1=vld1q_u64(wb1);

    const uint8_t wa2[]={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,
                         0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},
                  wb2[]={0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,
                         0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0,0xe0};
    const uint8x16_t a2=vld1q_u8(wa2), b2=vld1q_u8(wb2);

    const uint64x2_t r1 = PMULL_00(a1, b1);
    const uint64x2_t r2 = PMULL_11(vreinterpretq_u64_u8(a2),
                                   vreinterpretq_u64_u8(b2));

    return 0;
}
