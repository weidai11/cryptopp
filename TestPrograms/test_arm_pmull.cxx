#include <arm_neon.h>
#include <stdint.h>

// test_acle.h determines if this is available. Then,
// -DCRYPTOPP_ARM_ACLE_AVAILABLE=0 is added to CXXFLAGS
// if the ACLE header is not available.
#if (CRYPTOPP_ARM_ACLE_AVAILABLE)
#  include <arm_acle.h>
#endif

int main(int argc, char* argv[])
{
	poly64_t   a1={0x9090909090909090}, b1={0xb0b0b0b0b0b0b0b0};
	poly64x2_t c1={0x9090909090909090, 0xb0b0b0b0b0b0b0b0};
	poly8x16_t a2={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,
	               0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},

	poly128_t r1 = vmull_p64(a1, b1);
	poly128_t r2 = vmull_high_p64(c1, c1);

	return 0;
}
