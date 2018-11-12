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
	const poly64_t   a=0x60606060, b=0x90909090, c=0xb0b0b0b0;
	const poly64x2_t d={0x60606060,0x90909090};
	const poly8x16_t e={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,
	                    0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0};

	const poly128_t r1 = vmull_p64(a, b);
	const poly128_t r2 = vmull_high_p64(d, d);

	return 0;
}
