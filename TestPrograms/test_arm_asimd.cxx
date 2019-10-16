#include <arm_neon.h>
#include <stdint.h>

// test_acle.h determines if this is available. Then,
// -DCRYPTOPP_ARM_ACLE_HEADER=0 is added to CXXFLAGS
// if the ACLE header is not available.
#if (CRYPTOPP_ARM_ACLE_HEADER)
#  include <arm_acle.h>
#endif

int main(int argc, char* argv[])
{
	uint32x4_t x={0};
	x=veorq_u32(x,x);
	return 0;
}
