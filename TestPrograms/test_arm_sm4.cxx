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
	// SM4 block cipher
	uint32x4_t x;
	x=vsm4ekeyq_u32(x,x);
	x=vsm4eq_u32(x,x);
	return 0;
}
