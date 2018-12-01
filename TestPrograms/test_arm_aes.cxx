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
	uint8x16_t x={0};
	x=vaeseq_u8(x,x);
	x=vaesmcq_u8(x);
	x=vaesdq_u8(x,x);
	x=vaesimcq_u8(x);
	return 0;
}
