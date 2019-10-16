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
	uint32x4_t y = {0};
	y=vsha1cq_u32(y,0,y);
	y=vsha1mq_u32(y,1,y);
	y=vsha1pq_u32(y,2,y);
	return 0;
}
