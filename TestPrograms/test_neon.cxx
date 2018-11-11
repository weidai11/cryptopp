#include <arm_neon.h>
#include <stdint.h>

#if (CRYPTOPP_ARM_ACLE_AVAILABLE)
#  include <arm_acle.h>
#endif

int main(int argc, char* argv[])
{
	uint32x4_t x;
	x=veorq_u32(x,x);
	return 0;
}
