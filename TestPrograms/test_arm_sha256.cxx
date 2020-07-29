#include <arm_neon.h>
#include <arm_acle.h>
#include <stdint.h>

int main(int argc, char* argv[])
{
	uint32x4_t y = {0};
	y=vsha256hq_u32(y, y, y);
	y=vsha256h2q_u32(y, y, y);
	y=vsha256su1q_u32(y, y, y);
	return 0;
}
