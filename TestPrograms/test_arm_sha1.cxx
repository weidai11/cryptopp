#include <arm_neon.h>
#include <arm_acle.h>
#include <stdint.h>

int main(int argc, char* argv[])
{
	uint32x4_t y = {0};
	y=vsha1cq_u32(y,0,y);
	y=vsha1mq_u32(y,1,y);
	y=vsha1pq_u32(y,2,y);
	return 0;
}
