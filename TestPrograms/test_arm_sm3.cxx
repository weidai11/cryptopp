#include <arm_neon.h>
#include <arm_acle.h>
#include <stdint.h>

int main(int argc, char* argv[])
{
	// SM3 hash
	uint32x4_t y;
	y=vsm3ss1q_u32(x,y,y);
	y=vsm3tt1aq_u32(x,y,y,3);
	y=vsm3tt1bq_u32(x,y,y,1);
	y=vsm3tt2aq_u32(x,y,y,2);
	y=vsm3tt2bq_u32(x,y,y,3);
	y=vsm3partw1q_u32(x,y,y);
	y=vsm3partw2q_u32(x,y,y);
	return 0;
}
