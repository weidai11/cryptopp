#include <arm_neon.h>
#include <stdint.h>

int main(int argc, char* argv[])
{
	uint32x4_t x={0};
	x=veorq_u32(x,x);
	return 0;
}
