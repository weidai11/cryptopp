#include <arm_neon.h>
#include <arm_acle.h>
#include <stdint.h>

int main(int argc, char* argv[])
{
	// SM4 block cipher
	uint32x4_t x;
	x=vsm4ekeyq_u32(x,x);
	x=vsm4eq_u32(x,x);
	return 0;
}
