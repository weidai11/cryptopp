#include <arm_neon.h>
#include <arm_acle.h>
#include <stdint.h>

int main(int argc, char* argv[])
{
	uint8x16_t x={0};
	x=vaeseq_u8(x,x);
	x=vaesmcq_u8(x);
	x=vaesdq_u8(x,x);
	x=vaesimcq_u8(x);
	return 0;
}
