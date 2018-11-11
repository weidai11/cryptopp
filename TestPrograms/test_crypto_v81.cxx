#include <arm_neon.h>
#include <stdint.h>

// This is how config.h includes it.
#if defined(__aarch32__) || defined(__aarch64__) || (__ARM_ARCH >= 8) || defined(__ARM_ACLE)
# if !defined(__ANDROID__) && !defined(ANDROID) && !defined(__APPLE__)
#  include <arm_acle.h>
# endif
#endif

int main(int argc, char* argv[])
{
	uint8x16_t x;
	x=vaeseq_u8(x,x);
	x=vaesdq_u8(x,x);

	uint32x4_t y;
	y=vsha1cq_u32(y,0,y);
	y=vsha1mq_u32(y,1,y);
	y=vsha1pq_u32(y,2,y);

	return 0;
}
