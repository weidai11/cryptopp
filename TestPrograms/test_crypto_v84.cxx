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
	// SM4 block cipher
	uint32x4_t x;
	x=vsm4ekeyq_u32(x,x);
	x=vsm4eq_u32(x,x);

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
