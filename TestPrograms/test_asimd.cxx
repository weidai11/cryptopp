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
	uint32x4_t x;
	x=veorq_u32(x,x);
	return 0;
}
