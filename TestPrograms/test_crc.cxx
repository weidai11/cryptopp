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
	uint32_t w=0xffffffff;

	w = __crc32w(w,w);
	w = __crc32h(w,w);
	w = __crc32b(w,w);
	w = __crc32cw(w,w);
	w = __crc32ch(w,w);
	w = __crc32cb(w,w);

	return 0;
}
