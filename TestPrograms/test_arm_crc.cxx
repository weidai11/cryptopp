#include <arm_neon.h>
#include <stdint.h>

// test_acle.h determines if this is available. Then,
// -DCRYPTOPP_ARM_ACLE_AVAILABLE=0 is added to CXXFLAGS
// if the ACLE header is not available.
#if (CRYPTOPP_ARM_ACLE_AVAILABLE)
#  include <arm_acle.h>
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
