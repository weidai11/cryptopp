#include <stdint.h>
#ifdef CRYPTOPP_ARM_NEON_HEADER
# include <arm_neon.h>
#endif
#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

// Keep sync'd with arm_simd.h
inline uint32_t CRC32B (uint32_t crc, uint8_t val)
{
#if defined(_MSC_VER)
	return __crc32b(crc, val);
#else
    uint32_t r;
    __asm__ ("crc32b    %w0, %w1, %w2   \n\t"
            :"=r" (r) : "r" (crc), "r" (val) );
    return r;
#endif
}

inline uint32_t CRC32W (uint32_t crc, uint32_t val)
{
#if defined(_MSC_VER)
	return __crc32w(crc, val);
#else
    uint32_t r;
    __asm__ ("crc32w    %w0, %w1, %w2   \n\t"
            :"=r" (r) : "r" (crc), "r" (val) );
    return r;
#endif
}

inline uint32_t CRC32CB (uint32_t crc, uint8_t val)
{
#if defined(_MSC_VER)
	return __crc32cb(crc, val);
#else
    uint32_t r;
    __asm__ ("crc32cb    %w0, %w1, %w2   \n\t"
            :"=r" (r) : "r" (crc), "r" (val) );
    return r;
#endif
}

inline uint32_t CRC32CW (uint32_t crc, uint32_t val)
{
#if defined(_MSC_VER)
	return __crc32cw(crc, val);
#else
    uint32_t r;
    __asm__ ("crc32cw    %w0, %w1, %w2   \n\t"
            :"=r" (r) : "r" (crc), "r" (val) );
    return r;
#endif
}

int main(int argc, char* argv[])
{
    uint32_t w=0xffffffff;

    w = CRC32B(w,w);
    w = CRC32W(w,w);
    w = CRC32CB(w,w);
    w = CRC32CW(w,w);

    return 0;
}
