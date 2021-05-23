#include <stdint.h>
#ifdef CRYPTOPP_ARM_NEON_HEADER
# include <arm_neon.h>
#endif

inline uint64x2_t VEOR3(uint64x2_t a, uint64x2_t b, uint64x2_t c)
{
#if defined(_MSC_VER)
    return veor3q_u64(a, b, c);
#else
    uint64x2_t r;
    __asm__ ("eor3   %0.16b, %1.16b, %2.16b, %3.16b   \n\t"
            :"=w" (r) : "w" (a), "w" (b), "w" (c));
    return r;
#endif
}

template <unsigned int C>
inline uint64x2_t VXAR(uint64x2_t a, uint64x2_t b)
{
#if defined(_MSC_VER)
    return vxarq_u64(a, b, C);
#else
    uint64x2_t r;
    __asm__ ("xar   %0.2d, %1.2d, %2.2d, %3   \n\t"
            :"=w" (r) : "w" (a), "w" (b), "I" (C));
    return r;
#endif
}

inline uint64x2_t VRAX1(uint64x2_t a, uint64x2_t b)
{
#if defined(_MSC_VER)
    return vrax1q_u64(a, b);
#else
    uint64x2_t r;
    __asm__ ("rax1   %0.2d, %1.2d, %2.2d   \n\t"
            :"=w" (r) : "w" (a), "w" (b));
    return r;
#endif
}

int main(int argc, char* argv[])
{
    // SHA3 intrinsics are merely ARMv8.4 instructions.
    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics
    uint32x4_t x={0}, y={1}, z={2};
    x=VEOR3(x,y,z);
    x=VXAR(y,z,6);
    x=VRAX1(y,z);

    return 0;
}
