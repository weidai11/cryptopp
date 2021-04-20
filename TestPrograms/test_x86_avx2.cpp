#include <immintrin.h>
int main(int argc, char* argv[])
{
    // _mm256_broadcastsi128_si256 due to Clang
    __m128i x = _mm_setzero_si128 ();
    __m256i y = _mm256_broadcastsi128_si256 (x);
    y = _mm256_add_epi64 (y,y);
    return 0;
}
