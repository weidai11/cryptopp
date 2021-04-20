#include <immintrin.h>
int main(int argc, char* argv[])
{
    __m256d x = _mm256_setzero_pd();
    x=_mm256_addsub_pd(x,x);
    return 0;
}
