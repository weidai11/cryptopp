#include <emmintrin.h>
#include <pmmintrin.h>
int main(int argc, char* argv[])
{
    __m128d x = _mm_setzero_pd();
    x=_mm_addsub_pd(x,x);
    return 0;
}
