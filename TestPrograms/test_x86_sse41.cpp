#include <emmintrin.h>
#include <smmintrin.h>
int main(int argc, char* argv[])
{
    __m128i x = _mm_setzero_si128();
    __m128i a = _mm_setzero_si128();
    __m128i b = _mm_setzero_si128();
    x=_mm_blend_epi16(a,b,4);
    return 0;
}
