#include <emmintrin.h>
#include <immintrin.h>
int main(int argc, char* argv[])
{
    __m128i x = _mm_setzero_si128();
    x=_mm_sha1msg1_epu32(x,x);
    x=_mm_sha1msg2_epu32(x,x);
    x=_mm_sha1nexte_epu32(x,x);
    x=_mm_sha1rnds4_epu32(x,x,0);
    x=_mm_sha256msg1_epu32(x,x);
    x=_mm_sha256msg2_epu32(x,x);
    x=_mm_sha256rnds2_epu32(x,x,x);
    return 0;
}
