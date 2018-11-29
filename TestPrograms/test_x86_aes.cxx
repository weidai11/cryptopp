#include <emmintrin.h>
#include <wmmintrin.h>
int main(int argc, char* argv[])
{
	__m128i x = _mm_setzero_si128();
	x=_mm_aesenc_si128(x,x);
	x=_mm_aesenclast_si128(x,x);
	x=_mm_aesdec_si128(x,x);
	x=_mm_aesdeclast_si128(x,x);
	return 0;
}
