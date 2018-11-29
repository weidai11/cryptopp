#include <emmintrin.h>
#include <tmmintrin.h>
int main(int argc, char* argv[])
{
	__m128i x = _mm_setzero_si128();
	x=_mm_alignr_epi8(x,x,2);
	return 0;
}
