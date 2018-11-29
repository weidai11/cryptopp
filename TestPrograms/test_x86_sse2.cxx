#include <emmintrin.h>
int main(int argc, char* argv[])
{
	__m128i x = _mm_setzero_si128();
	x=_mm_add_epi64(x,x);
	return 0;
}
