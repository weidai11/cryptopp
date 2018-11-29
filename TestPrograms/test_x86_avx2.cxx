#include <immintrin.h>
int main(int argc, char* argv[])
{
	__m256i x = _mm256_setzero_si256();
	x=_mm256_add_epi64 (x,x);
	return 0;
}
