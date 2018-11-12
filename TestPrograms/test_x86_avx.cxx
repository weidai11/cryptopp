#include <immintrin.h>
int main(int argc, char* argv[])
{
	__m256d x;
	x=_mm256_addsub_pd(x,x);
	return 0;
}
