#include <pmmintrin.h>
int main(int argc, char* argv[])
{
	__m128d x;
	x=_mm_addsub_pd(x,x);
	return 0;
}
