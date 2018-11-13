#include <tmmintrin.h>
int main(int argc, char* argv[])
{
	__m128i x;
	x=_mm_alignr_epi8(x,x,2);
	return 0;
}
