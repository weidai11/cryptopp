#include <smmintrin.h>
int main(int argc, char* argv[])
{
	__m128i x, a, b;
	x=_mm_blend_epi16(a,b,4);
	return 0;
}
