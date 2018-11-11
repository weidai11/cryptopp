#include <emmintrin.h>
int main(int argc, char* argv[])
{
	__m128i x;
	x=_mm_add_epi64(x,x);
	return 0;
}
