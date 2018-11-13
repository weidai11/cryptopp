#include <wmmintrin.h>
int main(int argc, char* argv[])
{
	__m128i x;
	x=_mm_clmulepi64_si128(x,x,0x11);
	return 0;
}
