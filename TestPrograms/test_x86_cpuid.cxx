#include <stdint.h>
int main(int argc, char* argv[])
{
	uint32_t a, b, c, d;
	asm volatile ( "cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) );

	return 0;
}
