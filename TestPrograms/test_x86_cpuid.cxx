int main(int argc, char* argv[])
{
	unsigned int a, b, c, d;
	asm volatile ( "cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) );

	return 0;
}
