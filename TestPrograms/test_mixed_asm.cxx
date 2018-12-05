// This represents the pattern found in Crypto++
#include <cstddef>
int main(int argc, char* argv[])
{
	size_t ret = 1;
	asm __volatile__
	(
#if defined(__amd64__) || defined(__x86_64__)
		".intel_syntax   noprefix ;\n"
		"xor rsi, rsi    ;\n"
		"neg rsi         ;\n"
		"inc rsi         ;\n"
		"push rsi        ;\n"
		"pop rax         ;\n"
		".att_syntax     prefix ;\n"
		: "=a" (ret) : : "%rsi"
#else
		".intel_syntax   noprefix ;\n"
		"xor esi, esi    ;\n"
		"neg esi         ;\n"
		"inc esi         ;\n"
		"push esi        ;\n"
		"pop eax         ;\n"
		".att_syntax     prefix ;\n"
		: "=a" (ret) : : "%esi"
#endif
	);
	return (int)ret;
}
