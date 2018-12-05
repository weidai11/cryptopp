// Most Clang cannot handle mixed asm with positional arguments, where the
// body is Intel style with no prefix and the templates are AT&T style.
// Also see https://bugs.llvm.org/show_bug.cgi?id=39895 .
#include <cstddef>
int main(int argc, char* argv[])
{
	size_t ret = 1, N = 1;
	asm __volatile__
	(
#if defined(__amd64__) || defined(__x86_64__)
		".intel_syntax   noprefix ;\n"
		"xor rsi, rsi    ;\n"
		"neg %1          ;\n"
		"inc %1          ;\n"
		"push %1         ;\n"
		"pop rax         ;\n"
		".att_syntax     prefix ;\n"
		: "=a" (ret) : "c" (N) : "%rsi"
#else
		".intel_syntax   noprefix ;\n"
		"xor esi, esi    ;\n"
		"neg %1          ;\n"
		"inc %1          ;\n"
		"push %1         ;\n"
		"pop eax         ;\n"
		".att_syntax     prefix ;\n"
		: "=a" (ret) : "c" (N) : "%esi"
#endif
	);
	return (int)ret;
}
