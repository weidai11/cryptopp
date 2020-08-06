// TODO: cut-in xcrypt-ecb
#include <cstdlib>
int main(int argc, char* argv[])
{
    unsigned int msr=0;
    unsigned int divisor=2;
    unsigned int buffer;

    __asm__ __volatile__
    (
#if defined(__x86_64__) || defined(__amd64__)
        "mov  %1, %%rdi          ;\n"
        "movl %2, %%edx          ;\n"
#else
        "mov  %1, %%edi          ;\n"
        "movl %2, %%edx          ;\n"
#endif

        // xstore-rng
        ".byte 0x0f, 0xa7, 0xc0  ;\n"

#if defined(__x86_64__) || defined(__amd64__)
        "andq %%rax, 0x1f        ;\n"
        "movl %%eax, %0          ;\n"
#else
        "andl  %%eax, 0x1f       ;\n"
        "movl  %%eax, %0         ;\n"
#endif

        : "=g" (msr) : "g" (buffer), "g" (divisor)
#if defined(__x86_64__) || defined(__amd64__)
        : "rax", "rdx", "rdi", "cc"
#else
        : "eax", "edx", "edi", "cc"
#endif
    );

    return 0;
}
