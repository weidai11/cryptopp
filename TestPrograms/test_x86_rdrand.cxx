#include <immintrin.h>
int main(int argc, char* argv[])
{
    unsigned int x=0;
    (void)_rdrand32_step (&x);
    return x == 0 ? 0 : 0;
}
