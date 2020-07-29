#include <immintrin.h>
#if (__GNUC__ >= 5) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 6))
# include <x86intrin.h>
#endif
int main(int argc, char* argv[])
{
    unsigned int x=0;
    (void)_rdseed32_step (&x);
    return x == 0 ? 0 : 0;
}
