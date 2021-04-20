#include <stdint.h>
#include <immintrin.h>
int main(int argc, char* argv[])
{
    uint64_t x[8] = {0};
    __m512i y = _mm512_loadu_si512((__m512i*)x);
    return 0;
}
