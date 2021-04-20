#include <atomic>
int main(int argc, char* argv[])
{
    std::atomic_flag f = ATOMIC_FLAG_INIT;
    std::atomic<bool> g (false);
    return 0;
}
