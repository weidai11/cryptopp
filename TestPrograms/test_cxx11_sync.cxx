#include <mutex>
int main(int argc, char* argv[])
{
    static std::mutex m;
    std::lock_guard<std::mutex> l(m);
    return 0;
}
