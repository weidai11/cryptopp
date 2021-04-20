// Real C++11 libraries provide <forward_list>
#include <forward_list>
int main(int argc, char* argv[])
{
#if __cplusplus >= 201103L
    std::forward_list<int> x;
#else
    int x[-1];
#endif
    return 0;
}
