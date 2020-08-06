// https://stackoverflow.com/a/30940639
#include <tuple>
#include <functional>
auto f()
{
    // this fn returns multiple values
    int x = 5;
    return std::make_tuple(x, 7);
}

int main(int argc, char* argv[])
{
    int a, b;
    std::tie(a, b) = f();
    return 0;
}
