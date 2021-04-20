#include <cstddef>
int main(int argc, char* argv[])
{
    enum Size : std::size_t { Zero=0, One=1, Two=2 };
    Size s(Size::Zero);
    return 0;
}
