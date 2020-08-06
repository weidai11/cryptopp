// Real C++17 compilers provide 'if constexpr'
#include <type_traits>

template <typename T>
auto get_value(T t)
{
    if constexpr (std::is_pointer_v<T>)
        return t[0];
    else
        return t;
}

int main(int argc, char* argv[])
{
    char c = get_value(argv[0]);
    return 0;
}
