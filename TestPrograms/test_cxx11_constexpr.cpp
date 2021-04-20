constexpr int fact(int n)
{
    return n <= 1 ? 1 : (n * fact(n - 1));
}

int main(int argc, char* argv[])
{
    fact(4);
    return 0;
}
