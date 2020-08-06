int main(int argc, char* argv[])
{
#if __cpp_variadic_templates >= 200704L
    int x[1];
#else
    int x[-1];
#endif
    return 0;
}
