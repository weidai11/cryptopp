int main(int argc, char* argv[])
{
#if __cplusplus >= 201402L
    int x[1];
#else
    int x[-1];
#endif
    return 0;
}
