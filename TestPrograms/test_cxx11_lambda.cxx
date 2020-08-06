// https://en.cppreference.com/w/cpp/feature_test
int main(int argc, char* argv[])
{
#if __cpp_lambdas >= 200907L
    int x[1];
#else
    int x[-1];
#endif
    return 0;
}
