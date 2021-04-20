// https://en.cppreference.com/w/cpp/feature_test
// Apple bug https://bugs.llvm.org/show_bug.cgi?id=47012.
int main(int argc, char* argv[])
{
#if __cpp_threadsafe_static_init >= 200806L
    int x[1];
#else
    int x[-1];
#endif
    return 0;
}
