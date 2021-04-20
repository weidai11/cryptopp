struct S {
    S() = delete;
    explicit S(int n) { }
};

int main (int argc, char* rgv[])
{
    S s(1);
    return 0;
}
