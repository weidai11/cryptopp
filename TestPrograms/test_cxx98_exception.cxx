#include <exception>
struct S {
    S() {}
    virtual ~S() {
        bool b = std::uncaught_exception();
    }
};
int main(int argc, char* argv[])
{
    S s;
    return 0;
}
