#include <string>
int main(int argc, char* argv[])
{
#ifndef __GLIBCXX__
    int x[-1];
#endif
    return 0;
}
