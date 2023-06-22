#include <iostream>

// Compile with:
//   g++ cryptopp-compiler.cpp -o cryptopp-compiler.exe
// Or:
//   cl.exe /EHs cryptopp-compiler.cpp /Fe:cryptopp-compiler.exe

int main(int argc, char* argv[])
{
#if defined (_MSC_VER)
    std::cout << "_MSC_VER is defined" << std::endl;
#else
    std::cout << "_MSC_VER is not defined" << std::endl;
#endif

#if defined (__GNUC__)
    std::cout << "__GNUC__ is defined" << std::endl;
#else
    std::cout << "__GNUC__ is not defined" << std::endl;
#endif

#if defined (__clang__)
    std::cout << "__clang__ is defined" << std::endl;
#else
    std::cout << "__clang__ is not defined" << std::endl;
#endif

#if defined (__INTEL_COMPILER)
    std::cout << "__INTEL_COMPILER is defined" << std::endl;
#else
    std::cout << "__INTEL_COMPILER is not defined" << std::endl;
#endif

#if defined (__xlC__)
    std::cout << "__xlC__ is defined" << std::endl;
#else
    std::cout << "__xlC__ is not defined" << std::endl;
#endif

#if defined (__SUNPRO_CC)
    std::cout << "__SUNPRO_CC is defined" << std::endl;
#else
    std::cout << "__SUNPRO_CC is not defined" << std::endl;
#endif

    return 0;
}
