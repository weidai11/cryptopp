// validat1.cpp - originally written and placed in the public domain by Wei Dai and Jeffrey Walton
//                Routines in this source file are only tested in Debug builds.
//                Source files split in July 2018 to expedite compiles.

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "cpu.h"
#include "validate.h"

#include "secblock.h"
#include "gzip.h"
#include "zlib.h"

#if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
# include "ppc_simd.h"
#endif

#include <iostream>
#include <iomanip>
#include <sstream>

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
bool TestSecBlock()
{
    std::cout << "\nTesting SecBlock...\n\n";

    bool pass1=true, pass2=true, pass3=true, pass4=true, pass5=true, pass6=true, pass7=true, temp=false;

    //************ Allocators ************//

    {
        std::basic_string<char, std::char_traits<char>, AllocatorWithCleanup<char, false> > s1;
        std::basic_string<char, std::char_traits<char>, AllocatorWithCleanup<char,  true> > s2;
        s1.resize(1024); s2.resize(1024);

        std::vector<byte, AllocatorWithCleanup<byte, false> > v1;
        std::vector<byte, AllocatorWithCleanup<byte,  true> > v2;
        v1.resize(1024); v2.resize(1024);
    }

    //********** Zeroized block **********//

    {
        // NULL ptr with a size means to create a new SecBlock with all elements zero'd
        SecByteBlock z1(NULLPTR, 256);
        temp = true;

        for (size_t i = 0; i < z1.size(); i++)
            temp &= (z1[i] == 0);

        pass1 &= temp;
        if (!temp)
            std::cout << "FAILED:";
        else
            std::cout << "passed:";
        std::cout << "  Zeroized byte array\n";

        SecBlock<word32> z2(NULLPTR, 256);
        temp = true;

        for (size_t i = 0; i < z2.size(); i++)
            temp &= (z2[i] == 0);

        pass1 &= temp;
        if (!temp)
            std::cout << "FAILED:";
        else
            std::cout << "passed:";
        std::cout << "  Zeroized word32 array\n";

        SecBlock<word64> z3(NULLPTR, 256);
        temp = true;

        for (size_t i = 0; i < z3.size(); i++)
            temp &= (z3[i] == 0);

        pass1 &= temp;
        if (!temp)
            std::cout << "FAILED:";
        else
            std::cout << "passed:";
        std::cout << "  Zeroized word64 array\n";

#if defined(CRYPTOPP_WORD128_AVAILABLE)
        SecBlock<word128> z4(NULLPTR, 256);
        temp = true;

        for (size_t i = 0; i < z4.size(); i++)
            temp &= (z4[i] == 0);

        pass1 &= temp;
        if (!temp)
            std::cout << "FAILED:";
        else
            std::cout << "passed:";
        std::cout << "  Zeroized word128 array\n";
#endif
    }

    //********** Non-zero'd block **********//

    {
        SecByteBlock z1(NULLPTR, 256);
        z1.SetMark(0);

        SecBlock<word32> z2(NULLPTR, 256);
        z2.SetMark(0);

        SecBlock<word64> z3(NULLPTR, 256);
        z3.SetMark(0);

#if defined(CRYPTOPP_WORD128_AVAILABLE)
        SecBlock<word128> z4(NULLPTR, 256);
        z4.SetMark(0);
#endif
    }

    //********** Assign **********//

    try
    {
        SecByteBlock a, b;
        temp = true;

        a.Assign((const byte*)"a", 1);
        b.Assign((const byte*)"b", 1);

        temp &= (a.SizeInBytes() == 1);
        temp &= (b.SizeInBytes() == 1);
        temp &= (a[0] == 'a');
        temp &= (b[0] == 'b');

        a.Assign((const byte*)"ab", 2);
        b.Assign((const byte*)"cd", 2);

        temp &= (a.SizeInBytes() == 2);
        temp &= (b.SizeInBytes() == 2);
        temp &= (a[0] == 'a' && a[1] == 'b');
        temp &= (b[0] == 'c' && b[1] == 'd');
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass2 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Assign byte\n";

    try
    {
        SecBlock<word32> a, b;
        temp = true;

        word32 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        temp &= (a.SizeInBytes() == 4);
        temp &= (b.SizeInBytes() == 4);
        temp &= (a[0] == 1);
        temp &= (b[0] == 2);

        word32 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        temp &= (a.SizeInBytes() == 8);
        temp &= (b.SizeInBytes() == 8);
        temp &= (a[0] == 1 && a[1] == 2);
        temp &= (b[0] == 3 && b[1] == 4);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass2 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Assign word32\n";

    try
    {
        SecBlock<word64> a, b;
        temp = true;

        word64 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        temp &= (a.SizeInBytes() == 8);
        temp &= (b.SizeInBytes() == 8);
        temp &= (a[0] == 1);
        temp &= (b[0] == 2);

        word64 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        temp &= (a.SizeInBytes() == 16);
        temp &= (b.SizeInBytes() == 16);
        temp &= (a[0] == 1 && a[1] == 2);
        temp &= (b[0] == 3 && b[1] == 4);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass2 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Assign word64\n";

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    try
    {
        SecBlock<word128> a, b;
        temp = true;

        word128 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        temp &= (a.SizeInBytes() == 16);
        temp &= (b.SizeInBytes() == 16);
        temp &= (a[0] == 1);
        temp &= (b[0] == 2);

        word128 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        temp &= (a.SizeInBytes() == 32);
        temp &= (b.SizeInBytes() == 32);
        temp &= (a[0] == 1 && a[1] == 2);
        temp &= (b[0] == 3 && b[1] == 4);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass2 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Assign word128\n";
#endif

    //********** Append **********//

    try
    {
        SecByteBlock a, b;
        temp = true;

        a.Assign((const byte*)"a", 1);
        b.Assign((const byte*)"b", 1);

        a += b;
        temp &= (a.SizeInBytes() == 2);
        temp &= (a[0] == 'a' && a[1] == 'b');

        a.Assign((const byte*)"ab", 2);
        b.Assign((const byte*)"cd", 2);

        a += b;
        temp &= (a.SizeInBytes() == 4);
        temp &= (a[0] == 'a' && a[1] == 'b' && a[2] == 'c' && a[3] == 'd');

        a.Assign((const byte*)"a", 1);

        a += a;
        temp &= (a.SizeInBytes() == 2);
        temp &= (a[0] == 'a' && a[1] == 'a');

        a.Assign((const byte*)"ab", 2);

        a += a;
        temp &= (a.SizeInBytes() == 4);
        temp &= (a[0] == 'a' && a[1] == 'b' && a[2] == 'a' && a[3] == 'b');
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass3 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Append byte\n";

    try
    {
        SecBlock<word32> a, b;
        temp = true;

        const word32 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        a += b;
        temp &= (a.SizeInBytes() == 8);
        temp &= (a[0] == 1 && a[1] == 2);

        const word32 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        a += b;
        temp &= (a.SizeInBytes() == 16);
        temp &= (a[0] == 1 && a[1] == 2 && a[2] == 3 && a[3] == 4);

        a.Assign(one, 1);

        a += a;
        temp &= (a.SizeInBytes() == 8);
        temp &= (a[0] == 1 && a[1] == 1);

        a.Assign(three, 2);

        a += a;
        temp &= (a.SizeInBytes() == 16);
        temp &= (a[0] == 1 && a[1] == 2 && a[2] == 1 && a[3] == 2);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass3 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Append word32\n";

    try
    {
        SecBlock<word64> a, b;
        temp = true;

        const word64 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        a += b;
        temp &= (a.SizeInBytes() == 16);
        temp &= (a[0] == 1 && a[1] == 2);

        const word64 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        a += b;
        temp &= (a.SizeInBytes() == 32);
        temp &= (a[0] == 1 && a[1] == 2 && a[2] == 3 && a[3] == 4);

        a.Assign(one, 1);

        a += a;
        temp &= (a.SizeInBytes() == 16);
        temp &= (a[0] == 1 && a[1] == 1);

        a.Assign(three, 2);

        a += a;
        temp &= (a.SizeInBytes() == 32);
        temp &= (a[0] == 1 && a[1] == 2 && a[2] == 1 && a[3] == 2);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass3 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Append word64\n";

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    try
    {
        SecBlock<word128> a, b;
        temp = true;

        const word128 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        a += b;
        temp &= (a.SizeInBytes() == 32);
        temp &= (a[0] == 1 && a[1] == 2);

        const word128 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        a += b;
        temp &= (a.SizeInBytes() == 64);
        temp &= (a[0] == 1 && a[1] == 2 && a[2] == 3 && a[3] == 4);

        a.Assign(one, 1);

        a += a;
        temp &= (a.SizeInBytes() == 32);
        temp &= (a[0] == 1 && a[1] == 1);

        a.Assign(three, 2);

        a += a;
        temp &= (a.SizeInBytes() == 64);
        temp &= (a[0] == 1 && a[1] == 2 && a[2] == 1 && a[3] == 2);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass3 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Append word128\n";
#endif

    //********** Concatenate **********//

    // byte
    try
    {
        SecByteBlock a, b, c;
        temp = true;

        a.Assign((const byte*)"a", 1);
        b.Assign((const byte*)"b", 1);

        c = a + b;
        temp &= (a[0] == 'a');
        temp &= (b[0] == 'b');
        temp &= (c.SizeInBytes() == 2);
        temp &= (c[0] == 'a' && c[1] == 'b');

        a.Assign((const byte*)"ab", 2);
        b.Assign((const byte*)"cd", 2);

        c = a + b;
        temp &= (a[0] == 'a' && a[1] == 'b');
        temp &= (b[0] == 'c' && b[1] == 'd');
        temp &= (c.SizeInBytes() == 4);
        temp &= (c[0] == 'a' && c[1] == 'b' && c[2] == 'c' && c[3] == 'd');
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass4 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Concatenate byte\n";

    // word32
    try
    {
        SecBlock<word32> a, b, c;
        temp = true;

        const word32 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        c = a + b;
        temp &= (a[0] == 1);
        temp &= (b[0] == 2);
        temp &= (c.SizeInBytes() == 8);
        temp &= (c[0] == 1 && c[1] == 2);

        const word32 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        c = a + b;
        temp &= (a[0] == 1 && a[1] == 2);
        temp &= (b[0] == 3 && b[1] == 4);
        temp &= (c.SizeInBytes() == 16);
        temp &= (c[0] == 1 && c[1] == 2 && c[2] == 3 && c[3] == 4);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass4 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Concatenate word32\n";

    // word64
    try
    {
        SecBlock<word64> a, b, c;
        temp = true;

        const word64 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        c = a + b;
        temp &= (a[0] == 1);
        temp &= (b[0] == 2);
        temp &= (c.SizeInBytes() == 16);
        temp &= (c[0] == 1 && c[1] == 2);

        const word64 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        c = a + b;
        temp &= (a[0] == 1 && a[1] == 2);
        temp &= (b[0] == 3 && b[1] == 4);
        temp &= (c.SizeInBytes() == 32);
        temp &= (c[0] == 1 && c[1] == 2 && c[2] == 3 && c[3] == 4);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass4 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Concatenate word64\n";

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    try
    {
        SecBlock<word128> a, b, c;
        temp = true;

        const word128 one[1] = {1}, two[1] = {2};
        a.Assign(one, 1);
        b.Assign(two, 1);

        c = a + b;
        temp &= (a[0] == 1);
        temp &= (b[0] == 2);
        temp &= (c.SizeInBytes() == 32);
        temp &= (c[0] == 1 && c[1] == 2);

        const word128 three[2] = {1,2}, four[2] = {3,4};
        a.Assign(three, 2);
        b.Assign(four, 2);

        c = a + b;
        temp &= (a[0] == 1 && a[1] == 2);
        temp &= (b[0] == 3 && b[1] == 4);
        temp &= (c.SizeInBytes() == 64);
        temp &= (c[0] == 1 && c[1] == 2 && c[2] == 3 && c[3] == 4);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass4 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Concatenate word128\n";
#endif

    //********** Equality **********//

    // byte
    try
    {
        static const byte str1[] = "abcdefghijklmnopqrstuvwxyz";
        static const byte str2[] = "zyxwvutsrqponmlkjihgfedcba";
        static const byte str3[] = "0123456789";

        temp = true;
        SecByteBlock a,b;

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str1, COUNTOF(str1));
        temp &= (a.operator==(b));

        a.Assign(str3, COUNTOF(str3));
        b.Assign(str3, COUNTOF(str3));
        temp &= (a == b);

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str2, COUNTOF(str2));
        temp &= (a.operator!=(b));

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str3, COUNTOF(str3));
        temp &= (a != b);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass5 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Equality byte\n";

    // word32
    try
    {
        static const word32 str1[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97};
        static const word32 str2[] = {97,89,83,79,73,71,67,61,59,53,47,43,41,37,31,29,23,19,17,13,11,7,5,3,2};
        static const word32 str3[] = {0,1,2,3,4,5,6,7,8,9};

        temp = true;
        SecBlock<word32> a,b;

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str1, COUNTOF(str1));
        temp &= (a.operator==(b));

        a.Assign(str3, COUNTOF(str3));
        b.Assign(str3, COUNTOF(str3));
        temp &= (a == b);

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str2, COUNTOF(str2));
        temp &= (a.operator!=(b));

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str3, COUNTOF(str3));
        temp &= (a != b);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass5 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Equality word32\n";

    // word64
    try
    {
        static const word64 str1[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97};
        static const word64 str2[] = {97,89,83,79,73,71,67,61,59,53,47,43,41,37,31,29,23,19,17,13,11,7,5,3,2};
        static const word64 str3[] = {0,1,2,3,4,5,6,7,8,9};

        temp = true;
        SecBlock<word64> a,b;

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str1, COUNTOF(str1));
        temp &= (a.operator==(b));

        a.Assign(str3, COUNTOF(str3));
        b.Assign(str3, COUNTOF(str3));
        temp &= (a == b);

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str2, COUNTOF(str2));
        temp &= (a.operator!=(b));

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str3, COUNTOF(str3));
        temp &= (a != b);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass5 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Equality word64\n";

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    // word128
    try
    {
        static const word128 str1[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97};
        static const word128 str2[] = {97,89,83,79,73,71,67,61,59,53,47,43,41,37,31,29,23,19,17,13,11,7,5,3,2};
        static const word128 str3[] = {0,1,2,3,4,5,6,7,8,9};

        temp = true;
        SecBlock<word128> a,b;

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str1, COUNTOF(str1));
        temp &= (a.operator==(b));

        a.Assign(str3, COUNTOF(str3));
        b.Assign(str3, COUNTOF(str3));
        temp &= (a == b);

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str2, COUNTOF(str2));
        temp &= (a.operator!=(b));

        a.Assign(str1, COUNTOF(str1));
        b.Assign(str3, COUNTOF(str3));
        temp &= (a != b);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }

    pass5 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Equality word128\n";
#endif

    //********** Allocator Size/Overflow **********//

    try
    {
        temp = false;

        AllocatorBase<word32> A;
        const size_t max = A.max_size();
        SecBlock<word32> t(max+1);
    }
    catch(const Exception& /*ex*/)
    {
        temp = true;
    }
    catch(const std::exception& /*ex*/)
    {
        temp = true;
    }

    pass6 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Overflow word32\n";

    try
    {
        temp = false;

        AllocatorBase<word64> A;
        const size_t max = A.max_size();
        SecBlock<word64> t(max+1);
    }
    catch(const Exception& /*ex*/)
    {
        temp = true;
    }
    catch(const std::exception& /*ex*/)
    {
        temp = true;
    }

    pass6 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Overflow word64\n";

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    try
    {
        temp = false;

        AllocatorBase<word128> A;
        const size_t max = A.max_size();
        SecBlock<word128> t(max+1);
    }
    catch(const Exception& /*ex*/)
    {
        temp = true;
    }
    catch(const std::exception& /*ex*/)
    {
        temp = true;
    }

    pass6 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Overflow word128\n";
#endif

    //********** FixedSizeAllocatorWithCleanup and Grow **********//

    // byte
    try
    {
        static const unsigned int SIZE = 8;
        SecBlockWithHint<byte, SIZE> block(SIZE);
        std::memset(block, 0xaa, block.SizeInBytes());

        temp = true;
        block.CleanGrow(SIZE*2);
        temp &= (block.size() == SIZE*2);

        for (size_t i = 0; i < block.size()/2; i++)
            temp &= (block[i] == 0xaa);
        for (size_t i = block.size()/2; i < block.size(); i++)
            temp &= (block[i] == 0);

        block.CleanNew(SIZE*4);
        temp &= (block.size() == SIZE*4);
        for (size_t i = 0; i < block.size(); i++)
            temp &= (block[i] == 0);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }
    catch(const std::exception& /*ex*/)
    {
        temp = false;
    }

    pass7 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  FixedSizeAllocator Grow with byte\n";

    // word32
    try
    {
        static const unsigned int SIZE = 8;
        SecBlockWithHint<word32, SIZE> block(SIZE);
        std::memset(block, 0xaa, block.SizeInBytes());

        temp = true;
        block.CleanGrow(SIZE*2);
        temp &= (block.size() == SIZE*2);

        for (size_t i = 0; i < block.size()/2; i++)
            temp &= (block[i] == 0xaaaaaaaa);

        for (size_t i = block.size()/2; i < block.size(); i++)
            temp &= (block[i] == 0);

        block.CleanNew(SIZE*4);
        temp &= (block.size() == SIZE*4);
        for (size_t i = 0; i < block.size(); i++)
            temp &= (block[i] == 0);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }
    catch(const std::exception& /*ex*/)
    {
        temp = false;
    }

    pass7 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  FixedSizeAllocator Grow with word32\n";

    // word64
    try
    {
        static const unsigned int SIZE = 8;
        SecBlockWithHint<word64, SIZE> block(SIZE);
        std::memset(block, 0xaa, block.SizeInBytes());

        temp = true;
        block.CleanGrow(SIZE*2);
        temp &= (block.size() == SIZE*2);

        for (size_t i = 0; i < block.size()/2; i++)
            temp &= (block[i] == W64LIT(0xaaaaaaaaaaaaaaaa));

        for (size_t i = block.size()/2; i < block.size(); i++)
            temp &= (block[i] == 0);

        block.CleanNew(SIZE*4);
        temp &= (block.size() == SIZE*4);
        for (size_t i = 0; i < block.size(); i++)
            temp &= (block[i] == 0);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }
    catch(const std::exception& /*ex*/)
    {
        temp = false;
    }

    pass7 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  FixedSizeAllocator Grow with word64\n";

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    // word128
    try
    {
        static const unsigned int SIZE = 8;
        SecBlock<word128, AllocatorWithCleanup<word128, true> > block(SIZE);
        std::memset(block, 0xaa, block.SizeInBytes());

        temp = true;
        block.CleanGrow(SIZE*2);
        temp &= (block.size() == SIZE*2);

        for (size_t i = 0; i < block.size()/2; i++)
            temp &= (block[i] == (((word128)W64LIT(0xaaaaaaaaaaaaaaaa) << 64U) | W64LIT(0xaaaaaaaaaaaaaaaa)));

        for (size_t i = block.size()/2; i < block.size(); i++)
            temp &= (block[i] == 0);

        block.CleanNew(SIZE*4);
        temp &= (block.size() == SIZE*4);
        for (size_t i = 0; i < block.size(); i++)
            temp &= (block[i] == 0);
    }
    catch(const Exception& /*ex*/)
    {
        temp = false;
    }
    catch(const std::exception& /*ex*/)
    {
        temp = false;
    }

    pass7 &= temp;
    if (!temp)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  FixedSizeAllocator Grow with word128\n";
#endif

    return pass1 && pass2 && pass3 && pass4 && pass5 && pass6 && pass7;
}
#endif

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
bool TestHuffmanCodes()
{
    std::cout << "\nTesting Huffman codes...\n\n";
    bool pass=true;

    static const size_t nCodes = 30;
    const unsigned int codeCounts[nCodes] = {
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    static const unsigned int maxCodeBits = nCodes >> 1;
    unsigned int codeBits[nCodes] = {
        ~0u, ~0u, ~0u, ~0u, ~0u,
        ~0u, ~0u, ~0u, ~0u, ~0u,
        ~0u, ~0u, ~0u, ~0u, ~0u,
    };

    try
    {
        HuffmanEncoder::GenerateCodeLengths(codeBits, maxCodeBits, codeCounts, nCodes);
    }
    catch(const Exception& /*ex*/)
    {
        pass=false;
    }

    if (!pass)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  GenerateCodeLengths" << std::endl;

    // Try to crash the HuffmanDecoder
    for (unsigned int i=0; i<128; ++i)
    {
        try
        {
            byte data1[0xfff];  // Place on stack, avoid new
            unsigned int data2[0xff];

            unsigned int len1 = GlobalRNG().GenerateWord32(4, 0xfff);
            GlobalRNG().GenerateBlock(data1, len1);
            unsigned int len2 = GlobalRNG().GenerateWord32(4, 0xff);
            GlobalRNG().GenerateBlock((byte*)data2, len2*sizeof(unsigned int));

            ArraySource source(data1, len1, false);
            HuffmanDecoder decoder(data2, len2);

            LowFirstBitReader reader(source);
            unsigned int val;
            for (unsigned int j=0; !source.AnyRetrievable(); ++j)
                decoder.Decode(reader, val);
        }
        catch (const Exception&) {}
    }

    std::cout << "passed:  HuffmanDecoder decode" << std::endl;

    return pass;
}
#endif

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
# if defined(CRYPTOPP_ALTIVEC_AVAILABLE)
bool TestAltivecOps()
{
    std::cout << "\nTesting Altivec operations...\n\n";

    if (HasAltivec() == false)
    {
        std::cout << "\nAltivec not available, skipping test." << std::endl;
        return true;
    }

    // These tests may seem superfluous, but we really want to test the
    // Altivec/POWER4 implementation. That does not happen when POWER7
    // or POWER8 is available because we use POWER7's unaligned loads
    // and stores with POWER8's AES, SHA, etc. These tests enage
    // Altivec/POWER4 without POWER7, like on an old PowerMac.

    //********** Unaligned loads and stores **********//
    bool pass1=true;

    CRYPTOPP_ALIGN_DATA(16)
    byte dest[20], src[20] = {23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4};
    const byte st1[16] = {22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7};
    const byte st2[16] = {21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6};
    const byte st3[16] = {20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5};

    VecStore(VecLoad(src), dest);
    pass1 = (0 == std::memcmp(src, dest, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

    VecStore(VecLoad(src+1), dest+1);
    pass1 = (0 == std::memcmp(st1, dest+1, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

    VecStore(VecLoad(src+2), dest+2);
    pass1 = (0 == std::memcmp(st2, dest+2, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

    VecStore(VecLoad(src+3), dest+3);
    pass1 = (0 == std::memcmp(st3, dest+3, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

    VecStoreBE(VecLoadBE(src), dest);
    pass1 = (0 == std::memcmp(src, dest, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

    VecStoreBE(VecLoadBE(src+1), dest+1);
    pass1 = (0 == std::memcmp(st1, dest+1, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

    VecStoreBE(VecLoadBE(src+2), dest+2);
    pass1 = (0 == std::memcmp(st2, dest+2, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

    VecStoreBE(VecLoadBE(src+3), dest+3);
    pass1 = (0 == std::memcmp(st3, dest+3, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

#if (CRYPTOPP_LITTLE_ENDIAN)
    VecStore(VecLoadBE(src), dest);
    pass1 = (0 != std::memcmp(src, dest, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);

    VecStoreBE(VecLoad(src), dest);
    pass1 = (0 != std::memcmp(src, dest, 16)) && pass1;
    CRYPTOPP_ASSERT(pass1);
#endif

    if (!pass1)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Altivec loads and stores" << std::endl;

    //********** Shifts **********//
    bool pass2=true;

    uint8x16_p val = {0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
                      0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff};

    pass2 = (VecEqual(val, VecShiftLeftOctet<0>(val))) && pass2;
    CRYPTOPP_ASSERT(pass2);
    pass2 = (VecEqual(val, VecShiftRightOctet<0>(val))) && pass2;
    CRYPTOPP_ASSERT(pass2);

    uint8x16_p lsh1 = {0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
                       0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0x00};
    uint8x16_p rsh1 = {0x00,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
                       0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff};

    pass2 = (VecEqual(lsh1, VecShiftLeftOctet<1>(val))) && pass2;
    CRYPTOPP_ASSERT(pass2);
    pass2 = (VecEqual(rsh1, VecShiftRightOctet<1>(val))) && pass2;
    CRYPTOPP_ASSERT(pass2);

    uint8x16_p lsh15 = {0xff,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00};
    uint8x16_p rsh15 = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0xff};

    pass2 = (VecEqual(lsh15, VecShiftLeftOctet<15>(val))) && pass2;
    CRYPTOPP_ASSERT(pass2);
    pass2 = (VecEqual(rsh15, VecShiftRightOctet<15>(val))) && pass2;
    CRYPTOPP_ASSERT(pass2);

    uint8x16_p lsh16 = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00};
    uint8x16_p rsh16 = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00};

    pass2 = (VecEqual(lsh16, VecShiftLeftOctet<16>(val))) && pass2;
    CRYPTOPP_ASSERT(pass2);
    pass2 = (VecEqual(rsh16, VecShiftRightOctet<16>(val))) && pass2;
    CRYPTOPP_ASSERT(pass2);

    if (!pass2)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Altivec left and right shifts" << std::endl;

    //********** Extraction **********//
    bool pass3=true;

    const byte bex1[] = {0x1f,0x1e,0x1d,0x1c, 0x1b,0x1a,0x19,0x18,
                         0x17,0x16,0x15,0x14, 0x13,0x12,0x11,0x10};
    const byte bex2[] = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                         0x17,0x16,0x15,0x14, 0x13,0x12,0x11,0x10};
    const byte bex3[] = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                         0x1f,0x1e,0x1d,0x1c, 0x1b,0x1a,0x19,0x18};

    const uint8x16_p ex1 = (uint8x16_p)VecLoad(bex1);
    const uint8x16_p ex2 = (uint8x16_p)VecLoad(bex2);
    const uint8x16_p ex3 = (uint8x16_p)VecLoad(bex3);

    pass3 = VecEqual(ex2, VecGetLow(ex1)) && pass3;
    CRYPTOPP_ASSERT(pass3);
    pass3 = VecEqual(ex3, VecGetHigh(ex1)) && pass3;
    CRYPTOPP_ASSERT(pass3);

    uint8x16_p ex4 = VecShiftRightOctet<8>(VecShiftLeftOctet<8>(ex1));
    pass3 = VecEqual(ex4, VecGetLow(ex1)) && pass3;
    CRYPTOPP_ASSERT(pass3);
    uint8x16_p ex5 = VecShiftRightOctet<8>(ex1);
    pass3 = VecEqual(ex5, VecGetHigh(ex1)) && pass3;
    CRYPTOPP_ASSERT(pass3);

    if (!pass3)
        std::cout << "FAILED:";
    else
        std::cout << "passed:";
    std::cout << "  Altivec vector extraction" << std::endl;

    return pass1 && pass2 && pass3;
}
#endif
#endif

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
