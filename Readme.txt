Crypto++: free C++ Class Library of Cryptographic Schemes
Version 7.0 - APR/08/2018

Crypto++ Library is a free C++ class library of cryptographic schemes.
Currently the library contains the following algorithms:

                   algorithm type  name

 authenticated encryption schemes  GCM, CCM, EAX

        high speed stream ciphers  ChaCha (8/12/20), Panama, Sosemanuk, Salsa20,
                                   XSalsa20

           AES and AES candidates  AES (Rijndael), RC6, MARS, Twofish, Serpent,
                                   CAST-256

                                   ARIA, IDEA, Blowfish, Triple-DES (DES-EDE2 and
                                   DES-EDE3), Camellia, SEED, Kalyna (128/256/512),
              other block ciphers  RC5, SIMON-64, SIMON-128, SPECK-64, SPECK-128,
                                   Skipjack, SHACAL-2, SM4, Threefish (256/512/1024),
                                   TEA, XTEA

  block cipher modes of operation  ECB, CBC, CBC ciphertext stealing (CTS),
                                   CFB, OFB, counter mode (CTR)

     message authentication codes  BLAKE2s, BLAKE2b, CMAC, CBC-MAC, DMAC, GMAC, HMAC,
                                   Poly1305, SipHash, Two-Track-MAC, VMAC,

                                   BLAKE2s, BLAKE2b, Keccack (F1600), SHA-1,
                   hash functions  SHA-2 (224/256/384/512), SHA-3 (224/256/384/512),
                                   SipHash, SM3, Tiger, RIPEMD-128, RIPEMD-160,
                                   RIPEMD-256, RIPEMD-320, WHIRLPOOL

                                   RSA, DSA, Determinsitic DSA, ElGamal,
          public-key cryptography  Nyberg-Rueppel (NR), Rabin-Williams (RW), LUC,
                                   LUCELG, EC-based German Digital Signature (ECGDSA),
                                   DLIES (variants of DHAES), ESIGN

   padding schemes for public-key  PKCS#1 v2.0, OAEP, PSS, PSSR, IEEE P1363
                          systems  EMSA2 and EMSA5

                                   Diffie-Hellman (DH), Unified Diffie-Hellman
            key agreement schemes  (DH2), Menezes-Qu-Vanstone (MQV), Hashed MQV (HMQV),
                                   Fully Hashed MQV (FHMQV), LUCDIF, XTR-DH

      elliptic curve cryptography  ECDSA, Determinsitic ECDSA, ECNR, ECIES, ECDH, ECMQV

          insecure or obsolescent  MD2, MD4, MD5, Panama Hash, DES, ARC4, SEAL
algorithms retained for backwards  3.0, WAKE-OFB, DESX (DES-XEX3), RC2,
     compatibility and historical  SAFER, 3-WAY, GOST, SHARK, CAST-128, Square
                            value

Other features include:

  * pseudo random number generators (PRNG): ANSI X9.17 appendix C, RandomPool,
    VIA Padlock, RDRAND, RDSEED, NIST Hash and HMAC DRBGs
  * password based key derivation functions: PBKDF1 and PBKDF2 from PKCS #5,
    PBKDF from PKCS #12 appendix B, HKDF from RFC 5869, Scrypt from RFC 7914
  * Shamir's secret sharing scheme and Rabin's information dispersal algorithm
    (IDA)
  * fast multi-precision integer (bignum) and polynomial operations
  * finite field arithmetics, including GF(p) and GF(2^n)
  * prime number generation and verification
  * useful non-cryptographic algorithms
      + DEFLATE (RFC 1951) compression/decompression with gzip (RFC 1952) and
        zlib (RFC 1950) format support
      + Hex, base-32, base-64, URL safe base-64 encoding and decoding
      + 32-bit CRC, CRC-C and Adler32 checksum
  * class wrappers for these platform and operating system features (optional):
      + high resolution timers on Windows, Unix, and Mac OS
      + Berkeley and Windows style sockets
      + Windows named pipes
      + /dev/random, /dev/urandom, /dev/srandom
      + Microsoft's CryptGenRandom or BCryptGenRandom on Windows
  * A high level interface for most of the above, using a filter/pipeline
    metaphor
  * benchmarks and validation testing
  * x86, x64 (x86-64), x32 (ILP32), ARM-32, Aarch32, Aarch64 and Power8 in-core code
    for the commonly used algorithms
      + run-time CPU feature detection and code selection
      + supports GCC-style and MSVC-style inline assembly, and MASM for x64
      + x86, x64 (x86-64), x32 provides MMX, SSE2, and SSE4 implementations
      + ARM-32, Aarch32 and Aarch64 provides NEON, ASIMD and ARMv8 implementations
      + Power8 provides in-core AES using NX Crypto Acceleration

The Crypto++ library was orginally written by Wei Dai. The library is now
maintained by several team members and the community. You are welcome to use it
for any purpose without paying anyone, but see License.txt for the fine print.

The following compilers are supported for this release. Please visit
http://www.cryptopp.com the most up to date build instructions and porting notes.

  * Visual Studio 2003 - 2017
  * GCC 3.3 - 8.0
  * Apple Clang 4.3 - 9.3
  * LLVM Clang 2.9 - 4.0
  * C++Builder 2010
  * Intel C++ Compiler 9 - 16.0
  * Sun Studio 12u1 - 12.5
  * IBM XL C/C++ 10.0 - 13.1

*** Important Usage Notes ***

1. If a constructor for A takes a pointer to an object B (except primitive
types such as int and char), then A owns B and will delete B at A's
destruction.  If a constructor for A takes a reference to an object B,
then the caller retains ownership of B and should not destroy it until
A no longer needs it.

2. Crypto++ is thread safe at the class level. This means you can use
Crypto++ safely in a multithreaded application, but you must provide
synchronization when multiple threads access a common Crypto++ object.

*** MSVC-Specific Information ***

To compile Crypto++ with MSVC, open "cryptest.sln" (for MSVC 2003 - 2015)
and build one or more of the following projects:

cryptest Non-DLL-Import Configuration - This builds the full static library
  along with a full test driver.
cryptest DLL-Import Configuration - This builds a static library containing
  only algorithms not in the DLL, along with a full test driver that uses
  both the DLL and the static library.
cryptdll - This builds the DLL. Please note that if you wish to use Crypto++
  as a FIPS validated module, you must use a pre-built DLL that has undergone
  the FIPS validation process instead of building your own.
dlltest - This builds a sample application that only uses the DLL.

The DLL used to provide FIPS validated cryptography. The library was moved
to the CMVP's <A HREF=
"http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-historical.htm">
Historical Validation List</A>. The library and the DLL are no longer considered
validated. You should no longer use the DLL.

To use the Crypto++ DLL in your application, #include "dll.h" before including
any other Crypto++ header files, and place the DLL in the same directory as
your .exe file. dll.h includes the line #pragma comment(lib, "cryptopp")
so you don't have to explicitly list the import library in your project
settings. To use a static library form of Crypto++, make the "cryptlib"
project a dependency of your application project, or specify it as
an additional library to link with in your project settings.
In either case you should check the compiler options to
make sure that the library and your application are using the same C++
run-time libraries and calling conventions.

*** DLL Memory Management ***

Because it's possible for the Crypto++ DLL to delete objects allocated
by the calling application, they must use the same C++ memory heap. Three
methods are provided to achieve this.
1.  The calling application can tell Crypto++ what heap to use. This method
    is required when the calling application uses a non-standard heap.
2.  Crypto++ can tell the calling application what heap to use. This method
    is required when the calling application uses a statically linked C++ Run
    Time Library. (Method 1 does not work in this case because the Crypto++ DLL
    is initialized before the calling application's heap is initialized.)
3.  Crypto++ can automatically use the heap provided by the calling application's
    dynamically linked C++ Run Time Library. The calling application must
    make sure that the dynamically linked C++ Run Time Library is initialized
    before Crypto++ is loaded. (At this time it is not clear if it is possible
    to control the order in which DLLs are initialized on Windows 9x machines,
    so it might be best to avoid using this method.)

When Crypto++ attaches to a new process, it searches all modules loaded
into the process space for exported functions "GetNewAndDeleteForCryptoPP"
and "SetNewAndDeleteFromCryptoPP". If one of these functions is found,
Crypto++ uses methods 1 or 2, respectively, by calling the function.
Otherwise, method 3 is used.

*** Linux and Unix-like Specific Information ***

A makefile is included for you to compile Crypto++ with GCC and compatibles.
Make sure you are using GNU Make and GNU ld. The make process will produce
two files, libcryptopp.a and cryptest.exe. Run "cryptest.exe v" for the
validation suite and "cryptest.exe tv all" for additional test vectors.

The makefile uses '-DNDEBUG -g2 -O2' CXXFLAGS by default. If you use an
alternate build system, like Autotools or CMake, then ensure the build system
includes '-DNDEBUG' for production or release builds. The Crypto++ library uses
asserts for debugging and diagnostics during development; it does not
rely on them to crash a program at runtime.

If an assert triggers in production software, then unprotected sensitive
information could be egressed from the program to the filesystem or the
platform's error reporting program, like Apport on Ubuntu or CrashReporter
on Apple.

The makefile orders object files to help remediate problems associated with
C++ static initialization order. The library does not use custom linker scripts.
If you use an alternate build system, like Autotools or CMake, and collect source
files into a list, then ensure these three are at the head of the list: 'cryptlib.cpp
cpu.cpp integer.cpp <other sources>'. They should be linked in the same order:
'cryptlib.o cpu.o integer.o <other objects>'.

If your linker supports initialization attributes, like init_priority, then you can
define CRYPTOPP_INIT_PRIORITY to control object initialization order. Set it to a
value like 250. User programs can use CRYPTOPP_USER_PRIORITY to avoid conflicts with
library values. Initialization attributes are more reliable than object file ordering,
but its not ubiquitously supported by linkers.

The makefile links to the static version of the Crypto++ library to avoid binary
planting and other LD_PRELOAD tricks. You should use the static version of the
library in your programs to help avoid unwanted redirections.

*** Side Channel Attacks ***

Crypto++ attempts to resist side channel attacks using various remediations. We
believe the library is hardened but the remdiations may be incomplete. The first
line of defense uses hardware instructions when possible. The library also uses
cache-aware algoirthms and access patterns to minimize leakage. If you suspect
or find an information leak then please report it.

Crypto++ does not enagage Specter remediations at this time. The GCC options for
Specter are -mfunction-return=thunk and -mindirect-branch=thunk, and the library
uses them during testing. If you want the Specter workarounds then add the GCC
options to your CXXFLAGS when building the library.

*** Documentation and Support ***

Crypto++ is documented through inline comments in header files, which are
processed through Doxygen to produce an HTML reference manual. You can find
a link to the manual from http://www.cryptopp.com. Also at that site is
the Crypto++ FAQ, which you should browse through before attempting to
use this library, because it will likely answer many of questions that
may come up. Finally, the site provide the wiki which has many topics
and code examples.

If you run into any problems, please try the Crypto++ mailing list.
The subscription information and the list archive are available on
http://www.cryptopp.com.

*** Source Code and Contributing ***

The source code and its planned changes are available at the following locations.

  * The Crypto++ GitHub repository allows you to view the latest (unreleased)
    Crypto++ source code via the Linux kernel's git beginning around June 2015.
    Its also serves as an incubator to nuture and grow the library.
  * The former Crypto++ SourceForge repository allows you to view the Crypto++
    source code via Apache's subversion until about July 2015. At that time,
    SourceForge had infrastructure problems and a cutover to GutHub was performed.
  * The Roadmap on the wiki provides the general direction the library is heading.
    It includes planned features and releases, and even some wishlist items.

Contributions of all types are welcomed. Contributions include the following.

  * Bug finding and fixes
  * Features and enhancements
  * Test scripts and test cases
  * Branch and release testing
  * Documentation and updates

If you think you have found a bug in the library, then you should discuss it on the
Users mailing list. Discussing it will help bring the issue to the attention of folks
who can help resolve the issue. If you want to contribute a bug fix to the library,
then make a Pull Request or make a Diff available somewhere. Also see Bug Reports on
the wiki.

Features and enhancements are welcomend additions to the library. This category tends
to be time consuming because algorithms and their test cases need to be reviewed and
merged. Please be mindful of the test cases, and attempt to procure them from an
independent source.

The library cherishes test scripts and test cases. They ensure the library is fit and
they help uncover issues with the library before users experience them. If you have
some time, then write some test cases, especially the ones that are intended to break
things.

Branch and release testing is your chance to ensure Master (and planned merges) meets
your expectations and perform as expected. If you have a few spare cycles, then please
test Master on your favorite platform. We need more testing on MinGW, Windows Phone,
Windows Store, Solaris 10 (and below), and modern iOS and OS X (including TV and
Watch builds).

Documentation and updates includes both the inline source code annotations using
Doxygen, and the online information provided in the wiki. The wiki is more verbose and
usually provides more contextual information than the API reference. Besides testing,
documentation is one of the highest returns on investment.

*** History ***

The items in this section comprise the most recent history. Please see History.txt
for the record back to Crypto++ 1.0.

7.0.0 - April 8, 2018
      - major release, recompile of programs required
      - expanded community input and support
         * 48 unique contributors as of this release
      - fix incorrect result when using Integer::ModInverse
         * may be CVE worthy, but request was not submitted
      - fix ARIA/CTR bus error on Sparc64
      - fix incorrect result when using a_exp_b_mod_c
      - fix undeclared identifier uint32_t on early Visual Studio
      - fix iPhoneSimulator build on i386
      - fix incorrect adler32 in ZlibDecompressor
      - fix Power7 test using PPC_FEATURE_ARCH_2_06
      - workaround incorrect Glibc sysconf return value on ppc64-le
      - add KeyDerivationFunction interface
      - add scrypt key derivation function
      - add Salsa20_Core transform callable from outside class
      - add sbyte, sword16, sword32 and sword64
      - remove s_nullNameValuePairs from unnamed namespace
      - ported to MSVC 2017, Xcode 9.3, Sun Studio 12.5, GCC 8.0.1,
        MacPorts GCC 7.0, Clang 4.0, Intel C++ 17.00, IBM XL C/C++ 13.1

6.1.0 - February 22, 2018
      - minor release, maintenance items
      - expanded community input and support
         * 46 unique contributors as of this release
      - use 2048-bit modulus default for DSA
      - fix build under Linuxbrew
      - use /bin/sh in GNUmakefile
      - fix missing flags for SIMON and SPECK in GNUMakefile-cross
      - fix ARM and MinGW misdetection
      - port setenv-android.sh to latest NDK
      - fix Clang check for C++11 lambdas
      - Simon and Speck to little-endian implementation
      - use LIB_MAJOR for ABI compatibility
      - fix ODR violation in AdvancedProcessBlocks_{ARCH} templates
      - handle C++17 std::uncaught_exceptions
      - ported to MSVC 2017, Xcode 8.1, Sun Studio 12.5, GCC 8.0.1,
        MacPorts GCC 7.0, Clang 4.0, Intel C++ 17.00, IBM XL C/C++ 13.1

6.0.0 - January 22, 2018
      - major release, recompile of programs required
      - expanded community input and support
         * 43 unique contributors as of this release
      - fixed CVE-2016-9939 (Issue 346, transient DoS)
      - fixed CVE-2017-9434 (Issue 414, misidentified memory error)
      - converted to BASE+SIMD implementation
         * BASE provides an architecture neutral C++ implementation
         * SIMD provides architecture specific hardware acceleration
      - improved PowerPC Power4, Power7 and Power8 support
      - added ARIA, EC German DSA, Deterministic signatures (RFC 6979),
        Kalyna, NIST Hash and HMAC DRBG, Padlock RNG, Poly1305, SipHash,
        Simon, Speck, SM3, SM4, Threefish algorithms
      - added NaCl interface from the compact library
         * x25519 key exhange and ed25519 signing provided through NaCl interface
      - improved Testing and QA
      - ported to MSVC 2017, Xcode 8.1, Sun Studio 12.5, GCC 7.3,
        MacPorts GCC 7.0, Clang 4.0, Intel C++ 17.00, IBM XL C/C++ 13.1

5.6.5 - October 11, 2016
      - maintenance release, recompile of programs recommended
      - expanded community input and support
         * 25 unique contributors as of this release
      - fixed CVE-2016-7420 (Issue 277, document NDEBUG for production/release)
      - fixed CVE-2016-7544 (Issue 302, avoid _malloca and _freea)
      - shipped library in recommended state
         * backwards compatibility achieved with <config.compat>
      - Visual Studio project file cleanup
         * improved X86 and X64 MSBuild support
         * added ARM-based MSBuild awareness
      - improved Testing and QA
         * expanded platforms and compilers
         * expanded Coverity into OS X and Windows platforms
         * added Windows test scripts using Strawberry Perl
      - ported to MSVC 2015 SP3, Xcode 7.3, Sun Studio 12.5, GCC 7.0,
        MacPorts GCC 7.0, Clang 3.8, Intel C++ 17.00

5.6.4 - September 11, 2016
      - maintenance release, honored API/ABI/Versioning requirements
      - expanded community input and support
         * 22 unique contributors for this release
      - fixed CVE-2016-3995
      - changed SHA3 to FIPS 202 (F1600, XOF d=0x06)
      - added Keccak (F1600, XOF d=0x01)
      - added ChaCha (ChaCha8/12/20)
      - added HMQV and FHMQV
         * Hashed and Fully Hashed MQV
      - added BLAKE2 (BLAKE2s and BLAKE2b)
         * C++, SSE2, SSE4, ARM NEON and ARMv8 ASIMD
      - added CRC32-C
         * C/C++, Amd64 CRC, and ARMv8 CRC
      - improved Rabin-William signatures
         * Tweaked roots <em>e</em> and <em>f</em>
      - improved C++11 support
         * atomics, threads and fences
         * alginof, alignas
         * constexpr
         * noexcept
      - improved GCM mode
         * ARM NEON and ARMv8 ASIMD
         * ARMv8 carry-less multiply
      - improved Windows 8 and 10 support
         * Windows Phone, Universal Windows Platform, Windows Store
      - improved MIPS, ARMv7 and ARMv8 support
         * added scripts setenv-{android|embedded|ios}.sh for GNUmakefile-cross
         * aggressive use of -march=<arch> and -mfpu=<fpu> in cryptest.sh
      - improved build systems
         * Visual Studio 2010 default
         * added CMake support (lacks FindCryptopp.cmake)
         * archived VC++ 5/0/6.0 project files (vc60.zip)
         * archived VS2005 project files (vs2005.zip)
         * archived Borland project files (bds10.zip)
      - improved Testing and QA
         * expanded platforms and compilers
         * added code generation tests based on CPU features
         * added C++03, C++11, C++14, C++17 testing
         * added -O3, -O5, -Ofast and -Os testing
      - ported to MSVC 2015 SP3, Xcode 9.0, Sun Studio 12.5, GCC 7.0,
        MacPorts GCC 7.0, Clang 3.8, Intel C++ 17.00

June 2015 - Changing of the guard. Wei Dai turned the library over to the
        community. The first community release was Crypto++ 5.6.3. Wei is
        no longer involved with the daily operations of the project. Wei
        still provides guidance when we have questions.

Originally written by Wei Dai, maintained by the Crypto++ Project
