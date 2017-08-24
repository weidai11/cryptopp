Crypto++: free C++ Class Library of Cryptographic Schemes
Version 5.6.5 - OCT/11/2016

Crypto++ Library is a free C++ class library of cryptographic schemes.
Currently the library contains the following algorithms:

                   algorithm type  name

 authenticated encryption schemes  GCM, CCM, EAX, OCB

        high speed stream ciphers  ChaCha (ChaCha8/12/20), Panama, Sosemanuk,
                                   Salsa20, XSalsa20

           AES and AES candidates  AES (Rijndael), RC6, MARS, Twofish, Serpent,
                                   CAST-256

                                   ARIA, IDEA, Triple-DES (DES-EDE2 and DES-EDE3),
              other block ciphers  Camellia, SEED, Kalyna, RC5, Blowfish, TEA, XTEA,
                                   Threefish, Skipjack, SHACAL-2

  block cipher modes of operation  ECB, CBC, CBC ciphertext stealing (CTS),
                                   CFB, OFB, counter mode (CTR)

     message authentication codes  VMAC, HMAC, GMAC, CMAC, CBC-MAC, DMAC,
                                   Two-Track-MAC, BLAKE2s, BLAKE2b

                                   BLAKE2s, BLAKE2b, Keccack (F1600) SHA-1, SHA-2
                   hash functions  (SHA-224, SHA-256, SHA-384, and SHA-512), SHA-3,
                                   Tiger, WHIRLPOOL, RIPEMD-128, RIPEMD-256,
                                   RIPEMD-160, RIPEMD-320

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
    PBKDF from PKCS #12 appendix B, HKDF from RFC 5869
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
      + Microsoft's CryptGenRandom on Windows
  * A high level interface for most of the above, using a filter/pipeline
    metaphor
  * benchmarks and validation testing
  * x86, x64 (x86-64), x32 (ILP32), ARM-32, Aarch32 and Aarch64 code for the commonly
    used algorithms
      + run-time CPU feature detection and code selection</li>
      + supports GCC-style and MSVC-style inline assembly, and MASM for x64
      + x86, x64 (x86-64), x32 provides MMX, SSE2, and SSE4 implementations
      + ARM-32, Aarch32 and Aarch64 provides NEON, ASIMD and ARMv8 implementations

The Crypto++ library was orginally written by Wei Dai. The library is now
maintained by several team members and the community. You are welcome to use it
for any purpose without paying anyone, but see License.txt for the fine print.

The following compilers are supported for this release. Please visit
http://www.cryptopp.com the most up to date build instructions and porting notes.

  * Visual Studio 2003 - 2015
  * GCC 3.3 - 7.1
  * Apple Clang 4.3 - 8.3
  * LLVM Clang 2.9 - 4.0
  * C++Builder 2010
  * Intel C++ Compiler 9 - 16.0
  * Sun Studio 12u1 - 12.5

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

1.0 - First public release.  Withdrawn at the request of RSA DSI.
    - included Blowfish, BBS, DES, DH, Diamond, DSA, ElGamal, IDEA,
      MD5, RC4, RC5, RSA, SHA, WAKE, secret sharing, DEFLATE compression
    - had a serious bug in the RSA key generation code.

1.1 - Removed RSA, RC4, RC5
    - Disabled calls to RSAREF's non-public functions
    - Minor bugs fixed

2.0 - a completely new, faster multiprecision integer class
    - added MD5-MAC, HAVAL, 3-WAY, TEA, SAFER, LUC, Rabin, BlumGoldwasser,
      elliptic curve algorithms
    - added the Lucas strong probable primality test
    - ElGamal encryption and signature schemes modified to avoid weaknesses
    - Diamond changed to Diamond2 because of key schedule weakness
    - fixed bug in WAKE key setup
    - SHS class renamed to SHA
    - lots of miscellaneous optimizations

2.1 - added Tiger, HMAC, GOST, RIPE-MD160, LUCELG, LUCDIF, XOR-MAC,
      OAEP, PSSR, SHARK
    - added precomputation to DH, ElGamal, DSA, and elliptic curve algorithms
    - added back RC5 and a new RSA
    - optimizations in elliptic curves over GF(p)
    - changed Rabin to use OAEP and PSSR
    - changed many classes to allow copy constructors to work correctly
    - improved exception generation and handling

2.2 - added SEAL, CAST-128, Square
    - fixed bug in HAVAL (padding problem)
    - fixed bug in triple-DES (decryption order was reversed)
    - fixed bug in RC5 (couldn't handle key length not a multiple of 4)
    - changed HMAC to conform to RFC-2104 (which is not compatible
      with the original HMAC)
    - changed secret sharing and information dispersal to use GF(2^32)
      instead of GF(65521)
    - removed zero knowledge prover/verifier for graph isomorphism
    - removed several utility classes in favor of the C++ standard library

2.3 - ported to EGCS
    - fixed incomplete workaround of min/max conflict in MSVC

3.0 - placed all names into the "CryptoPP" namespace
    - added MD2, RC2, RC6, MARS, RW, DH2, MQV, ECDHC, CBC-CTS
    - added abstract base classes PK_SimpleKeyAgreementDomain and
      PK_AuthenticatedKeyAgreementDomain
    - changed DH and LUCDIF to implement the PK_SimpleKeyAgreementDomain
      interface and to perform domain parameter and key validation
    - changed interfaces of PK_Signer and PK_Verifier to sign and verify
      messages instead of message digests
    - changed OAEP to conform to PKCS#1 v2.0
    - changed benchmark code to produce HTML tables as output
    - changed PSSR to track IEEE P1363a
    - renamed ElGamalSignature to NR and changed it to track IEEE P1363
    - renamed ECKEP to ECMQVC and changed it to track IEEE P1363
    - renamed several other classes for clarity
    - removed support for calling RSAREF
    - removed option to compile old SHA (SHA-0)
    - removed option not to throw exceptions

3.1 - added ARC4, Rijndael, Twofish, Serpent, CBC-MAC, DMAC
    - added interface for querying supported key lengths of symmetric ciphers
      and MACs
    - added sample code for RSA signature and verification
    - changed CBC-CTS to be compatible with RFC 2040
    - updated SEAL to version 3.0 of the cipher specification
    - optimized multiprecision squaring and elliptic curves over GF(p)
    - fixed bug in MARS key setup
    - fixed bug with attaching objects to Deflator

3.2 - added DES-XEX3, ECDSA, DefaultEncryptorWithMAC
    - renamed DES-EDE to DES-EDE2 and TripleDES to DES-EDE3
    - optimized ARC4
    - generalized DSA to allow keys longer than 1024 bits
    - fixed bugs in GF2N and ModularArithmetic that can cause calculation errors
    - fixed crashing bug in Inflator when given invalid inputs
    - fixed endian bug in Serpent
    - fixed padding bug in Tiger

4.0 - added Skipjack, CAST-256, Panama, SHA-2 (SHA-256, SHA-384, and SHA-512),
      and XTR-DH
    - added a faster variant of Rabin's Information Dispersal Algorithm (IDA)
    - added class wrappers for these operating system features:
      - high resolution timers on Windows, Unix, and MacOS
      - Berkeley and Windows style sockets
      - Windows named pipes
      - /dev/random and /dev/urandom on Linux and FreeBSD
      - Microsoft's CryptGenRandom on Windows
    - added support for SEC 1 elliptic curve key format and compressed points
    - added support for X.509 public key format (subjectPublicKeyInfo) for
      RSA, DSA, and elliptic curve schemes
    - added support for DER and OpenPGP signature format for DSA
    - added support for ZLIB compressed data format (RFC 1950)
    - changed elliptic curve encryption to use ECIES (as defined in SEC 1)
    - changed MARS key schedule to reflect the latest specification
    - changed BufferedTransformation interface to support multiple channels
      and messages
    - changed CAST and SHA-1 implementations to use public domain source code
    - fixed bug in StringSource
    - optmized multi-precision integer code for better performance

4.1 - added more support for the recommended elliptic curve parameters in SEC 2
    - added Panama MAC, MARC4
    - added IV stealing feature to CTS mode
    - added support for PKCS #8 private key format for RSA, DSA, and elliptic
      curve schemes
    - changed Deflate, MD5, Rijndael, and Twofish to use public domain code
    - fixed a bug with flushing compressed streams
    - fixed a bug with decompressing stored blocks
    - fixed a bug with EC point decompression using non-trinomial basis
    - fixed a bug in NetworkSource::GeneralPump()
    - fixed a performance issue with EC over GF(p) decryption
    - fixed syntax to allow GCC to compile without -fpermissive
    - relaxed some restrictions in the license

4.2 - added support for longer HMAC keys
    - added MD4 (which is not secure so use for compatibility purposes only)
    - added compatibility fixes/workarounds for STLport 4.5, GCC 3.0.2,
      and MSVC 7.0
    - changed MD2 to use public domain code
    - fixed a bug with decompressing multiple messages with the same object
    - fixed a bug in CBC-MAC with MACing multiple messages with the same object
    - fixed a bug in RC5 and RC6 with zero-length keys
    - fixed a bug in Adler32 where incorrect checksum may be generated

5.0 - added ESIGN, DLIES, WAKE-OFB, PBKDF1 and PBKDF2 from PKCS #5
    - added key validation for encryption and signature public/private keys
    - renamed StreamCipher interface to SymmetricCipher, which is now implemented
      by both stream ciphers and block cipher modes including ECB and CBC
    - added keying interfaces to support resetting of keys and IVs without
      having to destroy and recreate objects
    - changed filter interface to support non-blocking input/output
    - changed SocketSource and SocketSink to use overlapped I/O on Microsoft Windows
    - grouped related classes inside structs to help templates, for example
      AESEncryption and AESDecryption are now AES::Encryption and AES::Decryption
    - where possible, typedefs have been added to improve backwards
      compatibility when the CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY macro is defined
    - changed Serpent, HAVAL and IDEA to use public domain code
    - implemented SSE2 optimizations for Integer operations
    - fixed a bug in HMAC::TruncatedFinal()
    - fixed SKIPJACK byte ordering following NIST clarification dated 5/9/02

5.01 - added known answer test for X9.17 RNG in FIPS 140 power-up self test
     - submitted to NIST/CSE, but not publicly released

5.02 - changed EDC test to MAC integrity check using HMAC/SHA1
     - improved performance of integrity check
     - added blinding to defend against RSA timing attack

5.03 - created DLL version of Crypto++ for FIPS 140-2 validation
     - fixed vulnerabilities in GetNextIV for CTR and OFB modes

5.0.4 - Removed DES, SHA-256, SHA-384, SHA-512 from DLL

5.1 - added PSS padding and changed PSSR to track IEEE P1363a draft standard
    - added blinding for RSA and Rabin to defend against timing attacks
      on decryption operations
    - changed signing and decryption APIs to support the above
    - changed WaitObjectContainer to allow waiting for more than 64
      objects at a time on Win32 platforms
    - fixed a bug in CBC and ECB modes with processing non-aligned data
    - fixed standard conformance bugs in DLIES (DHAES mode) and RW/EMSA2
      signature scheme (these fixes are not backwards compatible)
    - fixed a number of compiler warnings, minor bugs, and portability problems
    - removed Sapphire

5.2 - merged in changes for 5.01 - 5.0.4
    - added support for using encoding parameters and key derivation parameters
      with public key encryption (implemented by OAEP and DL/ECIES)
    - added Camellia, SHACAL-2, Two-Track-MAC, Whirlpool, RIPEMD-320,
      RIPEMD-128, RIPEMD-256, Base-32 coding, FIPS variant of CFB mode
    - added ThreadUserTimer for timing thread CPU usage
    - added option for password-based key derivation functions
      to iterate until a mimimum elapsed thread CPU time is reached
    - added option (on by default) for DEFLATE compression to detect
      uncompressible files and process them more quickly
    - improved compatibility and performance on 64-bit platforms,
      including Alpha, IA-64, x86-64, PPC64, Sparc64, and MIPS64
    - fixed ONE_AND_ZEROS_PADDING to use 0x80 instead 0x01 as padding.
    - fixed encoding/decoding of PKCS #8 privateKeyInfo to properly
      handle optional attributes

5.2.1 - fixed bug in the "dlltest" DLL testing program
      - fixed compiling with STLport using VC .NET
      - fixed compiling with -fPIC using GCC
      - fixed compiling with -msse2 on systems without memalign()
      - fixed inability to instantiate PanamaMAC
      - fixed problems with inline documentation

5.2.2 - added SHA-224
      - put SHA-256, SHA-384, SHA-512, RSASSA-PSS into DLL

5.2.3 - fixed issues with FIPS algorithm test vectors
      - put RSASSA-ISO into DLL

5.3 - ported to MSVC 2005 with support for x86-64
    - added defense against AES timing attacks, and more AES test vectors
    - changed StaticAlgorithmName() of Rijndael to "AES", CTR to "CTR"

5.4 - added Salsa20
    - updated Whirlpool to version 3.0
    - ported to GCC 4.1, Sun C++ 5.8, and Borland C++Builder 2006

5.5 - added VMAC and Sosemanuk (with x86-64 and SSE2 assembly)
    - improved speed of integer arithmetic, AES, SHA-512, Tiger, Salsa20,
      Whirlpool, and PANAMA cipher using assembly (x86-64, MMX, SSE2)
    - optimized Camellia and added defense against timing attacks
    - updated benchmarks code to show cycles per byte and to time key/IV setup
    - started using OpenMP for increased multi-core speed
    - enabled GCC optimization flags by default in GNUmakefile
    - added blinding and computational error checking for RW signing
    - changed RandomPool, X917RNG, GetNextIV, DSA/NR/ECDSA/ECNR to reduce
      the risk of reusing random numbers and IVs after virtual machine state
      rollback
    - changed default FIPS mode RNG from AutoSeededX917RNG<DES_EDE3> to
      AutoSeededX917RNG<AES>
    - fixed PANAMA cipher interface to accept 256-bit key and 256-bit IV
    - moved MD2, MD4, MD5, PanamaHash, ARC4, WAKE_CFB into the namespace "Weak"
    - removed HAVAL, MD5-MAC, XMAC

5.5.1 - fixed VMAC validation failure on 32-bit big-endian machines

5.5.2 - ported x64 assembly language code for AES, Salsa20, Sosemanuk, and Panama
        to MSVC 2005 (using MASM since MSVC doesn't support inline assembly on x64)
      - fixed Salsa20 initialization crash on non-SSE2 machines
      - fixed Whirlpool crash on Pentium 2 machines
      - fixed possible branch prediction analysis (BPA) vulnerability in
        MontgomeryReduce(), which may affect security of RSA, RW, LUC
      - fixed link error with MSVC 2003 when using "debug DLL" form of runtime library
      - fixed crash in SSE2_Add on P4 machines when compiled with
        MSVC 6.0 SP5 with Processor Pack
      - ported to MSVC 2008, GCC 4.2, Sun CC 5.9, Intel C++ Compiler 10.0,
        and Borland C++Builder 2007

5.6.0 - added AuthenticatedSymmetricCipher interface class and Filter wrappers
      - added CCM, GCM (with SSE2 assembly), EAX, CMAC, XSalsa20, and SEED
      - added support for variable length IVs
      - added OIDs for Brainpool elliptic curve parameters
      - improved AES and SHA-256 speed on x86 and x64
      - changed BlockTransformation interface to no longer assume data alignment
      - fixed incorrect VMAC computation on message lengths
        that are >64 mod 128 (x86 assembly version is not affected)
      - fixed compiler error in vmac.cpp on x86 with GCC -fPIC
      - fixed run-time validation error on x86-64 with GCC 4.3.2 -O2
      - fixed HashFilter bug when putMessage=true
      - fixed AES-CTR data alignment bug that causes incorrect encryption on ARM
      - removed WORD64_AVAILABLE; compiler support for 64-bit int is now required
      - ported to GCC 4.3, C++Builder 2009, Sun CC 5.10, Intel C++ Compiler 11

5.6.1 - added support for AES-NI and CLMUL instruction sets in AES and GMAC/GCM
      - removed WAKE-CFB
      - fixed several bugs in the SHA-256 x86/x64 assembly code:
          * incorrect hash on non-SSE2 x86 machines on non-aligned input
          * incorrect hash on x86 machines when input crosses 0x80000000
          * incorrect hash on x64 when compiled with GCC with optimizations enabled
      - fixed bugs in AES x86 and x64 assembly causing crashes in some MSVC build configurations
      - switched to a public domain implementation of MARS
      - ported to MSVC 2010, GCC 4.5.1, Sun Studio 12u1, C++Builder 2010, Intel C++ Compiler 11.1
      - renamed the MSVC DLL project to "cryptopp" for compatibility with MSVC 2010

5.6.2 - changed license to Boost Software License 1.0
      - added SHA-3 (Keccak)
      - updated DSA to FIPS 186-3 (see DSA2 class)
      - fixed Blowfish minimum keylength to be 4 bytes (32 bits)
      - fixed Salsa validation failure when compiling with GCC 4.6
      - fixed infinite recursion when on x64, assembly disabled, and no AESNI
      - ported to MSVC 2012, GCC 4.7, Clang 3.2, Solaris Studio 12.3, Intel C++ Compiler 13.0

5.6.3 - maintenance release, honored API/ABI/Versioning requirements
      - expanded processes to include community and its input
          * 12 unique contributors for this release
      - fixed CVE-2015-2141
      - cleared most Undefined Behavior Sanitizer (UBsan) findings
      - cleared all Address Sanitizer (Asan) findings
      - cleared all Valgrind findings
      - cleared all Coverity findings
      - cleared all Enterprise Analysis (/analyze) findings
      - cleared most GCC warnings with -Wall
      - cleared most Clang warnings with -Wall
      - cleared most MSVC warnings with /W4
      - added -fPIC 64-bit builds. Off by default for i386
      - added HKDF class from RFC 5868
      - switched to member_ptr due to C++ 11 warnings for auto_ptr
      - initialization of C++ static objects, off by default
          * GCC and init_priotirty/constructor attributes
          * MSVC and init_seg(lib)
          * CRYPTOPP_INIT_PRIORITY disabled by default, but available
      - improved OS X support
      - improved GNUmakefile support for Testing and QA
      - added self tests for additional Testing and QA
      - added cryptest.sh for systematic Testing and QA
      - added GNU Gold linker support
      - added Visual Studio 2010 solution and project files in vs2010.zip
      - added Clang integrated assembler support
      - unconditionally define CRYPTOPP_NO_UNALIGNED_DATA_ACCESS for Makefile
        target 'ubsan' and at -O3 due to GCC vectorization on x86 and x86_64
      - workaround ARMEL/GCC 5.2 bug and failed self test
      - fixed crash in MQV due to GCC 4.9+ and inlining
      - fixed hang in SHA due to GCC 4.9+ and inlining
      - fixed missing rdtables::Te under VS with ALIGNED_DATA_ACCESS
      - fixed S/390 and big endian feature detection
      - fixed S/390 and int128_t/uint128_t detection
      - fixed X32 (ILP32) feature detection
      - removed  _CRT_SECURE_NO_DEPRECATE for Microsoft platforms
      - utilized bound checking interfaces from ISO/IEC TR 24772 when available
      - improved ARM, ARM64, MIPS, MIPS64, S/390 and X32 (ILP32) support
      - introduced CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
      - added additional Doxygen-based documentation
      - ported to MSVC 2015, Xcode 7.2, GCC 5.2, Clang 3.7, Intel C++ 16.00

5.6.4 - maintenance release, honored API/ABI/Versioning requirements
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
      - ported to MSVC 2015 SP3, Xcode 9.0, Sun Studio 12.5, GCC 7.0, MacPorts GCC 7.0, Clang 3.8, Intel C++ 17.00

5.6.5 - maintenance release, recompile of programs recommended
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
      - ported to MSVC 2015 SP3, Xcode 7.3, Sun Studio 12.5, GCC 7.0, MacPorts GCC 7.0, Clang 3.8, Intel C++ 17.00

Written by Wei Dai and the Crypto++ Project
