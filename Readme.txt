Crypto++: a C++ Class Library of Cryptographic Schemes
Version 5.3 (in development)

This library includes:

- a class hierarchy with an API defined by abstract base classes
- AES (Rijndael) and AES candidates: RC6, MARS, Twofish, Serpent,
  CAST-256
- other symmetric block ciphers: IDEA, DES, Triple-DES (DES-EDE2
  and DES-EDE3), DESX (DES-XEX3), RC2, RC5, Blowfish, Diamond2,
  TEA, SAFER, 3-WAY, GOST, SHARK, CAST-128, Square, Skipjack,
  Camellia, SHACAL-2
- generic cipher modes: ECB, CBC, CBC ciphertext stealing (CTS),
  CFB, OFB, counter mode (CTR)
- stream ciphers: Panama, ARC4, SEAL, WAKE, WAKE-OFB,
  BlumBlumShub
- public key cryptography: RSA, DSA, ElGamal, Nyberg-Rueppel
  (NR), Rabin, Rabin-Williams (RW), LUC, LUCELG, DLIES (variants
  of DHAES), ESIGN
- padding schemes for public-key systems: PKCS#1 v2.0, OAEP,
  PSSR, IEEE P1363 EMSA2
- key agreement schemes: Diffie-Hellman (DH), Unified Diffie-
  Hellman (DH2), Menezes-Qu-Vanstone (MQV), LUCDIF, XTR-DH
- elliptic curve cryptography: ECDSA, ECNR, ECIES, ECDH, ECMQV
- one-way hash functions: SHA-1, MD2, MD4, MD5, HAVAL, RIPEMD-
  128, RIPEMD-256, RIPEMD-160, RIPEMD-320, Tiger, SHA-2 (SHA-256,
  SHA-384, and SHA-512), Panama, Whirlpool
- message authentication codes: MD5-MAC, HMAC, XOR-MAC, CBC-MAC,
  DMAC, Two-Track-MAC
- cipher constructions based on hash functions: Luby-Rackoff, MDC
- pseudo random number generators (PRNG): ANSI X9.17 appendix C,
  PGP's RandPool
- password based key derivation functions: PBKDF1 and PBKDF2 from
  PKCS #5
- Shamir's secret sharing scheme and Rabin's information
  dispersal algorithm (IDA)
- DEFLATE (RFC 1951) compression/decompression with gzip (RFC
  1952) and zlib (RFC 1950) format support
- fast multi-precision integer (bignum) and polynomial
  operations, with SSE2 optimizations for Pentium 4 processors
- finite field arithmetics, including GF(p) and GF(2^n)
- prime number generation and verification
- various miscellaneous modules such as base 64 coding and 32-bit
  CRC
- class wrappers for these operating system features (optional):
	- high resolution timers on Windows, Unix, and MacOS
	- Berkeley and Windows style sockets
	- Windows named pipes
	- /dev/random and /dev/urandom on Linux and FreeBSD
	- Microsoft's CryptGenRandom on Windows
- A high level interface for most of the above, using a
  filter/pipeline metaphor
- benchmarks and validation testing
- FIPS 140-2 Validated

You are welcome to use it for any purpose without paying me, but see
license.txt for the fine print.

This version of Crypto++ has been compiled successfully with MSVC 6.0 SP5
and .NET 2003 on Windows XP, GCC 2.95.4 on FreeBSD 4.6, GCC 2.95.3 on
Linux 2.4 and SunOS 5.8, GCC 3.4 on Cygwin 1.5.10, and Metrowerks
CodeWarrior 8.3 for Windows and MacOS.

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

On Windows, Crypto++ can be compiled into 3 forms: a static library
including all algorithms, a DLL with only FIPS Approved algorithms, and
a static library with only algorithms not in the DLL.
(FIPS Approved means Approved according to the FIPS 140-2 standard.)
The DLL may be used by itself, or it may be used together with the second
form of the static library. MSVC project files are included to build
all three forms, and sample applications using each of the three forms
are also included.

To compile Crypto++ with MSVC, open the "cryptest.dsw" workspace file
and build one or more of the following projects:

cryptdll - This builds the DLL. Please note that if you wish to use Crypto++
  as a FIPS validated module, you must use a pre-built DLL that has undergone
  the FIPS validation process instead of building your own.
dlltest - This builds a sample application that only uses the DLL.
cryptest Non-DLL-Import Configuration - This builds the full static library
  along with a full test driver.
cryptest DLL-Import Configuration - This builds a static library containing
  only algorithms not in the DLL, along with a full test driver that uses
  both the DLL and the static library.

To use the Crypto++ DLL in your application, #include "dll.h" before including
any other Crypto++ header files, and place the DLL in the same directory as
your .exe file. dll.h includes the line #pragma comment(lib, "cryptopp")
so you don't have to explicitly list the import library in your project
settings. To use a static library form of Crypto++, specify it as
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

*** GCC-Specific Information ***

A makefile is included for you to compile Crypto++ with GCC. Make sure
you are using GNU Make and GNU ld. The make process will produce two files,
libcryptopp.a and cryptest.exe. Run "cryptest.exe v" for the validation
suite.

*** Documentation and Support ***

Crypto++ is documented through inline comments in header files, which are
processed through Doxygen to produce an HTML reference manual. You can find
a link to the manual from http://www.cryptopp.com. Also at that site is
the Crypto++ FAQ, which you should browse through before attempting to 
use this library, because it will likely answer many of questions that
may come up.

If you run into any problems, please try the Crypto++ mailing list.
The subscription information and the list archive are available on
http://www.cryptopp.com. You can also email me directly at
cryptopp@weidai.com, but you will probably get a faster response through
the mailing list.

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

5.3 - Ported to MSVC .NET 2005 with support for x86-64
    - Added defense against AES timing attacks, and more AES test vectors
    - Changed StaticAlgorithmName() of Rijndael to "AES", CTR to "CTR"

Written by Wei Dai
