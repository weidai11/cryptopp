// validat0.cpp - originally written and placed in the public domain by Wei Dai and Jeffrey Walton
//                Routines in this source file are only tested in Debug builds.
//                Source files split in July 2018 to expedite compiles.

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "cpu.h"
#include "validate.h"

#include "asn.h"
#include "gf2n.h"
#include "default.h"
#include "integer.h"
#include "polynomi.h"
#include "channels.h"

#include "ida.h"
#include "gzip.h"
#include "zlib.h"

//curve25519
#include "xed25519.h"
#include "donna.h"
#include "naclite.h"

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
// Issue 64: "PolynomialMod2::operator<<=", http://github.com/weidai11/cryptopp/issues/64
bool TestPolynomialMod2()
{
    std::cout << "\nTesting PolynomialMod2 bit operations...\n\n";
    bool pass1 = true, pass2 = true, pass3 = true;

    const unsigned int start = 0;
    const unsigned int stop = 4 * WORD_BITS + 1;

    for (unsigned int i = start; i < stop; i++)
    {
        PolynomialMod2 p(1);
        p <<= i;

        Integer n(Integer::One());
        n <<= i;

        std::ostringstream oss1;
        oss1 << p;

        std::string str1, str2;

        // str1 needs the commas removed used for grouping
        str1 = oss1.str();
        str1.erase(std::remove(str1.begin(), str1.end(), ','), str1.end());

        // str1 needs the trailing 'b' removed
        str1.erase(str1.end() - 1);

        // str2 is fine as-is
        str2 = IntToString(n, 2);

        pass1 &= (str1 == str2);
    }

    for (unsigned int i = start; i < stop; i++)
    {
        const word w((word)SIZE_MAX);

        PolynomialMod2 p(w);
        p <<= i;

        Integer n(Integer::POSITIVE, static_cast<lword>(w));
        n <<= i;

        std::ostringstream oss1;
        oss1 << p;

        std::string str1, str2;

        // str1 needs the commas removed used for grouping
        str1 = oss1.str();
        str1.erase(std::remove(str1.begin(), str1.end(), ','), str1.end());

        // str1 needs the trailing 'b' removed
        str1.erase(str1.end() - 1);

        // str2 is fine as-is
        str2 = IntToString(n, 2);

        pass2 &= (str1 == str2);
    }

    RandomNumberGenerator& prng = GlobalRNG();
    for (unsigned int i = start; i < stop; i++)
    {
        word w;     // Cast to lword due to Visual Studio
        prng.GenerateBlock((byte*)&w, sizeof(w));

        PolynomialMod2 p(w);
        p <<= i;

        Integer n(Integer::POSITIVE, static_cast<lword>(w));
        n <<= i;

        std::ostringstream oss1;
        oss1 << p;

        std::string str1, str2;

        // str1 needs the commas removed used for grouping
        str1 = oss1.str();
        str1.erase(std::remove(str1.begin(), str1.end(), ','), str1.end());

        // str1 needs the trailing 'b' removed
        str1.erase(str1.end() - 1);

        // str2 is fine as-is
        str2 = IntToString(n, 2);

        if (str1 != str2)
        {
            std::cout << "  Oops..." << "\n";
            std::cout << "     random: " << std::hex << n << std::dec << "\n";
            std::cout << "     str1: " << str1 << "\n";
            std::cout << "     str2: " << str2 << "\n";
        }

        pass3 &= (str1 == str2);
    }

    std::cout << (!pass1 ? "FAILED" : "passed") << ":  " << "1 shifted over range [" << std::dec << start << "," << stop << "]" << "\n";
    std::cout << (!pass2 ? "FAILED" : "passed") << ":  " << "0x" << std::hex << word(SIZE_MAX) << std::dec << " shifted over range [" << start << "," << stop << "]" << "\n";
    std::cout << (!pass3 ? "FAILED" : "passed") << ":  " << "random values shifted over range [" << std::dec << start << "," << stop << "]" << "\n";

    return pass1 && pass2 && pass3;
}
#endif

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
bool TestCompressors()
{
    std::cout << "\nTesting Compressors and Decompressors...\n\n";
    bool fail1 = false, fail2 = false, fail3 = false;
    const unsigned int COMP_COUNT = 64;

    try
    {
        // Gzip uses Adler32 checksums. We expect a failure to to happen on occasion.
        // If we see more than 2 failures in a run of 128, then we need to investigate.
        unsigned int truncatedCount=0;
        for (unsigned int i = 0; i<COMP_COUNT; ++i)
        {
            std::string src, dest, rec;
            unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);

            RandomNumberSource(GlobalRNG(), len, true, new StringSink(src));
            StringSource(src, true, new Gzip(new StringSink(dest)));
            StringSource(dest, true, new Gunzip(new StringSink(rec)));

            if (src != rec)
                throw Exception(Exception::OTHER_ERROR, "Gzip failed to decompress stream");

            // Tamper
            try {
                StringSource(dest.substr(0, len - 2), true, new Gunzip(new StringSink(rec)));
                if (truncatedCount++ >= 2)
                {
                    std::cout << "FAILED:  Gzip failed to detect a truncated stream\n";
                    fail1 = true;
                }
            }
            catch (const Exception&) {}
        }
    }
    catch (const Exception& ex)
    {
        std::cout << "FAILED:   " << ex.what() << "\n";
        fail1 = true;
    }

    // **************************************************************

    // Gzip Filename, Filetime and Comment
    try
    {
        std::string filename = "test.txt";
        std::string comment = "This is a test";
        word32 filetime = GlobalRNG().GenerateWord32(4, 0xffffff);

        AlgorithmParameters params = MakeParameters(Name::FileTime(), (int)filetime)
            (Name::FileName(), ConstByteArrayParameter(filename.c_str(), false))
            (Name::Comment(), ConstByteArrayParameter(comment.c_str(), false));

        std::string src, dest;
        unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);

        RandomNumberSource(GlobalRNG(), len, true, new StringSink(src));
        Gunzip unzip(new StringSink(dest));
        StringSource(src, true, new Gzip(params, new Redirector(unzip)));

        if (filename != unzip.GetFilename())
            throw Exception(Exception::OTHER_ERROR, "Failed to retrieve filename");

        if (filetime != unzip.GetFiletime())
            throw Exception(Exception::OTHER_ERROR, "Failed to retrieve filetime");

        if (comment != unzip.GetComment())
            throw Exception(Exception::OTHER_ERROR, "Failed to retrieve comment");

        std::cout << "passed:  filenames, filetimes and comments\n";
    }
    catch (const Exception& ex)
    {
        std::cout << "FAILED:  " << ex.what() << "\n";
    }

    // Unzip random data. See if we can induce a crash
    for (unsigned int i = 0; i<COMP_COUNT; i++)
    {
        SecByteBlock src;
        unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);
        RandomNumberSource(GlobalRNG(), len, true, new ArraySink(src, src.size()));

        try {
            ArraySource(src.data(), src.size(), true, new Gunzip(new Redirector(TheBitBucket())));
        }
        catch (const Exception&) {}
    }

    // Unzip random data. See if we can induce a crash
    for (unsigned int i = 0; i<COMP_COUNT; i++)
    {
        SecByteBlock src;
        unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);
        src.resize(len);
        RandomNumberSource(GlobalRNG(), len, true, new ArraySink(src, src.size()));

        src[0] = (byte)0x1f;  // magic header
        src[1] = (byte)0x8b;
        src[2] = 0x00;  // extra flags
        src[3] = src[3] & (2 | 4 | 8 | 16 | 32);   // flags

        // Commit d901ecd9a4de added Filenames, Filetimes and Comments. Gzip does
        // not specify a length for them; rather, they are NULL terminated. We add
        // a couple of NULLs in random places near filenames and comments to ensure
        // we are getting coverage in areas beyond the header.
        len = GlobalRNG().GenerateWord32(12, 24);
        if (len < src.size())  // guard it to ensure in-bounds
            src[len] = (byte)0x00;
        len = GlobalRNG().GenerateWord32(12+len, 24+len);
        if (len < src.size())  // guard it to ensure in-bounds
            src[len] = (byte)0x00;

        // The remainder are extra headers and the payload

        try {
            ArraySource(src.data(), src.size(), true, new Gunzip(new Redirector(TheBitBucket())));
        }
        catch (const Exception&) {}
    }

    if (!fail1)
        std::cout << "passed:";
    else
        std::cout << "FAILED:";
    std::cout << "  " << COMP_COUNT << " zips and unzips" << std::endl;

    // **************************************************************

    try
    {
        for (unsigned int i = 0; i<COMP_COUNT; ++i)
        {
            std::string src, dest, rec;
            unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);

            RandomNumberSource(GlobalRNG(), len, true, new StringSink(src));
            StringSource(src, true, new Deflator(new StringSink(dest)));
            StringSource(dest, true, new Inflator(new StringSink(rec)));

            if (src != rec)
                throw Exception(Exception::OTHER_ERROR, "Inflate failed to decompress stream");

            // Tamper
            try {
                StringSource(dest.substr(0, len - 2), true, new Gunzip(new StringSink(rec)));
                std::cout << "FAILED:  Inflate failed to detect a truncated stream\n";
                fail2 = true;
            }
            catch (const Exception&) {}
        }
    }
    catch (const Exception& ex)
    {
        std::cout << "FAILED:   " << ex.what() << "\n";
        fail2 = true;
    }

    // **************************************************************

    // Inflate random data. See if we can induce a crash
    for (unsigned int i = 0; i<COMP_COUNT; i++)
    {
        SecByteBlock src;
        unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);
        src.resize(len);
        RandomNumberSource(GlobalRNG(), len, true, new ArraySink(src, src.size()));

        src[0] = (byte)0x1f;  // magic header
        src[1] = (byte)0x8b;
        src[2] = 0x00;  // extra flags
        src[3] = src[3] & (2 | 4 | 8 | 16 | 32);   // flags

        // Don't allow ENCRYPTED|CONTINUED to over-run tests
        if (src[3] & (2 | 32)) {
            if (i % 3 == 0) { src[3] &= ~2; }
            if (i % 3 == 1) { src[3] &= ~32; }
        }

        // The remainder are extra headers and the payload

        try {
            ArraySource(src.data(), src.size(), true, new Inflator(new Redirector(TheBitBucket())));
        }
        catch (const Exception&) {}
    }

    // Inflate random data. See if we can induce a crash
    for (unsigned int i = 0; i<COMP_COUNT; i++)
    {
        SecByteBlock src;
        unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);
        RandomNumberSource(GlobalRNG(), len, true, new ArraySink(src, src.size()));

        try {
            ArraySource(src.data(), src.size(), true, new Inflator(new Redirector(TheBitBucket())));
        }
        catch (const Exception&) {}
    }

    if (!fail2)
        std::cout << "passed:";
    else
        std::cout << "FAILED:";
    std::cout << "  " << COMP_COUNT << " deflates and inflates\n";

    // **************************************************************

    try
    {
        for (unsigned int i = 0; i<COMP_COUNT; ++i)
        {
            std::string src, dest, rec;
            unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);

            RandomNumberSource(GlobalRNG(), len, true, new StringSink(src));
            StringSource(src, true, new ZlibCompressor(new StringSink(dest)));
            StringSource(dest, true, new ZlibDecompressor(new StringSink(rec)));

            if (src != rec)
                throw Exception(Exception::OTHER_ERROR, "Zlib failed to decompress stream");

            // Tamper
            try {
                StringSource(dest.substr(0, len - 2), true, new Gunzip(new StringSink(rec)));
                std::cout << "FAILED:  Zlib failed to detect a truncated stream\n";
                fail3 = true;
            }
            catch (const Exception&) {}
        }
    }
    catch (const Exception& ex)
    {
        std::cout << "FAILED:   " << ex.what() << "\n";
        fail3 = true;
    }

    // **************************************************************

    // Decompress random data. See if we can induce a crash
    for (unsigned int i = 0; i<COMP_COUNT; i++)
    {
        SecByteBlock src;
        unsigned int len = GlobalRNG().GenerateWord32(4, 0xfff);
        src.resize(len);
        RandomNumberSource(GlobalRNG(), len, true, new ArraySink(src, src.size()));

        // CMF byte
        src[0] = (byte)(GlobalRNG().GenerateWord32(0, 14) << 4);
        src[0] |= (byte)(GlobalRNG().GenerateWord32(0, 7));

        // FLG byte
        src[1] = (byte)(GlobalRNG().GenerateWord32(0, 7) << 5);
        src[1] |= (byte)(31 - (src[0] * 256 + src[1]) % 31);

        // The remainder are the payload, but missing Adler32

        try {
            ArraySource(src.data(), src.size(), true, new ZlibDecompressor(new Redirector(TheBitBucket())));
        }
        catch (const Exception&) {}
    }

    if (!fail3)
        std::cout << "passed:";
    else
        std::cout << "FAILED:";
    std::cout << "  " << COMP_COUNT << " zlib decompress and compress" << std::endl;

    // **************************************************************

    return !fail1 && !fail2 && !fail3;
}

bool TestCurve25519()
{
    std::cout << "\nTesting curve25519 Key Agreements...\n\n";
    const unsigned int AGREE_COUNT = 64;
    bool pass = true;

    SecByteBlock priv1(32), priv2(32), pub1(32), pub2(32), share1(32), share2(32);
    for (unsigned int i=0; i<AGREE_COUNT; ++i)
    {
        // Langley's curve25519-donna
        GlobalRNG().GenerateBlock(priv1, priv1.size());
        GlobalRNG().GenerateBlock(priv2, priv2.size());

        priv1[0] &= 248; priv1[31] &= 127; priv1[31] |= 64;
        priv2[0] &= 248; priv2[31] &= 127; priv2[31] |= 64;

        const byte base[32] = {9};
        Donna::curve25519(pub1, priv1, base);
        Donna::curve25519(pub2, priv2, base);

        int ret1 = Donna::curve25519(share1, priv1, pub2);
        int ret2 = Donna::curve25519(share2, priv2, pub1);
        int ret3 = std::memcmp(share1, share2, 32);

        // Bernstein's Tweet NaCl
        NaCl::crypto_box_keypair(pub2, priv2);

        int ret4 = Donna::curve25519(share1, priv1, pub2);
        int ret5 = NaCl::crypto_scalarmult(share2, priv2, pub1);
        int ret6 = std::memcmp(share1, share2, 32);

        bool fail = ret1 != 0 || ret2 != 0 || ret3 != 0 || ret4 != 0 || ret5 != 0 || ret6 != 0;
        pass = pass && !fail;
    }

    if (pass)
        std::cout << "passed:";
    else
        std::cout << "FAILED:";
    std::cout << "  " << AGREE_COUNT << " key agreements" << std::endl;

    return pass;
}

bool TestEncryptors()
{
    std::cout << "\nTesting Default Encryptors and Decryptors...\n\n";
    const unsigned int ENCRYPT_COUNT = 64, ENCRYPT_MAC_COUNT = 64;
    bool fail0 = false, fail1 = false, fail2 = false, fail3 = false, fail4 = false;

    // **************************************************************

    try
    {
        // Common password and message.
        std::string password = "super secret password";
        std::string recovered, message = "Now is the time for all good men to come to the aide of their country.";

        // This data was generated with Crypto++ 5.6.2
        //StringSource(message, true, new LegacyEncryptorWithMAC(password.c_str(), new FileSink("TestData/defdmac1.bin")));
        FileSource(DataDir("TestData/defdmac1.bin").c_str(), true, new LegacyDecryptorWithMAC(password.c_str(), new StringSink(recovered)));
        if (message != recovered)
            throw Exception(Exception::OTHER_ERROR, "LegacyDecryptorWithMAC failed a self test");

        // Reset sink
        recovered.clear();

        // This data was generated with Crypto++ 6.0
        //StringSource(message, true, new DefaultEncryptorWithMAC(password.c_str(), new FileSink("TestData/defdmac2.bin")));
        FileSource(DataDir("TestData/defdmac2.bin").c_str(), true, new DefaultDecryptorWithMAC(password.c_str(), new StringSink(recovered)));
        if (message != recovered)
            throw Exception(Exception::OTHER_ERROR, "DefaultDecryptorWithMAC failed a self test");
    }
    catch(const Exception&)
    {
        fail0 = true;
    }

    if (!fail0)
       std::cout << "passed:";
    else
       std::cout << "FAILED:";
    std::cout << "  cross-platform decryption with MAC of binary file" << std::endl;

    // **************************************************************

    try
    {
        for (unsigned int i=0; i<ENCRYPT_COUNT; ++i)
        {
            std::string pwd, src, dest, rec;
            unsigned int len = GlobalRNG().GenerateWord32(8, 0xfff);
            unsigned int plen = GlobalRNG().GenerateWord32(0, 32);

            RandomNumberSource(GlobalRNG(), len, true, new StringSink(src));
            RandomNumberSource(GlobalRNG(), plen, true, new HexEncoder(new StringSink(pwd)));

            StringSource(src, true, new DefaultEncryptor(pwd.c_str(), new StringSink(dest)));
            StringSource(dest, true, new DefaultDecryptor(pwd.c_str(), new StringSink(rec)));
            if (src != rec)
                throw Exception(Exception::OTHER_ERROR, "DefaultEncryptor failed a self test");
        }
    }
    catch(const Exception&)
    {
        fail1 = true;
    }

    if (!fail1)
       std::cout << "passed:";
    else
       std::cout << "FAILED:";
    std::cout << "  " << ENCRYPT_COUNT << " default encryptions and decryptions" << std::endl;

    // **************************************************************

    try
    {
        for (unsigned int i=0; i<ENCRYPT_MAC_COUNT; ++i)
        {
            const unsigned int runt = DefaultEncryptorWithMAC::SALTLENGTH + DefaultEncryptorWithMAC::KEYLENGTH;
            std::string pwd, src, dest, rec;
            unsigned int len = GlobalRNG().GenerateWord32(runt, 0xfff);
            unsigned int plen = GlobalRNG().GenerateWord32(0, 32);

            RandomNumberSource(GlobalRNG(), len, true, new StringSink(src));
            RandomNumberSource(GlobalRNG(), plen, true, new HexEncoder(new StringSink(pwd)));

            StringSource(src, true, new DefaultEncryptorWithMAC(pwd.c_str(),new StringSink(dest)));
            StringSource(dest, true, new DefaultDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
            if (src != rec)
                throw Exception(Exception::OTHER_ERROR, "DefaultEncryptorWithMAC failed a self test");

            // Tamper with the stream. Data format is [SALT][KEYCHECK][ENCRYPTED DATA].
            try {
                StringSource(dest.substr(0, len-2), true, new DefaultDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
                std::cout << "FAILED:  DefaultDecryptorWithMAC failed to detect a truncated stream\n";
                fail2 = true;
            } catch(const Exception&) { }
            try {
                // tamper salt
                dest[DefaultDecryptorWithMAC::SALTLENGTH/2] ^= 0x01;
                StringSource(dest, true, new DefaultDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
                std::cout << "FAILED:  DefaultDecryptorWithMAC failed to detect a tampered salt\n";
                fail2 = true;
            } catch(const Exception&) { }
            try {
                // undo previous tamper
                dest[DefaultDecryptorWithMAC::SALTLENGTH/2] ^= 0x01;
                // tamper keycheck
                dest[DefaultDecryptorWithMAC::SALTLENGTH+DefaultDecryptorWithMAC::KEYLENGTH/2] ^= 0x01;
                StringSource(dest, true, new DefaultDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
                std::cout << "FAILED:  DefaultDecryptorWithMAC failed to detect a tampered keycheck\n";
                fail2 = true;
            } catch(const Exception&) { }
            try {
                // undo previous tamper
                dest[DefaultDecryptorWithMAC::SALTLENGTH+DefaultDecryptorWithMAC::KEYLENGTH/2] ^= 0x01;
                // tamper encrypted data
                dest[dest.size()-2] ^= 0x01;
                StringSource(dest, true, new DefaultDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
                std::cout << "FAILED:  DefaultDecryptorWithMAC failed to detect a tampered data\n";
                fail2 = true;
            } catch(const Exception&) { }
        }
    }
    catch(const Exception&)
    {
        fail2 = true;
    }

    if (!fail2)
       std::cout << "passed:";
    else
       std::cout << "FAILED:";
    std::cout << "  " << ENCRYPT_MAC_COUNT << " default encryptions and decryptions with MAC" << std::endl;

    // **************************************************************

    try
    {
        for (unsigned int i=0; i<ENCRYPT_COUNT; ++i)
        {
            std::string pwd, src, dest, rec;
            unsigned int len = GlobalRNG().GenerateWord32(16, 0xfff);
            unsigned int plen = GlobalRNG().GenerateWord32(0, 32);

            RandomNumberSource(GlobalRNG(), len, true, new StringSink(src));
            RandomNumberSource(GlobalRNG(), plen, true, new HexEncoder(new StringSink(pwd)));

            StringSource(src, true, new LegacyEncryptor(pwd.c_str(),new StringSink(dest)));
            StringSource(dest, true, new LegacyDecryptor(pwd.c_str(),new StringSink(rec)));

            if (src != rec)
                throw Exception(Exception::OTHER_ERROR, "LegacyEncryptor failed a self test");
        }
    }
    catch(const Exception&)
    {
        fail3 = true;
    }

    if (!fail3)
       std::cout << "passed:";
    else
       std::cout << "FAILED:";
    std::cout << "  " << ENCRYPT_COUNT << " legacy encryptions and decryptions" << std::endl;

    // **************************************************************

    try
    {
        for (unsigned int i=0; i<ENCRYPT_MAC_COUNT; ++i)
        {
            const unsigned int runt = LegacyDecryptorWithMAC::SALTLENGTH + LegacyDecryptorWithMAC::KEYLENGTH;
            std::string pwd, src, dest, rec;
            unsigned int len = GlobalRNG().GenerateWord32(runt, 0xfff);
            unsigned int plen = GlobalRNG().GenerateWord32(0, 32);

            RandomNumberSource(GlobalRNG(), len, true, new StringSink(src));
            RandomNumberSource(GlobalRNG(), plen, true, new HexEncoder(new StringSink(pwd)));

            StringSource(src, true, new LegacyEncryptorWithMAC(pwd.c_str(), new StringSink(dest)));
            StringSource(dest, true, new LegacyDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
            if (src != rec)
                throw Exception(Exception::OTHER_ERROR, "LegacyEncryptorWithMAC failed a self test");

            // Tamper with the stream. Data format is [SALT][KEYCHECK][ENCRYPTED DATA].
            try {
                StringSource(dest.substr(0, len-2), true, new LegacyDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
                std::cout << "FAILED:  LegacyEncryptorWithMAC failed to detect a truncated stream\n";
                fail4 = true;
            } catch(const Exception&) { }
            try {
                // tamper salt
                dest[LegacyEncryptorWithMAC::SALTLENGTH/2] ^= 0x01;
                StringSource(dest, true, new LegacyDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
                std::cout << "FAILED:  LegacyEncryptorWithMAC failed to detect a tampered salt\n";
                fail4 = true;
            } catch(const Exception&) { }
            try {
                // undo previous tamper
                dest[LegacyEncryptorWithMAC::SALTLENGTH/2] ^= 0x01;
                // tamper keycheck
                dest[LegacyEncryptorWithMAC::SALTLENGTH+LegacyEncryptorWithMAC::KEYLENGTH/2] ^= 0x01;
                StringSource(dest, true, new LegacyDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
                std::cout << "FAILED:  LegacyEncryptorWithMAC failed to detect a tampered keycheck\n";
                fail4 = true;
            } catch(const Exception&) { }
            try {
                // undo previous tamper
                dest[LegacyEncryptorWithMAC::SALTLENGTH+LegacyEncryptorWithMAC::KEYLENGTH/2] ^= 0x01;
                // tamper encrypted data
                dest[dest.size()-2] ^= 0x01;
                StringSource(dest, true, new LegacyDecryptorWithMAC(pwd.c_str(), new StringSink(rec)));
                std::cout << "FAILED:  LegacyEncryptorWithMAC failed to detect a tampered data\n";
                fail4 = true;
            } catch(const Exception&) { }
        }
    }
    catch(const Exception&)
    {
        fail4 = true;
    }

    if (!fail4)
       std::cout << "passed:";
    else
       std::cout << "FAILED:";
    std::cout << "  " << ENCRYPT_MAC_COUNT << " legacy encryptions and decryptions with MAC" << std::endl;

    return !fail0 && !fail1 && !fail2 && !fail3 && !fail4;
}

// Information Dispesal and Secret Sharing
bool TestSharing()
{
    std::cout << "\nInformation Dispersal and Secret Sharing...\n\n";
    const unsigned int INFORMATION_SHARES = 64;
    const unsigned int SECRET_SHARES = 64;
    const unsigned int CHID_LENGTH = 4;
    bool pass=true, fail=false;

    // ********** Infrmation Dispersal **********//

    for (unsigned int shares=3; shares<INFORMATION_SHARES; ++shares)
    {
        std::string message;
        unsigned int len = GlobalRNG().GenerateWord32(4, 0xff);
        unsigned int threshold = GlobalRNG().GenerateWord32(2, shares-1);

        RandomNumberSource(GlobalRNG(), len, true, new StringSink(message));

        ChannelSwitch *channelSwitch = NULLPTR;
        StringSource source(message, false, new InformationDispersal(threshold, shares, channelSwitch = new ChannelSwitch));

        std::vector<std::string> strShares(shares);
        vector_member_ptrs<StringSink> strSinks(shares);
        std::string channel;

        // ********** Create Shares
        for (unsigned int i=0; i<shares; i++)
        {
            strSinks[i].reset(new StringSink(strShares[i]));
            channel = WordToString<word32>(i);
            strSinks[i]->Put((const byte *)channel.data(), CHID_LENGTH);
            channelSwitch->AddRoute(channel, *strSinks[i], DEFAULT_CHANNEL);
        }
        source.PumpAll();

        // ********** Randomize shares

        GlobalRNG().Shuffle(strShares.begin(), strShares.end());

        // ********** Recover secret
        try
        {
            std::string recovered;
            InformationRecovery recovery(threshold, new StringSink(recovered));

            vector_member_ptrs<StringSource> strSources(threshold);
            channel.resize(CHID_LENGTH);

            for (unsigned int i=0; i<threshold; i++)
            {
                strSources[i].reset(new StringSource(strShares[i], false));
                strSources[i]->Pump(CHID_LENGTH);
                strSources[i]->Get((byte*)&channel[0], CHID_LENGTH);
                strSources[i]->Attach(new ChannelSwitch(recovery, channel));
            }

            while (strSources[0]->Pump(256))
            {
                for (unsigned int i=1; i<threshold; i++)
                    strSources[i]->Pump(256);
            }

            for (unsigned int i=0; i<threshold; i++)
                strSources[i]->PumpAll();

            fail = (message != recovered);
        }
        catch (const Exception&)
        {
            fail = true;
        }

        pass &= !fail;
    }

    std::cout << (fail ? "FAILED:" : "passed:") << "  " << INFORMATION_SHARES << " information dispersals\n";

    // ********** Secret Sharing **********//

    for (unsigned int shares=3; shares<SECRET_SHARES; ++shares)
    {

        std::string message;
        unsigned int len = GlobalRNG().GenerateWord32(4, 0xff);
        unsigned int threshold = GlobalRNG().GenerateWord32(2, shares-1);

        RandomNumberSource(GlobalRNG(), len, true, new StringSink(message));

        ChannelSwitch *channelSwitch = NULLPTR;
        StringSource source(message, false, new SecretSharing(GlobalRNG(), threshold, shares, channelSwitch = new ChannelSwitch));

        std::vector<std::string> strShares(shares);
        vector_member_ptrs<StringSink> strSinks(shares);
        std::string channel;

        // ********** Create Shares
        for (unsigned int i=0; i<shares; i++)
        {
            strSinks[i].reset(new StringSink(strShares[i]));
            channel = WordToString<word32>(i);
            strSinks[i]->Put((const byte *)channel.data(), CHID_LENGTH);
            channelSwitch->AddRoute(channel, *strSinks[i], DEFAULT_CHANNEL);
        }
        source.PumpAll();

        // ********** Randomize shares

        GlobalRNG().Shuffle(strShares.begin(), strShares.end());

        // ********** Recover secret
        try
        {
            std::string recovered;
            SecretRecovery recovery(threshold, new StringSink(recovered));

            vector_member_ptrs<StringSource> strSources(threshold);
            channel.resize(CHID_LENGTH);
            for (unsigned int i=0; i<threshold; i++)
            {
                strSources[i].reset(new StringSource(strShares[i], false));
                strSources[i]->Pump(CHID_LENGTH);
                strSources[i]->Get((byte*)&channel[0], CHID_LENGTH);
                strSources[i]->Attach(new ChannelSwitch(recovery, channel));
            }

            while (strSources[0]->Pump(256))
            {
                for (unsigned int i=1; i<threshold; i++)
                    strSources[i]->Pump(256);
            }

            for (unsigned int i=0; i<threshold; i++)
                strSources[i]->PumpAll();

            fail = (message != recovered);
        }
        catch (const Exception&)
        {
            fail = true;
        }

        pass &= !fail;
    }

    std::cout << (fail ? "FAILED:" : "passed:") << "  " << SECRET_SHARES << " secret sharings\n";

    return pass;
}

bool TestRounding()
{
    std::cout << "\nTesting RoundUpToMultipleOf/RoundDownToMultipleOf...\n\n";
    bool pass=true, fail;

    // ********** byte **********//
    try
    {
        const byte v=0, b=0x08;
        byte r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, byte, no overflow\n";

    try
    {
        const byte v=1, b=0x08;
        byte r=RoundUpToMultipleOf(v, b);
        fail = (r != b);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, byte, no overflow\n";

    try
    {
        const byte v=0x08, b=0x08;
        byte r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, byte, no overflow\n";

    try
    {
        const byte v=0xf7, b=0x08;
        byte r=RoundUpToMultipleOf(v, b);
        fail = (r != 0xf8);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, byte, no overflow\n";

    try
    {
        const byte v=0xf8, b=0x08;
        byte r=RoundUpToMultipleOf(v, b);
        fail = (r != 0xf8);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, byte, no overflow\n";

    try
    {
        const byte v=0xf9, b=0x08;
        byte r=RoundUpToMultipleOf(v, b);
        CRYPTOPP_UNUSED(r);
        fail = true;
    }
    catch(const Exception&)
    {
        fail = false;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, byte, overflow\n";

    // ********** word16 **********//
    try
    {
        const word16 v=0, b=0x08;
        word16 r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word16, no overflow\n";

    try
    {
        const word16 v=1, b=0x08;
        word16 r=RoundUpToMultipleOf(v, b);
        fail = (r != b);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word16, no overflow\n";

    try
    {
        const word16 v=0x08, b=0x08;
        word16 r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word16, no overflow\n";

    try
    {
        const word16 v=0xfff7, b=0x08;
        word16 r=RoundUpToMultipleOf(v, b);
        fail = (r != 0xfff8);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word16, no overflow\n";

    try
    {
        const word16 v=0xfff8, b=0x08;
        word16 r=RoundUpToMultipleOf(v, b);
        fail = (r != 0xfff8);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word16, no overflow\n";

    try
    {
        const word16 v=0xfff9, b=0x08;
        word16 r=RoundUpToMultipleOf(v, b);
        CRYPTOPP_UNUSED(r);
        fail = true;
    }
    catch(const Exception&)
    {
        fail = false;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word16, overflow\n";

    // ********** word32 **********//
    try
    {
        const word32 v=0, b=0x08;
        word32 r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word32, no overflow\n";

    try
    {
        const word32 v=1, b=0x08;
        word32 r=RoundUpToMultipleOf(v, b);
        fail = (r != b);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word32, no overflow\n";

    try
    {
        const word32 v=0x08, b=0x08;
        word32 r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word32, no overflow\n";

    try
    {
        const word32 v=0xfffffff7, b=0x08;
        word32 r=RoundUpToMultipleOf(v, b);
        fail = (r != 0xfffffff8);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word32, no overflow\n";

    try
    {
        const word32 v=0xfffffff8, b=0x08;
        word32 r=RoundUpToMultipleOf(v, b);
        fail = (r != 0xfffffff8);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word32, no overflow\n";

    try
    {
        const word32 v=0xfffffff9, b=0x08;
        word32 r=RoundUpToMultipleOf(v, b);
        CRYPTOPP_UNUSED(r);
        fail = true;
    }
    catch(const Exception&)
    {
        fail = false;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word32, overflow\n";

    // ********** word64 **********//
    try
    {
        const word64 v=0, b=0x08;
        word64 r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word64, no overflow\n";

    try
    {
        const word64 v=1, b=0x08;
        word64 r=RoundUpToMultipleOf(v, b);
        fail = (r != b);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word64, no overflow\n";

    try
    {
        const word64 v=0x08, b=0x08;
        word64 r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word64, no overflow\n";

    try
    {
        const word64 v=W64LIT(0xffffffffffffff7), b=0x08;
        word64 r=RoundUpToMultipleOf(v, b);
        fail = (r != W64LIT(0xffffffffffffff8));
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word64, no overflow\n";

    try
    {
        const word64 v=W64LIT(0xffffffffffffff8), b=0x08;
        word64 r=RoundUpToMultipleOf(v, b);
        fail = (r != W64LIT(0xffffffffffffff8));
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word64, no overflow\n";

    try
    {
        const word64 v=W64LIT(0xfffffffffffffff9), b=0x08;
        word64 r=RoundUpToMultipleOf(v, b);
        CRYPTOPP_UNUSED(r);
        fail = true;
    }
    catch(const Exception&)
    {
        fail = false;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word64, overflow\n";

#if defined(CRYPTOPP_WORD128_AVAILABLE)
    // ********** word128 **********//
    try
    {
        const word128 v=0, b=0x08;
        word128 r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word128, no overflow\n";

    try
    {
        const word128 v=1, b=0x08;
        word128 r=RoundUpToMultipleOf(v, b);
        fail = (r != b);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word128, no overflow\n";

    try
    {
        const word128 v=0x08, b=0x08;
        word128 r=RoundUpToMultipleOf(v, b);
        fail = (r != v);
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word128, no overflow\n";

    try
    {
        // http://stackoverflow.com/q/31461318/608639
        const word128 h = ((word128)W64LIT(0xffffffffffffffff)) << 64U;
        const word128 v = h | (word128)W64LIT(0xfffffffffffffff7), b=0x08;
        word128 r=RoundUpToMultipleOf(v, b);
        fail = (r != (h | (word128)W64LIT(0xfffffffffffffff8)));
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word128, no overflow\n";

    try
    {
        const word128 h = ((word128)W64LIT(0xffffffffffffffff)) << 64U;
        const word128 v = h | (word128)W64LIT(0xfffffffffffffff8), b=0x08;
        word128 r=RoundUpToMultipleOf(v, b);
        fail = (r != (h | (word128)W64LIT(0xfffffffffffffff8)));
    }
    catch(const Exception&)
    {
        fail = true;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word128, no overflow\n";

    try
    {
        const word128 h = ((word128)W64LIT(0xffffffffffffffff)) << 64U;
        const word128 v = h | (word128)W64LIT(0xfffffffffffffff9), b=0x08;
        word128 r=RoundUpToMultipleOf(v, b);
        CRYPTOPP_UNUSED(r);
        fail = true;
    }
    catch(const Exception&)
    {
        fail = false;
    }

    pass = !fail && pass;
    std::cout << (fail ? "FAILED:" : "passed:") << "  RoundUpToMultipleOf, word128, overflow\n";
#endif

    return pass;
}
#endif

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
struct ASN1_TestTuple
{
    int disposition;
    int identifier;
    const char* name;
    const char* data;
    size_t len;
};

bool RunASN1TestSet(const ASN1_TestTuple asnTuples[], size_t count)
{
    bool pass=true, fail;

    // Disposition
    enum {REJECT=3, ACCEPT=4};

    for(size_t i=0; i<count; i++)
    {
        const ASN1_TestTuple & thisTest = asnTuples[i];
        ArraySource as1((const byte*)thisTest.data, thisTest.len, true);
        ArraySource as2((const byte*)thisTest.data, thisTest.len, true);

        SecByteBlock unused1;
        std::string unused2;
        unsigned int unused3;
        word32 unused4;
        word64 unused5;

        // Reporting
        std::string val;
        HexEncoder encoder(new StringSink(val));
        encoder.Put((const byte*)thisTest.data, thisTest.len);
        encoder.MessageEnd();

        try
        {
            int tag = thisTest.identifier;
            switch (tag)
            {
                case BIT_STRING:
                    BERDecodeBitString(as1, unused1, unused3);
                    break;

                case OCTET_STRING:
                    BERDecodeOctetString(as1, unused1);
                    break;

                case INTEGER:
                    BERDecodeUnsigned(as1, unused4);
                    BERDecodeUnsigned<word64>(as2, unused5, byte(INTEGER), 0, W64LIT(0xffffffffffffffff));
                    break;

                case UTF8_STRING: case PRINTABLE_STRING: case IA5_STRING:
                    BERDecodeTextString(as1, unused2, (byte)tag);
                    break;

                default:
                    BERGeneralDecoder(as1, (byte)tag);
                    break;
            }

            fail = !(thisTest.disposition == ACCEPT);
        }
        catch(const Exception&)
        {
            fail = !(thisTest.disposition == REJECT);
        }

        std::cout << (fail ? "FAILED:" : "passed:") << (thisTest.disposition == ACCEPT ? "  accept " : "  reject ");
        std::cout << asnTuples[i].name << " " << val << "\n";
        pass = !fail && pass;
    }

    return pass;
}

bool TestASN1Parse()
{
    std::cout << "\nTesting ASN.1 parser...\n\n";

    bool pass = true;

    // Disposition
    enum {REJECT=3, ACCEPT=4};

    // All the types Crypto++ recognizes.
    //   "C" is one content octet with value 0x43.
    const ASN1_TestTuple bitStrings[] =
    {
        // The first "\x00" content octet is the "initial octet" representing unused bits. In the
        //   primitive encoding form, there may be zero, one or more contents after the initial octet.
        {ACCEPT, BIT_STRING, "BIT_STRING", "\x03\x01" "\x00", 3},  // definite length, short form, initial octet, zero subsequent octets
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x01" "\x08", 3},  // definite length, short form, initial octet, zero subsequent octets
        {ACCEPT, BIT_STRING, "BIT_STRING", "\x03\x02" "\x00" "C", 4},  // definite length, short form, expected subsequent octets
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x02" "\x08" "C", 4},  // too many unused bits
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x7F" "\x00" "C", 4},  // runt or underrun
        {ACCEPT, BIT_STRING, "BIT_STRING", "\x03\x81\x01" "\x00", 4},  // definite length, long form, initial octet, zero subsequent octets
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x81\x01" "\x08", 4},  // definite length, long form, initial octet, zero subsequent octets
        {ACCEPT, BIT_STRING, "BIT_STRING", "\x03\x81\x02" "\x00" "C", 5},  // definite length, long form
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x81\x02" "\x08" "C", 5},  // too many unused bits
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x81\xff" "\x00" "C", 5},  // runt or underrun
        {ACCEPT, BIT_STRING, "BIT_STRING", "\x03\x82\x00\x02" "\x00" "C", 6},  // definite length, long form
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x82\x00\x02" "\x08" "C", 6},  // too many unused bits
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x82\xff\xff" "\x00" "C", 6},  // runt or underrun
        {ACCEPT, BIT_STRING, "BIT_STRING", "\x03\x83\x00\x00\x02" "\x00" "C", 7},  // definite length, long form
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x83\x00\x00\x02" "\x08" "C", 7},  // too many unused bits
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x83\xff\xff\xff" "\x00" "C", 7},  // runt or underrun
        {ACCEPT, BIT_STRING, "BIT_STRING", "\x03\x84\x00\x00\x00\x02" "\x00" "C", 8},  // definite length, long form
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x84\x00\x00\x00\x02" "\x08" "C", 8},  // too many unused bits
        {REJECT, BIT_STRING, "BIT_STRING", "\x03\x84\xff\xff\xff\xff" "\x00" "C", 8},  // <== Issue 346; requires large allocation
    };

    pass = RunASN1TestSet(bitStrings, COUNTOF(bitStrings)) && pass;

    const ASN1_TestTuple octetStrings[] =
    {
        // In the primitive encoding form, there may be zero, one or more contents.
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x00", 2},  // definite length, short form, zero content octets
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x01" "C", 3},  // definite length, short form, expected content octets
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x02" "C", 3},  // runt or underrun
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x7F" "C", 3},  // runt or underrun
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x81\x00", 3},  // definite length, long form, zero content octets
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x81\x01" "C", 4},  // definite length, long form, expected content octets
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x81\x02" "C", 4},  // runt or underrun
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x81\xff" "C", 4},  // runt or underrun
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x82\x00\x00", 4},  // definite length, long form, zero content octets
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x82\x00\x01" "C", 5},  // definite length, long form, expected content octets
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x82\x00\x02" "C", 5},  // runt or underrun
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x82\xff\xff" "C", 5},  // runt or underrun
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x83\x00\x00\x00", 5},  // definite length, long form, zero content octets
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x83\x00\x00\x01" "C", 6},  // definite length, long form, expected content octets
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x83\x00\x00\x02" "C", 6},  // runt or underrun
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x83\xff\xff\xff" "C", 6},  // runt or underrun
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x84\x00\x00\x00\x00", 6},  // definite length, long form, zero content octets
        {ACCEPT, OCTET_STRING, "OCTET_STRING", "\x04\x84\x00\x00\x00\x01" "C", 7},  // definite length, long form, expected content octets
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x84\x00\x00\x00\x02" "C", 7},  // runt or underrun
        {REJECT, OCTET_STRING, "OCTET_STRING", "\x04\x84\xff\xff\xff\xff" "C", 7},  // <== Issue 346; requires large allocation
    };

    pass = RunASN1TestSet(octetStrings, COUNTOF(octetStrings)) && pass;

    const ASN1_TestTuple utf8Strings[] =
    {
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x00", 2},  // definite length, short form, zero content octets
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x01" "C", 3},  // definite length, short form, expected content octets
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x02" "C", 3},  // runt or underrun
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x7F" "C", 3},  // runt or underrun
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x81\x00", 3},  // definite length, long form, zero content octets
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x81\x01" "C", 4},  // definite length, long form, expected content octets
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x81\x02" "C", 4},  // runt or underrun
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x81\xff" "C", 4},  // runt or underrun
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x82\x00\x00", 4},  // definite length, long form, zero content octets
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x82\x00\x01" "C", 5},  // definite length, long form, expected content octets
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x82\x00\x02" "C", 5},  // runt or underrun
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x82\xff\xff" "C", 5},  // runt or underrun
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x83\x00\x00\x00", 5},  // definite length, long form, zero content octets
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x83\x00\x00\x01" "C", 6},  // definite length, long form, expected content octets
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x83\x00\x00\x02" "C", 6},  // runt or underrun
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x83\xff\xff\xff" "C", 6},  // runt or underrun
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x84\x00\x00\x00\x00", 6},  // definite length, long form, zero content octets
        {ACCEPT, UTF8_STRING, "UTF8_STRING", "\x0c\x84\x00\x00\x00\x01" "C", 7},  // definite length, long form, expected content octets
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x84\x00\x00\x00\x02" "C", 7},  // runt or underrun
        {REJECT, UTF8_STRING, "UTF8_STRING", "\x0c\x84\xff\xff\xff\xff" "C", 7},  // <== Issue 346; requires large allocation
    };

    pass = RunASN1TestSet(utf8Strings, COUNTOF(utf8Strings)) && pass;

    const ASN1_TestTuple printableStrings[] =
    {
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x00", 2},  // definite length, short form, zero content octets
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x01" "C", 3},  // definite length, short form, expected content octets
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x02" "C", 3},  // runt or underrun
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x7F" "C", 3},  // runt or underrun
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x81\x00", 3},  // definite length, long form, zero content octets
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x81\x01" "C", 4},  // definite length, long form, expected content octets
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x81\x02" "C", 4},  // runt or underrun
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x81\xff" "C", 4},  // runt or underrun
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x82\x00\x00", 4},  // definite length, long form, zero content octets
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x82\x00\x01" "C", 5},  // definite length, long form, expected content octets
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x82\x00\x02" "C", 5},  // runt or underrun
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x82\xff\xff" "C", 5},  // runt or underrun
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x83\x00\x00\x00", 5},  // definite length, long form, zero content octets
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x83\x00\x00\x01" "C", 6},  // definite length, long form, expected content octets
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x83\x00\x00\x02" "C", 6},  // runt or underrun
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x83\xff\xff\xff" "C", 6},  // runt or underrun
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x84\x00\x00\x00\x00", 6},  // definite length, long form, zero content octets
        {ACCEPT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x84\x00\x00\x00\x01" "C", 7},  // definite length, long form, expected content octets
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x84\x00\x00\x00\x02" "C", 7},  // runt or underrun
        {REJECT, PRINTABLE_STRING, "PRINTABLE_STRING", "\x13\x84\xff\xff\xff\xff" "C", 7},  // <== Issue 346; requires large allocation
    };

    pass = RunASN1TestSet(printableStrings, COUNTOF(printableStrings)) && pass;

    const ASN1_TestTuple ia5Strings[] =
    {
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x00", 2},  // definite length, short form, zero content octets
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x01" "C", 3},  // definite length, short form, expected content octets
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x02" "C", 3},  // runt or underrun
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x7F" "C", 3},  // runt or underrun
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x81\x00", 3},  // definite length, long form, zero content octets
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x81\x01" "C", 4},  // definite length, long form, expected content octets
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x81\x02" "C", 4},  // runt or underrun
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x81\xff" "C", 4},  // runt or underrun
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x82\x00\x00", 4},  // definite length, long form, zero content octets
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x82\x00\x01" "C", 5},  // definite length, long form, expected content octets
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x82\x00\x02" "C", 5},  // runt or underrun
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x82\xff\xff" "C", 5},  // runt or underrun
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x83\x00\x00\x00", 5},  // definite length, long form, zero content octets
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x83\x00\x00\x01" "C", 6},  // definite length, long form, expected content octets
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x83\x00\x00\x02" "C", 6},  // runt or underrun
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x83\xff\xff\xff" "C", 6},  // runt or underrun
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x84\x00\x00\x00\x00", 6},  // definite length, long form, zero content octets
        {ACCEPT, IA5_STRING, "IA5_STRING", "\x16\x84\x00\x00\x00\x01" "C", 7},  // definite length, long form, expected content octets
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x84\x00\x00\x00\x02" "C", 7},  // runt or underrun
        {REJECT, IA5_STRING, "IA5_STRING", "\x16\x84\xff\xff\xff\xff" "C", 7},  // <== Issue 346; requires large allocation
    };

    pass = RunASN1TestSet(ia5Strings, COUNTOF(ia5Strings)) && pass;

    const ASN1_TestTuple integerValues[] =
    {
        // 8.3.1 The encoding of an integer value shall be primitive. The contents octets shall consist of one or more octets.
        {REJECT, INTEGER, "INTEGER", "\x02\x00", 2},  // definite length, short form, zero content octets
        {ACCEPT, INTEGER, "INTEGER", "\x02\x01" "C", 3},  // definite length, short form, expected content octets
        {REJECT, INTEGER, "INTEGER", "\x02\x02" "C", 3},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x7F" "C", 3},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x81\x00", 3},  // definite length, long form, zero content octets
        {ACCEPT, INTEGER, "INTEGER", "\x02\x81\x01" "C", 4},  // definite length, long form, expected content octets
        {REJECT, INTEGER, "INTEGER", "\x02\x81\x02" "C", 4},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x81\xff" "C", 4},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x82\x00\x00", 4},  // definite length, long form, zero content octets
        {ACCEPT, INTEGER, "INTEGER", "\x02\x82\x00\x01" "C", 5},  // definite length, long form, expected content octets
        {REJECT, INTEGER, "INTEGER", "\x02\x82\x00\x02" "C", 5},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x82\xff\xff" "C", 5},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x83\x00\x00\x00", 5},  // definite length, long form, zero content octets
        {ACCEPT, INTEGER, "INTEGER", "\x02\x83\x00\x00\x01" "C", 6},  // definite length, long form, expected content octets
        {REJECT, INTEGER, "INTEGER", "\x02\x83\x00\x00\x02" "C", 6},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x83\xff\xff\xff" "C", 6},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x84\x00\x00\x00\x00", 6},  // definite length, long form, zero content octets
        {ACCEPT, INTEGER, "INTEGER", "\x02\x84\x00\x00\x00\x01" "C", 7},  // definite length, long form, expected content octets
        {REJECT, INTEGER, "INTEGER", "\x02\x84\x00\x00\x00\x02" "C", 7},  // runt or underrun
        {REJECT, INTEGER, "INTEGER", "\x02\x84\xff\xff\xff\xff" "C", 7},  // <== Issue 346; requires large allocation
    };

    pass = RunASN1TestSet(integerValues, COUNTOF(integerValues)) && pass;

    return pass;
}
#endif

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
bool TestStringSink()
{
    try
    {
        std::string in = "The quick brown fox jumps over the lazy dog";

        std::string str;
        StringSource s1(in, true, new StringSink(str));

        std::vector<byte> vec;
        StringSource s2(in, true, new VectorSink(vec));

        std::vector<byte> vec2;
        VectorSource s3(vec, true, new VectorSink(vec2));

        return str.size() == vec.size() &&
            std::equal(str.begin(), str.end(), vec.begin()) &&
            vec.size() == vec2.size() &&
            std::equal(vec.begin(), vec.end(), vec2.begin());
    }
    catch(const std::exception&)
    {
    }
    return false;
}
#endif

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
