// validat0.cpp - originally written and placed in the public domain by Wei Dai and Jeffrey Walton
//                Routines in this source file are only tested in Debug builds

#include "pch.h"

#include "secblock.h"
#include "integer.h"
#include "nbtheory.h"
#include "zdeflate.h"
#include "filters.h"
#include "stdcpp.h"
#include "default.h"
#include "zinflate.h"
#include "channels.h"
#include "files.h"
#include "gf2n.h"
#include "gzip.h"
#include "zlib.h"
#include "ida.h"
#include "hex.h"
#include "asn.h"

#include <iostream>
#include <iomanip>
#include <sstream>

#include "validate.h"

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
    bool pass1 = true, pass2 = true, pass3 = true;

    std::cout << "\nTesting PolynomialMod2 bit operations...\n\n";

    static const unsigned int start = 0;
    static const unsigned int stop = 4 * WORD_BITS + 1;

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

    try
    {
        // Gzip uses Adler32 checksums. We expect a failure to to happen on occasion.
        // If we see more than 2 failures in a run of 128, then we need to investigate.
        unsigned int truncatedCount=0;
        for (unsigned int i = 0; i<128; ++i)
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
    for (unsigned int i = 0; i<128; i++)
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
    for (unsigned int i = 0; i<128; i++)
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
    std::cout << "  128 zips and unzips" << std::endl;

    // **************************************************************

    try
    {
        for (unsigned int i = 0; i<128; ++i)
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
    for (unsigned int i = 0; i<128; i++)
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
    for (unsigned int i = 0; i<128; i++)
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
    std::cout << "  128 deflates and inflates\n";

    // **************************************************************

    try
    {
        for (unsigned int i = 0; i<128; ++i)
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
    for (unsigned int i = 0; i<128; i++)
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
    std::cout << "  128 zlib decompress and compress" << std::endl;

    // **************************************************************

    return !fail1 && !fail2 && !fail3;
}

bool TestEncryptors()
{
    std::cout << "\nTesting Default Encryptors and Decryptors...\n\n";
    static const unsigned int ENCRYPT_COUNT = 128, ENCRYPT_MAC_COUNT = 64;
    bool fail1 = false, fail2 = false, fail3 = false, fail4 = false;

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

    return !fail1 && !fail2 && !fail3 && !fail4;
}

// Information Dispesal and Secret Sharing
bool TestSharing()
{
    std::cout << "\nInformation Dispersal and Secret Sharing...\n\n";
    static const unsigned int INFORMATION_SHARES = 128;
    static const unsigned int SECRET_SHARES = 64;
    static const unsigned int CHID_LENGTH = 4;
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
    static const ASN1_TestTuple bitStrings[] =
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

    static const ASN1_TestTuple octetStrings[] =
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

    static const ASN1_TestTuple utf8Strings[] =
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

    static const ASN1_TestTuple printableStrings[] =
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

    static const ASN1_TestTuple ia5Strings[] =
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

    static const ASN1_TestTuple integerValues[] =
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
        memset(block, 0xaa, block.SizeInBytes());

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
        memset(block, 0xaa, block.SizeInBytes());

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
        memset(block, 0xaa, block.SizeInBytes());

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
        memset(block, 0xaa, block.SizeInBytes());

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
bool TestIntegerBitops()
{
    std::cout << "\nTesting Integer operations...\n\n";
    bool pass;

    // Integer is missing a couple of tests...
    try {
        Integer x = Integer::Two().Power2(128) / Integer::Zero();
        pass=false;
    } catch (const Exception&) {
        pass=true;
    }

    if (pass)
        std::cout << "passed:";
    else
        std::cout << "FAILED:";
    std::cout << "  Integer DivideByZero\n";

    // Integer is missing a couple of tests...
    pass=true;
    try {
        // A run of 71 composites; see http://en.wikipedia.org/wiki/Prime_gap
        Integer x = Integer(GlobalRNG(), 31398, 31468, Integer::PRIME);
        pass=false;
    } catch (const Exception&) { }

    if (pass)
        std::cout << "passed:";
    else
        std::cout << "FAILED:";
    std::cout << "  Integer RandomNumberNotFound\n";

    // Carmichael pseudo-primes
    pass=true;
    if (IsPrime(Integer("561")))
        pass = false;
    if (IsPrime(Integer("41041")))
        pass = false;
    if (IsPrime(Integer("321197185")))
        pass = false;
    if (IsPrime(Integer("5394826801")))
        pass = false;
    if (IsPrime(Integer("232250619601")))
        pass = false;
    if (IsPrime(Integer("974637772161")))
        pass = false;

    if (pass)
        std::cout << "passed:";
    else
        std::cout << "FAILED:";
    std::cout << "  Carmichael pseudo-primes\n";

    // Integer is missing a couple of tests...
    try {
        Integer x = Integer::One().Doubled();
        pass=(x == Integer::Two());
    } catch (const Exception&) {
        pass=false;
    }

    if (!pass)
        std::cout << "FAILED:  Integer Doubled\n";

    // Now onto the meat and potatoes...
    struct Bitops_TestTuple
    {
        // m,n are operands; a,o,x are and,or,xor results
        const char *m, *n, *a, *o, *x;
    };
    static const Bitops_TestTuple tests[] = {
        {
            "0xc2cea8a4", "0xb36e5794", "0x824e0084", "0xf3eeffb4", "0x71a0ff30"
        },
        {
            "0x436eb828", "0x1b375cb4", "0x3261820", "0x5b7ffcbc", "0x5859e49c"
        },
        {
            "0x1e5c0b28", "0x4fded465", "0xe5c0020", "0x5fdedf6d", "0x5182df4d"
        },
        {
            "0xeb71fde7", "0xf7bb47cf", "0xe33145c7", "0xfffbffef", "0x1ccaba28"
        },
        {
            "0xa6b0f01f", "0x8a8ca98", "0xa0c018", "0xaeb8fa9f", "0xae183a87"
        },
        {
            "0xa70bd8b7", "0x5c758cf5", "0x40188b5", "0xff7fdcf7", "0xfb7e5442"
        },
        {
            "0xf91af382", "0x718a9995", "0x710a9180", "0xf99afb97", "0x88906a17"
        },
        {
            "0xbd2a76ad", "0xddd8dfeb", "0x9d0856a9", "0xfdfaffef", "0x60f2a946"
        },
        {
            "0xd4b559cc", "0x91a53295", "0x90a51084", "0xd5b57bdd", "0x45106b59"
        },
        {
            "0x89434e9e", "0xa42fdaf9", "0x80034a98", "0xad6fdeff", "0x2d6c9467"
        },
        {
            "0xb947ac04", "0xd4201e52", "0x90000c00", "0xfd67be56", "0x6d67b256"
        },
        {
            "0xa83945c1", "0x3a9c5dba", "0x28184580", "0xbabd5dfb", "0x92a5187b"
        },
        {
            "0xbca38ffa", "0x881ba9fd", "0x880389f8", "0xbcbbafff", "0x34b82607"
        },
        {
            "0xfcd0b92", "0xeaad8534", "0xa8d0110", "0xefed8fb6", "0xe5608ea6"
        },
        {
            "0x50d160d0", "0x64646f75", "0x40406050", "0x74f56ff5", "0x34b50fa5"
        },
        {
            "0x165ccff8", "0x67d49127", "0x6548120", "0x77dcdfff", "0x71885edf"
        },
        {
            "0x8c4f4bbb7adaacb5", "0x2566b7a909b24aa9", "0x44603a9089208a1", "0xad6fffbb7bfaeebd", "0xa929fc127368e61c"
        },
        {
            "0x6f9ef50aafb31e8d", "0x7a93b2ccd1bbbff2", "0x6a92b00881b31e80", "0x7f9ff7ceffbbbfff", "0x150d47c67e08a17f"
        },
        {
            "0x4c99e967f8de5294", "0x1f4699e0c14e6974", "0xc008960c04e4014", "0x5fdff9e7f9de7bf4", "0x53df708739903be0"
        },
        {
            "0xcc55f5d6d3ea45c", "0x6805b4ddb6390c2f", "0x805145d2438040c", "0x6cc5ffddff3fac7f", "0x64c0eb80db07a873"
        },
        {
            "0x90620d1a012459e7", "0x89d31098ce3fed42", "0x8042001800244942", "0x99f31d9acf3ffde7", "0x19b11d82cf1bb4a5"
        },
        {
            "0xb87d1674e90a935a", "0x75ea466cbb782ac4", "0x30680664a9080240", "0xfdff567cfb7abbde", "0xcd9750185272b99e"
        },
        {
            "0x1f135732240701f0", "0x6aa09a1614bf4dd4", "0xa001212040701d0", "0x7fb3df3634bf4df4", "0x75b3cd2430b84c24"
        },
        {
            "0xc9a88d8300099a31", "0xdc8e91df745169ee", "0xc888818300010820", "0xddae9ddf7459fbff", "0x15261c5c7458f3df"
        },
        {
            "0xc8c828d15228b562", "0x43f86cffa3d15d80", "0x40c828d102001500", "0xcbf86cfff3f9fde2", "0x8b30442ef1f9e8e2"
        },
        {
            "0x41fdc0bc2009563f", "0x59dd1c417e3c07bc", "0x41dd00002008063c", "0x59fddcfd7e3d57bf", "0x1820dcfd5e355183"
        },
        {
            "0x9e2f78600c3a84e7", "0xac69a0e1fe7887b0", "0x8c2920600c3884a0", "0xbe6ff8e1fe7a87f7", "0x3246d881f2420357"
        },
        {
            "0xd424d1d9a955f617", "0x9608f5bde1c4d893", "0x9400d199a144d013", "0xd62cf5fde9d5fe97", "0x422c246448912e84"
        },
        {
            "0x1aa8b60a0627719a", "0x5b26e6aca95f5f60", "0x1a20a60800075100", "0x5baef6aeaf7f7ffa", "0x418e50a6af782efa"
        },
        {
            "0xcf5db499233fac00", "0xf33e7a29c3c33da8", "0xc31c300903032c00", "0xff7ffeb9e3ffbda8", "0x3c63ceb0e0fc91a8"
        },
        {
            "0x6b47c03d576e878d", "0x2032d13574d67da4", "0x2002c03554460584", "0x6b77d13d77feffad", "0x4b75110823b8fa29"
        },
        {
            "0xd47eeb3aefebf074", "0x6d7ba17a42c66b89", "0x447aa13a42c26000", "0xfd7feb7aefeffbfd", "0xb9054a40ad2d9bfd"
        },
        {
            "0x33ad9c5d20b03f5c05535f20a2941c8f4ae0f1f19500759151060dce39e5dfed41ec4f",
            "0x277401dc000fde7eda4d60a5698935f7febd8fbe49e5d6f56ca2e7f6118380d3cd655da392df3ba6c1b13dc0119af34cfa1d18a65",
            "0x10a9841c002016480453410020041c8640c0312191006411110401082924cfa1418845",
            "0x277401dc000fde7eda4d60a5698935f7febfbfffcdf7dff7fde2f7f7f38ba9d3cdf5ffaf9fdf7ba7d9b53de0ddfbff5dfedd1ee6f",
            "0x277401dc000fde7eda4d60a5698935f7febeb5678c37ddf69962b2c3e389a9920591f3ac8dc66ba198a42da0cd796d1104c90662a"
        },
        {
            "0xb6ea335c13111216862e370d12fb9c761a6266617f62a1904b0d7944ab3cddc71f11752ad9424b0",
            "0xa6b380f048a9cbe45ff4ea824064c831eb03ff875e1e3e",
            "0xa62200104028090410d480020044c831e1035285140430",
            "0xb6ea335c13111216862e370d12fb9c761a6b7e6f7feabdbe4fff7fecaf3eddc71fb17ffafde3ebe",
            "0xb6ea335c13111216862e370d12fb9c7610095e6e7be83d2e0ef237ec8f3a914401a14ad2aca3a8e"
        },
        {
            "0x8fb9486ad1f89ca5b3f6da9f0d5ef9ec328b8cc3e5122afbd8a67bd1b2b4ab5c548b90cf9fe1933a0362922f1e84ef0",
            "0x10615f963dffc13718ed1ecdb9cfbef33148befeb91b190dc7e7d28d8821ff248ab26a34e1b89885c643e447c72",
            "0x6051901ca58136188d0c4cb9cc32830040a412281b180443c192848800540080820a208138000082030404c70",
            "0x8fb9586bdffebdfff3f7daff1fdff9efbefbbdcbfffebbfbd9affff7f2bdab7dffaf9afffff5f3ba9be7d66ffec7ef2",
            "0x8fb9580b8e6ea15a72c1c272139340238c78bd8b5bec93e0c1abbc366039237dabaf1a7df5d572829be7546cfac3282"
        },
        {
            "0x10af96443b186faf790279bf3bbe0517d56ffc01e7fec8c88e765d48cc32333390224f4d762d1ba788c50801cba02524cb49",
            "0x95d44e7344fb1701bace3ae83affbb6290bf282f7565b9a82c386823f5f213a53eccb2cfe5deb4dd040067a64ada8c1b6828599b96cc70647e7d19dc7dfba393addabe689ffbe1a36642bc9844b81c6c4c2e178",
            "0x2c96442b084000000260ad288004028509b800c70640c080144548883032118022094d3608122408c1000181800400c148",
            "0x95d44e7344fb1701bace3ae83affbb6290bf282f7565b9a82c386823f5f213a53ecdbaffe5dfb5dffef7f7a7dbfbbffb797d5fffd6de7fecfefdfffdfdffe3b3bffbbe6cffffe3f3fe7abcd8c4bcbe6e5e6eb79",
            "0x95d44e7344fb1701bace3ae83affbb6290bf282f7565b9a82c386823f5f213a53ecdb836819d055bfef7f781d12937fb39550f6456d20f88f2f5feb9a97760b09ee3bc4c6b2c8372dc3a30c8c4a4a66e1e62a31"
        },
        {
            "0x5fc77dab8cd9c1da8c91eb7ba9c23ce85375b61bf3b9a8c4e4df7bc917aa8a14e747888c9756a2be2fd2e256e44194ce093a0185594de0dcf8340c45b6af7dbdc7682fbef6313f9f1cb234689d9f1ff603e1273faad89d0fe1ab57fbc7c32d29dce125fafc973754464b55ae5de58a8a5661c2065b95c2c94d7ec34",
            "0xd4a9158961d4c11258cd047eda13d6804c16c3a374b7f4115bd835bde0b5",
            "0x1080158800548100504504649012c480480081221420641158081495e034",
            "0x5fc77dab8cd9c1da8c91eb7ba9c23ce85375b61bf3b9a8c4e4df7bc917aa8a14e747888c9756a2be2fd2e256e44194ce093a0185594de0dcf8340c45b6af7dbdc7682fbef6313f9f1cb234689d9f1ff603e1273faad89d0fe1ab57fbc7cf6fb9dcf73dfefdb7bfd447eff5bf7de5cbee7e77cb7f5b95ffcb5ffecb5",
            "0x5fc77dab8cd9c1da8c91eb7ba9c23ce85375b61bf3b9a8c4e4df7bc917aa8a14e747888c9756a2be2fd2e256e44194ce093a0185594de0dcf8340c45b6af7dbdc7682fbef6313f9f1cb234689d9f1ff603e1273faad89d0fe1ab57fbc7ce67b8847738b6edb2bb8401a6f49335e14be66c5689791a807f4a16a0c81"
        },
        {
            "0x52cbea1f4d78445fb8f9267203f0f04bddf65b69b1acb0877143e77317f2d9679cb",
            "0x331e156a1e1daa0039926a08ec80c2d7c1500bc435a53ebfc32fa398a3304fcd79d90725528e320add050da666b9de42b8307b",
            "0x88421a41684412b839023200f0d00990725128a120a0805042666315e0090304b",
            "0x331e156a1e1daa0039926a08ec80c2d7c1552ffeb5f5ffbfc7ffaf9ae7307fcf7dfddf65f69f3acbdd771dbe77b9ff6fbe79fb",
            "0x331e156a1e1daa0039926a08ec80c2d7c155277a9451e93b86d42c0ac41070c27d64d840e41528c1d57219981188a16f2e49b0"
        },
        {
            "0xbde7e20f37c3ed822555d36050240dcfb5a9a3867d149cffe78e92b95573cbdde33a8c9495148e04cafa1325aae058b4a98c50f7019de1345de6dce12436bed4b86eca2d",
            "0xee480b4096f0c1ac565d623dd53b62dba81c507d3c8e15372396fa49de0ecf074fb0ed1785f00f8094022ff50fc436a7cbd18de8ff317c33ea9bdbd8814a7658fcd1fd10b2ed10eaf7e4c2b8f409df3c36f1f0c986a49805a9ed08bbcd603e2eec9e18",
            "0x547a00d1781e0020014022050040406a58981846814107c238a929950014a544038809410108c00caf20000a8e00894280450f00184a01005a0cc0020042014286c8a08",
            "0xee480b4096f0c1ac565d623dd53b62dba81c507d3c8e15372396fa49de0ecfbfeff2ef37c7fd8fa5d5d36ff52fcdffb7ebf38ffdffbdfff7ee9bfbddf3cbfffbfeddfd95b6ef14eafff7e7baf459ffbdbef1f7c99fe5bc5deffde9bffffefebeeede3d",
            "0xee480b4096f0c1ac565d623dd53b62dba81c507d3c8e15372396fa49de0ecfbaa852e220461d8da5c1d14fa52bc9f91262720b95ebad83d46409628df281abbbc65d6985a66314200df7e71214516b95baa107c81b45ac584f31e99ffbdeea96825435"
        },
        {
            "0x17ed0a1aa80542396e82ab79f6d4dda731d10f9487467fcfa5c8b501fa86488fbe268605c01beb257c9e301a42833d22965ea2ff0eda5f18427481a300a8f9aa81e76d774ea1dbed40268eca094bef627d2c206f6885fc12f71557bfda836",
            "0x422340e8ff3b4177efa5f58111fe306aa602d8020164fa34c12acdb3de81e",
            "0x2340604e21416540248480014a2062240000020004f810c10045b3da816",
            "0x17ed0a1aa80542396e82ab79f6d4dda731d10f9487467fcfa5c8b501fa86488fbe268605c01beb257c9e301a42833d22965ea2ff0eda5f18427481a300a8f9aac3e76dffffbbdbffefa7ffcb19ffff6aff2ef86f69e5fe36f73fdfbfde83e",
            "0x17ed0a1aa80542396e82ab79f6d4dda731d10f9487467fcfa5c8b501fa86488fbe268605c01beb257c9e301a42833d22965ea2ff0eda5f18427481a300a8f9aac3c42d9fb19a9a9aaf837b4b18b5df08db2ef86d69e10626363f9a0c04028"
        },
        {
            "0x290796408a0b8baa742b9d466afc4958528f7976fdce50caa83ed63285f58d200e4c65842ea24c3d4a3850a1824b61d25af9d3b41b9e64407a5262a75d9efd08481cfbc339ae26b0755438894b9e2298a35ed9",
            "0x4cb6f7935f5cc586320c6ce957f82cff774cde7d4201735a5acd22190fcb1c9c16d1887a",
            "0x4012f193141884040008406007580cfd00481c794201220210450018094b1c0010810858",
            "0x290796408a0b8baa742b9d466afc4958528f7976fdce50caa83ed63285f58d200e4c65842ea24c3d4a3850a1824b61defeffd3ff5fdfe6727e7eebf7fdbeff7f4cdeffc339ff7efafd76398fcb9ebe9ef3defb",
            "0x290796408a0b8baa742b9d466afc4958528f7976fdce50caa83ed63285f58d200e4c65842ea24c3d4a3850a1824b619eec0e40eb475be272763e8bf0a5b2027f04c2868138dd7ceab87621868082be8e72d6a3"
        },
        {
            "0x14e55ecb09d8c6827022df7c713c05a5d882e25782",
            "0x2dbdb54cb6341fcea6f67cfaa5186aa0a91b9782e362cbb0dd0ef3cbc130ce0cb2ce7232c0562",
            "0x10600e020898048060209c1000200124c002200502",
            "0x2dbdb54cb6341fcea6f67cfaa5186aa0a91bdfd7eff2dfbcfd2ff3eff7f7dfccfadffa3ee57e2",
            "0x2dbdb54cb6341fcea6f67cfaa5186aa0a91ad9d70fd2563cb529f1e636f7ddcce893fa1ce52e0"
        },
        {
            "0x2b0dfd23fc740e1759697bcba800aa1be7df28c59fe72b9869766ac34ecb4e5d0dbc74c2cbb5f734bb8d38dab59c3f22cdc706c657839580c2793c4c7660606548c048a697db3dfbad82e695c605",
            "0x33080f6fd52aeca572f24a98ff19b9e7327c3b951ccfd8c9a6b9bd6f7c940079e4be88178a2a6d5a2b17",
            "0x30007249108288030900a00cd0100c612001180004918482620206548800020849a0813880264100205",
            "0x2b0dfd23fc740e1759697bcba800aa1be7df28c59fe72b9869766ac34ecb4e5d0dbc74c2fbbdff7fffaffcfff7fe7fbaffdfbfe777ffbf95defffccdf6f9fd6f7cd448fff7ffbdffafaaefdfef17",
            "0x2b0dfd23fc740e1759697bcba800aa1be7df28c59fe72b9869766ac34ecb4e5d0dbc74c2f8bdf85b6ea7d47fc76e75ba32debf2165ffae15deb6e485d0d9dd0a345448df7365b5ec27a88bcfed12"
        },
        {
            "0xc0cc21922748d7626df1ab92b4ad4df1861050ca7de74adb92a140",
            "0x3531a6880ccc47bc3826056efe912f3db02df9c0b6931e253ab9248f472359fe59218690f6781f35da89b8f1ff45cd5a1db9a414c9d7ec62ff5859a1572b1c1880a99aa74ebe8b12c68e791c11dd6cc0e5ed5",
            "0xc40192054091400800898234a948b104004080410542c8020040",
            "0x3531a6880ccc47bc3826056efe912f3db02df9c0b6931e253ab9248f472359fe59218690f6781f35da89b8f1ff45cd5a1db9a414c9d7ec6effda59a377af7e3edfbbbbaf4efedf1ae78f7dbfdffdedf9effd5",
            "0x3531a6880ccc47bc3826056efe912f3db02df9c0b6931e253ab9248f472359fe59218690f6781f35da89b8f1ff45cd5a1db9a414c9d7ec6ef39a408323a66a3e5fb3238c046a540aa78b75bbcfa9c179cff95"
        },
        {
            "0x68cbb0a526d1fa61003e12401db51090fa4649b00b7be7465d0eb18f74c86157a919",
            "0x1ca7d6f9bc3e11d3c365af63bf9499b6c7e9c569da7361f0214b8d",
            "0x1610001c111080600641b00019a6464904218a704060010909",
            "0x68cbb0a526d1fa7da7fefbfc3fb5d3d3ffef6bbf9ffbf7c7fdcff9df77e9f177eb9d",
            "0x68cbb0a526d1fa7da7e8ebfc23a4c3539fe92a0f9fe25181b4cbd85507a99176e294"
        },
        {
            "0x210bef18d384992c5eb72e2b362c7296d9810f5ba9fd25e2d5648989d65095e45d1478f2a83140a0f68033a08fa3d7c392a3dc77e8e6aeba9ed76038e9e7825255fac990bf1098e6f9cba0",
            "0xdb48641b3f63e5f1f41ff3b1578c4b190de42379d45cba03c4c6f34b1b14ea930fdff90dca53116710228e45b081fbddc9273a542e6f689642453adb91086bdb99681342113262d67f5517f2691024fe367459b01872549211067798063cc00b16c883b8cd2ffaa6d6116863f204bb23ce26c5bcdaf3e1b816dcf65ca",
            "0x21014200d280002452a52800062c309681000113202d25e051640081024081644510008220010000660000208c00914080238c52e8a22c201686202049a20042445ac9803e108064c94180",
            "0xdb48641b3f63e5f1f41ff3b1578c4b190de42379d45cba03c4c6f34b1b14ea930fdff90dca53116710228e45b081fbddc9273afeffef78dfd2c5fbfbf3bb6bdfb96d9b52f5baffd67f7d57faf99d65ff7e75d9f79f7ad7961b0f7f9b3e3cfa3f7ef9abbdcf7ffeeeffb9ed77f38ebf7bef27dfbcdbfbf1b99efffefea",
            "0xdb48641b3f63e5f1f41ff3b1578c4b190de42379d45cba03c4c6f34b1b14ea930fdff90dca53116710228e45b081fbddc9252aeadfe250dfd080d1a973bb091cb0058b52e488fd04217841baf18d41f7683188f79758d7861b091f9b3c343a366af1a9850a5174cc3db88515f18a255beb039a1043f810b198b36ae6a"
        },
        {
            "0x143143205d76a7287d48be24db8fbfe37c291d82e103aa05cfc172fb920f0e8cc15c47de948b964e39be34a5b8a2610198c0c5b98543e6e727be153cfff0338f229cc22f029e04f766c62988634fee1a0a16880c93e5b10bada4018b6765b54c08f5710344dbfb9e9ad5dd7914cab496b22a6",
            "0x2d58b8b513f4bceb8300f8b978e31c163f36155e9678bb0f221ee7cbcf7262b9d53c7a395ea916218fa2478baada74f3e69df63a7be0c9554c07004f9e4d869642bbd63a9fe07138a6aef7ad14c74231cf6401c597f9b6d15c266c42c28613838609bd4f4522c9eb65fc8456acc339c641ac7d7b7bc2c48c8f2",
            "0x100201970a308140836045a8638a30c201c82c103220089c1307a100e0804010c0246808a924431a614a4382260011040050005024486060211143a902001208482270014044220c620004107e8120014000c02c080038184018947452048086570004488c31882418c79104a8084800a2",
            "0x2d58b8b513f4bcffb343f8fd7ee73c7f7fbe35df9ffffb7f2b1fe7ebcffa67ffd57efbbb5faf9ee1dfe7df9fabde7efbfebdf7bafbe1c9ddccc7b9cfdfefe7b7febffefffff3ff3abeeeffaf9ec7f777cf6d89e7dfffbedb5eae6cd3e7b71bafa609bf6f65b7cdebf5fd8756fffbbfded5fd7d7ffbf6d6beaf6",
            "0x2d58b8b513f4bcffb243d8e40e44346b7788318519c758730b03652accd86776144e81ab51a79ae0d3e5991f214c3aca58a95382d981c8cd8cc2b9caddab61b1fcaeeac56fd3fe1a3a6cd8af8ac3b557094d89a6d817acdb4aae60d12737182e22083628209785e3908d87127738a75c9471046fb176523ea54"
        },
        {
            "0x258e988b847b06b73462629161e28517f7b9ad7b5c19a9ad2c07f9a66f33fb2220fddb5a33b9cd5c2d63fd543efa1bef16e26b95484d70d0d7cfce28491ace0a608fb6cf9e97cb88d73c96c9150f9ef53c5e75bd68805fdce891e5935e9428ca67eba1e345148fcf2",
            "0x1857c0e26e0476169cf804c8d5a431022cce0da75d7642a2414a900370f201f5073c7e700ff6626fbd8a104182954fa9f23a45474af5456a00e36f6a6c8162afdf7492d387a455dd8506167d5cc24e6861d7b480b1458230",
            "0x1812c0a04000121280780040d12430020ccc05a319144082400a900360a000f10624385004d6000d3c880000808440a0003a44414874000800c16c0040816203c56412d2800455cc8106103548420c206092140011408030",
            "0x258e988b847b06b73462629161e28517f7bdfd7f7ef9efed6dcff9eeef7bfb3222fdfbda77ffed7e2d77fd543fff3bff56f3eff748ff76f6ffdfef2c593bdefaffafb6dffebfdfdef73eb6ffb7cf9efffdff7dbd78fa5fddf8d1e5f7dfdc2ceee7fffbeb4f14dfef2",
            "0x258e988b847b06b73462629161e28517f63cd1757af9eecc45c879eae269b83202313b80466ea9760977545409f53bf04691ac7248b216f62c176f2c51339af0ffac129bea389fde7732a03fb3c788dfc1a93c9050fa1a8130c184f48b580c2ce1f6daab4e00d7ec2"
        },
        {
            "0x328edc02c67d84bf095ac048e50c2dc29cffc08184b11e4da02904be14eccd317e9f6bdd6fe2b8233e8928d65d4ad434ef8a629cae6013bfb3c54be167e16371dc6412b62c2b1213424dfb7d391cea8a7494a28576ce823d8e111994182909efba7dd3533dbbe510dab4ac5ef",
            "0x61a1365a1226597896c514f5bb16a064f6ff6982ac91ea568daa43e473aa63867bdb628e92e97ebd4f2091",
            "0x4121224210201020968510918a00a04042284100a801c84001884180108a63865911228a92410ca94a0081",
            "0x328edc02c67d84bf095ac048e50c2dc29cffc08184b11e4da02904be14eccd317e9f6bdd6fe2b8233e8928d65d4ad434ef8a629cae6013bfb3c54be167e16371dc661ab76dab3277d7cdff7d7f5ffbea76dfeff7feeecb3faf79dbb43e6f3befba7ffff73dfbef97fbf4fe5ff",
            "0x328edc02c67d84bf095ac048e50c2dc29cffc08184b11e4da02904be14eccd317e9f6bdd6fe2b8233e8928d65d4ad434ef8a629cae6013bfb3c54be167e16371dc6208a5498a3076d5c4972c76475be072dbcd73eee44b232b79c330266e3349821a6ee51552cb8731605e57e"
        },
        {
            "0x37a92944b67fae733d201c024838975531bc3f748d98089eed38faed40c9463441cf48ac40e98097ce75db2bf0120ef69087a176d31d562cc99137c67e4a659cbb1298ba150aa191ced4089deee7048511de602414936af93cb2cef1b7ee801d9b75d961d33bb2958669b16193abf7b55ccfebac3a490415128dac92",
            "0x6fb8d83d986c4604db1b9396493a0a68270806cdbcc3299a049ebe77bd6891258e6313c720fb1b30ae9c4387ba51db3325e15033d9e01d499707c138b4cf4b85032da65e9ce3aabc5effbf7003771476ff71e86f665d2d3e7578dfcbb8f08c1619f609ec147f0",
            "0x88c811882c440490030014400a0008000804c51c822900008e2800380001218462008100780320a6184381280181102001102140801c4810004118a4024101022d824a0ce30a3c4801993001161432bb2148660214093a357855c8b8b080041040012810490",
            "0x37a92944b67fae733d201c024838975531bc3f748d9efb9feff9feed60cdf7bd79efdbace6ebf097eeffdf3bf9b24ffff7fff7ffd35df63dfdf33ff7ff4aeddcbb7bbdbfb73aff95cffd9e9dfeff74fd13df6cf4bcd37afb7dfbcefbbfefefffff75ff71d77ff79f86fff5f3d3eff7bdfcffefacfb699f759ecdeff2",
            "0x37a92944b67fae733d201c024838975531bc3f748d9ef3136ee17c292084f78d78abdb0ce66bf017a2ae171969b2471d77fc77ffc145b01df5e33877cd408c5883693da7a638ff84cde9969c3a7e74f902552cd0acc35823595b00cb1c2b6fe66c75ee109454458b009fd4b3404ca038a07464a4fb289b758c4ceb62"
        },
        {
            "0x1ab020d8beb54c354411f3a5658b5e5e87a896d7049c5eab20a302b6e35ca98364d7edd00eb3e209dcb035fe4b6eeace4e525229bf790c67bae63821e1282712d7c624efa64b3e5ad1a73aeb1033d4cd5949d63183173632445c9f488e74cd",
            "0x4d706a200a7a70e0b6eeef2dbdb88779dd50af16e6405c17fd2c2efb5493cf13b730207a009a14ca150042af3e6b7f05230161a10073f87a56afede3c2cfd09857f78d7913cdd966e9a2e6e6e3",
            "0x45000000a2a20a002a6e30ca9800451cd500e12e2005c10352c0a6a40824e1212202078000210c21000402826025704200120010052d02212ab0023c0cd5008563181111200404489008664c1",
            "0x1ab020d8beb54c354411f3a5658b5e5e87a8dff76ebc5efb70e3b6feef7dbdbbe7fffdd0afb7e649dcb7fdfe6ffffedfcf53f739bf7b0cffbeee3d21e3af3f7bffc727efe7eb3e7bf9ff7eeffdf3d6cfd9d9d7f78f7f37ffdd7effeaeef6ef",
            "0x1ab020d8beb54c354411f3a5658b5e5e87a8dba76ebc54d15043b4580c71143be3ae3080a1a5044980a7c8d26595be5d8141e5199f030cfdae2c2d21a3871979a8c307eec7ea3e2929dd6c44fdd0160289d181c60e6e25ff9d3a76ea68922e"
        },
        {
            "0x85993ec08ac960d46bcba87136f24042485c6d3e0a9973e828df60e537860d6bc83dafa7fb292beef466d0a939ab9da2b",
            "0x4c9a310b11d6e4b4d29d7ede30fb42161fd6a58792440f416abda6df55913a8a26c35140524de5dd9519c30f19641f4f0863bfefc2ae6c89333dd77d6f688cffcbde281772cee0dac9bb0dd16b6c1d33fa7e39b2e781896dcc2b0aba3abedf1381f9f38eb210f5bd2001ea8453ceb136dc3915fabdc30709db0b1a07ec40be",
            "0x811926c08a08601002c8803022a2004040180d1e0889210808d2000420040c6b002d83815b290820700490a1202a8402a",
            "0x4c9a310b11d6e4b4d29d7ede30fb42161fd6a58792440f416abda6df55913a8a26c35140524de5dd9519c30f19641f4f0863bfefc2ae6c89333dd77d6f688cffcbde281772cee0dac9bb0dd16b6c1d7bfbfe39bef78dcffdfeaf1bff3ebeff97c7fbf3afb73ef7bdf60ffbfc73debdb7defb7ffabfffef4fff0b9b9ffddabf",
            "0x4c9a310b11d6e4b4d29d7ede30fb42161fd6a58792440f416abda6df55913a8a26c35140524de5dd9519c30f19641f4f0863bfefc2ae6c89333dd77d6f688cffcbde281772cee0dac9bb0dd16b6c156a6992311e718ccfd176ac19d51ebafb96472a1327252e7730d60fb9fc33180db506c36a482f7de84fb601899d559a95"
        },
        {
            "0x4d9f3e8aae22123e382e7835d3d9d7e944a5c81cab3415fda40d0ec8fde8a50d8b21b2298f83a65bbdb10d120d302d8db4e9807715be0e",
            "0x4dacc1a6f2cecd4179556cbbdfe1cedbc952de5232ff1fe1ae9c0c3bbfcd9087e4ed5bcd1f8c289b1456ef032d888",
            "0xa48104308c4c004854008a93414eda4050cc02128a10c0a2180018b8080083c00051001300089b0410070109808",
            "0x4d9f3e8aae22123e3cfefc3ffffdfffd57b5dedfbffe1dfdbc9d2fedffeff5ff9be9f2ebbfffff5bffffddbeddf8ef8db5edeef737fe8e",
            "0x4d9f3e8aae22123e3cf4b42fbcf53b3d53309ed716ca09101898232ddec754f391c872ea347f7f53c3ffd8aedcc8ef0405acee87276686"
        },
        {
            "0x28d61d5ca1f56b4d3134009f478b17ac208a5b559d9c3726a7a16919e3b12ec6d61a142dc04d834141a9a4",
            "0xb444947aba00d50e10326ebea7a2618a10144dde07c15c685d4785eae16d232eb741bc2a09b7cf794a33ed3598803ad61af",
            "0xc00104a1e06a041020000445801404008050501c8c160222a16019c2a00a44d610002cc04980010121a4",
            "0xb444947aba00d78f71f7eebff7b6f39b501dfdfeb7fbde68fdf7ddfbe37f6b7eb7d1be3b1bffef79eb73fd35d8b43ede9af",
            "0xb444947aba00d78371e7a4a1f116b299501db9a6b6bb9e60f8f2dc33221f4954a1d022111b5ba218eb71313140b42ecc80b"
        },
        {
            "0x1b9a0b9c87fa234d05d06e18171cce3f8fc4adf7f75a402c4c5a281f46e714b96badab2184546aa11a7be482616cbb973da00e329628d3e692b69b43d34391884d87fcd64e2339fbb30044a370fffde97a128d1e5",
            "0x7d641e556550c3ddb89ee553cbc0d8d92cdaec6519a2ff3bd792e0b309c24cb49056fb219ef4dfb2a72e76ac7df3407a44e55af5689e9c85c87e74d542dfb445f56a0a518c",
            "0x78640a55655080008084a001c0405049049ac8201800462a1182a000000248b01052002108608d32212a60a43d30001804c05ac56082108588300440020fb4449520085184",
            "0x1b9a0b9c87fa234d05d06e18171cce3fdfc5edf7f75e7dffcdfe7d3ffeef9dbbefafef719e7ffbbd7b7fefb2fd6cfbdf3defbe3bff6dfbeef2f7fbc7df7797ac4fd7ffd6cfebf9ffb7e74df77dfffdff7eb2ad1ed",
            "0x1b9a0b9c87fa234d05d06e18171cce38598548a1a2567df7c5b47d23faea992ba6036d701e7b991c6355efb2fd4870de38cfbc2b796528cce051f1840c77962c03d25380c7caf1a734e709f75d04b9b62cb228069"
        },
        {
            "0x142cd4c71f04927a526ca430e542cd9432860",
            "0x1337869f6c145daf15b226485ef3c48b8037bf7cb2cc9834153b90f55d4217a5e4a9ea133",
            "0x142c90c41804103a106404000500c48022020",
            "0x1337869f6c145daf15b226485ef3c48b8037bf7cf6cf9f34977bd2fdfd72f7e7edbdfa973",
            "0x1337869f6c145daf15b226485ef3c48b8037ab50660b87308741c299f972f2e7293dd8953"
        },
        {
            "0x4f517f63e95a08284faaf4d4a290c334fc5d039e386727ddbb5d0a6d5fbb5540e97767023d60bedd158ed25051a6c56",
            "0x9e2c9c6d2e3be2ad25733871aeba4ba64081294478f936f9c4fc45ada6bb2c098c98f21e709a88995cc3b0cf7e693f8e73f58f8f4735c81e8421182fc15426174f3b6da7b493135c",
            "0x4f405a4269120008498a20c400808114cc190096200320c53b5808645318014040110200154020541186d2504120054",
            "0x9e2c9c6d2e3be2ad25733871aeba4ba64081294478f936f9c4fd57ffbebfac8b8cfaff5f7abb8cbb5fc7f0ffffef7ffffbf5dfafd7fffd5e8eb77e7fe3d62fffdf7beda7b59b7f5e",
            "0x9e2c9c6d2e3be2ad25733871aeba4ba64081294478f936f9c009525b982e8c8b08625d533ab384aa130660f69def4df3a8405f2992ce7d4a8ab66e5fe2822dfa9e638082b1897f0a"
        },
        {
            "0x1713f8f439c07e35b741ec9b0bca80149a7ef129c73c23c34b4515d29dc7dec711007fa395ced70f3bebc6d229edb75bf04231f2414e0a826f3edae4edcf770d59650cc252c6a2eff07fda9baa70938085d1e15144a451d26304d8f3df2406b8eb40f4fae3666780d2e54cd93a5f17439a4d3656dc5d48",
            "0x328df4b64b0bd0fbea359666904ea4aa215b03727a70bda853b6cf612b12c3d56ee93b003bd00a7b9c1d6755f580b467deba33bf7f33da4c37fffe79e73e4381ad4bf1306d1b58f5eb276cae813d6f9153d1294c51098d37b3b80154da",
            "0x108094864a0310006a219446900e20aa005201603250b00011b241400a0243144ae02900330008610c004244a080b067da9a22301300804021514420411243008843d12004184840e02260260100428140d1284c110188053210005448",
            "0x1713f8f439c07e35b741ec9b0bca80149a7ef129c73c23c34b4537dffdf7dfcfd1fbffb797eed74fbfebe7db2bffff7bfdea73f6cf6f2b92effffeedffcf7fdd5b7f9cdf77d7f7eff47fdebbbbffffb3dfddf7fffefdf7fe6385fdfbff346fbbfbf5ffffefeee7bdfff55fd93b5f574b9f7fb7fedd5dda",
            "0x1713f8f439c07e35b741ec9b0bca80149a7ef129c73c23c34b45275f697195ccc1fb959603a847419f41e7892a9fcd2b4dea62448e2f2190acebb40dd6cf4cdd531e90df3593576f4418042199cfecb35f9dd6aebaddb6ec208575b82e146ba3b3b51fdd8fc8e6bdbd741f081313464a177a85eedd0992"
        },
        {
            "0x68bc9c8f8257c6c88c0b2d46defc4539748fb906140acbf1a68820d1748bfc13ec84619f2b495d1ce74e0ca441a246497",
            "0x2d30db90794c4b611858b19c973ea865904346738291751ba5fccc5cbf02c09876aca6bf23289174f545ad8039e0fbcefe359521dfc9681a7715e672fdc23cc446c7900851d2ed09568729c88bf9653c63f7e229893f31059e8b51924a54968d44e5bb26decae3159ce786d9b3a1454c6d6cb8108d22bd5111d2cc7eddb",
            "0x68241c03824200880c0105068a50000854868904040a02d0828000906482d813a004400d2808100c220c0000408046493",
            "0x2d30db90794c4b611858b19c973ea865904346738291751ba5fccc5cbf02c09876aca6bf23289174f545ad8039e0fbcefe359521dfc9681a7715e672fdc23cc446c7900851d2ed09568729c88bf9fdbceff7f7efc9bf3b2ddedffdd77b749fbd46f5bbefffeeeb35ddf78ffdb3edc56dff6ff95d9de7ff5db5d3ee7eddf",
            "0x2d30db90794c4b611858b19c973ea865904346738291751ba5fccc5cbf02c09876aca6bf23289174f545ad8039e0fbcefe359521dfc9681a7715e672fdc23cc446c7900851d2ed09568729c88b91d9a0ec75b5ef41b33a28d855add77320193442f1b1ed2f6c6b354d930d25a04dc12df247f14d91c5f35db5936e3894c"
        },
        {
            "0x6eef644a36b1e052a413160909a537f81d46b2d330981f507d84737065541b5bb5faebfa8491dcd0347fbe498a501e254b91f6d82d6771a69d0aee5a490e2a44a8ba4f5da963d70b486f36f4a65f372a6a60522cac6e6a01d1a2da8743d5381",
            "0x391d108a0ba169bb746b3d5816fa985288c230bdde7e3b8433f8d595b63f08a90448923f30926960cf736be42e377b087e68848af89d80d95122b942b0162153d9d665c0e3508d8a25c8862c0bb7ad4f00e4b1213326f5ce32433df12cb9",
            "0x3004000a0a01280130601018127a8050080030098074038003300415003508090408800910800140cb6008a4002250081e688082701800d00020a000a004000380d4408021508482214802240332a406002080002220150a200034310081",
            "0x6eeff5db3eb1fa56bfb756bbdda57ff99d6ebef33bddfff3fdc77ffd7d5f7bfbbffaeffba7f3ddf6b67fff7fbe52ff77fb97f6d86deff9fe9d9ffe7bdd2f2b66bdbfdf7ffd6ff70bd8ef7efce6dfbf7afef05e6fbe7f7a6fdde3feb7dfd7fb9",
            "0x6eecf59b3e115a443fa450badc245851986e3ef03b45f8b3c5c74cfd3c0f78ab3f6aaf73a762d5f6a273497f3412fd52fb16105065c8f87e909ffc71dd252b26bd87d23bf56de20390cd6a7cc49f8c50be905c67be7d586e8d41feb49cc7f38"
        },
        {
            "0xa210334e6ffbec2fcfa42021075f84222c7",
            "0x181b940df674ffa93b3346264fed88e40b8d8f252487bc1f2cb4c3284fa17145d2cd0c77102fc177898e53fb12c40525aeb017a57661a80a268f27b4c78cbb4bae0e96ed0065e32bc7dcb01be9cc4e6bd5db5e453e94855cb2d1d3f86e8218fe55035102fc10901add0eb539089af",
            "0x821032440351002c0080000106150000087",
            "0x181b940df674ffa93b3346264fed88e40b8d8f252487bc1f2cb4c3284fa17145d2cd0c77102fc177898e53fb12c40525aeb017a57661a80a268f27b4c78cbb4bae0e96ed0065e32bc7dcb01be9cc4e6bd5db5e453e94855cb2d1d3f86ea218ff5f6ffbeeffdfb43afd0fffbd2abef",
            "0x181b940df674ffa93b3346264fed88e40b8d8f252487bc1f2cb4c3284fa17145d2cd0c77102fc177898e53fb12c40525aeb017a57661a80a268f27b4c78cbb4bae0e96ed0065e32bc7dcb01be9cc4e6bd5db5e453e94855cb2d1d3f86e2008cd1b6caaeed3df343afc09eabd2ab68"
        },
        {
            "0x2db0666cd0edeeab9e46e5b729521be3ece0714ffeefe18cd1b8b0f17e04c51b0d79fc6d428c22b9af63756",
            "0x1c1d5f18453c10d365065465c676fb8b58cb436b88660a0e19c350feb1f6954caf029a43a3e59bb35ce0bdbf80a7b8ff4b4f5d7d133bd244df8813e9695b1a6af9cea293e5da9ce4f8e1035fc8ce4ca62ecbec89e89fe25053e4153899415f61c41fcb412f13b58ac70fb84077831497f",
            "0x8906468c0014e888e44a426094009e08ce05043e4052088411820c01e00410b01318845028800318300156",
            "0x1c1d5f18453c10d365065465c676fb8b58cb436b88660a0e19c350feb1f6954caf029a43a3e59bb35ce0bdbf80a7b8ff4b4f5d7d133bd244df8813e9695b1a6af9cea293e5ffbce6fcf1efffebde4ee7bfebfe9bebffe2715ffefff99dd1fff1f57fcfc53f1ffdfeef4fbc62ffaf77f7f",
            "0x1c1d5f18453c10d365065465c676fb8b58cb436b88660a0e19c350feb1f6954caf029a43a3e59bb35ce0bdbf80a7b8ff4b4f5d7d133bd244df8813e9695b1a6af9cea293e5f72c829431eeb163500a4399e2be920b7302211c1afad91590e7d13561cf84341ecc76aa4d3462ce2c77e29"
        },
        {
            "0x33de1dc3fc5d6eeb5cbca27cc816a3727d1f9188400ea6b2c2799a40f7e611770b45cac7ed49fc0b66a46fcaf2393c0e03741bd08d26308fce62b0c56fbe44cb0949990bc3d4e5919ee1706dce518d6a06e865bdc26e761ef6723241b33583262bc4365103ba49dd17c0",
            "0x148a80223564208532d09dd94cf189921325cad8f2a6a32568e36b2007f00866ce0c8e59034cac999f915817492737af76413832e2c4e840627b91b54766a1555e91b87b2692df16c41161184ac9a124d59aad5c06b1a61892cf5c0cd6cc628f764a161f1bdd6546cb51a1510eef5ddfbd",
            "0x1121081d84c608910102048c812a222250881080006a00042480800510200240905804005492403262441083220040800601b9085062081444290806b2600cb004011010040c18104c1102d4c0081220080451c00464402867202001311812402c01001010a495d1780",
            "0x148a8022356420b7fedddffd5dffebdebfa7fed8f6a7f37d7ff3eb600ff6bae6ff9eceffe75dff9bdfdbdfff49ff3feff66ffaf2fbfcee43767bd1bd6776afdf7eb1fd7fbed6df1fcd996bdbdeedb1bef5faedde57bdee1efaeffdcefefe7eff767a57bf3fdf676fcf77f153beefdddffd",
            "0x148a8022356420b6eccd5e25119f62ceaf87b610e405d1587772e3600956baa4b796ceaee55ddb92da5b9ffa00db3cc9d22ef2c0dbf8e6431660413861562e9b3c217d1498d6141f8d886adb9e2c30ba34eac092573ccc1e7aaae1ceb8ba7c79047857ac2e5e436d0f67f052b4a680c87d"
        },
        {
            "0x683d881de1820ee9fbb71ccd74fd10e3a9ce71bd132955b9e9840d9259275498d2fae81b112416f37e9af907c319657d5d81623462b98d93818a23751a2196de6dd7c18e05960",
            "0xa9a2ae43423e6c78cc59ceba6601f6d85397527c462767dceeb1ebc6ad425fb2810a2b7525",
            "0xa880a002402e24688c104c300601d4d81203422800012018a2314182094046900008205120",
            "0x683d881de1820ee9fbb71ccd74fd10e3a9ce71bd132955b9e9840d9259275498d2fafa3bf53437f7ff9efd9febbf657f7d857b7567fdeff7fdceeb7fbe6bd6ffffffd1aeb7d65",
            "0x683d881de1820ee9fbb71ccd74fd10e3a9ce71bd132955b9e9840d9259275498d2f07231f5103515b9163c9b28bf056230045b41457defe5fc44c86ba64b42fb96ffd12cb2c45"
        },
        {
            "0xa827c5e2bd4293ed726065b32cac5c18d9df68b18300848f23f98c22fecd6b9fe7ed38a5adedd78f8dfe975d85c171f62b766947d7cd3d2ed3be52b50b792c0d6bb2701e28f22674a092e5ee0ec89bcd52680c6ae673a",
            "0x1deac63a0a7ae71db949662f05aafcefed47a6c6dd5819dc82d250d978001903a1f19e1b8b44e76bd5899884bb97121fa13a63c33822314a486d29b59b66f141fd64af3414a3ea6bdca9b4362e704c744e8a12c1ab736636ca3aa9da4b75795f1a",
            "0x202040a28c429068606045810c880c00099700018000040921b88402768d48998049382121e813860c328201048000d20b502047140d140ad30042340239080943226004004020202012a52602488388102004428471a",
            "0x1deac63a0a7ae71db9496eaf7dfeffffed7ff7e6df5b3bdec7d3ddddfe8b1933a9f9fe3f9bc6efefd7b9fefefb9f5adffd7afbdff977f95e5f7f6bb7fff6fd7dfff6ef3ff5abfaffdee9f6bf2f71eeff6eef5ac9af7fe6fecbbefdfecbf7ff7f3a",
            "0x1deac63a0a7ae71db9496cad79f4d73bc47971e0db032b164713dd448e8b0133a9b96c241386c887033066fa681d48c17c429b1cd157e9165f724b02fdf28c3d2eb6420ff188badc4e69628d0971aefb6ced58c8852d86da43867cfccbb3d73820"
        },
        {
            "0x1cc981657c8a20f5c777fc1df0e3cde0b23d434e043732dcaaa0758e009a8d1bf8591ff8db693d676eff2c39645b79c06b510ac22b1b47551eb728aa9404c24f2a6dee6bbdf2276759786f4116d21f4009dd6fb8e277976668bd021effecc797ca23682b97dbdffb93333834b8bb8fb68e922f42e3c00111",
            "0x1e52f1e05fbedda88873e9984a7a19bfbfbe9ea43e30588f46317b5cadc8eb02d255875f1dde872476d05dec1164e46c7fcf3fd718fff34a80d4c6e951d10f6ae0225d00e3953e99e",
            "0x61010a002b094200063608808400824b2a69ea43a10000644110254014821000015865b0c060124668050200164c4687c823682187db14a801002814181086a60200000221400110",
            "0x1cc981657c8a20f5c777fc1df0e3cde0b23d434e043732dcaaa0758e009a8d1bf8591ff8db693d676eff2c39645b79c1ef7f1ec7fbffdfdd9fbfb9aeb7a5dbfffbedee6bfff7aff77b7fffcbdedebf6d2ddd7ff9fffff7676dbddedfffeec7d7fef3fd7b9ffffffb9f7f7eb5bdbbffbe8eb7ff4efbd3e99f",
            "0x1cc981657c8a20f5c777fc1df0e3cde0b23d434e043732dcaaa0758e009a8d1bf8591ff8db693d676eff2c39645b79c18e7e14c7d0f69ddd9989b12e33a559b4d18404285ef7af933a6fda8bca5caf6d2c851a493f9fe52105b8dcdfe9a2815036d0955a1824eb539e7f56a1a5ab79188cb7ff4cda93e88f"
        },
        {
            "0xb77c8e0971a4f32bc9539c14b542ed2fa08e87560981cbdca4ccf4f7cc04fe7546a4a7eebe2592d131329fd591f66728a4179e",
            "0x2fb77bc1694a8265e74ee9f41672fc681d72ea8eb65ef5807bcba4bc52ef9e381a4e4315a771497e506b734def1ca93dd519fe9e6944dd782380dff70b72798c",
            "0x327c080970a08222485180108100ac02a08e0012080101842048745048004c6504a025c4182492410010180180d6670820118c",
            "0x2fb77bc1694a8265e74ee9f416f7fcee1d73eeffbfdff79c7fffe6fd7fef9ebf5e4fc3dffff5cdfef7ef77ffff5eadbfffbfff9ef975fffff791fff72bf67f9e",
            "0x2fb77bc1694a8265e74ee9f416c580e614034e7d9d97a61c6f7ee6517d4f10bf4c47c2de7bd5858aa7a777b39a5a0d9a3ba7db0cb875efe7f611299023d66e12"
        },
        {
            "0x89a0fbe80f4c622f45f4f7a15d8dc23bff17d939349f39cffa643af024db78243fc46c7948ab14ea12595e8a6cf2196ed4f353d9b1b8834b96fb61073301b99af019f042b2215e8cd5f31cf65123dab47d6b697a",
            "0xc2b6f7a999af54a94c156f771b995b528",
            "0x22215a8890f108944102d23039012128",
            "0x89a0fbe80f4c622f45f4f7a15d8dc23bff17d939349f39cffa643af024db78243fc46c7948ab14ea12595e8a6cf2196ed4f353d9b1b8834b96fb61073301b99af019f04ebb6f7e9ddff75ef6d177fff5fdfffd7a",
            "0x89a0fbe80f4c622f45f4f7a15d8dc23bff17d939349f39cffa643af024db78243fc46c7948ab14ea12595e8a6cf2196ed4f353d9b1b8834b96fb61073301b99af019f04e994e24154f06566290752dc5c4fedc52"
        },
        {
            "0x61cc2de53fe06a0381ce0dc4999795469453324c9036484632c257f02dddee71188198ed649bbe9ddae347178970bfbd3f1f28a787ee407a433f8473ba4fb77940227b769c9d555a8a70917ecfd038f80da4c6d5dc7211cc468c69a2275cfc119f145d2887543bbeb24",
            "0x117135d192a9645062d1be59a1f8b151692159285e5877a0ae304521ad800f51fbba812d038e053cb79578c70cd34248a2b4026533bb961add83d9362893b74ce01695861c82b6f94f181feb4a957875c74cf1e7fe48dcc5196bf1214cc564f599168bf2fee1a07e617cfac992443fcdb28247",
            "0x1c408050b000202018205c4811200420452124800340802200250302051ca71108010cd24008a09402243138960ad983d13208103644000411800402a4f947100223020148554508a1011648dc010900d0004c454421180408c29a20204e4118f04192003541b28204",
            "0x117135d192a9645062d7bedbfffbff57e9395de8de59fff9fe794533adc90f75fffbad2d7f8eddfef795f8df8ed74bfbebfdae7573fb971bffd3f9f6aafbffece7b6b7fe5fbbb6fb7f9c1feffffdf9f5d7ecf7efffecfdc79febfb6d6ddde7f59dd6ebf6fee3f5ffe17dfbcdd2cc7fcfbbeb67",
            "0x117135d192a9645062d7a29b7fab4f57c91945c88211eed9fa59001289490c357fd9ad087c8cd8e25084f0de82050bf34b69ac5142c30111265028c4a2ebc9a8e7b2a67e5bb91202388c1dccfdfcb1a092e456eee9a421c696eb2b6d2198a3d485d2e33464c3d5b1a0650b8c40cc4a8e096963"
        },
        {
            "0x1af3ce2ba6101f661c52430ae7280e3491d8d044a6621c3ef348c4e6e45fc6dfc91ec46b27214a9ebff52a0922fdebf1e895cd7cc4f428c64b7b3c4711b53f1f04f25b2f63ba70f281f52cb8149509f1ad38156397556eedf9e5c72388364cdba9112913",
            "0x5c5811bd255dad9049ec956e6eeaa95895e56e1c5c03cbfe24ae065ac3f528fda51a966771d288dfe3aab7611232e6f6bde10cf0d97620ebde6370ab24dbdecd4d7783c05cc8579517951049f16b26cf1612f6344a669d93ac990a997dfb5180a07a75f6a20dc110fd5547e744cfe0b348cc1786d8c7f587dc83fd9e8fdb9",
            "0xa00e02861011200452010885280a201010000426621c10c3088462041dc61708124429240042183c050801205169510095043044f02006434024411130091000925b25000a00a201602098100501502c30046203140cc1786584230834481b89002911",
            "0x5c5811bd255dad9049ec956e6eeaa95895e56e1c5c03cbfe24ae07fffff7bafda5fef7e775f2aeffe3ebff7d9f36eef6bde3eff4dd7e6eeffe6ffcbbecdffeff5dffebff5ee8d7bfdfbf1ec9fdffeecf569ef6b7fbe6fd9bfff9fadf7dfbf7bba77f7dfff2cfc159fddf5ff7c5dff9f75eeedf9edcf7fd87fccfff9f9fdbb",
            "0x5c5811bd255dad9049ec956e6eeaa95895e56e1c5c03cbfe24ae07f5ff17929ca4ecf7a255e226ad6349fe7c9f36ac909c22e3c455384eae220e8c3ac89d6cbf59de683f0e68c5bac92a0ec0adbcea80549e9283f9a2ec88ff68fad65849a7bb07755de9f0c64059adca5d34c599d9c61e22c81884b5cd04b84e470f9d4aa"
        },
        {
            "0xcd10bb69c381582eff7391a446db73312e738c6978564b350ca88e09cad650ef89dfb4cb00831c41d4739e957fdac00124348c91183da60b8f12dd3e349cad8b8d752fd9ea5613b1a41818032e0a2f2030790009a4fe9cdca54f96402b143e",
            "0x7c4f944973a8882522976043833419c2c15b1531af1207b40092dd1e3c123a4cf06370c3111b",
            "0x104d140010a888052007404202101180001801200a020030000009043c10180440024003101a",
            "0xcd10bb69c381582eff7391a446db73312e738c6978564b350ca88e09cad650ef89dfb4cb00831c41d4739e957fdac00124348c91183da60b8f7edfbe7dffad8bad77bff9ebd737b9e6d95b173faf3f27b47992ddbefe9efeedfff770eb153f",
            "0xcd10bb69c381582eff7391a446db73312e738c6978564b350ca88e09cad650ef89dfb4cb00831c41d4739e957fdac00124348c91183da60b8f6e92aa7def0503a857b8b9a9d527a866d943161fa53d27847992d4bac28ee6e9bff530e80525"
        },
        {
            "0x1cdc2579b3f1727c03a0f733c6a1a50025c8b51640ed21fb0e700f873d35c83797a14",
            "0xe3e7298d39a9c7cd225125b1a01505e3d9ca63f8b494e4d7218b10e8bddc06984bbbe43e263f30f6a92a9d7",
            "0x10042120110162580220f03084a085000100a0144004004b0a600e063d30c02102814",
            "0xe3e7298d39a9c7cd225dfdb5f9b7f5f3fdcbe3ffb7d6e5f721afd8fdbfdcefb9fbbff43fa73f35febfbfbd7",
            "0xe3e7298d39a9c7cd224df994d9a6f491a5c9c30f8752457221aed85dab9cebb9b0b59431a102053e9ebd3c3"
        },
        {
            "0x3ac7a7062a50d421ec7b732acfeafd988b5fe95661d371a7f2fdb5b9c1d37e304dd3a0dfcb995e9f99e1b86696b54df83fcd4e87764ffe27fbbd785875c31993f20f4628df79cbaeb50c3dfd132e20935f33ee0276c23f445dff5a075a8198907c1e248787fb28c44495d2e2ed677832432eeda5026afb91467cef4b8",
            "0x12659e0b26181845981459681797ab57a50c5b4a34882e973f884d99c1e89c0457b99c9445be077039c60cffa057c608594d38423730d3eae76e8a8db6f946877e90bfecde4aaa320128ef3811cd31c3834e66fa7a61d1454778bf82781c091ae5fd348fd903d85116f83f331d84edaa925d1d65b0b30c1b7c6c69da380",
            "0x20860306081044000459600287aa5580085b481400021127804d9181c0900410099080458a0150198000b820168408580d0842073043ea276a88081071420112900f44084a280200200c3811012000834e22ea0260c0054458bf0200180118807c14048103d800044015120084652812410c65a002081b104468ca080",
            "0x127fdfaf263a58d5b9fc7b7b3fdfebffbd8f5feb76e9fff7bffafdbdf9e9df7e77fddfb4dfff9f7ebfdfedffe6d7f74df97ffd4eb776dffee7ffbffdfefdc79ffff2bfeefedffbfbafbdef3dfddf3fe3935f77fe7a77d37f477dffda7f5e899af5fd3eafdf87fb79d6fcbff3ffedeffab25f3fedb5b36efbfd6e7dff7b8",
            "0x125f59ac20324891b9f8221b3d5841aa3d8704a362e9fde6987ab02c78294f7a67f44f349a759e2ea65fed47c6c17345a172f50cb0469c14c09537f5ee8c859eed62b0aaf695d3f9af9de305ecde1fe3101155147817137a032540d87f46888275812aab5e842379d2bcaae1ff698ad2a01e338815b166e0ed2a1535738"
        },
        {
            "0x39d2210d760b098917fd1293f0708ed6ffcd7686a4041e774a0f52e808524d686429da6774dd45dcf69abb4a7a48116d71f8e38074196cddf128b041a28cdc1e12cf755c7",
            "0x59d65c9b948dab08f5c3604fb8b4d15085e4ae6ea8e762bbcceb904b3d9b5837977c4c9f2b9e9f3f8c6babd3b5e846ed8bdad898648bc4f8ccbea95d7a9cf5fd694e6b1a176058fbb30257aafa296741ab7181398c43a264a94972c08b4a5c56807a5f06b5b88eb420df822b43c43b400d0",
            "0x284221095208080003c41080b0200c529cc5740004001a17400852a000520868202140237081018c42822008484000094058428070190495b008b00082800802000b400c0",
            "0x59d65c9b948dab08f5c3604fb8b4d15085e4ae6ea8e762bbcceb904b3d9b5837977c4c9f2b9e9f3f8c6babd3b5f9d6ed8ffedb99ed9ffdfadffef9dffefffdffefee6f1e776a5ffbfb0a57effa6d6fdbef75dd7ddcf7baffeb7b7ad1ef7bfcf7807e5f6efdf9aeb461ff8eff5fd6ff755d7",
            "0x59d65c9b948dab08f5c3604fb8b4d15085e4ae6ea8e762bbcceb904b3d9b5837977c4c9f2b9e9f3f8c6babd3b5d194cc86acd391ed9c39ea5f4ed9d3ac63388befea6f04602a57a95b0a05e7924d4e9bcc055c7c50b538dfe3333ad1e63ba4b5000e466a6849a604617d0ef75dd6f435517"
        },
        {
            "0xcf08fe64414998cc59938913e660f0f9b221f459cd8e04126cf902d0b6cea0edc26164b9d84e9ce7dfe058c1fe0fb452848616368c3",
            "0x234286d14c1098ea9fd7f83508641ef3288da679fce09dd1359514ebf0dbcdc73b8f7f6171762d3d5df6492591c9386",
            "0x4000910810806090d1b02100400c820000247900c094c0208500616099c84618875f6050402c0d145200041000082",
            "0xcf08fe644149bbcedfd3cd13feeafffffa35fc7ddfff2c9feef9fef0bfdfb5fdd6ebf4fbddcfbfefffe179f7ff3ffdf6cda797ffbc7",
            "0xcf08fe644149bb8edf42c5037e8a6f2e4a14fc3dd37d2c9fca80fe302b1f9578d68a94621589a768a08129b7d332e9a4cda387ffb45"
        },
        {
            "0x343e32e61b86c0c7cc895cf233ea3d5b5ad65435c1f87e034b59788a9af14ffae9249f1f3cfe0789abbe8edc8ce",
            "0x63f7afb1dcebc9d65f9d468754ea558119988cb7d85e427003f2c1d9b360d2c75b97c1308ee3a7b5901044c6353e14f3e6b54a2ead64acdf914c6f7b6d4ed3205abdc78aa7bb47d548607b4ffe1db7331aac39c8bc7fcfd62238467352656a3ad04a423",
            "0x241e10440b024046c00058b0038a251b42d4402041487e010311188818c00c7ac9040218047202012a3a8048002",
            "0x63f7afb1dcebc9d65f9d468754ea558119988cb7d85e427003f2c1d9b360d2c75b97c1308ee3a7b5901044c6353e14f3e6b54a2ead64bcffb3ee7fffedcfdfa95efff7eabffb5fd75c75fbfffe1fff7b7aaebbf9ffffeff6bf3f7eff57edebbededecef",
            "0x63f7afb1dcebc9d65f9d468754ea558119988cb7d85e427003f2c1d9b360d2c75b97c1308ee3a7b5901044c6353e14f3e6b54a2ead6498e1a3aa74fdad891fa9064ff4609ae01d031c55bab7801efc6a6226a339f38526f2bd277a8d55ecc1845e96ced"
        },
        {
            "0x981ba5db1da1fe952887e32cd21d51ba024022c8d837ec00f9772a111f87644012cee4a01f66d09ef168ebdfb91232e9e8f65d63ee7e6e050ae9707e7b15df4f8037b0d8d427f32429a45312a24081ed5a9c8ec22358f3621c961349638f30e049d00d513901fe065d5364f4cfca93f14a2b1b",
            "0x1ba08accd8474ea8d9dc2f10d3c2c2edcbf9c3a909ab45",
            "0x38000c048400c0019002e00514240e4cbc883a1082b01",
            "0x981ba5db1da1fe952887e32cd21d51ba024022c8d837ec00f9772a111f87644012cee4a01f66d09ef168ebdfb91232e9e8f65d63ee7e6e050ae9707e7b15df4f8037b0d8d427f32429a45312a24081ed5a9c8ec22358f3621c9613497bafbaecd9d74ff9f9ddff16dfd3e6fdcffbd3f94bab5f",
            "0x981ba5db1da1fe952887e32cd21d51ba024022c8d837ec00f9772a111f87644012cee4a01f66d09ef168ebdfb91232e9e8f65d63ee7e6e050ae9707e7b15df4f8037b0d8d427f32429a45312a24081ed5a9c8ec22358f3621c961349782fba2c919743f9e0ddd1168e91a6190433505843805e"
        },
        {
            "0x1d9992a4fce731fe937e70ec9efba437b1efa9e5459e3145f8c9142c6988eca9a61273750bcc1f00a64b32bab5a3a4c89858231f4fedce7a73bcc7285bbd18b328ccc298919f5511e973cd124f7e1c3912d52f4593c676f1c3f87a521",
            "0x6e195204da93bdade43f0622217647326502417d70305d050d988",
            "0x421810045011a921c412062200300210250001447030410008100",
            "0x1d9992a4fce731fe937e70ec9efba437b1efa9e5459e3145f8c9142c6988eca9a61273750bcc1f00a64b32bab5a3a4c89858231f4fedce7a73bcc7285bbd18b328ccee99d39fdf93fdffed3f4f7e3d7f57f76f47d3ff76f1dffd7fda9",
            "0x1d9992a4fce731fe937e70ec9efba437b1efa9e5459e3145f8c9142c6988eca9a61273750bcc1f00a64b32bab5a3a4c89858231f4fedce7a73bcc7285bbd18b328ccac81c39b8f8254de292d495c3d4f55e74a47d2bb06c19efd77ca9"
        },
        {
            "0x123b8aaf5660144d596f10574b4c232f267222596831",
            "0x10ab460448ce805f18a3c1d64fc8cc0c02b2cd5f860d462e33602f09fd131e5468c86997e5a033729b2a03d3c284ee0111488ea",
            "0x1021028c0600144801270012000c2028066000100820",
            "0x10ab460448ce805f18a3c1d64fc8cc0c02b2cd5f860d462e33602f09fd133ffceafd6f97e5f5b7f39f7eb7d3f2f6ef2335de8fb",
            "0x10ab460448ce805f18a3c1d64fc8cc0c02b2cd5f860d462e33602f09fd123decc23d0f96a175a5839e5eb711f076892334de0db"
        },
        {
            "0x17529608c59c36277d9e89f9b275032e62ab42b4dc006f1943e12b088c36657b02937109db797e2fbb83c984f507841be083c5e36dd04a8b7d3",
            "0x1d556659e3b765044e08b1f7879bf057ef",
            "0x1814004940304104080810368500a017c3",
            "0x17529608c59c36277d9e89f9b275032e62ab42b4dc006f1943e12b088c36657b02937109db797e2fbbd7dfe5ff3ff65be4e3cfff7df9ff8f7ff",
            "0x17529608c59c36277d9e89f9b275032e62ab42b4dc006f1943e12b088c36657b02937109db797e2fba569fe16b3cf24ba4634efc15a9f58e03c"
        },
        {
            "0x23ed0547893da2de2673832f9e6d988ce38c44a47495c1e0a714eb2f18ec455157cc20ea9da75cdcb0c4e9afa546efb3650b7e5cb7e659359d17fe79d2d5116bcd6c5cca45e0719d063e7df33f6788e5c6bd77c114340748cf553c5aa4992076953c4904181e24bb7c26a6e895d8b808c70133b52c9ca4a2266c2e2302bf777",
            "0x3eaf5dd3cbba83558163fd16469a3d64905ff28ee65c15ff01f4d720b1ad669a893671bb614382f2331985333b0af52cbc0af22e50e4cb39d4ab3ad58127b3c481e692bb22dc0b497690e57e6fc84a87c2e1eb85e6c8bfc253fd497fc88",
            "0x20aa1d83489880448123a50646922500105cb286401415170070d20011294408080241a061010232311105230800c42c340010240040cb11140a2091002691040104101a20980800268085582808420102a12884a48026400221003f400",
            "0x23ed0547893da2de2673832f9e6d988ce38c44a47495c1e0a714eb2f18ec455157cc3eefddf7dffeb3d5e9effd56efbb7d6ffe5ff7eeff7d9dfffffdd7f5b1efeffeddfe75fb71df86fe7ffbbf77bbeff7bdffcbf63e57eccf7dfcfbbedda177b7fcc9e69abf26ff7f6ff6f8f5feffc8cf87f3f5ef9de6eabfee7fff4bfffff",
            "0x23ed0547893da2de2673832f9e6d988ce38c44a47495c1e0a714eb2f18ec455157cc1e45c0749766339168cc5850a929586fee034568bf6988e8ff8d05f5a0c6abf6d5fc345b10de84cc4eeaba54b3ef3391cbcbe61a57ac046ce8f19e4ca15126f8c8e28aa50667776fd07870a6d7c08d86f154c719426a99ae7dde4bc0bff"
        },
        {
            "0x4881b1172db56487aa0b4362479871a57",
            "0xd40bc374f241c2bb638ed6dea08d7885135052619d2f58523b3218b57371993a62bea6cfc8abf4abb8e4a96b0a38bbffffdd0bc5e5a6514f0db",
            "0x4081210228b16487880b4160061041053",
            "0xd40bc374f241c2bb638ed6dea08d7885135052619d2f58523b3218b57371993a62bea6cfc8abf4abb8eca9fb1f3dbfffffff0bc7e7e7d97fadf",
            "0xd40bc374f241c2bb638ed6dea08d7885135052619d2f58523b3218b57371993a62bea6cfc8abf4abb8ac28da1d150e9b7877008687e1c93ea8c"
        },
        {
            "0x1e0e22b43b6de9f7ee3000e87eef492f84ee1bcd3f490cdbf35171b174335fe53afa9b752d9b1e1b0bd58d71d35687cb7b74",
            "0xac57c7cfa532414e1182c7c499ffa996f7a28187f7f5d7586f0fd6b64e566bff1ff68daa60d7b650cfece99b8e2551941008aaa5ab966c526d584251600baf9f48d6b573e2779363363cea427961c0ac63d9c9abcc30976c3755b739dcbcccfbb7ae06b5deed54c59a5271caaa26134877898f75b065f3c72a8429ab5",
            "0x40602140a4429948a30000876c3410b008c0bcc0f0908c0635160914411052518aa82612483181803510451105280421a34",
            "0xac57c7cfa532414e1182c7c499ffa996f7a28187f7f5d7586f0fd6b64e566bff1ff68daa60d7b650cfece99b8e2551941008aaa5ab966c526d584251600baf9f48d6b573e2779363363cebe2fb6bc3beffdfffebcc3e97eef7d7ff7ffdbcdfffb7efbfb5dfff57c7bffe73efabb753d9f7e9bffdf8f7fff76afcbfbf5",
            "0xac57c7cfa532414e1182c7c499ffa996f7a28187f7f5d7586f0fd6b64e566bff1ff68daa60d7b650cfece99b8e2551941008aaa5ab966c526d584251600baf9f48d6b573e2779363363ceba29b4a831abd46b748cc3e1082c3c74f773d001f0f2763b980c9f64386afac226503914191c6683fc8e8b2eef242f89e1c1"
        },
        {
            "0x46529c1d4b03b4a0efd29ce200ce9564cdc4fa4b53b9b6725e3fffe3454d6e53848fa573858f0bdbcf846d790a5bfc7470d0b8ac1d494804fa7048b869d5e016e389bf93cb959469dca3f4c5e93f8bcb7dbb64bcec19c8d9dbc5f2cecb285d81f5fefe99ff4564662c7cc275a40f0ea519adb2",
            "0x1b10fed79bfd5e52ba14eea13cf223bfbeb5f42bd781083545c4306ed5f69250efc19707288aadf9df45b4056a293da0cfae076ee9b08e7a7058ef0a58e67149980cdc60a75825607ec4e531e9d036e71e3df52048853e3",
            "0x1010d6c518485a523810e0a13cf0029790a5b4034701080041c4100045a6000086811601280889f91c01100408083d004e82002ca190864a40408c0818a4510888008440075825601ec4440060c004271a00f02040801a2",
            "0x46529c1d4b03b4a0efd29ce200ce9564cdc4fa4b53b9b6725e3fffe3f54fef7bbfdfe57ba5cfebdbcfa67ffbeb5ffefd78d0bbfc5d4b4eedff796dbefdddf076ebabff9fffdfd47ffeb3fecdfbffffefffbbe7bfed9ff8fddfe7f6dfcbeddf8bf5fefe9fff4f777ebd7fee75e7df5ea599fff3",
            "0x46529c1d4b03b4a0efd29ce200ce9564cdc4fa4b53b9b6725e3fffe2f442832a3b5a405824c1e1c800a65682e104bec908c03bf8410a4ee9a5196db695cc90646b23600e3fced43f7e302ec913dffd25e6b3831be997387c55a2e6574be59b8b807ca89e130b3778b17fac0447d05ca191fe51"
        },
        {
            "0x1c61ea1ba6135d29a669cc258f24a09ce0c6af1fa717",
            "0x277557a8f45578e7730c64350cd3fd389bf96320fb3079402e9949062868fda63a6c371adf34952bd8fbf8a361671041556548ecabc7561f3febfcf26290dc819caa54b8eb26a7fb3a593202b2eb9a87fa214342ea4d639c3487882c7b6a03401d0715171c8ec44d45eff0c2571ca3f556d0d986fbeb5ff",
            "0x10416008a4005408a60804218a24000c00802f1ea517",
            "0x277557a8f45578e7730c64350cd3fd389bf96320fb3079402e9949062868fda63a6c371adf34952bd8fbf8a361671041556548ecabc7561f3febfcf26290dc819caa54b8eb26a7fb3a593202b2eb9a87fa214342ea4d639c3487882c7b6a03401d07d71fbdbee57dd7fff6ded75cf3ff5fdeddeefbfb7ff",
            "0x277557a8f45578e7730c64350cd3fd389bf96320fb3079402e9949062868fda63a6c371adf34952bd8fbf8a361671041556548ecabc7561f3febfcf26290dc819caa54b8eb26a7fb3a593202b2eb9a87fa214342ea4d639c3487882c7b6a03401d06d309bd34a5789775965e954451bf5f1ed5ec0a112e8"
        },
        {
            "0x259856f9c56582b4f8056fdbd37332ff6684ad104683782087ef2b965fa2d22153ca880d735c116878afac5b2477b7f",
            "0x1518494828299164e2ee455afe73cd24484df0def1e24c01926bdb2566d44e483a04bbdd5aeab159678305b6ade08cb5bc83e0e63a7bd9e2bb016c355f0fd9e94044e8e9dd380c64ea2f83d239d0987a6864dd1a07c9d742",
            "0x20105268c4008210c8040e438331122b2004811040811800044e0a945380c20002c8080111080120000d80002415342",
            "0x1518494828299164e2ee455afe73cd24484df0def1e24c01926bdb2566d44e483a04bbdd5aeab15967db85ffbdf6dcbfff83f6ffbf7ffbefff696ef55f6fffeb487efaf9fdfa2d66ff3fabd2fff5d97eefeeffdfb7cfff7f",
            "0x1518494828299164e2ee455afe73cd24484df0def1e24c01926bdb2566d44e483a04bbdd5aeab15965da80d931b6d49ef303b61b874ceacd4d6926e45b67ee6b483a1a50b8c22146ff132b52eee5596cefee27dfb58eac3d"
        },
        {
            "0xd8526c4a399bb415b422ab254fb7c9a053c1507e3260aac195366c5fed9ff583053547f1b8f54561838e8d5fff273e25",
            "0xdc8169197ca1b7f60394685c3438a5b9ff07c0deafe3d68064567be3d9ad3c577600e0d98c4bda37a6ed8175d437cded052bdf221c4c3d76221331061",
            "0x4002480a30180400b42028044527882012c14076200008808434205a6c981501013446d010b540218082854221231021",
            "0xdc8169197ca1b7f60394685c3dbda7fdff9ffbdfffe3feb274ff7ffbddbd3d57f726eafd9d5bfef7fefdff7df477ddff1fafdf761c7cfdf7fff373e65",
            "0xdc8169197ca1b7f60394685c39bd837d5c9e7b9ff4a1fc3230ad0779dc9129509526ea759518bcf258347e2de46499921ea48b740474d5a3dde142e44"
        },
        {
            "0x47ac96c78ee0c7a9906ce5af63d0ad1b0420e1ca783cc6904ee84",
            "0x630297e0f122e36f0c5f2f34efbb078c2f4c00e7c16f96cb054",
            "0x20028780e002a1000c452f20c0a90304204000600046904a004",
            "0x47ef96d7eef1e7ebff6cffaf77ffbf1f8c2fedcafffdef96cfed4",
            "0x47cf94506e11e54aff60ba80573f161c880fadca9ffda90685ed0"
        },
        {
            "0x432a40ea48fcb8b8161bc19a26b544f54833bf5e005c7d1c19e8405c5464c8c139fdd9b627865e596c513fc68454827f070310dd7efe80306693ce441c89a74d91db5e27d6ba966aa1e109cc8385bd86a23d127cf609eea4118e0e1d9be83b561dcffb0ec3844d22",
            "0x70d78d38ebcadb77733fc709a6d3b76576ca71acd7e3196640d6adc00225142070b943d5624a3a3d4e77a787d8221848ab06c5135",
            "0x50c7880002481864410882008011b560744a212482021004401009c002211020402002c0400820214836838540001800a80044120",
            "0x432a40ea48fcb8b8161bc19a26b544f54833bf5e005c7d1c19e8405c5464c8c139fdd9b627865e596c513fc68454827f070310df7ffed3befebfff773ffdf7dffdfb7e77febf9eeffff19fec8feffd86a27d527fff9dfff635afafddfffa7b7f9fefff8ef3ec5d37",
            "0x432a40ea48fcb8b8161bc19a26b544f54833bf5e005c7d1c19e8405c5464c8c139fdd9b627865e596c513fc68454827f070310da738653beda3e79332f75d7d7fce02870ba1d8ca7dfd09fa88eef6186806c507bfd9dd3f2352dadc97c92432b9fee7f8473e81c17"
        },
        {
            "0x7c4c2d104ca2a5c080fbf1e717e47f848ff9be3555bcff60c07907ade9e334a556157dcd28ebbfd73367defdc4d8f5de60815360394e4de6e7535d356ccb8a2d896157ba65a7e8541a06e604454aef3e8cebfc7aedb48466eb65039cf17c13fcdb1b",
            "0x2a73b2854f05d043d4e28e0b2634fd7023aaf3e57e58f213dd0693769",
            "0x2a0100804e00404084e2880a2604ac50000262a45018c213c10681309",
            "0x7c4c2d104ca2a5c080fbf1e717e47f848ff9be3555bcff60c07907ade9e334a556157dcd28ebbfd73367defdc4d8f5de60815360394e4de6e7535d356ccb8a2d896157ba65a7ef7f3a56f65d457fef3eecfbff7fffb6beefff77e79ff17dd3fdff7b",
            "0x7c4c2d104ca2a5c080fbf1e717e47f848ff9be3555bcff60c07907ade9e334a556157dcd28ebbfd73367defdc4d8f5de60815360394e4de6e7535d356ccb8a2d896157ba65a54f6f325216594177a1166c599f353ab6bec9d532e613d041c395ec72"
        },
        {
            "0x3ee957090c3ab10e1c8af669f2093bba430a4322a741522d2ce1d20b07558298627de3dbbbef8828abc64195bad0f9f6acbb734a420d0d8dd330e90d23ab633826a612060eb95070758199006b547b24792d59f97c3191b2dee7a96e",
            "0x7e30cfb7abf89648583c2f705f30abb997ded579a0de3172e2b546c920f92fbdf3bf5ffbd5d73620da518e7b4964a44505817d16c7028f4da494135d2589deffbfdb19f6a454f0431cda1884e51f48c67605f9f044e955a4f23da9dfa92af8dfba09ea6adf0390c",
            "0x4e102090838a1061808e20122091028020a02228701502d2c415202050500802014424010480000284000949a4041348018114a420d018d42004904218921080600100406205010040091004b005a0478000989782090a28ce0290c",
            "0x7e30cfb7abf89648583c2f73ffb5fbb9d7ffd5f9e8ff77ffe2b7ffed30fd3fbff7bf7ffbdfdf36b0ff59afff6ffebdffbff9ff9eff669f5fad9f9f7fefbffeffbfdbd9ffb75ef0d33efe3b86ef7f68e6ff95fff75cf9d5a6f77fbbdfbbffffdffb19fb6fff7b96e",
            "0x7e30cfb7abf89648583c2f73b1a5db295475c598687157edc226fd6d105d1d9787aa7d291bca1690af09a7fd6eba99febb79ff9c7b669616099b8c37ee3eea5b9f0bc12b975a6091266c2b068f7e68a69d90fef71cf0c5a2477a1b983bff67487910f1473179062"
        },
        {
            "0x20265b43c9319cd56eac6a02cbf7913ba44b",
            "0x995b92e854a8e0d548bfc02e18529b37790f0e4d9aaf36e7abc4a0f1e6d69489215aaa61b5863b1c86b3536b443dc639d1eb3db7789c2cb2f8cad1a74e5168ef33948c81a06fbad3b9ab0b7c84045cd1f77620ef43c7f2088d2901917bec5346a44f679be9491d273dbe5bf6e39095bb411cac63e38626013d671445c",
            "0x20261901493010c0462c2802401390310448",
            "0x995b92e854a8e0d548bfc02e18529b37790f0e4d9aaf36e7abc4a0f1e6d69489215aaa61b5863b1c86b3536b443dc639d1eb3db7789c2cb2f8cad1a74e5168ef33948c81a06fbad3b9ab0b7c84045cd1f77620ef43c7f2088d2901917bec5346a44f679be9491d273dbe5bf6e7b4bdbb59ddfeebe7a62ebf7d77be45f",
            "0x995b92e854a8e0d548bfc02e18529b37790f0e4d9aaf36e7abc4a0f1e6d69489215aaa61b5863b1c86b3536b443dc639d1eb3db7789c2cb2f8cad1a74e5168ef33948c81a06fbad3b9ab0b7c84045cd1f77620ef43c7f2088d2901917bec5346a44f679be9491d273dbe59f48624a92858d1fa8925260abe4474ae017"
        },
        {
            "0x20a92c71c161a786989694109718416d7a291b8f9c71a5a71ee827e003a5a19cf2aa8faeecbfa231c330e2d4c747b75ccc4d43d8c37472b60",
            "0xc2ba3ef844b62f020cd6e4b010499c2c28ab3c15ed2ef3114e5b806244e57be1a7d999a21399c1e950977f021c82a906bed39caeec6aa077628421f9d5dfed01b24fe857000e259537fbe07d6a83080080ae927512d4518f9a56f0a40376234855377d8ef40dcb6055bd8d351",
            "0x20282071400021809096840092084045000801851471a0250a80000000a480141280018e8816a020033022404507350cc40d4340413400340",
            "0xc2ba3ef844b62f020cd6e4b010499c2c28ab3c15ed2ef3114e5b806244e57be1a7d999a21399c1e950977f021c82a906bed39caeecebac77e3e5a7ffdddffd11b75fe97f7a2f3f9fbffbe5ff7eeb2fe083afb3fdf2fedfaffefff2b5c376e3dcd777ffdefc4dcbf8d7fdffb71",
            "0xc2ba3ef844b62f020cd6e4b010499c2c28ab3c15ed2ef3114e5b806244e57be1a7d999a21399c1e950977f021c82a906bed39caeccc38c06a3e5867f4d4979112557a93a7a273e1aab8a45da746b2fe0830b33e9e07ede2176e95295c046c19c9270cad2384088b896c9ff831"
        },
        {
            "0xf6b7f399370d10b097b17e514f044d77a8f170148f4837033bb5d425f73a4079e1c7a9c3e69246f902d8c9fd27caad1e93d83578d4af8d3b7b1c02041c44917a22ed56f2562ac1426a356f8d31965e8e367b8929f3907b1dc6e73a8f3a566ca5c4e113e9d2c53770b110df51cf504701ff3fcea5b819b9bfc49f",
            "0x61989df2b7097a6a84dc016aec2716d9cac359d2d799d90ec006a66efe3f1fd0851978c4cfe2f64b307b852e23f5dfdc2f63196e1076782a228a46f5f7d4e54afc1ad7abf1f8fef46edaad1706956f95eb95953bd4",
            "0x990290097822808c0002c82510d08a8119521400000c40002222ec1612500001404005628401105a8426238109d0006319460032082a020804c4e110e142c41250a110d850c440420117068425900991950094",
            "0xf6b7f399370d10b097b17e514f044d77a8f170148f4837033bb5d425f73a4079e1c7a9c3e6f3defdf2ffc9ff6fcefd1ffbfc377eddefcf7bfbdf9bdd1ec497fe6eff7fffd6afd97aeeffefff7bb67f8f3e7bfdffffbf7b1deef77eff3a76eee7f5f7d7eddafd3ff7bbf1ffffff7edfadff3fdfefbdfbbdbfffdf",
            "0xf6b7f399370d10b097b17e514f044d77a8f170148f4837033bb5d425f73a4079e1c7a9c3e6f3de64f06fc0874d4e711ff934126e0d654e62a9cb9bdd128497dc4c1369ed86afd83aaefa8d7b7aa6250b18587cf62fbf1804a8f74cf71074e6e33116c70c98392da71ae127af3b3e9dace8395bca2df22c2aff4b"
        },
        {
            "0x31d126e874580b754389fad8b64aaa61cabb4f8eb6904fe7e504341ed903f7daa3e74d4da3afca80b2415672a",
            "0x16fb17a0468c0afa6bad456efa4f9baf26860eda9d7c00c2520c8c9b6026fb50df59b8cb74f6d9be861052c5e831158e7ffd98746328ce11f91d9ea22f0803a8b059aea22d1715ca1abeae53a8bc6b8bfb9b6c9d24ae714767",
            "0x11100e0745803440288e0189048aa20c0800a8a04904a22c10014008902e51a83c6080da1a6c880024114722",
            "0x16fb17a0468c0afa6bad456efa4f9baf26860eda9d7c00c2520c8c9b6026fb50df59b8cb74f6d9be861052c5eb3d17eefffd98f77738dfbdfb7dbea63fabb7f8fb79aefe7f5757cbffbebf7faabe7fdffbbbfcbd2fae75676f",
            "0x16fb17a0468c0afa6bad456efa4f9baf26860eda9d7c00c2520c8c9b6026fb50df59b8cb74f6d9be861052c5eb2c07e0f8b818c3371051bc7279340433a3b7505b30aa5c5347568bf72e912e02821f5f21a190352f8a64204d"
        },
        {
            "0xbf1a14e469c234b72d56324d100e016bc38cdf7158e35f230c047585e7b107acc8e222e7f19552541e59316affd90e96ca657b6112f5e8c786dfcff342fc46252fcdab10c632578540dbf6235f164bc5711924c7c6ba9da85ab",
            "0x5dd3fb9a3de26cd89eb9517af6bb25678f149f906e8751a0c20d7646d21c17191237022a990e0156541e376986fd6a680c60228e5955df08bae5789c81751cdcafe5a2e72d45b09",
            "0x5d5158821d220c001481413006a800620204919042041000000876400214020112210220880600564412026806252a480800020251054008b22158140145101824c582a20d00109",
            "0xbf1a14e469c234b72d56324d100e016bc38cdff3fbfb7fe36cdcffbdf7fbf7bfede7aff7ff957ed75ff9f36fffdfde9edf7d7b7712fff9cf87dfdfff77fdc6fd6fedaf70e6be5fd5dfdbfee77f9ecbf57dddafe7e6ffbdedfab",
            "0xbf1a14e469c234b72d56324d100e016bc38c82a2a37962c160dceb3cb6cbf117ed85adf36e053cd34ff9f367899fdc8add7c695610df71c987899bed7595c0d845a5a770e4bc0ed09fd34cc6278acab06dc58b22645db0edea2"
        },
    };

    bool opa=true, opo=true, opx=true;

    //////////////////// AND ////////////////////

    for (size_t i=0; i<COUNTOF(tests); i++)
    {
        Integer m(tests[i].m), n(tests[i].n), a(tests[i].a);

        opa &= ((m & n) == a);
        opa &= ((-m & n) == a);
        opa &= ((m & -n) == a);
        opa &= ((-m & -n) == a);

        Integer t(m); t &= n;
        opa &= (t == a);
        t = n; t &= m;
        opa &= (t == a);

        opa &= ((m & m) == m);
        opa &= ((n & n) == n);
    }

    if (opa)
       std::cout << "passed:";
    else
       std::cout << "FAILED:";
    std::cout << "  Bitwise AND over 32-bits to 1024-bits\n";

    //////////////////// OR ////////////////////

    for (size_t i=0; i<COUNTOF(tests); i++)
    {
        Integer m(tests[i].m), n(tests[i].n), o(tests[i].o);

        opo &= ((m | n) == o);
        opo &= ((-m | n) == o);
        opo &= ((m | -n) == o);
        opo &= ((-m | -n) == o);

        Integer t(m); t |= n;
        opo &= (t == o);
        t = n; t |= m;
        opo &= (t == o);

        opo &= ((m | m) == m);
        opo &= ((n | n) == n);
    }

    if (opo)
       std::cout << "passed:";
    else
       std::cout << "FAILED:";
    std::cout << "  Bitwise OR over 32-bits to 1024-bits\n";

    //////////////////// XOR ////////////////////

    for (size_t i=0; i<COUNTOF(tests); i++)
    {
        Integer m(tests[i].m), n(tests[i].n), x(tests[i].x);

        opx &= ((m ^ n) == x);
        opx &= ((-m ^ n) == x);
        opx &= ((m ^ -n) == x);
        opx &= ((-m ^ -n) == x);

        Integer t(m); t ^= n;
        opx &= (t == x);
        t = n; t ^= m;
        opx &= (t == x);

        opx &= ((m ^ m) == Integer::Zero());
        opx &= ((n ^ n) == Integer::Zero());
    }

    if (opx)
       std::cout << "passed:";
    else
       std::cout << "FAILED:";
    std::cout << "  Bitwise XOR over 32-bits to 1024-bits\n";

    return opa && opo && opx;
}
#endif

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
