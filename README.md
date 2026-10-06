# Crypto++ Code Examples

A collection of modular C++ examples demonstrating common Crypto++ usage patterns.  
For more details and advanced use, see the [Crypto++ Wiki](https://www.cryptopp.com/wiki/Main_Page).

---

## 1. Random Key and IV Generation

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock key(32); // 256-bit key
CryptoPP::SecByteBlock iv(16);  // 128-bit IV
prng.GenerateBlock(key, key.size());
prng.GenerateBlock(iv, iv.size());
```

---

## 2. AES Encryption (CBC Mode)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

std::string plaintext = "Secret message.";
std::string ciphertext;

CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

CryptoPP::StringSource ss1(plaintext, true,
    new CryptoPP::StreamTransformationFilter(encryptor,
        new CryptoPP::StringSink(ciphertext)
    )
);
```

---

## 3. AES Decryption (CBC Mode)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

std::string recovered;

CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

CryptoPP::StringSource ss2(ciphertext, true,
    new CryptoPP::StreamTransformationFilter(decryptor,
        new CryptoPP::StringSink(recovered)
    )
);
```

---

## 4. RSA Key Generation

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

CryptoPP::AutoSeededRandomPool rng;
CryptoPP::InvertibleRSAFunction params;
params.GenerateRandomWithKeySize(rng, 2048);

CryptoPP::RSA::PrivateKey privateKey(params);
CryptoPP::RSA::PublicKey publicKey(params);
```

---

## 5. RSA Encryption

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/filters.h>

std::string plaintext = "RSA encryption!";
std::string ciphertext;

CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

CryptoPP::StringSource ss(plaintext, true,
    new CryptoPP::PK_EncryptorFilter(rng, encryptor,
        new CryptoPP::StringSink(ciphertext)
    )
);
```

---

## 6. RSA Decryption

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/filters.h>

std::string recovered;

CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

CryptoPP::StringSource ss(ciphertext, true,
    new CryptoPP::PK_DecryptorFilter(rng, decryptor,
        new CryptoPP::StringSink(recovered)
    )
);
```

---

## 7. Hashing with SHA-256

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

std::string message = "Hash me!";
std::string digest, encoded;

CryptoPP::SHA256 hash;
CryptoPP::StringSource s1(message, true,
    new CryptoPP::HashFilter(hash,
        new CryptoPP::StringSink(digest)
    )
);

CryptoPP::StringSource s2(digest, true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded))
);
// encoded now contains the hex-encoded SHA-256 hash
```

---

## 8. HMAC with SHA-256

```cpp
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

std::string key = "supersecret";
std::string data = "message";
std::string mac, encoded;

CryptoPP::HMAC<CryptoPP::SHA256> hmac((const CryptoPP::byte*)key.data(), key.size());
CryptoPP::StringSource(data, true,
    new CryptoPP::HashFilter(hmac,
        new CryptoPP::StringSink(mac)
    )
);

CryptoPP::StringSource(mac, true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded))
);
// encoded now contains the hex-encoded HMAC
```

---

## 9. Base64 Encoding/Decoding

```cpp
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

std::string raw = "encode me";
std::string encoded, decoded;

// Encode
CryptoPP::StringSource(raw, true,
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded))
);

// Decode
CryptoPP::StringSource(encoded, true,
    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded))
);
```

---

## 10. Secure Random Bytes

```cpp
#include <cryptopp/osrng.h>
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock randomBytes(16);
prng.GenerateBlock(randomBytes, randomBytes.size());
```

---

## Notes

- All examples assume using namespace CryptoPP; for brevity.
- For full programs, include necessary headers and a main() function.
- Crypto++ is highly modular—combine these building blocks as needed!
- See the [Crypto++ Wiki](https://www.cryptopp.com/wiki/Main_Page) for more details and advanced operations.

---

## 11. SHA3-256 Hashing

```cpp
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

std::string message = "SHA3 test";
std::string digest, encoded;

CryptoPP::SHA3_256 sha3;
CryptoPP::StringSource s1(message, true,
    new CryptoPP::HashFilter(sha3, new CryptoPP::StringSink(digest))
);
CryptoPP::StringSource s2(digest, true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded))
);
// encoded contains hex-encoded SHA3-256 hash
```

---

## 12. Digital Signature Generation (ECDSA, SHA-256)

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

AutoSeededRandomPool prng;
ECDSA<ECP, SHA256>::PrivateKey privateKey;
privateKey.Initialize(prng, ASN1::secp256r1());
ECDSA<ECP, SHA256>::PublicKey publicKey;
privateKey.MakePublicKey(publicKey);

std::string message = "Sign me!";
std::string signature;

ECDSA<ECP, SHA256>::Signer signer(privateKey);
StringSource(message, true,
    new SignerFilter(prng, signer, new StringSink(signature))
);
```

---

## 13. Digital Signature Verification (ECDSA, SHA-256)

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Use the publicKey and signature from above
bool result = false;
ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

StringSource ss(message + signature, true,
    new SignatureVerificationFilter(
        verifier,
        new ArraySink((byte*)&result, sizeof(result)),
        SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END
    )
);
// result is true if signature is valid
```

---

## 14. GCM Authenticated Encryption (AES/GCM)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>

AutoSeededRandomPool prng;
SecByteBlock key(16), iv(12);
prng.GenerateBlock(key, key.size());
prng.GenerateBlock(iv, iv.size());

std::string plaintext = "Authenticate me!";
std::string ciphertext, decrypted, mac;

GCM<AES>::Encryption gcm;
gcm.SetKeyWithIV(key, key.size(), iv, iv.size());

StringSource(plaintext, true,
    new AuthenticatedEncryptionFilter(gcm,
        new StringSink(ciphertext)
    )
);

// For decryption, use GCM<AES>::Decryption and AuthenticatedDecryptionFilter
```

---

## 15. ChaCha20 Stream Cipher

```cpp
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>

SecByteBlock key(32), iv(12);
AutoSeededRandomPool prng;
prng.GenerateBlock(key, key.size());
prng.GenerateBlock(iv, iv.size());

std::string plaintext = "ChaCha20 stream cipher!";
std::string ciphertext, recovered;

CryptoPP::ChaCha20::Encryption enc;
enc.SetKeyWithIV(key, key.size(), iv, iv.size());

StringSource(plaintext, true,
    new StreamTransformationFilter(enc, new StringSink(ciphertext))
);

// Decrypt
CryptoPP::ChaCha20::Decryption dec;
dec.SetKeyWithIV(key, key.size(), iv, iv.size());
StringSource(ciphertext, true,
    new StreamTransformationFilter(dec, new StringSink(recovered))
);
```

---

## 16. CMAC with AES

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

SecByteBlock key(16);
AutoSeededRandomPool prng;
prng.GenerateBlock(key, key.size());

std::string data = "CMAC message";
std::string mac, encoded;

CryptoPP::CMAC<CryptoPP::AES> cmac(key, key.size());
CryptoPP::StringSource(data, true,
    new CryptoPP::HashFilter(cmac, new CryptoPP::StringSink(mac))
);
CryptoPP::StringSource(mac, true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded))
);
```

---

## 17. Blake2b Hashing

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

std::string msg = "Blake2b hash";
std::string digest, encoded;

CryptoPP::BLAKE2b blake2b;
CryptoPP::StringSource(msg, true, new CryptoPP::HashFilter(blake2b, new CryptoPP::StringSink(digest)));
CryptoPP::StringSource(digest, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));
```

---

## 18. Hex Encoding/Decoding

```cpp
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

std::string input = "Hello!";
std::string encoded, decoded;

// Encode
CryptoPP::StringSource(input, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));

// Decode
CryptoPP::StringSource(encoded, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
```

---
