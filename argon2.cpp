// argon2.cpp - written and placed in public domain by Colin Brown.
//              Based on Argon2 designed by Alex Biryukov, Daniel Dinu,
//              Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves.
//              Reference implementation at http://github.com/P-H-C/phc-winner-argon2.

#include "pch.h"

#include "argon2.h"
#include "algparam.h"
#include "argnames.h"
#include "blake2.h"
#include "misc.h"
#include "stdcpp.h"

#include <sstream>
#include <limits>

#ifdef _OPENMP
# include <omp.h>
#endif

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::GetWord;
using CryptoPP::PutWord;
using CryptoPP::LITTLE_ENDIAN_ORDER;
using CryptoPP::AlignedSecByteBlock;
using CryptoPP::BLAKE2b;

// Argon2 constants
const word32 ARGON2_VERSION = 0x13;         // Version 1.3
const word32 ARGON2_BLOCK_SIZE = 1024;      // Block size in bytes
const word32 ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;  // 128 qwords
const word32 ARGON2_SYNC_POINTS = 4;        // Number of synchronization points

/// \brief Encode 32-bit value as little-endian
inline void Store32(byte* dst, word32 w)
{
    PutWord(false, LITTLE_ENDIAN_ORDER, dst, w);
}

/// \brief Load 32-bit value from little-endian
inline word32 Load32(const byte* src)
{
    return GetWord<word32>(false, LITTLE_ENDIAN_ORDER, src);
}

/// \brief Encode 64-bit value as little-endian
inline void Store64(byte* dst, word64 w)
{
    PutWord(false, LITTLE_ENDIAN_ORDER, dst, w);
}

/// \brief Load 64-bit value from little-endian
inline word64 Load64(const byte* src)
{
    return GetWord<word64>(false, LITTLE_ENDIAN_ORDER, src);
}

/// \brief Variable-length hash function H'
/// \param out output buffer
/// \param outlen desired output length in bytes
/// \param in input buffer
/// \param inlen input length in bytes
/// \details Implements the variable-length hash function H' using BLAKE2b
///   as specified in RFC 9106 Section 3.2
inline void Blake2bLong(byte* out, word32 outlen, const byte* in, word32 inlen)
{
    CRYPTOPP_ASSERT(outlen > 0);

    byte outlen_bytes[4];
    Store32(outlen_bytes, outlen);

    if (outlen <= 64)
    {
        // Direct BLAKE2b hash
        BLAKE2b blake(false, outlen);
        blake.Update(outlen_bytes, 4);
        blake.Update(in, inlen);
        blake.TruncatedFinal(out, outlen);
    }
    else
    {
        // Extended output mode
        byte out_buffer[64];
        word32 toproduce;

        // First block
        BLAKE2b blake(false, 64);
        blake.Update(outlen_bytes, 4);
        blake.Update(in, inlen);
        blake.TruncatedFinal(out_buffer, 64);

        std::memcpy(out, out_buffer, 32);
        out += 32;
        toproduce = outlen - 32;

        // Subsequent blocks
        while (toproduce > 64)
        {
            BLAKE2b blake2(false, 64);
            blake2.Update(out_buffer, 64);
            blake2.TruncatedFinal(out_buffer, 64);

            std::memcpy(out, out_buffer, 32);
            out += 32;
            toproduce -= 32;
        }

        // Final block
        BLAKE2b blake_final(false, toproduce);
        blake_final.Update(out_buffer, 64);
        blake_final.TruncatedFinal(out, toproduce);
    }
}

/// \brief Initial hash H0
/// \param digest output buffer (64 bytes)
/// \param parallelism degree of parallelism
/// \param taglen desired tag length
/// \param memoryCost memory size in kibibytes
/// \param timeCost number of iterations
/// \param variant Argon2 variant (0=d, 1=i, 2=id)
/// \param password password buffer
/// \param passwordLen password length
/// \param salt salt buffer
/// \param saltLen salt length
/// \param secret optional secret buffer
/// \param secretLen secret length
/// \param associatedData optional associated data buffer
/// \param associatedDataLen associated data length
/// \details Computes H0 as specified in RFC 9106 Section 3.2
inline void InitialHash(byte* digest,
    word32 parallelism, word32 taglen, word32 memoryCost, word32 timeCost,
    word32 variant,
    const byte* password, word32 passwordLen,
    const byte* salt, word32 saltLen,
    const byte* secret, word32 secretLen,
    const byte* associatedData, word32 associatedDataLen)
{
    BLAKE2b blake(false, 64);
    byte temp[4];

    Store32(temp, parallelism);
    blake.Update(temp, 4);

    Store32(temp, taglen);
    blake.Update(temp, 4);

    Store32(temp, memoryCost);
    blake.Update(temp, 4);

    Store32(temp, timeCost);
    blake.Update(temp, 4);

    Store32(temp, ARGON2_VERSION);
    blake.Update(temp, 4);

    Store32(temp, variant);
    blake.Update(temp, 4);

    Store32(temp, passwordLen);
    blake.Update(temp, 4);
    if (passwordLen > 0)
        blake.Update(password, passwordLen);

    Store32(temp, saltLen);
    blake.Update(temp, 4);
    if (saltLen > 0)
        blake.Update(salt, saltLen);

    Store32(temp, secretLen);
    blake.Update(temp, 4);
    if (secretLen > 0)
        blake.Update(secret, secretLen);

    Store32(temp, associatedDataLen);
    blake.Update(temp, 4);
    if (associatedDataLen > 0)
        blake.Update(associatedData, associatedDataLen);

    blake.TruncatedFinal(digest, 64);
}

/// \brief Argon2 block structure (1024 bytes = 128 qwords)
struct Block
{
    word64 v[ARGON2_QWORDS_IN_BLOCK];

    void Clear()
    {
        std::memset(v, 0, sizeof(v));
    }

    void XorWith(const Block& other)
    {
        for (word32 i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
            v[i] ^= other.v[i];
    }

    void CopyFrom(const Block& other)
    {
        std::memcpy(v, other.v, sizeof(v));
    }
};

/// \brief Blake2b round function (used in G)
inline word64 Rotr64(word64 x, unsigned int n)
{
    return (x >> n) | (x << (64 - n));
}

/// \brief Quarter round of BLAKE2b (used in G compression function)
inline void Blake2bG(word64& a, word64& b, word64& c, word64& d)
{
    a = a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
    d = Rotr64(d ^ a, 32);
    c = c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF);
    b = Rotr64(b ^ c, 24);
    a = a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
    d = Rotr64(d ^ a, 16);
    c = c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF);
    b = Rotr64(b ^ c, 63);
}

/// \brief Permutation P (row and column mixing)
inline void PermuteBlock(Block& block)
{
    // Apply row-wise mixing
    for (word32 i = 0; i < 8; ++i)
    {
        Blake2bG(block.v[16 * i + 0], block.v[16 * i + 4], block.v[16 * i + 8], block.v[16 * i + 12]);
        Blake2bG(block.v[16 * i + 1], block.v[16 * i + 5], block.v[16 * i + 9], block.v[16 * i + 13]);
        Blake2bG(block.v[16 * i + 2], block.v[16 * i + 6], block.v[16 * i + 10], block.v[16 * i + 14]);
        Blake2bG(block.v[16 * i + 3], block.v[16 * i + 7], block.v[16 * i + 11], block.v[16 * i + 15]);
        Blake2bG(block.v[16 * i + 0], block.v[16 * i + 5], block.v[16 * i + 10], block.v[16 * i + 15]);
        Blake2bG(block.v[16 * i + 1], block.v[16 * i + 6], block.v[16 * i + 11], block.v[16 * i + 12]);
        Blake2bG(block.v[16 * i + 2], block.v[16 * i + 7], block.v[16 * i + 8], block.v[16 * i + 13]);
        Blake2bG(block.v[16 * i + 3], block.v[16 * i + 4], block.v[16 * i + 9], block.v[16 * i + 14]);
    }

    // Apply column-wise mixing
    for (word32 i = 0; i < 8; ++i)
    {
        Blake2bG(block.v[2 * i], block.v[2 * i + 32], block.v[2 * i + 64], block.v[2 * i + 96]);
        Blake2bG(block.v[2 * i + 1], block.v[2 * i + 33], block.v[2 * i + 65], block.v[2 * i + 97]);
        Blake2bG(block.v[2 * i + 16], block.v[2 * i + 48], block.v[2 * i + 80], block.v[2 * i + 112]);
        Blake2bG(block.v[2 * i + 17], block.v[2 * i + 49], block.v[2 * i + 81], block.v[2 * i + 113]);
        Blake2bG(block.v[2 * i], block.v[2 * i + 33], block.v[2 * i + 80], block.v[2 * i + 113]);
        Blake2bG(block.v[2 * i + 1], block.v[2 * i + 48], block.v[2 * i + 81], block.v[2 * i + 96]);
        Blake2bG(block.v[2 * i + 16], block.v[2 * i + 49], block.v[2 * i + 64], block.v[2 * i + 97]);
        Blake2bG(block.v[2 * i + 17], block.v[2 * i + 32], block.v[2 * i + 65], block.v[2 * i + 112]);
    }
}

/// \brief Compression function G
/// \param result output block
/// \param x first input block
/// \param y second input block
/// \details Implements the compression function G(X, Y) as specified in RFC 9106 Section 3.3
inline void CompressionG(Block& result, const Block& x, const Block& y)
{
    Block r;

    // R = X XOR Y
    for (word32 i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
        r.v[i] = x.v[i] ^ y.v[i];

    // Q = copy of R (for final XOR)
    Block q;
    q.CopyFrom(r);

    // Z = P(R)
    PermuteBlock(r);

    // result = Z XOR Q
    for (word32 i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
        result.v[i] = r.v[i] ^ q.v[i];
}

/// \brief Fill initial blocks of a lane
/// \param blocks memory blocks array
/// \param h0 initial hash H0
/// \param lane lane index
inline void FillFirstBlocks(Block* blocks, const byte* h0, word32 lane)
{
    byte blockhash[1024];
    byte temp[72];  // 64 bytes of H0 + 8 bytes for indices

    std::memcpy(temp, h0, 64);

    // Fill block 0 of this lane
    Store32(temp + 64, 0);  // i = 0
    Store32(temp + 68, lane);
    Blake2bLong(blockhash, 1024, temp, 72);
    for (word32 i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
        blocks[0].v[i] = Load64(blockhash + i * 8);

    // Fill block 1 of this lane
    Store32(temp + 64, 1);  // i = 1
    Store32(temp + 68, lane);
    Blake2bLong(blockhash, 1024, temp, 72);
    for (word32 i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
        blocks[1].v[i] = Load64(blockhash + i * 8);
}

/// \brief Compute reference block index for Argon2i and Argon2id
/// \param pass current pass number
/// \param lane current lane
/// \param slice current slice
/// \param index current index within slice
/// \param pseudoRand pseudo-random value J1
/// \param sameLane true if selecting within same lane
/// \return reference block index
inline word32 IndexAlpha(word32 pass, word32 lane, word32 slice, word32 index,
    word32 pseudoRand, bool sameLane, word32 segmentLength, word32 laneLength)
{
    word32 referenceAreaSize;
    word32 startPosition;

    if (pass == 0)
    {
        if (slice == 0)
        {
            // First slice, first pass: can only reference already computed blocks in this slice
            referenceAreaSize = index - 1;
        }
        else
        {
            // Not first slice, first pass
            if (sameLane)
                referenceAreaSize = slice * segmentLength + index - 1;
            else
                referenceAreaSize = slice * segmentLength + ((index == 0) ? -1 : 0);
        }
    }
    else
    {
        // Not first pass
        if (sameLane)
            referenceAreaSize = laneLength - segmentLength + index - 1;
        else
            referenceAreaSize = laneLength - segmentLength + ((index == 0) ? -1 : 0);
    }

    word64 relativePosition = pseudoRand;
    relativePosition = (relativePosition * relativePosition) >> 32;
    relativePosition = referenceAreaSize - 1 - (referenceAreaSize * relativePosition >> 32);

    if (pass == 0)
    {
        // First pass: reference from beginning of memory
        startPosition = 0;
    }
    else
    {
        startPosition = ((slice + 1) % ARGON2_SYNC_POINTS) * segmentLength;
    }

    return (startPosition + static_cast<word32>(relativePosition)) % laneLength;
}

/// \brief Generate pseudo-random values for Argon2i indexing
/// \param addressBlock block containing pseudo-random values
/// \param inputBlock input block for generating addresses
/// \param zeroBlock zero-filled block
inline void NextAddresses(Block& addressBlock, Block& inputBlock, const Block& zeroBlock)
{
    inputBlock.v[6]++;
    CompressionG(addressBlock, zeroBlock, inputBlock);
    CompressionG(addressBlock, zeroBlock, addressBlock);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

Argon2::Argon2(Variant variant) : m_variant(variant)
{
}

std::string Argon2::StaticAlgorithmName(Variant variant)
{
    switch (variant)
    {
    case ARGON2D:
        return "Argon2d";
    case ARGON2I:
        return "Argon2i";
    case ARGON2ID:
        return "Argon2id";
    default:
        return "Argon2";
    }
}

std::string Argon2::AlgorithmName() const
{
    return StaticAlgorithmName(m_variant);
}

size_t Argon2::GetValidDerivedLength(size_t keylength) const
{
    if (keylength < 4)
        return 4;
    if (keylength > MaxDerivedKeyLength())
        return MaxDerivedKeyLength();
    return keylength;
}

void Argon2::ValidateParameters(size_t derivedLen, word32 timeCost, word32 memoryCost, word32 parallelism) const
{
    CRYPTOPP_ASSERT(derivedLen >= 4);
    CRYPTOPP_ASSERT(timeCost >= 1);
    CRYPTOPP_ASSERT(memoryCost >= 8 * parallelism);
    CRYPTOPP_ASSERT(parallelism >= 1);
    CRYPTOPP_ASSERT(parallelism <= 0xFFFFFF);

    if (derivedLen < 4)
        throw InvalidArgument("Argon2: derived length must be at least 4 bytes");

    if (timeCost < 1)
        throw InvalidArgument("Argon2: time cost must be at least 1");

    if (parallelism < 1)
        throw InvalidArgument("Argon2: parallelism must be at least 1");

    if (parallelism > 0xFFFFFF)
        throw InvalidArgument("Argon2: parallelism cannot exceed 2^24-1");

    if (memoryCost < 8 * parallelism)
    {
        std::ostringstream oss;
        oss << "Argon2: memory cost " << memoryCost << " is less than minimum ";
        oss << (8 * parallelism) << " (8 * parallelism)";
        throw InvalidArgument(oss.str());
    }

    // Check for OpenMP limits
    CRYPTOPP_ASSERT(parallelism <= static_cast<word32>((std::numeric_limits<int>::max)()));
    if (parallelism > static_cast<word32>((std::numeric_limits<int>::max)()))
    {
        std::ostringstream oss;
        oss << "Argon2: parallelism " << parallelism << " exceeds ";
        oss << (std::numeric_limits<int>::max)();
        throw InvalidArgument(oss.str());
    }

    // Check memory allocation limits
    const word64 blockCount = (static_cast<word64>(memoryCost) + (ARGON2_BLOCK_SIZE / 1024 - 1)) / (ARGON2_BLOCK_SIZE / 1024);
    if (blockCount > SIZE_MAX / sizeof(Block))
        throw std::bad_alloc();
}

size_t Argon2::DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen,
    const NameValuePairs& params) const
{
    CRYPTOPP_ASSERT(password || passwordLen == 0);
    CRYPTOPP_ASSERT(derived && derivedLen >= 4);

    word32 timeCost = 0, memoryCost = 0, parallelism = 0;

    if (params.GetValue("TimeCost", timeCost) == false)
        timeCost = defaultTimeCost;

    if (params.GetValue("MemoryCost", memoryCost) == false)
        memoryCost = defaultMemoryCost;

    if (params.GetValue("Parallelism", parallelism) == false)
        parallelism = defaultParallelism;

    ConstByteArrayParameter salt, secret, associatedData;
    (void)params.GetValue("Salt", salt);
    (void)params.GetValue("Secret", secret);
    (void)params.GetValue("AssociatedData", associatedData);

    return DeriveKey(derived, derivedLen, password, passwordLen,
        salt.begin(), salt.size(), timeCost, memoryCost, parallelism,
        secret.begin(), secret.size(),
        associatedData.begin(), associatedData.size());
}

size_t Argon2::DeriveKey(byte *derived, size_t derivedLen,
    const byte *password, size_t passwordLen,
    const byte *salt, size_t saltLen,
    word32 timeCost, word32 memoryCost, word32 parallelism,
    const byte *secret, size_t secretLen,
    const byte *associatedData, size_t associatedDataLen) const
{
    CRYPTOPP_ASSERT(password || passwordLen == 0);
    CRYPTOPP_ASSERT(salt && saltLen >= 8);
    CRYPTOPP_ASSERT(derived && derivedLen >= 4);

    ThrowIfInvalidDerivedKeyLength(derivedLen);
    ValidateParameters(derivedLen, timeCost, memoryCost, parallelism);

    if (!salt || saltLen < 8)
        throw InvalidArgument("Argon2: salt must be at least 8 bytes");

    // Calculate actual memory blocks (ensure divisible by 4*parallelism for slicing)
    word32 memoryBlocks = memoryCost;
    if (memoryCost < 8 * parallelism)
        memoryBlocks = 8 * parallelism;

    const word32 segmentLength = memoryBlocks / (parallelism * ARGON2_SYNC_POINTS);
    const word32 laneLength = segmentLength * ARGON2_SYNC_POINTS;
    memoryBlocks = laneLength * parallelism;

    // Allocate memory
    AlignedSecByteBlock memoryBlockStorage(memoryBlocks * sizeof(Block));
    Block* memory = reinterpret_cast<Block*>(memoryBlockStorage.data());

    // Compute H0
    byte h0[64];
    InitialHash(h0, parallelism, static_cast<word32>(derivedLen), memoryCost, timeCost,
        static_cast<word32>(m_variant),
        password, static_cast<word32>(passwordLen),
        salt, static_cast<word32>(saltLen),
        secret ? secret : reinterpret_cast<const byte*>(""), static_cast<word32>(secretLen),
        associatedData ? associatedData : reinterpret_cast<const byte*>(""), static_cast<word32>(associatedDataLen));

    // Fill first two blocks of each lane
    for (word32 lane = 0; lane < parallelism; ++lane)
    {
        FillFirstBlocks(memory + lane * laneLength, h0, lane);
    }

    // Process all passes
    for (word32 pass = 0; pass < timeCost; ++pass)
    {
        for (word32 slice = 0; slice < ARGON2_SYNC_POINTS; ++slice)
        {
            // Visual Studio and OpenMP 2.0 fixup
            int maxParallel = static_cast<int>(parallelism);

            #ifdef _OPENMP
            int threads = STDMIN(omp_get_max_threads(), maxParallel);
            #endif

            #pragma omp parallel num_threads(threads)
            {
                Block addressBlock, inputBlock, zeroBlock;
                zeroBlock.Clear();
                inputBlock.Clear();

                bool dataIndependent = (m_variant == ARGON2I) ||
                    (m_variant == ARGON2ID && pass == 0 && slice < ARGON2_SYNC_POINTS / 2);

                if (dataIndependent)
                {
                    inputBlock.v[0] = pass;
                    inputBlock.v[1] = 0;  // Will be set to lane in loop
                    inputBlock.v[2] = slice;
                    inputBlock.v[3] = memoryBlocks;
                    inputBlock.v[4] = timeCost;
                    inputBlock.v[5] = static_cast<word64>(m_variant);
                }

                #pragma omp for
                for (int lane = 0; lane < maxParallel; ++lane)
                {
                    word32 startIndex = (pass == 0 && slice == 0) ? 2 : 0;
                    word32 currentIndex = slice * segmentLength + startIndex;
                    word32 addressCounter = 0;

                    if (dataIndependent)
                    {
                        inputBlock.v[1] = lane;
                        inputBlock.v[6] = 0;
                    }

                    for (word32 i = startIndex; i < segmentLength; ++i, ++currentIndex)
                    {
                        word64 pseudoRand;
                        word32 refLane, refIndex;

                        if (dataIndependent)
                        {
                            if (addressCounter % ARGON2_QWORDS_IN_BLOCK == 0)
                                NextAddresses(addressBlock, inputBlock, zeroBlock);

                            pseudoRand = addressBlock.v[addressCounter % ARGON2_QWORDS_IN_BLOCK];
                            addressCounter++;

                            refLane = static_cast<word32>((pseudoRand >> 32) % parallelism);

                            // First pass, first slice must reference same lane (RFC 9106)
                            if (pass == 0 && slice == 0)
                                refLane = lane;

                            refIndex = IndexAlpha(pass, lane, slice, i,
                                static_cast<word32>(pseudoRand & 0xFFFFFFFF),
                                refLane == static_cast<word32>(lane),
                                segmentLength, laneLength);
                        }
                        else
                        {
                            // Argon2d or Argon2id (data-dependent portion)
                            word32 prevIndex = (currentIndex == 0) ? (laneLength - 1) : (currentIndex - 1);
                            Block& prevBlock = memory[lane * laneLength + prevIndex];
                            pseudoRand = prevBlock.v[0];

                            refLane = static_cast<word32>((pseudoRand >> 32) % parallelism);

                            // First pass, first slice must reference same lane (RFC 9106)
                            if (pass == 0 && slice == 0)
                                refLane = lane;

                            refIndex = IndexAlpha(pass, lane, slice, i,
                                static_cast<word32>(pseudoRand & 0xFFFFFFFF),
                                refLane == static_cast<word32>(lane),
                                segmentLength, laneLength);
                        }

                        // Compute new block
                        word32 prevIndex = (currentIndex == 0) ? (laneLength - 1) : (currentIndex - 1);

                        Block& refBlock = memory[refLane * laneLength + refIndex];
                        Block& prevBlock = memory[lane * laneLength + prevIndex];
                        Block& currBlock = memory[lane * laneLength + currentIndex];

                        Block tmpBlock;
                        CompressionG(tmpBlock, prevBlock, refBlock);

                        if (pass == 0)
                            currBlock.CopyFrom(tmpBlock);
                        else
                            currBlock.XorWith(tmpBlock);
                    }
                }
            }
        }
    }

    // Final hash: XOR last column
    Block finalBlock;
    finalBlock.CopyFrom(memory[laneLength - 1]);
    for (word32 lane = 1; lane < parallelism; ++lane)
        finalBlock.XorWith(memory[lane * laneLength + laneLength - 1]);

    // Produce tag
    byte blockhash[ARGON2_BLOCK_SIZE];
    for (word32 i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
        Store64(blockhash + i * 8, finalBlock.v[i]);

    Blake2bLong(derived, static_cast<word32>(derivedLen), blockhash, ARGON2_BLOCK_SIZE);

    return timeCost;
}

NAMESPACE_END
