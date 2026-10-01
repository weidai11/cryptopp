// blake3.h - written and placed in the public domain by Colin Brown
//            Based on the BLAKE3 team's reference implementation
//            at http://github.com/BLAKE3-team/BLAKE3.

/// \file blake3.h
/// \brief Classes for BLAKE3 message digests and keyed message digests
/// \details This implementation follows the BLAKE3 specification and reference
///   implementation. BLAKE3 supports standard hashing, keyed hashing (MAC), and
///   key derivation, with variable-length output.
/// \since Crypto++ 8.9

#ifndef CRYPTOPP_BLAKE3_H
#define CRYPTOPP_BLAKE3_H

#include "cryptlib.h"
#include "secblock.h"
#include "seckey.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief BLAKE3 hash information
/// \since Crypto++ 8.9
struct BLAKE3_Info : public VariableKeyLength<32,0,32,1,SimpleKeyingInterface::NOT_RESYNCHRONIZABLE>
{
	typedef VariableKeyLength<32,0,32,1,SimpleKeyingInterface::NOT_RESYNCHRONIZABLE> KeyBase;
	CRYPTOPP_CONSTANT(MIN_KEYLENGTH = KeyBase::MIN_KEYLENGTH);
	CRYPTOPP_CONSTANT(MAX_KEYLENGTH = KeyBase::MAX_KEYLENGTH);
	CRYPTOPP_CONSTANT(DEFAULT_KEYLENGTH = KeyBase::DEFAULT_KEYLENGTH);

	CRYPTOPP_CONSTANT(BLOCKSIZE = 64);
	CRYPTOPP_CONSTANT(DIGESTSIZE = 32);
	CRYPTOPP_CONSTANT(CHUNKSIZE = 1024);

	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "BLAKE3";}
};

/// \brief BLAKE3 chunk state for processing 1024-byte chunks
/// \details BLAKE3 processes input in 1024-byte chunks. Each chunk is further
///   divided into 64-byte blocks. The chunk state tracks the progress through
///   a single chunk and produces a chaining value when the chunk is complete.
/// \since Crypto++ 8.9
struct CRYPTOPP_NO_VTABLE BLAKE3_ChunkState
{
	CRYPTOPP_CONSTANT(BLOCKSIZE = BLAKE3_Info::BLOCKSIZE);
	CRYPTOPP_CONSTANT(CHUNKSIZE = BLAKE3_Info::CHUNKSIZE);

	BLAKE3_ChunkState() {
		Reset();
	}

	/// \brief Reset the chunk state for a new chunk
	void Reset();

	inline word32* cv() {
		return m_cv.data();
	}

	inline byte* buf() {
		return m_buf.data();
	}

	FixedSizeAlignedSecBlock<word32, 8, true> m_cv;
	FixedSizeAlignedSecBlock<byte, BLOCKSIZE, true> m_buf;
	word64 m_chunkCounter;
	byte m_buf_len;
	byte m_blocks_compressed;
	byte m_flags;
};

/// \brief BLAKE3 hasher state with CV stack for tree hashing
/// \details The BLAKE3 state maintains a stack of chaining values (CVs) that form
///   a Merkle tree structure. As chunks are processed, their CVs are merged in a
///   tree pattern. The maximum depth of 54 allows for 2^54 chunks, supporting
///   exabyte-scale inputs.
/// \since Crypto++ 8.9
struct CRYPTOPP_NO_VTABLE BLAKE3_State
{
	CRYPTOPP_CONSTANT(MAX_DEPTH = 54);

	BLAKE3_State() {
		Reset();
	}

	/// \brief Reset the hasher state
	void Reset();

	inline word32* key() {
		return m_key.data();
	}

	inline word32* cv_stack() {
		return m_cv_stack.data();
	}

	FixedSizeAlignedSecBlock<word32, 8, true> m_key;
	BLAKE3_ChunkState m_chunk;
	FixedSizeAlignedSecBlock<word32, 8 * (MAX_DEPTH + 1), true> m_cv_stack;
	byte m_cv_stack_len;
	byte m_flags;
};

/// \brief The BLAKE3 cryptographic hash function
/// \details BLAKE3 can function as a hash, keyed hash (MAC), or key derivation function.
///   It supports variable-length output. The mode is determined at construction and
///   cannot be changed. Use Restart() to reset the state while preserving the mode.
/// \sa BLAKE3 specification at <A HREF="https://github.com/BLAKE3-team/BLAKE3-specs">
///   BLAKE3-specs</A>
/// \since Crypto++ 8.9
class BLAKE3 : public SimpleKeyingInterfaceImpl<MessageAuthenticationCode, BLAKE3_Info>
{
public:
	CRYPTOPP_CONSTANT(DEFAULT_KEYLENGTH = BLAKE3_Info::DEFAULT_KEYLENGTH);
	CRYPTOPP_CONSTANT(MIN_KEYLENGTH = BLAKE3_Info::MIN_KEYLENGTH);
	CRYPTOPP_CONSTANT(MAX_KEYLENGTH = BLAKE3_Info::MAX_KEYLENGTH);

	CRYPTOPP_CONSTANT(DIGESTSIZE = BLAKE3_Info::DIGESTSIZE);
	CRYPTOPP_CONSTANT(BLOCKSIZE = BLAKE3_Info::BLOCKSIZE);
	CRYPTOPP_CONSTANT(CHUNKSIZE = BLAKE3_Info::CHUNKSIZE);

	typedef BLAKE3_State State;

	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "BLAKE3";}

	virtual ~BLAKE3() {}

	/// \brief Construct a BLAKE3 hash
	/// \param digestSize the digest size, in bytes (default 32)
	/// \since Crypto++ 8.9
	BLAKE3(unsigned int digestSize = DIGESTSIZE);

	/// \brief Construct a BLAKE3 keyed hash (MAC)
	/// \param key a byte array used to key the hash
	/// \param keyLength the size of the byte array (must be 32 bytes)
	/// \param digestSize the digest size, in bytes (default 32)
	/// \since Crypto++ 8.9
	BLAKE3(const byte *key, size_t keyLength, unsigned int digestSize = DIGESTSIZE);

	/// \brief Construct a BLAKE3 key derivation function
	/// \param context a string identifying the KDF context
	/// \param digestSize the digest size, in bytes (default 32)
	/// \since Crypto++ 8.9
	BLAKE3(const char* context, unsigned int digestSize = DIGESTSIZE);

	/// \brief Retrieve the object's name
	/// \return the object's algorithm name with digest size
	/// \details Returns "BLAKE3-256" for 32-byte output, "BLAKE3-512" for 64-byte, etc.
	std::string AlgorithmName() const {
		return std::string(BLAKE3_Info::StaticAlgorithmName()) + "-" + IntToString(DigestSize()*8);
	}

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return m_digestSize;}
	unsigned int OptimalDataAlignment() const;

	/// \brief Updates the hash with additional input
	/// \param input the additional input as a buffer
	/// \param length the size of the buffer, in bytes
	void Update(const byte *input, size_t length);

	/// \brief Restart the hash
	/// \details Discards the current state and starts a new hash using the same
	///   mode (standard hash, keyed hash, or KDF) as originally configured.
	void Restart();

	/// \brief Computes the hash of the current message
	/// \param hash a pointer to the buffer to receive the hash
	/// \param size the size of the truncated hash, in bytes
	/// \details TruncatedFinal() calls Final() and then copies size bytes to hash.
	///   The hash algorithm will be restarted ready for a new message.
	void TruncatedFinal(byte *hash, size_t size);

	std::string AlgorithmProvider() const;

protected:
	// Compression function - processes one 64-byte block
	void Compress(word32 cv[8], const byte block[BLOCKSIZE], byte block_len,
	              word64 counter, byte flags);

	// Output chaining value from chunk state
	void ChunkStateOutput(const BLAKE3_ChunkState& chunk, word32 out[8]);

	// Update chunk state with input
	void ChunkStateUpdate(BLAKE3_ChunkState& chunk, const byte *input, size_t len);

	// Add chunk CV to the tree
	void AddChunkCV(const word32 cv[8], word64 total_chunks);

	// Merge parent nodes
	void ParentCV(const word32 left_cv[8], const word32 right_cv[8],
	              const word32 key[8], byte flags, word32 out[8]);

	// Extract output (supports XOF)
	void Output(const word32 cv[8], byte block[BLOCKSIZE], byte block_len,
	            word64 counter, byte flags, byte* out, size_t out_len);

	void UncheckedSetKey(const byte* key, unsigned int length, const CryptoPP::NameValuePairs& params);

private:
	State m_state;
	AlignedSecByteBlock m_keyBytes;
	word32 m_digestSize;
	bool m_treeMode;
};

NAMESPACE_END

#endif  // CRYPTOPP_BLAKE3_H
