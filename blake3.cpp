// blake3.cpp - written and placed in the public domain by Colin Brown
//              Based on the BLAKE3 team's reference implementation
//              at http://github.com/BLAKE3-team/BLAKE3.

#include "pch.h"
#include "blake3.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

////////////////////////////// Constants and Tables //////////////////////////////

// BLAKE3 initialization vector - same as SHA-256
static const word32 BLAKE3_IV[8] = {
	0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
	0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

// BLAKE3 compression flags indicating block position and mode
enum {
	CHUNK_START = 1 << 0,          // First block of a chunk
	CHUNK_END = 1 << 1,            // Last block of a chunk
	PARENT = 1 << 2,               // Parent node in tree
	ROOT = 1 << 3,                 // Root node (final output)
	KEYED_HASH = 1 << 4,           // Keyed hash (MAC) mode
	DERIVE_KEY_CONTEXT = 1 << 5,   // KDF context string
	DERIVE_KEY_MATERIAL = 1 << 6   // KDF derived key output
};

// Message schedule permutations for the 7 rounds
// Each round uses a different permutation of the 16 message words
static const byte MSG_SCHEDULE[7][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
	{3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
	{10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
	{12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
	{9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
	{11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13}
};

////////////////////////////// Helper Functions //////////////////////////////

// 32-bit rotate right
static inline word32 rotr32(word32 w, unsigned int c)
{
	return (w >> c) | (w << (32 - c));
}

// Load 16 little-endian words from a 64-byte block
static inline void load_block_words(const byte block[64], word32 out[16])
{
	for (size_t i = 0; i < 16; i++) {
		out[i] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, block + i * 4);
	}
}

// Store 8 chaining value words as 32 little-endian bytes
static inline void store_cv_words(byte out[32], const word32 cv[8])
{
	for (size_t i = 0; i < 8; i++) {
		PutWord<word32>(false, LITTLE_ENDIAN_ORDER, out + i * 4, cv[i]);
	}
}

////////////////////////////// Core Algorithm //////////////////////////////

// The mixing function g() - heart of BLAKE3 compression
// Performs quarter-round mixing with two message words
static inline void g(word32 state[16], size_t a, size_t b, size_t c, size_t d, word32 x, word32 y)
{
	state[a] = state[a] + state[b] + x;
	state[d] = rotr32(state[d] ^ state[a], 16);
	state[c] = state[c] + state[d];
	state[b] = rotr32(state[b] ^ state[c], 12);
	state[a] = state[a] + state[b] + y;
	state[d] = rotr32(state[d] ^ state[a], 8);
	state[c] = state[c] + state[d];
	state[b] = rotr32(state[b] ^ state[c], 7);
}

// One round of BLAKE3 compression
// Applies the g() function in column-major then diagonal order
static inline void round_fn(word32 state[16], const word32 m[16], size_t round)
{
	// Column mixing
	g(state, 0, 4, 8,  12, m[MSG_SCHEDULE[round][0]],  m[MSG_SCHEDULE[round][1]]);
	g(state, 1, 5, 9,  13, m[MSG_SCHEDULE[round][2]],  m[MSG_SCHEDULE[round][3]]);
	g(state, 2, 6, 10, 14, m[MSG_SCHEDULE[round][4]],  m[MSG_SCHEDULE[round][5]]);
	g(state, 3, 7, 11, 15, m[MSG_SCHEDULE[round][6]],  m[MSG_SCHEDULE[round][7]]);

	// Diagonal mixing
	g(state, 0, 5, 10, 15, m[MSG_SCHEDULE[round][8]],  m[MSG_SCHEDULE[round][9]]);
	g(state, 1, 6, 11, 12, m[MSG_SCHEDULE[round][10]], m[MSG_SCHEDULE[round][11]]);
	g(state, 2, 7, 8,  13, m[MSG_SCHEDULE[round][12]], m[MSG_SCHEDULE[round][13]]);
	g(state, 3, 4, 9,  14, m[MSG_SCHEDULE[round][14]], m[MSG_SCHEDULE[round][15]]);
}

// Core compression function - processes one 64-byte block
// Performs 7 rounds of mixing to produce a 64-byte output
static void compress_internal(const word32 cv[8], const byte block[64], byte block_len,
                              word64 counter, byte flags, word32 out[16])
{
	word32 block_words[16];
	load_block_words(block, block_words);

	word32 state[16] = {
		cv[0], cv[1], cv[2], cv[3],
		cv[4], cv[5], cv[6], cv[7],
		BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
		(word32)counter, (word32)(counter >> 32), (word32)block_len, (word32)flags
	};

	// 7 rounds of mixing
	for (size_t round = 0; round < 7; round++) {
		round_fn(state, block_words, round);
	}

	// Output: XOR state columns
	for (size_t i = 0; i < 8; i++) {
		out[i] = state[i] ^ state[i + 8];
		out[i + 8] = state[i + 8] ^ cv[i];
	}
}

////////////////////////////// State Management //////////////////////////////

void BLAKE3_ChunkState::Reset()
{
	std::memset(m_cv.data(), 0, m_cv.size() * sizeof(word32));
	std::memset(m_buf.data(), 0, m_buf.size());
	m_chunkCounter = 0;
	m_buf_len = 0;
	m_blocks_compressed = 0;
	m_flags = 0;
}

void BLAKE3_State::Reset()
{
	std::memcpy(m_key.data(), BLAKE3_IV, sizeof(BLAKE3_IV));
	m_chunk.Reset();
	std::memset(m_cv_stack.data(), 0, m_cv_stack.size() * sizeof(word32));
	m_cv_stack_len = 0;
	m_flags = 0;
}

////////////////////////////// BLAKE3 Class Implementation //////////////////////////////

// Wrapper for compression - updates chaining value in-place
void BLAKE3::Compress(word32 cv[8], const byte block[64], byte block_len,
                      word64 counter, byte flags)
{
	word32 output[16];
	compress_internal(cv, block, block_len, counter, flags, output);
	std::memcpy(cv, output, 8 * sizeof(word32));
}

void BLAKE3::ChunkStateOutput(const BLAKE3_ChunkState& chunk, word32 out[8])
{
	word32 output[16];
	byte flags = chunk.m_flags | CHUNK_END;
	if (chunk.m_blocks_compressed == 0) {
		flags |= CHUNK_START;
	}
	compress_internal(chunk.m_cv.data(), chunk.m_buf.data(), chunk.m_buf_len,
	                 chunk.m_chunkCounter, flags, output);
	std::memcpy(out, output, 8 * sizeof(word32));
}

void BLAKE3::ChunkStateUpdate(BLAKE3_ChunkState& chunk, const byte *input, size_t len)
{
	while (len > 0) {
		// If buffer is full, compress it
		if (chunk.m_buf_len == BLOCKSIZE) {
			word32 cv[8];
			std::memcpy(cv, chunk.m_cv.data(), 8 * sizeof(word32));

			byte block_flags = chunk.m_flags;
			if (chunk.m_blocks_compressed == 0) {
				block_flags |= CHUNK_START;
			}

			Compress(cv, chunk.m_buf.data(), BLOCKSIZE, chunk.m_chunkCounter, block_flags);
			std::memcpy(chunk.m_cv.data(), cv, 8 * sizeof(word32));

			chunk.m_blocks_compressed++;
			chunk.m_buf_len = 0;
			std::memset(chunk.m_buf.data(), 0, BLOCKSIZE);
		}

		// Fill buffer with input
		size_t want = BLOCKSIZE - chunk.m_buf_len;
		size_t take = (len < want) ? len : want;
		std::memcpy(chunk.m_buf.data() + chunk.m_buf_len, input, take);
		chunk.m_buf_len += (byte)take;
		input += take;
		len -= take;
	}
}

void BLAKE3::ParentCV(const word32 left_cv[8], const word32 right_cv[8],
                      const word32 key[8], byte flags, word32 out[8])
{
	byte block[BLOCKSIZE];
	store_cv_words(block, left_cv);
	store_cv_words(block + 32, right_cv);

	word32 output[16];
	compress_internal(key, block, BLOCKSIZE, 0, flags | PARENT, output);
	std::memcpy(out, output, 8 * sizeof(word32));
}

// Add a chunk chaining value to the tree
// Uses the lazy merkle tree algorithm: merge nodes when chunk count is even
void BLAKE3::AddChunkCV(const word32 cv[8], word64 total_chunks)
{
	// Determine how many stack items to merge
	// Merge whenever the total chunk count is even (LSB = 0)
	size_t merge_count = 0;
	while ((total_chunks & 1) == 0) {
		total_chunks >>= 1;
		merge_count++;
	}

	// Merge with existing stack items
	word32 parent_cv[8];
	std::memcpy(parent_cv, cv, 8 * sizeof(word32));

	for (size_t i = 0; i < merge_count; i++) {
		word32 left_cv[8];
		std::memcpy(left_cv, m_state.m_cv_stack.data() + (m_state.m_cv_stack_len - 1) * 8,
		           8 * sizeof(word32));
		m_state.m_cv_stack_len--;

		ParentCV(left_cv, parent_cv, m_state.m_key.data(), m_state.m_flags, parent_cv);
	}

	// Push result onto stack
	std::memcpy(m_state.m_cv_stack.data() + m_state.m_cv_stack_len * 8, parent_cv,
	           8 * sizeof(word32));
	m_state.m_cv_stack_len++;
}

void BLAKE3::Output(const word32 cv[8], byte block[64], byte block_len,
                   word64 counter, byte flags, byte* out, size_t out_len)
{
	word32 output_block[16];
	size_t offset = 0;

	while (out_len > 0) {
		compress_internal(cv, block, block_len, counter, flags | ROOT, output_block);

		size_t take = (out_len < 64) ? out_len : 64;
		for (size_t i = 0; i < take / 4; i++) {
			PutWord<word32>(false, LITTLE_ENDIAN_ORDER, out + offset + i * 4, output_block[i]);
		}

		// Handle remaining bytes
		if (take % 4 != 0) {
			byte temp[4];
			PutWord<word32>(false, LITTLE_ENDIAN_ORDER, temp, output_block[take / 4]);
			std::memcpy(out + offset + (take / 4) * 4, temp, take % 4);
		}

		offset += take;
		out_len -= take;
		counter++;
	}
}

unsigned int BLAKE3::OptimalDataAlignment() const
{
	return GetAlignmentOf<word32>();
}

std::string BLAKE3::AlgorithmProvider() const
{
	return "C++";
}

// Constructors

BLAKE3::BLAKE3(unsigned int digestSize)
	: m_digestSize(digestSize), m_treeMode(false)
{
	CRYPTOPP_ASSERT(digestSize >= 1 && digestSize <= 1024);
	m_state.Reset();
	m_state.m_flags = 0;
	// Initialize key and chunk CV with IV for unkeyed mode
	std::memcpy(m_state.m_key.data(), BLAKE3_IV, sizeof(BLAKE3_IV));
	std::memcpy(m_state.m_chunk.m_cv.data(), BLAKE3_IV, sizeof(BLAKE3_IV));
	m_state.m_chunk.m_flags = 0;
}

BLAKE3::BLAKE3(const byte *key, size_t keyLength, unsigned int digestSize)
	: m_digestSize(digestSize), m_treeMode(false)
{
	CRYPTOPP_ASSERT(keyLength == 32);
	CRYPTOPP_ASSERT(digestSize >= 1 && digestSize <= 1024);

	m_keyBytes.resize(keyLength);
	std::memcpy(m_keyBytes.data(), key, keyLength);

	m_state.Reset();

	// Load key as words
	for (size_t i = 0; i < 8; i++) {
		m_state.m_key[i] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key + i * 4);
	}

	m_state.m_flags = KEYED_HASH;
	std::memcpy(m_state.m_chunk.m_cv.data(), m_state.m_key.data(), 8 * sizeof(word32));
	m_state.m_chunk.m_flags = KEYED_HASH;
}

BLAKE3::BLAKE3(const char* context, unsigned int digestSize)
	: m_digestSize(digestSize), m_treeMode(false)
{
	CRYPTOPP_ASSERT(digestSize >= 1 && digestSize <= 1024);

	m_state.Reset();

	// Derive context key
	BLAKE3 hasher(32);
	hasher.m_state.m_flags = DERIVE_KEY_CONTEXT;
	hasher.m_state.m_chunk.m_flags = DERIVE_KEY_CONTEXT;
	std::memcpy(hasher.m_state.m_chunk.m_cv.data(), BLAKE3_IV, sizeof(BLAKE3_IV));

	hasher.Update((const byte*)context, std::strlen(context));

	byte context_key[32];
	hasher.TruncatedFinal(context_key, 32);

	// Use derived key
	for (size_t i = 0; i < 8; i++) {
		m_state.m_key[i] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, context_key + i * 4);
	}

	m_state.m_flags = DERIVE_KEY_MATERIAL;
	std::memcpy(m_state.m_chunk.m_cv.data(), m_state.m_key.data(), 8 * sizeof(word32));
	m_state.m_chunk.m_flags = DERIVE_KEY_MATERIAL;
}

void BLAKE3::Update(const byte *input, size_t length)
{
	while (length > 0) {
		// If current chunk is full, finalize it and start new chunk
		if (m_state.m_chunk.m_buf_len == BLOCKSIZE &&
		    m_state.m_chunk.m_blocks_compressed * BLOCKSIZE >= CHUNKSIZE - BLOCKSIZE) {

			word32 chunk_cv[8];
			ChunkStateOutput(m_state.m_chunk, chunk_cv);

			word64 total_chunks = m_state.m_chunk.m_chunkCounter + 1;
			AddChunkCV(chunk_cv, total_chunks);

			// Start new chunk
			m_state.m_chunk.Reset();
			std::memcpy(m_state.m_chunk.m_cv.data(), m_state.m_key.data(), 8 * sizeof(word32));
			m_state.m_chunk.m_chunkCounter = total_chunks;
			m_state.m_chunk.m_flags = m_state.m_flags;
		}

		// Feed data to current chunk
		size_t want = CHUNKSIZE - (m_state.m_chunk.m_blocks_compressed * BLOCKSIZE +
		                           m_state.m_chunk.m_buf_len);
		size_t take = (length < want) ? length : want;

		ChunkStateUpdate(m_state.m_chunk, input, take);
		input += take;
		length -= take;
	}
}

void BLAKE3::TruncatedFinal(byte *hash, size_t size)
{
	CRYPTOPP_ASSERT(size <= m_digestSize);

	// For single chunk (no tree), output from current chunk
	if (m_state.m_cv_stack_len == 0) {
		byte flags = m_state.m_flags | ROOT;
		if (m_state.m_chunk.m_blocks_compressed == 0) {
			flags |= CHUNK_START;
		}
		flags |= CHUNK_END;

		// Use Output() for proper XOF support
		Output(m_state.m_chunk.m_cv.data(), m_state.m_chunk.m_buf.data(),
		      m_state.m_chunk.m_buf_len, 0, flags, hash, size);
	} else {
		// Multi-chunk tree hashing - match reference implementation's roll-up merge
		// The output structure stores INPUTS for compression (input_cv + block),
		// not the output CV
		size_t chunk_len = m_state.m_chunk.m_blocks_compressed * BLOCKSIZE + m_state.m_chunk.m_buf_len;

		word32 output_input_cv[8];  // Input CV for compression
		byte output_block[BLOCKSIZE];
		byte output_block_len;
		word64 output_counter;
		byte output_flags;
		size_t num_cvs;

		// Determine starting output structure
		if (chunk_len > 0) {
			// Current chunk has data - output structure represents this chunk
			num_cvs = m_state.m_cv_stack_len;
			std::memcpy(output_input_cv, m_state.m_chunk.m_cv.data(), 8 * sizeof(word32));
			std::memcpy(output_block, m_state.m_chunk.m_buf.data(), m_state.m_chunk.m_buf_len);
			output_block_len = m_state.m_chunk.m_buf_len;
			output_counter = m_state.m_chunk.m_chunkCounter;
			output_flags = m_state.m_chunk.m_flags | CHUNK_END;
			if (m_state.m_chunk.m_blocks_compressed == 0) {
				output_flags |= CHUNK_START;
			}
		} else {
			// No data in current chunk - start with top two stack entries as parent
			num_cvs = m_state.m_cv_stack_len - 2;
			word32 left_cv[8], right_cv[8];
			std::memcpy(left_cv, m_state.m_cv_stack.data() + num_cvs * 8, 8 * sizeof(word32));
			std::memcpy(right_cv, m_state.m_cv_stack.data() + (num_cvs + 1) * 8, 8 * sizeof(word32));

			store_cv_words(output_block, left_cv);
			store_cv_words(output_block + 32, right_cv);
			output_block_len = BLOCKSIZE;
			output_counter = 0;
			output_flags = m_state.m_flags | PARENT;
			std::memcpy(output_input_cv, m_state.m_key.data(), 8 * sizeof(word32));
		}

		// Roll-up merge: combine output CV with stack entries
		while (num_cvs > 0) {
			num_cvs--;

			// Get the chaining value from current output structure by compressing
			word32 output_cv[8];
			std::memcpy(output_cv, output_input_cv, 8 * sizeof(word32));

			// Compress to get output CV
			word32 compress_output[16];
			compress_internal(output_cv, output_block, output_block_len, output_counter,
			                 output_flags, compress_output);

			// Extract CV (first 8 words)
			for (size_t i = 0; i < 8; i++) {
				output_cv[i] = compress_output[i];
			}

			// Build parent block: [stack_cv | output_cv]
			byte parent_block[BLOCKSIZE];
			std::memcpy(parent_block, m_state.m_cv_stack.data() + num_cvs * 8, 8 * sizeof(word32));
			store_cv_words(parent_block + 32, output_cv);

			// Update output structure to represent this parent
			std::memcpy(output_input_cv, m_state.m_key.data(), 8 * sizeof(word32));
			std::memcpy(output_block, parent_block, BLOCKSIZE);
			output_block_len = BLOCKSIZE;
			output_counter = 0;
			output_flags = m_state.m_flags | PARENT;
		}

		// Now compress the final output structure with ROOT flag
		Output(output_input_cv, output_block, output_block_len, output_counter,
		      output_flags | ROOT, hash, size);
	}

	Restart();
}

void BLAKE3::Restart()
{
	byte flags = m_state.m_flags;
	word32 key[8];
	std::memcpy(key, m_state.m_key.data(), 8 * sizeof(word32));

	m_state.Reset();

	std::memcpy(m_state.m_key.data(), key, 8 * sizeof(word32));
	std::memcpy(m_state.m_chunk.m_cv.data(), key, 8 * sizeof(word32));
	m_state.m_flags = flags;
	m_state.m_chunk.m_flags = flags;
}

void BLAKE3::UncheckedSetKey(const byte* key, unsigned int length, const CryptoPP::NameValuePairs& params)
{
	CRYPTOPP_UNUSED(params);
	CRYPTOPP_ASSERT(length == 32);

	m_keyBytes.resize(length);
	std::memcpy(m_keyBytes.data(), key, length);

	for (size_t i = 0; i < 8; i++) {
		m_state.m_key[i] = GetWord<word32>(false, LITTLE_ENDIAN_ORDER, key + i * 4);
	}

	m_state.m_flags = KEYED_HASH;
	std::memcpy(m_state.m_chunk.m_cv.data(), m_state.m_key.data(), 8 * sizeof(word32));
	m_state.m_chunk.m_flags = KEYED_HASH;
}

NAMESPACE_END
