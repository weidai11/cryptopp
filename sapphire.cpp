// sapphire.cpp -- modified by Wei Dai from:

/* sapphire.cpp -- the Saphire II stream cipher class.
   Dedicated to the Public Domain the author and inventor:
   (Michael Paul Johnson).  This code comes with no warranty.
   Use it at your own risk.
   Ported from the Pascal implementation of the Sapphire Stream
   Cipher 9 December 1994.
   Added hash pre- and post-processing 27 December 1994.
   Modified initialization to make index variables key dependent,
   made the output function more resistant to cryptanalysis,
   and renamed to Sapphire II 2 January 1995
*/

#include "pch.h"
#include "sapphire.h"

NAMESPACE_BEGIN(CryptoPP)

byte SapphireBase::keyrand(unsigned int limit,
						   const byte *user_key,
						   byte keysize,
						   byte *rsum,
						   unsigned *keypos)
{
	unsigned u,             // Value from 0 to limit to return.
		retry_limiter,      // No infinite loops allowed.
		mask;               // Select just enough bits.

	retry_limiter = 0;
	mask = 1;               // Fill mask with enough bits to cover
	while (mask < limit)    // the desired range.
		mask = (mask << 1) + 1;
	do
		{
		*rsum = cards[*rsum] + user_key[(*keypos)++];
		if (*keypos >= keysize)
			{
			*keypos = 0;            // Recycle the user key.
			*rsum += keysize;   // key "aaaa" != key "aaaaaaaa"
			}
		u = mask & *rsum;
		if (++retry_limiter > 11)
			u %= limit;     // Prevent very rare long loops.
		}
	while (u > limit);
	return u;
}

SapphireBase::SapphireBase()
	: cards(256)
{
}

SapphireBase::SapphireBase(const byte *key, unsigned int keysize)
	: cards(256)
{
	assert(keysize < 256);
	// Key size may be up to 256 bytes.
	// Pass phrases may be used directly, with longer length
	// compensating for the low entropy expected in such keys.
	// Alternatively, shorter keys hashed from a pass phrase or
	// generated randomly may be used. For random keys, lengths
	// of from 4 to 16 bytes are recommended, depending on how
	// secure you want this to be.

	int i;
	byte rsum;
	unsigned keypos;

	// Start with cards all in order, one of each.

	for (i=0;i<256;i++)
		cards[i] = i;

	// Swap the card at each position with some other card.

	keypos = 0;         // Start with first byte of user key.
	rsum = 0;
	for (i=255;i;i--)
		std::swap(cards[i], cards[keyrand(i, key, keysize, &rsum, &keypos)]);

	// Initialize the indices and data dependencies.
	// Indices are set to different values instead of all 0
	// to reduce what is known about the state of the cards
	// when the first byte is emitted.

	rotor = cards[1];
	ratchet = cards[3];
	avalanche = cards[5];
	last_plain = cards[7];
	last_cipher = cards[rsum];

	rsum = 0;
	keypos = 0;
}

SapphireBase::~SapphireBase()
{
	rotor = ratchet = avalanche = last_plain = last_cipher = 0;
}

void SapphireEncryption::ProcessString(byte *outString, const byte *inString, unsigned int length)
{
	while(length--)
		*outString++ = SapphireEncryption::ProcessByte(*inString++);
}

void SapphireEncryption::ProcessString(byte *inoutString, unsigned int length)
{
	while(length--)
	{
		*inoutString = SapphireEncryption::ProcessByte(*inoutString);
		inoutString++;
	}
}

void SapphireDecryption::ProcessString(byte *outString, const byte *inString, unsigned int length)
{
	while(length--)
		*outString++ = SapphireDecryption::ProcessByte(*inString++);
}

void SapphireDecryption::ProcessString(byte *inoutString, unsigned int length)
{
	while(length--)
	{
		*inoutString = SapphireDecryption::ProcessByte(*inoutString);
		inoutString++;
	}
}

SapphireHash::SapphireHash(unsigned int hashLength)
	: hashLength(hashLength)
{
	Init();
}

void SapphireHash::Init()
{
	// This function is used to initialize non-keyed hash
	// computation.

	int i, j;

	// Initialize the indices and data dependencies.

	rotor = 1;
	ratchet = 3;
	avalanche = 5;
	last_plain = 7;
	last_cipher = 11;

	// Start with cards all in inverse order.

	for (i=0, j=255;i<256;i++,j--)
		cards[i] = (byte) j;
}

void SapphireHash::Update(const byte *input, unsigned int length)
{
	while(length--)
		SapphireEncryption::ProcessByte(*input++);
}

void SapphireHash::TruncatedFinal(byte *hash, unsigned int size)
{
	ThrowIfInvalidTruncatedSize(size);

	for (int i=255; i>=0; i--)
		ProcessByte((byte) i);

	for (unsigned int j=0; j<size; j++)
		hash[j] = ProcessByte(0);

	Init();
}

NAMESPACE_END
