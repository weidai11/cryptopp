// lubyrack.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_LUBYRACK_H
#define CRYPTOPP_LUBYRACK_H

/** \file */

#include "simple.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T> struct DigestSizeDoubleWorkaround {enum {RESULT = 2*T::DIGESTSIZE};};	// VC60 workaround

//! .
template <class T>
struct LR_Info : public VariableKeyLength<16, 0, 2*(UINT_MAX/2), 2>, public FixedBlockSize<DigestSizeDoubleWorkaround<T>::RESULT>
{
	static std::string StaticAlgorithmName() {return std::string("LR/")+T::StaticAlgorithmName();}
};

//! Luby-Rackoff
template <class T>
class LR : public LR_Info<T>, public BlockCipherDocumentation
{
	class Base : public BlockCipherBaseTemplate<LR_Info<T> >
	{
	public:
		// VC60 workaround: have to define these functions within class definition
		void UncheckedSetKey(CipherDir direction, const byte *userKey, unsigned int length)
		{
			AssertValidKeyLength(length);

			L = length/2;
			buffer.New(2*S);
			digest.New(S);
			key.Assign(userKey, 2*L);
		}

	protected:
		enum {S=T::DIGESTSIZE};
		unsigned int L;	// key length / 2
		SecByteBlock key;

		mutable T hm;
		mutable SecByteBlock buffer, digest;
	};

	class Enc : public Base
	{
	public:

#define KL key
#define KR key+L
#define BL buffer
#define BR buffer+S
#define IL inBlock
#define IR inBlock+S
#define OL outBlock
#define OR outBlock+S

		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
		{
			hm.Update(KL, L);
			hm.Update(IL, S);
			hm.Final(BR);
			xorbuf(BR, IR, S);

			hm.Update(KR, L);
			hm.Update(BR, S);
			hm.Final(BL);
			xorbuf(BL, IL, S);

			hm.Update(KL, L);
			hm.Update(BL, S);
			hm.Final(digest);
			xorbuf(BR, digest, S);

			hm.Update(KR, L);
			hm.Update(OR, S);
			hm.Final(digest);
			xorbuf(BL, digest, S);

			if (xorBlock)
				xorbuf(outBlock, xorBlock, buffer, 2*S);
			else
				memcpy(outBlock, buffer, 2*S);
		}
	};

	class Dec : public Base
	{
	public:
		void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
		{
			hm.Update(KR, L);
			hm.Update(IR, S);
			hm.Final(BL);
			xorbuf(BL, IL, S);

			hm.Update(KL, L);
			hm.Update(BL, S);
			hm.Final(BR);
			xorbuf(BR, IR, S);

			hm.Update(KR, L);
			hm.Update(BR, S);
			hm.Final(digest);
			xorbuf(BL, digest, S);

			hm.Update(KL, L);
			hm.Update(OL, S);
			hm.Final(digest);
			xorbuf(BR, digest, S);

			if (xorBlock)
				xorbuf(outBlock, xorBlock, buffer, 2*S);
			else
				memcpy(outBlock, buffer, 2*S);
		}
#undef KL
#undef KR
#undef BL
#undef BR
#undef IL
#undef IR
#undef OL
#undef OR
	};

public:
	typedef BlockCipherTemplate<ENCRYPTION, Enc> Encryption;
	typedef BlockCipherTemplate<DECRYPTION, Dec> Decryption;
};

NAMESPACE_END

#endif
