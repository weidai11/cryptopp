#ifndef CRYPTOPP_MD5_H
#define CRYPTOPP_MD5_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

namespace Weak {

//! <a href="http://www.cryptolounge.org/wiki/MD5">MD5</a>
class MD5 : public IteratedHashWithStaticTransform<word32, LittleEndian, 64, 16, MD5>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word32 *digest, const word32 *data);
	static const char * StaticAlgorithmName() {return "MD5";}
};

}
#ifndef CRYPTOPP_ENABLE_NAMESPACE_WEAK
using namespace Weak;
#ifdef __GNUC__
#warning "You may be using a weak algorithm that has been retained for backwards compatibility. Please define CRYPTOPP_ENABLE_NAMESPACE_WEAK and prepend the class name with 'Weak::' to remove this warning."
#else
#pragma message("You may be using a weak algorithm that has been retained for backwards compatibility. Please define CRYPTOPP_ENABLE_NAMESPACE_WEAK and prepend the class name with 'Weak::' to remove this warning.")
#endif
#endif

NAMESPACE_END

#endif
