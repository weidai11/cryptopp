// kalyna.cpp - written and placed in the public domain by Jeffrey Walton
//              This code relied upon three sources. First was Oliynykov, Gorbenko, Kazymyrov, Ruzhentsev,
//              Kuznetsov, Gorbenko, Dyrda, Dolgov, Pushkaryov, Mordvinov and Kaidalov's "A New Encryption
//              Standard of Ukraine: The Kalyna Block Cipher" (http://eprint.iacr.org/2015/650.pdf). Second
//              was Roman Oliynykov and Oleksandr Kazymyrov's GitHub with the reference implementation
//              (http://github.com/Roman-Oliynykov/Kalyna-reference). The third and most utilized resource
//              was Keru Kuro's public domain implementation of Kalyna in CppCrypto
//              (http://sourceforge.net/projects/cppcrypto/). Kuro has an outstanding implementation that
//              performed better than the reference implementation and our initial attempts. The only downside
//              was the missing big endian port.

#include "pch.h"
#include "config.h"

#include "kalyna.h"
#include "argnames.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(KalynaTab)

// T can be shared between Kupyna and Kalyna; IT, S and IS are Kalyna specific
extern const word64 T[8][256];  // Columns
extern const word64 IT[8][256]; // Inverse
extern const byte S[4][256];    // Substitution
extern const byte IS[4][256];   // Inverse

NAMESPACE_END
NAMESPACE_END

ANONYMOUS_NAMESPACE_BEGIN

// The typedef here is to sidestep problems with byte in the global namespace
typedef unsigned char byte;

using CryptoPP::word64;
using CryptoPP::KalynaTab::T;
using CryptoPP::KalynaTab::S;
using CryptoPP::KalynaTab::IT;
using CryptoPP::KalynaTab::IS;

template <unsigned int NB>
inline void MakeOddKey(const word64 evenkey[NB], word64 oddkey[NB])
{
#if (CRYPTOPP_BIG_ENDIAN)
    if (NB == 2)
    {
        oddkey[0] = (evenkey[1] << 8) | (evenkey[0] >> 56);
        oddkey[1] = (evenkey[0] << 8) | (evenkey[1] >> 56);
    }
    else if (NB == 4)
    {
        oddkey[0] = (evenkey[2] << 40) | (evenkey[1] >> 24);
        oddkey[1] = (evenkey[3] << 40) | (evenkey[2] >> 24);
        oddkey[2] = (evenkey[0] << 40) | (evenkey[3] >> 24);
        oddkey[3] = (evenkey[1] << 40) | (evenkey[0] >> 24);
    }
    else if (NB == 8)
    {
        oddkey[0] = (evenkey[3] << 40) | (evenkey[2] >> 24);
        oddkey[1] = (evenkey[4] << 40) | (evenkey[3] >> 24);
        oddkey[2] = (evenkey[5] << 40) | (evenkey[4] >> 24);
        oddkey[3] = (evenkey[6] << 40) | (evenkey[5] >> 24);

        oddkey[4] = (evenkey[7] << 40) | (evenkey[6] >> 24);
        oddkey[5] = (evenkey[0] << 40) | (evenkey[7] >> 24);
        oddkey[6] = (evenkey[1] << 40) | (evenkey[0] >> 24);
        oddkey[7] = (evenkey[2] << 40) | (evenkey[1] >> 24);
    }
    else
    {
        CRYPTOPP_ASSERT(0);
    }
#else
    static const unsigned int U = (NB == 2) ? 16 : (NB == 4) ? 32 : (NB == 8) ? 64 : -1;
    static const unsigned int V = (NB == 2) ?  7 : (NB == 4) ? 11 : (NB == 8) ? 19 : -1;

    const byte* even = reinterpret_cast<const byte*>(evenkey);
    byte* odd = reinterpret_cast<byte*>(oddkey);

    memcpy(odd, even + V, U - V);
    memcpy(odd + U - V, even, V);
#endif
}

template <unsigned int NB>
inline void SwapBlocks(word64 k[NB])
{
    const word64 t = k[0];
    k[0] = k[1];

    if (NB > 2)
    {
        k[1] = k[2];
        k[2] = k[3];
    }

    if (NB > 4)
    {
        k[3] = k[4];
        k[4] = k[5];
        k[5] = k[6];
        k[6] = k[7];
    }

    k[NB - 1] = t;
}

template <unsigned int NB>
inline void AddKey(const word64 x[NB], word64 y[NB], const word64 k[NB])
{
    y[0] = x[0] + k[0];
    y[1] = x[1] + k[1];

    if (NB > 2)
    {
        y[2] = x[2] + k[2];
        y[3] = x[3] + k[3];
    }

    if (NB > 4)
    {
        y[4] = x[4] + k[4];
        y[5] = x[5] + k[5];
        y[6] = x[6] + k[6];
        y[7] = x[7] + k[7];
    }
}

template <unsigned int NB>
inline void SubKey(const word64 x[NB], word64 y[NB], const word64 k[NB])
{
    y[0] = x[0] - k[0];
    y[1] = x[1] - k[1];

    if (NB > 2)
    {
        y[2] = x[2] - k[2];
        y[3] = x[3] - k[3];
    }

    if (NB > 4)
    {
        y[4] = x[4] - k[4];
        y[5] = x[5] - k[5];
        y[6] = x[6] - k[6];
        y[7] = x[7] - k[7];
    }
}

template <unsigned int NB>
static inline void AddConstant(word64 src[NB], word64 dst[NB], word64 constant)
{
    dst[0] = src[0] + constant;
    dst[1] = src[1] + constant;

    if (NB > 2)
    {
        dst[2] = src[2] + constant;
        dst[3] = src[3] + constant;
    }

    if (NB > 4)
    {
        dst[4] = src[4] + constant;
        dst[5] = src[5] + constant;
        dst[6] = src[6] + constant;
        dst[7] = src[7] + constant;
    }
}

inline void G0128(const word64 x[2], word64 y[2])
{
    y[0] = T[0][(byte)x[0]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[1] >> 56)];
    y[1] = T[0][(byte)x[1]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[0] >> 56)];
}

inline void G0256(const word64 x[4], word64 y[4])
{
    y[0] = T[0][(byte)x[0]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[3] >> 16)] ^ T[3][(byte)(x[3] >> 24)] ^
        T[4][(byte)(x[2] >> 32)] ^ T[5][(byte)(x[2] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[1] >> 56)];
    y[1] = T[0][(byte)x[1]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[3] >> 32)] ^ T[5][(byte)(x[3] >> 40)] ^ T[6][(byte)(x[2] >> 48)] ^ T[7][(byte)(x[2] >> 56)];
    y[2] = T[0][(byte)x[2]] ^ T[1][(byte)(x[2] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[3] >> 48)] ^ T[7][(byte)(x[3] >> 56)];
    y[3] = T[0][(byte)x[3]] ^ T[1][(byte)(x[3] >> 8)] ^ T[2][(byte)(x[2] >> 16)] ^ T[3][(byte)(x[2] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[0] >> 56)];
}

inline void G0512(const word64 x[8], word64 y[8])
{
    y[0] = T[0][(byte)x[0]] ^ T[1][(byte)(x[7] >> 8)] ^ T[2][(byte)(x[6] >> 16)] ^ T[3][(byte)(x[5] >> 24)] ^
        T[4][(byte)(x[4] >> 32)] ^ T[5][(byte)(x[3] >> 40)] ^ T[6][(byte)(x[2] >> 48)] ^ T[7][(byte)(x[1] >> 56)];
    y[1] = T[0][(byte)x[1]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[7] >> 16)] ^ T[3][(byte)(x[6] >> 24)] ^
        T[4][(byte)(x[5] >> 32)] ^ T[5][(byte)(x[4] >> 40)] ^ T[6][(byte)(x[3] >> 48)] ^ T[7][(byte)(x[2] >> 56)];
    y[2] = T[0][(byte)x[2]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[7] >> 24)] ^
        T[4][(byte)(x[6] >> 32)] ^ T[5][(byte)(x[5] >> 40)] ^ T[6][(byte)(x[4] >> 48)] ^ T[7][(byte)(x[3] >> 56)];
    y[3] = T[0][(byte)x[3]] ^ T[1][(byte)(x[2] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[7] >> 32)] ^ T[5][(byte)(x[6] >> 40)] ^ T[6][(byte)(x[5] >> 48)] ^ T[7][(byte)(x[4] >> 56)];
    y[4] = T[0][(byte)x[4]] ^ T[1][(byte)(x[3] >> 8)] ^ T[2][(byte)(x[2] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[7] >> 40)] ^ T[6][(byte)(x[6] >> 48)] ^ T[7][(byte)(x[5] >> 56)];
    y[5] = T[0][(byte)x[5]] ^ T[1][(byte)(x[4] >> 8)] ^ T[2][(byte)(x[3] >> 16)] ^ T[3][(byte)(x[2] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[7] >> 48)] ^ T[7][(byte)(x[6] >> 56)];
    y[6] = T[0][(byte)x[6]] ^ T[1][(byte)(x[5] >> 8)] ^ T[2][(byte)(x[4] >> 16)] ^ T[3][(byte)(x[3] >> 24)] ^
        T[4][(byte)(x[2] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[7] >> 56)];
    y[7] = T[0][(byte)x[7]] ^ T[1][(byte)(x[6] >> 8)] ^ T[2][(byte)(x[5] >> 16)] ^ T[3][(byte)(x[4] >> 24)] ^
        T[4][(byte)(x[3] >> 32)] ^ T[5][(byte)(x[2] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[0] >> 56)];
}

inline void GL128(const word64 x[2], word64 y[2], const word64 k[2])
{
    y[0] = k[0] + (T[0][(byte)x[0]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[1] >> 56)]);
    y[1] = k[1] + (T[0][(byte)x[1]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[0] >> 56)]);
}

inline void GL256(const word64 x[4], word64 y[4], const word64 k[4])
{
    y[0] = k[0] + (T[0][(byte)x[0]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[3] >> 16)] ^ T[3][(byte)(x[3] >> 24)] ^
        T[4][(byte)(x[2] >> 32)] ^ T[5][(byte)(x[2] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[1] >> 56)]);
    y[1] = k[1] + (T[0][(byte)x[1]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[3] >> 32)] ^ T[5][(byte)(x[3] >> 40)] ^ T[6][(byte)(x[2] >> 48)] ^ T[7][(byte)(x[2] >> 56)]);
    y[2] = k[2] + (T[0][(byte)x[2]] ^ T[1][(byte)(x[2] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[3] >> 48)] ^ T[7][(byte)(x[3] >> 56)]);
    y[3] = k[3] + (T[0][(byte)x[3]] ^ T[1][(byte)(x[3] >> 8)] ^ T[2][(byte)(x[2] >> 16)] ^ T[3][(byte)(x[2] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[0] >> 56)]);
}

inline void GL512(const word64 x[8], word64 y[8], const word64 k[8])
{
    y[0] = k[0] + (T[0][(byte)x[0]] ^ T[1][(byte)(x[7] >> 8)] ^ T[2][(byte)(x[6] >> 16)] ^ T[3][(byte)(x[5] >> 24)] ^
        T[4][(byte)(x[4] >> 32)] ^ T[5][(byte)(x[3] >> 40)] ^ T[6][(byte)(x[2] >> 48)] ^ T[7][(byte)(x[1] >> 56)]);
    y[1] = k[1] + (T[0][(byte)x[1]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[7] >> 16)] ^ T[3][(byte)(x[6] >> 24)] ^
        T[4][(byte)(x[5] >> 32)] ^ T[5][(byte)(x[4] >> 40)] ^ T[6][(byte)(x[3] >> 48)] ^ T[7][(byte)(x[2] >> 56)]);
    y[2] = k[2] + (T[0][(byte)x[2]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[7] >> 24)] ^
        T[4][(byte)(x[6] >> 32)] ^ T[5][(byte)(x[5] >> 40)] ^ T[6][(byte)(x[4] >> 48)] ^ T[7][(byte)(x[3] >> 56)]);
    y[3] = k[3] + (T[0][(byte)x[3]] ^ T[1][(byte)(x[2] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[7] >> 32)] ^ T[5][(byte)(x[6] >> 40)] ^ T[6][(byte)(x[5] >> 48)] ^ T[7][(byte)(x[4] >> 56)]);
    y[4] = k[4] + (T[0][(byte)x[4]] ^ T[1][(byte)(x[3] >> 8)] ^ T[2][(byte)(x[2] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[7] >> 40)] ^ T[6][(byte)(x[6] >> 48)] ^ T[7][(byte)(x[5] >> 56)]);
    y[5] = k[5] + (T[0][(byte)x[5]] ^ T[1][(byte)(x[4] >> 8)] ^ T[2][(byte)(x[3] >> 16)] ^ T[3][(byte)(x[2] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[7] >> 48)] ^ T[7][(byte)(x[6] >> 56)]);
    y[6] = k[6] + (T[0][(byte)x[6]] ^ T[1][(byte)(x[5] >> 8)] ^ T[2][(byte)(x[4] >> 16)] ^ T[3][(byte)(x[3] >> 24)] ^
        T[4][(byte)(x[2] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[7] >> 56)]);
    y[7] = k[7] + (T[0][(byte)x[7]] ^ T[1][(byte)(x[6] >> 8)] ^ T[2][(byte)(x[5] >> 16)] ^ T[3][(byte)(x[4] >> 24)] ^
        T[4][(byte)(x[3] >> 32)] ^ T[5][(byte)(x[2] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[0] >> 56)]);
}

inline void IMC128(word64 x[2])
{
    x[0] = IT[0][S[0][(byte)x[0]]] ^ IT[1][S[1][(byte)(x[0] >> 8)]] ^ IT[2][S[2][(byte)(x[0] >> 16)]] ^ IT[3][S[3][(byte)(x[0] >> 24)]] ^
        IT[4][S[0][(byte)(x[0] >> 32)]] ^ IT[5][S[1][(byte)(x[0] >> 40)]] ^ IT[6][S[2][(byte)(x[0] >> 48)]] ^ IT[7][S[3][(byte)(x[0] >> 56)]];
    x[1] = IT[0][S[0][(byte)x[1]]] ^ IT[1][S[1][(byte)(x[1] >> 8)]] ^ IT[2][S[2][(byte)(x[1] >> 16)]] ^ IT[3][S[3][(byte)(x[1] >> 24)]] ^
        IT[4][S[0][(byte)(x[1] >> 32)]] ^ IT[5][S[1][(byte)(x[1] >> 40)]] ^ IT[6][S[2][(byte)(x[1] >> 48)]] ^ IT[7][S[3][(byte)(x[1] >> 56)]];
}

inline void IMC256(word64 x[4])
{
    x[0] = IT[0][S[0][(byte)x[0]]] ^ IT[1][S[1][(byte)(x[0] >> 8)]] ^ IT[2][S[2][(byte)(x[0] >> 16)]] ^ IT[3][S[3][(byte)(x[0] >> 24)]] ^
        IT[4][S[0][(byte)(x[0] >> 32)]] ^ IT[5][S[1][(byte)(x[0] >> 40)]] ^ IT[6][S[2][(byte)(x[0] >> 48)]] ^ IT[7][S[3][(byte)(x[0] >> 56)]];
    x[1] = IT[0][S[0][(byte)x[1]]] ^ IT[1][S[1][(byte)(x[1] >> 8)]] ^ IT[2][S[2][(byte)(x[1] >> 16)]] ^ IT[3][S[3][(byte)(x[1] >> 24)]] ^
        IT[4][S[0][(byte)(x[1] >> 32)]] ^ IT[5][S[1][(byte)(x[1] >> 40)]] ^ IT[6][S[2][(byte)(x[1] >> 48)]] ^ IT[7][S[3][(byte)(x[1] >> 56)]];
    x[2] = IT[0][S[0][(byte)x[2]]] ^ IT[1][S[1][(byte)(x[2] >> 8)]] ^ IT[2][S[2][(byte)(x[2] >> 16)]] ^ IT[3][S[3][(byte)(x[2] >> 24)]] ^
        IT[4][S[0][(byte)(x[2] >> 32)]] ^ IT[5][S[1][(byte)(x[2] >> 40)]] ^ IT[6][S[2][(byte)(x[2] >> 48)]] ^ IT[7][S[3][(byte)(x[2] >> 56)]];
    x[3] = IT[0][S[0][(byte)x[3]]] ^ IT[1][S[1][(byte)(x[3] >> 8)]] ^ IT[2][S[2][(byte)(x[3] >> 16)]] ^ IT[3][S[3][(byte)(x[3] >> 24)]] ^
        IT[4][S[0][(byte)(x[3] >> 32)]] ^ IT[5][S[1][(byte)(x[3] >> 40)]] ^ IT[6][S[2][(byte)(x[3] >> 48)]] ^ IT[7][S[3][(byte)(x[3] >> 56)]];
}

inline void IMC512(word64 x[8])
{
    x[0] = IT[0][S[0][(byte)x[0]]] ^ IT[1][S[1][(byte)(x[0] >> 8)]] ^ IT[2][S[2][(byte)(x[0] >> 16)]] ^ IT[3][S[3][(byte)(x[0] >> 24)]] ^
        IT[4][S[0][(byte)(x[0] >> 32)]] ^ IT[5][S[1][(byte)(x[0] >> 40)]] ^ IT[6][S[2][(byte)(x[0] >> 48)]] ^ IT[7][S[3][(byte)(x[0] >> 56)]];
    x[1] = IT[0][S[0][(byte)x[1]]] ^ IT[1][S[1][(byte)(x[1] >> 8)]] ^ IT[2][S[2][(byte)(x[1] >> 16)]] ^ IT[3][S[3][(byte)(x[1] >> 24)]] ^
        IT[4][S[0][(byte)(x[1] >> 32)]] ^ IT[5][S[1][(byte)(x[1] >> 40)]] ^ IT[6][S[2][(byte)(x[1] >> 48)]] ^ IT[7][S[3][(byte)(x[1] >> 56)]];
    x[2] = IT[0][S[0][(byte)x[2]]] ^ IT[1][S[1][(byte)(x[2] >> 8)]] ^ IT[2][S[2][(byte)(x[2] >> 16)]] ^ IT[3][S[3][(byte)(x[2] >> 24)]] ^
        IT[4][S[0][(byte)(x[2] >> 32)]] ^ IT[5][S[1][(byte)(x[2] >> 40)]] ^ IT[6][S[2][(byte)(x[2] >> 48)]] ^ IT[7][S[3][(byte)(x[2] >> 56)]];
    x[3] = IT[0][S[0][(byte)x[3]]] ^ IT[1][S[1][(byte)(x[3] >> 8)]] ^ IT[2][S[2][(byte)(x[3] >> 16)]] ^ IT[3][S[3][(byte)(x[3] >> 24)]] ^
        IT[4][S[0][(byte)(x[3] >> 32)]] ^ IT[5][S[1][(byte)(x[3] >> 40)]] ^ IT[6][S[2][(byte)(x[3] >> 48)]] ^ IT[7][S[3][(byte)(x[3] >> 56)]];
    x[4] = IT[0][S[0][(byte)x[4]]] ^ IT[1][S[1][(byte)(x[4] >> 8)]] ^ IT[2][S[2][(byte)(x[4] >> 16)]] ^ IT[3][S[3][(byte)(x[4] >> 24)]] ^
        IT[4][S[0][(byte)(x[4] >> 32)]] ^ IT[5][S[1][(byte)(x[4] >> 40)]] ^ IT[6][S[2][(byte)(x[4] >> 48)]] ^ IT[7][S[3][(byte)(x[4] >> 56)]];
    x[5] = IT[0][S[0][(byte)x[5]]] ^ IT[1][S[1][(byte)(x[5] >> 8)]] ^ IT[2][S[2][(byte)(x[5] >> 16)]] ^ IT[3][S[3][(byte)(x[5] >> 24)]] ^
        IT[4][S[0][(byte)(x[5] >> 32)]] ^ IT[5][S[1][(byte)(x[5] >> 40)]] ^ IT[6][S[2][(byte)(x[5] >> 48)]] ^ IT[7][S[3][(byte)(x[5] >> 56)]];
    x[6] = IT[0][S[0][(byte)x[6]]] ^ IT[1][S[1][(byte)(x[6] >> 8)]] ^ IT[2][S[2][(byte)(x[6] >> 16)]] ^ IT[3][S[3][(byte)(x[6] >> 24)]] ^
        IT[4][S[0][(byte)(x[6] >> 32)]] ^ IT[5][S[1][(byte)(x[6] >> 40)]] ^ IT[6][S[2][(byte)(x[6] >> 48)]] ^ IT[7][S[3][(byte)(x[6] >> 56)]];
    x[7] = IT[0][S[0][(byte)x[7]]] ^ IT[1][S[1][(byte)(x[7] >> 8)]] ^ IT[2][S[2][(byte)(x[7] >> 16)]] ^ IT[3][S[3][(byte)(x[7] >> 24)]] ^
        IT[4][S[0][(byte)(x[7] >> 32)]] ^ IT[5][S[1][(byte)(x[7] >> 40)]] ^ IT[6][S[2][(byte)(x[7] >> 48)]] ^ IT[7][S[3][(byte)(x[7] >> 56)]];
}

inline void IG128(const word64 x[2], word64 y[2], const word64 k[2])
{
    y[0] = k[0] ^ IT[0][(byte)x[0]] ^ IT[1][(byte)(x[0] >> 8)] ^ IT[2][(byte)(x[0] >> 16)] ^ IT[3][(byte)(x[0] >> 24)] ^
        IT[4][(byte)(x[1] >> 32)] ^ IT[5][(byte)(x[1] >> 40)] ^ IT[6][(byte)(x[1] >> 48)] ^ IT[7][(byte)(x[1] >> 56)];
    y[1] = k[1] ^ IT[0][(byte)x[1]] ^ IT[1][(byte)(x[1] >> 8)] ^ IT[2][(byte)(x[1] >> 16)] ^ IT[3][(byte)(x[1] >> 24)] ^
        IT[4][(byte)(x[0] >> 32)] ^ IT[5][(byte)(x[0] >> 40)] ^ IT[6][(byte)(x[0] >> 48)] ^ IT[7][(byte)(x[0] >> 56)];
}

inline void IG256(const word64 x[4], word64 y[4], const word64 k[4])
{
    y[0] = k[0] ^ IT[0][(byte)x[0]] ^ IT[1][(byte)(x[0] >> 8)] ^ IT[2][(byte)(x[1] >> 16)] ^ IT[3][(byte)(x[1] >> 24)] ^
        IT[4][(byte)(x[2] >> 32)] ^ IT[5][(byte)(x[2] >> 40)] ^ IT[6][(byte)(x[3] >> 48)] ^ IT[7][(byte)(x[3] >> 56)];
    y[1] = k[1] ^ IT[0][(byte)x[1]] ^ IT[1][(byte)(x[1] >> 8)] ^ IT[2][(byte)(x[2] >> 16)] ^ IT[3][(byte)(x[2] >> 24)] ^
        IT[4][(byte)(x[3] >> 32)] ^ IT[5][(byte)(x[3] >> 40)] ^ IT[6][(byte)(x[0] >> 48)] ^ IT[7][(byte)(x[0] >> 56)];
    y[2] = k[2] ^ IT[0][(byte)x[2]] ^ IT[1][(byte)(x[2] >> 8)] ^ IT[2][(byte)(x[3] >> 16)] ^ IT[3][(byte)(x[3] >> 24)] ^
        IT[4][(byte)(x[0] >> 32)] ^ IT[5][(byte)(x[0] >> 40)] ^ IT[6][(byte)(x[1] >> 48)] ^ IT[7][(byte)(x[1] >> 56)];
    y[3] = k[3] ^ IT[0][(byte)x[3]] ^ IT[1][(byte)(x[3] >> 8)] ^ IT[2][(byte)(x[0] >> 16)] ^ IT[3][(byte)(x[0] >> 24)] ^
        IT[4][(byte)(x[1] >> 32)] ^ IT[5][(byte)(x[1] >> 40)] ^ IT[6][(byte)(x[2] >> 48)] ^ IT[7][(byte)(x[2] >> 56)];
}

inline void IG512(const word64 x[8], word64 y[8], const word64 k[8])
{
    y[0] = k[0] ^ IT[0][(byte)x[0]] ^ IT[1][(byte)(x[1] >> 8)] ^ IT[2][(byte)(x[2] >> 16)] ^ IT[3][(byte)(x[3] >> 24)] ^
        IT[4][(byte)(x[4] >> 32)] ^ IT[5][(byte)(x[5] >> 40)] ^ IT[6][(byte)(x[6] >> 48)] ^ IT[7][(byte)(x[7] >> 56)];
    y[1] = k[1] ^ IT[0][(byte)x[1]] ^ IT[1][(byte)(x[2] >> 8)] ^ IT[2][(byte)(x[3] >> 16)] ^ IT[3][(byte)(x[4] >> 24)] ^
        IT[4][(byte)(x[5] >> 32)] ^ IT[5][(byte)(x[6] >> 40)] ^ IT[6][(byte)(x[7] >> 48)] ^ IT[7][(byte)(x[0] >> 56)];
    y[2] = k[2] ^ IT[0][(byte)x[2]] ^ IT[1][(byte)(x[3] >> 8)] ^ IT[2][(byte)(x[4] >> 16)] ^ IT[3][(byte)(x[5] >> 24)] ^
        IT[4][(byte)(x[6] >> 32)] ^ IT[5][(byte)(x[7] >> 40)] ^ IT[6][(byte)(x[0] >> 48)] ^ IT[7][(byte)(x[1] >> 56)];
    y[3] = k[3] ^ IT[0][(byte)x[3]] ^ IT[1][(byte)(x[4] >> 8)] ^ IT[2][(byte)(x[5] >> 16)] ^ IT[3][(byte)(x[6] >> 24)] ^
        IT[4][(byte)(x[7] >> 32)] ^ IT[5][(byte)(x[0] >> 40)] ^ IT[6][(byte)(x[1] >> 48)] ^ IT[7][(byte)(x[2] >> 56)];
    y[4] = k[4] ^ IT[0][(byte)x[4]] ^ IT[1][(byte)(x[5] >> 8)] ^ IT[2][(byte)(x[6] >> 16)] ^ IT[3][(byte)(x[7] >> 24)] ^
        IT[4][(byte)(x[0] >> 32)] ^ IT[5][(byte)(x[1] >> 40)] ^ IT[6][(byte)(x[2] >> 48)] ^ IT[7][(byte)(x[3] >> 56)];
    y[5] = k[5] ^ IT[0][(byte)x[5]] ^ IT[1][(byte)(x[6] >> 8)] ^ IT[2][(byte)(x[7] >> 16)] ^ IT[3][(byte)(x[0] >> 24)] ^
        IT[4][(byte)(x[1] >> 32)] ^ IT[5][(byte)(x[2] >> 40)] ^ IT[6][(byte)(x[3] >> 48)] ^ IT[7][(byte)(x[4] >> 56)];
    y[6] = k[6] ^ IT[0][(byte)x[6]] ^ IT[1][(byte)(x[7] >> 8)] ^ IT[2][(byte)(x[0] >> 16)] ^ IT[3][(byte)(x[1] >> 24)] ^
        IT[4][(byte)(x[2] >> 32)] ^ IT[5][(byte)(x[3] >> 40)] ^ IT[6][(byte)(x[4] >> 48)] ^ IT[7][(byte)(x[5] >> 56)];
    y[7] = k[7] ^ IT[0][(byte)x[7]] ^ IT[1][(byte)(x[0] >> 8)] ^ IT[2][(byte)(x[1] >> 16)] ^ IT[3][(byte)(x[2] >> 24)] ^
        IT[4][(byte)(x[3] >> 32)] ^ IT[5][(byte)(x[4] >> 40)] ^ IT[6][(byte)(x[5] >> 48)] ^ IT[7][(byte)(x[6] >> 56)];
}

inline void IGL128(const word64 x[2], word64 y[2], const word64 k[2])
{
    y[0] = (word64(IS[0][(byte)x[0]]) ^ word64(IS[1][(byte)(x[0] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[0] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[0] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[1] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[1] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[1] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[1] >> 56)]) << 56) - k[0];
    y[1] = (word64(IS[0][(byte)x[1]]) ^ word64(IS[1][(byte)(x[1] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[1] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[1] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[0] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[0] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[0] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[0] >> 56)]) << 56) - k[1];
}

inline void IGL256(const word64 x[4], word64 y[4], const word64 k[4])
{
    y[0] = (word64(IS[0][(byte)x[0]]) ^ word64(IS[1][(byte)(x[0] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[1] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[1] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[2] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[2] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[3] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[3] >> 56)]) << 56) - k[0];
    y[1] = (word64(IS[0][(byte)x[1]]) ^ word64(IS[1][(byte)(x[1] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[2] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[2] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[3] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[3] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[0] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[0] >> 56)]) << 56) - k[1];
    y[2] = (word64(IS[0][(byte)x[2]]) ^ word64(IS[1][(byte)(x[2] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[3] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[3] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[0] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[0] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[1] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[1] >> 56)]) << 56) - k[2];
    y[3] = (word64(IS[0][(byte)x[3]]) ^ word64(IS[1][(byte)(x[3] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[0] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[0] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[1] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[1] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[2] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[2] >> 56)]) << 56) - k[3];
}

inline void IGL512(const word64 x[8], word64 y[8], const word64 k[8])
{
    y[0] = (word64(IS[0][(byte)x[0]]) ^ word64(IS[1][(byte)(x[1] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[2] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[3] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[4] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[5] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[6] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[7] >> 56)]) << 56) - k[0];
    y[1] = (word64(IS[0][(byte)x[1]]) ^ word64(IS[1][(byte)(x[2] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[3] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[4] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[5] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[6] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[7] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[0] >> 56)]) << 56) - k[1];
    y[2] = (word64(IS[0][(byte)x[2]]) ^ word64(IS[1][(byte)(x[3] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[4] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[5] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[6] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[7] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[0] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[1] >> 56)]) << 56) - k[2];
    y[3] = (word64(IS[0][(byte)x[3]]) ^ word64(IS[1][(byte)(x[4] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[5] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[6] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[7] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[0] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[1] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[2] >> 56)]) << 56) - k[3];
    y[4] = (word64(IS[0][(byte)x[4]]) ^ word64(IS[1][(byte)(x[5] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[6] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[7] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[0] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[1] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[2] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[3] >> 56)]) << 56) - k[4];
    y[5] = (word64(IS[0][(byte)x[5]]) ^ word64(IS[1][(byte)(x[6] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[7] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[0] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[1] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[2] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[3] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[4] >> 56)]) << 56) - k[5];
    y[6] = (word64(IS[0][(byte)x[6]]) ^ word64(IS[1][(byte)(x[7] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[0] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[1] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[2] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[3] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[4] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[5] >> 56)]) << 56) - k[6];
    y[7] = (word64(IS[0][(byte)x[7]]) ^ word64(IS[1][(byte)(x[0] >> 8)]) << 8 ^ word64(IS[2][(byte)(x[1] >> 16)]) << 16 ^ word64(IS[3][(byte)(x[2] >> 24)]) << 24 ^
        word64(IS[0][(byte)(x[3] >> 32)]) << 32 ^ word64(IS[1][(byte)(x[4] >> 40)]) << 40 ^ word64(IS[2][(byte)(x[5] >> 48)]) << 48 ^ word64(IS[3][(byte)(x[6] >> 56)]) << 56) - k[7];
}

inline void G128(const word64 x[2], word64 y[2], const word64 k[2])
{
    y[0] = k[0] ^ T[0][(byte)x[0]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[1] >> 56)];
    y[1] = k[1] ^ T[0][(byte)x[1]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[0] >> 56)];
}

inline void G256(const word64 x[4], word64 y[4], const word64 k[4])
{
    y[0] = k[0] ^ T[0][(byte)x[0]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[3] >> 16)] ^ T[3][(byte)(x[3] >> 24)] ^
        T[4][(byte)(x[2] >> 32)] ^ T[5][(byte)(x[2] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[1] >> 56)];
    y[1] = k[1] ^ T[0][(byte)x[1]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[3] >> 32)] ^ T[5][(byte)(x[3] >> 40)] ^ T[6][(byte)(x[2] >> 48)] ^ T[7][(byte)(x[2] >> 56)];
    y[2] = k[2] ^ T[0][(byte)x[2]] ^ T[1][(byte)(x[2] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[3] >> 48)] ^ T[7][(byte)(x[3] >> 56)];
    y[3] = k[3] ^ T[0][(byte)x[3]] ^ T[1][(byte)(x[3] >> 8)] ^ T[2][(byte)(x[2] >> 16)] ^ T[3][(byte)(x[2] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[0] >> 56)];
}

inline void G512(const word64 x[8], word64 y[8], const word64 k[8])
{
    y[0] = k[0] ^ T[0][(byte)x[0]] ^ T[1][(byte)(x[7] >> 8)] ^ T[2][(byte)(x[6] >> 16)] ^ T[3][(byte)(x[5] >> 24)] ^
        T[4][(byte)(x[4] >> 32)] ^ T[5][(byte)(x[3] >> 40)] ^ T[6][(byte)(x[2] >> 48)] ^ T[7][(byte)(x[1] >> 56)];
    y[1] = k[1] ^ T[0][(byte)x[1]] ^ T[1][(byte)(x[0] >> 8)] ^ T[2][(byte)(x[7] >> 16)] ^ T[3][(byte)(x[6] >> 24)] ^
        T[4][(byte)(x[5] >> 32)] ^ T[5][(byte)(x[4] >> 40)] ^ T[6][(byte)(x[3] >> 48)] ^ T[7][(byte)(x[2] >> 56)];
    y[2] = k[2] ^ T[0][(byte)x[2]] ^ T[1][(byte)(x[1] >> 8)] ^ T[2][(byte)(x[0] >> 16)] ^ T[3][(byte)(x[7] >> 24)] ^
        T[4][(byte)(x[6] >> 32)] ^ T[5][(byte)(x[5] >> 40)] ^ T[6][(byte)(x[4] >> 48)] ^ T[7][(byte)(x[3] >> 56)];
    y[3] = k[3] ^ T[0][(byte)x[3]] ^ T[1][(byte)(x[2] >> 8)] ^ T[2][(byte)(x[1] >> 16)] ^ T[3][(byte)(x[0] >> 24)] ^
        T[4][(byte)(x[7] >> 32)] ^ T[5][(byte)(x[6] >> 40)] ^ T[6][(byte)(x[5] >> 48)] ^ T[7][(byte)(x[4] >> 56)];
    y[4] = k[4] ^ T[0][(byte)x[4]] ^ T[1][(byte)(x[3] >> 8)] ^ T[2][(byte)(x[2] >> 16)] ^ T[3][(byte)(x[1] >> 24)] ^
        T[4][(byte)(x[0] >> 32)] ^ T[5][(byte)(x[7] >> 40)] ^ T[6][(byte)(x[6] >> 48)] ^ T[7][(byte)(x[5] >> 56)];
    y[5] = k[5] ^ T[0][(byte)x[5]] ^ T[1][(byte)(x[4] >> 8)] ^ T[2][(byte)(x[3] >> 16)] ^ T[3][(byte)(x[2] >> 24)] ^
        T[4][(byte)(x[1] >> 32)] ^ T[5][(byte)(x[0] >> 40)] ^ T[6][(byte)(x[7] >> 48)] ^ T[7][(byte)(x[6] >> 56)];
    y[6] = k[6] ^ T[0][(byte)x[6]] ^ T[1][(byte)(x[5] >> 8)] ^ T[2][(byte)(x[4] >> 16)] ^ T[3][(byte)(x[3] >> 24)] ^
        T[4][(byte)(x[2] >> 32)] ^ T[5][(byte)(x[1] >> 40)] ^ T[6][(byte)(x[0] >> 48)] ^ T[7][(byte)(x[7] >> 56)];
    y[7] = k[7] ^ T[0][(byte)x[7]] ^ T[1][(byte)(x[6] >> 8)] ^ T[2][(byte)(x[5] >> 16)] ^ T[3][(byte)(x[4] >> 24)] ^
        T[4][(byte)(x[3] >> 32)] ^ T[5][(byte)(x[2] >> 40)] ^ T[6][(byte)(x[1] >> 48)] ^ T[7][(byte)(x[0] >> 56)];
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

// *********************** UncheckedSetKey specializations *********************** //

void Kalyna128::Base::SetKey_22(const word64 key[2])
{
    word64 *ks = m_wspace+0, *ksc = m_wspace+2, *t1 = m_wspace+4;
    word64 *t2 = m_wspace+6, *k = m_wspace+8, *kswapped = m_wspace+10;

    memset(t1, 0, 2*8);
    t1[0] = (128 + 128 + 64) / 64;

    AddKey<2>(t1, t2, key);
    G128(t2, t1, key);
    GL128(t1, t2, key);
    G0128(t2, ks);

    word64 constant = W64LIT(0x0001000100010001);

    // round 0
    memcpy(k, key, 16);
    kswapped[1] = k[0];
    kswapped[0] = k[1];

    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[0], ksc);
    MakeOddKey<2>(&m_rkeys[0], &m_rkeys[2]);

    // round 2
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(kswapped, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[4], ksc);
    MakeOddKey<2>(&m_rkeys[4], &m_rkeys[6]);

    // round 4
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[8], ksc);
    MakeOddKey<2>(&m_rkeys[8], &m_rkeys[10]);

    // round 6
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(kswapped, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[12], ksc);
    MakeOddKey<2>(&m_rkeys[12], &m_rkeys[14]);

    // round 8
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[16], ksc);
    MakeOddKey<2>(&m_rkeys[16], &m_rkeys[18]);

    // round 10
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(kswapped, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[20], ksc);

    if (!IsForwardTransformation())
    {
        IMC128(&m_rkeys[18]); IMC128(&m_rkeys[16]);
        IMC128(&m_rkeys[14]); IMC128(&m_rkeys[12]);
        IMC128(&m_rkeys[10]); IMC128(&m_rkeys[ 8]);
        IMC128(&m_rkeys[ 6]); IMC128(&m_rkeys[ 4]);
        IMC128(&m_rkeys[ 2]);
    }
}

void Kalyna128::Base::SetKey_24(const word64 key[4])
{
    word64 *ks = m_wspace+0, *ksc = m_wspace+2, *t1 = m_wspace+4, *t2 = m_wspace+6;
    word64 *k = m_wspace+8, *ka = m_wspace+12, *ko = m_wspace+14;

    memset(t1, 0, 2*8);
    t1[0] = (128 + 256 + 64) / 64;
    memcpy(ka, key, 16);
    memcpy(ko, key + 2, 16);

    AddKey<2>(t1, t2, ka);
    G128(t2, t1, ko);
    GL128(t1, t2, ka);
    G0128(t2, ks);

    word64 constant = W64LIT(0x0001000100010001);

    // round 0
    memcpy(k, key, 256 / 8);
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[0], ksc);
    MakeOddKey<2>(&m_rkeys[0], &m_rkeys[2]);

    // round 2
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k + 2, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[4], ksc);
    MakeOddKey<2>(&m_rkeys[4], &m_rkeys[6]);

    // round 4
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[8], ksc);
    MakeOddKey<2>(&m_rkeys[8], &m_rkeys[10]);

    // round 6
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k + 2, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[12], ksc);
    MakeOddKey<2>(&m_rkeys[12], &m_rkeys[14]);

    // round 8
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[16], ksc);
    MakeOddKey<2>(&m_rkeys[16], &m_rkeys[18]);

    // round 10
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k + 2, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[20], ksc);
    MakeOddKey<2>(&m_rkeys[20], &m_rkeys[22]);

    // round 12
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[24], ksc);
    MakeOddKey<2>(&m_rkeys[24], &m_rkeys[26]);

    // round 14
    constant <<= 1;
    AddConstant<2>(ks, ksc, constant);
    AddKey<2>(k + 2, t2, ksc);
    G128(t2, t1, ksc);
    GL128(t1, &m_rkeys[28], ksc);

    if (!IsForwardTransformation())
    {
        IMC128(&m_rkeys[26]);
        IMC128(&m_rkeys[24]);
        IMC128(&m_rkeys[22]);
        IMC128(&m_rkeys[20]);
        IMC128(&m_rkeys[18]);
        IMC128(&m_rkeys[16]);
        IMC128(&m_rkeys[14]);
        IMC128(&m_rkeys[12]);
        IMC128(&m_rkeys[10]);
        IMC128(&m_rkeys[8]);
        IMC128(&m_rkeys[6]);
        IMC128(&m_rkeys[4]);
        IMC128(&m_rkeys[2]);
    }
}

void Kalyna256::Base::SetKey_44(const word64 key[4])
{
    word64 *ks = m_wspace+0, *ksc = m_wspace+4, *t1 = m_wspace+8;
    word64 *t2 = m_wspace+12, *k = m_wspace+16;

    memset(t1, 0, 32);
    t1[0] = (256 + 256 + 64) / 64;

    AddKey<4>(t1, t2, key);
    G256(t2, t1, key);
    GL256(t1, t2, key);
    G0256(t2, ks);

    word64 constant = W64LIT(0x0001000100010001);

    // round 0
    memcpy(k, key, 32);
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[0], ksc);
    MakeOddKey<4>(&m_rkeys[0], &m_rkeys[4]);

    // round 2
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[8], ksc);
    MakeOddKey<4>(&m_rkeys[8], &m_rkeys[12]);

    // round 4
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[16], ksc);
    MakeOddKey<4>(&m_rkeys[16], &m_rkeys[20]);

    // round 6
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[24], ksc);
    MakeOddKey<4>(&m_rkeys[24], &m_rkeys[28]);

    // round 8
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[32], ksc);
    MakeOddKey<4>(&m_rkeys[32], &m_rkeys[36]);

    // round 10
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[40], ksc);
    MakeOddKey<4>(&m_rkeys[40], &m_rkeys[44]);

    // round 12
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[48], ksc);
    MakeOddKey<4>(&m_rkeys[48], &m_rkeys[52]);

    // round 14
    SwapBlocks<4>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[56], ksc);

    if (!IsForwardTransformation())
    {
        IMC256(&m_rkeys[52]);
        IMC256(&m_rkeys[48]);
        IMC256(&m_rkeys[44]);
        IMC256(&m_rkeys[40]);
        IMC256(&m_rkeys[36]);
        IMC256(&m_rkeys[32]);
        IMC256(&m_rkeys[28]);
        IMC256(&m_rkeys[24]);
        IMC256(&m_rkeys[20]);
        IMC256(&m_rkeys[16]);
        IMC256(&m_rkeys[12]);
        IMC256(&m_rkeys[8]);
        IMC256(&m_rkeys[4]);
    }
}

void Kalyna256::Base::SetKey_48(const word64 key[8])
{
    word64 *ks = m_wspace+0, *ksc = m_wspace+4, *t1 = m_wspace+8, *t2 = m_wspace+12;
    word64 *k = m_wspace+16, *ka = m_wspace+24, *ko = m_wspace+28;

    memset(t1, 0, 4*8);
    t1[0] = (512 + 256 + 64) / 64;
    memcpy(ka, key, 32);
    memcpy(ko, key+4, 32);

    AddKey<4>(t1, t2, ka);
    G256(t2, t1, ko);
    GL256(t1, t2, ka);
    G0256(t2, ks);

    word64 constant = W64LIT(0x0001000100010001);

    // round 0
    memcpy(k, key, 512 / 8);
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[0], ksc);
    MakeOddKey<4>(&m_rkeys[0], &m_rkeys[4]);

    // round 2
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k+4, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[8], ksc);
    MakeOddKey<4>(&m_rkeys[8], &m_rkeys[12]);

    // round 4
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[16], ksc);
    MakeOddKey<4>(&m_rkeys[16], &m_rkeys[20]);

    // round 6
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k+4, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[24], ksc);
    MakeOddKey<4>(&m_rkeys[24], &m_rkeys[28]);

    // round 8
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[32], ksc);
    MakeOddKey<4>(&m_rkeys[32], &m_rkeys[36]);

    // round 10
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k+4, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[40], ksc);
    MakeOddKey<4>(&m_rkeys[40], &m_rkeys[44]);

    // round 12
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[48], ksc);
    MakeOddKey<4>(&m_rkeys[48], &m_rkeys[52]);

    // round 14
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k+4, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[56], ksc);
    MakeOddKey<4>(&m_rkeys[56], &m_rkeys[60]);

    // round 16
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[64], ksc);
    MakeOddKey<4>(&m_rkeys[64], &m_rkeys[68]);

    // round 18
    constant <<= 1;
    AddConstant<4>(ks, ksc, constant);
    AddKey<4>(k+4, t2, ksc);
    G256(t2, t1, ksc);
    GL256(t1, &m_rkeys[72], ksc);

    if (!IsForwardTransformation())
    {
        IMC256(&m_rkeys[68]);
        IMC256(&m_rkeys[64]);
        IMC256(&m_rkeys[60]);
        IMC256(&m_rkeys[56]);
        IMC256(&m_rkeys[52]);
        IMC256(&m_rkeys[48]);
        IMC256(&m_rkeys[44]);
        IMC256(&m_rkeys[40]);
        IMC256(&m_rkeys[36]);
        IMC256(&m_rkeys[32]);
        IMC256(&m_rkeys[28]);
        IMC256(&m_rkeys[24]);
        IMC256(&m_rkeys[20]);
        IMC256(&m_rkeys[16]);
        IMC256(&m_rkeys[12]);
        IMC256(&m_rkeys[8]);
        IMC256(&m_rkeys[4]);
    }
}

void Kalyna512::Base::SetKey_88(const word64 key[8])
{
    word64 *ks = m_wspace+0, *ksc = m_wspace+8, *t1 = m_wspace+16;
    word64 *t2 = m_wspace+24, *k = m_wspace+32;

    memset(t1, 0, 8*8);
    t1[0] = (512 + 512 + 64) / 64;

    AddKey<8>(t1, t2, key);
    G512(t2, t1, key);
    GL512(t1, t2, key);
    G0512(t2, ks);

    word64 constant = W64LIT(0x0001000100010001);

    // round 0
    memcpy(k, key, 512 / 8);
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[0], ksc);
    MakeOddKey<8>(&m_rkeys[0], &m_rkeys[8]);

    // round 2
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[16], ksc);
    MakeOddKey<8>(&m_rkeys[16], &m_rkeys[24]);

    // round 4
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[32], ksc);
    MakeOddKey<8>(&m_rkeys[32], &m_rkeys[40]);

    // round 6
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[48], ksc);
    MakeOddKey<8>(&m_rkeys[48], &m_rkeys[56]);

    // round 8
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[64], ksc);
    MakeOddKey<8>(&m_rkeys[64], &m_rkeys[72]);

    // round 10
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[80], ksc);
    MakeOddKey<8>(&m_rkeys[80], &m_rkeys[88]);

    // round 12
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[96], ksc);
    MakeOddKey<8>(&m_rkeys[96], &m_rkeys[104]);

    // round 14
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[112], ksc);
    MakeOddKey<8>(&m_rkeys[112], &m_rkeys[120]);

    // round 16
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[128], ksc);
    MakeOddKey<8>(&m_rkeys[128], &m_rkeys[136]);

    // round 18
    SwapBlocks<8>(k);
    constant <<= 1;
    AddConstant<8>(ks, ksc, constant);
    AddKey<8>(k, t2, ksc);
    G512(t2, t1, ksc);
    GL512(t1, &m_rkeys[144], ksc);

    if (!IsForwardTransformation())
    {
        IMC512(&m_rkeys[136]); IMC512(&m_rkeys[128]); IMC512(&m_rkeys[120]); IMC512(&m_rkeys[112]);
        IMC512(&m_rkeys[104]); IMC512(&m_rkeys[ 96]); IMC512(&m_rkeys[ 88]); IMC512(&m_rkeys[ 80]);
        IMC512(&m_rkeys[ 72]); IMC512(&m_rkeys[ 64]); IMC512(&m_rkeys[ 56]); IMC512(&m_rkeys[ 48]);
        IMC512(&m_rkeys[ 40]); IMC512(&m_rkeys[ 32]); IMC512(&m_rkeys[ 24]); IMC512(&m_rkeys[ 16]);
        IMC512(&m_rkeys[  8]);
    }
}

// *********************** ProcessAndXorBlock specializations *********************** //

void Kalyna128::Base::ProcessBlock_22(const word64 inBlock[2], const word64 xorBlock[2], word64 outBlock[2]) const
{
    word64 *t1 = m_wspace+0, *t2 = m_wspace+2, *msg = m_wspace+4;

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(msg[0])(msg[1]);

    inBlock = msg;
    if (IsForwardTransformation())
    {
        AddKey<2>(inBlock, t1, m_rkeys);
        G128(t1, t2, &m_rkeys[2]);   // 1
        G128(t2, t1, &m_rkeys[4]);   // 2
        G128(t1, t2, &m_rkeys[6]);   // 3
        G128(t2, t1, &m_rkeys[8]);   // 4
        G128(t1, t2, &m_rkeys[10]);  // 5
        G128(t2, t1, &m_rkeys[12]);  // 6
        G128(t1, t2, &m_rkeys[14]);  // 7
        G128(t2, t1, &m_rkeys[16]);  // 8
        G128(t1, t2, &m_rkeys[18]);  // 9
        GL128(t2, t1, &m_rkeys[20]); // 10
    }
    else
    {
        SubKey<2>(inBlock, t1, &m_rkeys[20]);
        IMC128(t1);
        IG128(t1, t2, &m_rkeys[18]);
        IG128(t2, t1, &m_rkeys[16]);
        IG128(t1, t2, &m_rkeys[14]);
        IG128(t2, t1, &m_rkeys[12]);
        IG128(t1, t2, &m_rkeys[10]);
        IG128(t2, t1, &m_rkeys[8]);
        IG128(t1, t2, &m_rkeys[6]);
        IG128(t2, t1, &m_rkeys[4]);
        IG128(t1, t2, &m_rkeys[2]);
        IGL128(t2, t1, &m_rkeys[0]);
    }

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(t1[0])(t1[1]);
}

void Kalyna128::Base::ProcessBlock_24(const word64 inBlock[2], const word64 xorBlock[2], word64 outBlock[2]) const
{
    word64 *t1 = m_wspace+0, *t2 = m_wspace+2, *msg = m_wspace+4;

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(msg[0])(msg[1]);

    inBlock = msg;
    if (IsForwardTransformation())
    {
        AddKey<2>(inBlock, t1, m_rkeys);
        G128(t1, t2, &m_rkeys[ 2]); // 1
        G128(t2, t1, &m_rkeys[ 4]); // 2
        G128(t1, t2, &m_rkeys[ 6]); // 3
        G128(t2, t1, &m_rkeys[ 8]); // 4
        G128(t1, t2, &m_rkeys[10]); // 5
        G128(t2, t1, &m_rkeys[12]); // 6
        G128(t1, t2, &m_rkeys[14]); // 7
        G128(t2, t1, &m_rkeys[16]); // 8
        G128(t1, t2, &m_rkeys[18]); // 9
        G128(t2, t1, &m_rkeys[20]); // 10
        G128(t1, t2, &m_rkeys[22]); // 11
        G128(t2, t1, &m_rkeys[24]); // 12
        G128(t1, t2, &m_rkeys[26]); // 13
        GL128(t2, t1, &m_rkeys[28]); // 14
    }
    else
    {
        SubKey<2>(inBlock, t1, &m_rkeys[28]);
        IMC128(t1);
        IG128(t1, t2, &m_rkeys[26]);
        IG128(t2, t1, &m_rkeys[24]);
        IG128(t1, t2, &m_rkeys[22]);
        IG128(t2, t1, &m_rkeys[20]);
        IG128(t1, t2, &m_rkeys[18]);
        IG128(t2, t1, &m_rkeys[16]);
        IG128(t1, t2, &m_rkeys[14]);
        IG128(t2, t1, &m_rkeys[12]);
        IG128(t1, t2, &m_rkeys[10]);
        IG128(t2, t1, &m_rkeys[8]);
        IG128(t1, t2, &m_rkeys[6]);
        IG128(t2, t1, &m_rkeys[4]);
        IG128(t1, t2, &m_rkeys[2]);
        IGL128(t2, t1, &m_rkeys[0]);
    }

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(t1[0])(t1[1]);
}

void Kalyna256::Base::ProcessBlock_44(const word64 inBlock[4], const word64 xorBlock[4], word64 outBlock[4]) const
{
    word64 *t1 = m_wspace+0, *t2 = m_wspace+4, *msg = m_wspace+8;

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(msg[0])(msg[1])(msg[2])(msg[3]);

    inBlock = msg;
    if (IsForwardTransformation())
    {
        AddKey<4>(inBlock, t1, m_rkeys);
        G256(t1, t2, &m_rkeys[4]); // 1
        G256(t2, t1, &m_rkeys[8]); // 2
        G256(t1, t2, &m_rkeys[12]); // 3
        G256(t2, t1, &m_rkeys[16]); // 4
        G256(t1, t2, &m_rkeys[20]); // 5
        G256(t2, t1, &m_rkeys[24]); // 6
        G256(t1, t2, &m_rkeys[28]); // 7
        G256(t2, t1, &m_rkeys[32]); // 8
        G256(t1, t2, &m_rkeys[36]); // 9
        G256(t2, t1, &m_rkeys[40]); // 10
        G256(t1, t2, &m_rkeys[44]); // 11
        G256(t2, t1, &m_rkeys[48]); // 12
        G256(t1, t2, &m_rkeys[52]); // 13
        GL256(t2, t1, &m_rkeys[56]); // 14
    }
    else
    {
        SubKey<4>(inBlock, t1, &m_rkeys[56]);
        IMC256(t1);
        IG256(t1, t2, &m_rkeys[52]);
        IG256(t2, t1, &m_rkeys[48]);
        IG256(t1, t2, &m_rkeys[44]);
        IG256(t2, t1, &m_rkeys[40]);
        IG256(t1, t2, &m_rkeys[36]);
        IG256(t2, t1, &m_rkeys[32]);
        IG256(t1, t2, &m_rkeys[28]);
        IG256(t2, t1, &m_rkeys[24]);
        IG256(t1, t2, &m_rkeys[20]);
        IG256(t2, t1, &m_rkeys[16]);
        IG256(t1, t2, &m_rkeys[12]);
        IG256(t2, t1, &m_rkeys[8]);
        IG256(t1, t2, &m_rkeys[4]);
        IGL256(t2, t1, &m_rkeys[0]);
    }

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(t1[0])(t1[1])(t1[2])(t1[3]);
}

void Kalyna256::Base::ProcessBlock_48(const word64 inBlock[4], const word64 xorBlock[4], word64 outBlock[4]) const
{
    word64 *t1 = m_wspace+0, *t2 = m_wspace+4, *msg = m_wspace+8;

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(msg[0])(msg[1])(msg[2])(msg[3]);

    inBlock = msg;
    if (IsForwardTransformation())
    {
        AddKey<4>(inBlock, t1, m_rkeys);
        G256(t1, t2, &m_rkeys[4]); // 1
        G256(t2, t1, &m_rkeys[8]); // 2
        G256(t1, t2, &m_rkeys[12]); // 3
        G256(t2, t1, &m_rkeys[16]); // 4
        G256(t1, t2, &m_rkeys[20]); // 5
        G256(t2, t1, &m_rkeys[24]); // 6
        G256(t1, t2, &m_rkeys[28]); // 7
        G256(t2, t1, &m_rkeys[32]); // 8
        G256(t1, t2, &m_rkeys[36]); // 9
        G256(t2, t1, &m_rkeys[40]); // 10
        G256(t1, t2, &m_rkeys[44]); // 11
        G256(t2, t1, &m_rkeys[48]); // 12
        G256(t1, t2, &m_rkeys[52]); // 13
        G256(t2, t1, &m_rkeys[56]); // 14
        G256(t1, t2, &m_rkeys[60]); // 15
        G256(t2, t1, &m_rkeys[64]); // 16
        G256(t1, t2, &m_rkeys[68]); // 17
        GL256(t2, t1, &m_rkeys[72]); // 18
    }
    else
    {
        SubKey<4>(inBlock, t1, &m_rkeys[72]);
        IMC256(t1);
        IG256(t1, t2, &m_rkeys[68]);
        IG256(t2, t1, &m_rkeys[64]);
        IG256(t1, t2, &m_rkeys[60]);
        IG256(t2, t1, &m_rkeys[56]);
        IG256(t1, t2, &m_rkeys[52]);
        IG256(t2, t1, &m_rkeys[48]);
        IG256(t1, t2, &m_rkeys[44]);
        IG256(t2, t1, &m_rkeys[40]);
        IG256(t1, t2, &m_rkeys[36]);
        IG256(t2, t1, &m_rkeys[32]);
        IG256(t1, t2, &m_rkeys[28]);
        IG256(t2, t1, &m_rkeys[24]);
        IG256(t1, t2, &m_rkeys[20]);
        IG256(t2, t1, &m_rkeys[16]);
        IG256(t1, t2, &m_rkeys[12]);
        IG256(t2, t1, &m_rkeys[8]);
        IG256(t1, t2, &m_rkeys[4]);
        IGL256(t2, t1, &m_rkeys[0]);
    }

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(t1[0])(t1[1])(t1[2])(t1[3]);
}

void Kalyna512::Base::ProcessBlock_88(const word64 inBlock[8], const word64 xorBlock[8], word64 outBlock[8]) const
{
    word64 *t1 = m_wspace+0, *t2 = m_wspace+8, *msg = m_wspace+16;

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef GetBlock<word64, LittleEndian, false> InBlock;
    InBlock iblk(inBlock);
    iblk(msg[0])(msg[1])(msg[2])(msg[3])(msg[4])(msg[5])(msg[6])(msg[7]);

    inBlock = msg;
    if (IsForwardTransformation())
    {
        AddKey<8>(inBlock, t1, m_rkeys);
        G512(t1, t2, &m_rkeys[8]); // 1
        G512(t2, t1, &m_rkeys[16]); // 2
        G512(t1, t2, &m_rkeys[24]); // 3
        G512(t2, t1, &m_rkeys[32]); // 4
        G512(t1, t2, &m_rkeys[40]); // 5
        G512(t2, t1, &m_rkeys[48]); // 6
        G512(t1, t2, &m_rkeys[56]); // 7
        G512(t2, t1, &m_rkeys[64]); // 8
        G512(t1, t2, &m_rkeys[72]); // 9
        G512(t2, t1, &m_rkeys[80]); // 10
        G512(t1, t2, &m_rkeys[88]); // 11
        G512(t2, t1, &m_rkeys[96]); // 12
        G512(t1, t2, &m_rkeys[104]); // 13
        G512(t2, t1, &m_rkeys[112]); // 14
        G512(t1, t2, &m_rkeys[120]); // 15
        G512(t2, t1, &m_rkeys[128]); // 16
        G512(t1, t2, &m_rkeys[136]); // 17
        GL512(t2, t1, &m_rkeys[144]); // 18
    }
    else
    {
        SubKey<8>(inBlock, t1, &m_rkeys[144]);
        IMC512(t1);
        IG512(t1, t2, &m_rkeys[136]);
        IG512(t2, t1, &m_rkeys[128]);
        IG512(t1, t2, &m_rkeys[120]);
        IG512(t2, t1, &m_rkeys[112]);
        IG512(t1, t2, &m_rkeys[104]);
        IG512(t2, t1, &m_rkeys[96]);
        IG512(t1, t2, &m_rkeys[88]);
        IG512(t2, t1, &m_rkeys[80]);
        IG512(t1, t2, &m_rkeys[72]);
        IG512(t2, t1, &m_rkeys[64]);
        IG512(t1, t2, &m_rkeys[56]);
        IG512(t2, t1, &m_rkeys[48]);
        IG512(t1, t2, &m_rkeys[40]);
        IG512(t2, t1, &m_rkeys[32]);
        IG512(t1, t2, &m_rkeys[24]);
        IG512(t2, t1, &m_rkeys[16]);
        IG512(t1, t2, &m_rkeys[8]);
        IGL512(t2, t1, &m_rkeys[0]);
    }

    // Reverse bytes on BigEndian; Align pointer on LittleEndian
    typedef PutBlock<word64, LittleEndian, false> OutBlock;
    OutBlock oblk(xorBlock, outBlock);
    oblk(t1[0])(t1[1])(t1[2])(t1[3])(t1[4])(t1[5])(t1[6])(t1[7]);
}

// *********************** Library routines *********************** //

void Kalyna128::Base::UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    m_nb = static_cast<unsigned int>(16U / sizeof(word64));
    m_nk = static_cast<unsigned int>(keylen / sizeof(word64));

    switch (keylen)
    {
    case 16:  // 128
        m_kl = 16;
        m_mkey.New(2);
        m_rkeys.New(11*2);
        m_wspace.New(2*6);

        GetUserKey(LITTLE_ENDIAN_ORDER, m_mkey.begin(), 2, key, 16);
        SetKey_22(m_mkey.begin());
        break;
    case 32:  // 256
        m_kl = 32;
        m_mkey.New(4);
        m_rkeys.New(15*2);
        m_wspace.New(6*2+4);

        GetUserKey(LITTLE_ENDIAN_ORDER, m_mkey.begin(), 4, key, 32);
        SetKey_24(m_mkey.begin());
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }
}

void Kalyna128::Base::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Timing attack countermeasure. see comments in Rijndael for more details
    const int cacheLineSize = GetCacheLineSize();
    volatile word64 _u = 0;
    word64 u = _u;

    const byte* p = reinterpret_cast<const byte*>(KalynaTab::S);
    for (unsigned int i=0; i<256; i+=cacheLineSize)
        u ^= *reinterpret_cast<const word64*>(p+i);
    m_wspace[0] = u;

    switch ((m_nb << 8) | m_nk)
    {
    case (2 << 8) | 2:
        ProcessBlock_22(reinterpret_cast<const word64*>(inBlock),
            reinterpret_cast<const word64*>(xorBlock), reinterpret_cast<word64*>(outBlock));
        break;
    case (2 << 8) | 4:
        ProcessBlock_24(reinterpret_cast<const word64*>(inBlock),
            reinterpret_cast<const word64*>(xorBlock), reinterpret_cast<word64*>(outBlock));
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }
}

void Kalyna256::Base::UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    m_nb = static_cast<unsigned int>(32U / sizeof(word64));
    m_nk = static_cast<unsigned int>(keylen / sizeof(word64));

    switch (keylen)
    {
    case 32:  // 256
        m_kl = 32;
        m_mkey.New(4);
        m_rkeys.New(15*4);
        m_wspace.New(5*4);

        GetUserKey(LITTLE_ENDIAN_ORDER, m_mkey.begin(), 4, key, 32);
        SetKey_44(m_mkey.begin());
        break;
    case 64:  // 512
        m_kl = 64;
        m_mkey.New(8);
        m_rkeys.New(19*4);
        m_wspace.New(6*4+8);

        GetUserKey(LITTLE_ENDIAN_ORDER, m_mkey.begin(), 8, key, 64);
        SetKey_48(m_mkey.begin());
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }
}

void Kalyna256::Base::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Timing attack countermeasure. see comments in Rijndael for more details
    const int cacheLineSize = GetCacheLineSize();
    volatile word64 _u = 0;
    word64 u = _u;

    const byte* p = reinterpret_cast<const byte*>(KalynaTab::S);
    for (unsigned int i=0; i<256; i+=cacheLineSize)
        u ^= *reinterpret_cast<const word64*>(p+i);
    m_wspace[0] = u;

    switch ((m_nb << 8) | m_nk)
    {
    case (4 << 8) | 4:
        ProcessBlock_44(reinterpret_cast<const word64*>(inBlock),
            reinterpret_cast<const word64*>(xorBlock), reinterpret_cast<word64*>(outBlock));
        break;
    case (4 << 8) | 8:
        ProcessBlock_48(reinterpret_cast<const word64*>(inBlock),
            reinterpret_cast<const word64*>(xorBlock), reinterpret_cast<word64*>(outBlock));
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }
}

void Kalyna512::Base::UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    m_nb = static_cast<unsigned int>(64U / sizeof(word64));
    m_nk = static_cast<unsigned int>(keylen / sizeof(word64));

    switch (keylen)
    {
    case 64:  // 512
        m_kl = 64;
        m_nb = static_cast<unsigned int>(64U / sizeof(word64));
        m_nk = static_cast<unsigned int>(keylen / sizeof(word64));

        m_mkey.New(8);
        m_rkeys.New(19*8);
        m_wspace.New(5*8);

        GetUserKey(LITTLE_ENDIAN_ORDER, m_mkey.begin(), 8, key, 64);
        SetKey_88(m_mkey.begin());
        break;
    default:
        CRYPTOPP_ASSERT(0);
    }
}

void Kalyna512::Base::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
    // Timing attack countermeasure. see comments in Rijndael for more details
    const int cacheLineSize = GetCacheLineSize();
    volatile word64 _u = 0;
    word64 u = _u;

    const byte* p = reinterpret_cast<const byte*>(KalynaTab::S);
    for (unsigned int i=0; i<256; i+=cacheLineSize)
        u ^= *reinterpret_cast<const word64*>(p+i);
    m_wspace[0] = u;

    ProcessBlock_88(reinterpret_cast<const word64*>(inBlock),
        reinterpret_cast<const word64*>(xorBlock), reinterpret_cast<word64*>(outBlock));
}

NAMESPACE_END
