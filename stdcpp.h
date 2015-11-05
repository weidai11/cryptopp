#ifndef CRYPTOPP_STDCPP_H
#define CRYPTOPP_STDCPP_H

#if _MSC_VER >= 1500
#define _DO_NOT_DECLARE_INTERLOCKED_INTRINSICS_IN_MEMORY
#include <intrin.h>
#endif

#include <string>
#include <memory>
#include <exception>
#include <typeinfo>
#include <functional>
#include <utility>
#include <vector>
#include <deque>
#include <limits>
#include <map>
#include <new>

// GCC began indirectly including wmmintrin.h via <algorithm>. Or, maybe it was
//   doing it all along, but we did not experience issues.
// The net result is a number of C++11 compile failures on the _mm_* intrinsics
//   from cpu.h. The _mm_* collisions are on AES and PCLMUL intrinsics (they
//   are the only intrinsics in the file).
// TODO: perhaps use a namespace to resolve the symbol collisions. That
//   needs to occur when symbols can change, which is a major bump.
#if defined(__GNUC__) && defined(CRYPTOPP_CXX11) && (CRYPTOPP_GCC_VERSION >= 40300)
# pragma push_macro("_WMMINTRIN_H_INCLUDED")
# undef  _WMMINTRIN_H_INCLUDED
# define _WMMINTRIN_H_INCLUDED
# include <algorithm>
# pragma pop_macro("_WMMINTRIN_H_INCLUDED")
#else
# include <algorithm>
#endif

#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <climits>
#include <cassert>

#ifdef CRYPTOPP_INCLUDE_VECTOR_CC
// workaround needed on Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21
#include <vector.cc>
#endif

// for alloca
#if defined(CRYPTOPP_BSD_AVAILABLE)
#include <stdlib.h>
#elif defined(CRYPTOPP_UNIX_AVAILABLE) || defined(__sun)
#include <alloca.h>
#elif defined(CRYPTOPP_WIN32_AVAILABLE) || defined(__MINGW32__) || defined(__BORLANDC__) 
#include <malloc.h>
#endif

#ifdef _MSC_VER
#pragma warning(disable: 4231)	// re-disable this
#ifdef _CRTAPI1
#define CRYPTOPP_MSVCRT6
#endif
#endif

#endif
