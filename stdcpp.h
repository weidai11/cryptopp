#ifndef CRYPTOPP_STDCPP_H
#define CRYPTOPP_STDCPP_H

#if _MSC_VER >= 1500
#define _DO_NOT_DECLARE_INTERLOCKED_INTRINSICS_IN_MEMORY
#include <intrin.h>
#endif

#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

// http://marshall.calepin.co/c-and-xcode-46.html.
// This include is needed so we can pickup _LIBCPP_VERSION, if needed.
#if defined(__APPLE__)
# include <ciso646>
#endif

#include <map>
#include <vector>
#include <string>
#include <limits>
#include <memory>
#include <exception>
#include <typeinfo>
#include <algorithm>
#include <functional>

// Rvalue references and std::move
#if (__cplusplus >= 201103L) || (_MSC_VER >= 1600)
# include <utility>
#endif

#ifdef CRYPTOPP_INCLUDE_VECTOR_CC
// workaround needed on Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21
#include <vector.cc>
#endif

// Handle alloca...
#if defined(CRYPTOPP_WIN32_AVAILABLE) || defined(__MINGW32__) || defined(__BORLANDC__)
#  include <malloc.h>
#elif defined(CRYPTOPP_BSD_AVAILABLE)
#  include <stdlib.h>
#else // CRYPTOPP_UNIX_AVAILABLE
#  include <alloca.h>
#endif

#ifdef _MSC_VER
#pragma warning(disable: 4231)	// re-disable this
#ifdef _CRTAPI1
#define CRYPTOPP_MSVCRT6
#endif
#endif

#endif
