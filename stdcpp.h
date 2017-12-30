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
#include <algorithm>
#include <functional>
#include <utility>
#include <vector>
#include <limits>
#include <deque>
#include <list>
#include <map>
#include <new>

// http://connect.microsoft.com/VisualStudio/feedback/details/1600701/type-info-does-not-compile-with-has-exceptions-0
#if defined(_MSC_VER) && (_MSC_VER < 1900) && defined(_HAS_EXCEPTIONS) && (_HAS_EXCEPTIONS == 0)
namespace std {
  using ::type_info;
}
#endif

// make_unchecked_array_iterator
#if _MSC_VER >= 1600
#include <iterator>
#endif

#if defined(CRYPTOPP_CXX11_ATOMICS)
#include <atomic>
#endif

#if defined(CRYPTOPP_CXX11_SYNCHRONIZATION)
#include <mutex>
#endif

#if defined(CRYPTOPP_CXX11_RVALUES)
# include <utility>
#endif

#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <climits>
#include <cmath>

// uintptr_t and ptrdiff_t
#if (__cplusplus < 201103L) && (!defined(_MSC_VER) || (_MSC_VER >= 1700))
# include <stdint.h>
#elif defined(_MSC_VER) && (_MSC_VER < 1700)
# include <stddef.h>
#endif

// workaround needed on Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21
#ifdef CRYPTOPP_INCLUDE_VECTOR_CC
# include <vector.cc>
#endif

// C++Builder's standard library (Dinkumware) do not have C's global log() function
// https://github.com/weidai11/cryptopp/issues/520
#ifdef __BORLANDC__
using std::log;
#endif

#endif
