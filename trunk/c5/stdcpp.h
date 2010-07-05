#ifndef CRYPTOPP_STDCPP_H
#define CRYPTOPP_STDCPP_H

#include <stddef.h>
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
#include <string>
#include <exception>
#include <typeinfo>
#include <algorithm>
#include <map>
#include <vector>

#ifdef __SUNPRO_CC
// workaround needed on Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21
#include <vector.cc>
#endif

// for alloca
#ifdef __sun
#include <alloca.h>
#elif defined(__MINGW32__)
#include <malloc.h>
#endif

#ifdef _MSC_VER
#pragma warning(disable: 4231)	// re-disable this
#ifdef _CRTAPI1
#define CRYPTOPP_MSVCRT6
#endif
#endif

#endif
