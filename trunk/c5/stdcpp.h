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
