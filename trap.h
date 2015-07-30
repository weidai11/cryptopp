// trap.h - written and placed in public domain by Jeffrey Walton.
//          Copyright assigned to Crypto++ project

#ifndef CRYPTOPP_TRAP_H
#define CRYPTOPP_TRAP_H

#ifndef NDEBUG
#ifdef CRYPTOPP_UNIX_AVAILABLE
# include <iostream>
# include <sstream>
# include <signal.h>
#endif // CRYPTOPP_UNIX_AVAILABLE
#endif // NDEBUG

#include <cassert>

// ************** run-time assertion ***************

// See test.cpp and DebugTrapHandler for code to install a NULL
// signal handler for SIGTRAP. The handler installs itself during
// initialization of the test program.

// Linux and Unix
#if !defined(NDEBUG) && defined(CRYPTOPP_UNIX_AVAILABLE)
#  define CRYPTOPP_ASSERT(exp) {                                  \
    if (!(exp)) {                                                  \
      std::ostringstream oss;                                     \
      oss << "Assertion failed: " << (char*)(__FILE__) << "("     \
          << (int)(__LINE__) << "): " << (char*)(__func__)        \
          << std::endl;                                           \
      std::cerr << oss.str();                                     \
      raise(SIGTRAP);                                             \
    }                                                             \
  }
// Fallback to original behavior (including for NDEBUG)
#else
#  define CRYPTOPP_ASSERT(exp) assert(exp)
#endif // DEBUG and CRYPTOPP_UNIX_AVAILABLE

#endif // CRYPTOPP_TRAP_H

