
###########################################################
#####        System Attributes and Programs           #####
###########################################################

# https://www.gnu.org/software/make/manual/make.html#Makefile-Conventions
# and https://www.gnu.org/prep/standards/standards.html

SHELL = /bin/sh

# If needed
TMPDIR ?= /tmp
# Used for ARMv7 and NEON.
FP_ABI ?= hard

# Command and arguments
AR ?= ar
ARFLAGS ?= -cr # ar needs the dash on OpenBSD
RANLIB ?= ranlib

CP ?= cp
MV ?= mv
RM ?= rm -f
CHMOD ?= chmod
MKDIR ?= mkdir -p

LN ?= ln -sf
LDCONF ?= /sbin/ldconfig -n

INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

# Solaris provides a non-Posix grep at /usr/bin
ifneq ($(wildcard /usr/xpg4/bin),)
  GREP ?= /usr/xpg4/bin/grep
else
  GREP ?= grep
endif

# Attempt to determine host machine, fallback to "this" machine.
#   The host machine is the one the package runs on. Most people
#   call this the "target", but not Autotools.
HOSTX := $(shell $(CXX) $(CXXFLAGS) -dumpmachine 2>/dev/null | cut -f 1 -d '-')
ifeq ($(HOSTX),)
  HOSTX := $(shell uname -m 2>/dev/null)
endif

IS_X86 := $(shell echo "$(HOSTX)" | $(GREP) -v "64" | $(GREP) -i -c -E 'i.86|x86|i86')
IS_X64 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E '_64|d64')
IS_PPC32 := $(shell echo "$(HOSTX)" | $(GREP) -v "64" | $(GREP) -i -c -E 'ppc|power')
IS_PPC64 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E 'ppc64|power64')
IS_ARM32 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E 'arm|armhf|arm7l|eabihf')
IS_ARMV8 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E 'aarch32|aarch64')
IS_SPARC32 := $(shell echo "$(HOSTX)" | $(GREP) -v "64" | $(GREP) -i -c -E 'sun|sparc')
IS_SPARC64 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E 'sun|sparc64')

IS_NEON := $(shell $(CXX) $(CXXFLAGS) -dumpmachine 2>/dev/null | $(GREP) -i -c -E 'armv7|armhf|arm7l|eabihf|armv8|aarch32|aarch64')

SYSTEMX := $(shell $(CXX) $(CXXFLAGS) -dumpmachine 2>/dev/null)
IS_LINUX := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "Linux")
IS_MINGW := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "MinGW")
IS_CYGWIN := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "Cygwin")
IS_DARWIN := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "Darwin")
IS_NETBSD := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "NetBSD")

UNAMEX := $(shell uname -s 2>&1)
IS_AIX := $(shell echo "$(UNAMEX)" | $(GREP) -i -c "aix")
IS_SUN := $(shell echo "$(UNAMEX)" | $(GREP) -i -c "SunOS")

SUN_COMPILER := $(shell $(CXX) -V 2>&1 | $(GREP) -i -c -E 'CC: (Sun|Studio)')
GCC_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -v -E '(llvm|clang)' | $(GREP) -i -c -E '(gcc|g\+\+)')
XLC_COMPILER := $(shell $(CXX) -qversion 2>/dev/null |$(GREP) -i -c "IBM XL")
CLANG_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -i -c -E '(llvm|clang)')
INTEL_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -i -c '\(icc\)')

# Various Port compilers on OS X
MACPORTS_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -i -c "macports")
HOMEBREW_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -i -c "homebrew")
ifeq ($(IS_DARWIN),1)
  ifneq ($(MACPORTS_COMPILER)$(HOMEBREW_COMPILER),00)
    OSXPORT_COMPILER := 1
  endif
endif

# Sun Studio 12.0 provides SunCC 0x0510; and Sun Studio 12.3 provides SunCC 0x0512
SUNCC_VERSION := $(subst `,',$(shell $(CXX) -V 2>&1))
SUNCC_510_OR_LATER := $(shell echo "$(SUNCC_VERSION)" | $(GREP) -i -c -E "CC: (Sun|Studio) .* (5\.1[0-9]|5\.[2-9]|6\.)")
SUNCC_511_OR_LATER := $(shell echo "$(SUNCC_VERSION)" | $(GREP) -i -c -E "CC: (Sun|Studio) .* (5\.1[1-9]|5\.[2-9]|6\.)")
SUNCC_512_OR_LATER := $(shell echo "$(SUNCC_VERSION)" | $(GREP) -i -c -E "CC: (Sun|Studio) .* (5\.1[2-9]|5\.[2-9]|6\.)")
SUNCC_513_OR_LATER := $(shell echo "$(SUNCC_VERSION)" | $(GREP) -i -c -E "CC: (Sun|Studio) .* (5\.1[3-9]|5\.[2-9]|6\.)")

# Enable shared object versioning for Linux and Solaris
HAS_SOLIB_VERSION ?= 0
ifneq ($(IS_LINUX)$(IS_SUN),00)
HAS_SOLIB_VERSION := 1
endif

# Newlib needs _XOPEN_SOURCE=600 for signals
HAS_NEWLIB := $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c "__NEWLIB__")

# Formely adhoc.cpp was created from adhoc.cpp.proto when needed.
# This is now needed because ISA tests are performed using adhoc.cpp.
ifeq ($(wildcard adhoc.cpp),)
$(shell cp adhoc.cpp.proto adhoc.cpp)
endif

# Fixup AIX
ifeq ($(IS_AIX),1)
  BITNESS=$(shell getconf KERNEL_BITMODE)
  ifeq ($(BITNESS),64)
    IS_PPC64=1
  else
    IS_PPC32=1
  endif
endif

###########################################################
#####                General Variables                #####
###########################################################

# Base CXXFLAGS used if the user did not specify them
ifeq ($(SUN_COMPILER),1)
  CXXFLAGS ?= -DNDEBUG -g -xO3
else
  CXXFLAGS ?= -DNDEBUG -g2 -O3
endif

# On ARM we may compile aes-armv4.S though the CC compiler
ifeq ($(GCC_COMPILER),1)
  CC=gcc
else ifeq ($(CLANG_COMPILER),1)
  CC=clang
endif

# Default prefix for make install
ifeq ($(PREFIX),)
PREFIX = /usr/local
endif

# http://www.gnu.org/prep/standards/html_node/Directory-Variables.html
ifeq ($(DATADIR),)
DATADIR := $(PREFIX)/share
endif
ifeq ($(LIBDIR),)
LIBDIR := $(PREFIX)/lib
endif
ifeq ($(BINDIR),)
BINDIR := $(PREFIX)/bin
endif
ifeq ($(INCLUDEDIR),)
INCLUDEDIR := $(PREFIX)/include
endif

# Fix CXX on Cygwin 1.1.4
ifeq ($(CXX),gcc)
CXX := g++
endif

# We honor ARFLAGS, but the "v" option used by default causes a noisy make
ifeq ($(ARFLAGS),rv)
ARFLAGS = r
endif

ifneq ($(HAS_NEWLIB),0)
 ifeq ($(findstring -D_XOPEN_SOURCE,$(CXXFLAGS)),)
   CXXFLAGS += -D_XOPEN_SOURCE=600
 endif
endif

# Clang integrated assembler will be used with -Wa,-q
CLANG_INTEGRATED_ASSEMBLER ?= 0

# original MinGW targets Win2k by default, but lacks proper Win2k support
# if target Windows version is not specified, use Windows XP instead
ifeq ($(IS_MINGW),1)
ifeq ($(findstring -D_WIN32_WINNT,$(CXXFLAGS)),)
ifeq ($(findstring -D_WIN32_WINDOWS,$(CXXFLAGS)),)
ifeq ($(findstring -DWINVER,$(CXXFLAGS)),)
ifeq ($(findstring -DNTDDI_VERSION,$(CXXFLAGS)),)
  CXXFLAGS += -D_WIN32_WINNT=0x0501
endif # NTDDI_VERSION
endif # WINVER
endif # _WIN32_WINDOWS
endif # _WIN32_WINNT
endif # IS_MINGW

###########################################################
#####               X86/X32/X64 Options               #####
###########################################################

ifneq ($(IS_X86)$(IS_X64),00)

# Fixup. Clang reports an error rather than "LLVM assembler" or similar.
ifneq ($(OSXPORT_COMPILER),1)
  HAVE_GAS := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c "GNU assembler")
endif

ifneq ($(GCC_COMPILER),0)
  IS_GCC_29 := $(shell $(CXX) -v 2>&1 | $(GREP) -i -c -E gcc-9[0-9][0-9])
  GCC42_OR_LATER := $(shell $(CXX) -v 2>&1 | $(GREP) -i -c -E "gcc version (4\.[2-9]|[5-9]\.)")
  GCC46_OR_LATER := $(shell $(CXX) -v 2>&1 | $(GREP) -i -c -E "gcc version (4\.[6-9]|[5-9]\.)")
endif

ifneq ($(HAVE_GAS),0)
  GAS210_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.[1-9][0-9]|[3-9])")
  GAS217_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.1[7-9]|2\.[2-9]|[3-9])")
  GAS218_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.1[8-9]|2\.[2-9]|[3-9])")
  GAS219_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.19|2\.[2-9]|[3-9])")
  GAS224_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.2[4-9]|2\.[3-9]|[3-9])")
endif

ICC111_OR_LATER := $(shell $(CXX) --version 2>&1 | $(GREP) -c -E "\(ICC\) ([2-9][0-9]|1[2-9]|11\.[1-9])")

# .intel_syntax wasn't supported until GNU assembler 2.10
ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
ifeq ($(HAVE_GAS)$(GAS210_OR_LATER),10)
CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
else
ifeq ($(HAVE_GAS)$(GAS217_OR_LATER),10)
CXXFLAGS += -DCRYPTOPP_DISABLE_SSSE3
else
ifeq ($(HAVE_GAS)$(GAS218_OR_LATER),10)
CXXFLAGS += -DCRYPTOPP_DISABLE_SSE4
else
ifeq ($(HAVE_GAS)$(GAS219_OR_LATER),10)
CXXFLAGS += -DCRYPTOPP_DISABLE_AESNI
else
ifeq ($(HAVE_GAS)$(GAS224_OR_LATER),10)
CXXFLAGS += -DCRYPTOPP_DISABLE_SHANI

endif  # -DCRYPTOPP_DISABLE_SHANI
endif  # -DCRYPTOPP_DISABLE_AESNI
endif  # -DCRYPTOPP_DISABLE_SSE4
endif  # -DCRYPTOPP_DISABLE_SSSE3
endif  # -DCRYPTOPP_DISABLE_ASM
endif  # CXXFLAGS

# SSE2 is a core feature of x86_64
ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
  ifeq ($(IS_X86),1)
    SSE_FLAG = -msse2
  endif
endif
ifeq ($(findstring -DCRYPTOPP_DISABLE_SSSE3,$(CXXFLAGS)),)
  HAVE_SSSE3 = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -mssse3 -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __SSSE3__)
  ifeq ($(HAVE_SSSE3),1)
    ARIA_FLAG = -mssse3
    CHAM_FLAG = -mssse3
    LEA_FLAG = -mssse3
    SSSE3_FLAG = -mssse3
    SIMECK_FLAG = -mssse3
    SIMON64_FLAG = -mssse3
    SIMON128_FLAG = -mssse3
    SPECK64_FLAG = -mssse3
    SPECK128_FLAG = -mssse3
  endif
ifeq ($(findstring -DCRYPTOPP_DISABLE_SSE4,$(CXXFLAGS)),)
  HAVE_SSE4 = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -msse4.1 -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __SSE4_1__)
  ifeq ($(HAVE_SSE4),1)
    BLAKE2_FLAG = -msse4.1
    SIMON64_FLAG = -msse4.1
    SPECK64_FLAG = -msse4.1
  endif
  HAVE_SSE4 = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -msse4.2 -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __SSE4_2__)
  ifeq ($(HAVE_SSE4),1)
    CRC_FLAG = -msse4.2
  endif
ifeq ($(findstring -DCRYPTOPP_DISABLE_AESNI,$(CXXFLAGS)),)
  HAVE_CLMUL = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -mssse3 -mpclmul -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __PCLMUL__ )
  ifeq ($(HAVE_CLMUL),1)
    GCM_FLAG = -mssse3 -mpclmul
  endif
  HAVE_AES = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -msse4.1 -maes -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __AES__)
  ifeq ($(HAVE_AES),1)
    AES_FLAG = -msse4.1 -maes
    SM4_FLAG = -mssse3 -maes
  endif
ifeq ($(findstring -DCRYPTOPP_DISABLE_SHANI,$(CXXFLAGS)),)
  HAVE_SHA = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -msse4.2 -msha -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __SHA__)
  ifeq ($(HAVE_SHA),1)
    SHA_FLAG = -msse4.2 -msha
  endif
endif  # -DCRYPTOPP_DISABLE_SHANI
endif  # -DCRYPTOPP_DISABLE_AESNI
endif  # -DCRYPTOPP_DISABLE_SSE4
endif  # -DCRYPTOPP_DISABLE_SSSE3

# Begin SunCC
ifeq ($(SUN_COMPILER),1)
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=sse2 -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal")
  ifeq ($(COUNT),0)
    AES_FLAG = -xarch=sse2 -D__SSE2__=1
    GCM_FLAG = -xarch=sse2 -D__SSE2__=1
    SHA_FLAG = -xarch=sse2 -D__SSE2__=1
    LDFLAGS += -xarch=sse2
  endif
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=ssse3 -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal")
  ifeq ($(COUNT),0)
    SSSE3_FLAG = -xarch=ssse3 -D__SSSE3__=1
    ARIA_FLAG = -xarch=ssse3 -D__SSSE3__=1
    CHAM_FLAG = -xarch=ssse3 -D__SSSE3__=1
    LEA_FLAG = -xarch=ssse3 -D__SSSE3__=1
    SIMECK_FLAG = -xarch=ssse3 -D__SSSE3__=1
    SIMON64_FLAG = -xarch=ssse3 -D__SSSE3__=1
    SIMON128_FLAG = -xarch=ssse3 -D__SSSE3__=1
    SPECK64_FLAG = -xarch=ssse3 -D__SSSE3__=1
    SPECK128_FLAG = -xarch=ssse3 -D__SSSE3__=1
    LDFLAGS += -xarch=ssse3
  endif
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=sse4_1 -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal")
  ifeq ($(COUNT),0)
    BLAKE2_FLAG = -xarch=sse4_1 -D__SSE4_1__=1
    SIMON64_FLAG = -xarch=sse4_1 -D__SSE4_1__=1
    SPECK64_FLAG = -xarch=sse4_1 -D__SSE4_1__=1
    LDFLAGS += -xarch=sse4_1
  endif
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=sse4_2 -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal")
  ifeq ($(COUNT),0)
    CRC_FLAG = -xarch=sse4_2 -D__SSE4_2__=1
    LDFLAGS += -xarch=sse4_2
  endif
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=aes -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal")
  ifeq ($(COUNT),0)
    GCM_FLAG = -xarch=aes -D__PCLMUL__=1
    AES_FLAG = -xarch=aes -D__AES__=1
    SM4_FLAG = -xarch=aes -D__AES__=1
    LDFLAGS += -xarch=aes
  endif
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=sha -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal")
  ifeq ($(COUNT),0)
    SHA_FLAG = -xarch=sha -D__SHA__=1
    LDFLAGS += -xarch=sha
  endif
endif
# End SunCC

ifneq ($(INTEL_COMPILER),0)
  CXXFLAGS += -wd68 -wd186 -wd279 -wd327 -wd161 -wd3180
  ifeq ($(ICC111_OR_LATER),0)
    # "internal error: backend signals" occurs on some x86 inline assembly with ICC 9 and some x64 inline assembly with ICC 11.0
    # if you want to use Crypto++'s assembly code with ICC, try enabling it on individual files
    CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
  endif
endif

# Tell MacPorts and Homebrew GCC to use Clang integrated assembler
#   http://github.com/weidai11/cryptopp/issues/190
ifeq ($(GCC_COMPILER)$(OSXPORT_COMPILER),11)
  ifeq ($(findstring -Wa,-q,$(CXXFLAGS)),)
    CXXFLAGS += -Wa,-q
  endif
  ifeq ($(findstring -DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER,$(CXXFLAGS)),)
    CLANG_INTEGRATED_ASSEMBLER := 1
    CXXFLAGS += -DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER=1
  endif
endif

# Allow use of "/" operator for GNU Assembler.
#   http://sourceware.org/bugzilla/show_bug.cgi?id=4572
ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
ifeq ($(IS_SUN)$(GCC_COMPILER),11)
CXXFLAGS += -Wa,--divide
endif
endif

else

###########################################################
#####                 Not X86/X32/X64                 #####
###########################################################

ifeq ($(IS_NEON),1)
  HAVE_NEON = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c -E '\<__ARM_NEON\>')
  ifeq ($(HAVE_NEON),1)
    NEON_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    ARIA_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    AES_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    CRC_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    GCM_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    BLAKE2_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    CHAM_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    LEA_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    SHA_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    SIMECK_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    SIMON64_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    SIMON128_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    SPECK64_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    SPECK128_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    SM4_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
  endif
endif

ifeq ($(IS_ARMV8),1)
  HAVE_NEON = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -march=armv8-a -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __ARM_NEON)
  ifeq ($(HAVE_NEON),1)
    ARIA_FLAG = -march=armv8-a
    BLAKE2_FLAG = -march=armv8-a
    CHAM_FLAG = -march=armv8-a
    LEA_FLAG = -march=armv8-a
    NEON_FLAG = -march=armv8-a
    SIMECK_FLAG = -march=armv8-a
    SIMON64_FLAG = -march=armv8-a
    SIMON128_FLAG = -march=armv8-a
    SPECK64_FLAG = -march=armv8-a
    SPECK128_FLAG = -march=armv8-a
    SM4_FLAG = -march=armv8-a
  endif
  HAVE_CRC = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -march=armv8-a+crc -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __ARM_FEATURE_CRC32)
  ifeq ($(HAVE_CRC),1)
    CRC_FLAG = -march=armv8-a+crc
  endif
  HAVE_CRYPTO = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -march=armv8-a+crypto -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __ARM_FEATURE_CRYPTO)
  ifeq ($(HAVE_CRYPTO),1)
    AES_FLAG = -march=armv8-a+crypto
    GCM_FLAG = -march=armv8-a+crypto
    SHA_FLAG = -march=armv8-a+crypto
  endif
  HAVE_CRYPTO = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -march=armv8.4-a+crypto -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c __ARM_FEATURE_CRYPTO)
  ifeq ($(HAVE_CRYPTO),1)
    SM4_FLAG = -march=armv8.4-a+crypto
  endif
endif

# PowerPC and PowerPC-64. Altivec is available with POWER4 with GCC and
# POWER6 with XLC. The tests below are crafted for IBM XLC and the LLVM
# front-end. XLC/LLVM only supplies POWER8 so we have to set the flags for
# XLC/LLVM to POWER8. I've got a feeling LLVM is going to cause trouble.
ifneq ($(IS_PPC32)$(IS_PPC64),00)
  HAVE_POWER8 = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -mcpu=power8 -maltivec -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c -E '_ARCH_PWR8|_ARCH_PWR9|__CRYPTO')
  ifneq ($(HAVE_POWER8),0)
    POWER8_FLAG = -mcpu=power8 -maltivec
    AES_FLAG = $(POWER8_FLAG)
    GCM_FLAG = $(POWER8_FLAG)
    SHA_FLAG = $(POWER8_FLAG)
    SM4_FLAG = $(POWER8_FLAG)
    SIMON64_FLAG = $(POWER8_FLAG)
    SIMON128_FLAG = $(POWER8_FLAG)
    SPECK64_FLAG = $(POWER8_FLAG)
    SPECK128_FLAG = $(POWER8_FLAG)
  endif

  # GCC and some compatibles
  HAVE_POWER7 = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -mcpu=power7 -maltivec -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c '_ARCH_PWR7')
  ifneq ($(HAVE_POWER7),0)
    POWER7_FLAG = -mcpu=power7 -maltivec
    ARIA_FLAG = $(POWER7_FLAG)
    BLAKE2_FLAG = $(POWER7_FLAG)
    CHAM_FLAG = $(POWER7_FLAG)
    LEA_FLAG = $(POWER7_FLAG)
    SIMECK_FLAG = $(POWER7_FLAG)
    SIMON64_FLAG = $(POWER7_FLAG)
    SPECK64_FLAG = $(POWER7_FLAG)
  endif

  # GCC and some compatibles
  HAVE_ALTIVEC = $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -mcpu=power4 -maltivec -dM -E adhoc.cpp 2>&1 | $(GREP) -i -c '__ALTIVEC__')
  ifneq ($(HAVE_ALTIVEC),0)
    ALTIVEC_FLAG = -mcpu=power4 -maltivec
  endif

  # IBM XL C/C++
  HAVE_POWER8 = $(shell $(CXX) $(CXXFLAGS) -qshowmacros -qarch=pwr8 -qaltivec -E adhoc.cpp 2>&1 | $(GREP) -i -c -E '_ARCH_PWR8|_ARCH_PWR9|__CRYPTO')
  ifneq ($(HAVE_POWER8),0)
    POWER8_FLAG = -qarch=pwr8 -qaltivec
    AES_FLAG = $(POWER8_FLAG)
    GCM_FLAG = $(POWER8_FLAG)
    SHA_FLAG = $(POWER8_FLAG)
    SM4_FLAG = $(POWER8_FLAG)
    SIMON64_FLAG = $(POWER8_FLAG)
    SIMON128_FLAG = $(POWER8_FLAG)
    SPECK64_FLAG = $(POWER8_FLAG)
    SPECK128_FLAG = $(POWER8_FLAG)
  endif

  # IBM XL C/C++
  HAVE_POWER7 = $(shell $(CXX) $(CXXFLAGS) -qshowmacros -qarch=pwr7 -qaltivec -E adhoc.cpp 2>&1 | $(GREP) -i -c -E '_ARCH_PWR7')
  ifneq ($(HAVE_POWER7),0)
    POWER7_FLAG = -qarch=pwr7 -qaltivec
    ARIA_FLAG = $(POWER7_FLAG)
    BLAKE2_FLAG = $(POWER7_FLAG)
    CHAM_FLAG = $(POWER7_FLAG)
    LEA_FLAG = $(POWER7_FLAG)
    SIMECK_FLAG = $(POWER7_FLAG)
    SIMON64_FLAG = $(POWER7_FLAG)
    SPECK64_FLAG = $(POWER7_FLAG)
  endif

  # IBM XL C/C++
  HAVE_ALTIVEC = $(shell $(CXX) $(CXXFLAGS) -qshowmacros -qarch=pwr6 -qaltivec -E adhoc.cpp 2>&1 | $(GREP) -i -c '__ALTIVEC__')
  ifneq ($(HAVE_ALTIVEC),0)
    ALTIVEC_FLAG = -qarch=pwr6 -qaltivec
  endif

  # LLVM front-ends only provide Power8. It really jambs us up
  # for ppc-simd.cpp which needs ALTIVEC/POWER4. We have similar
  # problems {lea|cham|simon|speck|...}-simd.cpp and POWER7.
  HAVE_LLVM = $(shell $(CXX) $(CXXFLAGS) -qshowmacros -E adhoc.cpp 2>&1 | $(GREP) -i -c '__llvm__')
  ifneq ($(HAVE_LLVM),0)
    POWER7_FLAG = $(POWER8_FLAG)
    ARIA_FLAG = $(POWER8_FLAG)
    BLAKE2_FLAG = $(POWER8_FLAG)
    CHAM_FLAG = $(POWER8_FLAG)
    LEA_FLAG = $(POWER8_FLAG)
    SIMECK_FLAG = $(POWER8_FLAG)
    SIMON64_FLAG = $(POWER8_FLAG)
    SIMON128_FLAG = $(POWER8_FLAG)
    SPECK64_FLAG = $(POWER8_FLAG)
    SPECK128_FLAG = $(POWER8_FLAG)
    ALTIVEC_FLAG = $(POWER8_FLAG)
  endif

  ifeq ($(ALTIVEC_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_ALTIVEC
  endif
  ifeq ($(POWER7_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_POWER7
  endif
  ifeq ($(POWER8_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_POWER8
  endif
endif

# IBM XL C/C++ compiler
ifeq ($(XLC_COMPILER),1)
  # More stupid LLVM games, with Clang pretending to be a different compiler.
  # https://lists.tetaneutral.net/pipermail/cfarm-users/2018-July/000331.html
  HAVE_COMPAT = $(shell $(CXX) $(CXXFLAGS) -qxlcompatmacros adhoc.cpp 2>&1 | $(GREP) -i -c -E 'illegal|not supported')
  ifeq ($(HAVE_COMPAT),0)
    CXXFLAGS += -qxlcompatmacros
  endif
  # http://www-01.ibm.com/support/docview.wss?uid=swg21007500
  ifeq ($(findstring -qrtti,$(CXXFLAGS)),)
    CXXFLAGS += -qrtti
  endif
endif

endif  # X86, X64, ARM32, ARM64, PPC32, PPC64, etc

###########################################################
#####                      Common                     #####
###########################################################

# Add -fPIC for targets *except* X86, X32, Cygwin or MinGW
ifeq ($(IS_X86)$(IS_CYGWIN)$(IS_MINGW),000)
 ifeq ($(findstring -fPIC,$(CXXFLAGS)),)
   CXXFLAGS += -fPIC
 endif
endif

# Use -pthread whenever it is available. See http://www.hpl.hp.com/techreports/2004/HPL-2004-209.pdf
#   http://stackoverflow.com/questions/2127797/gcc-significance-of-pthread-flag-when-compiling
# BAD_PTHREAD and HAVE_PTHREAD is due to GCC on Solaris. GCC rejects -pthread but defines
#   39 *_PTHREAD_* related macros. Then we pickup the macros and enable the option...
BAD_PTHREAD = $(shell $(CXX) $(CXXFLAGS) -pthread -c adhoc.cpp 2>&1 | $(GREP) -i -c -E 'warning|incorrect|illegal|unrecognized')
HAVE_PTHREAD = $(shell $(CXX) $(CXXFLAGS) -pthread -dM -E adhoc.cpp 2>/dev/null | $(GREP) -i -c 'PTHREAD')
ifeq ($(BAD_PTHREAD),0)
ifneq ($(HAVE_PTHREAD),0)
  CXXFLAGS += -pthread
endif # CXXFLAGS
endif # CXXFLAGS

# Remove -fPIC if present. SunCC use -KPIC, and needs the larger GOT table
# https://docs.oracle.com/cd/E19205-01/819-5267/bkbaq/index.html
ifeq ($(SUN_COMPILER),1)
  CXXFLAGS := $(subst -fPIC,-KPIC,$(CXXFLAGS))
  CXXFLAGS := $(subst -fpic,-KPIC,$(CXXFLAGS))
endif

# For SunOS and SunCC Sun wants folks to use -xregs=no%appl
# https://docs.oracle.com/cd/E18659_01/html/821-1383/bkamt.html
ifeq ($(IS_SUN)$(SUN_COMPILER),11)
  ifneq ($(IS_SPARC32)$(IS_SPARC64),00)
    ifeq ($(findstring -xregs=no%appl,$(CXXFLAGS)),)
      CXXFLAGS += -xregs=no%appl
    endif  # -xregs
  endif  # Sparc
endif  # SunOS

# Remove -fPIC if present. IBM XL C/C++ use -qpic
ifeq ($(XLC_COMPILER),1)
  CXXFLAGS := $(subst -fPIC,-qpic,$(CXXFLAGS))
endif

# Add -pipe for everything except IBM XL C/C++, SunCC and ARM.
# Allow ARM-64 because they seems to have >1 GB of memory
ifeq ($(XLC_COMPILER)$(SUN_COMPILER)$(IS_ARM32),000)
  ifeq ($(findstring -save-temps,$(CXXFLAGS)),)
    CXXFLAGS += -pipe
  endif
endif

# For SunOS, create a Mapfile that allows our object files
# to contain additional bits (like SSE4 and AES on old Xeon)
# http://www.oracle.com/technetwork/server-storage/solaris/hwcap-modification-139536.html
ifeq ($(IS_SUN)$(SUN_COMPILER),11)
  ifneq ($(IS_X86)$(IS_X64),00)
    ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
      LDFLAGS += -M cryptopp.mapfile
    endif  # No CRYPTOPP_DISABLE_ASM
  endif  # X86/X32/X64
endif  # SunOS

ifneq ($(IS_MINGW),0)
  LDLIBS += -lws2_32
endif

ifneq ($(IS_SUN),0)
  LDLIBS += -lnsl -lsocket
endif

ifeq ($(IS_LINUX),1)
  ifeq ($(findstring -fopenmp,$(CXXFLAGS)),-fopenmp)
    ifeq ($(findstring -lgomp,$(LDLIBS)),)
      LDLIBS += -lgomp
    endif # LDLIBS
  endif # OpenMP
endif # IS_LINUX

# libc++ is LLVM's standard C++ library. If we add libc++
# here then all user programs must use it too. The open
# question is, which choice is easier on users?
ifneq ($(IS_DARWIN),0)
  CXX ?= c++
  # CXXFLAGS += -stdlib=libc++
  AR = libtool
  ARFLAGS = -static -o
endif

# Add -errtags=yes to get the name for a warning suppression
ifneq ($(SUN_COMPILER),0)	# override flags for CC Sun C++ compiler
# Add to all Solaris
CXXFLAGS += -template=no%extdef
SUN_CC10_BUGGY := $(shell $(CXX) -V 2>&1 | $(GREP) -c -E "CC: Sun .* 5\.10 .* (2009|2010/0[1-4])")
ifneq ($(SUN_CC10_BUGGY),0)
# -DCRYPTOPP_INCLUDE_VECTOR_CC is needed for Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21 and was fixed in May 2010
# remove it if you get "already had a body defined" errors in vector.cc
CXXFLAGS += -DCRYPTOPP_INCLUDE_VECTOR_CC
endif
AR = $(CXX)
ARFLAGS = -xar -o
RANLIB = true
endif

# No ASM for Travis testing
ifeq ($(findstring no-asm,$(MAKECMDGOALS)),no-asm)
ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
endif # CXXFLAGS
endif # No ASM

# Native build testing. Issue 'make native'.
ifeq ($(findstring native,$(MAKECMDGOALS)),native)
  ifeq ($(findstring -march=native,$(CXXFLAGS)),)
    ifeq ($(IS_SUN)$(SUN_COMPILER),11)
      CXXFLAGS += -native
    else
      CXXFLAGS += -march=native
    endif # CXXFLAGS
  endif # Sun
endif # Native

# Undefined Behavior Sanitizer (UBsan) testing. Issue 'make ubsan'.
ifeq ($(findstring ubsan,$(MAKECMDGOALS)),ubsan)
  CXXFLAGS := $(CXXFLAGS:-g%=-g3)
  CXXFLAGS := $(CXXFLAGS:-O%=-O1)
  CXXFLAGS := $(CXXFLAGS:-xO%=-xO1)
  ifeq ($(findstring -fsanitize=undefined,$(CXXFLAGS)),)
    CXXFLAGS += -fsanitize=undefined
  endif # CXXFLAGS
  ifeq ($(findstring -DCRYPTOPP_COVERAGE,$(CXXFLAGS)),)
    CXXFLAGS += -DCRYPTOPP_COVERAGE
  endif # CXXFLAGS
endif # UBsan

# Address Sanitizer (Asan) testing. Issue 'make asan'.
ifeq ($(findstring asan,$(MAKECMDGOALS)),asan)
  CXXFLAGS := $(CXXFLAGS:-g%=-g3)
  CXXFLAGS := $(CXXFLAGS:-O%=-O1)
  CXXFLAGS := $(CXXFLAGS:-xO%=-xO1)
  ifeq ($(findstring -fsanitize=address,$(CXXFLAGS)),)
    CXXFLAGS += -fsanitize=address
  endif # CXXFLAGS
  ifeq ($(findstring -DCRYPTOPP_COVERAGE,$(CXXFLAGS)),)
    CXXFLAGS += -DCRYPTOPP_COVERAGE
  endif # CXXFLAGS
  ifeq ($(findstring -fno-omit-frame-pointer,$(CXXFLAGS)),)
    CXXFLAGS += -fno-omit-frame-pointer
  endif # CXXFLAGS
endif # Asan

# LD gold linker testing. Triggered by 'LD=ld.gold'.
ifeq ($(findstring ld.gold,$(LD)),ld.gold)
  ifeq ($(findstring -fuse-ld=gold,$(CXXFLAGS)),)
    LD_GOLD = $(shell command -v ld.gold)
    ELF_FORMAT := $(shell file $(LD_GOLD) 2>&1 | cut -d":" -f 2 | $(GREP) -i -c "elf")
    ifneq ($(ELF_FORMAT),0)
      LDFLAGS += -fuse-ld=gold
    endif # ELF/ELF64
  endif # CXXFLAGS
endif # Gold

# lcov code coverage. Issue 'make coverage'.
ifneq ($(filter lcov coverage,$(MAKECMDGOALS)),)
  CXXFLAGS := $(CXXFLAGS:-g%=-g3)
  CXXFLAGS := $(CXXFLAGS:-O%=-O1)
  CXXFLAGS := $(CXXFLAGS:-xO%=-xO1)
  ifeq ($(findstring -DCRYPTOPP_COVERAGE,$(CXXFLAGS)),)
    CXXFLAGS += -DCRYPTOPP_COVERAGE
  endif # CRYPTOPP_COVERAGE
  ifeq ($(findstring -coverage,$(CXXFLAGS)),)
    CXXFLAGS += -coverage
  endif # -coverage
endif # GCC code coverage

# gcov code coverage for Travis. Issue 'make codecov'.
ifneq ($(filter gcov codecov,$(MAKECMDGOALS)),)
  CXXFLAGS := $(CXXFLAGS:-g%=-g3)
  CXXFLAGS := $(CXXFLAGS:-O%=-O1)
  CXXFLAGS := $(CXXFLAGS:-xO%=-xO1)
  ifeq ($(findstring -DCRYPTOPP_COVERAGE,$(CXXFLAGS)),)
    CXXFLAGS += -DCRYPTOPP_COVERAGE
  endif # CRYPTOPP_COVERAGE
  ifeq ($(findstring -coverage,$(CXXFLAGS)),)
    CXXFLAGS += -coverage
  endif # -coverage
endif # GCC code coverage

# Valgrind testing. Issue 'make valgrind'.
ifneq ($(filter valgrind,$(MAKECMDGOALS)),)
  # Tune flags; see http://valgrind.org/docs/manual/quick-start.html
  CXXFLAGS := $(CXXFLAGS:-g%=-g3)
  CXXFLAGS := $(CXXFLAGS:-O%=-O1)
  CXXFLAGS := $(CXXFLAGS:-xO%=-xO1)
  ifeq ($(findstring -DCRYPTOPP_VALGRIND,$(CXXFLAGS)),)
    CXXFLAGS += -DCRYPTOPP_VALGRIND
  endif # -DCRYPTOPP_VALGRIND
endif # Valgrind

# Debug testing on GNU systems. Triggered by -DDEBUG.
#   Newlib test due to http://sourceware.org/bugzilla/show_bug.cgi?id=20268
ifneq ($(filter -DDEBUG -DDEBUG=1,$(CXXFLAGS)),)
  USING_GLIBCXX := $(shell $(CXX) $(CXXFLAGS) -DADHOC_MAIN -E adhoc.cpp 2>&1 | $(GREP) -i -c "__GLIBCXX__")
  ifneq ($(USING_GLIBCXX),0)
    ifeq ($(HAS_NEWLIB),0)
      ifeq ($(findstring -D_GLIBCXX_DEBUG,$(CXXFLAGS)),)
        CXXFLAGS += -D_GLIBCXX_DEBUG
      endif # CXXFLAGS
    endif # HAS_NEWLIB
  endif # USING_GLIBCXX
endif # GNU Debug build

# Dead code stripping. Issue 'make lean'.
ifeq ($(findstring lean,$(MAKECMDGOALS)),lean)
  ifeq ($(findstring -ffunction-sections,$(CXXFLAGS)),)
    CXXFLAGS += -ffunction-sections
  endif # CXXFLAGS
  ifeq ($(findstring -fdata-sections,$(CXXFLAGS)),)
    CXXFLAGS += -fdata-sections
  endif # CXXFLAGS
  ifneq ($(IS_DARWIN),0)
    ifeq ($(findstring -Wl,-dead_strip,$(LDFLAGS)),)
      LDFLAGS += -Wl,-dead_strip
    endif # CXXFLAGS
  else # BSD, Linux and Unix
    ifeq ($(findstring -Wl,--gc-sections,$(LDFLAGS)),)
      LDFLAGS += -Wl,--gc-sections
    endif # LDFLAGS
  endif # MAKECMDGOALS
endif # Dead code stripping

# For Shared Objects, Diff, Dist/Zip rules
LIB_VER := $(shell $(GREP) "define CRYPTOPP_VERSION" config.h | cut -d" " -f 3)
LIB_MAJOR := $(shell echo $(LIB_VER) | cut -c 1)
LIB_MINOR := $(shell echo $(LIB_VER) | cut -c 2)
LIB_PATCH := $(shell echo $(LIB_VER) | cut -c 3)

ifeq ($(strip $(LIB_PATCH)),)
  LIB_PATCH := 0
endif

ifeq ($(HAS_SOLIB_VERSION),1)
# Different patchlevels and minors are compatible since 6.1
SOLIB_COMPAT_SUFFIX=.$(LIB_MAJOR)
# Linux uses -Wl,-soname
ifeq ($(IS_LINUX),1)
# Linux uses full version suffix for shared library
SOLIB_VERSION_SUFFIX=.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)
SOLIB_FLAGS=-Wl,-soname,libcryptopp.so$(SOLIB_COMPAT_SUFFIX)
endif
# Solaris uses -Wl,-h
ifeq ($(IS_SUN),1)
# Solaris uses major version suffix for shared library, but we use major.minor
# The minor version allows previous version to remain and not overwritten.
# https://blogs.oracle.com/solaris/how-to-name-a-solaris-shared-object-v2
SOLIB_VERSION_SUFFIX=.$(LIB_MAJOR).$(LIB_MINOR)
SOLIB_FLAGS=-Wl,-h,libcryptopp.so$(SOLIB_COMPAT_SUFFIX)
endif
endif # HAS_SOLIB_VERSION

###########################################################
#####              Source and object files            #####
###########################################################

# List cryptlib.cpp first, then cpu.cpp, then integer.cpp to tame C++ static initialization problems.
SRCS := cryptlib.cpp cpu.cpp integer.cpp $(filter-out cryptlib.cpp cpu.cpp integer.cpp pch.cpp simple.cpp winpipes.cpp cryptlib_bds.cpp,$(sort $(wildcard *.cpp)))
# For Makefile.am; resource.h is Windows
INCL := $(filter-out resource.h,$(sort $(wildcard *.h)))

ifneq ($(IS_MINGW),0)
INCL += resource.h
endif

# Cryptogams AES for ARMv4 and above. We couple to ARMv7.
ifeq ($(IS_ARM32),1)
CRYPTOGAMS_AES_FLAG = -march=armv7-a
CRYPTOGAMS_AES_FLAG += -Wa,--noexecstack
SRCS += aes-armv4.S
endif

# List cryptlib.cpp first, then cpu.cpp, then integer.cpp to tame C++ static initialization problems.
OBJS := $(SRCS:.cpp=.o)
OBJS := $(OBJS:.S=.o)

# List test.cpp first to tame C++ static initialization problems.
TESTSRCS := adhoc.cpp test.cpp bench1.cpp bench2.cpp bench3.cpp datatest.cpp dlltest.cpp fipsalgt.cpp validat0.cpp validat1.cpp validat2.cpp validat3.cpp validat4.cpp validat5.cpp validat6.cpp validat7.cpp validat8.cpp validat9.cpp validat10.cpp regtest1.cpp regtest2.cpp regtest3.cpp regtest4.cpp
TESTINCL := bench.h factory.h validate.h

# Test objects
TESTOBJS := $(TESTSRCS:.cpp=.o)
LIBOBJS := $(filter-out $(TESTOBJS),$(OBJS))

# In Crypto++ 5.6.2 these were the source and object files for the FIPS DLL.
# Since the library is on the Historical Validation List we add all files.
# The 5.6.2 list is at https://github.com/weidai11/cryptopp/blob/789f81f048c9.
DLLSRCS := $(SRCS)
DLLOBJS := $(DLLSRCS:.cpp=.export.o)
DLLOBJS := $(DLLOBJS:.S=.export.o)

# Import lib testing
LIBIMPORTOBJS := $(LIBOBJS:.o=.import.o)
TESTIMPORTOBJS := $(TESTOBJS:.o=.import.o)
DLLTESTOBJS := dlltest.dllonly.o

###########################################################
#####                Targets and Recipes              #####
###########################################################

# Default builds program with static library only
.PHONY: default
default: cryptest.exe

.PHONY: all static dynamic
all: static dynamic cryptest.exe

ifneq ($(IS_DARWIN),0)
static: libcryptopp.a
shared dynamic dylib: libcryptopp.dylib
else
static: libcryptopp.a
shared dynamic: libcryptopp.so$(SOLIB_VERSION_SUFFIX)
endif

.PHONY: dep deps depend
dep deps depend GNUmakefile.deps:
	$(CXX) $(strip $(CXXFLAGS)) -MM *.cpp > GNUmakefile.deps

# CXXFLAGS are tuned earlier.
.PHONY: native no-asm asan ubsan
native no-asm asan ubsan: cryptest.exe

# CXXFLAGS are tuned earlier. Applications must use linker flags
#  -Wl,--gc-sections (Linux and Unix) or -Wl,-dead_strip (OS X)
.PHONY: lean
lean: static dynamic cryptest.exe

# May want to export CXXFLAGS="-g3 -O1"
.PHONY: lcov coverage
lcov coverage: cryptest.exe
	@-$(RM) -r ./TestCoverage/
	lcov --base-directory . --directory . --zerocounters -q
	./cryptest.exe v
	./cryptest.exe tv all
	lcov --base-directory . --directory . -c -o cryptest.info
	lcov --remove cryptest.info "adhoc.cpp" "wait.*" "network.*" "socketft.*" "fips140.*" "*test.*" "bench*.cpp" "validat*.*" "/usr/*" -o cryptest.info
	genhtml -o ./TestCoverage/ -t "cryptest.exe test coverage" --num-spaces 4 cryptest.info

# Travis CI and CodeCov rule
.PHONY: gcov codecov
gcov codecov: cryptest.exe
	@-$(RM) -r ./TestCoverage/
	./cryptest.exe v
	./cryptest.exe tv all
	gcov -r $(SRCS)

# Should use CXXFLAGS="-g3 -O1"
.PHONY: valgrind
valgrind: cryptest.exe
	valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe v

.PHONY: test check
test check: cryptest.exe
	./cryptest.exe v

# Used to generate list of source files for Autotools, CMakeList, Android.mk, etc
.PHONY: sources
sources: adhoc.cpp
	$(info ***** Library sources *****)
	$(info $(filter-out $(TESTSRCS),$(SRCS)))
	$(info )
	$(info ***** Library headers *****)
	$(info $(filter-out $(TESTINCL),$(INCL)))
	$(info )
	$(info ***** Test sources *****)
	$(info $(TESTSRCS))
	$(info )
	$(info ***** Test headers *****)
	$(info $(TESTINCL))

# Directory we want (can't specify on Doygen command line)
DOCUMENT_DIRECTORY := ref$(LIB_VER)
# Directory Doxygen uses (specified in Doygen config file)
ifeq ($(wildcard Doxyfile),Doxyfile)
DOXYGEN_DIRECTORY := $(strip $(shell $(GREP) "OUTPUT_DIRECTORY" Doxyfile | $(GREP) -v "\#" | cut -d "=" -f 2))
endif
# Default directory (in case its missing in the config file)
ifeq ($(strip $(DOXYGEN_DIRECTORY)),)
DOXYGEN_DIRECTORY := html-docs
endif

# Builds the documentation. Directory name is ref563, ref570, etc.
.PHONY: docs html
docs html:
	@-$(RM) -r $(DOXYGEN_DIRECTORY)/ $(DOCUMENT_DIRECTORY)/ html-docs/
	@-$(RM) CryptoPPRef.zip
	doxygen Doxyfile -d CRYPTOPP_DOXYGEN_PROCESSING
	$(MV) $(DOXYGEN_DIRECTORY)/ $(DOCUMENT_DIRECTORY)/
	zip -9 CryptoPPRef.zip -x ".*" -x "*/.*" -r $(DOCUMENT_DIRECTORY)/

.PHONY: clean
clean:
	-$(RM) adhoc.cpp.o adhoc.cpp.proto.o $(LIBOBJS) rdrand-*.o $(TESTOBJS) $(DLLOBJS) $(LIBIMPORTOBJS) $(TESTIMPORTOBJS) $(DLLTESTOBJS)
	@-$(RM) libcryptopp.a libcryptopp.dylib cryptopp.dll libcryptopp.dll.a libcryptopp.import.a
	@-$(RM) libcryptopp.so libcryptopp.so$(SOLIB_COMPAT_SUFFIX) libcryptopp.so$(SOLIB_VERSION_SUFFIX)
	@-$(RM) cryptest.exe dlltest.exe cryptest.import.exe cryptest.info ct et
	@-$(RM) *.la *.lo *.gcov *.gcno *.gcda *.stackdump core core-*
	@-$(RM) /tmp/adhoc.exe
	@-$(RM) -r /tmp/cryptopp_test/
	@-$(RM) -r *.exe.dSYM/
	@-$(RM) -r *.dylib.dSYM/
	@-$(RM) -r cov-int/

.PHONY: autotools-clean
autotools-clean:
	@-$(RM) -f configure.ac configure configure.in Makefile.am Makefile.in Makefile
	@-$(RM) -f config.guess config.status config.sub config.h.in compile depcomp
	@-$(RM) -f install-sh stamp-h1 ar-lib *.lo *.la *.m4 local.* lt*.sh missing
	@-$(RM) -f cryptest cryptestcwd libtool* libcryptopp.la libcryptopp.pc*
	@-$(RM) -rf m4/ auto*.cache/ .deps/ .libs/

.PHONY: cmake-clean
cmake-clean:
	@-$(RM) -f cryptopp-config.cmake CMakeLists.txt
	@-$(RM) -rf cmake_build/

.PHONY: distclean
distclean: clean autotools-clean cmake-clean
	-$(RM) adhoc.cpp adhoc.cpp.copied GNUmakefile.deps benchmarks.html cryptest.txt
	@-$(RM) cryptest-*.txt cryptopp.tgz libcryptopp.pc *.o *.bc *.ii *~
	@-$(RM) -r cryptlib.lib cryptest.exe *.suo *.sdf *.pdb Win32/ x64/ ipch/
	@-$(RM) -r $(LIBOBJS:.o=.obj) $(TESTOBJS:.o=.obj)
	@-$(RM) -r $(LIBOBJS:.o=.lst) $(TESTOBJS:.o=.lst)
	@-$(RM) -r TestCoverage/ ref*/
	@-$(RM) cryptopp$(LIB_VER)\.* CryptoPPRef.zip

# Install cryptest.exe, libcryptopp.a, libcryptopp.so and libcryptopp.pc.
# The library install was broken-out into its own recipe at GH #653.
.PHONY: install
install: cryptest.exe install-lib
	@-$(MKDIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_PROGRAM) cryptest.exe $(DESTDIR)$(BINDIR)
	@-$(MKDIR) $(DESTDIR)$(DATADIR)/cryptopp/TestData
	@-$(MKDIR) $(DESTDIR)$(DATADIR)/cryptopp/TestVectors
	$(INSTALL_DATA) TestData/*.dat $(DESTDIR)$(DATADIR)/cryptopp/TestData
	$(INSTALL_DATA) TestVectors/*.txt $(DESTDIR)$(DATADIR)/cryptopp/TestVectors

# A recipe to install only the library, and not cryptest.exe. Also
# see https://github.com/weidai11/cryptopp/issues/653. Some users
# already have a libcryptopp.pc. Install the *.pc file if the file
# is present. If you want one, then issue 'make libcryptopp.pc'.
.PHONY: install-lib
install-lib:
	@-$(MKDIR) $(DESTDIR)$(INCLUDEDIR)/cryptopp
	$(INSTALL_DATA) *.h $(DESTDIR)$(INCLUDEDIR)/cryptopp
ifneq ($(wildcard libcryptopp.a),)
	@-$(MKDIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) libcryptopp.a $(DESTDIR)$(LIBDIR)
endif
ifneq ($(wildcard libcryptopp.dylib),)
	@-$(MKDIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_PROGRAM) libcryptopp.dylib $(DESTDIR)$(LIBDIR)
	-install_name_tool -id $(DESTDIR)$(LIBDIR)/libcryptopp.dylib $(DESTDIR)$(LIBDIR)/libcryptopp.dylib
endif
ifneq ($(wildcard libcryptopp.so$(SOLIB_VERSION_SUFFIX)),)
	@-$(MKDIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_PROGRAM) libcryptopp.so$(SOLIB_VERSION_SUFFIX) $(DESTDIR)$(LIBDIR)
ifeq ($(HAS_SOLIB_VERSION),1)
	-$(LN) libcryptopp.so$(SOLIB_VERSION_SUFFIX) $(DESTDIR)$(LIBDIR)/libcryptopp.so
	$(LDCONF) $(DESTDIR)$(LIBDIR)
endif
endif
ifneq ($(wildcard libcryptopp.pc),)
	@-$(MKDIR) $(DESTDIR)$(LIBDIR)/pkgconfig
	$(INSTALL_DATA) libcryptopp.pc $(DESTDIR)$(LIBDIR)/pkgconfig/libcryptopp.pc
endif

.PHONY: remove uninstall
remove uninstall:
	-$(RM) -r $(DESTDIR)$(INCLUDEDIR)/cryptopp
	-$(RM) $(DESTDIR)$(LIBDIR)/libcryptopp.a
	-$(RM) $(DESTDIR)$(BINDIR)/cryptest.exe
	@-$(RM) $(DESTDIR)$(LIBDIR)/libcryptopp.dylib
	@-$(RM) $(DESTDIR)$(LIBDIR)/libcryptopp.so$(SOLIB_VERSION_SUFFIX)
	@-$(RM) $(DESTDIR)$(LIBDIR)/libcryptopp.so$(SOLIB_COMPAT_SUFFIX)
	@-$(RM) $(DESTDIR)$(LIBDIR)/libcryptopp.so
	@-$(RM) $(DESTDIR)$(LIBDIR)/pkgconfig/libcryptopp.pc
	@-$(RM) -r $(DESTDIR)$(DATADIR)/cryptopp

libcryptopp.a: $(LIBOBJS)
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
ifeq ($(IS_SUN),0)
	$(RANLIB) $@
endif

ifeq ($(HAS_SOLIB_VERSION),1)
.PHONY: libcryptopp.so
libcryptopp.so: libcryptopp.so$(SOLIB_VERSION_SUFFIX) | so_warning
endif

libcryptopp.so$(SOLIB_VERSION_SUFFIX): $(LIBOBJS)
ifeq ($(XLC_COMPILER),1)
	$(CXX) -qmkshrobj $(SOLIB_FLAGS) -o $@ $(strip $(CXXFLAGS)) $(LDFLAGS) $(LIBOBJS) $(LDLIBS)
else
	$(CXX) -shared $(SOLIB_FLAGS) -o $@ $(strip $(CXXFLAGS)) $(LDFLAGS) $(LIBOBJS) $(LDLIBS)
endif
ifeq ($(HAS_SOLIB_VERSION),1)
	-$(LN) libcryptopp.so$(SOLIB_VERSION_SUFFIX) libcryptopp.so
	-$(LN) libcryptopp.so$(SOLIB_VERSION_SUFFIX) libcryptopp.so$(SOLIB_COMPAT_SUFFIX)
endif

libcryptopp.dylib: $(LIBOBJS)
	$(CXX) -dynamiclib -o $@ $(strip $(CXXFLAGS)) -install_name "$@" -current_version "$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)" -compatibility_version "$(LIB_MAJOR).$(LIB_MINOR)" -headerpad_max_install_names $(LDFLAGS) $(LIBOBJS)

cryptest.exe:libcryptopp.a $(TESTOBJS)
	$(CXX) -o $@ $(strip $(CXXFLAGS)) $(TESTOBJS) ./libcryptopp.a $(LDFLAGS) $(LDLIBS)

# Makes it faster to test changes
nolib: $(OBJS)
	$(CXX) -o ct $(strip $(CXXFLAGS)) $(OBJS) $(LDFLAGS) $(LDLIBS)

dll: cryptest.import.exe dlltest.exe

cryptopp.dll: $(DLLOBJS)
	$(CXX) -shared -o $@ $(strip $(CXXFLAGS)) $(DLLOBJS) $(LDFLAGS) $(LDLIBS) -Wl,--out-implib=libcryptopp.dll.a

libcryptopp.import.a: $(LIBIMPORTOBJS)
	$(AR) $(ARFLAGS) $@ $(LIBIMPORTOBJS)
ifeq ($(IS_SUN),0)
	$(RANLIB) $@
endif

cryptest.import.exe: cryptopp.dll libcryptopp.import.a $(TESTIMPORTOBJS)
	$(CXX) -o $@ $(strip $(CXXFLAGS)) $(TESTIMPORTOBJS) -L. -lcryptopp.dll -lcryptopp.import $(LDFLAGS) $(LDLIBS)

dlltest.exe: cryptopp.dll $(DLLTESTOBJS)
	$(CXX) -o $@ $(strip $(CXXFLAGS)) $(DLLTESTOBJS) -L. -lcryptopp.dll $(LDFLAGS) $(LDLIBS)

# Some users already have a libcryptopp.pc. We install it if the file
# is present. If you want one, then issue 'make libcryptopp.pc'. Be sure
# to use/verify PREFIX and LIBDIR below after writing the file.
libcryptopp.pc:
	@echo '# Crypto++ package configuration file' > libcryptopp.pc
	@echo '' >> libcryptopp.pc
	@echo 'prefix=$(PREFIX)' >> libcryptopp.pc
	@echo 'libdir=$(LIBDIR)' >> libcryptopp.pc
	@echo 'includedir=$${prefix}/include' >> libcryptopp.pc
	@echo '' >> libcryptopp.pc
	@echo 'Name: Crypto++' >> libcryptopp.pc
	@echo 'Description: Crypto++ cryptographic library' >> libcryptopp.pc
	@echo 'Version: 7.1' >> libcryptopp.pc
	@echo 'URL: https://cryptopp.com/' >> libcryptopp.pc
	@echo '' >> libcryptopp.pc
	@echo 'Cflags: -I$${includedir}' >> libcryptopp.pc
	@echo 'Libs: -L$${libdir} -lcryptopp' >> libcryptopp.pc

# This recipe prepares the distro files
TEXT_FILES := *.h *.cpp adhoc.cpp License.txt Readme.txt Install.txt Filelist.txt Doxyfile cryptest* cryptlib* dlltest* cryptdll* *.sln *.s *.S *.vcxproj *.filters cryptopp.rc TestVectors/*.txt TestData/*.dat TestScripts/*.sh TestScripts/*.cmd
EXEC_FILES := GNUmakefile GNUmakefile-cross TestData/ TestVectors/ TestScripts/

ifeq ($(wildcard Filelist.txt),Filelist.txt)
DIST_FILES := $(shell cat Filelist.txt)
endif

.PHONY: trim
trim:
ifneq ($(IS_DARWIN),0)
	sed -i '' -e's/[[:space:]]*$$//' *.supp *.txt *.sh .*.yml *.h *.cpp *.asm *.s *.S *.sln *.vcxproj *.filters GNUmakefile GNUmakefile-cross
	sed -i '' -e's/[[:space:]]*$$//' TestData/*.dat TestVectors/*.txt TestScripts/*.*
	make convert
else
	sed -i -e's/[[:space:]]*$$//' *.supp *.txt *.sh .*.yml *.h *.cpp *.asm *.s *.S *.sln *.vcxproj *.filters GNUmakefile GNUmakefile-cross
	sed -i -e's/[[:space:]]*$$//' TestData/*.dat TestVectors/*.txt TestScripts/*.*
	make convert
endif

.PHONY: convert
convert:
	@-$(CHMOD) 0700 TestVectors/ TestData/ TestScripts/
	@-$(CHMOD) 0600 $(TEXT_FILES) *.supp .*.yml *.asm *.s *.zip TestVectors/*.txt TestData/*.dat TestScripts/*.*
	@-$(CHMOD) 0700 $(EXEC_FILES) *.sh *.cmd TestScripts/*.sh TestScripts/*.cmd
	@-$(CHMOD) 0700 *.cmd *.sh GNUmakefile GNUmakefile-cross TestScripts/*.sh
	-unix2dos --keepdate --quiet $(TEXT_FILES) .*.yml *.asm *.cmd TestScripts/*.*
	-dos2unix --keepdate --quiet GNUmakefile GNUmakefile-cross *.supp *.s *.sh *.mapfile TestScripts/*.sh TestScripts/*.patch
ifneq ($(IS_DARWIN),0)
	@-xattr -c *
endif

# Build the ZIP file with source files. No documentation.
.PHONY: zip dist
zip dist: | distclean convert
	zip -q -9 cryptopp$(LIB_VER).zip $(DIST_FILES)

# Build the ISO to transfer the ZIP to old distros via CDROM
.PHONY: iso
iso: | zip
ifneq ($(IS_DARWIN),0)
	$(MKDIR) $(PWD)/cryptopp$(LIB_VER)
	$(CP) cryptopp$(LIB_VER).zip $(PWD)/cryptopp$(LIB_VER)
	hdiutil makehybrid -iso -joliet -o cryptopp$(LIB_VER).iso $(PWD)/cryptopp$(LIB_VER)
	@-$(RM) -r $(PWD)/cryptopp$(LIB_VER)
else ifneq ($(IS_LINUX),0)
	$(MKDIR) $(PWD)/cryptopp$(LIB_VER)
	$(CP) cryptopp$(LIB_VER).zip $(PWD)/cryptopp$(LIB_VER)
	genisoimage -q -o cryptopp$(LIB_VER).iso $(PWD)/cryptopp$(LIB_VER)
	@-$(RM) -r $(PWD)/cryptopp$(LIB_VER)
endif

# CRYPTOPP_CPU_FREQ in GHz
CRYPTOPP_CPU_FREQ ?= 0.0
.PHONY: bench benchmark benchmarks
bench benchmark benchmarks: cryptest.exe
	@-$(RM) -f benchmarks.html
	./cryptest.exe b 2 $(CRYPTOPP_CPU_FREQ)

adhoc.cpp: adhoc.cpp.proto
ifeq ($(wildcard adhoc.cpp),)
	cp adhoc.cpp.proto adhoc.cpp
else
	touch adhoc.cpp
endif

# Include dependencies, if present. You must issue `make deps` to create them.
ifeq ($(wildcard GNUmakefile.deps),GNUmakefile.deps)
-include GNUmakefile.deps
endif # Dependencies

# Cryptogams ARM asm implementation.
aes-armv4.o : aes-armv4.S
	$(CC) $(strip $(CXXFLAGS) $(CRYPTOGAMS_AES_FLAG) -mfloat-abi=$(FP_ABI) -c) $<

# SSSE3 or NEON available
aria-simd.o : aria-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(ARIA_FLAG) -c) $<

# SSE4.1 or ARMv8a available
blake2-simd.o : blake2-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(BLAKE2_FLAG) -c) $<

# SSSE3 available
cham-simd.o : cham-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(CHAM_FLAG) -c) $<

# SSE2 on i586
sse-simd.o : sse-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SSE_FLAG) -c) $<

# SSE4.2 or ARMv8a available
crc-simd.o : crc-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(CRC_FLAG) -c) $<

# PCLMUL or ARMv7a/ARMv8a available
gcm-simd.o : gcm-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(GCM_FLAG) -c) $<

# SSSE3 available
lea-simd.o : lea-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(LEA_FLAG) -c) $<

# NEON available
neon-simd.o : neon-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(NEON_FLAG) -c) $<

# AltiVec, Power7, Power8 available
ppc-simd.o : ppc-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(ALTIVEC_FLAG) -c) $<

# AESNI or ARMv7a/ARMv8a available
rijndael-simd.o : rijndael-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(AES_FLAG) -c) $<

# SSE4.2/SHA-NI or ARMv8a available
sha-simd.o : sha-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SHA_FLAG) -c) $<

# SSE4.2/SHA-NI or ARMv8a available
shacal2-simd.o : shacal2-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SHA_FLAG) -c) $<

# SSSE3 or NEON available
simeck-simd.o : simeck-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SIMECK_FLAG) -c) $<

# SSE4.1, NEON or POWER7 available
simon64-simd.o : simon64-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SIMON64_FLAG) -c) $<

# SSSE3, NEON or POWER8 available
simon128-simd.o : simon128-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SIMON128_FLAG) -c) $<

# SSE4.1, NEON or POWER7 available
speck64-simd.o : speck64-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SPECK64_FLAG) -c) $<

# SSSE3, NEON or POWER8 available
speck128-simd.o : speck128-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SPECK128_FLAG) -c) $<

# AESNI available
sm4-simd.o : sm4-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SM4_FLAG) -c) $<

# IBM XLC -O3 optimization bug
ifeq ($(XLC_COMPILER),1)
sm3.o : sm3.cpp
	$(CXX) $(strip $(subst -O3,-O2,$(CXXFLAGS)) -c) $<
endif

# Don't build Rijndael with UBsan. Too much noise due to unaligned data accesses.
ifneq ($(findstring -fsanitize=undefined,$(CXXFLAGS)),)
rijndael.o : rijndael.cpp
	$(CXX) $(strip $(subst -fsanitize=undefined,,$(CXXFLAGS)) -c) $<
endif

# Only use CRYPTOPP_DATA_DIR if its not set in CXXFLAGS
ifeq ($(findstring -DCRYPTOPP_DATA_DIR, $(strip $(CXXFLAGS))),)
ifneq ($(strip $(CRYPTOPP_DATA_DIR)),)
validat%.o : validat%.cpp
	$(CXX) $(strip $(CXXFLAGS) -DCRYPTOPP_DATA_DIR=\"$(CRYPTOPP_DATA_DIR)\" -c) $<
bench%.o : bench%.cpp
	$(CXX) $(strip $(CXXFLAGS) -DCRYPTOPP_DATA_DIR=\"$(CRYPTOPP_DATA_DIR)\" -c) $<
datatest.o : datatest.cpp
	$(CXX) $(strip $(CXXFLAGS) -DCRYPTOPP_DATA_DIR=\"$(CRYPTOPP_DATA_DIR)\" -c) $<
test.o : test.cpp
	$(CXX) $(strip $(CXXFLAGS) -DCRYPTOPP_DATA_DIR=\"$(CRYPTOPP_DATA_DIR)\" -c) $<
endif
endif

validat%.o : validat%.cpp
	$(CXX) $(strip $(CXXFLAGS) $(ALTIVEC_FLAG) -c) $<

%.dllonly.o : %.cpp
	$(CXX) $(strip $(CXXFLAGS) -DCRYPTOPP_DLL_ONLY -c) $< -o $@

%.import.o : %.cpp
	$(CXX) $(strip $(CXXFLAGS) -DCRYPTOPP_IMPORTS -c) $< -o $@

%.export.o : %.cpp
	$(CXX) $(strip $(CXXFLAGS) -DCRYPTOPP_EXPORTS -c) $< -o $@

%.bc : %.cpp
	$(CXX) $(strip $(CXXFLAGS) -c) $<

%.o : %.cpp
	$(CXX) $(strip $(CXXFLAGS) -c) $<

.PHONY: so_warning
so_warning:
ifeq ($(HAS_SOLIB_VERSION),1)
	$(info WARNING: Only the symlinks to the shared-object library have been updated.)
	$(info WARNING: If the library is installed in a system directory you will need)
	$(info WARNING: to run 'ldconfig' to update the shared-object library cache.)
	$(info )
endif
