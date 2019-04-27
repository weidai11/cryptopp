
###########################################################
#####        System Attributes and Programs           #####
###########################################################

# https://www.gnu.org/software/make/manual/make.html#Makefile-Conventions
# and https://www.gnu.org/prep/standards/standards.html

SHELL = /bin/sh

# If needed
TMPDIR ?= /tmp
# Used for feature tests
TOUT ?= a.out
TOUT := $(strip $(TOUT))

# Command and arguments
AR ?= ar
ARFLAGS ?= -cr # ar needs the dash on OpenBSD
RANLIB ?= ranlib

CP ?= cp
MV ?= mv
RM ?= rm -f
GREP ?= grep
CHMOD ?= chmod
MKDIR ?= mkdir -p

LN ?= ln -sf
LDCONF ?= /sbin/ldconfig -n

# Solaris provides a non-Posix grep at /usr/bin
ifneq ($(wildcard /usr/xpg4/bin/grep),)
  GREP := /usr/xpg4/bin/grep
endif

# Attempt to determine target machine, fallback to "this" machine.
#   The target machine is the one the package runs on. Most people
#   call this the "target", but not Autotools.
HOSTX := $(shell $(CXX) $(CXXFLAGS) -dumpmachine 2>/dev/null | cut -f 1 -d '-')
ifeq ($(HOSTX),)
  HOSTX := $(shell uname -m 2>/dev/null)
endif

IS_X86 := $(shell echo "$(HOSTX)" | $(GREP) -v "64" | $(GREP) -i -c -E 'i.86|x86|i86')
IS_X64 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E '_64|d64')
IS_PPC32 := $(shell echo "$(HOSTX)" | $(GREP) -v "64" | $(GREP) -i -c -E 'ppc|power')
IS_PPC64 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E 'ppc64|powerpc64|power64')
IS_SPARC32 := $(shell echo "$(HOSTX)" | $(GREP) -v "64" | $(GREP) -i -c -E 'sun|sparc')
IS_SPARC64 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E 'sun|sparc64')
IS_ARM32 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E 'arm|armhf|arm7l|eabihf')
IS_ARMV8 := $(shell echo "$(HOSTX)" | $(GREP) -i -c -E 'aarch32|aarch64|arm64|armv8')

# Attempt to determine platform
SYSTEMX := $(shell $(CXX) $(CXXFLAGS) -dumpmachine 2>/dev/null)
ifeq ($(SYSTEMX),)
  SYSTEMX := $(shell uname -s 2>/dev/null)
endif

IS_LINUX := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "Linux")
IS_HURD := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c -E "GNU|Hurd")
IS_MINGW := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "MinGW")
IS_CYGWIN := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "Cygwin")
IS_DARWIN := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "Darwin")
IS_NETBSD := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "NetBSD")
IS_AIX := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c "aix")
IS_SUN := $(shell echo "$(SYSTEMX)" | $(GREP) -i -c -E "SunOS|Solaris")

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

# Enable shared object versioning for Linux and Solaris
HAS_SOLIB_VERSION ?= 0
ifneq ($(IS_LINUX)$(IS_HURD)$(IS_SUN),000)
  HAS_SOLIB_VERSION := 1
endif

# Formely adhoc.cpp was created from adhoc.cpp.proto when needed.
ifeq ($(wildcard adhoc.cpp),)
$(shell cp adhoc.cpp.proto adhoc.cpp)
endif

# Tell MacPorts and Homebrew GCC to use Clang integrated assembler (only on Intel-based Macs)
#   http://github.com/weidai11/cryptopp/issues/190
ifeq ($(GCC_COMPILER)$(OSXPORT_COMPILER)$(IS_PPC32)$(IS_PPC64),1100)
  ifeq ($(findstring -Wa,-q,$(CXXFLAGS)),)
    CXXFLAGS += -Wa,-q
  endif
endif

# Hack to skip CPU feature tests for some recipes
DETECT_FEATURES ?= 1
ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),-DCRYPTOPP_DISABLE_ASM)
  DETECT_FEATURES := 0
else ifeq ($(findstring clean,$(MAKECMDGOALS)),clean)
  DETECT_FEATURES := 0
else ifeq ($(findstring distclean,$(MAKECMDGOALS)),distclean)
  DETECT_FEATURES := 0
else ifeq ($(findstring distclean,$(MAKECMDGOALS)),trim)
  DETECT_FEATURES := 0
endif

# Strip out -Wall, -Wextra and friends for feature testing
ifeq ($(DETECT_FEATURES),1)
  TCXXFLAGS := $(filter-out -Wall -Wextra -Werror% -Wunused -Wconversion -Wp%, $(CXXFLAGS))
  ifneq ($(strip $(TCXXFLAGS)),)
    $(info Using testing flags: $(TCXXFLAGS))
  endif
  #TPROG = TestPrograms/test_cxx.cxx
  #$(info Testing compile... )
  #$(info $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 1>/dev/null))
endif

# Fixup AIX
ifeq ($(IS_AIX),1)
  TPROG = TestPrograms/test_64bit.cxx
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    IS_PPC64=1
  else
    IS_PPC32=1
  endif
endif

# libc++ is LLVM's standard C++ library. If we add libc++
# here then all user programs must use it too. The open
# question is, which choice is easier on users?
ifneq ($(IS_DARWIN),0)
  CXX ?= c++
  # CXXFLAGS += -stdlib=libc++
  AR = libtool
  ARFLAGS = -static -o
endif

###########################################################
#####                General Variables                #####
###########################################################

# Base CXXFLAGS used if the user did not specify them
ifeq ($(SUN_COMPILER),1)
  CXXFLAGS ?= -DNDEBUG -g -xO3
  ZOPT = -xO0
else
  CXXFLAGS ?= -DNDEBUG -g2 -O3
  ZOPT = -O0
endif

# On ARM we may compile aes_armv4.S though the CC compiler
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

# Clang integrated assembler will be used with -Wa,-q
CLANG_INTEGRATED_ASSEMBLER ?= 0

# Original MinGW targets Win2k by default, but lacks proper Win2k support
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

# Newlib needs _XOPEN_SOURCE=600 for signals
TPROG = TestPrograms/test_newlib.cxx
HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
ifeq ($(strip $(HAVE_OPT)),0)
  ifeq ($(findstring -D_XOPEN_SOURCE,$(CXXFLAGS)),)
    CXXFLAGS += -D_XOPEN_SOURCE=600
  endif
endif

###########################################################
#####               X86/X32/X64 Options               #####
###########################################################

ifneq ($(IS_X86)$(IS_X64),00)
ifeq ($(DETECT_FEATURES),1)

  ifeq ($(SUN_COMPILER),1)
    SSE2_FLAG = -xarch=sse2
    SSE3_FLAG = -xarch=sse3
    SSSE3_FLAG = -xarch=ssse3
    SSE41_FLAG = -xarch=sse4_1
    SSE42_FLAG = -xarch=sse4_2
    CLMUL_FLAG = -xarch=aes
    AESNI_FLAG = -xarch=aes
    AVX_FLAG = -xarch=avx
    AVX2_FLAG = -xarch=avx2
    SHANI_FLAG = -xarch=sha
  else
    SSE2_FLAG = -msse2
    SSE3_FLAG = -msse3
    SSSE3_FLAG = -mssse3
    SSE41_FLAG = -msse4.1
    SSE42_FLAG = -msse4.2
    CLMUL_FLAG = -mpclmul
    AESNI_FLAG = -maes
    AVX_FLAG = -mavx
    AVX2_FLAG = -mavx2
    SHANI_FLAG = -msha
  endif

  TPROG = TestPrograms/test_x86_sse2.cxx
  TOPT = $(SSE2_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    CHACHA_FLAG = $(SSE2_FLAG)
    SUN_LDFLAGS += $(SSE2_FLAG)
  else
    SSE2_FLAG =
  endif

  TPROG = TestPrograms/test_x86_ssse3.cxx
  TOPT = $(SSSE3_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    ARIA_FLAG = $(SSSE3_FLAG)
    CHAM_FLAG = $(SSSE3_FLAG)
    KECCAK_FLAG = $(SSSE3_FLAG)
    LEA_FLAG = $(SSSE3_FLAG)
    SIMECK_FLAG = $(SSSE3_FLAG)
    SIMON64_FLAG = $(SSSE3_FLAG)
    SIMON128_FLAG = $(SSSE3_FLAG)
    SPECK64_FLAG = $(SSSE3_FLAG)
    SPECK128_FLAG = $(SSSE3_FLAG)
    SUN_LDFLAGS += $(SSSE3_FLAG)
  else
    SSSE3_FLAG =
  endif

  TPROG = TestPrograms/test_x86_sse41.cxx
  TOPT = $(SSE41_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    BLAKE2B_FLAG = $(SSE41_FLAG)
    BLAKE2S_FLAG = $(SSE41_FLAG)
    SIMON64_FLAG = $(SSE41_FLAG)
    SPECK64_FLAG = $(SSE41_FLAG)
    SUN_LDFLAGS += $(SSE41_FLAG)
  else
    SSE41_FLAG =
  endif

  TPROG = TestPrograms/test_x86_sse42.cxx
  TOPT = $(SSE42_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    CRC_FLAG = $(SSE42_FLAG)
    SUN_LDFLAGS += $(SSE42_FLAG)
  else
    SSE42_FLAG =
  endif

  TPROG = TestPrograms/test_x86_clmul.cxx
  TOPT = $(CLMUL_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    GCM_FLAG = $(SSSE3_FLAG) $(CLMUL_FLAG)
    GF2N_FLAG = $(CLMUL_FLAG)
    SUN_LDFLAGS += $(CLMUL_FLAG)
  else
    CLMUL_FLAG =
  endif

  TPROG = TestPrograms/test_x86_aes.cxx
  TOPT = $(AESNI_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    AES_FLAG = $(SSE41_FLAG) $(AESNI_FLAG)
    SM4_FLAG = $(SSSE3_FLAG) $(AESNI_FLAG)
    SUN_LDFLAGS += $(AESNI_FLAG)
  else
    AESNI_FLAG =
  endif

  TPROG = TestPrograms/test_x86_avx.cxx
  TOPT = $(AVX_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    # XXX_FLAG = $(AVX_FLAG)
    SUN_LDFLAGS += $(AVX_FLAG)
  else
    AVX_FLAG =
  endif

  TPROG = TestPrograms/test_x86_avx2.cxx
  TOPT = $(AVX2_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    CHACHA_AVX2_FLAG = $(AVX2_FLAG)
    SUN_LDFLAGS += $(AVX2_FLAG)
  else
    AVX2_FLAG =
  endif

  TPROG = TestPrograms/test_x86_sha.cxx
  TOPT = $(SHANI_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    SHA_FLAG = $(SSE42_FLAG) $(SHANI_FLAG)
    SUN_LDFLAGS += $(SHANI_FLAG)
  else
    SHANI_FLAG =
  endif

  ifeq ($(SUN_COMPILER),1)
    LDFLAGS += $(SUN_LDFLAGS)
  endif

  ifeq ($(SSE2_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
  else ifeq ($(SSE3_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_SSE3
  else ifeq ($(SSSE3_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_SSSE3
  else ifeq ($(SSE41_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_SSE4
  else ifeq ($(SSE42_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_SSE4
  endif

  ifneq ($(SSE42_FLAG),)

    # Unusual GCC/Clang on Macports. It assembles AES, but not CLMUL.
    # test_x86_clmul.s:15: no such instruction: 'pclmulqdq $0, %xmm1,%xmm0'
    ifeq ($(CLMUL_FLAG),)
      CXXFLAGS += -DCRYPTOPP_DISABLE_CLMUL
    endif
    ifeq ($(AESNI_FLAG),)
      CXXFLAGS += -DCRYPTOPP_DISABLE_AESNI
    endif

    ifeq ($(AVX_FLAG),)
      CXXFLAGS += -DCRYPTOPP_DISABLE_AVX
    else ifeq ($(AVX2_FLAG),)
      CXXFLAGS += -DCRYPTOPP_DISABLE_AVX2
    else ifeq ($(SHANI_FLAG),)
      CXXFLAGS += -DCRYPTOPP_DISABLE_SHANI
    endif
  endif

  # Drop to SSE2 if available
  ifeq ($(GCM_FLAG),)
    ifneq ($(SSE2_FLAG),)
      GCM_FLAG = $(SSE2_FLAG)
    endif
  endif

# DETECT_FEATURES
endif

ifneq ($(INTEL_COMPILER),0)
  CXXFLAGS += -wd68 -wd186 -wd279 -wd327 -wd161 -wd3180

  ICC111_OR_LATER := $(shell $(CXX) --version 2>&1 | $(GREP) -c -E "\(ICC\) ([2-9][0-9]|1[2-9]|11\.[1-9])")
  ifeq ($(ICC111_OR_LATER),0)
    # "internal error: backend signals" occurs on some x86 inline assembly with ICC 9 and
    # some x64 inline assembly with ICC 11.0. If you want to use Crypto++'s assembly code
    # with ICC, try enabling it on individual files
    CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
  endif
endif

# Allow use of "/" operator for GNU Assembler.
#   http://sourceware.org/bugzilla/show_bug.cgi?id=4572
ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
  ifeq ($(IS_SUN)$(GCC_COMPILER),11)
    CXXFLAGS += -Wa,--divide
  endif
endif

# Most Clang cannot handle mixed asm with positional arguments, where the
# body is Intel style with no prefix and the templates are AT&T style.
# Also see https://bugs.llvm.org/show_bug.cgi?id=39895 .
TPROG = TestPrograms/test_mixed_asm.cxx
HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
ifneq ($(strip $(HAVE_OPT)),0)
  CXXFLAGS += -DCRYPTOPP_DISABLE_MIXED_ASM
endif

# IS_X86, IS_X32 and IS_X64
endif

###########################################################
#####            ARM A-32, Aach64 and NEON            #####
###########################################################

ifneq ($(IS_ARM32)$(IS_ARMV8),00)
ifeq ($(DETECT_FEATURES),1)

ifneq ($(IS_ARM32),0)

  TPROG = TestPrograms/test_arm_neon.cxx
  TOPT = -march=armv7-a -mfpu=neon
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    NEON_FLAG = -march=armv7-a -mfpu=neon
    ARIA_FLAG = -march=armv7-a -mfpu=neon
    AES_FLAG = -march=armv7-a -mfpu=neon
    CRC_FLAG = -march=armv7-a -mfpu=neon
    GCM_FLAG = -march=armv7-a -mfpu=neon
    BLAKE2B_FLAG = -march=armv7-a -mfpu=neon
    BLAKE2S_FLAG = -march=armv7-a -mfpu=neon
    CHACHA_FLAG = -march=armv7-a -mfpu=neon
    CHAM_FLAG = -march=armv7-a -mfpu=neon
    LEA_FLAG = -march=armv7-a -mfpu=neon
    SHA_FLAG = -march=armv7-a -mfpu=neon
    SIMECK_FLAG = -march=armv7-a -mfpu=neon
    SIMON64_FLAG = -march=armv7-a -mfpu=neon
    SIMON128_FLAG = -march=armv7-a -mfpu=neon
    SPECK64_FLAG = -march=armv7-a -mfpu=neon
    SPECK128_FLAG = -march=armv7-a -mfpu=neon
    SM4_FLAG = -march=armv7-a -mfpu=neon
  else
    CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
  endif

# IS_ARM32
endif

ifeq ($(IS_ARMV8),1)

  TPROG = TestPrograms/test_arm_acle.cxx
  TOPT = -march=armv8-a
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
	ACLE_FLAG += -DCRYPTOPP_ARM_ACLE_AVAILABLE=1
  else
	CXXFLAGS += -DCRYPTOPP_ARM_ACLE_AVAILABLE=0
  endif

  TPROG = TestPrograms/test_arm_asimd.cxx
  TOPT = -march=armv8-a
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ACLE_FLAG) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    ASIMD_FLAG = -march=armv8-a
    ARIA_FLAG = -march=armv8-a
    BLAKE2B_FLAG = -march=armv8-a
    BLAKE2S_FLAG = -march=armv8-a
    CHACHA_FLAG = -march=armv8-a
    CHAM_FLAG = -march=armv8-a
    LEA_FLAG = -march=armv8-a
    NEON_FLAG = -march=armv8-a
    SIMECK_FLAG = -march=armv8-a
    SIMON64_FLAG = -march=armv8-a
    SIMON128_FLAG = -march=armv8-a
    SPECK64_FLAG = -march=armv8-a
    SPECK128_FLAG = -march=armv8-a
    SM4_FLAG = -march=armv8-a
  else
    CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
  endif

  ifneq ($(ASIMD_FLAG),)
    TPROG = TestPrograms/test_arm_crc.cxx
    TOPT = -march=armv8-a+crc
    HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ACLE_FLAG) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
    ifeq ($(strip $(HAVE_OPT)),0)
      CRC_FLAG = -march=armv8-a+crc
    else
      CXXFLAGS += -DCRYPTOPP_ARM_CRC32_AVAILABLE=0
    endif

    TPROG = TestPrograms/test_arm_aes.cxx
    TOPT = -march=armv8-a+crypto
    HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ACLE_FLAG) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
    ifeq ($(strip $(HAVE_OPT)),0)
      AES_FLAG = -march=armv8-a+crypto
    else
      CXXFLAGS += -DCRYPTOPP_ARM_AES_AVAILABLE=0
    endif

    TPROG = TestPrograms/test_arm_pmull.cxx
    TOPT = -march=armv8-a+crypto
    HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ACLE_FLAG) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
    ifeq ($(strip $(HAVE_OPT)),0)
      GCM_FLAG = -march=armv8-a+crypto
      GF2N_FLAG = -march=armv8-a+crypto
    else
      CXXFLAGS += -DCRYPTOPP_ARM_PMULL_AVAILABLE=0
    endif

    TPROG = TestPrograms/test_arm_sha.cxx
    TOPT = -march=armv8-a+crypto
    HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ACLE_FLAG) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
    ifeq ($(strip $(HAVE_OPT)),0)
      SHA_FLAG = -march=armv8-a+crypto
    else
      CXXFLAGS += -DCRYPTOPP_ARM_SHA_AVAILABLE=0
    endif

    TPROG = TestPrograms/test_arm_sm3.cxx
    TOPT = -march=armv8.4-a+crypto
    HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ACLE_FLAG) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
    ifeq ($(strip $(HAVE_OPT)),0)
      SM3_FLAG = -march=armv8.4-a+crypto
      SM4_FLAG = -march=armv8.4-a+crypto
    endif

    TPROG = TestPrograms/test_arm_sha3.cxx
    TOPT = -march=armv8.4-a+crypto
    HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ACLE_FLAG) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
    ifeq ($(strip $(HAVE_OPT)),0)
      SHA3_FLAG = -march=armv8.4-a+crypto
    endif

  # ASIMD_FLAG
  endif

# IS_ARMV8
endif

# DETECT_FEATURES
endif

# IS_ARM32, IS_ARMV8
endif

###########################################################
#####                     PowerPC                     #####
###########################################################

# PowerPC and PowerPC-64. Altivec is available with POWER4 with GCC and
# POWER6 with XLC. The tests below are crafted for IBM XLC and the LLVM
# front-end. XLC/LLVM only supplies POWER8 so we have to set the flags for
# XLC/LLVM to POWER8. I've got a feeling LLVM is going to cause trouble.
ifneq ($(IS_PPC32)$(IS_PPC64),00)
ifeq ($(DETECT_FEATURES),1)

  ifeq ($(XLC_COMPILER),1)
    POWER9_FLAG = -qarch=pwr9 -qaltivec
    POWER8_FLAG = -qarch=pwr8 -qaltivec
    POWER7_FLAG = -qarch=pwr7 -qaltivec
    POWER6_FLAG = -qarch=pwr6 -qaltivec
    POWER5_FLAG = -qarch=pwr5 -qaltivec
    POWER4_FLAG = -qarch=pwr4 -qaltivec
    ALTIVEC_FLAG = -qaltivec
  else
    POWER9_FLAG = -mcpu=power9 -maltivec
    POWER8_FLAG = -mcpu=power8 -maltivec
    POWER7_FLAG = -mcpu=power7 -maltivec
    ALTIVEC_FLAG = -maltivec
  endif

  # XLC with LLVM front-ends failed to define XLC defines.
  #ifeq ($(findstring -qxlcompatmacros,$(CXXFLAGS)),)
  #  TPROG = TestPrograms/test_ppc_altivec.cxx
  #  TOPT = -qxlcompatmacros
  #  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  #  ifeq ($(strip $(HAVE_OPT)),0)
  #    CXXFLAGS += -qxlcompatmacros
  #  endif
  #endif

  #####################################################################
  # Looking for a POWER8 option

  TPROG = TestPrograms/test_ppc_power9.cxx
  TOPT = $(POWER9_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    # DARN_FLAG = $(POWER9_FLAG)
  else
    POWER9_FLAG =
  endif

  TPROG = TestPrograms/test_ppc_power8.cxx
  TOPT = $(POWER8_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    AES_FLAG = $(POWER8_FLAG)
    ARIA_FLAG = $(POWER8_FLAG)
    BLAKE2B_FLAG = $(POWER8_FLAG)
    BLAKE2S_FLAG = $(POWER8_FLAG)
    CHACHA_FLAG = $(POWER8_FLAG)
    CHAM_FLAG = $(POWER8_FLAG)
    CRC_FLAG = $(POWER8_FLAG)
    GCM_FLAG = $(POWER8_FLAG)
    GF2N_FLAG = $(POWER8_FLAG)
    LEA_FLAG = $(POWER8_FLAG)
    SHA_FLAG = $(POWER8_FLAG)
    SHACAL2_FLAG = $(POWER8_FLAG)
    SIMECK_FLAG = $(POWER8_FLAG)
    SIMON64_FLAG = $(POWER8_FLAG)
    SPECK64_FLAG = $(POWER8_FLAG)
    SIMON128_FLAG = $(POWER8_FLAG)
    SPECK128_FLAG = $(POWER8_FLAG)
  else
    POWER8_FLAG =
  endif

  #####################################################################
  # Looking for a POWER7 option

  TPROG = TestPrograms/test_ppc_power7.cxx
  TOPT = $(POWER7_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifneq ($(strip $(HAVE_OPT)),0)
    POWER7_FLAG =
  endif

  #####################################################################
  # Looking for an Altivec option

  TPROG = TestPrograms/test_ppc_altivec.cxx
  TOPT = $(ALTIVEC_FLAG)
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifneq ($(strip $(HAVE_OPT)),0)
    ALTIVEC_FLAG =
  endif

  # XLC fixup
  ifeq ($(XLC_COMPILER)$(ALTIVEC_FLAG),1)
    TPROG = TestPrograms/test_ppc_altivec.cxx
    TOPT = $(POWER4_FLAG)
    HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
    ifeq ($(strip $(HAVE_OPT)),0)
      ALTIVEC_FLAG = $(POWER4_FLAG)
    else
      TPROG = TestPrograms/test_ppc_altivec.cxx
      TOPT = $(POWER5_FLAG)
      HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
      ifeq ($(strip $(HAVE_OPT)),0)
        ALTIVEC_FLAG = $(POWER5_FLAG)
      else
        TPROG = TestPrograms/test_ppc_altivec.cxx
        TOPT = $(POWER6_FLAG)
        HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
        ifeq ($(strip $(HAVE_OPT)),0)
          ALTIVEC_FLAG = $(POWER6_FLAG)
        else
          ALTIVEC_FLAG =
        endif
      endif
    endif
  endif

  #####################################################################
  # Fixups for algorithms that can drop to a lower ISA, if needed

  # Drop to Power4 if Power8 not available
  ifeq ($(POWER8_FLAG),)
    ifneq ($(ALTIVEC_FLAG),)
      BLAKE2S_FLAG = $(ALTIVEC_FLAG)
      CHACHA_FLAG = $(ALTIVEC_FLAG)
      GCM_FLAG = $(ALTIVEC_FLAG)
      SIMON64_FLAG = $(ALTIVEC_FLAG)
      SPECK64_FLAG = $(ALTIVEC_FLAG)
    endif
  endif

  #####################################################################
  # Fixups for missing ISAs

  ifeq ($(ALTIVEC_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_ALTIVEC
  else ifeq ($(POWER8_FLAG)$(POWER7_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_POWER7
  else ifeq ($(POWER8_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_POWER8
  else ifeq ($(POWER9_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_POWER9
  endif

# DETECT_FEATURES
endif

# IBM XL C/C++ compiler
ifeq ($(XLC_COMPILER),1)
  ifeq ($(findstring -qmaxmem,$(CXXFLAGS)),)
    CXXFLAGS += -qmaxmem=-1
  endif
  # http://www-01.ibm.com/support/docview.wss?uid=swg21007500
  ifeq ($(findstring -qrtti,$(CXXFLAGS)),)
    CXXFLAGS += -qrtti
  endif
endif

# IS_PPC32, IS_PPC64
endif

###########################################################
#####                      Common                     #####
###########################################################

# Add -fPIC for targets *except* X86, X32, Cygwin or MinGW
ifeq ($(IS_X86)$(IS_CYGWIN)$(IS_MINGW),000)
  ifeq ($(findstring -fpic,$(CXXFLAGS))$(findstring -fPIC,$(CXXFLAGS)),)
    CXXFLAGS += -fPIC
  endif
endif

# Use -pthread whenever it is available. See http://www.hpl.hp.com/techreports/2004/HPL-2004-209.pdf
#   http://stackoverflow.com/questions/2127797/gcc-significance-of-pthread-flag-when-compiling
ifeq ($(DETECT_FEATURES),1)
 ifeq ($(XLC_COMPILER),1)
  ifeq ($(findstring -qthreaded,$(CXXFLAGS)),)
   TPROG = TestPrograms/test_pthreads.cxx
   TOPT = -qthreaded
   HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
   ifeq ($(strip $(HAVE_OPT)),0)
    CXXFLAGS += -qthreaded
   endif # CXXFLAGS
  endif # qthreaded
 else
  ifeq ($(findstring -pthread,$(CXXFLAGS)),)
   TPROG = TestPrograms/test_pthreads.cxx
   TOPT = -pthread
   HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
   ifeq ($(strip $(HAVE_OPT)),0)
    CXXFLAGS += -pthread
   endif  # CXXFLAGS
  endif  # pthread
 endif  # XLC/GCC and friends
endif  # DETECT_FEATURES

# Remove -fPIC if present. SunCC use -KPIC, and needs the larger GOT table
# https://docs.oracle.com/cd/E19205-01/819-5267/bkbaq/index.html
ifeq ($(SUN_COMPILER),1)
  CXXFLAGS := $(subst -fPIC,-KPIC,$(CXXFLAGS))
  CXXFLAGS := $(subst -fpic,-KPIC,$(CXXFLAGS))
endif

# Remove -fPIC if present. IBM XL C/C++ use -qpic
ifeq ($(XLC_COMPILER),1)
  CXXFLAGS := $(subst -fPIC,-qpic,$(CXXFLAGS))
  CXXFLAGS := $(subst -fpic,-qpic,$(CXXFLAGS))
endif

# Add -xregs=no%appl SPARC. SunCC should not use certain registers in library code.
# https://docs.oracle.com/cd/E18659_01/html/821-1383/bkamt.html
ifeq ($(IS_SUN)$(SUN_COMPILER),11)
  ifneq ($(IS_SPARC32)$(IS_SPARC64),00)
    ifeq ($(findstring -xregs=no%appl,$(CXXFLAGS)),)
      CXXFLAGS += -xregs=no%appl
    endif  # -xregs
  endif  # Sparc
endif  # SunOS

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

# TODO: can we remove this since removing sockets?
#ifneq ($(IS_MINGW),0)
#  LDLIBS += -lws2_32
#endif

# TODO: can we remove this since removing sockets?
#ifneq ($(IS_SUN),0)
#  LDLIBS += -lnsl -lsocket
#endif

ifneq ($(IS_LINUX)$(IS_HURD),00)
  ifeq ($(findstring -fopenmp,$(CXXFLAGS)),-fopenmp)
    ifeq ($(findstring -lgomp,$(LDLIBS)),)
      LDLIBS += -lgomp
    endif # LDLIBS
  endif # OpenMP
endif # IS_LINUX or IS_HURD

# Add -errtags=yes to get the name for a warning suppression
ifneq ($(SUN_COMPILER),0)	# override flags for CC Sun C++ compiler
# Add to all Solaris
CXXFLAGS += -template=no%extdef
SUN_CC10_BUGGY := $(shell $(CXX) -V 2>&1 | $(GREP) -c -E "CC: Sun .* 5\.10 .* (2009|2010/0[1-4])")
ifneq ($(SUN_CC10_BUGGY),0)
# -DCRYPTOPP_INCLUDE_VECTOR_CC is needed for Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21
# and was fixed in May 2010. Remove it if you get "already had a body defined" errors in vector.cc
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
  NATIVE_OPT =

  # Try GCC and compatibles first
  TPROG = TestPrograms/test_cxx.cxx
  TOPT = -march=native
  HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
  ifeq ($(strip $(HAVE_OPT)),0)
    NATIVE_OPT = -march=native
  endif # NATIVE_OPT

  # Try SunCC next
  ifeq ($(NATIVE_OPT),)
    TOPT = -native
    HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
    ifeq ($(strip $(HAVE_OPT)),0)
      NATIVE_OPT = -native
    endif # NATIVE_OPT
  endif

  ifneq ($(NATIVE_OPT),)
    CXXFLAGS += $(NATIVE_OPT)
  endif

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
  TPROG = TestPrograms/test_cxx.cxx
  USING_GLIBCXX := $(shell $(CXX) $(CXXFLAGS) -E $(TPROG) -o $(TOUT) 2>&1 | $(GREP) -i -c "__GLIBCXX__")
  ifneq ($(USING_GLIBCXX),0)
    ifeq ($(HAS_NEWLIB),0)
      ifeq ($(findstring -D_GLIBCXX_DEBUG,$(CXXFLAGS)),)
        CXXFLAGS += -D_GLIBCXX_DEBUG
      endif # CXXFLAGS
    endif # HAS_NEWLIB
  endif # USING_GLIBCXX

  ifeq ($(XLC_COMPILER),1)
   TPROG = TestPrograms/test_cxx.cxx
   TOPT = -qheapdebug -qro
   HAVE_OPT = $(shell $(CXX) $(TCXXFLAGS) $(ZOPT) $(TOPT) $(TPROG) -o $(TOUT) 2>&1 | tr ' ' '\n' | wc -l)
   ifeq ($(strip $(HAVE_OPT)),0)
    CXXFLAGS += -qheapdebug -qro
   endif  # CXXFLAGS
  endif # XLC_COMPILER
endif  # Debug build

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
ifneq ($(IS_LINUX)$(IS_HURD),00)
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
#####                Temp file cleanup                #####
###########################################################

# After this point no more test programs should be run.
# https://github.com/weidai11/cryptopp/issues/738
ifeq ($(findstring /dev/null,$(TOUT)),)
  # $(info TOUT is not /dev/null, cleaning $(TOUT))
  ifeq ($(wildcard $(TOUT)),$(TOUT))
    UNUSED := $(shell $(RM) $(TOUT) 2>/dev/null)
  endif
  ifeq ($(wildcard $(TOUT).dSYM/),$(TOUT).dSYM/)
    UNUSED := $(shell $(RM) -r $(TOUT).dSYM/ 2>/dev/null)
  endif
endif

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
# Avoid iOS. It cannot consume the assembly.
ifeq ($(IS_ARM32),1)
  CRYPTOGAMS_AES_FLAG = -march=armv7-a
  CRYPTOGAMS_AES_FLAG += -Wa,--noexecstack
  SRCS += aes_armv4.S
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
	$(CXX) $(strip $(CXXFLAGS) -DCRYPTOPP_DISABLE_ASM) -MM *.cpp > GNUmakefile.deps

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
	./cryptest.exe b 0.25
	lcov --base-directory . --directory . -c -o cryptest.info
	lcov --remove cryptest.info "adhoc.*" -o cryptest.info
	lcov --remove cryptest.info "fips140.*" -o cryptest.info
	lcov --remove cryptest.info "*test.*" -o cryptest.info
	lcov --remove cryptest.info "/usr/*" -o cryptest.info
	genhtml -o ./TestCoverage/ -t "Crypto++ test coverage" --num-spaces 4 cryptest.info

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
	@-$(RM) -r *.exe.dSYM/ *.dylib.dSYM/
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
	$(CP) cryptest.exe $(DESTDIR)$(BINDIR)
	$(CHMOD) 0755 $(DESTDIR)$(BINDIR)/cryptest.exe
	@-$(MKDIR) $(DESTDIR)$(DATADIR)/cryptopp/TestData
	@-$(MKDIR) $(DESTDIR)$(DATADIR)/cryptopp/TestVectors
	$(CP) TestData/*.dat $(DESTDIR)$(DATADIR)/cryptopp/TestData
	$(CHMOD) 0644 $(DESTDIR)$(DATADIR)/cryptopp/TestData/*.dat
	$(CP) TestVectors/*.txt $(DESTDIR)$(DATADIR)/cryptopp/TestVectors
	$(CHMOD) 0644 $(DESTDIR)$(DATADIR)/cryptopp/TestVectors/*.txt

# A recipe to install only the library, and not cryptest.exe. Also
# see https://github.com/weidai11/cryptopp/issues/653. Some users
# already have a libcryptopp.pc. Install the *.pc file if the file
# is present. If you want one, then issue 'make libcryptopp.pc'.
.PHONY: install-lib
install-lib:
	@-$(MKDIR) $(DESTDIR)$(INCLUDEDIR)/cryptopp
	$(CP) *.h $(DESTDIR)$(INCLUDEDIR)/cryptopp
	$(CHMOD) 0644 $(DESTDIR)$(INCLUDEDIR)/cryptopp/*.h
ifneq ($(wildcard libcryptopp.a),)
	@-$(MKDIR) $(DESTDIR)$(LIBDIR)
	$(CP) libcryptopp.a $(DESTDIR)$(LIBDIR)
	$(CHMOD) 0644 $(DESTDIR)$(LIBDIR)/libcryptopp.a
endif
ifneq ($(wildcard libcryptopp.dylib),)
	@-$(MKDIR) $(DESTDIR)$(LIBDIR)
	$(CP) libcryptopp.dylib $(DESTDIR)$(LIBDIR)
	$(CHMOD) 0755 $(DESTDIR)$(LIBDIR)/libcryptopp.dylib
	-install_name_tool -id $(DESTDIR)$(LIBDIR)/libcryptopp.dylib $(DESTDIR)$(LIBDIR)/libcryptopp.dylib
endif
ifneq ($(wildcard libcryptopp.so$(SOLIB_VERSION_SUFFIX)),)
	@-$(MKDIR) $(DESTDIR)$(LIBDIR)
	$(CP) libcryptopp.so$(SOLIB_VERSION_SUFFIX) $(DESTDIR)$(LIBDIR)
	$(CHMOD) 0755 $(DESTDIR)$(LIBDIR)/libcryptopp.so$(SOLIB_VERSION_SUFFIX)
ifeq ($(HAS_SOLIB_VERSION),1)
	-$(LN) libcryptopp.so$(SOLIB_VERSION_SUFFIX) $(DESTDIR)$(LIBDIR)/libcryptopp.so
	$(LDCONF) $(DESTDIR)$(LIBDIR)
endif
endif
ifneq ($(wildcard libcryptopp.pc),)
	@-$(MKDIR) $(DESTDIR)$(LIBDIR)/pkgconfig
	$(CP) libcryptopp.pc $(DESTDIR)$(LIBDIR)/pkgconfig
	$(CHMOD) 0644 $(DESTDIR)$(LIBDIR)/pkgconfig/libcryptopp.pc
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
	@echo 'Version: 8.2' >> libcryptopp.pc
	@echo 'URL: https://cryptopp.com/' >> libcryptopp.pc
	@echo '' >> libcryptopp.pc
	@echo 'Cflags: -I$${includedir}' >> libcryptopp.pc
	@echo 'Libs: -L$${libdir} -lcryptopp' >> libcryptopp.pc

# This recipe prepares the distro files
TEXT_FILES := *.h *.cpp adhoc.cpp License.txt Readme.txt Install.txt Filelist.txt Doxyfile cryptest* cryptlib* dlltest* cryptdll* *.sln *.s *.S *.vcxproj *.filters cryptopp.rc TestVectors/*.txt TestData/*.dat TestPrograms/*.cxx TestScripts/*.sh TestScripts/*.cmd
EXEC_FILES := GNUmakefile GNUmakefile-cross TestData/ TestVectors/ TestScripts/ TestPrograms/

ifeq ($(wildcard Filelist.txt),Filelist.txt)
DIST_FILES := $(shell cat Filelist.txt)
endif

.PHONY: trim
trim:
ifneq ($(IS_DARWIN),0)
	sed -i '' -e's/[[:space:]]*$$//' *.supp *.txt *.sh .*.yml *.h *.cpp *.asm *.s *.S
	sed -i '' -e's/[[:space:]]*$$//' *.sln *.vcxproj *.filters GNUmakefile GNUmakefile-cross
	sed -i '' -e's/[[:space:]]*$$//' TestData/*.dat TestVectors/*.txt TestPrograms/*.cxx TestScripts/*.*
	make convert
else
	sed -i -e's/[[:space:]]*$$//' *.supp *.txt *.sh .*.yml *.h *.cpp *.asm *.s *.S
	sed -i -e's/[[:space:]]*$$//' *.sln *.vcxproj *.filters GNUmakefile GNUmakefile-cross
	sed -i -e's/[[:space:]]*$$//' TestData/*.dat TestVectors/*.txt TestPrograms/*.cxx TestScripts/*.*
	make convert
endif

.PHONY: convert
convert:
	@-$(CHMOD) 0700 TestVectors/ TestData/ TestPrograms/ TestScripts/
	@-$(CHMOD) 0600 $(TEXT_FILES) *.supp .*.yml *.asm *.s *.zip TestVectors/*.txt TestData/*.dat TestPrograms/*.cxx TestScripts/*.*
	@-$(CHMOD) 0700 $(EXEC_FILES) *.sh *.cmd TestScripts/*.sh TestScripts/*.cmd
	@-$(CHMOD) 0700 *.cmd *.sh GNUmakefile GNUmakefile-cross TestScripts/*.sh
	-unix2dos --keepdate --quiet $(TEXT_FILES) .*.yml *.asm *.cmd TestScripts/*.*
	-dos2unix --keepdate --quiet GNUmakefile* *.supp *.s *.S *.sh *.mapfile TestScripts/*.sh
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
else ifneq ($(IS_LINUX)$(IS_HURD),00)
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
aes_armv4.o : aes_armv4.S
	$(CC) $(strip $(CXXFLAGS) $(CRYPTOGAMS_AES_FLAG) -c) $<

# SSSE3 or NEON available
aria_simd.o : aria_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(ARIA_FLAG) -c) $<

# SSE, NEON or POWER7 available
blake2s_simd.o : blake2s_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(BLAKE2S_FLAG) -c) $<

# SSE, NEON or POWER8 available
blake2b_simd.o : blake2b_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(BLAKE2B_FLAG) -c) $<

# SSE2 or NEON available
chacha_simd.o : chacha_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(CHACHA_FLAG) -c) $<

# AVX2 available
chacha_avx.o : chacha_avx.cpp
	$(CXX) $(strip $(CXXFLAGS) $(CHACHA_AVX2_FLAG) -c) $<

# SSSE3 available
cham_simd.o : cham_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(CHAM_FLAG) -c) $<

# SSE4.2 or ARMv8a available
crc_simd.o : crc_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(CRC_FLAG) -c) $<

# Power9 available
darn.o : darn.cpp
	$(CXX) $(strip $(CXXFLAGS) $(DARN_FLAG) -c) $<

# SSE2 on i686
donna_sse.o : donna_sse.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SSE2_FLAG) -c) $<

# Carryless multiply
gcm_simd.o : gcm_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(GCM_FLAG) -c) $<

# Carryless multiply
gf2n_simd.o : gf2n_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(GF2N_FLAG) -c) $<

# SSSE3 available
keccak_simd.o : keccak_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(KECCAK_FLAG) -c) $<

# SSSE3 available
lea_simd.o : lea_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(LEA_FLAG) -c) $<

# NEON available
neon_simd.o : neon_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(NEON_FLAG) -c) $<

# AltiVec available
ppc_simd.o : ppc_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(ALTIVEC_FLAG) -c) $<

# Power7 available
ppc_power7.o : ppc_power7.cpp
	$(CXX) $(strip $(CXXFLAGS) $(POWER7_FLAG) -c) $<

# Power8 available
ppc_power8.o : ppc_power8.cpp
	$(CXX) $(strip $(CXXFLAGS) $(POWER8_FLAG) -c) $<

# Power9 available
ppc_power9.o : ppc_power9.cpp
	$(CXX) $(strip $(CXXFLAGS) $(POWER9_FLAG) -c) $<

# AESNI or ARMv7a/ARMv8a available
rijndael_simd.o : rijndael_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(AES_FLAG) -c) $<

# SSE4.2/SHA-NI or ARMv8a available
sha_simd.o : sha_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SHA_FLAG) -c) $<

sha3_simd.o : sha3_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SHA3_FLAG) -c) $<

# SSE4.2/SHA-NI or ARMv8a available
shacal2_simd.o : shacal2_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SHA_FLAG) -c) $<

# SSSE3 or NEON available
simeck_simd.o : simeck_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SIMECK_FLAG) -c) $<

# SSE4.1, NEON or POWER7 available
simon64_simd.o : simon64_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SIMON64_FLAG) -c) $<

# SSSE3, NEON or POWER8 available
simon128_simd.o : simon128_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SIMON128_FLAG) -c) $<

# SSE4.1, NEON or POWER7 available
speck64_simd.o : speck64_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SPECK64_FLAG) -c) $<

# SSSE3, NEON or POWER8 available
speck128_simd.o : speck128_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SPECK128_FLAG) -c) $<

# ARMv8.4 available
sm3_simd.o : sm3_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SM3_FLAG) -c) $<

# AESNI available
sm4_simd.o : sm4_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SM4_FLAG) -c) $<

# IBM XLC -O3 optimization bug
ifeq ($(XLC_COMPILER),1)
sm3.o : sm3.cpp
	$(CXX) $(strip $(subst -O3,-O2,$(CXXFLAGS)) -c) $<
donna_32.o : donna_32.cpp
	$(CXX) $(strip $(subst -O3,-O2,$(CXXFLAGS)) -c) $<
donna_64.o : donna_64.cpp
	$(CXX) $(strip $(subst -O3,-O2,$(CXXFLAGS)) -c) $<
endif

# SSE2 on i686
sse_simd.o : sse_simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(SSE2_FLAG) -c) $<

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

validat1.o : validat1.cpp
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
