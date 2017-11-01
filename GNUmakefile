###########################################################
#####        System Attributes and Programs           #####
###########################################################

# Must use Bash
SHELL = bash
# If needed
TMPDIR ?= /tmp
# Used for ARMv7 and NEON.
FP_ABI ?= hard

# Command ard arguments
AR ?= ar
ARFLAGS ?= -cr # ar needs the dash on OpenBSD
RANLIB ?= ranlib

CP ?= cp
MV ?= mv
RM ?= rm -f
CHMOD ?= chmod
MKDIR ?= mkdir
LN ?= ln -sf
LDCONF ?= /sbin/ldconfig -n
UNAME := $(shell uname)

# Solaris provides a non-Posix shell at /usr/bin
ifneq ($(wildcard /usr/xpg4/bin),)
  GREP ?= /usr/xpg4/bin/grep
else
  GREP ?= grep
endif

IS_X86 := $(shell uname -m | $(GREP) -v "64" | $(GREP) -i -c -E "i.86|x86|i86")
IS_X64 := $(shell uname -m | $(GREP) -i -c -E "(_64|d64)")
IS_PPC32 := $(shell uname -m | $(GREP) -i -v "64" | $(GREP) -i -c -E "ppc|power")
IS_PPC64 := $(shell uname -m | $(GREP) -i -c -E "ppc64|power64")
IS_ARM32 := $(shell uname -m | $(GREP) -i -v "64" | $(GREP) -i -c -E 'armhf|arm7l|eabihf')
IS_ARM64 := $(shell uname -m | $(GREP) -i -c 'aarch64')
IS_ARMV8 ?= $(shell uname -m | $(GREP) -i -c -E 'aarch32|aarch64')
IS_NEON ?= $(shell uname -m | $(GREP) -i -c -E 'armv7|armv8|aarch32|aarch64')
IS_SPARC := $(shell uname -m | $(GREP) -i -c "sparc")
IS_SPARC64 := $(shell uname -m | $(GREP) -i -c "sparc64")

IS_AIX := $(shell uname -s | $(GREP) -i -c 'aix')
IS_SUN := $(shell uname -s | $(GREP) -i -c "SunOS")

IS_LINUX := $(shell $(CXX) -dumpmachine 2>/dev/null | $(GREP) -i -c "Linux")
IS_MINGW := $(shell $(CXX) -dumpmachine 2>/dev/null | $(GREP) -i -c "MinGW")
IS_CYGWIN := $(shell $(CXX) -dumpmachine 2>/dev/null | $(GREP) -i -c "Cygwin")
IS_DARWIN := $(shell $(CXX) -dumpmachine 2>/dev/null | $(GREP) -i -c "Darwin")
IS_NETBSD := $(shell $(CXX) -dumpmachine 2>/dev/null | $(GREP) -i -c "NetBSD")

SUN_COMPILER := $(shell $(CXX) -V 2>&1 | $(GREP) -i -c -E 'CC: (Sun|Studio)')
GCC_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -v -E '(llvm|clang)' | $(GREP) -i -c -E '(gcc|g\+\+)')
XLC_COMPILER := $(shell $(CXX) $(CXX) -qversion 2>/dev/null |$(GREP) -i -c "IBM XL")
CLANG_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -i -c -E '(llvm|clang)')
INTEL_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -i -c '\(icc\)')
MACPORTS_COMPILER := $(shell $(CXX) --version 2>/dev/null | $(GREP) -i -c "macports")

# Sun Studio 12.0 provides SunCC 0x0510; and Sun Studio 12.3 provides SunCC 0x0512
SUNCC_510_OR_LATER := $(shell $(CXX) -V 2>&1 | $(GREP) -i -c -E "CC: (Sun|Studio) .* (5\.1[0-9]|5\.[2-9]|6\.)")
SUNCC_511_OR_LATER := $(shell $(CXX) -V 2>&1 | $(GREP) -i -c -E "CC: (Sun|Studio) .* (5\.1[1-9]|5\.[2-9]|6\.)")
SUNCC_512_OR_LATER := $(shell $(CXX) -V 2>&1 | $(GREP) -i -c -E "CC: (Sun|Studio) .* (5\.1[2-9]|5\.[2-9]|6\.)")
SUNCC_513_OR_LATER := $(shell $(CXX) -V 2>&1 | $(GREP) -i -c -E "CC: (Sun|Studio) .* (5\.1[3-9]|5\.[2-9]|6\.)")

# Enable shared object versioning for Linux
HAS_SOLIB_VERSION := $(IS_LINUX)

# Set to 1 if you want to use X32 on X64
IS_X32 ?= 0

# Set to 1 if you used NASM to build rdrand-{x86|x32|x64}
USE_NASM ?= 0

# Fixup for X32
ifeq ($(IS_X32),1)
IS_X86 = 0
IS_X64 = 0
endif

# Fixup SunOS
ifeq ($(IS_SUN),1)
IS_X86 := $(shell isainfo -k 2>/dev/null | $(GREP) -i -c "i386")
IS_X64 := $(shell isainfo -k 2>/dev/null | $(GREP) -i -c "amd64")
endif

# Fixup AIX
ifeq ($(IS_AIX),1)
  # https://www-01.ibm.com/support/docview.wss?uid=swg21256116
  IS_64BIT := $(shell getconf KERNEL_BITMODE | $(GREP) -i -c "64")
  ifeq ($(IS_64BIT),1)
    IS_PPC32 := 0
    IS_PPC64 := 1
  else
    IS_PPC32 := 1
    IS_PPC64 := 0
  endif
endif

# Newlib needs _XOPEN_SOURCE=700 for signals
HAS_NEWLIB := $(shell $(CXX) -x c++ $(CXXFLAGS) -dM -E adhoc.cpp.proto 2>&1 | $(GREP) -i -c "__NEWLIB__")

###########################################################
#####                General Variables                #####
###########################################################

# Base CXXFLAGS used if the user did not specify them
ifeq ($(SUN_COMPILER),1)
  ifeq ($(SUNCC_512_OR_LATER),1)
    CXXFLAGS ?= -DNDEBUG -g3 -xO3
  else
    CXXFLAGS ?= -DNDEBUG -g -xO3
  endif
else
  CXXFLAGS ?= -DNDEBUG -g2 -O3
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

###########################################################
#####               X86/X32/X64 Options               #####
###########################################################

ifneq ($(IS_X86)$(IS_X32)$(IS_X64),000)

# Fixup. Clang reports an error rather than "LLVM assembler" or similar.
ifneq ($(MACPORTS_COMPILER),1)
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
  GAS223_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.2[3-9]|2\.[3-9]|[3-9])")
endif

ICC111_OR_LATER := $(shell $(CXX) --version 2>&1 | $(GREP) -c -E "\(ICC\) ([2-9][0-9]|1[2-9]|11\.[1-9])")

# Add -fPIC for targets *except* X86, X32, Cygwin or MinGW
ifeq ($(IS_X86)$(IS_X32)$(IS_CYGWIN)$(IS_MINGW)$(SUN_COMPILER),00000)
 ifeq ($(findstring -fPIC,$(CXXFLAGS)),)
   CXXFLAGS += -fPIC
 endif
endif

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
ifeq ($(HAVE_GAS)$(GAS223_OR_LATER),10)
CXXFLAGS += -DCRYPTOPP_DISABLE_SHA

endif  # -DCRYPTOPP_DISABLE_SHA
endif  # -DCRYPTOPP_DISABLE_AESNI
endif  # -DCRYPTOPP_DISABLE_SSE4
endif  # -DCRYPTOPP_DISABLE_SSSE3
endif  # -DCRYPTOPP_DISABLE_ASM
endif  # CXXFLAGS

ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
  ifeq ($(IS_X86),1)
    CPU_FLAG = -msse2
  endif
endif
ifeq ($(findstring -DCRYPTOPP_DISABLE_SSSE3,$(CXXFLAGS)),)
  HAVE_SSSE3 = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -mssse3 -dM -E - 2>/dev/null | $(GREP) -i -c __SSSE3__)
  ifeq ($(HAVE_SSSE3),1)
    ARIA_FLAG = -mssse3
    SSSE3_FLAG = -mssse3
  endif
ifeq ($(findstring -DCRYPTOPP_DISABLE_SSE4,$(CXXFLAGS)),)
  HAVE_SSE4 = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -msse4.2 -dM -E - 2>/dev/null | $(GREP) -i -c __SSE4_2__)
  ifeq ($(HAVE_SSE4),1)
    BLAKE2_FLAG = -msse4.2
    CRC_FLAG = -msse4.2
  endif
ifeq ($(findstring -DCRYPTOPP_DISABLE_AESNI,$(CXXFLAGS)),)
  HAVE_CLMUL = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -mssse3 -mpclmul -dM -E - 2>/dev/null | $(GREP) -i -c __PCLMUL__ )
  ifeq ($(HAVE_CLMUL),1)
    GCM_FLAG = -mssse3 -mpclmul
  endif
  HAVE_AES = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -msse4.1 -maes -dM -E - 2>/dev/null | $(GREP) -i -c __AES__)
  ifeq ($(HAVE_AES),1)
    AES_FLAG = -msse4.1 -maes
  endif
ifeq ($(findstring -DCRYPTOPP_DISABLE_SHA,$(CXXFLAGS)),)
  HAVE_SHA = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -msse4.2 -msha -dM -E - 2>/dev/null | $(GREP) -i -c __SHA__)
  ifeq ($(HAVE_SHA),1)
    SHA_FLAG = -msse4.2 -msha
  endif
endif  # -DCRYPTOPP_DISABLE_SHA
endif  # -DCRYPTOPP_DISABLE_AESNI
endif  # -DCRYPTOPP_DISABLE_SSE4
endif  # -DCRYPTOPP_DISABLE_SSSE3

# Begin SunCC
ifeq ($(SUN_COMPILER),1)
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=ssse3 -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal value ignored")
  ifeq ($(COUNT),0)
    SSSE3_FLAG = -xarch=ssse3 -D__SSSE3__=1
    ARIA_FLAG = -xarch=ssse3 -D__SSSE3__=1
    LDFLAGS += -xarch=ssse3
  endif
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=sse4_2 -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal value ignored")
  ifeq ($(COUNT),0)
    BLAKE2_FLAG = -xarch=sse4_2 -D__SSE4_2__=1
    CRC_FLAG = -xarch=sse4_2 -D__SSE4_2__=1
    LDFLAGS += -xarch=sse4_2
  endif
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=aes -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal value ignored")
  ifeq ($(COUNT),0)
    GCM_FLAG = -xarch=aes -D__PCLMUL__=1
    AES_FLAG = -xarch=aes -D__AES__=1
    LDFLAGS += -xarch=aes
  endif
  COUNT := $(shell $(CXX) $(CXXFLAGS) -E -xarch=sha -xdumpmacros /dev/null 2>&1 | $(GREP) -i -c "illegal value ignored")
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

# Tell MacPorts GCC to use Clang integrated assembler
#   http://github.com/weidai11/cryptopp/issues/190
ifeq ($(GCC_COMPILER)$(MACPORTS_COMPILER),11)
  ifeq ($(findstring -Wa,-q,$(CXXFLAGS)),)
    CXXFLAGS += -Wa,-q
  endif
  ifeq ($(findstring -DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER,$(CXXFLAGS)),)
    CLANG_INTEGRATED_ASSEMBLER := 1
    CXXFLAGS += -DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER=1
  endif
endif

# GCC on Solaris needs -m64. Otherwise, i386 is default
#   http://github.com/weidai11/cryptopp/issues/230
HAVE_BITS=$(shell echo $(CXXFLAGS) | $(GREP) -i -c -E '\-m32|\-m64')
ifeq ($(IS_SUN)$(GCC_COMPILER)$(IS_X64)$(HAVE_BITS),1110)
  CXXFLAGS += -m64
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

# Add PIC
ifeq ($(findstring -fPIC,$(CXXFLAGS)),)
  CXXFLAGS += -fPIC
endif

ifeq ($(IS_NEON),1)
  HAVE_NEON = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon -dM -E - 2>/dev/null | $(GREP) -i -c -E '\<__ARM_NEON\>')
  ifeq ($(HAVE_NEON),1)
    NEON_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    GCM_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    ARIA_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
    BLAKE2_FLAG = -march=armv7-a -mfloat-abi=$(FP_ABI) -mfpu=neon
  endif
endif

ifeq ($(IS_ARMV8),1)
  HAVE_NEON = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -march=armv8-a -dM -E - 2>/dev/null | $(GREP) -i -c __ARM_NEON)
  ifeq ($(HAVE_NEON),1)
    ARIA_FLAG = -march=armv8-a
    BLAKE2_FLAG = -march=armv8-a
    NEON_FLAG = -march=armv8-a
  endif
  HAVE_CRC = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -march=armv8-a+crc -dM -E - 2>/dev/null | $(GREP) -i -c __ARM_FEATURE_CRC32)
  ifeq ($(HAVE_CRC),1)
    CRC_FLAG = -march=armv8-a+crc
  endif
  HAVE_CRYPTO = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -march=armv8-a+crypto -dM -E - 2>/dev/null | $(GREP) -i -c __ARM_FEATURE_CRYPTO)
  ifeq ($(HAVE_CRYPTO),1)
    AES_FLAG = -march=armv8-a+crypto
    GCM_FLAG = -march=armv8-a+crypto
    SHA_FLAG = -march=armv8-a+crypto
  endif
endif

# PowerPC and PowerPC-64
# Altivec is available with Power4, but the library is tied to Power7 and unaligned loads/stores.
ifneq ($(IS_PPC32)$(IS_PPC64)$(IS_AIX),000)
  # GCC and some compatibles
  HAVE_ALTIVEC = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -mcpu=power7 -maltivec -dM -E - 2>/dev/null | $(GREP) -i -c '__ALTIVEC__')
  ifneq ($(HAVE_ALTIVEC),0)
    ALTIVEC_FLAG = -mcpu=power7 -maltivec
  endif
  # GCC and some compatibles
  HAVE_CRYPTO = $(shell echo | $(CXX) -x c++ $(CXXFLAGS) -mcpu=power8 -maltivec -dM -E - 2>/dev/null | $(GREP) -i -c -E '_ARCH_PWR8|_ARCH_PWR9|__CRYPTO')
  ifneq ($(HAVE_CRYPTO),0)
    AES_FLAG = -mcpu=power8 -maltivec
    GCM_FLAG = -mcpu=power8 -maltivec
    SHA_FLAG = -mcpu=power8 -maltivec
    ALTIVEC_FLAG = -mcpu=power8 -maltivec
  endif
  # IBM XL C/C++
  HAVE_ALTIVEC = $(shell $(CXX) $(CXXFLAGS) -qshowmacros -qarch=pwr7 -qaltivec -E adhoc.cpp.proto 2>/dev/null | $(GREP) -i -c '__ALTIVEC__')
  ifneq ($(HAVE_ALTIVEC),0)
    ALTIVEC_FLAG = -qarch=pwr7 -qaltivec
  endif
  # IBM XL C/C++
  HAVE_CRYPTO = $(shell $(CXX) $(CXXFLAGS) -qshowmacros -qarch=pwr8 -qaltivec -E adhoc.cpp.proto 2>/dev/null | $(GREP) -i -c -E '_ARCH_PWR8|_ARCH_PWR9|__CRYPTO')
  ifneq ($(HAVE_CRYPTO),0)
    AES_FLAG = -qarch=pwr8 -qaltivec
    GCM_FLAG = -qarch=pwr8 -qaltivec
    SHA_FLAG = -qarch=pwr8 -qaltivec
    ALTIVEC_FLAG = -qarch=pwr8 -qaltivec
  endif
  # Fail safe to disable intrinsics on down level machines, like PowerMac G5
  ifeq ($(ALTIVEC_FLAG),)
    CXXFLAGS += -DCRYPTOPP_DISABLE_ALTIVEC
  endif
endif

# IBM XL C/C++ compiler
ifeq ($(XLC_COMPILER),1)
  # http://www-01.ibm.com/support/docview.wss?uid=swg21007500
  ifeq ($(findstring -qrtti,$(CXXFLAGS)),)
    CXXFLAGS += -qrtti
  endif
  # -fPIC causes link errors dues to unknown option
  ifneq ($(findstring -fPIC,$(CXXFLAGS)),)
      CXXFLAGS := $(CXXFLAGS:-fPIC=-qpic)
  endif
  HAVE_BITS=$(shell echo $(CXXFLAGS) | $(GREP) -i -c -E '\-q32|\-q64')
  ifeq ($(IS_PPC64)$(XLC_COMPILER)$(HAVE_BITS),110)
    CXXFLAGS += -q64
  else
  ifeq ($(IS_PPC32)$(XLC_COMPILER)$(HAVE_BITS),110)
    CXXFLAGS += -q32
  endif
  endif
  ifeq ($(findstring -q64,$(CXXFLAGS)),-q64)
    ifeq ($(findstring -X64,$(ARFLAGS)),)
      ARFLAGS := -r -X64
    endif
  else
  ifeq ($(findstring -q32,$(CXXFLAGS)),-q32)
    ifeq ($(findstring -X32,$(ARFLAGS)),)
      ARFLAGS := -r -X32
    endif
  endif
  endif
endif

endif  # X86, X64, ARM32, ARM64, PPC32, PPC64, etc

###########################################################
#####                      Common                     #####
###########################################################

# Use -pthread whenever it is available. See http://www.hpl.hp.com/techreports/2004/HPL-2004-209.pdf
#   http://stackoverflow.com/questions/2127797/gcc-significance-of-pthread-flag-when-compiling
ifneq ($(IS_LINUX)$(GCC_COMPILER)$(CLANG_COMPILER)$(INTEL_COMPILER),0000)
  CXXFLAGS += -pthread
endif # CXXFLAGS

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
  ifneq ($(IS_X86)$(IS_X32)$(IS_X64),000)
    ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
      LDFLAGS += -M cryptest.mapfile
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

ifneq ($(IS_DARWIN),0)
  AR = libtool
  ARFLAGS = -static -o
  CXX ?= c++
endif

# Add -errtags=yes to get the name for a warning suppression
ifneq ($(SUN_COMPILER),0)	# override flags for CC Sun C++ compiler
IS_64 := $(shell isainfo -b 2>/dev/null | $(GREP) -i -c "64")
HAVE_BITS=$(shell echo $(CXXFLAGS) | $(GREP) -i -c -E '\-m32|\-m64')
ifeq ($(IS_64)$(HAVE_BITS),10)
CXXFLAGS += -m64
else ifeq ($(IS_64)$(HAVE_BITS),00)
CXXFLAGS += -m32
endif
# Add for non-i386
ifneq ($(IS_X86),1)
CXXFLAGS += -KPIC
endif
# Add to all Solaris
CXXFLAGS += -template=no%extdef
# http://github.com/weidai11/cryptopp/issues/403
ifneq ($(IS_SPARC)$(IS_SPARC64),00)
CXXFLAGS += -xmemalign=4i
endif
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
    ELF_FORMAT := $(shell file `which ld.gold` 2>&1 | cut -d":" -f 2 | $(GREP) -i -c "elf")
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
  USING_GLIBCXX := $(shell $(CXX) -x c++ $(CXXFLAGS) -E adhoc.cpp.proto 2>&1 | $(GREP) -i -c "__GLIBCXX__")
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
# Full version suffix for shared library
SOLIB_VERSION_SUFFIX=.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)
# Different patchlevels are compatible, minor versions are not
SOLIB_COMPAT_SUFFIX=.$(LIB_MAJOR).$(LIB_MINOR)
SOLIB_FLAGS=-Wl,-soname,libcryptopp.so$(SOLIB_COMPAT_SUFFIX)
endif # HAS_SOLIB_VERSION

###########################################################
#####              Source and object files            #####
###########################################################

# List cryptlib.cpp first, then cpu.cpp, then integer.cpp to tame C++ static initialization problems.
SRCS := cryptlib.cpp cpu.cpp integer.cpp $(filter-out cryptlib.cpp cpu.cpp integer.cpp pch.cpp simple.cpp winpipes.cpp cryptlib_bds.cpp,$(sort $(wildcard *.cpp)))
# For Makefile.am; resource.h is Windows
INCL := $(filter-out resource.h,$(sort $(wildcard *.h)))

ifneq ($(IS_MINGW),0)
SRCS += winpipes.cpp
INCL += resource.h
endif

# List cryptlib.cpp first, then cpu.cpp, then integer.cpp to tame C++ static initialization problems.
OBJS := $(SRCS:.cpp=.o)

ifeq ($(USE_NASM),1)
ifeq ($(IS_X64),1)
OBJS += rdrand-x64.o
else ifeq ($(IS_X32),1)
OBJS += rdrand-x32.o
else ifeq ($(IS_X86),1)
OBJS += rdrand-x86.o
endif
endif # Nasm

# List test.cpp first to tame C++ static initialization problems.
TESTSRCS := adhoc.cpp test.cpp bench1.cpp bench2.cpp validat0.cpp validat1.cpp validat2.cpp validat3.cpp datatest.cpp regtest1.cpp regtest2.cpp regtest3.cpp dlltest.cpp fipsalgt.cpp
TESTINCL := bench.h factory.h validate.h
# Test objects
TESTOBJS := $(TESTSRCS:.cpp=.o)
LIBOBJS := $(filter-out $(TESTOBJS),$(OBJS))

# List cryptlib.cpp first, then cpu.cpp, then integer.cpp to tame C++ static initialization problems.
DLLSRCS :=  cryptlib.cpp cpu.cpp integer.cpp 3way.cpp adler32.cpp algebra.cpp algparam.cpp arc4.cpp aria-simd.cpp aria.cpp ariatab.cpp asn.cpp authenc.cpp base32.cpp base64.cpp basecode.cpp bfinit.cpp blake2-simd.cpp blake2.cpp blowfish.cpp blumshub.cpp camellia.cpp cast.cpp casts.cpp cbcmac.cpp ccm.cpp chacha.cpp channels.cpp cmac.cpp crc-simd.cpp crc.cpp default.cpp des.cpp dessp.cpp dh.cpp dh2.cpp dll.cpp dsa.cpp eax.cpp ec2n.cpp eccrypto.cpp ecp.cpp elgamal.cpp emsa2.cpp eprecomp.cpp esign.cpp files.cpp filters.cpp fips140.cpp fipstest.cpp gcm-simd.cpp gcm.cpp gf256.cpp gf2_32.cpp gf2n.cpp gfpcrypt.cpp gost.cpp gzip.cpp hex.cpp hmac.cpp hrtimer.cpp ida.cpp idea.cpp iterhash.cpp kalyna.cpp kalynatab.cpp keccak.cpp luc.cpp mars.cpp marss.cpp md2.cpp md4.cpp md5.cpp misc.cpp modes.cpp mqueue.cpp mqv.cpp nbtheory.cpp neon-simd.cpp network.cpp oaep.cpp ospstore.cpp osrng.cpp panama.cpp pkcspad.cpp poly1305.cpp polynomi.cpp pssr.cpp pubkey.cpp queue.cpp rabin.cpp randpool.cpp rc2.cpp rc5.cpp rc6.cpp rdrand.cpp rdtables.cpp rijndael.cpp ripemd.cpp rng.cpp rsa.cpp rw.cpp safer.cpp salsa.cpp seal.cpp seed.cpp serpent.cpp sha-simd.cpp sha.cpp sha3.cpp shacal2-simd.cpp shacal2.cpp shark.cpp sharkbox.cpp skipjack.cpp socketft.cpp sosemanuk.cpp square.cpp squaretb.cpp strciphr.cpp tea.cpp tftables.cpp threefish.cpp tiger.cpp tigertab.cpp trdlocal.cpp ttmac.cpp twofish.cpp vmac.cpp wait.cpp wake.cpp whrlpool.cpp xtr.cpp xtrcrypt.cpp zdeflate.cpp zinflate.cpp zlib.cpp

DLLOBJS := $(DLLSRCS:.cpp=.export.o)

# Import lib testing
LIBIMPORTOBJS := $(LIBOBJS:.o=.import.o)
TESTIMPORTOBJS := $(TESTOBJS:.o=.import.o)
DLLTESTOBJS := dlltest.dllonly.o

###########################################################
#####                Targets and Recipes              #####
###########################################################

.PHONY: all
all: cryptest.exe

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
native no-asm asan ubsan: libcryptopp.a cryptest.exe

# CXXFLAGS are tuned earlier. Applications must use linker flags
#  -Wl,--gc-sections (Linux and Unix) or -Wl,-dead_strip (OS X)
.PHONY: lean
lean: static dynamic cryptest.exe

# May want to export CXXFLAGS="-g3 -O1"
.PHONY: lcov coverage
lcov coverage: libcryptopp.a cryptest.exe
	@-$(RM) -r ./TestCoverage/
	lcov --base-directory . --directory . --zerocounters -q
	./cryptest.exe v
	./cryptest.exe tv all
	lcov --base-directory . --directory . -c -o cryptest.info
	lcov --remove cryptest.info "adhoc.cpp" "wait.*" "network.*" "socketft.*" "fips140.*" "*test.*" "bench*.cpp" "validat*.*" "/usr/*" -o cryptest.info
	genhtml -o ./TestCoverage/ -t "cryptest.exe test coverage" --num-spaces 4 cryptest.info

# Travis CI and CodeCov rule
.PHONY: gcov codecov
gcov codecov: libcryptopp.a cryptest.exe
	@-$(RM) -r ./TestCoverage/
	./cryptest.exe v
	./cryptest.exe tv all
	gcov -r $(SRCS)

# Should use CXXFLAGS="-g3 -O1"
.PHONY: valgrind
valgrind: libcryptopp.a cryptest.exe
	valgrind ./cryptest.exe v

.PHONY: test check
test check: cryptest.exe
	./cryptest.exe v

# Used to generate list of source files for Autotools, CMakeList, Android.mk, etc
.PHONY: sources
sources: adhoc.cpp
	$(info Library sources: $(filter-out $(TESTSRCS),$(SRCS)))
	$(info )
	$(info Library headers: $(filter-out $(TESTINCL),$(INCL)))
	$(info )
	$(info Test sources: $(TESTSRCS))
	$(info )
	$(info Test headers: $(TESTINCL))

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
	@-$(RM) *.gcov *.gcno *.gcda *.stackdump core core-*
	@-$(RM) /tmp/adhoc.exe
	@-$(RM) -r /tmp/cryptopp_test/
	@-$(RM) -r *.exe.dSYM/
	@-$(RM) -r *.dylib.dSYM/
	@-$(RM) -r cov-int/

.PHONY: distclean
distclean: clean
	-$(RM) adhoc.cpp adhoc.cpp.copied GNUmakefile.deps benchmarks.html cryptest.txt cryptest-*.txt
	@-$(RM) cryptopp.tgz *.o *.bc *.ii *~
	@-$(RM) -r $(SRCS:.cpp=.obj) cryptlib.lib cryptest.exe *.suo *.sdf *.pdb Win32/ x64/ ipch/
	@-$(RM) -r $(DOCUMENT_DIRECTORY)/
	@-$(RM) -f configure.ac configure Makefile.am Makefile *.m4 local.* lt*.sh missing libtool
	@-$(RM) -f config.guess config.status config.sub depcomp install-sh compile stamp-h1
	@-$(RM) -rf m4/ auto*.cache/ .deps/
	@-$(RM) -r TestCoverage/
	@-$(RM) cryptopp$(LIB_VER)\.*
	@-$(RM) CryptoPPRef.zip

.PHONY: install
install:
	@-$(MKDIR) -p $(DESTDIR)$(INCLUDEDIR)/cryptopp
	$(CP) *.h $(DESTDIR)$(INCLUDEDIR)/cryptopp
	-$(CHMOD) 0755 $(DESTDIR)$(INCLUDEDIR)/cryptopp
	-$(CHMOD) 0644 $(DESTDIR)$(INCLUDEDIR)/cryptopp/*.h
ifneq ($(wildcard libcryptopp.a),)
	@-$(MKDIR) -p $(DESTDIR)$(LIBDIR)
	$(CP) libcryptopp.a $(DESTDIR)$(LIBDIR)
	-$(CHMOD) 0644 $(DESTDIR)$(LIBDIR)/libcryptopp.a
endif
ifneq ($(wildcard cryptest.exe),)
	@-$(MKDIR) -p $(DESTDIR)$(BINDIR)
	$(CP) cryptest.exe $(DESTDIR)$(BINDIR)
	-$(CHMOD) 0755 $(DESTDIR)$(BINDIR)/cryptest.exe
	$(MKDIR) -p $(DESTDIR)$(DATADIR)/cryptopp
	$(CP) -r TestData $(DESTDIR)$(DATADIR)/cryptopp
	$(CP) -r TestVectors $(DESTDIR)$(DATADIR)/cryptopp
	-$(CHMOD) 0755 $(DESTDIR)$(DATADIR)/cryptopp
	-$(CHMOD) 0755 $(DESTDIR)$(DATADIR)/cryptopp/TestData
	-$(CHMOD) 0755 $(DESTDIR)$(DATADIR)/cryptopp/TestVectors
	-$(CHMOD) 0644 $(DESTDIR)$(DATADIR)/cryptopp/TestData/*.dat
	-$(CHMOD) 0644 $(DESTDIR)$(DATADIR)/cryptopp/TestVectors/*.txt
endif
ifneq ($(wildcard libcryptopp.dylib),)
	@-$(MKDIR) -p $(DESTDIR)$(LIBDIR)
	$(CP) libcryptopp.dylib $(DESTDIR)$(LIBDIR)
	-install_name_tool -id $(DESTDIR)$(LIBDIR)/libcryptopp.dylib $(DESTDIR)$(LIBDIR)/libcryptopp.dylib
	-$(CHMOD) 0755 $(DESTDIR)$(LIBDIR)/libcryptopp.dylib
endif
ifneq ($(wildcard libcryptopp.so$(SOLIB_VERSION_SUFFIX)),)
	@-$(MKDIR) -p $(DESTDIR)$(LIBDIR)
	$(CP) libcryptopp.so$(SOLIB_VERSION_SUFFIX) $(DESTDIR)$(LIBDIR)
	@-$(CHMOD) 0755 $(DESTDIR)$(LIBDIR)/libcryptopp.so$(SOLIB_VERSION_SUFFIX)
ifeq ($(HAS_SOLIB_VERSION),1)
	-$(LN) -sf libcryptopp.so$(SOLIB_VERSION_SUFFIX) $(DESTDIR)$(LIBDIR)/libcryptopp.so
	$(LDCONF) $(DESTDIR)$(LIBDIR)
endif
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
	$(CXX) -shared $(SOLIB_FLAGS) -o $@ $(strip $(CXXFLAGS)) $(PIC_FLAG) $(LDFLAGS) $(LIBOBJS) $(LDLIBS)
endif
ifeq ($(HAS_SOLIB_VERSION),1)
	-$(LN) libcryptopp.so$(SOLIB_VERSION_SUFFIX) libcryptopp.so
	-$(LN) libcryptopp.so$(SOLIB_VERSION_SUFFIX) libcryptopp.so$(SOLIB_COMPAT_SUFFIX)
endif

libcryptopp.dylib: $(LIBOBJS)
	$(CXX) -dynamiclib -o $@ $(strip $(CXXFLAGS)) -install_name "$@" -current_version "$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)" -compatibility_version "$(LIB_MAJOR).$(LIB_MINOR)" -headerpad_max_install_names $(LDFLAGS) $(LIBOBJS)

cryptest.exe: libcryptopp.a $(TESTOBJS)
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

# This recipe prepares the distro files
TEXT_FILES := *.h *.cpp adhoc.cpp.proto License.txt Readme.txt Install.txt Filelist.txt Doxyfile cryptest* cryptlib* dlltest* cryptdll* *.sln *.vcxproj *.filters cryptopp.rc TestVectors/*.txt TestData/*.dat TestScripts/*.sh TestScripts/*.pl TestScripts/*.cmd
EXEC_FILES := GNUmakefile GNUmakefile-cross TestData/ TestVectors/ TestScripts/

ifeq ($(wildcard Filelist.txt),Filelist.txt)
DIST_FILES := $(shell cat Filelist.txt)
endif

.PHONY: trim
trim:
ifneq ($(IS_DARWIN),0)
	sed -i '' -e's/[[:space:]]*$$//' *.txt *.sh .*.yml *.h *.cpp *.asm *.s *.sln *.vcxproj *.filters GNUmakefile GNUmakefile-cross
	sed -i '' -e's/[[:space:]]*$$//' TestData/*.dat TestVectors/*.txt TestScripts/*.*
	make convert
else
	sed -i -e's/[[:space:]]*$$//' *.txt *.sh .*.yml *.h *.cpp *.asm *.s *.sln *.vcxproj *.filters GNUmakefile GNUmakefile-cross
	sed -i -e's/[[:space:]]*$$//' TestData/*.dat TestVectors/*.txt TestScripts/*.*
	make convert
endif

.PHONY: convert
convert:
	@-$(CHMOD) 0700 TestVectors/ TestData/ TestScripts/
	@-$(CHMOD) 0600 $(TEXT_FILES) .*.yml *.asm *.s *.zip TestVectors/*.txt TestData/*.dat TestScripts/*.*
	@-$(CHMOD) 0700 $(EXEC_FILES) *.sh *.cmd TestScripts/*.sh TestScripts/*.pl TestScripts/*.cmd
	@-$(CHMOD) 0700 *.cmd *.sh GNUmakefile GNUmakefile-cross TestScripts/*.sh TestScripts/*.pl
	-unix2dos --keepdate --quiet $(TEXT_FILES) .*.yml *.asm *.cmd TestScripts/*.*
	-dos2unix --keepdate --quiet GNUmakefile GNUmakefile-cross *.s *.sh *.mapfile TestScripts/*.sh
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
	$(MKDIR) -p $(PWD)/cryptopp$(LIB_VER)
	$(CP) cryptopp$(LIB_VER).zip $(PWD)/cryptopp$(LIB_VER)
	hdiutil makehybrid -iso -joliet -o cryptopp$(LIB_VER).iso $(PWD)/cryptopp$(LIB_VER)
	@-$(RM) -r $(PWD)/cryptopp$(LIB_VER)
else ifneq ($(IS_LINUX),0)
	$(MKDIR) -p $(PWD)/cryptopp$(LIB_VER)
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

# Run rdrand-nasm.sh to create the object files
ifeq ($(USE_NASM),1)
rdrand.o: rdrand.h rdrand.cpp rdrand.s
	$(CXX) $(strip $(CXXFLAGS) -DNASM_RDRAND_ASM_AVAILABLE=1 -DNASM_RDSEED_ASM_AVAILABLE=1 -c rdrand.cpp)
rdrand-%.o:
	./rdrand-nasm.sh
endif

# SSE4.2 or NEON available
aria-simd.o : aria-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(ARIA_FLAG) -c) $<

# SSE4.2 or ARMv8a available
blake2-simd.o : blake2-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(BLAKE2_FLAG) -c) $<

# SSE2 on i586
cpu.o : cpu.cpp
	$(CXX) $(strip $(CXXFLAGS) $(CPU_FLAG) -c) $<

# SSE4.2 or ARMv8a available
crc-simd.o : crc-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(CRC_FLAG) -c) $<

# PCLMUL or ARMv7a/ARMv8a available
gcm-simd.o : gcm-simd.cpp
	$(CXX) $(strip $(CXXFLAGS) $(GCM_FLAG) -c) $<

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

# Don't build Threefish with UBsan on Travis CI. Timeouts cause the build to fail.
#   Also see http://stackoverflow.com/q/12983137/608639.
ifeq ($(findstring true,$(CI)),true)
threefish.o : threefish.cpp
	$(CXX) $(strip $(subst -fsanitize=undefined,,$(CXXFLAGS)) -c) $<
endif

# Don't build Rijndael with UBsan. Too much noise due to unaligned data accesses.
ifneq ($(findstring -fsanitize=undefined,$(CXXFLAGS)),)
rijndael.o : rijndael.cpp
	$(CXX) $(strip $(subst -fsanitize=undefined,,$(CXXFLAGS)) -c) $<
endif

# Don't build VMAC and friends with Asan. Too many false positives.
ifneq ($(findstring -fsanitize=address,$(CXXFLAGS)),)
vmac.o : vmac.cpp
	$(CXX) $(strip $(subst -fsanitize=address,,$(CXXFLAGS)) -c) $<
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
