#################################################################
# Tool and flag setup

AS ?= as
AR ?= ar
ARFLAGS ?= -cr	# ar needs the dash on OpenBSD
RANLIB ?= ranlib
STRIP ?= strip -s
CP ?= cp
MKDIR ?= mkdir
EGREP ?= egrep
UNAME ?= uname

#########################
# CXXFLAGS
CXXFLAGS ?= -DNDEBUG -g2 -O3
# -fPIC is supported, and enabled by default for x86_64.

# the following options reduce code size, but breaks link or makes link very slow on some systems
# CXXFLAGS += -ffunction-sections -fdata-sections
# LDFLAGS += -Wl,--gc-sections

#########################
# Compilers
CLANG_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c "clang")
INTEL_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c "\(ICC\)")
SUN_COMPILER = $(shell $(CXX) -V 2>&1 | $(EGREP) -i -c "CC: Sun")

# Also see LLVM Bug 24200 (https://llvm.org/bugs/show_bug.cgi?id=24200)
# CLANG_ASSEMBLER ?= $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(EGREP) -i -c "^clang")
# TODO: Uncomment the line above when Clang's integrated assembler can parse and generate code that passes the self tests.

#################################################################
# Platform detection

IS_X86 = $(shell uname -m | $(EGREP) -c "i.86|x86|i86|amd64")
IS_X86_64 = $(shell uname -m | $(EGREP) -c "_64|d64")
IS_DARWIN = $(shell uname -s | $(EGREP) -i -c "darwin")
IS_LINUX = $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "linux")
IS_MINGW = $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "mingw")
IS_CYGWIN = $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "cygwin")
IS_OPENBSD = $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "openbsd")
IS_SUN = $(shell uname -s | $(EGREP) -i -c "SunOS")
IS_FEDORA22_i686 = $(shell uname -r | $(EGREP) -i -c "fc22.i686")

#################################################################
# Architecture detection

#########################
# May (or may not) be used below
ifeq ($(findstring -m32 -m64,$(CXXFLAGS)),)
ifneq ($(IS_X86_64),0)
M32OR64 = -m64
endif
endif # -m32 or -m64

#################################################################
# User install preferences

# Pick up the user's choice (lower prefix is the standard name)
ifneq ($(prefix),)
PREFIX = $(prefix)
else

# Default prefix for make install
ifeq ($(PREFIX),)
PREFIX = /usr
endif

# Can't put C++ headers in system include
ifneq ($(IS_OPENBSD),0)
PREFIX = /usr/local
endif

endif	# prefix

#################################################################
# Undefined behavior and Address sanitizer
#   Clang 3.2 and GCC 4.8 and above, i386/i686/x86_64

ifneq ($(IS_X86),0)

# Undefined Behavior Sanitizer (UBsan)
ifeq ($(findstring ubsan,$(MAKECMDGOALS)),ubsan)
CXXFLAGS += -fsanitize=undefined
# CXXFLAGS += -fsanitize-undefined-trap-on-error
endif # UBsan

# Address Sanitizer (Asan)
ifeq ($(findstring asan,$(MAKECMDGOALS)),asan)
CXXFLAGS += -fsanitize=address
endif # Asan

# Test CXXFLAGS in case the user passed the flags directly through it
ifeq ($(findstring -fsanitize=address,$(CXXFLAGS)),-fsanitize=address)
ASAN = 1
endif
ifeq ($(findstring -fsanitize=undefined,$(CXXFLAGS)),-fsanitize=undefined)
UBSAN = 1
endif

# Enforce Sanitizer business logic...
ifeq ($(ASAN)$(UBSAN),11)
$(error Asan and UBsan are mutually exclusive)
endif

endif # IS_X86

#################################################################
# Darwin tweaks

ifneq ($(IS_DARWIN),0)

CXX ?= c++
ifeq ($(AR),ar)
AR = libtool
ARFLAGS = -static -o
endif

#########################
# Build a boolean circuit that says "Darwin && (GCC 4.2 || Clang)"
# MULTIARCH ?= $(shell echo $$(($(IS_DARWIN) * ($(GCC42_OR_LATER) + $(CLANG_COMPILER)))))
MULTIARCH ?= 0
ifneq ($(MULTIARCH),0)
CXXFLAGS += -arch i386 -arch x86_64
endif # MULTIARCH

endif # IS_DARWIN

#################################################################
# i386, i686, x86_64 and friends

ifneq ($(IS_X86),0)

GCC42_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c "^gcc version (4.[2-9]|[5-9])")
ICC111_OR_LATER = $(shell $(CXX) --version 2>&1 | $(EGREP) -c "\(ICC\) ([2-9][0-9]|1[2-9]|11\.[1-9])")

# Using system provided assembler. It may be GNU AS (GAS).
GAS210_OR_LATER ?= $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(EGREP) -c "GNU assembler version (2\.[1-9][0-9]|[3-9])")
GAS217_OR_LATER ?= $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(EGREP) -c "GNU assembler version (2\.1[7-9]|2\.[2-9]|[3-9])")
GAS219_OR_LATER ?= $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(EGREP) -c "GNU assembler version (2\.19|2\.[2-9]|[3-9])")

# For testing and development. If CXX=clang++, then it effectively
#   enables ASM code paths and engages the integrated assembler.
FORCE_ASM ?= 0
ifneq ($(FORCE_ASM),0)
  GAS210_OR_LATER = 1
  GAS217_OR_LATER = 1
  GAS219_OR_LATER = 1
endif

# Enable PIC for x86_64 targets
ifneq ($(IS_X86_64),0)
CXXFLAGS += -fPIC
endif # PIC for x86_64 targets

#########################
# Cygwin work arounds
ifneq ($(IS_CYGWIN),0)

# CXX is gcc on Cygwin 1.1.4
ifeq ($(CXX),gcc)
CXX = g++
endif # CXX

# -fPIC causes spurious output during compile. Remove it even if the user passed it in.
ifeq ($(findstring -fPIC,$(CXXFLAGS)),-fPIC)
CXXFLAGS := $(subst -fPIC,,$(CXXFLAGS))
endif # -fPIC

# -O3 fails to link with GCC 4.5.3
IS_GCC45 = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c "^gcc version 4\.5\.[0-9]")
ifneq ($(IS_GCC45),0)
ifeq ($(findstring -O3,$(CXXFLAGS)),-O3)
CXXFLAGS := $(subst -O3,-O2,$(CXXFLAGS))
endif # -O3
endif # GCC 4.5

endif # Cygwin work arounds

#########################
# F22/i386 crash
ifneq ($(IS_FEDORA22_i686),0)
ifeq ($(findstring -O3,$(CXXFLAGS)),-O3)
CXXFLAGS := $(subst -O3,-O2,$(CXXFLAGS))
endif # -O2
endif # Fedora 22/i686

#########################
# Original Crypto++ code. Way back when, this caused a compiler crash with GCC on Ubuntu 9 or 10
ifeq ($(findstring -m32 -m64,$(CXXFLAGS)),)
CXXFLAGS += -march=native
endif

#########################
# Intel work arounds.
# Should this be moved to outside of i386/i686/x86_64 block?
ifneq ($(INTEL_COMPILER),0)
CXXFLAGS += -wd68 -wd186 -wd279 -wd327
ifeq ($(ICC111_OR_LATER),0)
# "internal error: backend signals" occurs on some x86 inline assembly with ICC 9 and some x64 inline assembly with ICC 11.0
# if you want to use Crypto++'s assembly code with ICC, try enabling it on individual files
CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
endif
endif

#########################
# GAS work arounds.
# Should this be moved to outside of i386/i686/x86_64 block?
ifeq ($(GAS210_OR_LATER),0)
CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
else
ifeq ($(GAS217_OR_LATER),0)
CXXFLAGS += -DCRYPTOPP_DISABLE_SSSE3
else
ifeq ($(GAS219_OR_LATER),0)
CXXFLAGS += -DCRYPTOPP_DISABLE_AESNI
endif   # GAS219_OR_LATER
endif   # GAS217_OR_LATER
ifneq ($(IS_SUN),0)
CXXFLAGS += -Wa,--divide	# allow use of "/" operator
endif   # IS_SUN
endif   # GAS210_OR_LATER

#########################
ifeq ($(IS_MINGW),1)
LDLIBS += -lws2_32
endif 	# IS_MINGW

endif	# IS_X86

# Should most of this be moved to outside of i386/i686/x86_64 block?
ifeq ($(IS_LINUX),1)
LDFLAGS += -pthread
ifeq ($(findstring -fopenmp,$(MAKECMDGOALS)),-fopenmp)
LDLIBS += -lgomp
endif 	# -fopenmp
endif 	# IS_LINUX

ifneq ($(IS_SUN),0)
LDLIBS += -lnsl -lsocket
M32OR64 = -m$(shell isainfo -b)
endif

ifneq ($(SUN_COMPILER),0)	# override flags for CC Sun C++ compiler
CXXFLAGS = -DNDEBUG -O -g0 -native -template=no%extdef $(M32OR64)
AR = $(CXX)
ARFLAGS = -xar -o
RANLIB = true
LDFLAGS =
SUN_CC10_BUGGY = $(shell $(CXX) -V 2>&1 | $(EGREP) -c "CC: Sun .* 5\.10 .* (2009|2010/0[1-4])")
ifneq ($(SUN_CC10_BUGGY),0)
# -DCRYPTOPP_INCLUDE_VECTOR_CC is needed for Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21 and was fixed in May 2010
# remove it if you get "already had a body defined" errors in vector.cc
CXXFLAGS += -DCRYPTOPP_INCLUDE_VECTOR_CC
endif # SUN_CC10_BUGGY
endif # SUN_COMPILER

#################################################################
# Compiler diagnostics and warnings

# -Wall, -Wextra and -Wno-type-limits for GCC 4.3 and above. It needs -Wno-unknown-pragmas due
# to bug https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53431. We can't use -Wall
# unguarded because it lights up CentOS 5 (GCC 4.1) and OpenBSD (4.2.1)
GCC43_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c "^gcc version (4\.[3-9]|[5-9])")
ifneq ($(GCC43_OR_LATER),0)
CXXFLAGS += -Wall -Wextra -Wno-type-limits -Wno-unknown-pragmas
endif

# -Wall, -Wextra and -Wno-tautological-compare for Clang
ifneq ($(CLANG_COMPILER),0)
CXXFLAGS += -Wall -Wextra -Wno-tautological-compare
endif

ifeq ($(findstring -pipe,$(CXXFLAGS)),)
CXXFLAGS += -pipe
endif

#################################################################
# Sources, objects and temporaries

WIN_SRCS = pch.cpp cryptlib_bds.cpp
ifeq ($(IS_MINGW),0)
WIN_SRCS += winpipes.cpp
endif

# List of sources to compile and objects to link
SRCS = $(filter-out $(WIN_SRCS), $(wildcard *.cpp))
OBJS = $(SRCS:.cpp=.o)

# Compiling with --save-temps creates these
TEMPS = $(SRCS:.cpp=.s) $(SRCS:.cpp=.ii)

# test.o needs to be after bench.o for cygwin 1.1.4 (possible ld bug?)
TESTOBJS = bench.o bench2.o test.o validat1.o validat2.o validat3.o adhoc.o datatest.o regtest.o fipsalgt.o dlltest.o
LIBOBJS = $(filter-out $(TESTOBJS),$(OBJS))

DLLSRCS = algebra.cpp algparam.cpp asn.cpp basecode.cpp cbcmac.cpp channels.cpp cryptlib.cpp des.cpp dessp.cpp dh.cpp \
			dll.cpp dsa.cpp ec2n.cpp eccrypto.cpp ecp.cpp eprecomp.cpp files.cpp filters.cpp fips140.cpp fipstest.cpp \
			gf2n.cpp gfpcrypt.cpp hex.cpp hmac.cpp integer.cpp iterhash.cpp misc.cpp modes.cpp modexppc.cpp mqueue.cpp \
			nbtheory.cpp oaep.cpp osrng.cpp pch.cpp pkcspad.cpp pubkey.cpp queue.cpp randpool.cpp rdtables.cpp \
			rijndael.cpp rng.cpp rsa.cpp sha.cpp simple.cpp skipjack.cpp strciphr.cpp trdlocal.cpp
DLLOBJS = $(DLLSRCS:.cpp=.export.o)
LIBIMPORTOBJS = $(LIBOBJS:.o=.import.o)
TESTIMPORTOBJS = $(TESTOBJS:.o=.import.o)
DLLTESTOBJS = dlltest.dllonly.o

#################################################################
# Recipes

# For various targets, see https://www.gnu.org/prep/standards/html_node/Standard-Targets.html
# We want to include libcryptopp, cryptest, clean, distclean, install, install-strip, uninstall

all cryptest: cryptest.exe
static: libcryptopp.a

ifeq ($(IS_DARWIN),0)
shared dynamic: libcryptopp.so
else
shared dynamic: libcryptopp.dylib
endif

asan ubsan: libcryptopp.a cryptest.exe

.PHONY: test check
test check: cryptest.exe
	./cryptest.exe v

.PHONY: clean
clean:
	-$(RM) cryptest.exe libcryptopp.a libcrypto++.a libcryptopp.so libcrypto++.so libcryptopp.dylib $(LIBOBJS) $(TESTOBJS) $(TEMPS) cryptopp.dll libcryptopp.dll.a libcryptopp.import.a cryptest.import.exe dlltest.exe $(DLLOBJS) $(LIBIMPORTOBJS) $(TESTI MPORTOBJS) $(DLLTESTOBJS)
ifneq ($(IS_DARWIN),0)
	-$(RM) -r cryptest.exe.dSYM
endif

.PHONY: distclean
distclean:
	-$(RM) -r GNUmakefile.deps *.o *.obj *.a *.so *.exe a.out *~ \.*~ *\.h\. *\.cpp\. *.bu *.bak adhoc.cpp adhoc.cpp.copied *.diff *.patch cryptopp.zip
ifneq ($(IS_DARWIN),0)
	-$(RM) *.dSYM .DS_Store TestVectors/.DS_Store TestData/.DS_Store
endif

.PHONY: install
install:
	$(MKDIR) -p $(PREFIX)/include/cryptopp $(PREFIX)/lib $(PREFIX)/bin
	-$(CP) *.h $(PREFIX)/include/cryptopp
	-$(CP) libcryptopp.a $(PREFIX)/lib
	-$(CP) cryptest.exe $(PREFIX)/bin
ifeq ($(IS_DARWIN),0)
	-$(CP) *.so $(PREFIX)/lib
else
	-$(CP) *.dylib $(PREFIX)/lib
endif

.PHONY: install-strip
install-strip: install
	-$(STRIP) -s $(PREFIX)/bin/cryptest.exe
ifeq ($(IS_DARWIN),0)
	-$(STRIP) -s $(PREFIX)/lib/libcryptopp.so
else
	-$(STRIP) -s $(PREFIX)/lib/libcryptopp.dylib
endif

.PHONY: uninstall remove
uninstall remove:
	-$(RM) -rf $(PREFIX)/include/cryptopp
	-$(RM) $(PREFIX)/lib/libcryptopp.a
	-$(RM) $(PREFIX)/bin/cryptest.exe
ifeq ($(IS_DARWIN),0)
	-$(RM) $(PREFIX)/lib/libcryptopp.so
else
	-$(RM) $(PREFIX)/lib/libcryptopp.dylib
endif

.PHONY: zip dist
zip dist: distclean
	-zip -9 cryptopp.zip *.h *.cpp *.asm License.txt Readme.txt \
		GNUmakefile GNUmakefile-cross Doxyfile \
		cryptest_bds.bdsgroup cryptest_bds.bdsproj cryptest_bds.bpf cryptlib_bds.bdsproj \
		cryptest.sln cryptest.dsp cryptest.dsw cryptest.vcproj \
		dlltest.dsp dlltest.vcproj cryptlib.dsp cryptlib.vcproj cryptopp.rc \
		TestVectors/*.txt TestVectors/*.dat TestData/*.txt TestData/*.dat 

libcryptopp.a: $(LIBOBJS)
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
	$(RANLIB) $@

libcryptopp.so: $(LIBOBJS)
	$(CXX) -shared -o $@ $(CXXFLAGS) $(LIBOBJS)

libcryptopp.dylib: $(LIBOBJS)
	$(CXX) -shared -dynamiclib -o $@ $(CXXFLAGS) $(LIBOBJS)

.PHONY: cryptest.exe
cryptest.exe: libcryptopp.a $(TESTOBJS)
	$(CXX) -o $@ $(CXXFLAGS) $(TESTOBJS) ./libcryptopp.a $(LDFLAGS) $(LDLIBS)

dll: cryptest.import.exe dlltest.exe

cryptopp.dll: $(DLLOBJS)
	$(CXX) -shared -o $@ $(CXXFLAGS) $(DLLOBJS) $(LDFLAGS) $(LDLIBS) -Wl,--out-implib=libcryptopp.dll.a

libcryptopp.import.a: $(LIBIMPORTOBJS)
	$(AR) $(ARFLAGS) $@ $(LIBIMPORTOBJS)
	$(RANLIB) $@

cryptest.import.exe: cryptopp.dll libcryptopp.import.a $(TESTIMPORTOBJS)
	$(CXX) -o $@ $(CXXFLAGS) $(TESTIMPORTOBJS) -L. -lcryptopp.dll -lcryptopp.import $(LDFLAGS) $(LDLIBS)

dlltest.exe: cryptopp.dll $(DLLTESTOBJS)
	$(CXX) -o $@ $(CXXFLAGS) $(DLLTESTOBJS) -L. -lcryptopp.dll $(LDFLAGS) $(LDLIBS)

adhoc.cpp: adhoc.cpp.proto
ifeq ($(wildcard adhoc.cpp),)
	cp adhoc.cpp.proto adhoc.cpp
else
	touch adhoc.cpp
endif

%.dllonly.o : %.cpp
	$(CXX) $(CXXFLAGS) -DCRYPTOPP_DLL_ONLY -c $< -o $@

%.import.o : %.cpp
	$(CXX) $(CXXFLAGS) -DCRYPTOPP_IMPORTS -c $< -o $@

%.export.o : %.cpp
	$(CXX) $(CXXFLAGS) -DCRYPTOPP_EXPORTS -c $< -o $@

%.o : %.cpp
	$(CXX) $(CXXFLAGS) -c $<

#################################################################
# Dependencies

# Do not build dependencies for some targets
NO_DEPS = dist install install-strip uninstall remove clean distclean
ifeq ($(findstring $(MAKECMDGOALS),$(NO_DEPS)),)

# Do not build dependencies when multiarch is in effect
ifeq ($(MULTIARCH),0)
-include GNUmakefile.deps
endif

GNUmakefile.deps:
	$(CXX) $(CXXFLAGS) -MM *.cpp > GNUmakefile.deps

endif # NO_DEPS
