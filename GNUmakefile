# can't use -fno-rtti yet because it causes problems with exception handling in GCC 2.95.2
CXXFLAGS = -g
# Uncomment the following two lines to do a release build.
# Note that you must define NDEBUG for your own application if you define it for Crypto++.
# Make sure you run the validation tests and test your own program thoroughly
# after turning on -O2. The GCC optimizer may have bugs that cause it to generate incorrect code.
# Try removing -fdata-sections if you get "undefined external reference" errors.
# CXXFLAGS = -O2 -DNDEBUG -ffunction-sections -fdata-sections
# LDFLAGS += -Wl,--gc-sections
ARFLAGS = -cr	# ar needs the dash on OpenBSD
RANLIB = ranlib
CP = cp
MKDIR = mkdir
UNAME = $(shell uname)
ISX86 = $(shell uname -m | grep -c "i.86\|x86_64")
ISMINGW = $(shell uname | grep -c "MINGW32")

# Default prefix for make install
ifeq ($(PREFIX),)
PREFIX = /usr
endif

ifeq ($(CXX),gcc)	# for some reason CXX is gcc on cygwin 1.1.4
CXX = g++
endif

ifeq ($(ISX86),1)

GCC33ORLATER = $(shell $(CXX) -v 2>&1 | grep -c "gcc version \(3.[3-9]\|[4-9]\)")
GAS210ORLATER = $(shell echo "" | $(AS) -v 2>&1 | grep -c "GNU assembler version \(2.[1-9][0-9]\|[3-9]\)")

ifeq ($(GCC33ORLATER) $(ISMINGW),1 0)	# MINGW32 is missing the memalign function
CXXFLAGS += -msse2
endif

ifeq ($(GAS210ORLATER),0)	# .intel_syntax wasn't supported until GNU assembler 2.10
CXXFLAGS += -DCRYPTOPP_DISABLE_X86ASM
endif

endif

ifeq ($(ISMINGW),1)
LDLIBS += -lws2_32
endif

ifeq ($(UNAME),)	# for DJGPP, where uname doesn't exist
CXXFLAGS += -mbnu210
else
CXXFLAGS += -pipe
endif

ifeq ($(UNAME),Linux)
LDFLAGS += -pthread
endif

ifeq ($(UNAME),Darwin)
AR = libtool
ARFLAGS = -static -o
CXX = c++
CXXFLAGS += -D__pic__
IS_GCC2 = $(shell $(CXX) -v 2>&1 | grep -c gcc-932)
ifeq ($(IS_GCC2),1)
CXXFLAGS += -fno-coalesce-templates -fno-coalesce-static-vtables
LDLIBS += -lstdc++
LDFLAGS += -flat_namespace -undefined suppress -m
endif
endif

ifeq ($(UNAME),SunOS)
LDLIBS += -lnsl -lsocket
endif

SRCS = $(wildcard *.cpp)
ifeq ($(SRCS),)				# workaround wildcard function bug in GNU Make 3.77
SRCS = $(shell ls *.cpp)
endif

OBJS = $(SRCS:.cpp=.o)
# test.o needs to be after bench.o for cygwin 1.1.4 (possible ld bug?)
TESTOBJS = bench.o bench2.o test.o validat1.o validat2.o validat3.o adhoc.o datatest.o regtest.o fipsalgt.o dlltest.o
LIBOBJS = $(filter-out $(TESTOBJS),$(OBJS))

DLLSRCS = algebra.cpp algparam.cpp asn.cpp basecode.cpp cbcmac.cpp channels.cpp cryptlib.cpp des.cpp dessp.cpp dh.cpp dll.cpp dsa.cpp ec2n.cpp eccrypto.cpp ecp.cpp eprecomp.cpp files.cpp filters.cpp fips140.cpp fipstest.cpp gf2n.cpp gfpcrypt.cpp hex.cpp hmac.cpp integer.cpp iterhash.cpp misc.cpp modes.cpp modexppc.cpp mqueue.cpp nbtheory.cpp oaep.cpp osrng.cpp pch.cpp pkcspad.cpp pubkey.cpp queue.cpp randpool.cpp rdtables.cpp rijndael.cpp rng.cpp rsa.cpp sha.cpp simple.cpp skipjack.cpp strciphr.cpp trdlocal.cpp
DLLOBJS = $(DLLSRCS:.cpp=.export.o)
LIBIMPORTOBJS = $(LIBOBJS:.o=.import.o)
TESTIMPORTOBJS = $(TESTOBJS:.o=.import.o)
DLLTESTOBJS = dlltest.dllonly.o

all: cryptest.exe

clean:
	$(RM) cryptest.exe libcryptopp.a $(LIBOBJS) $(TESTOBJS) cryptopp.dll libcryptopp.dll.a libcryptopp.import.a cryptest.import.exe dlltest.exe $(DLLOBJS) $(LIBIMPORTOBJS) $(TESTIMPORTOBJS) $(DLLTESTOBJS)

install:
	$(MKDIR) -p $(PREFIX)/include/cryptopp $(PREFIX)/lib $(PREFIX)/bin
	$(CP) *.h $(PREFIX)/include/cryptopp
	$(CP) *.a $(PREFIX)/lib
	$(CP) *.exe $(PREFIX)/bin

libcryptopp.a: $(LIBOBJS)
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
	$(RANLIB) $@

cryptest.exe: libcryptopp.a $(TESTOBJS)
	$(CXX) -o $@ $(CXXFLAGS) $(TESTOBJS) -L. -lcryptopp $(LDFLAGS) $(LDLIBS)

nolib: $(OBJS)		# makes it faster to test changes
	$(CXX) -o ct $(CXXFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS)

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
