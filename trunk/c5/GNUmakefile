# can't use -fno-rtti yet because it causes problems with exception handling in GCC 2.95.2
CXXFLAGS = -g
# Uncomment the next two lines to do a release build.
# Note that you must define NDEBUG for your own application if you define it for Crypto++.
# Also, make sure you run the validation tests and test your own program thoroughly
# after turning on -O2. The GCC optimizer may have bugs that cause it to generate incorrect code.
# CXXFLAGS = -O2 -DNDEBUG -ffunction-sections -fdata-sections
# LDFLAGS = -Wl,--gc-sections
ARFLAGS = -cr	# ar needs the dash on OpenBSD
RANLIB = ranlib
UNAME = $(shell uname)

ifeq ($(UNAME),)	# for DJGPP, where uname doesn't exist
CXXFLAGS += -mbnu210
else
CXXFLAGS += -pipe
endif

ifeq ($(UNAME),Darwin)
AR = libtool
ARFLAGS = -static -o
CXXFLAGS += -D__pic__
IS_GCC2 = $(shell c++ -v 2>&1 | grep -c gcc-932)
ifeq ($(IS_GCC2),1)
CXXFLAGS += -fno-coalesce-templates -fno-coalesce-static-vtables
CXX = c++
LDLIBS += -lstdc++
LDFLAGS += -flat_namespace -undefined suppress -m
endif
endif

ifeq ($(UNAME),SunOS)
LDLIBS += -lnsl -lsocket
endif

ifeq ($(CXX),gcc)	# for some reason CXX is gcc on cygwin 1.1.4
CXX = g++
endif

SRCS = $(wildcard *.cpp)
ifeq ($(SRCS),)				# workaround wildcard function bug in GNU Make 3.77
SRCS = $(shell ls *.cpp)
endif

OBJS = $(SRCS:.cpp=.o)
# test.o needs to be after bench.o for cygwin 1.1.4 (possible ld bug?)
TESTOBJS = bench.o test.o validat1.o validat2.o validat3.o adhoc.o datatest.o regtest.o
LIBOBJS = $(filter-out $(TESTOBJS),$(OBJS))

all: cryptest.exe

clean:
	$(RM) cryptest.exe libcryptopp.a $(LIBOBJS) $(TESTOBJS)

libcryptopp.a: $(LIBOBJS)
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
	$(RANLIB) $@

cryptest.exe: libcryptopp.a $(TESTOBJS)
	$(CXX) -o $@ $(CXXFLAGS) $(TESTOBJS) -L. -lcryptopp $(LDFLAGS) $(LDLIBS)

nolib: $(OBJS)		# makes it faster to test changes
	$(CXX) -o ct $(CXXFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS)

adhoc.cpp: adhoc.cpp.proto
ifeq ($(wildcard adhoc.cpp),)
	cp adhoc.cpp.proto adhoc.cpp
else
	touch adhoc.cpp
endif

.SUFFIXES: .cpp

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $<
