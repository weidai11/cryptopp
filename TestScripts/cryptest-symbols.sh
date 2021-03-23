#!/usr/bin/env bash

#############################################################################
#
# This is a test script that can be used on some Linux/Unix/Apple machines to
# automate testing of the shared object to ensure linking and symbols don't go
# missing from release to release.
#
# Written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
#############################################################################

#############################################################################
# Tags to test

OLD_VERSION_TAG=CRYPTOPP_8_3_0
NEW_VERSION_TAG=master

#############################################################################
# If local repo is dirty, then prompt first

DIRTY=$(git diff --shortstat 2> /dev/null | tail -1)
if [[ ! -z "$DIRTY" ]]; then

	echo
	echo "The local repo is dirty. Continuing will reset the repo and lose changes."
	read -p "Type 'Y' to proceed or 'N' to exit. Proceed? " -n 1 -r
	echo # (optional) move to a new line
	if [[ !($REPLY =~ ^[Yy]$) ]]; then
		exit 0
	fi
else
	echo
	echo "The local repo is clean. Proceeding..."
fi

#############################################################################

echo
echo "****************************************************************"
echo "Testing '$NEW_VERSION_TAG' against '$OLD_VERSION_TAG'"
echo "****************************************************************"

#############################################################################
# Setup tools and platforms

GREP=grep
EGREP=egrep
SED=sed
AWK=awk
CXXFILT=c++filt

THIS_SYSTEM=$(uname -s 2>&1)
IS_DARWIN=$("${GREP}" -i -c darwin <<< "${THIS_SYSTEM}")
IS_LINUX=$("${GREP}" -i -c linux <<< "${THIS_SYSTEM}")
IS_CYGWIN=$("${GREP}" -i -c cygwin <<< "${THIS_SYSTEM}")
IS_MINGW=$("${GREP}" -i -c mingw <<< "${THIS_SYSTEM}")
IS_OPENBSD=$("${GREP}" -i -c openbsd <<< "${THIS_SYSTEM}")
IS_FREEBSD=$("${GREP}" -i -c freebsd <<< "${THIS_SYSTEM}")
IS_NETBSD=$("${GREP}" -i -c netbsd <<< "${THIS_SYSTEM}")
IS_SOLARIS=$("${GREP}" -i -c sunos <<< "${THIS_SYSTEM}")

THIS_MACHINE=$(uname -m 2>&1)
IS_X86=$("${EGREP}" -i -c 'i386|i486|i586|i686' <<< "${THIS_MACHINE}")
IS_X64=$("${EGREP}" -i -c "amd64|x86_64" <<< "${THIS_MACHINE}")
IS_PPC32=$("${EGREP}" -i -c "PowerPC|PPC" <<< "${THIS_MACHINE}")
IS_PPC64=$("${EGREP}" -i -c "PowerPC64|PPC64" <<< "${THIS_MACHINE}")
IS_ARM32=$("${EGREP}" -i -c "arm|aarch32" <<< "${THIS_MACHINE}")
IS_ARMV8=$("${EGREP}" -i -c "arm64|aarch64" <<< "${THIS_MACHINE}")
IS_S390=$("${EGREP}" -i -c "s390" <<< "${THIS_MACHINE}")

if [[ "${IS_X64}" -eq 1 ]]; then IS_X86=0; fi
if [[ "${IS_ARMV8}" -eq 1 ]]; then IS_ARM32=0; fi
if [[ "${IS_PPC64}" -eq 1 ]]; then IS_PPC32=0; fi

# Fixup
if [[ "$IS_FREEBSD" -ne "0" || "$IS_OPENBSD" -ne "0" || "$IS_NETBSD" -ne "0" ]]; then
	MAKE=gmake
elif [[ "$IS_SOLARIS" -ne "0" ]]; then
	MAKE=$(command -v gmake 2>/dev/null | "${GREP}" -v "no gmake" | head -1)
	if [[ -z "$MAKE" && -e "/usr/sfw/bin/gmake" ]]; then
		MAKE=/usr/sfw/bin/gmake
	fi
else
	MAKE=make
fi

if [[ "$IS_DARWIN" -ne "0" ]]; then
	LINK_LIBRARY=libcryptopp.dylib
else
	LINK_LIBRARY=libcryptopp.so
fi

if [[ -z "${CXX}" ]]; then CXX=c++; fi

SUN_COMPILER=$("${CXX}" -V 2>&1 | "${EGREP}" -i -c "CC: (Sun|Studio)")
GCC_COMPILER=$("${CXX}" --version 2>&1 | "${EGREP}" -i -c "^(gcc|g\+\+)")
INTEL_COMPILER=$("${CXX}" --version 2>&1 | "${GREP}" -i -c "icc")
MACPORTS_COMPILER=$("${CXX}" --version 2>&1 | "${GREP}" -i -c "MacPorts")
CLANG_COMPILER=$("${CXX}" --version 2>&1 | "${GREP}" -i -c "clang")

#############################################################################

# CPU is logical count, memory is in MiB. Low resource boards have
#  fewer than 4 cores and 1GB or less memory. We use this to
#  determine if we can build in parallel without an OOM kill.
CPU_COUNT=1
MEM_SIZE=512

if [[ -e "/proc/cpuinfo" && -e "/proc/meminfo" ]]; then
	CPU_COUNT=$(cat /proc/cpuinfo | "${GREP}" -c '^processor')
	MEM_SIZE=$(cat /proc/meminfo | "${GREP}" "MemTotal" | "${AWK}" '{print $2}')
	MEM_SIZE=$(($MEM_SIZE/1024))
elif [[ "$IS_DARWIN" -ne "0" ]]; then
	CPU_COUNT=$(sysctl -a 2>&1 | "${GREP}" 'hw.availcpu' | "${AWK}" '{print $3; exit}')
	MEM_SIZE=$(sysctl -a 2>&1 | "${GREP}" 'hw.memsize' | "${AWK}" '{print $3; exit;}')
	MEM_SIZE=$(($MEM_SIZE/1024/1024))
elif [[ "$IS_SOLARIS" -ne "0" ]]; then
	CPU_COUNT=$(psrinfo 2>/dev/null | wc -l | "${AWK}" '{print $1}')
	MEM_SIZE=$(prtconf 2>/dev/null | "${GREP}" Memory | "${AWK}" '{print $3}')
fi

# Some ARM devboards cannot use 'make -j N', even with multiple cores and RAM
# An 8-core Cubietruck Plus with 2GB RAM experiences OOM kills with '-j 2'.
HAVE_SWAP=1
if [[ "$IS_LINUX" -ne "0" ]]; then
	if [[ -e "/proc/meminfo" ]]; then
		SWAP_SIZE=$(cat /proc/meminfo | "${GREP}" "SwapTotal" | "${AWK}" '{print $2}')
		if [[ "$SWAP_SIZE" -eq "0" ]]; then
			HAVE_SWAP=0
		fi
	else
		HAVE_SWAP=0
	fi
fi

if [[ "$CPU_COUNT" -ge "2" && "$MEM_SIZE" -ge "1280" && "$HAVE_SWAP" -ne "0" ]]; then
	MAKEARGS=(-j "$CPU_COUNT")
fi

#############################################################################
#############################################################################

"${MAKE}" distclean &>/dev/null && cleanup &>/dev/null
git checkout master -f &>/dev/null
git checkout "$OLD_VERSION_TAG" -f &>/dev/null

if [[ "$?" -ne "0" ]]; then
	echo "Failed to checkout $OLD_VERSION_TAG"
	exit 1
fi

echo
echo "****************************************************************"
echo "Building dynamic library for $OLD_VERSION_TAG"
echo "****************************************************************"
echo

LINK_LIBRARY="$LINK_LIBRARY" "$MAKE" "${MAKEARGS[@]}" -f GNUmakefile cryptest.exe dynamic

if [[ ! -f "$LINK_LIBRARY" ]]; then
	echo "Failed to make $OLD_VERSION_TAG library"
	exit 1
fi

echo
echo "****************************************************************"
echo "Running $OLD_VERSION_TAG cryptest.exe using $OLD_VERSION_TAG library"
echo "****************************************************************"
echo

if [[ "$IS_DARWIN" -ne "0" ]]; then
	DYLD_LIBRARY_PATH="$PWD:$DYLD_LIBRARY_PATH" ./cryptest.exe v 2>&1 | "$CXXFILT"
	DYLD_LIBRARY_PATH="$PWD:$DYLD_LIBRARY_PATH" ./cryptest.exe tv all 2>&1 | "$CXXFILT"
else
	LD_LIBRARY_PATH="$PWD:$LD_LIBRARY_PATH" ./cryptest.exe v 2>&1 | "$CXXFILT"
	LD_LIBRARY_PATH="$PWD:$LD_LIBRARY_PATH" ./cryptest.exe tv all 2>&1 | "$CXXFILT"
fi

# Stash away old cryptest.exe
cp cryptest.exe cryptest.exe.saved

echo
echo "****************************************************************"
echo "Building dynamic library for $NEW_VERSION_TAG"
echo "****************************************************************"
echo

"${MAKE}" distclean &>/dev/null && cleanup &>/dev/null
git checkout master -f &>/dev/null
git checkout "$NEW_VERSION_TAG" -f &>/dev/null

LINK_LIBRARY="$LINK_LIBRARY" "$MAKE" "${MAKEARGS[@]}" -f GNUmakefile cryptest.exe dynamic

if [[ ! -f "$LINK_LIBRARY" ]]; then
	echo "Failed to make $NEW_VERSION_TAG library"
	exit 1
fi

# Fetch old cryptest.exe
cp cryptest.exe.saved cryptest.exe

echo
echo "****************************************************************"
echo "Running $OLD_VERSION_TAG cryptest.exe using $NEW_VERSION_TAG library"
echo "****************************************************************"
echo

if [[ "$IS_DARWIN" -ne "0" ]]; then
	DYLD_LIBRARY_PATH="$PWD:$DYLD_LIBRARY_PATH" ./cryptest.exe v 2>&1 | "$CXXFILT"
	DYLD_LIBRARY_PATH="$PWD:$DYLD_LIBRARY_PATH" ./cryptest.exe tv all 2>&1 | "$CXXFILT"
else
	LD_LIBRARY_PATH="$PWD:$LD_LIBRARY_PATH" ./cryptest.exe v 2>&1 | "$CXXFILT"
	LD_LIBRARY_PATH="$PWD:$LD_LIBRARY_PATH" ./cryptest.exe tv all 2>&1 | "$CXXFILT"
fi

"${MAKE}" distclean &>/dev/null && cleanup &>/dev/null
git checkout master -f &>/dev/null

exit 0
