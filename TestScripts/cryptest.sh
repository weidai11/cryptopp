#!/usr/bin/env bash

# cryptest.sh - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.

# This is a test script that can be used on some Linux/Unix/Apple machines to automate building the
# library and running the self test with various combinations of flags, options, and conditions.
# For more details, see http://cryptopp.com/wiki/cryptest.sh.

# To run the script, simply perform the following:
#     ./cryptest.sh

# If you want to test a particular compiler, like clang++ or icpc, issue:
#     CXX=clang++ ./cryptest.sh
#     CXX=/opt/intel/bin/icpc ./cryptest.sh
#     CXX=/opt/solstudio12.2/bin/CC ./cryptest.sh

# The script ignores CXXFLAGS. You can add CXXFLAGS, like -mcpu or -mtune, through USER_CXXFLAGS:
#     USER_CXXFLAGS=-Wall ./cryptest.sh
#     USER_CXXFLAGS="-Wall -Wextra" ./cryptest.sh

# The fastest results (in running time) will most likely omit Valgrind and Benchmarks because
# significantly increase execution time:
#     HAVE_VALGRIND=0 WANT_BENCHMARKS=0 ./cryptest.sh

# Using 'fast' is shorthand for HAVE_VALGRIND=0 WANT_BENCHMARKS=0:
#     ./cryptest.sh fast

# You can reduce CPU load with the following. It will use half the number of CPU cores
# rather than all of them. Its useful at places like the GCC Compile Farm, where being nice is policy.
#     ./cryptest.sh nice

# Keep the noise down
# shellcheck disable=SC2181

############################################
# Set to suite your taste

if [[ (-z "$TEST_RESULTS") ]]; then
	TEST_RESULTS=cryptest-result.txt
fi
if [[ (-z "$BENCHMARK_RESULTS") ]]; then
	BENCHMARK_RESULTS=cryptest-bench.txt
fi
if [[ (-z "$WARN_RESULTS") ]]; then
	WARN_RESULTS=cryptest-warn.txt
fi
if [[ (-z "$INSTALL_RESULTS") ]]; then
	INSTALL_RESULTS=cryptest-install.txt
fi

# Remove previous test results
rm -f "$TEST_RESULTS" > /dev/null 2>&1
touch "$TEST_RESULTS"

rm -f "$BENCHMARK_RESULTS" > /dev/null 2>&1
touch "$BENCHMARK_RESULTS"

rm -f "$WARN_RESULTS" > /dev/null 2>&1
touch "$WARN_RESULTS"

rm -f "$INSTALL_RESULTS" > /dev/null 2>&1
touch "$INSTALL_RESULTS"

# Avoid CRYPTOPP_DATA_DIR in this shell (it is tested below)
unset CRYPTOPP_DATA_DIR

# Avoid Malloc and Scribble guards on OS X (they are tested below)
unset MallocScribble MallocPreScribble MallocGuardEdges

# List of tests performed
TEST_LIST=()

############################################
# Setup tools and platforms

GREP=grep
SED=sed
AWK=awk
MAKE=make

DISASS=objdump
DISASSARGS=("--disassemble")

# Fixup ancient Bash
# https://unix.stackexchange.com/q/468579/56041
if [[ -z "$BASH_SOURCE" ]]; then
	BASH_SOURCE="$0"
fi

# Fixup, Solaris and friends
if [[ (-d /usr/xpg4/bin) ]]; then
	SED=/usr/xpg4/bin/sed
	AWK=/usr/xpg4/bin/awk
	GREP=/usr/xpg4/bin/grep
elif [[ (-d /usr/bin/posix) ]]; then
	SED=/usr/bin/posix/sed
	AWK=/usr/bin/posix/awk
	GREP=/usr/bin/posix/grep
fi

# Fixup, Solaris and BSDs
if [[ $(command -v gmake 2>/dev/null) ]]; then
	MAKE="gmake"
else
	MAKE="make"
fi

THIS_SYSTEM=$(uname -s 2>&1)
IS_AIX=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c aix)
IS_DARWIN=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c darwin)
IS_HURD=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c gnu)
IS_LINUX=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c linux)
IS_CYGWIN=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c cygwin)
IS_MINGW=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c mingw)
IS_OPENBSD=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c openbsd)
IS_DRAGONFLY=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c dragonfly)
IS_FREEBSD=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c freebsd)
IS_NETBSD=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c netbsd)
IS_SOLARIS=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c sunos)
IS_BSD=$(echo -n "$THIS_SYSTEM" | "$GREP" -i -c bsd)

IS_DEBIAN=$(lsb_release -a 2>&1 | "$GREP" -i -c debian)
IS_FEDORA=$(lsb_release -a 2>&1 | "$GREP" -i -c fedora)
IS_UBUNTU=$(lsb_release -a 2>&1 | "$GREP" -i -c ubuntu)

THIS_MACHINE=$(uname -m 2>&1)
IS_X86=$(echo -n "$THIS_MACHINE" | "$GREP" -i -c -E "(i386|i486|i686|i686)")
IS_X64=$(echo -n "$THIS_MACHINE" | "$GREP" -i -c -E "(amd64|x86_64)")
IS_PPC32=$(echo -n "$THIS_MACHINE" | "$GREP" -v "64" | "$GREP" -i -c -E "(Power|PPC)")
IS_PPC64=$(echo -n "$THIS_MACHINE" | "$GREP" -i -c -E "(Power64|PPC64)")
IS_ARM32=$(echo -n "$THIS_MACHINE" | "$GREP" -v "64" | "$GREP" -i -c -E "(arm|aarch32)")
IS_ARM64=$(echo -n "$THIS_MACHINE" | "$GREP" -i -c -E  "(arm64|aarch64)")
IS_S390=$(echo -n "$THIS_MACHINE" | "$GREP" -i -c "s390")
IS_SPARC=$(echo -n "$THIS_MACHINE" | "$GREP" -i -c "sparc")
IS_X32=0

# Fixup
if [[ "$IS_SOLARIS" -ne "0" ]]; then
	DISASS=dis
	DISASSARGS=()
fi

# Fixup
if [[ "$IS_DARWIN" -ne 0 ]]; then
	DISASS=otool
	DISASSARGS=("-tV")
fi

# CPU features and flags
if [[ ("$IS_X86" -ne "0" || "$IS_X64" -ne "0") ]]; then
	if [[ ("$IS_DARWIN" -ne "0") ]]; then
		X86_CPU_FLAGS=$(sysctl machdep.cpu.features 2>&1 | cut -f 2 -d ':')
	elif [[ ("$IS_SOLARIS" -ne "0") ]]; then
		X86_CPU_FLAGS=$(isainfo -v 2>/dev/null)
	elif [[ ("$IS_FREEBSD" -ne "0") ]]; then
		X86_CPU_FLAGS=$(grep Features /var/run/dmesg.boot)
	elif [[ ("$IS_DRAGONFLY" -ne "0") ]]; then
		X86_CPU_FLAGS=$(dmesg | grep Features)
	elif [[ ("$IS_HURD" -ne "0") ]]; then
		: # Do nothing... cpuid is not helpful at the moment
	else
		X86_CPU_FLAGS="$($AWK '{IGNORECASE=1}{if ($1 == "flags"){print;exit}}' < /proc/cpuinfo | cut -f 2 -d ':')"
	fi
elif [[ ("$IS_ARM32" -ne "0" || "$IS_ARM64" -ne "0") ]]; then
	if [[ ("$IS_DARWIN" -ne "0") ]]; then
		ARM_CPU_FLAGS="$(sysctl machdep.cpu.features 2>&1 | cut -f 2 -d ':')"
	else
		ARM_CPU_FLAGS="$($AWK '{IGNORECASE=1}{if ($1 == "Features"){print;exit}}' < /proc/cpuinfo | cut -f 2 -d ':')"
	fi
fi

for ARG in "$@"
do
	# Recognize "fast" and "quick", which does not perform tests that take more time to execute
    if [[ ($("$GREP" -ix "fast" <<< "$ARG") || $("$GREP" -ix "quick" <<< "$ARG")) ]]; then
		HAVE_VALGRIND=0
		WANT_BENCHMARKS=0
	# Recognize "farm" and "nice", which uses 1/2 the CPU cores in accordance with GCC Compile Farm policy
	elif [[ ($("$GREP" -ix "farm" <<< "$ARG") || $("$GREP" -ix "nice" <<< "$ARG")) ]]; then
		WANT_NICE=1
	elif [[ ($("$GREP" -ix "orig" <<< "$ARG") || $("$GREP" -ix "original" <<< "$ARG") || $("$GREP" -ix "config.h" <<< "$ARG")) ]]; then
		git checkout config.h > /dev/null 2>&1
	else
		echo "Unknown option $ARG"
	fi
done

# We need to use the C++ compiler to determine feature availablility. Otherwise
#   mis-detections occur on a number of platforms.
if [[ ((-z "$CXX") || ("$CXX" == "gcc")) ]]; then
	if [[ ("$CXX" == "gcc") ]]; then
		CXX="g++"
	elif [[ "$IS_DARWIN" -ne "0" ]]; then
		CXX="c++"
	elif [[ "$IS_SOLARIS" -ne "0" ]]; then
		if [[ (-e "/opt/developerstudio12.5/bin/CC") ]]; then
			CXX="/opt/developerstudio12.5/bin/CC"
		elif [[ (-e "/opt/solarisstudio12.4/bin/CC") ]]; then
			CXX="/opt/solarisstudio12.4/bin/CC"
		elif [[ (-e "/opt/solarisstudio12.3/bin/CC") ]]; then
			CXX="/opt/solarisstudio12.3/bin/CC"
		elif [[ (-e "/opt/solstudio12.2/bin/CC") ]]; then
			CXX="/opt/solstudio12.2/bin/CC"
		elif [[ (-e "/opt/solstudio12.1/bin/CC") ]]; then
			CXX="/opt/solstudio12.1/bin/CC"
		elif [[ (-e "/opt/solstudio12.0/bin/CC") ]]; then
			CXX="/opt/solstudio12.0/bin/CC"
		elif [[ $(command -v CC 2>/dev/null) ]]; then
			CXX="CC"
		elif [[ $(command -v g++ 2>/dev/null) ]]; then
			CXX="g++"
		else
			CXX=CC
		fi
	elif [[ $(command -v g++ 2>/dev/null) ]]; then
		CXX="g++"
	else
		CXX="c++"
	fi
fi

SUN_COMPILER=$("$CXX" -V 2>&1 | "$GREP" -i -c -E "CC: (Sun|Studio)")
GCC_COMPILER=$("$CXX" --version 2>&1 | "$GREP" -i -v "clang" | "$GREP" -i -c -E "(gcc|g\+\+)")
XLC_COMPILER=$("$CXX" -qversion 2>&1 | "$GREP" -i -c "IBM XL")
INTEL_COMPILER=$("$CXX" --version 2>&1 | "$GREP" -i -c "\(icc\)")
MACPORTS_COMPILER=$("$CXX" --version 2>&1 | "$GREP" -i -c "MacPorts")
CLANG_COMPILER=$("$CXX" --version 2>&1 | "$GREP" -i -c "clang")
GNU_LINKER=$(ld --version 2>&1 | "$GREP" -i -c "GNU ld")

if [[ ("$SUN_COMPILER" -eq "0") ]]; then
	AMD64=$("$CXX" -dM -E - </dev/null 2>/dev/null | "$GREP" -i -c -E "(__x64_64__|__amd64__)")
	ILP32=$("$CXX" -dM -E - </dev/null 2>/dev/null | "$GREP" -i -c -E "(__ILP32__|__ILP32)")
	if [[ ("$AMD64" -ne "0") && ("$ILP32" -ne "0") ]]; then
		IS_X32=1
	fi
fi

# Now that the compiler is fixed, determine the compiler version for fixups
GCC_51_OR_ABOVE=$("$CXX" -v 2>&1 | "$GREP" -i -c -E 'gcc version (5\.[1-9]|[6-9])')
GCC_48_COMPILER=$("$CXX" -v 2>&1 | "$GREP" -i -c -E 'gcc version 4\.8')
SUNCC_510_OR_ABOVE=$("$CXX" -V 2>&1 | "$GREP" -c -E "CC: (Sun|Studio) .* (5\.1[0-9]|5\.[2-9]|[6-9]\.)")
SUNCC_511_OR_ABOVE=$("$CXX" -V 2>&1 | "$GREP" -c -E "CC: (Sun|Studio) .* (5\.1[1-9]|5\.[2-9]|[6-9]\.)")

# Fixup, bad code generation
if [[ ("$SUNCC_510_OR_ABOVE" -ne "0") ]]; then
	HAVE_O5=0
	HAVE_OFAST=0
fi

# GCC compile farm is mounted RO
if [[ (-z "$TMPDIR") ]]; then
	if [[ (-d "/tmp") ]] && [[ $(touch "/tmp/ok-to-delete" &>/dev/null) ]]; then
		TMPDIR=/tmp
	elif [[ (-d "/temp") ]]; then
		TMPDIR=/temp
	elif [[ (-d "$HOME/tmp") ]]; then
		TMPDIR="$HOME/tmp"
	else
		echo "Please set TMPDIR to a valid directory"
		[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
	fi
fi

# Make temp if it does not exist
mkdir -p "$TMPDIR" &>/dev/null

# Sun Studio does not allow '-x c++'. Copy it here...
rm -f adhoc.cpp > /dev/null 2>&1
cp adhoc.cpp.proto adhoc.cpp

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX17") ]]; then
	HAVE_CXX17=0
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++17 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX17=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU17") ]]; then
	HAVE_GNU17=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++17 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU17=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX20") ]]; then
	HAVE_CXX20=0
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++20 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX20=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU20") ]]; then
	HAVE_GNU20=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++20 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU20=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX14") ]]; then
	HAVE_CXX14=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++14 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX14=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU14") ]]; then
	HAVE_GNU14=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++14 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU14=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX11") ]]; then
	HAVE_CXX11=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++11 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX11=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU11") ]]; then
	HAVE_GNU11=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++11 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU11=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX03") ]]; then
	HAVE_CXX03=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++03 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX03=1
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU03") ]]; then
	HAVE_GNU03=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++03 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU03=1
	fi
fi

# Use a fallback strategy so OPT_O0 can be used with DEBUG_CXXFLAGS
OPT_O0=
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O0 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	OPT_O0=-O0
else
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO0 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		OPT_O0=-xO0
	fi
fi

# Use a fallback strategy so OPT_O1 can be used with VALGRIND_CXXFLAGS
OPT_O1=
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O1 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	HAVE_O1=1
	OPT_O1=-O1
else
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO1 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_O1=1
		OPT_O1=-xO1
	fi
fi

# https://github.com/weidai11/cryptopp/issues/588
OPT_O2=
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O2 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	HAVE_O2=1
	OPT_O2=-O2
else
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO2 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_O2=1
		OPT_O2=-xO2
	fi
fi

# Use a fallback strategy so OPT_O3 can be used with RELEASE_CXXFLAGS
OPT_O3=
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O3 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	HAVE_O3=1
	OPT_O3=-O3
else
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO3 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_O3=1
		OPT_O3=-xO3
	fi
fi

# Hit or miss, mostly hit
if [[ ( (-z "$HAVE_O5") && ("$CLANG_COMPILER" -eq "0") ) ]]; then
	HAVE_O5=0
	OPT_O5=
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -O5 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_O5=1
		OPT_O5=-O5
	else
		rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO5 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ ("$?" -eq "0") ]]; then
			HAVE_O5=1
			OPT_O5=-xO5
		fi
	fi
fi

# Hit or miss, mostly hit
if [[ (-z "$HAVE_OS") ]]; then
	HAVE_OS=0
	OPT_OS=
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -Os adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_OS=1
		OPT_OS=-Os
	fi
fi

# Hit or miss, mostly hit
if [[ (-z "$HAVE_OFAST") ]]; then
	HAVE_OFAST=0
	OPT_OFAST=
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -Ofast adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_OFAST=1
		OPT_OFAST=-Ofast
	fi
fi

# Use a fallback strategy so OPT_G2 can be used with RELEASE_CXXFLAGS
OPT_G2=
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -g2 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	OPT_G2=-g2
else
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -g adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		OPT_G2=-g
	fi
fi

# Use a fallback strategy so OPT_G3 can be used with DEBUG_CXXFLAGS
OPT_G3=
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -g3 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	OPT_G3=-g3
else
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -g adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		OPT_G3=-g
	fi
fi

# Cygwin and noisy compiles
OPT_PIC=
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_PIC") ]]; then
	HAVE_PIC=0
	PIC_PROBLEMS=$("$CXX" -DCRYPTOPP_ADHOC_MAIN -fPIC adhoc.cpp -o "$TMPDIR/adhoc.exe" 2>&1 | "$GREP" -i -c -E  '(warning|error)')
	if [[ "$PIC_PROBLEMS" -eq "0" ]]; then
		HAVE_PIC=1
		OPT_PIC=-fPIC
		if [[ ("$XLC_COMPILER" -eq "1") ]]; then
			OPT_PIC=-qpic
		fi
	fi
fi

# GCC 4.8; Clang 3.4
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_UBSAN") ]]; then
	HAVE_UBSAN=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -fsanitize=undefined adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		"$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ ("$?" -eq "0") ]]; then
			HAVE_UBSAN=1
		fi
	fi
fi

# GCC 4.8; Clang 3.4
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_ASAN") ]]; then
	HAVE_ASAN=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -fsanitize=address adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		"$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ ("$?" -eq "0") ]]; then
			HAVE_ASAN=1
		fi
	fi
fi

# GCC 6.0; maybe Clang
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_BSAN") ]]; then
	HAVE_BSAN=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -fsanitize=bounds-strict adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		"$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ ("$?" -eq "0") ]]; then
			HAVE_BSAN=1
		fi
	fi
fi

# GCC 8.0; maybe Clang?
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CET") ]]; then
	HAVE_CET=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -fcf-protection=full -mcet adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		"$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ ("$?" -eq "0") ]]; then
			HAVE_CET=1
		fi
	fi
fi

# Meltdown and Specter. This is the Reptoline fix
rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_REPTOLINE") ]]; then
	HAVE_REPTOLINE=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -mfunction-return=thunk -mindirect-branch=thunk adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		"$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ ("$?" -eq "0") ]]; then
			HAVE_REPTOLINE=1
		fi
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_OMP") ]]; then
	HAVE_OMP=0
	if [[ "$GCC_COMPILER" -ne "0" ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -fopenmp -O3 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_OMP=1
			OMP_FLAGS=(-fopenmp -O3)
		fi
	elif [[ "$INTEL_COMPILER" -ne "0" ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -openmp -O3 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_OMP=1
			OMP_FLAGS=(-openmp -O3)
		fi
	elif [[ "$CLANG_COMPILER" -ne "0" ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -fopenmp=libomp -O3 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_OMP=1
			OMP_FLAGS=(-fopenmp=libomp -O3)
		fi
	elif [[ "$SUN_COMPILER" -ne "0" ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -xopenmp=parallel -xO3 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_OMP=1
			OMP_FLAGS=(-xopenmp=parallel -xO3)
		fi
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_INTEL_MULTIARCH") ]]; then
	HAVE_INTEL_MULTIARCH=0
	if [[ ("$IS_DARWIN" -ne "0") && ("$IS_X86" -ne "0" || "$IS_X64" -ne "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -arch i386 -arch x86_64 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_INTEL_MULTIARCH=1
		fi
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_PPC_MULTIARCH") ]]; then
	HAVE_PPC_MULTIARCH=0
	if [[ ("$IS_DARWIN" -ne "0") && ("$IS_PPC32" -ne "0" || "$IS_PPC64" -ne "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -arch ppc -arch ppc64 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_PPC_MULTIARCH=1
		fi
	fi
fi

rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_X32") ]]; then
	HAVE_X32=0
	if [[ "$IS_X32" -ne "0" ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -mx32 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_X32=1
		fi
	fi
fi

# Hit or miss, mostly hit
if [[ (-z "$HAVE_NATIVE_ARCH") ]]; then
	HAVE_NATIVE_ARCH=0
	rm -f "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -march=native adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_NATIVE_ARCH=1
	fi
fi

# ld-gold linker testing
if [[ (-z "$HAVE_LDGOLD") ]]; then
	HAVE_LDGOLD=0
	LD_GOLD=$(command -v ld.gold 2>/dev/null)
	ELF_FILE=$(command -v file 2>/dev/null)
	if [[ (! -z "$LD_GOLD") && (! -z "$ELF_FILE") ]]; then
		LD_GOLD=$(file "$LD_GOLD" | cut -d":" -f 2 | "$GREP" -i -c "elf")
		if [[ ("$LD_GOLD" -ne "0") ]]; then
			"$CXX" -DCRYPTOPP_ADHOC_MAIN -fuse-ld=gold adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
			if [[ "$?" -eq "0" ]]; then
				HAVE_LDGOLD=1
			fi
		fi
	fi
fi

# ARMv7 and ARMv8, including NEON, CRC32 and Crypto extensions
if [[ ("$IS_ARM32" -ne "0" || "$IS_ARM64" -ne "0") ]]; then

	if [[ (-z "$HAVE_ARMV7A" && "$IS_ARM32" -ne "0") ]]; then
		HAVE_ARMV7A=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c 'neon')
		if [[ ("$HAVE_ARMV7A" -gt "0") ]]; then HAVE_ARMV7A=1; fi
	fi

	if [[ (-z "$HAVE_ARMV8A" && ("$IS_ARM32" -ne "0" || "$IS_ARM64" -ne "0")) ]]; then
		HAVE_ARMV8A=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c -E '(asimd|crc|crypto)')
		if [[ ("$HAVE_ARMV8A" -gt "0") ]]; then HAVE_ARMV8A=1; fi
	fi

	if [[ (-z "$HAVE_ARM_VFPV3") ]]; then
		HAVE_ARM_VFPV3=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c 'vfpv3')
		if [[ ("$HAVE_ARM_VFPV3" -gt "0") ]]; then HAVE_ARM_VFPV3=1; fi
	fi

	if [[ (-z "$HAVE_ARM_VFPV4") ]]; then
		HAVE_ARM_VFPV4=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c 'vfpv4')
		if [[ ("$HAVE_ARM_VFPV4" -gt "0") ]]; then HAVE_ARM_VFPV4=1; fi
	fi

	if [[ (-z "$HAVE_ARM_VFPV5") ]]; then
		HAVE_ARM_VFPV5=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c 'fpv5')
		if [[ ("$HAVE_ARM_VFPV5" -gt "0") ]]; then HAVE_ARM_VFPV5=1; fi
	fi

	if [[ (-z "$HAVE_ARM_VFPD32") ]]; then
		HAVE_ARM_VFPD32=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c 'vfpd32')
		if [[ ("$HAVE_ARM_VFPD32" -gt "0") ]]; then HAVE_ARM_VFPD32=1; fi
	fi

	if [[ (-z "$HAVE_ARM_NEON") ]]; then
		HAVE_ARM_NEON=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c 'neon')
		if [[ ("$HAVE_ARM_NEON" -gt "0") ]]; then HAVE_ARM_NEON=1; fi
	fi

	if [[ (-z "$HAVE_ARM_CRYPTO") ]]; then
		HAVE_ARM_CRYPTO=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c -E '(aes|pmull|sha1|sha2)')
		if [[ ("$HAVE_ARM_CRYPTO" -gt "0") ]]; then HAVE_ARM_CRYPTO=1; fi
	fi

	if [[ (-z "$HAVE_ARM_CRC") ]]; then
		HAVE_ARM_CRC=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c 'crc32')
		if [[ ("$HAVE_ARM_CRC" -gt "0") ]]; then HAVE_ARM_CRC=1; fi
	fi
fi

# Valgrind testing of C++03, C++11, C++14 and C++17 binaries. Valgrind tests take a long time...
if [[ (-z "$HAVE_VALGRIND") ]]; then
	if [[ $(command -v valgrind 2>/dev/null) ]]; then
		HAVE_VALGRIND=1
	fi
fi

# Try to find a symbolizer for Asan
if [[ (-z "$HAVE_SYMBOLIZE") && (! -z "$ASAN_SYMBOLIZER_PATH") ]]; then
	# Sets default value
	if [[ $(command -v asan_symbolize 2>/dev/null) ]]; then
		HAVE_SYMBOLIZE=1
	fi
	if [[ (("$HAVE_SYMBOLIZE" -ne "0") && (-z "$ASAN_SYMBOLIZE")) ]]; then
		ASAN_SYMBOLIZE=asan_symbolize
	fi

	# Clang implicitly uses ASAN_SYMBOLIZER_PATH; set it if its not set.
	if [[ (-z "$ASAN_SYMBOLIZER_PATH") ]]; then
		if [[ $(command -v llvm-symbolizer 2>/dev/null) ]]; then
			LLVM_SYMBOLIZER_FOUND=1;
		fi
		if [[ ("$LLVM_SYMBOLIZER_FOUND" -ne "0") ]]; then
			ASAN_SYMBOLIZER_PATH=$(command -v llvm-symbolizer)
			export ASAN_SYMBOLIZER_PATH
		fi
	fi
fi

# Used to disassemble object modules so we can verify some aspects of code generation
if [[ (-z "$HAVE_DISASS") ]]; then
	echo "int main(int argc, char* argv[]) {return 0;}" > "$TMPDIR/test.cc"
	"$CXX" "$TMPDIR/test.cc" -o "$TMPDIR/test.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		"$DISASS" "${DISASSARGS[@]}" "$TMPDIR/test.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_DISASS=1
		else
			HAVE_DISASS=0
		fi
	fi
fi

# LD_LIBRARY_PATH and DYLD_LIBRARY_PATH
if [[ "$IS_LINUX" -ne "0" || "$IS_SOLARIS" -ne "0" || "$IS_BSD" -ne "0" ]]; then
    HAVE_LD_LIBRARY_PATH=1
fi
if [[ "$IS_DARWIN" -ne "0" ]]; then
    HAVE_DYLD_LIBRARY_PATH=1
fi

# Fixup... GCC 4.8 ASAN produces false positives under ARM
if [[ ( ("$IS_ARM32" -ne "0" || "$IS_ARM64" -ne "0") && "$GCC_48_COMPILER" -ne "0") ]]; then
	HAVE_ASAN=0
fi

# Benchmarks take a long time...
if [[ (-z "$WANT_BENCHMARKS") ]]; then
	WANT_BENCHMARKS=1
fi

# IBM XL C/C++ compiler fixups. Not sure why it fails to return non-0 on failure...
if [[ "$XLC_COMPILER" -ne "0" ]]; then
	HAVE_CXX03=0
	HAVE_GNU03=0
	HAVE_CXX11=0
	HAVE_GNU11=0
	HAVE_CXX14=0
	HAVE_GNU14=0
	HAVE_CXX17=0
	HAVE_GNU17=0
	HAVE_CXX20=0
	HAVE_GNU20=0
	HAVE_OMP=0
	HAVE_CET=0
	HAVE_REPTOLINE=0
	HAVE_ASAN=0
	HAVE_BSAN=0
	HAVE_UBSAN=0
	HAVE_LDGOLD=0
fi

############################################
# System information

echo | tee -a "$TEST_RESULTS"
if [[ "$IS_LINUX" -ne "0" ]]; then
	echo "IS_LINUX: $IS_LINUX" | tee -a "$TEST_RESULTS"
elif [[ "$IS_CYGWIN" -ne "0" ]]; then
	echo "IS_CYGWIN: $IS_CYGWIN" | tee -a "$TEST_RESULTS"
elif [[ "$IS_MINGW" -ne "0" ]]; then
	echo "IS_MINGW: $IS_MINGW" | tee -a "$TEST_RESULTS"
elif [[ "$IS_SOLARIS" -ne "0" ]]; then
	echo "IS_SOLARIS: $IS_SOLARIS" | tee -a "$TEST_RESULTS"
elif [[ "$IS_DARWIN" -ne "0" ]]; then
	echo "IS_DARWIN: $IS_DARWIN" | tee -a "$TEST_RESULTS"
elif [[ "$IS_AIX" -ne "0" ]]; then
	echo "IS_AIX: $IS_AIX" | tee -a "$TEST_RESULTS"
fi

if [[ "$IS_PPC64" -ne "0" ]]; then
	echo "IS_PPC64: $IS_PPC64" | tee -a "$TEST_RESULTS"
elif [[ "$IS_PPC32" -ne "0" ]]; then
	echo "IS_PPC32: $IS_PPC32" | tee -a "$TEST_RESULTS"
fi
if [[ "$IS_ARM64" -ne "0" ]]; then
	echo "IS_ARM64: $IS_ARM64" | tee -a "$TEST_RESULTS"
elif [[ "$IS_ARM32" -ne "0" ]]; then
	echo "IS_ARM32: $IS_ARM32" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARMV7A" -ne "0" ]]; then
	echo "HAVE_ARMV7A: $HAVE_ARMV7A" | tee -a "$TEST_RESULTS"
elif [[ "$HAVE_ARMV8A" -ne "0" ]]; then
	echo "HAVE_ARMV8A: $HAVE_ARMV8A" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_NEON" -ne "0" ]]; then
	echo "HAVE_ARM_NEON: $HAVE_ARM_NEON" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_VFPD32" -ne "0" ]]; then
	echo "HAVE_ARM_VFPD32: $HAVE_ARM_VFPD32" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_VFPV3" -ne "0" ]]; then
	echo "HAVE_ARM_VFPV3: $HAVE_ARM_VFPV3" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_VFPV4" -ne "0" ]]; then
	echo "HAVE_ARM_VFPV4: $HAVE_ARM_VFPV4" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_CRC" -ne "0" ]]; then
	echo "HAVE_ARM_CRC: $HAVE_ARM_CRC" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_CRYPTO" -ne "0" ]]; then
	echo "HAVE_ARM_CRYPTO: $HAVE_ARM_CRYPTO" | tee -a "$TEST_RESULTS"
fi

if [[ "$IS_X32" -ne "0" ]]; then
    echo "IS_X32: $IS_X32" | tee -a "$TEST_RESULTS"
elif [[ "$IS_X64" -ne "0" ]]; then
	echo "IS_X64: $IS_X64" | tee -a "$TEST_RESULTS"
elif [[ "$IS_X86" -ne "0" ]]; then
	echo "IS_X86: $IS_X86" | tee -a "$TEST_RESULTS"
fi

if [[ "$IS_S390" -ne "0" ]]; then
    echo "IS_S390: $IS_S390" | tee -a "$TEST_RESULTS"
fi

# C++03, C++11, C++14 and C++17
echo | tee -a "$TEST_RESULTS"
echo "HAVE_CXX03: $HAVE_CXX03" | tee -a "$TEST_RESULTS"
echo "HAVE_GNU03: $HAVE_GNU03" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX11: $HAVE_CXX11" | tee -a "$TEST_RESULTS"
echo "HAVE_GNU11: $HAVE_GNU11" | tee -a "$TEST_RESULTS"
if [[ ("$HAVE_CXX14" -ne "0" || "$HAVE_CXX17" -ne "0" || "$HAVE_CXX20" -ne "0" || "$HAVE_GNU14" -ne "0" || "$HAVE_GNU17" -ne "0" || "$HAVE_GNU20" -ne "0") ]]; then
	echo "HAVE_CXX14: $HAVE_CXX14" | tee -a "$TEST_RESULTS"
	echo "HAVE_GNU14: $HAVE_GNU14" | tee -a "$TEST_RESULTS"
	echo "HAVE_CXX17: $HAVE_CXX17" | tee -a "$TEST_RESULTS"
	echo "HAVE_GNU17: $HAVE_GNU17" | tee -a "$TEST_RESULTS"
	echo "HAVE_CXX20: $HAVE_CXX20" | tee -a "$TEST_RESULTS"
	echo "HAVE_GNU20: $HAVE_GNU20" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_LDGOLD" -ne "0" ]]; then
	echo "HAVE_LDGOLD: $HAVE_LDGOLD" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_UNIFIED_ASM" -ne "0" ]]; then
	echo "HAVE_UNIFIED_ASM: $HAVE_UNIFIED_ASM" | tee -a "$TEST_RESULTS"
fi

# -O3, -O5 and -Os
echo | tee -a "$TEST_RESULTS"
echo "OPT_O2: $OPT_O2" | tee -a "$TEST_RESULTS"
echo "OPT_O3: $OPT_O3" | tee -a "$TEST_RESULTS"
if [[ (! -z "$OPT_O5") || (! -z "$OPT_OS") || (! -z "$OPT_OFAST") ]]; then
	echo "OPT_O5: $OPT_O5" | tee -a "$TEST_RESULTS"
	echo "OPT_OS: $OPT_OS" | tee -a "$TEST_RESULTS"
	echo "OPT_OFAST: $OPT_OFAST" | tee -a "$TEST_RESULTS"
fi

# Tools available for testing
echo | tee -a "$TEST_RESULTS"
if [[ ((! -z "$HAVE_OMP") && ("$HAVE_OMP" -ne "0")) ]]; then echo "HAVE_OMP: $HAVE_OMP" | tee -a "$TEST_RESULTS"; fi
echo "HAVE_ASAN: $HAVE_ASAN" | tee -a "$TEST_RESULTS"
if [[ ("$HAVE_ASAN" -ne "0") && (! -z "$ASAN_SYMBOLIZE") ]]; then echo "ASAN_SYMBOLIZE: $ASAN_SYMBOLIZE" | tee -a "$TEST_RESULTS"; fi
echo "HAVE_UBSAN: $HAVE_UBSAN" | tee -a "$TEST_RESULTS"
echo "HAVE_BSAN: $HAVE_BSAN" | tee -a "$TEST_RESULTS"
echo "HAVE_CET: $HAVE_CET" | tee -a "$TEST_RESULTS"
echo "HAVE_REPTOLINE: $HAVE_REPTOLINE" | tee -a "$TEST_RESULTS"
echo "HAVE_VALGRIND: $HAVE_VALGRIND" | tee -a "$TEST_RESULTS"
# HAVE_REPTOLINE is for Meltdown and Spectre option testing, called Reptoline (play on trampoline)

if [[ "$HAVE_INTEL_MULTIARCH" -ne "0" ]]; then
	echo "HAVE_INTEL_MULTIARCH: $HAVE_INTEL_MULTIARCH" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_PPC_MULTIARCH" -ne "0" ]]; then
	echo "HAVE_PPC_MULTIARCH: $HAVE_PPC_MULTIARCH" | tee -a "$TEST_RESULTS"
fi

############################################

# CPU is logical count, memory is in MiB. Low resource boards have
#   fewer than 4 cores and 1GB or less memory. We use this to
#   determine if we can build in parallel without an OOM kill.
CPU_COUNT=1
MEM_SIZE=512

if [[ ("$IS_SPARC" -ne "0") && ("$IS_LINUX" -ne "0") ]]; then
	CPU_COUNT="$($GREP -E 'CPU.*' /proc/cpuinfo | cut -f 1 -d ':' | $SED 's|CPU||g' | sort -n | tail -1)"
	MEM_SIZE="$($GREP "MemTotal" < /proc/meminfo | $AWK '{print int($2/1024)}')"
elif [[ (-e "/proc/cpuinfo") && (-e "/proc/meminfo") ]]; then
	CPU_COUNT="$($GREP -c -E "^processor" < /proc/cpuinfo)"
	MEM_SIZE="$($GREP "MemTotal" < /proc/meminfo | $AWK '{print int($2/1024)}')"
elif [[ "$IS_DARWIN" -ne "0" ]]; then
	CPU_COUNT="$(sysctl -a 2>&1 | $GREP "hw.availcpu" | $AWK '{print $3; exit}')"
	MEM_SIZE="$(sysctl -a 2>&1 | $GREP "hw.memsize" | $AWK '{print int($3/1024/1024); exit;}')"
elif [[ "$IS_SOLARIS" -ne "0" ]]; then
	CPU_COUNT="$(psrinfo 2>/dev/null | wc -l | $AWK '{print $1}')"
	MEM_SIZE="$(prtconf 2>/dev/null | $GREP "Memory" | $AWK '{print int($3)}')"
elif [[ "$IS_AIX" -ne "0" ]]; then
	CPU_COUNT="$(bindprocessor -q 2>/dev/null | cut -f 2 -d ":" | wc -w | $AWK '{print $1}')"
	MEM_SIZE="$(prtconf -m 2>/dev/null | $GREP "MB" | $AWK '{print int($3); exit;}')"
fi

# Benchmarks expect frequency in GiHz.
CPU_FREQ=0.5
if [[ (-e "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq") ]]; then
	CPU_FREQ="$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)"
	CPU_FREQ="$(echo $CPU_FREQ | $AWK '{print $0/1024/1024; exit}')"
elif [[ (-e "/proc/cpuinfo") ]]; then
	CPU_FREQ="$($GREP 'MHz' < /proc/cpuinfo | $AWK '{print $4; exit}')"
	if [[ -z "$CPU_FREQ" ]]; then CPU_FREQ=512; fi
	CPU_FREQ="$(echo $CPU_FREQ | $AWK '{print $0/1024}')"
elif [[ "$IS_DARWIN" -ne "0" ]]; then
	CPU_FREQ="$(sysctl -a 2>&1 | $GREP "hw.cpufrequency" | $AWK '{print ($3); exit;}')"
	CPU_FREQ="$(echo $CPU_FREQ | $AWK '{print $0/1024/1024/1024}')"
elif [[ "$IS_SOLARIS" -ne "0" ]]; then
	CPU_FREQ="$(psrinfo -v 2>/dev/null | $GREP "MHz" | $AWK '{print $6; exit;}')"
	CPU_FREQ="$(echo $CPU_FREQ | $AWK '{print $0/1024}')"
elif [[ "$IS_AIX" -ne "0" ]]; then
	CPU_FREQ="$(prtconf -s 2>/dev/null | $GREP "MHz" | $AWK '{print $4; exit;}')"
	CPU_FREQ="$(echo $CPU_FREQ | $AWK '{print $0/1024}')"
fi

# Some ARM devboards cannot use 'make -j N', even with multiple cores and RAM
#  An 8-core Cubietruck Plus with 2GB RAM experiences OOM kills with '-j 2'.
HAVE_SWAP=1
if [[ "$IS_LINUX" -ne "0" ]]; then
	if [[ (-e "/proc/meminfo") ]]; then
		SWAP_SIZE="$($GREP 'SwapTotal' < /proc/meminfo | "$AWK" '{print $2}')"
		if [[ "$SWAP_SIZE" -eq "0" ]]; then
			HAVE_SWAP=0
		fi
	else
		HAVE_SWAP=0
	fi
fi

echo | tee -a "$TEST_RESULTS"
echo "CPU: $CPU_COUNT logical" | tee -a "$TEST_RESULTS"
echo "FREQ: $CPU_FREQ GHz" | tee -a "$TEST_RESULTS"
echo "MEM: $MEM_SIZE MB" | tee -a "$TEST_RESULTS"

if [[ ("$CPU_COUNT" -ge "2" && "$MEM_SIZE" -ge "1280" && "$HAVE_SWAP" -ne "0") ]]; then
	if [[ ("$WANT_NICE" -eq "1") ]]; then
		CPU_COUNT=$(echo -n "$CPU_COUNT 2" | "$AWK" '{print int($1/$2)}')
	fi
	MAKEARGS=(-j "$CPU_COUNT")
	echo "Using $MAKE -j $CPU_COUNT"
fi

############################################

GIT_REPO=$(git branch 2>&1 | "$GREP" -v "fatal" | wc -l | "$AWK" '{print $1; exit;}')
if [[ "$GIT_REPO" -ne "0" ]]; then
	GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
	GIT_HASH=$(git rev-parse HEAD 2>/dev/null | cut -c 1-16)
fi

echo | tee -a "$TEST_RESULTS"
if [[ ! -z "$GIT_BRANCH" ]]; then
	echo "Git branch: $GIT_BRANCH (commit $GIT_HASH)" | tee -a "$TEST_RESULTS"
fi

if [[ ("$SUN_COMPILER" -ne "0") ]]; then
	"$CXX" -V 2>&1 | "$SED" 's|CC:|Compiler:|g' | head -1 | tee -a "$TEST_RESULTS"
elif [[ ("$XLC_COMPILER" -ne "0") ]]; then
	echo "Compiler: $($CXX -qversion | head -1)" | tee -a "$TEST_RESULTS"
else
	echo "Compiler: $($CXX --version | head -1)" | tee -a "$TEST_RESULTS"
fi

CXX_PATH=$(command -v "$CXX" 2>/dev/null)
CXX_SYMLINK=$(ls -l "$CXX_PATH" 2>/dev/null | "$GREP" -c '\->' | "$AWK" '{print $1}')
if [[ ("$CXX_SYMLINK" -ne "0") ]]; then CXX_PATH="$CXX_PATH (symlinked)"; fi
echo "Pathname: $CXX_PATH" | tee -a "$TEST_RESULTS"

############################################

# Calculate these once. They handle Clang, GCC, ICC, etc
DEBUG_CXXFLAGS="-DDEBUG $OPT_G3 $OPT_O0"
RELEASE_CXXFLAGS="-DNDEBUG $OPT_G2 $OPT_O3"
VALGRIND_CXXFLAGS="-DNDEBUG $OPT_G3 $OPT_O1"
WARNING_CXXFLAGS=()

if [[ ("$GCC_COMPILER" -ne "0" || "$CLANG_COMPILER" -ne "0") ]]; then
	WARNING_CXXFLAGS+=("-Wall" "-Wextra" "-Wno-unknown-pragmas" "-Wstrict-overflow")
	WARNING_CXXFLAGS+=("-Wcast-align" "-Wwrite-strings" "-Wformat=2" "-Wformat-security")
fi

# On PowerPC we test the original Altivec load and store with unaligned data.
# Modern compilers generate a warning and recommend the new loads and stores.
if [[ ("$GCC_COMPILER" -ne "0" && ("$IS_PPC32" -ne "0" || "$IS_PPC64" -ne "0") ) ]]; then
	WARNING_CXXFLAGS+=("-Wno-deprecated")
fi

echo | tee -a "$TEST_RESULTS"
echo "DEBUG_CXXFLAGS: $DEBUG_CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "RELEASE_CXXFLAGS: $RELEASE_CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "VALGRIND_CXXFLAGS: $VALGRIND_CXXFLAGS" | tee -a "$TEST_RESULTS"
if [[ (! -z "$USER_CXXFLAGS") ]]; then
	echo "USER_CXXFLAGS: $USER_CXXFLAGS" | tee -a "$TEST_RESULTS"
fi

#############################################
#############################################
############### BEGIN TESTING ###############
#############################################
#############################################

TEST_BEGIN=$(date)
echo | tee -a "$TEST_RESULTS"
echo "Start time: $TEST_BEGIN" | tee -a "$TEST_RESULTS"

############################################
# Posix NDEBUG and assert
if true; then

	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: No Posix NDEBUG or assert" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("No Posix NDEBUG or assert")
	FAILED=0

	# Filter out C++ and Doxygen comments.
	COUNT=$(cat ./*.h ./*.cpp | "$GREP" -v '//' | "$GREP" -c -E '(assert.h|cassert)')
	if [[ "$COUNT" -ne "0" ]]; then
		FAILED=1
		echo "FAILED: found Posix assert headers" | tee -a "$TEST_RESULTS"
	fi

	# Filter out C++ and Doxygen comments.
	COUNT=$(cat ./*.h ./*.cpp | "$GREP" -v '//' | "$GREP" -c -E 'assert[[:space:]]*\(')
	if [[ "$COUNT" -ne "0" ]]; then
		FAILED=1
		echo "FAILED: found use of Posix assert" | tee -a "$TEST_RESULTS"
	fi

	# Filter out C++ and Doxygen comments.
	COUNT=$(cat ./*.h ./*.cpp | "$GREP" -v '//' | "$GREP" -c 'NDEBUG')
	if [[ "$COUNT" -ne "0" ]]; then
		FAILED=1
		echo "FAILED: found use of Posix NDEBUG" | tee -a "$TEST_RESULTS"
	fi

	if [[ ("$FAILED" -eq "0") ]]; then
		echo "Verified no Posix NDEBUG or assert" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# C++ std::min and std::max
# This is due to Windows.h and NOMINMAX. Linux test fine, while Windows breaks.
if true; then

	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: C++ std::min and std::max" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("C++ std::min and std::max")
	FAILED=0

	# If this fires, then use the library's STDMIN(a,b) or (std::min)(a, b);
	COUNT=$(cat ./*.h ./*.cpp | "$GREP" -v '//' | "$GREP" -c -E 'std::min[[:space:]]*\(')
	if [[ "$COUNT" -ne "0" ]]; then
		FAILED=1
		echo "FAILED: found std::min" | tee -a "$TEST_RESULTS"
	fi

	# If this fires, then use the library's STDMAX(a,b) or (std::max)(a, b);
	COUNT=$(cat ./*.h ./*.cpp | "$GREP" -v '//' | "$GREP" -c -E 'std::max[[:space:]]*\(')
	if [[ "$COUNT" -ne "0" ]]; then
		FAILED=1
		echo "FAILED: found std::max" | tee -a "$TEST_RESULTS"
	fi

	if [[ ("$FAILED" -eq "0") ]]; then
		echo "Verified std::min and std::max" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# X86 code generation tests
if [[ ("$HAVE_DISASS" -ne "0" && ("$IS_X86" -ne "0" || "$IS_X64" -ne "0")) ]]; then

	############################################
	# X86 rotate immediate code generation

	X86_ROTATE_IMM=1
	if [[ ("$X86_ROTATE_IMM" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: X86 rotate immediate code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("X86 rotate immediate code generation")

		OBJFILE=sha.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		X86_SSE2=$(echo -n "$X86_CPU_FLAGS" | "$GREP" -i -c sse2)
		X86_SHA256_HASH_BLOCKS=$(echo -n "$DISASS_TEXT" | "$GREP" -c 'SHA256_HashMultipleBlocks_SSE2')
		if [[ ("$X86_SHA256_HASH_BLOCKS" -ne "0") ]]; then
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E '(rol.*0x|ror.*0x)')
			if [[ ("$COUNT" -le "250") ]]; then
				FAILED=1
				echo "ERROR: failed to generate rotate immediate instruction (SHA256_HashMultipleBlocks_SSE2)" | tee -a "$TEST_RESULTS"
			fi
		else
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E '(rol.*0x|ror.*0x)')
			if [[ ("$COUNT" -le "500") ]]; then
				FAILED=1
				echo "ERROR: failed to generate rotate immediate instruction" | tee -a "$TEST_RESULTS"
			fi
		fi

		if [[ ("$X86_SSE2" -ne "0" && "$X86_SHA256_HASH_BLOCKS" -eq "0") ]]; then
			echo "ERROR: failed to use SHA256_HashMultipleBlocks_SSE2" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0" && "$X86_SHA256_HASH_BLOCKS" -ne "0") ]]; then
			echo "Verified rotate immediate machine instructions (SHA256_HashMultipleBlocks_SSE2)" | tee -a "$TEST_RESULTS"
		elif [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified rotate immediate machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Test CRC-32C code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -msse4.2 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		X86_CRC32=1
	fi

	if [[ ("$X86_CRC32" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: X86 CRC32 code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("X86 CRC32 code generation")

		OBJFILE=crc_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c crc32b)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate crc32b instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c crc32l)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate crc32l instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified crc32b and crc32l machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Test AES-NI code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -maes adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		X86_AESNI=1
	fi

	if [[ ("$X86_AESNI" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: X86 AES-NI code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("X86 AES-NI code generation")

		OBJFILE=rijndael_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aesenc)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aesenc instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aesenclast)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aesenclast instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aesdec)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aesdec instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aesdeclast)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aesdeclast instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aesimc)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aesimc instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aeskeygenassist)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aeskeygenassist instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified aesenc, aesenclast, aesdec, aesdeclast, aesimc, aeskeygenassist machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# X86 carryless multiply code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -mpclmul adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		X86_PCLMUL=1
	fi

	if [[ ("$X86_PCLMUL" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: X86 carryless multiply code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("X86 carryless multiply code generation")

		OBJFILE=gcm_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E '(pclmulqdq|pclmullqhq|vpclmulqdq)')
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate pclmullqhq instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E '(pclmulqdq|pclmullqlq|vpclmulqdq)')
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate pclmullqlq instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified pclmullqhq and pclmullqlq machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Test RDRAND and RDSEED code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -mrdrnd adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		X86_RDRAND=1
	fi
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -mrdseed adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		X86_RDSEED=1
	fi

	if [[ ("$X86_RDRAND" -ne "0" || "$X86_RDSEED" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: X86 RDRAND and RDSEED code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("X86 RDRAND and RDSEED code generation")

		OBJFILE=rdrand.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		if [[ "$X86_RDRAND" -ne "0" ]]; then
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c rdrand)
			if [[ ("$COUNT" -eq "0") ]]; then
				FAILED=1
				echo "ERROR: failed to generate rdrand instruction" | tee -a "$TEST_RESULTS"
			fi
		fi

		if [[ "$X86_RDSEED" -ne "0" ]]; then
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c rdseed)
			if [[ ("$COUNT" -eq "0") ]]; then
				FAILED=1
				echo "ERROR: failed to generate rdseed instruction" | tee -a "$TEST_RESULTS"
			fi
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified rdrand and rdseed machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# X86 SHA code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -msha adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		X86_SHA=1
	fi

	if [[ ("$X86_SHA" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: X86 SHA code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("X86 SHA code generation")

		OBJFILE=sha_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1rnds4)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1rnds4 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1nexte)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1nexte instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1msg1)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1msg1 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1msg2)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1msg2 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha256rnds2)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha256rnds2 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha256msg1)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha256msg1 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha256msg2)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha256msg2 instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified sha1rnds4, sha1nexte, sha1msg1, sha1msg2, sha256rnds2, sha256msg1 and sha256msg2 machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# ARM code generation tests
if [[ ("$HAVE_DISASS" -ne "0" && ("$IS_ARM32" -ne "0" || "$IS_ARM64" -ne "0")) ]]; then

	############################################
	# ARM NEON code generation

	ARM_NEON=$(echo -n "$ARM_CPU_FLAGS" | "$GREP" -i -c -E '(neon|asimd)')
	if [[ ("$ARM_NEON" -ne "0" || "$HAVE_ARM_NEON" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: ARM NEON code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("ARM NEON code generation")

		OBJFILE=aria_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		if [[ ("$HAVE_ARMV8A" -ne "0") ]]; then
			# ARIA::UncheckedKeySet: 4 ldr q{N}
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'ldr[[:space:]]*q')
			if [[ ("$COUNT" -lt "4") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON load instructions" | tee -a "$TEST_RESULTS"
			fi
		else  # ARMv7
			# ARIA::UncheckedKeySet: 4 vld1.32 {d1,d2}
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'vld1.32[[:space:]]*{')
			if [[ ("$COUNT" -lt "4") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON load instructions" | tee -a "$TEST_RESULTS"
			fi
		fi

		if [[ ("$HAVE_ARMV8A" -ne "0") ]]; then
			# ARIA::UncheckedKeySet: 17 str q{N}
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'str[[:space:]]*q')
			if [[ ("$COUNT" -lt "16") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON store instructions" | tee -a "$TEST_RESULTS"
			fi
		else
			# ARIA::UncheckedKeySet: 17 vstr1.32 {d1,d2}
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'vst1.32[[:space:]]*{')
			if [[ ("$COUNT" -lt "16") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON store instructions" | tee -a "$TEST_RESULTS"
			fi
		fi

		if [[ ("$HAVE_ARMV8A" -ne "0") ]]; then
			# ARIA::UncheckedKeySet: 17 shl v{N}
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'shl[[:space:]]*v')
			if [[ ("$COUNT" -lt "16") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON shift left instructions" | tee -a "$TEST_RESULTS"
			fi
		else
			# ARIA::UncheckedKeySet: 17 vshl
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'vshl')
			if [[ ("$COUNT" -lt "16") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON store instructions" | tee -a "$TEST_RESULTS"
			fi
		fi

		if [[ ("$HAVE_ARMV8A" -ne "0") ]]; then
			# ARIA::UncheckedKeySet: 17 shr v{N}
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'shr[[:space:]]*v')
			if [[ ("$COUNT" -lt "16") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON shift left instructions" | tee -a "$TEST_RESULTS"
			fi
		else
			# ARIA::UncheckedKeySet: 17 vshr
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'vshr')
			if [[ ("$COUNT" -lt "16") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON store instructions" | tee -a "$TEST_RESULTS"
			fi
		fi

		if [[ ("$HAVE_ARMV8A" -ne "0") ]]; then
			# ARIA::UncheckedKeySet: 12 ext v{N}
			COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'ext[[:space:]]*v')
			if [[ ("$COUNT" -lt "12") ]]; then
				FAILED=1
				echo "ERROR: failed to generate NEON extract instructions" | tee -a "$TEST_RESULTS"
			fi
		fi

		# ARIA::UncheckedKeySet: 17 veor
		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c -E 'eor.*v|veor')
		if [[ ("$COUNT" -lt "16") ]]; then
			FAILED=1
			echo "ERROR: failed to generate NEON xor instructions" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified NEON load, store, shfit left, shift right, xor machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# ARM CRC32 code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -march=armv8-a+crc adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		ARM_CRC32=1
	fi

	if [[ ("$HAVE_ARMV8A" -ne "0" && "$ARM_CRC32" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: ARM CRC32 code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("ARM CRC32 code generation")

		OBJFILE=crc_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c crc32cb)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate crc32cb instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c crc32cw)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate crc32cw instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c crc32b)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate crc32b instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c crc32w)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate crc32w instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified crc32cb, crc32cw, crc32b and crc32w machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# ARM carryless multiply code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -march=armv8-a+crypto adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		ARM_PMULL=1
	fi

	if [[ ("$HAVE_ARMV8A" -ne "0" && "$ARM_PMULL" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: ARM carryless multiply code generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("ARM carryless multiply code generation")

		OBJFILE=gcm_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -v pmull2 | "$GREP" -i -c pmull)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate pmull instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c pmull2)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate pmull2 instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified pmull and pmull2 machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# ARM AES code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -march=armv8-a+crypto adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		ARM_AES=1
	fi

	if [[ ("$HAVE_ARMV8A" -ne "0" && "$ARM_AES" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: ARM AES generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("ARM AES generation")

		OBJFILE=rijndael_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aese)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aese instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aesmc)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aesmc instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aesd)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aesd instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c aesimc)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate aesimc instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified aese, aesd, aesmc, aesimc machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# ARM SHA code generation

	"$CXX" -DCRYPTOPP_ADHOC_MAIN -march=armv8-a+crypto adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		ARM_SHA=1
	fi

	if [[ ("$HAVE_ARMV8A" -ne "0" && "$ARM_SHA" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: ARM SHA generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("ARM SHA generation")

		OBJFILE=sha_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1c)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1c instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1m)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1m instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1p)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1p instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1h)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1h instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1su0)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1su0 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha1su1)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha1su1 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -v sha256h2 | "$GREP" -i -c sha256h)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha256h instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha256h2)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha256h2 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha256su0)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha256su0 instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c sha256su1)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate sha256su1 instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified sha1c, sha1m, sha1p, sha1su0, sha1su1, sha256h, sha256h2, sha256su0, sha256su1 machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Power8 code generation tests
if [[ ("$HAVE_DISASS" -ne "0" && ("$IS_PPC32" -ne "0" || "$IS_PPC64" -ne "0")) ]]; then

	############################################
	# Power8 AES

	PPC_AES=0
	if [[ ("$PPC_AES" -eq "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -mcpu=power8 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			PPC_AES=1
			PPC_AES_FLAGS="-mcpu=power8"
		fi
	fi
	if [[ ("$PPC_AES" -eq "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -qarch=pwr8 -qaltivec adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			PPC_AES=1
			PPC_AES_FLAGS="-qarch=pwr8 -qaltivec"
		fi
	fi

	if [[ ("$PPC_AES" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Power8 AES generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Power8 AES generation")

		OBJFILE=rijndael_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS $PPC_AES_FLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -v vcipherlast | "$GREP" -i -c vcipher)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate vcipher instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c vcipherlast)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate vcipherlast instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -v vncipherlast | "$GREP" -i -c vncipher)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate vncipher instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c vncipherlast)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate vncipherlast instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified vcipher, vcipherlast,vncipher, vncipherlast machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Power8 SHA

	PPC_SHA=0
	if [[ ("$PPC_SHA" -eq "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -mcpu=power8 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			PPC_SHA=1
			PPC_SHA_FLAGS="-mcpu=power8"
		fi
	fi
	if [[ ("$PPC_SHA" -eq "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -qarch=pwr8 -qaltivec adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			PPC_SHA=1
			PPC_SHA_FLAGS="-qarch=pwr8 -qaltivec"
		fi
	fi

	if [[ ("$PPC_SHA" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Power8 SHA generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Power8 SHA generation")

		OBJFILE=sha_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS $PPC_SHA_FLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c vshasigmaw)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate vshasigmaw instruction" | tee -a "$TEST_RESULTS"
		fi

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c vshasigmad)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate vshasigmad instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified vshasigmaw and vshasigmad machine instructions" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Power8 VMULL

	PPC_VMULL=0
	if [[ ("$PPC_VMULL" -eq "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -mcpu=power8 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			PPC_VMULL=1
			PPC_VMULL_FLAGS="-mcpu=power8"
		fi
	fi
	if [[ ("$PPC_VMULL" -eq "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -qarch=pwr8 adhoc.cpp -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			PPC_VMULL=1
			PPC_VMULL_FLAGS="-qarch=pwr8"
		fi
	fi

	if [[ ("$PPC_VMULL" -ne "0") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Power8 carryless multiply generation" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Power8 carryless multiply generation")

		OBJFILE=gcm_simd.o; rm -f "$OBJFILE" 2>/dev/null
		CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS $PPC_VMULL_FLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

		COUNT=0
		FAILED=0
		DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

		COUNT=$(echo -n "$DISASS_TEXT" | "$GREP" -i -c vpmsum)
		if [[ ("$COUNT" -eq "0") ]]; then
			FAILED=1
			echo "ERROR: failed to generate vpmsum instruction" | tee -a "$TEST_RESULTS"
		fi

		if [[ ("$FAILED" -eq "0") ]]; then
			echo "Verified vpmsum machine instruction" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Default CXXFLAGS
if true; then
	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, default CXXFLAGS")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		# Stop now if things are broke
		[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			# Stop now if things are broke
			[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			# Stop now if things are broke
			[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, default CXXFLAGS")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		# Stop now if things are broke
		[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			# Stop now if things are broke
			[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			# Stop now if things are broke
			[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
		fi
		echo
	fi
fi

############################################
# Shared Objects
if [[ "$HAVE_LD_LIBRARY_PATH" -ne "0" ]]; then
	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, shared object" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, shared object")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	# Create a new makefile based on the old one
	"$SED" -e 's|\./libcryptopp.a|\./libcryptopp.so|g' -e 's|cryptest.exe: libcryptopp.a|cryptest.exe: libcryptopp.so|g' GNUmakefile > GNUmakefile.shared

	CXXFLAGS="$DEBUG_CXXFLAGS"
	DYN_MAKEARGS=("-f" "GNUmakefile.shared" "HAS_SOLIB_VERSION=0" "${MAKEARGS[@]}")
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${DYN_MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		LD_LIBRARY_PATH="." ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		LD_LIBRARY_PATH="." ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, shared object" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, shared object")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS"
	DYN_MAKEARGS=("-f" "GNUmakefile.shared" "HAS_SOLIB_VERSION=0" "${MAKEARGS[@]}")
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${DYN_MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		LD_LIBRARY_PATH="." ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		LD_LIBRARY_PATH="." ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
		echo
	fi

	rm -f GNUmakefile.shared > /dev/null 2>&1
fi

############################################
# Dynamic Objects on Darwin
if [[ "$HAVE_DYLD_LIBRARY_PATH" -ne "0" ]]; then
	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, dynamic library" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, dynamic library")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	# Create a new makefile based on the old one
	"$SED" -e 's|\./libcryptopp.a|\./libcryptopp.dylib|g' -e 's|cryptest.exe: libcryptopp.a|cryptest.exe: libcryptopp.dylib|g' GNUmakefile > GNUmakefile.shared

	CXXFLAGS="$DEBUG_CXXFLAGS"
	DYN_MAKEARGS=("-f" "GNUmakefile.shared" "HAS_SOLIB_VERSION=0" "${MAKEARGS[@]}")
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${DYN_MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		DYLD_LIBRARY_PATH="." ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		DYLD_LIBRARY_PATH="." ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, dynamic library" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, dynamic library")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS"
	DYN_MAKEARGS=("-f" "GNUmakefile.shared" "HAS_SOLIB_VERSION=0" "${MAKEARGS[@]}")
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${DYN_MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		DYLD_LIBRARY_PATH="." ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		DYLD_LIBRARY_PATH="." ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
		echo
	fi

	rm -f GNUmakefile.shared > /dev/null 2>&1
fi

############################################
# Debian specific.
if [[ ("$IS_DEBIAN" -ne "0" || "$IS_UBUNTU" -ne "0") ]]; then

	# Flags taken from Debian's build logs
	# https://buildd.debian.org/status/fetch.php?pkg=libcrypto%2b%2b&arch=i386&ver=5.6.4-6
	# https://buildd.debian.org/status/fetch.php?pkg=libcrypto%2b%2b&arch=kfreebsd-amd64&ver=5.6.4-6&stamp=1482663138

	DEBIAN_FLAGS=("-DHAVE_CONFIG_H" "-I." "-Wdate-time" "-D_FORTIFY_SOURCE=2" "-g" "-O2"
	"-fstack-protector-strong" "-Wformat -Werror=format-security" "-DCRYPTOPP_INIT_PRIORITY=250"
	"-DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS" "-DNDEBUG" "-fPIC" "-DPIC")

	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debian standard build" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debian standard build")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXX="g++" "$MAKE" "${MAKEARGS[@]}" CXXFLAGS="${DEBIAN_FLAGS[*]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Fedora specific.
if [[ ("$IS_FEDORA" -ne "0") ]]; then

	# Flags taken from Fedora's build logs
	# https://kojipkgs.fedoraproject.org//packages/cryptopp/5.6.3/8.fc27/data/logs/i686/build.log
	# https://kojipkgs.fedoraproject.org//packages/cryptopp/5.6.3/8.fc27/data/logs/x86_64/build.log
	if [[ ("$IS_X86" -ne "0") ]]; then
		MARCH_OPT=(-m32 -march=i686)
	elif [[ ("$IS_X64" -ne "0") ]]; then
		MARCH_OPT=(-m64 -mtune=generic)
	fi

	FEDORA_FLAGS=("-DHAVE_CONFIG_H" "-I." "-O2" "-g" "-pipe" "-Wall" "-Werror=format-security" "-fPIC" "-DPIC"
		"-Wp,-D_FORTIFY_SOURCE=2" "-fexceptions" "-fstack-protector-strong" "--param=ssp-buffer-size=4"
		"-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1" "${MARCH_OPT[@]}" "-fasynchronous-unwind-tables")

	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Fedora standard build" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Fedora standard build")

	if [[ ! -f /usr/lib/rpm/redhat/redhat-hardened-cc1 ]]; then
		echo "ERROR: please install redhat-rpm-config package"
	else
		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXX="g++" "$MAKE" "${MAKEARGS[@]}" CXXFLAGS="${FEDORA_FLAGS[*]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Minimum platform
if [[ ("$GCC_COMPILER" -ne "0" || "$CLANG_COMPILER" -ne "0" || "$INTEL_COMPILER" -ne "0") ]]; then

	# i686 (lacks MMX, SSE and SSE2)
	if [[ "$IS_X86" -ne "0" ]]; then
		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Debug, i686 minimum arch CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Debug, i686 minimum arch CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$DEBUG_CXXFLAGS -march=i686 $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Release, i686 minimum arch CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Release, i686 minimum arch CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -march=i686 $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi

	# x86_64
	if [[ "$IS_X64" -ne "0" ]]; then
		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Debug, x86_64 minimum arch CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Debug, x86_64 minimum arch CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$DEBUG_CXXFLAGS -march=x86-64 $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Release, x86_64 minimum arch CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Release, x86_64 minimum arch CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -march=x86-64 $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Mismatched arch capabilities
if [[ ( ("$IS_X86" -ne "0" || "$IS_X32" -ne "0" || "$IS_X64" -ne "0") && "$HAVE_NATIVE_ARCH" -ne "0") ]]; then

	# i686 (lacks MMX, SSE and SSE2)
	if [[ "$IS_X86" -ne "0" ]]; then
		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Debug, mismatched arch capabilities" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Debug, mismatched arch capabilities")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$DEBUG_CXXFLAGS -march=i686 $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static 2>&1 | tee -a "$TEST_RESULTS"

		# The makefile may add -DCRYPTOPP_DISABLE_XXX, so we can't add -march=native
		CXXFLAGS="$DEBUG_CXXFLAGS $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Release, mismatched arch capabilities" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Release, mismatched arch capabilities")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -march=i686 $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static 2>&1 | tee -a "$TEST_RESULTS"

		# The makefile may add -DCRYPTOPP_DISABLE_XXX, so we can't add -march=native
		CXXFLAGS="$RELEASE_CXXFLAGS $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi

	# x86-64
	if [[ "$IS_X64" -ne "0" ]]; then
		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Debug, mismatched arch capabilities" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Debug, mismatched arch capabilities")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$DEBUG_CXXFLAGS -march=x86-64 $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static 2>&1 | tee -a "$TEST_RESULTS"

		# The makefile may add -DCRYPTOPP_DISABLE_XXX, so we can't add -march=native
		CXXFLAGS="$DEBUG_CXXFLAGS $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Release, mismatched arch capabilities" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Release, mismatched arch capabilities")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -march=x86-64 $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static 2>&1 | tee -a "$TEST_RESULTS"

		# The makefile may add -DCRYPTOPP_DISABLE_XXX, so we can't add -march=native
		CXXFLAGS="$RELEASE_CXXFLAGS $OPT_PIC"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Debug build, DISABLE_ASM
if true; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, DISABLE_ASM" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, DISABLE_ASM")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_DISABLE_ASM"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, DISABLE_ASM" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, DISABLE_ASM")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_DISABLE_ASM"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Debug build, NO_CPU_FEATURE_PROBES
if true; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, NO_CPU_FEATURE_PROBES" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, NO_CPU_FEATURE_PROBES")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_NO_CPU_FEATURE_PROBES=1"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, NO_CPU_FEATURE_PROBES" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, NO_CPU_FEATURE_PROBES")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_NO_CPU_FEATURE_PROBES=1"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Debug build, CRYPTOPP_NO_CXX11
if [[ "$HAVE_CXX11" -ne "0" ]] || [[ "$HAVE_GNU11" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, CRYPTOPP_NO_CXX11" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, CRYPTOPP_NO_CXX11")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_CRYPTOPP_NO_CXX11=1"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, CRYPTOPP_NO_CXX11" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, CRYPTOPP_NO_CXX11")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_CRYPTOPP_NO_CXX11=1"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++03 debug and release build
if [[ "$HAVE_CXX03" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++03" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++03")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++03" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++03")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# gnu++03 debug and release build
if [[ "$HAVE_GNU03" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, gnu++03" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, gnu++03")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, gnu++03" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, gnu++03")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++11 debug and release build
if [[ "$HAVE_CXX11" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++11" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++11")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++11" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++11")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# gnu++11 debug and release build
if [[ "$HAVE_GNU11" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, gnu++11" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, gnu++11")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, gnu++11" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, gnu++11")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++14 debug and release build
if [[ "$HAVE_CXX14" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++14" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++14")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++14" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++14")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# gnu++14 debug and release build
if [[ "$HAVE_GNU14" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, gnu++14" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, gnu++14")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++14 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, gnu++14" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, gnu++14")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++14 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++17 debug and release build
if [[ "$HAVE_CXX17" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++17" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++17")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++17" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++17")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# gnu++17 debug and release build
if [[ "$HAVE_GNU17" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, gnu++17" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, gnu++17")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++17 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, gnu++17" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, gnu++17")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++17 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++20 debug and release build
if [[ "$HAVE_CXX20" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++20" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++20")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++20" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++20")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# gnu++20 debug and release build
if [[ "$HAVE_GNU20" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, gnu++20" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, gnu++20")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++20 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, gnu++20" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, gnu++20")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++20 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# X32 debug and release build
if [[ "$HAVE_X32" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, X32" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, X32")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -mx32 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, X32" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, X32")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -mx32 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# init_priority
if true; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, INIT_PRIORITY (0)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, INIT_PRIORITY (0)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_INIT_PRIORITY=0 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, INIT_PRIORITY (0)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, INIT_PRIORITY (0)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_INIT_PRIORITY=0 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# OS Independence
if true; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, NO_OS_DEPENDENCE" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, NO_OS_DEPENDENCE")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -DNO_OS_DEPENDENCE $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, NO_OS_DEPENDENCE" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, NO_OS_DEPENDENCE")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DNO_OS_DEPENDENCE $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Build with LD-Gold
if [[ "$HAVE_LDGOLD" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, ld-gold linker" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, ld-gold linker")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" LD="ld.gold" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, ld-gold linker" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, ld-gold linker")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" LD="ld.gold" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Build at -O2
if [[ "$HAVE_O2" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, -O2 optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, -O2 optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_O2 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, -O2 optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, -O2 optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_O2 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Build at -O3
if [[ "$HAVE_O3" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, -O3 optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, -O3 optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_O3 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, -O3 optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, -O3 optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_O3 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Build at -O5
if [[ "$HAVE_O5" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, -O5 optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, -O5 optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_O5 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, -O5 optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, -O5 optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_O5 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Build at -Os
if [[ "$HAVE_OS" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, -Os optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, -Os optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_OS $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, -Os optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, -Os optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_OS $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Build at -Ofast
if [[ "$HAVE_OFAST" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, -Ofast optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, -Ofast optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_OFAST $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, -Ofast optimizations" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, -Ofast optimizations")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_OFAST $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Dead code stripping
if [[ ("$GNU_LINKER" -eq "1") ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, dead code strip" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, dead code strip")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" lean 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, dead code strip" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, dead code strip")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" lean 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# OpenMP
if [[ ("$HAVE_OMP" -ne "0") ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, OpenMP" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, OpenMP")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG ${OMP_FLAGS[*]} $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, OpenMP" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, OpenMP")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG ${OMP_FLAGS[*]} $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# UBSan, c++03
if [[ ("$HAVE_CXX03" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then

	############################################
	# Debug build, UBSan, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++03, UBsan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++03, UBsan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build, UBSan, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++03, UBsan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++03, UBsan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Asan, c++03
if [[ ("$HAVE_CXX03" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then

	############################################
	# Debug build, Asan, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++03, Asan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++03, Asan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

	fi

	############################################
	# Release build, Asan, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++03, Asan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++03, Asan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Bounds Sanitizer, c++03
if [[ ("$HAVE_CXX03" -ne "0" && "$HAVE_BSAN" -ne "0") ]]; then

	############################################
	# Debug build, Bounds Sanitizer, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++03, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++03, Bounds Sanitizer")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 -fsanitize=bounds-strict $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

	fi

	############################################
	# Release build, Bounds Sanitizer, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++03, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++03, Bounds Sanitizer")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -fsanitize=bounds-strict $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Control-flow Enforcement Technology (CET), c++03
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_CET" -ne "0") ]]; then

	############################################
	# Debug build, CET, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++03, CET" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++03, CET")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 -fcf-protection=full -mcet $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build, CET, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++03, CET" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++03, CET")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -fcf-protection=full -mcet $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Specter, c++03
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_REPTOLINE" -ne "0") ]]; then

	############################################
	# Debug build, Specter, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++03, Specter" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++03, Specter")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build, Specter, c++03
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++03, Specter" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++03, Specter")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# UBSan, c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then

	############################################
	# Debug build, UBSan, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++11, UBsan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++11, UBsan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build, UBSan, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++11, UBsan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++11, UBsan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Asan, c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then

	############################################
	# Debug build, Asan, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++11, Asan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++11, Asan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

	fi

	############################################
	# Release build, Asan, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++11, Asan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++11, Asan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Bounds Sanitizer, c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_BSAN" -ne "0") ]]; then

	############################################
	# Debug build, Bounds Sanitizer, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++11, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++11, Bounds Sanitizer")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 -fsanitize=bounds-strict $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

	fi

	############################################
	# Release build, Bounds Sanitizer, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++11, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++11, Bounds Sanitizer")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -fsanitize=bounds-strict $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Control-flow Enforcement Technology (CET), c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_CET" -ne "0") ]]; then

	############################################
	# Debug build, CET, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++11, CET" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++11, CET")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 -fcf-protection=full -mcet $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build, CET, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++11, CET" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++11, CET")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -fcf-protection=full -mcet $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Specter, c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_REPTOLINE" -ne "0") ]]; then

	############################################
	# Debug build, Specter, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Debug, c++11, Specter" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Debug, c++11, Specter")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Release build, Specter, c++11
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++11, Specter" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++11, Specter")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, UBSan, c++14
if [[ ("$HAVE_CXX14" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++14, UBsan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++14, UBsan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Asan, c++14
if [[ ("$HAVE_CXX14" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++14, Asan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++14, Asan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Release build, Bounds Sanitizer, c++14
if [[ ("$HAVE_CXX14" -ne "0" && "$HAVE_BSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++14, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++14, Bounds Sanitizer")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -fsanitize=bounds-strict $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Control-flow Enforcement Technology (CET), c++14
if [[ ("$HAVE_CXX14" -ne "0" && "$HAVE_CET" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++14, CET" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++14, CET")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -fcf-protection=full -mcet $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Specter, c++14
if [[ ("$HAVE_CXX14" -ne "0" && "$HAVE_REPTOLINE" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++14, Specter" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++14, Specter")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, UBSan, c++17
if [[ ("$HAVE_CXX17" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++17, UBsan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++17, UBsan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Asan, c++17
if [[ ("$HAVE_CXX17" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++17, Asan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++17, Asan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Release build, Bounds Sanitizer, c++17
if [[ ("$HAVE_CXX17" -ne "0" && "$HAVE_BSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++17, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++17, Bounds Sanitizer")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -fsanitize=bounds-strict $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Control-flow Enforcement Technology (CET), c++17
if [[ ("$HAVE_CXX17" -ne "0" && "$HAVE_CET" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++17, CET" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++17, CET")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -fcf-protection=full -mcet $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Specter, c++17
if [[ ("$HAVE_CXX17" -ne "0" && "$HAVE_REPTOLINE" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++17, Specter" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++17, Specter")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, UBSan, c++20
if [[ ("$HAVE_CXX20" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++20, UBsan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++20, UBsan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Asan, c++20
if [[ ("$HAVE_CXX20" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++20, Asan" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++20, Asan")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		if [[ ("$HAVE_SYMBOLIZE" -ne "0") ]]; then
			./cryptest.exe v 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Release build, Bounds Sanitizer, c++20
if [[ ("$HAVE_CXX20" -ne "0" && "$HAVE_BSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++20, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++20, Bounds Sanitizer")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 -fsanitize=bounds-strict $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Control-flow Enforcement Technology (CET), c++20
if [[ ("$HAVE_CXX20" -ne "0" && "$HAVE_CET" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++20, CET" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++20, CET")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 -fcf-protection=full -mcet $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Specter, c++20
if [[ ("$HAVE_CXX20" -ne "0" && "$HAVE_REPTOLINE" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Release, c++20, Specter" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Release, c++20, Specter")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# For Solaris, test under Sun Studio 12.2 - 12.5
if [[ "$IS_SOLARIS" -ne "0" ]]; then

	############################################
	# Sun Studio 12.2/SunCC 5.11
	if [[ (-e "/opt/solstudio12.2/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.2, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.2, debug, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g -xO0"
		CXX="/opt/solstudio12.2/bin/CC" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.2, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Testing: Sun Studio 12.2, release, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g -xO2"
		CXX="/opt/solstudio12.2/bin/CC" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi

	############################################
	# Sun Studio 12.3/SunCC 5.12
	if [[ (-e "/opt/solarisstudio12.3/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.3, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.3, debug, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g3 -xO0"
		CXX=/opt/solarisstudio12.3/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.3, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.3, release, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g3 -xO2"
		CXX=/opt/solarisstudio12.3/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi

	############################################
	# Sun Studio 12.4/SunCC 5.13
	if [[ (-e "/opt/solarisstudio12.4/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.4, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.4, debug, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g3 -xO0"
		CXX=/opt/solarisstudio12.4/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.4, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.4, release, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -xO2"
		CXX=/opt/solarisstudio12.4/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi

	############################################
	# Sun Studio 12.5/SunCC 5.14
	if [[ (-e "/opt/developerstudio12.5/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.5, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.5, debug, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g3 -xO1"
		CXX=/opt/developerstudio12.5/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.5, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.5, release, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -xO2"
		CXX=/opt/developerstudio12.5/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi

	############################################
	# Sun Studio 12.6/SunCC 5.15
	if [[ (-e "/opt/developerstudio12.6/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.6, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.6, debug, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g3 -xO1"
		CXX=/opt/developerstudio12.6/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.6, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Sun Studio 12.6, release, platform CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -xO2"
		CXX=/opt/developerstudio12.6/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi

	############################################
	# GCC on Solaris
	if [[ (-e "/bin/g++") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Solaris GCC, debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Solaris GCC, debug, default CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g3 -O0"
		CXX="/bin/g++" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi

		############################################
		# Release build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Soalris GCC, release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Soalris GCC, release, default CXXFLAGS")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -O3"
		CXX="/bin/g++" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

# For Darwin, we need to test both -stdlib=libstdc++ (GNU) and
#  -stdlib=libc++ (LLVM) crossed with -std=c++03, -std=c++11, and -std=c++17

############################################
# Darwin, c++03, libc++
if [[ ("$IS_DARWIN" -ne "0") && ("$HAVE_CXX03" -ne "0" && "$CLANG_COMPILER" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++03, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++03, libc++ (LLVM)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -stdlib=libc++ $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++03, libstdc++
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX03" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++03, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++03, libstdc++ (GNU)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -stdlib=libstdc++ $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++11, libc++
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX11" -ne "0" && "$CLANG_COMPILER" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++11, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++11, libc++ (LLVM)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -stdlib=libc++ $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++11, libstdc++
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX11" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++11, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++11, libstdc++ (GNU)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -stdlib=libstdc++ $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++14, libc++
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX14" -ne "0" && "$CLANG_COMPILER" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++14, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++14, libc++ (LLVM)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -stdlib=libc++ $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++14, libstdc++
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX14" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++14, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++14, libstdc++ (GNU)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -stdlib=libstdc++ $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++17, libc++
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX17" -ne "0" && "$CLANG_COMPILER" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++17, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++17, libc++ (LLVM)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -stdlib=libc++ $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++17, libstdc++
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX17" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++17, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++17, libstdc++ (GNU)")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -stdlib=libstdc++ $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, Intel multiarch, c++03
if [[ "$IS_DARWIN" -ne "0" && "$HAVE_INTEL_MULTIARCH" -ne "0" && "$HAVE_CXX03" -ne "0" ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, Intel multiarch, c++03" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, Intel multiarch, c++03")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++03 -DCRYPTOPP_DISABLE_ASM $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "Running i386 version..."
		arch -i386 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
		fi
		arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
		fi

		echo "Running x86_64 version..."
		arch -x86_64 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
		fi
		arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, Intel multiarch, c++11
if [[ "$IS_DARWIN" -ne "0" && "$HAVE_INTEL_MULTIARCH" -ne "0" && "$HAVE_CXX11" -ne "0" ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, Intel multiarch, c++11" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, Intel multiarch, c++11")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++11 -DCRYPTOPP_DISABLE_ASM $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "Running i386 version..."
		arch -i386 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
		fi
		arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
		fi

		echo "Running x86_64 version..."
		arch -x86_64 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
		fi
		arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, Intel multiarch, c++14
if [[ "$IS_DARWIN" -ne "0" && "$HAVE_INTEL_MULTIARCH" -ne "0" && "$HAVE_CXX14" -ne "0" ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, Intel multiarch, c++14" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, Intel multiarch, c++14")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++14 -DCRYPTOPP_DISABLE_ASM $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "Running i386 version..."
		arch -i386 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
		fi
		arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
		fi

		echo "Running x86_64 version..."
		arch -x86_64 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
		fi
		arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, Intel multiarch, c++17
if [[ "$IS_DARWIN" -ne "0" && "$HAVE_INTEL_MULTIARCH" -ne "0" && "$HAVE_CXX17" -ne "0" ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, Intel multiarch, c++17" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, Intel multiarch, c++17")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++17 -DCRYPTOPP_DISABLE_ASM $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "Running i386 version..."
		arch -i386 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
		fi
		arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
		fi

		echo "Running x86_64 version..."
		arch -x86_64 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
		fi
		arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, PowerPC multiarch
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_PPC_MULTIARCH" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, PowerPC multiarch" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, PowerPC multiarch")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch ppc -arch ppc64 -DCRYPTOPP_DISABLE_ASM $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "Running PPC version..."
		arch -ppc ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (PPC)" | tee -a "$TEST_RESULTS"
		fi
		arch -ppc ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (PPC)" | tee -a "$TEST_RESULTS"
		fi

		echo "Running PPC64 version..."
		arch -ppc64 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite (PPC64)" | tee -a "$TEST_RESULTS"
		fi
		arch -ppc64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors (PPC64)" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++03, Malloc Guards
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX03" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++03, Malloc Guards" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++03, Malloc Guards")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		export MallocScribble=1
		export MallocPreScribble=1
		export MallocGuardEdges=1

		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi

		unset MallocScribble MallocPreScribble MallocGuardEdges
	fi
fi

############################################
# Darwin, c++11, Malloc Guards
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX11" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++11, Malloc Guards" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++11, Malloc Guards")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		export MallocScribble=1
		export MallocPreScribble=1
		export MallocGuardEdges=1

		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi

		unset MallocScribble MallocPreScribble MallocGuardEdges
	fi
fi

############################################
# Darwin, c++14, Malloc Guards
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX14" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++14, Malloc Guards" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++14, Malloc Guards")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		export MallocScribble=1
		export MallocPreScribble=1
		export MallocGuardEdges=1

		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi

		unset MallocScribble MallocPreScribble MallocGuardEdges
	fi
fi

############################################
# Darwin, c++17, Malloc Guards
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX17" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++17, Malloc Guards" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Darwin, c++17, Malloc Guards")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		export MallocScribble=1
		export MallocPreScribble=1
		export MallocGuardEdges=1

		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi

		unset MallocScribble MallocPreScribble MallocGuardEdges
	fi
fi

############################################
# Benchmarks
if [[ "$WANT_BENCHMARKS" -ne "0" ]]; then

	############################################
	# Benchmarks, c++03
	if [[ "$HAVE_CXX03" -ne "0" ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Benchmarks, c++03" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Testing: Benchmarks, c++03")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			echo "**************************************" >> "$BENCHMARK_RESULTS"
			./cryptest.exe b 3 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute benchmarks" | tee -a "$BENCHMARK_RESULTS"
			fi
		fi
	fi

	############################################
	# Benchmarks, c++11
	if [[ "$HAVE_CXX11" -ne "0" ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Benchmarks, c++11" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Testing: Benchmarks, c++11")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			echo "**************************************" >> "$BENCHMARK_RESULTS"
			./cryptest.exe b 3 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute benchmarks" | tee -a "$BENCHMARK_RESULTS"
			fi
		fi
	fi

	############################################
	# Benchmarks, c++14
	if [[ "$HAVE_CXX14" -ne "0" ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Benchmarks, c++14" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Benchmarks, c++14")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
		CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			echo "**************************************" >> "$BENCHMARK_RESULTS"
			./cryptest.exe b 3 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute benchmarks" | tee -a "$BENCHMARK_RESULTS"
			fi
		fi
	fi
fi

# For Cygwin, we need to test both PREFER_BERKELEY_STYLE_SOCKETS
#   and PREFER_WINDOWS_STYLE_SOCKETS

############################################
# MinGW and PREFER_BERKELEY_STYLE_SOCKETS
if [[ "$IS_MINGW" -ne "0" ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: MinGW, PREFER_BERKELEY_STYLE_SOCKETS" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("MinGW, PREFER_BERKELEY_STYLE_SOCKETS")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DPREFER_BERKELEY_STYLE_SOCKETS -DNO_WINDOWS_STYLE_SOCKETS $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# MinGW and PREFER_WINDOWS_STYLE_SOCKETS
if [[ "$IS_MINGW" -ne "0" ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: MinGW, PREFER_WINDOWS_STYLE_SOCKETS" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("MinGW, PREFER_WINDOWS_STYLE_SOCKETS")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DPREFER_WINDOWS_STYLE_SOCKETS -DNO_BERKELEY_STYLE_SOCKETS $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Valgrind, c++03. Requires -O1 for accurate results
if [[ "$HAVE_CXX03" -ne "0" && "$HAVE_VALGRIND" -ne "0" ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++03" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Valgrind, c++03")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Valgrind, c++11. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne "0" && "$HAVE_CXX11" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++11" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Valgrind, c++11")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Valgrind, c++14. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne "0" && "$HAVE_CXX14" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++14" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Valgrind, c++14")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Valgrind, c++17. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne "0" && "$HAVE_CXX17" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++17" | tee -a "$TEST_RESULTS"
	echo

	TEST_LIST+=("Valgrind, c++17")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# C++03 with elevated warnings
if [[ ("$HAVE_CXX03" -ne "0" && ("$GCC_COMPILER" -ne "0" || "$CLANG_COMPILER" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Debug, c++03, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Debug, c++03, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Release, c++03, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Release, c++03, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# C++11 with elevated warnings
if [[ ("$HAVE_CXX11" -ne "0" && ("$GCC_COMPILER" -ne "0" || "$CLANG_COMPILER" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Debug, c++11, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Debug, c++11, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Release, c++11, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Release, c++11, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# C++14 with elevated warnings
if [[ ("$HAVE_CXX14" -ne "0" && ("$GCC_COMPILER" -ne "0" || "$CLANG_COMPILER" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Debug, c++14, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Debug, c++14, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++14 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Release, c++14, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Release, c++14, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# C++17 with elevated warnings
if [[ ("$HAVE_CXX17" -ne "0" && ("$GCC_COMPILER" -ne "0" || "$CLANG_COMPILER" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Debug, c++17, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Debug, c++17, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++17 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Release, c++17, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Release, c++17, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# C++20 with elevated warnings
if [[ ("$HAVE_CXX20" -ne "0" && ("$GCC_COMPILER" -ne "0" || "$CLANG_COMPILER" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Debug, c++20, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Debug, c++20, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++20 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: Release, c++20, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	TEST_LIST+=("Release, c++20, elevated warnings")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 ${WARNING_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# Perform a quick check with Clang, if available.
#   This check was added after testing on Ubuntu 14.04 with Clang 3.4.
if [[ ("$CLANG_COMPILER" -eq "0") ]]; then

	CLANG_CXX=$(command -v clang++ 2>/dev/null)
	"$CLANG_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then

		############################################
		# Clang build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Clang compiler" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Clang compiler")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -O3"
		CXX="$CLANG_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Perform a quick check with GCC, if available.
if [[ ("$GCC_COMPILER" -eq "0") ]]; then

	GCC_CXX=$(command -v g++ 2>/dev/null)
	"$GCC_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then

		############################################
		# GCC build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: GCC compiler" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("GCC compiler")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -O3"
		CXX="$GCC_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Perform a quick check with Intel ICPC, if available.
if [[ ("$INTEL_COMPILER" -eq "0") ]]; then

	INTEL_CXX=$(command -v icpc 2>/dev/null)
	if [[ (-z "$INTEL_CXX") ]]; then
		INTEL_CXX=$(find /opt/intel -name icpc 2>/dev/null | "$GREP" -iv composer | head -1)
	fi
	"$INTEL_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then

		############################################
		# Intel build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Intel compiler" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Intel compiler")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -O3"
		CXX="$INTEL_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Perform a quick check with MacPorts compilers, if available.
if [[ ("$IS_DARWIN" -ne "0" && "$MACPORTS_COMPILER" -eq "0") ]]; then

	MACPORTS_CXX=$(find /opt/local/bin -name 'g++-mp-4*' 2>/dev/null | head -1)
	if [[ (! -z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts GCC 4.x build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts 4.x GCC compiler" | tee -a "$TEST_RESULTS"
			echo

			TEST_LIST+=("MacPorts 4.x GCC compiler")

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			# We want to use -stdlib=libstdc++ below, but it causes a compile error. Maybe MacPorts hardwired libc++.
			CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"
			CXX="$MACPORTS_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
			else
				./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
				fi
				./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
				fi
			fi
		fi
	fi

	MACPORTS_CXX=$(find /opt/local/bin -name 'g++-mp-5*' 2>/dev/null | head -1)
	if [[ (! -z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts GCC 5.x build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts 5.x GCC compiler" | tee -a "$TEST_RESULTS"
			echo

			TEST_LIST+=("MacPorts 5.x GCC compiler")

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			# We want to use -stdlib=libstdc++ below, but it causes a compile error. Maybe MacPorts hardwired libc++.
			CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"
			CXX="$MACPORTS_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
			else
				./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
				fi
				./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
				fi
			fi
		fi
	fi

	MACPORTS_CXX=$(find /opt/local/bin -name 'g++-mp-6*' 2>/dev/null | head -1)
	if [[ (! -z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts GCC 6.x build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts 6.x GCC compiler" | tee -a "$TEST_RESULTS"
			echo

			TEST_LIST+=("MacPorts 6.x GCC compiler")

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			# We want to use -stdlib=libstdc++ below, but it causes a compile error. Maybe MacPorts hardwired libc++.
			CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"
			CXX="$MACPORTS_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
			else
				./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
				fi
				./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
				fi
			fi
		fi
	fi

	MACPORTS_CXX=$(find /opt/local/bin -name 'g++-mp-7*' 2>/dev/null | head -1)
	if [[ (! -z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts GCC 7.x build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts 7.x GCC compiler" | tee -a "$TEST_RESULTS"
			echo

			TEST_LIST+=("MacPorts 7.x GCC compiler")

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			# We want to use -stdlib=libstdc++ below, but it causes a compile error. Maybe MacPorts hardwired libc++.
			CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"
			CXX="$MACPORTS_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
			else
				./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
				fi
				./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
				fi
			fi
		fi
	fi

	MACPORTS_CXX=$(find /opt/local/bin -name 'clang++-mp-3.7*' 2>/dev/null | head -1)
	if [[ (! -z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts 3.7 Clang build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts 3.7 Clang compiler" | tee -a "$TEST_RESULTS"
			echo

			TEST_LIST+=("MacPorts 3.7 Clang compiler")

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11 -stdlib=libc++"
			CXX="$MACPORTS_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
			else
				./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
				fi
				./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
				fi
			fi
		fi
	fi

	MACPORTS_CXX=$(find /opt/local/bin -name 'clang++-mp-3.8*' 2>/dev/null | head -1)
	if [[ (! -z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts 3.8 Clang build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts 3.8 Clang compiler" | tee -a "$TEST_RESULTS"
			echo

			TEST_LIST+=("MacPorts 3.8 Clang compiler")

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11 -stdlib=libc++"
			CXX="$MACPORTS_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
			else
				./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
				fi
				./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
				fi
			fi
		fi
	fi

	MACPORTS_CXX=$(find /opt/local/bin -name 'clang++-mp-3.9*' 2>/dev/null | head -1)
	if [[ (! -z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts 3.9 Clang build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts 3.9 Clang compiler" | tee -a "$TEST_RESULTS"
			echo

			TEST_LIST+=("MacPorts 3.9 Clang compiler")

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11 -stdlib=libc++"
			CXX="$MACPORTS_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
			else
				./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
				fi
				./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
				fi
			fi
		fi
	fi

	MACPORTS_CXX=$(find /opt/local/bin -name 'clang++-mp-4*' 2>/dev/null | head -1)
	if [[ (! -z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMPDIR/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts 4.x Clang build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts 4.x Clang compiler" | tee -a "$TEST_RESULTS"
			echo

			TEST_LIST+=("MacPorts 4.x Clang compiler")

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11 -stdlib=libc++"
			CXX="$MACPORTS_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
			else
				./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
				fi
				./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
				if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
					echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
				fi
			fi
		fi
	fi
fi

############################################
# Perform a quick check with Xcode compiler, if available.
if [[ "$IS_DARWIN" -ne "0" ]]; then
	XCODE_CXX=$(find /Applications/Xcode*.app/Contents/Developer -name clang++ 2>/dev/null | head -1)
	if [[ (-z "$XCODE_CXX") ]]; then
		XCODE_CXX=$(find /Developer/Applications/Xcode.app -name clang++ 2>/dev/null | head -1)
	fi

	if [[ ! (-z "$XCODE_CXX") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Xcode Clang compiler" | tee -a "$TEST_RESULTS"
		echo

		TEST_LIST+=("Xcode Clang compiler")

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -O3"
		CXX="$XCODE_CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Test an install with CRYPTOPP_DATA_DIR
if [[ ("$IS_CYGWIN" -eq "0") && ("$IS_MINGW" -eq "0") ]]; then

	echo
	echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
	echo "Testing: Install with data directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
	echo

	TEST_LIST+=("Install with data directory")

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	INSTALL_DIR="$TMPDIR/cryptopp_test"
	rm -rf "$INSTALL_DIR" > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_DATA_DIR='\"$INSTALL_DIR/share/cryptopp/\"' $USER_CXXFLAGS"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
	else
		OLD_DIR=$(pwd)
		"$MAKE" "${MAKEARGS[@]}" install PREFIX="$INSTALL_DIR" 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		cd "$INSTALL_DIR/bin"

		echo
		echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		echo "Testing: Install (validation suite)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		echo
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi

		echo
		echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		echo "Testing: Install (test vectors)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		echo
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi

		if [[ "$WANT_BENCHMARKS" -ne "0" ]]; then
			echo
			echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
			echo "Testing: Install (benchmarks)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
			echo
			./cryptest.exe b 1 "$CPU_FREQ" 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute benchmarks" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
			fi
		fi

		echo
		echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		echo "Testing: Install (help file)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		echo
		./cryptest.exe h 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "1") ]]; then
			echo "ERROR: failed to provide help" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi

		# Restore original PWD
		cd "$OLD_DIR"
	fi
fi

############################################
# Test a remove with CRYPTOPP_DATA_DIR
if [[ ("$IS_CYGWIN" -eq "0" && "$IS_MINGW" -eq "0") ]]; then

	echo
	echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
	echo "Testing: Remove with data directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
	echo

	TEST_LIST+=("Remove with data directory")

	"$MAKE" "${MAKEARGS[@]}" remove PREFIX="$INSTALL_DIR" 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make remove" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
	else
		# Test for complete removal
		if [[ (-d "$INSTALL_DIR/include/cryptopp") ]]; then
			echo "ERROR: failed to remove cryptopp include directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi
		if [[ (-d "$INSTALL_DIR/share/cryptopp") ]]; then
			echo "ERROR: failed to remove cryptopp share directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi
		if [[ (-d "$INSTALL_DIR/share/cryptopp/TestData") ]]; then
			echo "ERROR: failed to remove cryptopp test data directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi
		if [[ (-d "$INSTALL_DIR/share/cryptopp/TestVector") ]]; then
			echo "ERROR: failed to remove cryptopp test vector directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi
		if [[ (-e "$INSTALL_DIR/bin/cryptest.exe") ]]; then
			echo "ERROR: failed to remove cryptest.exe program" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi
		if [[ (-e "$INSTALL_DIR/lib/libcryptopp.a") ]]; then
			echo "ERROR: failed to remove libcryptopp.a static library" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi
		if [[ "$IS_DARWIN" -ne "0" && (-e "$INSTALL_DIR/lib/libcryptopp.dylib") ]]; then
			echo "ERROR: failed to remove libcryptopp.dylib dynamic library" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		elif [[ (-e "$INSTALL_DIR/lib/libcryptopp.so") ]]; then
			echo "ERROR: failed to remove libcryptopp.so dynamic library" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
		fi
	fi
fi

#############################################
#############################################
################ END TESTING ################
#############################################
#############################################

TEST_END=$(date)

############################################
# Cleanup, but leave output files
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

############################################
# Report tests performed

echo
echo "************************************************" | tee -a "$TEST_RESULTS"
echo "************************************************" | tee -a "$TEST_RESULTS"
echo | tee -a "$TEST_RESULTS"

COUNT="${#TEST_LIST[@]}"
if (( "$COUNT" == "0" )); then
	echo "No configurations tested" | tee -a "$TEST_RESULTS"
else
	echo "$COUNT configurations tested" | tee -a "$TEST_RESULTS"
	for TEST in "${TEST_LIST[@]}"
	do
	  echo "  - $TEST" | tee -a "$TEST_RESULTS"
	done
fi
echo | tee -a "$TEST_RESULTS"

############################################
# Report errors

echo
echo "************************************************" | tee -a "$TEST_RESULTS"
echo | tee -a "$TEST_RESULTS"

# "FAILED" and "Exception" are from Crypto++
# "ERROR" is from this script
# "Error" is from the GNU assembler
# "error" is from the sanitizers
# "Illegal", "Conditional", "0 errors" and "suppressed errors" are from Valgrind.
ECOUNT=$("$GREP" -E '(Error|ERROR|error|FAILED|Illegal|Conditional|CryptoPP::Exception)' $TEST_RESULTS | "$GREP" -v -E '( 0 errors|suppressed errors|error detector|format-security)' | wc -l | "$AWK" '{print $1}')
if (( "$ECOUNT" == "0" )); then
	echo "No failures detected" | tee -a "$TEST_RESULTS"
else
	echo "$ECOUNT errors detected. See $TEST_RESULTS for details" | tee -a "$TEST_RESULTS"
	if (( "$ECOUNT" < 16 )); then
		"$GREP" -n -E '(Error|ERROR|error|FAILED|Illegal|Conditional|CryptoPP::Exception)' "$TEST_RESULTS" | "$GREP" -v -E '( 0 errors|suppressed errors|error detector|Assertion|format-security)'
	fi
fi

############################################
# Report warnings

echo
echo "************************************************" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo | tee -a "$TEST_RESULTS" "$WARN_RESULTS"

WCOUNT=$("$GREP" -E '(warning:)' $WARN_RESULTS | wc -l | "$AWK" '{print $1}')
if (( "$WCOUNT" == "0" )); then
	echo "No warnings detected" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
else
	echo "$WCOUNT warnings detected. See $WARN_RESULTS for details" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
	# "$GREP" -n -E '(warning:)' $WARN_RESULTS | "$GREP" -v 'deprecated-declarations'
fi

############################################
# Report execution time

echo
echo "************************************************" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo | tee -a "$TEST_RESULTS" "$WARN_RESULTS"

echo "Testing started: $TEST_BEGIN" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo "Testing finished: $TEST_END" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo

############################################
# http://tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
if (( "$ECOUNT" == "0" )); then
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0
else
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi
