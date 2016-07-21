#!/usr/bin/env bash

# cryptest.sh - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
#               Copyright assigned to Crypto++ project.

# This is a test script that can be used on some Linux/Unix/Apple machines to automate building the
# library and running the self test with various combinations of flags, options, and conditions.
# For more details, see http://cryptopp.com/wiki/cryptest.sh.

# To run the script, simply perform the following:
#     ./cryptest.sh

# If you want to test a particular compiler, like clang++ or icpc, issue:
#     CXX=clang++ ./cryptest.sh
#     CXX=/opt/intel/bin/icpc ./cryptest.sh

# You can also provide some default CXXFLAGS. User supplied flags which are tested in this script
# are removed during testing. For a list of all filtered flags, see FILTERED_CXXFLAGS below.
# For example, -Wall will be removed from all builds and tested by the script when appropriate:
#     CXXFLAGS=-Wall ./cryptest.sh
#     CXXFLAGS="-Wall -Wextra" ./cryptest.sh

# The fastest results (in running time) will most likely use:
#     HAVE_VALGRIND=0 WANT_BENCHMARKS=0 ./cryptest.sh
# Using 'fast' is shorthand for it:
#     ./cryptest.sh fast

# You can also reduce CPU load with the folowing. It will use half the number of CPU cores
# rather than all of them. Its usefu for the GCC Compile Farm, where its policy.
#     ./cryptest.sh nice

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

############################################
# Setup tools and platforms

GREP=grep
EGREP=egrep
SED=sed
AWK=awk

THIS_SYSTEM=$(uname -s 2>&1)
IS_DARWIN=$(echo "$THIS_SYSTEM" | "$GREP" -i -c darwin)
IS_LINUX=$(echo "$THIS_SYSTEM" | "$GREP" -i -c linux)
IS_CYGWIN=$(echo "$THIS_SYSTEM" | "$GREP" -i -c cygwin)
IS_MINGW=$(echo "$THIS_SYSTEM" | "$GREP" -i -c mingw)
IS_OPENBSD=$(echo "$THIS_SYSTEM" | "$GREP" -i -c openbsd)
IS_NETBSD=$(echo "$THIS_SYSTEM" | "$GREP" -i -c netbsd)
IS_SOLARIS=$(echo "$THIS_SYSTEM" | "$GREP" -i -c sunos)

THIS_MACHINE=$(uname -m 2>&1)
IS_X86=$(echo "$THIS_MACHINE" | "$EGREP" -i -c "(i386|i586|i686|amd64|x86_64)")
IS_X64=$(echo "$THIS_MACHINE" | "$EGREP" -i -c "(amd64|x86_64)")
IS_PPC=$(echo "$THIS_MACHINE" | "$EGREP" -i -c "(Power|PPC)")
IS_ARM32=$(echo "$THIS_MACHINE" | "$GREP" -v "arm64" | "$EGREP" -i -c "(arm|aarch32)")
IS_ARM64=$(echo "$THIS_MACHINE" | "$EGREP" -i -c "(arm64|aarch64)")
IS_S390=$(echo "$THIS_MACHINE" | "$EGREP" -i -c "s390")
IS_X32=0

# Fixup
if [[ "$IS_SOLARIS" -ne "0" ]]; then
	IS_X64=$(isainfo 2>/dev/null | "$GREP" -i -c "amd64")
	if [[ "$IS_X64" -ne "0" ]]; then
		IS_X86=0
	fi

	# Need something more powerful than the non-Posix versions
	if [[ (-e "/usr/gnu/bin/grep") ]]; then
		GREP=/usr/gnu/bin/grep;
	fi
	if [[ (-e "/usr/gnu/bin/egrep") ]]; then
		EGREP=/usr/gnu/bin/egrep;
	fi
	if [[ (-e "/usr/gnu/bin/sed") ]]; then
		SED=/usr/gnu/bin/sed;
	fi
	if [[ (-e "/usr/gnu/bin/awk") ]]; then
		AWK=/usr/gnu/bin/awk;
	else
		AWK=nawk;
	fi
fi

for ARG in "$@"
do
	# Recognize "fast" and "quick", which does not perform tests that take more time to execute
    if [[ ($("$EGREP" -ix "fast" <<< "$ARG") || $("$EGREP" -ix "quick" <<< "$ARG")) ]]; then
		HAVE_VALGRIND=0
		WANT_BENCHMARKS=0
	# Recognize "farm" and "nice", which uses 1/2 the CPU cores in accordance with GCC Compile Farm policy
	elif [[ ($("$EGREP" -ix "farm" <<< "$ARG") || $("$EGREP" -ix "nice" <<< "$ARG")) ]]; then
		WANT_NICE=1
	fi
done

# We need to use the C++ compiler to determine feature availablility. Otherwise
#   mis-detections occur on a number of platforms.
if [[ ((-z "$CXX") || ("$CXX" == "gcc")) ]]; then
	if [[ "$IS_DARWIN" -ne "0" ]]; then
		CXX=c++
	elif [[ "$IS_SOLARIS" -ne "0" ]]; then
		# SunCC 12.5 is mostly broken
		if [[ (-e "/opt/developerstudio12.5/bin/CC") ]]; then
			CXX=/opt/developerstudio12.5/bin/CC
		elif [[ (-e "/opt/solarisstudio12.4/bin/CC") ]]; then
			CXX=/opt/solarisstudio12.4/bin/CC
		elif [[ (-e "/opt/solarisstudio12.3/bin/CC") ]]; then
			CXX=/opt/solarisstudio12.3/bin/CC
		elif [[ (-e "/opt/solstudio12.2/bin/CC") ]]; then
			CXX=/opt/solstudio12.2/bin/CC
		elif [[ (-e "/opt/solstudio12.1/bin/CC") ]]; then
			CXX=/opt/solstudio12.1/bin/CC
		elif [[ (-e "/opt/solstudio12.0/bin/CC") ]]; then
			CXX=/opt/solstudio12.0/bin/CC
		elif [[ (! -z $(which CC 2>/dev/null | "$GREP" -v "no CC" | head -1)) ]]; then
			CXX=$(which CC | head -1)
		elif [[ (! -z $(which g++ 2>/dev/null | "$GREP" -v "no g++" | head -1)) ]]; then
			CXX=$(which g++ | head -1)
		else
			CXX=CC
		fi
	elif [[ ($(which g++ 2>&1 | "$GREP" -v "no g++" | "$GREP" -i -c g++) -ne "0") ]]; then
		CXX=g++
	else
		CXX=c++
	fi
fi

SUN_COMPILER=$("$CXX" -V 2>&1 | "$EGREP" -i -c "CC: (Sun|Studio)")
GCC_COMPILER=$("$CXX" --version 2>&1 | "$EGREP" -i -c "(gcc|g\+\+)")
INTEL_COMPILER=$("$CXX" --version 2>&1 | "$EGREP" -i -c "\(icc\)")
MACPORTS_COMPILER=$("$CXX" --version 2>&1 | "$EGREP" -i -c "MacPorts")
CLANG_COMPILER=$("$CXX" --version 2>&1 | "$EGREP" -i -c "clang")

if [[ ("$SUN_COMPILER" -eq "0") ]]; then
	AMD64=$("$CXX" -dM -E - </dev/null 2>/dev/null | "$EGREP" -c "(__x64_64__|__amd64__)")
	ILP32=$("$CXX" -dM -E - </dev/null 2>/dev/null | "$EGREP" -c "(__ILP32__|__ILP32)")
	if [[ ("$AMD64" -ne "0") && ("$ILP32" -ne "0") ]]; then
		IS_X32=1
	fi
fi

# Now that the compiler is fixed, determine the compiler version for fixups
GCC_60_OR_ABOVE=$("$CXX" -v 2>&1 | "$EGREP" -i -c 'gcc version (6\.[0-9]|[7-9])')
GCC_51_OR_ABOVE=$("$CXX" -v 2>&1 | "$EGREP" -i -c 'gcc version (5\.[1-9]|[6-9])')
GCC_48_COMPILER=$("$CXX" -v 2>&1 | "$EGREP" -i -c 'gcc version 4\.8')
GCC_49_OR_ABOVE=$("$CXX" -v 2>&1 | "$EGREP" -i -c 'gcc version (4\.9|[5-9]\.[0-9])')
SUNCC_121_OR_ABOVE=$("$CXX" -V 2>&1 | "$EGREP" -c "CC: (Sun|Studio) .* (5\.1[0-9]|5\.[2-9]|[6-9]\.)")

# Fixup
if [[ ("$IS_OPENBSD" -ne "0" || "$IS_NETBSD" -ne "0") ]]; then
	MAKE=gmake
elif [[ ("$IS_SOLARIS" -ne "0") ]]; then
	MAKE=$(which gmake 2>/dev/null | "$GREP" -v "no gmake" | head -1)
	if [[ (-z "$MAKE") && (-e "/usr/sfw/bin/gmake") ]]; then
		MAKE=/usr/sfw/bin/gmake
	fi
else
	MAKE=make
fi

if [[ (-z "$TMP") ]]; then
	if [[ (-d "/tmp") ]]; then
		TMP=/tmp
	elif [[ (-d "/temp") ]]; then
		TMP=/temp
	elif [[ (-d "$HOME/tmp") ]]; then
		TMP="$HOME/tmp"
	else
		echo "Please set TMP to a valid directory"
		[[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
	fi
fi

# Sun Studio does not allow '-x c++'. Copy it here...
rm -f adhoc.cpp > /dev/null 2>&1
cp adhoc.cpp.proto adhoc.cpp

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX17") ]]; then
	HAVE_CXX17=0
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++17 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX17=1
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU17") ]]; then
	HAVE_GNU17=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++17 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU17=1
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX14") ]]; then
	HAVE_CXX14=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++14 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX14=1
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU14") ]]; then
	HAVE_GNU14=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++14 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU14=1
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX11") ]]; then
	HAVE_CXX11=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++11 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX11=1
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU11") ]]; then
	HAVE_GNU11=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++11 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU11=1
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_CXX03") ]]; then
	HAVE_CXX03=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=c++03 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_CXX03=1
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_GNU03") ]]; then
	HAVE_GNU03=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -std=gnu++03 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_GNU03=1
	fi
fi

# Use a fallback strategy so OPT_O0 can be used with DEBUG_CXXFLAGS
OPT_O0=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O0 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	OPT_O0=-O0
else
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO0 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		OPT_O0=-xO0
	fi
fi

# Use a fallback strategy so OPT_O1 can be used with VALGRIND_CXXFLAGS
OPT_O1=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O1 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	OPT_O1=-O1
else
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO1 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		OPT_O1=-xO1
	fi
fi

# Use a fallback strategy so OPT_O2 can be used with RELEASE_CXXFLAGS
OPT_O2=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O2 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	OPT_O2=-O2
else
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO2 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		OPT_O2=-xO2
	fi
fi

HAVE_O3=0
OPT_O3=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O3 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	HAVE_O3=1
	OPT_O3=-O3
else
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO3 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_O3=1
		OPT_O3=-xO3
	fi
fi

# Hit or miss, mostly hit
HAVE_O5=0
OPT_O5=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -O5 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	HAVE_O5=1
	OPT_O5=-O5
else
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO5 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		HAVE_O5=1
		OPT_O5=-xO5
	fi
fi

# Hit or miss, mostly hit
HAVE_OS=0
OPT_OS=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -Os adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	HAVE_OS=1
	OPT_OS=-Os
fi

HAVE_OFAST=0
OPT_OFAST=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -Ofast adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	HAVE_OFAST=1
	OPT_OFAST=-Ofast
fi

# Use a fallback strategy so OPT_G2 can be used with RELEASE_CXXFLAGS
OPT_G2=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -g2 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	OPT_G2=-g2
else
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -g adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		OPT_G2=-g
	fi
fi

# Use a fallback strategy so OPT_G3 can be used with DEBUG_CXXFLAGS
OPT_G3=
rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
"$CXX" -DCRYPTOPP_ADHOC_MAIN -g3 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ ("$?" -eq "0") ]]; then
	OPT_G3=-g3
else
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -g adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ ("$?" -eq "0") ]]; then
		OPT_G3=-g
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_UBSAN") ]]; then
	HAVE_UBSAN=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -fsanitize=undefined adhoc.cpp -o "$TMP/adhoc.exe" &>/dev/null
	if [[ ("$?" -eq "0") ]]; then
		"$TMP/adhoc.exe" &>/dev/null
		if [[ ("$?" -eq "0") ]]; then
			HAVE_UBSAN=1
		fi
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_ASAN") ]]; then
	HAVE_ASAN=0
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -fsanitize=address adhoc.cpp -o "$TMP/adhoc.exe" &>/dev/null
	if [[ ("$?" -eq "0") ]]; then
		"$TMP/adhoc.exe" &>/dev/null
		if [[ ("$?" -eq "0") ]]; then
			HAVE_ASAN=1
		fi
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_INTEL_MULTIARCH") ]]; then
	HAVE_INTEL_MULTIARCH=0
	if [[ ("$IS_DARWIN" -ne "0") && ("$IS_X86" -ne "0" || "$IS_X64" -ne "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -arch i386 -arch x86_64 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_INTEL_MULTIARCH=1
		fi
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_PPC_MULTIARCH") ]]; then
	HAVE_PPC_MULTIARCH=0
	if [[ ("$IS_DARWIN" -ne "0") && ("$IS_PPC" -ne "0") ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -arch ppc -arch ppc64 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_PPC_MULTIARCH=1
		fi
	fi
fi

rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ (-z "$HAVE_X32") ]]; then
	HAVE_X32=0
	if [[ "$IS_X32" -ne "0" ]]; then
		"$CXX" -DCRYPTOPP_ADHOC_MAIN -mx32 adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_X32=1
		fi
	fi
fi

# "Modern compiler, old hardware" combinations
HAVE_X86_AES=0
HAVE_X86_RDRAND=0
HAVE_X86_RDSEED=0
HAVE_X86_PCLMUL=0
if [[ (("$IS_X86" -ne "0") || ("$IS_X64" -ne "0")) && ("$SUN_COMPILER" -eq "0") ]]; then
	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -maes adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_X86_AES=1
	fi

	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -mrdrnd adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_X86_RDRAND=1
	fi

	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -mrdseed adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_X86_RDSEED=1
	fi

	rm -f "$TMP/adhoc.exe" > /dev/null 2>&1
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -mpclmul adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		HAVE_X86_PCLMUL=1
	fi
fi

# ld-gold linker testing
if [[ (-z "$HAVE_LDGOLD") ]]; then
	HAVE_LDGOLD=0
	LD_GOLD=$(which ld.gold 2>&1 | "$GREP" -v "no ld.gold" | head -1)
	ELF_FILE=$(which file 2>&1 | "$GREP" -v "no file" | head -1)
	if [[ (! -z "$LD_GOLD") && (! -z "$ELF_FILE") ]]; then
		HAVE_LDGOLD=$(file "$LD_GOLD" | cut -d":" -f 2 | "$EGREP" -i -c "elf")
	fi
fi

# ARMv7 and ARMv8, including NEON, CRC32 and Crypto extensions
if [[ ("$IS_ARM32" -ne "0" || "$IS_ARM64" -ne "0") ]]; then
	ARM_FEATURES=$(cat /proc/cpuinfo 2>&1 | "$AWK" '{IGNORECASE=1}{if ($1 == "Features") print}' | cut -f 2 -d ':')

	if [[  (-z "$HAVE_ARMV7A") ]]; then
		# NEON is optional on two ARMv7-a cores
		HAVE_ARMV7A=$(echo "$ARM_FEATURES" | "$GREP" -i -c 'neon')
	fi

	if [[ (-z "$HAVE_ARM_VFPV3") ]]; then
		HAVE_ARM_VFPV3=$(echo "$ARM_FEATURES" | "$GREP" -i -c 'vfpv3')
	fi

	if [[ (-z "$HAVE_ARM_VFPV4") ]]; then
		HAVE_ARM_VFPV4=$(echo "$ARM_FEATURES" | "$GREP" -i -c 'vfpv4')
	fi

	if [[ (-z "$HAVE_ARM_NEON") ]]; then
		HAVE_ARM_NEON=$(echo "$ARM_FEATURES" | "$GREP" -i -c 'neon')
	fi

	if [[ (-z "$HAVE_ARM_ASIMD") ]]; then
		HAVE_ARM_ASIMD=$(echo "$ARM_FEATURES" | "$GREP" -i -c 'asimd')
	fi

	if [[ (-z "$HAVE_ARM_CRYPTO") ]]; then
		HAVE_ARM_CRYPTO=$(echo "$ARM_FEATURES" | "$EGREP" -i -c '(aes|pmull|sha1|sha2)')
	fi

	if [[ (-z "$HAVE_ARM_CRC") ]]; then
		HAVE_ARM_CRC=$(echo "$ARM_FEATURES" | "$GREP" -i -c 'crc32')
	fi
fi

# Valgrind testing of C++03, C++11, C++14 and C++17 binaries. Valgrind tests take a long time...
if [[ (-z "$HAVE_VALGRIND") ]]; then
	HAVE_VALGRIND=$(which valgrind 2>&1 | "$GREP" -v "no valgrind" | "$GREP" -i -c valgrind)
fi

# Try to find a symbolizer for Asan
if [[ (-z "$HAVE_SYMBOLIZE") && (! -z "$ASAN_SYMBOLIZER_PATH") ]]; then
	# Sets default value
	HAVE_SYMBOLIZE=$(which asan_symbolize 2>&1 | "$GREP" -v "no asan_symbolize" | "$GREP" -i -c "asan_symbolize")
	if [[ (("$HAVE_SYMBOLIZE" -ne "0") && (-z "$ASAN_SYMBOLIZE")) ]]; then
		ASAN_SYMBOLIZE=asan_symbolize
	fi

	# Clang implicitly uses ASAN_SYMBOLIZER_PATH; set it if its not set.
	if [[ (-z "$ASAN_SYMBOLIZER_PATH") ]]; then
		LLVM_SYMBOLIZER_FOUND=$(which llvm-symbolizer 2>&1 | "$GREP" -v "no llvm-symbolizer" | "$GREP" -i -c llvm-symbolizer)
		if [[ ("$LLVM_SYMBOLIZER_FOUND" -ne "0") ]]; then
			export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)
		fi
	fi
fi

# Used to disassemble object modules so we can verify some aspects of code generation
if [[ (-z "$HAVE_DISASS") ]]; then
	echo "int main(int argc, char* argv[]) {return 0;}" > "$TMP/test.cc"
	gcc "$TMP/test.cc" -o "$TMP/test.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then
		gdb -batch -ex 'disassemble main' "$TMP/test.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then
			HAVE_DISASS=1
		else
			HAVE_DISASS=0
		fi
	fi
fi

# Fixup... GCC 4.8 ASAN produces false positives under ARM
if [[ ( ("$IS_ARM32" -ne "0" || "$IS_ARM64" -ne "0") && "$GCC_48_COMPILER" -ne "0") ]]; then
	HAVE_ASAN=0
fi

# Benchmarks take a long time...
if [[ (-z "$WANT_BENCHMARKS") ]]; then
	WANT_BENCHMARKS=1
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
fi

if [[ "$IS_PPC" -ne "0" ]]; then
	echo "IS_PPC: $IS_PPC" | tee -a "$TEST_RESULTS"
fi
if [[ "$IS_ARM64" -ne "0" ]]; then
	echo "IS_ARM64: $IS_ARM64" | tee -a "$TEST_RESULTS"
elif [[ "$IS_ARM32" -ne "0" ]]; then
	echo "IS_ARM32: $IS_ARM32" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARMV7" -ne "0" ]]; then
	echo "HAVE_ARMV7: $HAVE_ARMV7" | tee -a "$TEST_RESULTS"
elif [[ "$HAVE_ARMV7A" -ne "0" ]]; then
	echo "HAVE_ARMV7A: $HAVE_ARMV7A" | tee -a "$TEST_RESULTS"
elif [[ "$HAVE_ARMV8A" -ne "0" ]]; then
	echo "HAVE_ARMV8A: $HAVE_ARMV8A" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_NEON" -ne "0" ]]; then
	echo "HAVE_ARM_NEON: $HAVE_ARM_NEON" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_VFPV3" -ne "0" ]]; then
	echo "HAVE_ARM_VFPV3: $HAVE_ARM_VFPV3" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_VFPV4" -ne "0" ]]; then
	echo "HAVE_ARM_VFPV4: $HAVE_ARM_VFPV4" | tee -a "$TEST_RESULTS"
fi
if [[ ("$HAVE_ARM_ASIMD" -ne "0") ]]; then
	echo "HAVE_ARM_ASIMD: $HAVE_ARM_ASIMD" | tee -a "$TEST_RESULTS"
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
if [[ ("$HAVE_CXX14" -ne "0" || "$HAVE_CXX17" -ne "0" || "$HAVE_GNU14" -ne "0" || "$HAVE_GNU17" -ne "0") ]]; then
	echo "HAVE_CXX14: $HAVE_CXX14" | tee -a "$TEST_RESULTS"
	echo "HAVE_GNU14: $HAVE_GNU14" | tee -a "$TEST_RESULTS"
	echo "HAVE_CXX17: $HAVE_CXX17" | tee -a "$TEST_RESULTS"
	echo "HAVE_GNU17: $HAVE_GNU17" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_LDGOLD" -ne "0" ]]; then
	echo "HAVE_LDGOLD: $HAVE_LDGOLD" | tee -a "$TEST_RESULTS"
fi

# -O3, -O5 and -Os
echo | tee -a "$TEST_RESULTS"
echo "OPT_O3: $OPT_O3" | tee -a "$TEST_RESULTS"
if [[ (! -z "$OPT_O5") || (! -z "$OPT_OS") || (! -z "$OPT_OFAST") ]]; then
	echo "OPT_O5: $OPT_O5" | tee -a "$TEST_RESULTS"
	echo "OPT_OS: $OPT_OS" | tee -a "$TEST_RESULTS"
	echo "OPT_OFAST: $OPT_OFAST" | tee -a "$TEST_RESULTS"
fi

# Tools available for testing
echo | tee -a "$TEST_RESULTS"
echo "HAVE_ASAN: $HAVE_ASAN" | tee -a "$TEST_RESULTS"
if [[ ("$HAVE_ASAN" -ne "0") && (! -z "$ASAN_SYMBOLIZE") ]]; then echo "ASAN_SYMBOLIZE: $ASAN_SYMBOLIZE" | tee -a "$TEST_RESULTS"; fi
echo "HAVE_UBSAN: $HAVE_UBSAN" | tee -a "$TEST_RESULTS"
echo "HAVE_VALGRIND: $HAVE_VALGRIND" | tee -a "$TEST_RESULTS"

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

if [[ (-e "/proc/cpuinfo") && (-e "/proc/meminfo") ]]; then
	CPU_COUNT=$(cat /proc/cpuinfo | "$GREP" -c '^processor')
	MEM_SIZE=$(cat /proc/meminfo | "$GREP" "MemTotal" | "$AWK" '{print $2}')
	MEM_SIZE=$(($MEM_SIZE/1024))
elif [[ "$IS_DARWIN" -ne "0" ]]; then
	CPU_COUNT=$(sysctl -a 2>/dev/null | "$GREP" 'hw.availcpu' | "$AWK" '{print $3; exit}')
	MEM_SIZE=$(sysctl -a 2>/dev/null | "$GREP" 'hw.memsize' | "$AWK" '{print $3; exit;}')
	MEM_SIZE=$(($MEM_SIZE/1024/1024))
elif [[ "$IS_SOLARIS" -ne "0" ]]; then
	CPU_COUNT=$(psrinfo 2>/dev/null | wc -l | "$AWK" '{print $1}')
	MEM_SIZE=$(prtconf 2>/dev/null | "$GREP" Memory | "$AWK" '{print $3}')
fi

# Benchmarks expect frequency in GiHz.
CPU_FREQ=0.5
if [[ (-e "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq") ]]; then
	CPU_FREQ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)
	CPU_FREQ=$("$AWK" "BEGIN {print $CPU_FREQ/1024/1024}")
elif [[ (-e "/proc/cpuinfo") ]]; then
	CPU_FREQ=$(cat /proc/cpuinfo | "$GREP" 'MHz' | "$AWK" '{print $4; exit}')
	if [[ -z "$CPU_FREQ" ]]; then CPU_FREQ=512; fi
	CPU_FREQ=$("$AWK" "BEGIN {print $CPU_FREQ/1024}")
elif [[ "$IS_DARWIN" -ne "0" ]]; then
	CPU_FREQ=$(sysctl -a 2>/dev/null | "$GREP" 'hw.cpufrequency' | "$AWK" '{print $3; exit;}')
	CPU_FREQ=$("$AWK" "BEGIN {print $CPU_FREQ/1024/1024/1024}")
elif [[ "$IS_SOLARIS" -ne "0" ]]; then
	CPU_FREQ=$(psrinfo -v 2>/dev/null | "$GREP" 'MHz' | "$AWK" '{print $6; exit;}')
	CPU_FREQ=$("$AWK" "BEGIN {print $CPU_FREQ/1024}")
fi

# Some ARM devboards cannot use 'make -j N', even with multiple cores and RAM
#  An 8-core Cubietruck Plus with 2GB RAM experiences OOM kills with '-j 2'.
HAVE_SWAP=1
if [[ "$IS_LINUX" -ne "0" ]]; then
	if [[ (-e "/proc/meminfo") ]]; then
		SWAP_SIZE=$(cat /proc/meminfo | "$GREP" "SwapTotal" | "$AWK" '{print $2}')
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
		CPU_COUNT=$(echo "$CPU_COUNT 2" | "$AWK" '{print int($1/$2)}')
	fi
	MAKEARGS=(-j "$CPU_COUNT")
	echo "Using $MAKE -j $CPU_COUNT"
fi

############################################

# Respect user's preferred flags, but filter the stuff we expliclty test
FILTERED_CXXFLAGS=("-DDEBUG" "-DNDEBUG" "-g" "-g0" "-g1" "-g2" "-g3" "-O0" "-O1" "-O2" "-O3" "-O4" "-O5" "-Os" "-Og"
                   "-Ofast" "-xO0" "-xO1" "-xO2" "-xO3" "-xO4" "-xO5" "-std=c++03" "-std=c++11" "-std=c++14" "-std=c++17"
                   "-m32" "-m64" "-mx32" "-maes" "-mrdrand" "-mrdrnd" "-mrdseed" "-mpclmul" "-Wa,-q" "-mfpu=neon"
                   "-march=armv7-a" "-Wall" "-Wextra" "-Wconversion" "-Wcast-align" "-Wformat-security" "-Wtrampolines"
                   "-DCRYPTOPP_DISABLE_ASM" "-DCRYPTOPP_DISABLE_SSSE3" "-DCRYPTOPP_DISABLE_AESNI" "-fsanitize=address"
                   "-fsanitize=undefined" "-march=armv8-a+crypto" "-march=armv8-a+crc" "-march=armv8-a+crc+crypto"
                   "-DDCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562" "-DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS")

# Additional CXXFLAGS we did not filter
RETAINED_CXXFLAGS=("")

if [[ !(-z "CXXFLAGS") ]]; then
	TEMP_CXXFLAGS=$(echo "$CXXFLAGS" | "$SED" 's/\([[:blank:]]*=[[:blank:]]*\)/=/g')
	IFS=' ' read -r -a TEMP_ARRAY <<< "$TEMP_CXXFLAGS"

	for flag in "${TEMP_ARRAY[@]}"
	do
		found=0
		for filtered in "${FILTERED_CXXFLAGS[@]}"
		do
			if [[ "$flag" = "$filtered" ]]; then
				found=1
			fi
		done
		if [[ "$found" -eq "0" ]]; then
			RETAINED_CXXFLAGS+=("$flag")
		fi
	done
fi

if [[ !(-z "$CXXFLAGS") || !(-z "$RETAINED_CXXFLAGS") ]]; then
	echo | tee -a "$TEST_RESULTS"
	echo "User CXXFLAGS: $CXXFLAGS" | tee -a "$TEST_RESULTS"
	echo "Retained CXXFLAGS: ${RETAINED_CXXFLAGS[@]}" | tee -a "$TEST_RESULTS"
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
	echo $("$CXX" -V 2>&1 | "$SED" 's|CC:|Compiler:|g' | head -1) | tee -a "$TEST_RESULTS"
else
	echo "Compiler:" $("$CXX" --version | head -1) | tee -a "$TEST_RESULTS"
fi

CXX_PATH=$(which "$CXX")
CXX_SYMLINK=$(ls -l "$CXX_PATH" 2>/dev/null | "$GREP" -c '\->' | "$AWK" '{print $1}')
if [[ ("$CXX_SYMLINK" -ne "0") ]]; then CXX_PATH="$CXX_PATH (symlinked)"; fi
echo "Pathname: $CXX_PATH" | tee -a "$TEST_RESULTS"

############################################

# Calcualte these once. They handle Clang, GCC, ICC, etc
DEBUG_CXXFLAGS="-DDEBUG $OPT_G3 $OPT_O0"
RELEASE_CXXFLAGS="-DNDEBUG $OPT_G2 $OPT_O2"
VALGRIND_CXXFLAGS="-DNDEBUG $OPT_G3 $OPT_O1"
PLATFORM_CXXFLAGS=()
ELEVATED_CXXFLAGS=()
DEPRECATED_CXXFLAGS=()

# Keep noise to a minimum
"$CXX" -DCRYPTOPP_ADHOC_MAIN -Wno-deprecated-declarations adhoc.cpp -o "$TMP/adhoc.exe" > /dev/null 2>&1
if [[ "$?" -eq "0" ]]; then
	DEPRECATED_CXXFLAGS+=("-Wno-deprecated-declarations")
fi

# Please, someone put an end to the madness of determining Features, ABI, hard floats and soft floats...
if [[ ("$IS_ARM32" -ne "0" || "$IS_ARM64" -ne "0") ]]; then

	# Add to exercise ARMv7, ARMv7-a, VFPU and NEON more thoroughly
	if [[ ("$IS_ARM32" -ne "0") ]]; then
		if [[ ("$HAVE_ARMV7A" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-march=armv7-a ")
		else
			PLATFORM_CXXFLAGS+=("-march=armv7 ")
		fi

		# http://community.arm.com/groups/tools/blog/2013/04/15/arm-cortex-a-processors-and-gcc-command-lines
		#  These may need more tuning. If it was easy to get the CPU brand name, like Cortex-A9, then we could
		#  be fairly certain of the FPU and ABI flags. But we can't easily get a CPU name, so we suffer through it.
		if [[ ("$HAVE_ARM_NEON" -ne "0" && "$HAVE_ARM_VFPV4" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-mfpu=neon-vfpv4 ")
		elif [[ ("$HAVE_ARM_NEON" -ne "0" && "$HAVE_ARM_VFPV3" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-mfpu=neon-fp16 ")
		elif [[ ("$HAVE_ARM_NEON" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-mfpu=neon ")
		elif [[ ("$HAVE_ARM_VFPV4" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-mfpu=vfpv4-d16 ")
		elif [[ ("$HAVE_ARM_VFPV3" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-mfpu=vfpv3-d16 ")
		fi

		# Soft/Hard floats only apply to 32-bit ARM
		# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.faqs/ka16242.html
		ARM_HARD_FLOAT=$("$CXX" -v 2>&1 | "$GREP" 'Target' | "$EGREP" -i -c '(armhf|gnueabihf)')
		if [[ ("$ARM_HARD_FLOAT" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-mfloat-abi=hard ")
		else
			PLATFORM_CXXFLAGS+=("-mfloat-abi=softfp ")
		fi
	fi

	# Add to exercise ARMv8 more thoroughly. NEON is baked into the CPU asimd flag.
	if [[ ("$IS_ARM64" -ne "0") ]]; then
		if [[ ("$HAVE_ARM_CRC" -ne "0" && "$HAVE_ARM_CRYPTO" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-march=armv8-a+crc+crypto ")
		elif [[ ("$HAVE_ARM_CRC" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-march=armv8-a+crc ")
		elif [[ ("$HAVE_ARM_CRYPTO" -ne "0") ]]; then
			PLATFORM_CXXFLAGS+=("-march=armv8-a+crypto ")
		fi
	fi
fi

if [[ ("$IS_SOLARIS" -ne "0") && ("$SUNCC_121_OR_ABOVE" -ne "0") ]]; then
	ISAINFO=$(isainfo -v 2>/dev/null)
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "sse2") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__SSE2__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "sse3") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__SSE3__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "ssse3") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__SSSE3__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "sse4.1") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__SSE4_1__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "sse4.2") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__SSE4_2__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "aes") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__AES__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "pclmulqdq") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__PCLMUL__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "rdrand") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__RDRND__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "rdseed") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__RDSEED__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "avx") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__AVX__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "avx2") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__AVX2__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "bmi") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__BMI__ "; fi
	if [[ ($(echo "$ISAINFO" | "$GREP" -c "bmi2") -ne "0") ]]; then PLATFORM_CXXFLAGS+="-D__BMI2__ "; fi
fi

if [[ ("$GCC_COMPILER" -ne "0") ]]; then
	ELEVATED_CXXFLAGS+=("-DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562" "-DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS" "-Wall" "-Wextra"
	                    "-Wno-unknown-pragmas" "-Wstrict-aliasing=3" "-Wstrict-overflow" "-Waggressive-loop-optimizations"
	                    "-Wcast-align" "-Wwrite-strings" "-Wformat=2" "-Wformat-security" "-Wtrampolines")

	if [[ ("$GCC_60_OR_ABOVE" -ne "0") ]]; then
		ELEVATED_CXXFLAGS+=("-Wshift-negative-value -Wshift-overflow=2 -Wnull-dereference -Wduplicated-cond -Wodr-type-mismatch")
	fi
	if [[ ("$GCC_51_OR_ABOVE" -ne "0") ]]; then
		ELEVATED_CXXFLAGS+=("-Wabi" "-Wodr")
	fi
fi

if [[ ("$CLANG_COMPILER" -ne "0") ]]; then
	ELEVATED_CXXFLAGS+=("-DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562" "-DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS" "-Wall" "-Wextra")
	ELEVATED_CXXFLAGS+=("-Wno-unknown-pragmas" "-Wstrict-overflow" "-Wcast-align" "-Wwrite-strings" "-Wformat=2" "-Wformat-security")
fi

echo | tee -a "$TEST_RESULTS"
echo "DEBUG_CXXFLAGS: $DEBUG_CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "RELEASE_CXXFLAGS: $RELEASE_CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "VALGRIND_CXXFLAGS: $VALGRIND_CXXFLAGS" | tee -a "$TEST_RESULTS"
if [[ ("${#PLATFORM_CXXFLAGS[@]}" -ne "0") ]]; then
	echo "PLATFORM_CXXFLAGS: ${PLATFORM_CXXFLAGS[@]}" | tee -a "$TEST_RESULTS"
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
# Test AES-NI code generation
if [[ ("$HAVE_DISASS" -ne "0" && "$HAVE_X86_AES" -ne "0") ]] && false; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: AES-NI code generation" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	OBJFILE=rijndael.o
	CXX="$CXX" CXXFLAGS="$RELEASE_CXXFLAGS -march=native -maes" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

	MANGLED=($(nm $OBJFILE))
	UNMANGLED=($(nm $OBJFILE | c++filt))
	IDX=-1

	for i in "${!UNMANGLED[@]}"; do
		if [[ "${UNMANGLED[$i]}" = "${value}" ]]; then
			IDX="${i}";
		fi
	done

	DISASS=$(gdb -batch -ex 'disassemble AESNI_Enc_Block AESNI_Enc_4_Blocks' $OBJFILE 2>/dev/null)

	if [[ ($(echo "$DISASS" | grep -i aesenc) -eq "0") ]]; then
		echo "ERROR: failed to generate aesenc instruction" | tee -a "$TEST_RESULTS"
	fi
	if [[ ($(echo "$DISASS" | grep -i aesenclast) -eq "0") ]]; then
		echo "ERROR: failed to generate aesenclast instruction" | tee -a "$TEST_RESULTS"
	fi
	if [[ ($(echo "$DISASS" | grep -i aesdec) -eq "0") ]]; then
		echo "ERROR: failed to generate aesdec instruction" | tee -a "$TEST_RESULTS"
	fi
	if [[ ($(echo "$DISASS" | grep -i aesdeclast) -eq "0") ]]; then
		echo "ERROR: failed to generate aesdeclast instruction" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Debug build
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$DEBUG_CXXFLAGS ${DEPRECATED_CXXFLAGS[@]}"
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
	echo
fi

############################################
# Release build
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$RELEASE_CXXFLAGS ${DEPRECATED_CXXFLAGS[@]}"
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
	echo
fi

############################################
# Debug build, platform defines
if [[ ("${#PLATFORM_CXXFLAGS[@]}" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS ${PLATFORM_CXXFLAGS} ${DEPRECATED_CXXFLAGS[@]}"
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
		echo
	fi
fi

############################################
# Release build, platform defines
if [[ ("${#PLATFORM_CXXFLAGS[@]}" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS ${PLATFORM_CXXFLAGS} ${DEPRECATED_CXXFLAGS[@]}"
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
		echo
	fi
fi

############################################
# Debug build, DISABLE_ASM
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, DISABLE_ASM" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_DISABLE_ASM ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, DISABLE_ASM
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, DISABLE_ASM" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_DISABLE_ASM ${DEPRECATED_CXXFLAGS[@]}"
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
# c++03 debug and release build
if [[ "$HAVE_CXX03" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++03" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, c++03" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, gnu++03" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, gnu++03" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, c++11" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, c++11" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, gnu++11" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, gnu++11" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, c++14" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, c++14" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, gnu++14" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, gnu++14" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, c++17" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, c++17" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, gnu++17" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, gnu++17" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, X32" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -mx32 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, X32" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -mx32 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, all backwards compatibility.
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, MAINTAIN_BACKWARDS_COMPATIBILITY" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, all backwards compatibility.
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, MAINTAIN_BACKWARDS_COMPATIBILITY" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
fi

./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
	echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
fi
./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
	echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
fi

############################################
# Debug build, init_priority
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, INIT_PRIORITY" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_INIT_PRIORITY=250 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, init_priority
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, INIT_PRIORITY" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_INIT_PRIORITY=250 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, no unaligned data access
#  This test will not be needed in Crypto++ 5.7 and above
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, NO_UNALIGNED_DATA_ACCESS" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, no unaligned data access
#  This test will not be needed in Crypto++ 5.7 and above
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, NO_UNALIGNED_DATA_ACCESS" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, no backwards compatibility with Crypto++ 5.6.2.
#  This test will not be needed in Crypto++ 5.7 and above
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, NO_BACKWARDS_COMPATIBILITY_562" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, no backwards compatibility with Crypto++ 5.6.2.
#  This test will not be needed in Crypto++ 5.7 and above
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, NO_BACKWARDS_COMPATIBILITY_562" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, OS Independence
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, NO_OS_DEPENDENCE" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$DEBUG_CXXFLAGS -DNO_OS_DEPENDENCE ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, OS Independence
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, NO_OS_DEPENDENCE" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$RELEASE_CXXFLAGS -DNO_OS_DEPENDENCE ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, SHA3/FIPS 202
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, USE_FIPS_202_SHA3" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_USE_FIPS_202_SHA3 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, SHA3/FIPS 202
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, USE_FIPS_202_SHA3" | tee -a "$TEST_RESULTS"
echo

"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_USE_FIPS_202_SHA3 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Build with LD-Gold
if [[ "$HAVE_LDGOLD" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, ld-gold linker" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, ld-gold linker" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Build at -O3
if [[ "$HAVE_O3" -ne "0" ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, -O3 optimizations" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_O3 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, -O3 optimizations" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_O3 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, -O5 optimizations" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_O5 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, -O5 optimizations" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_O5 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, -Os optimizations" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_OS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, -Os optimizations" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_OS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: debug, -Ofast optimizations" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DDEBUG $OPT_OFAST -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: release, -Ofast optimizations" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="-DNDEBUG $OPT_OFAST -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, dead code strip
if [[ ("$SUN_COMPILER" -eq "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, dead code strip" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, dead code strip
if [[ ("$SUN_COMPILER" -eq "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, dead code strip" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, UBSan, c++03
if [[ ("$HAVE_CXX03" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++03, UBsan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, UBSan, c++03
if [[ ("$HAVE_CXX03" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++03, UBsan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, Asan, c++03
if [[ ("$HAVE_CXX03" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++03, Asan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, Asan, c++03
if [[ ("$HAVE_CXX03" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++03, Asan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, UBSan, c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++11, UBsan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, UBSan, c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++11, UBsan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Debug build, Asan, c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++11, Asan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, Asan, c++11
if [[ ("$HAVE_CXX11" -ne "0" && "$HAVE_ASAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++11, Asan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, UBSan, c++14
if [[ ("$HAVE_CXX14" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: c++14, UBsan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: c++14, Asan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Release build, UBSan, c++17
if [[ ("$HAVE_CXX17" -ne "0" && "$HAVE_UBSAN" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: c++17, UBsan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "Testing: c++17, Asan" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

# For Solaris, test under Sun Studio 12.2 - 12.5
if [[ "$IS_SOLARIS" -ne "0" ]]; then

	# If PLATFORM_CXXFLAGS is for SunCC, then use them
	if [[ ("$SUNCC_121_OR_ABOVE" -ne "0") ]]; then
		SUNCC_CXXFLAGS="${PLATFORM_CXXFLAGS[@]}"
	fi

	# Sun Studio 12.3 and below workaround, http://github.com/weidai11/cryptopp/issues/228
	SUNCC_SSE_CXXFLAGS=$(echo "$SUNCC_CXXFLAGS" | "$AWK" '/SSE/' ORS=' ' RS=' ')

	############################################
	# Sun Studio 12.2
	if [[ (-e "/opt/solstudio12.2/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.2, debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g -xO0 $SUNCC_SSE_CXXFLAGS"
		CXX=/opt/solstudio12.2/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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
		echo "Testing: Sun Studio 12.2, release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g0 -xO2 $SUNCC_SSE_CXXFLAGS"
		CXX=/opt/solstudio12.2/bin/CC CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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
	# Sun Studio 12.3
	if [[ (-e "/opt/solarisstudio12.3/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.3, debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g3 -xO0 $SUNCC_SSE_CXXFLAGS"
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
		echo "Testing: Sun Studio 12.3, release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g3 -xO2 $SUNCC_SSE_CXXFLAGS"
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
	# Sun Studio 12.4
	if [[ (-e "/opt/solarisstudio12.4/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.4, debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g3 -xO0 $SUNCC_CXXFLAGS"
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
		echo "Testing: Sun Studio 12.4, release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -xO2 $SUNCC_CXXFLAGS"
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
	# Sun Studio 12.5
	if [[ (-e "/opt/developerstudio12.5/bin/CC") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Sun Studio 12.5, debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DDEBUG -g3 -xO1 $SUNCC_CXXFLAGS"
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
		echo "Testing: Sun Studio 12.5, release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -xO2 $SUNCC_CXXFLAGS"
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
	# GCC on Solaris
	if [[ (-e "/bin/g++") ]]; then

		############################################
		# Debug build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Solaris GCC, debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
		echo

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

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="-DNDEBUG -g2 -O2"
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
if [[ ("$IS_DARWIN" -ne "0") && ("$HAVE_CXX03" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++03, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -stdlib=libc++ ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -stdlib=libstdc++ ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX11" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++11, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -stdlib=libc++ ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -stdlib=libstdc++ ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX14" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++14, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -stdlib=libc++ ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -stdlib=libstdc++ ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
if [[ ("$IS_DARWIN" -ne "0" && "$HAVE_CXX17" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++17, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -stdlib=libc++ ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -stdlib=libstdc++ ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -arch ppc -arch ppc64 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Modern compiler and old hardware, like PII, PIII or Core2
if [[ ("$HAVE_X86_AES" -ne "0" || "$HAVE_X86_RDRAND" -ne "0" || "$HAVE_X86_RDSEED" -ne "0") ]]; then

	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: AES, RDRAND and RDSEED" | tee -a "$TEST_RESULTS"
	echo

	OPTS=("-march=native")
	if [[ "$HAVE_X86_AES" -ne "0" ]]; then
		OPTS+=("-maes")
	fi
	if [[ "$HAVE_X86_RDRAND" -ne "0" ]]; then
		OPTS+=("-mrdrnd")
	fi
	if [[ "$HAVE_X86_RDSEED" -ne "0" ]]; then
		OPTS+=("-mrdseed")
	fi
	if [[ "$HAVE_X86_PCLMUL" -ne "0" ]]; then
		OPTS+=("-mpclmul")
	fi

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS ${OPTS[@]} ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
# Benchmarks
if [[ "$WANT_BENCHMARKS" -ne "0" ]]; then

	############################################
	# Benchmarks, c++03
	if [[ "$HAVE_CXX03" -ne "0" ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Benchmarks, c++03" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DPREFER_BERKELEY_STYLE_SOCKETS -DNO_WINDOWS_STYLE_SOCKETS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DPREFER_WINDOWS_STYLE_SOCKETS -DNO_BERKELEY_STYLE_SOCKETS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++03 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Valgrind, c++11. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne "0" && "$HAVE_CXX11" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++11" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++11 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Valgrind, c++14. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne "0" && "$HAVE_CXX14" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++14" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++14 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Valgrind, c++17. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne "0" && "$HAVE_CXX17" -ne "0") ]]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++17" | tee -a "$TEST_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++17 ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# C++03 with elevated warnings
if [[ ("$HAVE_CXX03" -ne "0" && ("$HAVE_GCC" -ne "0" || "$HAVE_CLANG" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: debug, c++03, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 ${DEPRECATED_CXXFLAGS[@]} ${ELEVATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: release, c++03, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 ${DEPRECATED_CXXFLAGS[@]} $RELEASE_CXXFLAGS_ELEVATED"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# C++11 with elevated warnings
if [[ ("$HAVE_CXX11" -ne "0" && ("$HAVE_GCC" -ne "0" || "$HAVE_CLANG" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: debug, c++11, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 ${DEPRECATED_CXXFLAGS[@]}  ${ELEVATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: release, c++11, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 ${DEPRECATED_CXXFLAGS[@]} ${ELEVATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# C++14 with elevated warnings
if [[ ("$HAVE_CXX14" -ne "0" && ("$HAVE_GCC" -ne "0" || "$HAVE_CLANG" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: debug, c++14, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++14 ${DEPRECATED_CXXFLAGS[@]} ${ELEVATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: release, c++14, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 ${DEPRECATED_CXXFLAGS[@]} ${ELEVATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# C++17 with elevated warnings
if [[ ("$HAVE_CXX17" -ne "0" && ("$HAVE_GCC" -ne "0" || "$HAVE_CLANG" -ne "0")) ]]; then

	############################################
	# Debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: debug, c++17, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$DEBUG_CXXFLAGS -std=c++17 ${DEPRECATED_CXXFLAGS[@]} ${ELEVATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# Release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: release, c++17, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 ${DEPRECATED_CXXFLAGS[@]} ${ELEVATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

	if [[ "$?" -ne "0" ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# Perform a quick check with Clang, if available.
#   This check was added after testing on Ubuntu 14.04 with Clang 3.4.
if [[ ("$CLANG_COMPILER" -eq "0") ]]; then

	CLANG_CXX=$(which clang++ 2>&1 | "$GREP" -v "no clang++" | head -1)
	"$CLANG_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then

		############################################
		# Clang build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Clang compiler" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXX="$CLANG_CXX" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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

	GCC_CXX=$(which g++ 2>&1 | "$GREP" -v "no g++" | head -1)
	"$GCC_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then

		############################################
		# GCC build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: GCC compiler" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXX="$GCC_CXX" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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

	INTEL_CXX=$(which icpc 2>&1 | "$GREP" -v "no icpc" | head -1)
	if [[ (-z "$INTEL_CXX") ]]; then
		INTEL_CXX=$(find /opt/intel -name icpc 2>/dev/null | "$GREP" -iv composer | head -1)
	fi
	"$INTEL_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMP/adhoc.exe" > /dev/null 2>&1
	if [[ "$?" -eq "0" ]]; then

		############################################
		# INTEL build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: INTEL compiler" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

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
if [[ ("$MACPORTS_COMPILER" -eq "0") ]]; then

	MACPORTS_CXX=$(find /opt/local/bin -name 'g++*' 2>/dev/null | head -1)
	if [[ (-z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMP/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts GCC build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts GCC compiler" | tee -a "$TEST_RESULTS"
			echo

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			CXX="$MACPORTS_CXX" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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

	MACPORTS_CXX=$(find /opt/local/bin -name 'clang++*' 2>/dev/null | head -1)
	if [[ (-z "$MACPORTS_CXX") ]]; then
		"$MACPORTS_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o "$TMP/adhoc.exe" > /dev/null 2>&1
		if [[ "$?" -eq "0" ]]; then

			############################################
			# MacPorts Clang build
			echo
			echo "************************************" | tee -a "$TEST_RESULTS"
			echo "Testing: MacPorts Clang compiler" | tee -a "$TEST_RESULTS"
			echo

			"$MAKE" clean > /dev/null 2>&1
			rm -f adhoc.cpp > /dev/null 2>&1

			CXX="$MACPORTS_CXX" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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

	if [[ !(-z "$XCODE_CXX") ]]; then
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Xcode Clang compiler" | tee -a "$TEST_RESULTS"
		echo

		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		CXXFLAGS="$RELEASE_CXXFLAGS ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
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
	echo "************************************" | tee -a "$INSTALL_RESULTS"
	echo "Testing: Test install with data directory" | tee -a "$INSTALL_RESULTS"
	echo

	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	INSTALL_DIR="/tmp/cryptopp_test"
	rm -rf "$INSTALL_DIR" > /dev/null 2>&1

	CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_DATA_DIR='\"$INSTALL_DIR/share/cryptopp/\"' ${PLATFORM_CXXFLAGS[@]} ${RETAINED_CXXFLAGS[@]} ${DEPRECATED_CXXFLAGS[@]}"
	CXX="$CXX" CXXFLAGS="$CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$INSTALL_RESULTS"

	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$INSTALL_RESULTS"
	else
		# Still need to manulally place TestData and TestVectors
		OLD_DIR=$(pwd)
		"$MAKE" "${MAKEARGS[@]}" install PREFIX="$INSTALL_DIR" 2>&1 | tee -a "$INSTALL_RESULTS"
		cd "$INSTALL_DIR/bin"

		echo
		echo "************************************" | tee -a "$INSTALL_RESULTS"
		echo "Testing: Install (validation suite)" | tee -a "$INSTALL_RESULTS"
		echo
		./cryptest.exe v 2>&1 | tee -a "$INSTALL_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$INSTALL_RESULTS"
		fi

		echo
		echo "************************************" | tee -a "$INSTALL_RESULTS"
		echo "Testing: Install (test vectors)" | tee -a "$INSTALL_RESULTS"
		echo
		./cryptest.exe tv all 2>&1 | tee -a "$INSTALL_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$INSTALL_RESULTS"
		fi

		if [[ "$WANT_BENCHMARKS" -ne "0" ]]; then
			echo
			echo "************************************" | tee -a "$INSTALL_RESULTS"
			echo "Testing: Install (benchmarks)" | tee -a "$INSTALL_RESULTS"
			echo
			./cryptest.exe b 1 2.4+1e9 2>&1 | tee -a "$INSTALL_RESULTS"
			if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
				echo "ERROR: failed to execute benchmarks" | tee -a "$INSTALL_RESULTS"
			fi
		fi

		echo
		echo "************************************" | tee -a "$INSTALL_RESULTS"
		echo "Testing: Install (help file)" | tee -a "$INSTALL_RESULTS"
		echo
		./cryptest.exe h 2>&1 | tee -a "$INSTALL_RESULTS"
		if [[ ("${PIPESTATUS[0]}" -ne "1") ]]; then
			echo "ERROR: failed to provide help" | tee -a "$INSTALL_RESULTS"
		fi

		# Restore original PWD
		cd "$OLD_DIR"
	fi
fi

############################################
# Test a remove with CRYPTOPP_DATA_DIR
if [[ ("$IS_CYGWIN" -eq "0" && "$IS_MINGW" -eq "0") ]]; then

	echo
	echo "************************************" | tee -a "$INSTALL_RESULTS"
	echo "Testing: Test remove with data directory" | tee -a "$INSTALL_RESULTS"
	echo

	"$MAKE" "${MAKEARGS[@]}" remove PREFIX="$INSTALL_DIR" 2>&1 | tee -a "$INSTALL_RESULTS"
	if [[ ("${PIPESTATUS[0]}" -ne "0") ]]; then
		echo "ERROR: failed to make remove" | tee -a "$INSTALL_RESULTS"
	else
		# Test for complete removal
		if [[ (-d "$INSTALL_DIR/include/cryptopp") ]]; then
			echo "ERROR: failed to remove cryptopp include directory" | tee -a "$INSTALL_RESULTS"
		fi
		if [[ (-d "$INSTALL_DIR/share/cryptopp") ]]; then
			echo "ERROR: failed to remove cryptopp share directory" | tee -a "$INSTALL_RESULTS"
		fi
		if [[ (-d "$INSTALL_DIR/share/cryptopp/TestData") ]]; then
			echo "ERROR: failed to remove cryptopp test data directory" | tee -a "$INSTALL_RESULTS"
		fi
		if [[ (-d "$INSTALL_DIR/share/cryptopp/TestVector") ]]; then
			echo "ERROR: failed to remove cryptopp test vector directory" | tee -a "$INSTALL_RESULTS"
		fi
		if [[ (-e "$INSTALL_DIR/bin/cryptest.exe") ]]; then
			echo "ERROR: failed to remove cryptest.exe program" | tee -a "$INSTALL_RESULTS"
		fi
		if [[ (-e "$INSTALL_DIR/lib/libcryptopp.a") ]]; then
			echo "ERROR: failed to remove libcryptopp.a static library" | tee -a "$INSTALL_RESULTS"
		fi
		if [[ "$IS_DARWIN" -ne "0" && (-e "$INSTALL_DIR/lib/libcryptopp.dylib") ]]; then
			echo "ERROR: failed to remove libcryptopp.dylib dynamic library" | tee -a "$INSTALL_RESULTS"
		elif [[ (-e "$INSTALL_DIR/lib/libcryptopp.so") ]]; then
			echo "ERROR: failed to remove libcryptopp.so dynamic library" | tee -a "$INSTALL_RESULTS"
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

COUNT=$("$GREP" 'Testing:' "$TEST_RESULTS" "$WARN_RESULTS" | wc -l | "$AWK" '{print $1}')
if (( "$COUNT" == "0" )); then
	echo "No configurations tested" | tee -a "$TEST_RESULTS"
else
	echo "$COUNT configurations tested" | tee -a "$TEST_RESULTS"
	ESCAPED=$("$GREP" 'Testing: ' "$TEST_RESULTS" | "$AWK" -F ": " '{print " - " $2 "$"}')
	echo " "$ESCAPED | tr $ '\n' | tee -a "$TEST_RESULTS"
	ESCAPED=$("$GREP" 'Testing: ' "$WARN_RESULTS" | "$AWK" -F ": " '{print " - " $2 "$"}')
	echo " "$ESCAPED | tr '$' '\n' | tee -a "$TEST_RESULTS"
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
ECOUNT=$("$EGREP" '(Error|ERROR|error|FAILED|Illegal|Conditional|CryptoPP::Exception)' $TEST_RESULTS | "$EGREP" -v '( 0 errors|suppressed errors|error detector)' | wc -l | "$AWK" '{print $1}')
if (( "$ECOUNT" == "0" )); then
	echo "No failures detected" | tee -a "$TEST_RESULTS"
else
	echo "$ECOUNT errors detected. See $TEST_RESULTS for details" | tee -a "$TEST_RESULTS"
	if (( "$ECOUNT" < 16 )); then
		"$EGREP" -n '(Error|ERROR|error|FAILED|Illegal|Conditional|CryptoPP::Exception)' "$TEST_RESULTS" | "$EGREP" -v '( 0 errors|suppressed errors|error detector)'
	fi
fi

############################################
# Report warnings

echo
echo "************************************************" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo | tee -a "$TEST_RESULTS" "$WARN_RESULTS"

WCOUNT=$("$EGREP" '(warning:)' $WARN_RESULTS | wc -l | "$AWK" '{print $1}')
if (( "$WCOUNT" == "0" )); then
	echo "No warnings detected" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
else
	echo "$WCOUNT warnings detected. See $WARN_RESULTS for details" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
	# "$EGREP" -n '(warning:)' $WARN_RESULTS | "$GREP" -v 'deprecated-declarations'
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
	[[ "$0" = "$BASH_SOURCE" ]] && exit 0 || return 0
else
	[[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi
