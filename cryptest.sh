#!/usr/bin/env bash

# cryptest.sh - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
#               Copyright assigned to Crypto++ project.

# This is a test script that can be used on some Linux/Unix/Apple machines to automate building the
# library and running the self test with various combinations of flags, options, and conditions.

# Set to suite your taste
TEST_RESULTS=cryptest-result.txt
BENCHMARK_RESULTS=cryptest-bench.txt
WARN_RESULTS=cryptest-warn.txt
INSTALL_RESULTS=cryptest-install.txt

# Remove previous test results
rm -f "$TEST_RESULTS" > /dev/null 2>&1
touch "$TEST_RESULTS"

rm -f "$BENCHMARK_RESULTS" > /dev/null 2>&1
touch "$BENCHMARK_RESULTS"

rm -f "$WARN_RESULTS" > /dev/null 2>&1
touch "$WARN_RESULTS"

# Respect user's preferred flags, but filter the stuff we expliclty test
FILTERED_CXXFLAGS=("-DDEBUG" "-DNDEBUG" "-g" "-g0" "-g1" "-g2" "-g3" "-O0" "-O1" "-O2" "-O3" "-Os" "-Og"
                   "-xO0" "-xO1" "-xO2" "-xO3" "-xOs" "-xOg" "-std=c++03" "-std=c++11" "-std=c++14"
                   "-maes" "-mrdrand" "-mrdrnd" "-mrdseed" "-mpclmul"
                   "-DCRYPTOPP_DISABLE_ASM" "-fsanitize=address" "-fsanitize=undefined" "-march=armv8-a+crypto" "-march=armv8-a+crc"
                   "-DDCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562" "-DDCRYPTOPP_NO_UNALIGNED_DATA_ACCESS")
# Additional CXXFLAGS we did not filter
RETAINED_CXXFLAGS=("")

if [ ! -z "CXXFLAGS" ]; then
	TEMP_CXXFLAGS=$(echo "$CXXFLAGS" | sed 's/\([[:blank:]]*=[[:blank:]]*\)/=/g')
	IFS=' ' read -r -a TEMP_ARRAY <<< "$TEMP_CXXFLAGS"

	for flag in "${TEMP_ARRAY[@]}"
	do
		found=0
		for filtered in "${FILTERED_CXXFLAGS[@]}"
		do
			if [ "$flag" = "$filtered" ]; then
				found=1
			fi
		done
		if [ "$found" -eq "0" ]; then
			RETAINED_CXXFLAGS+=("$flag")
		fi
	done
fi

# Avoid CRYPTOPP_DATA_DIR in this shell
unset CRYPTOPP_DATA_DIR

# Non-Posix $GREP and $EGREP on Solaris.
# We are OK with -i and -c, but we will eventually need more.
GREP=grep
EGREP=egrep

IS_DARWIN=$(uname -s | $GREP -i -c darwin)
IS_LINUX=$(uname -s | $GREP -i -c linux)
IS_CYGWIN=$(uname -s | $GREP -i -c cygwin)
IS_MINGW=$(uname -s | $GREP -i -c mingw)
IS_OPENBSD=$(uname -s | $GREP -i -c openbsd)
IS_NETBSD=$(uname -s | $GREP -i -c netbsd)
IS_SOLARIS=$(uname -s | $GREP -i -c sunos)
IS_X86=$(uname -m | $EGREP -i -c "(i386|i586|i686|amd64|x86_64)")
IS_X64=$(uname -m | $EGREP -i -c "(amd64|x86_64)")
IS_PPC=$(uname -m | $EGREP -i -c "(Power|PPC)")
IS_ARM32=$(uname -m | $EGREP -i -c "arm|aarch32")
IS_ARM64=$(uname -m | $EGREP -i -c "arm64|aarch64")

# Fixup
if [ "$IS_SOLARIS" -ne "0" ]; then
	IS_X64=$(isainfo 2>/dev/null | $GREP -i -c "amd64")
	if [ "$IS_X64" -ne "0" ]; then
		IS_X86=0
	fi

	# Need something more powerful than the non-Posix versions
	if [ -e "/usr/gnu/bin/grep" ]; then GREP=/usr/gnu/bin/grep; fi
	if [ -e "/usr/gnu/bin/egrep" ]; then EGREP=/usr/gnu/bin/egrep; fi
fi

# We need to use the C++ compiler to determine if c++11 is available. Otherwise
#   a mis-detection occurs on Mac OS X 10.9 and above. Below, we use the same
#   Implicit Variables as make. Also see
# https://www.gnu.org/software/make/manual/html_node/Implicit-Variables.html
if [ -z "$CXX" ]; then
	if [ "$IS_DARWIN" -ne "0" ]; then
		CXX=c++
	else
		# Linux, MinGW, Cygwin and fallback ...
		CXX=g++
	fi
fi

# Fixup
if [ "$CXX" == "gcc" ]; then
	CXX=g++
fi

# Fixup
if [ "$IS_SOLARIS" -ne "0" ]; then
	if [ -e "/opt/solarisstudio12.3/bin/CC" ]; then
		CXX=/opt/solarisstudio12.3/bin/CC
	elif [ -e "/opt/solarisstudio12.4/bin/CC" ]; then
		CXX=/opt/solarisstudio12.4/bin/CC
	fi
fi
SUN_COMPILER=$($CXX -V 2>&1 | $EGREP -i -c "CC: Sun")

# Now that the compiler is fixed, see if its GCC 5.1 or above with -Wabi, -Wabi-tag and -Wodr
GCC_51_OR_ABOVE=$(g++ -v 2>&1 | $EGREP -i -c 'gcc version (5\.[1-9]|[6-9])')

# Now that the compiler is fixed, see if its GCC 5.1 or above with -Wabi, -Wabi-tag and -Wodr
GCC_51_OR_ABOVE=$(g++ -v 2>&1 | egrep -i -c 'gcc version (5\.[1-9]|[6-9])')

# Fixup
if [ "$IS_OPENBSD" -ne "0" ] || [ "$IS_NETBSD" -ne "0" ] || [ "$IS_SOLARIS" -ne "0" ]; then
	MAKE=gmake
else
	MAKE=make
fi

if [ -z "$TMP" ]; then
	TMP=/tmp
fi

# Sun Studio does not allow '-x c++'. Copy it here...
rm -f adhoc.cpp > /dev/null 2>&1
cp adhoc.cpp.proto adhoc.cpp

$CXX -DCRYPTOPP_ADHOC_MAIN -Wno-deprecated-declarations adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	RETAINED_CXXFLAGS+=("-Wno-deprecated-declarations")
fi

# C++14 to ensure no surprises. Use the compiler driver, and not cpp, to tell us if the flag is consumed.
$CXX -DCRYPTOPP_ADHOC_MAIN -std=c++14 adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_CXX14=1
else
	HAVE_CXX14=0
fi

# Use the compiler driver, and not cpp, to tell us if the flag is consumed.
$CXX -DCRYPTOPP_ADHOC_MAIN -std=c++11 adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_CXX11=1
else
	HAVE_CXX11=0
fi

# OpenBSD 5.7 and OS X 10.5 cannot consume -std=c++03
$CXX -DCRYPTOPP_ADHOC_MAIN -std=c++03 adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_CXX03=1
else
	HAVE_CXX03=0
fi

# Set to 0 if you don't have UBsan
$CXX -DCRYPTOPP_ADHOC_MAIN -fsanitize=undefined adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
if [ "$?" -eq "0" ] && [ "$IS_X86" -ne "0" ]; then
	HAVE_UBSAN=1
else
	HAVE_UBSAN=0
fi

# Set to 0 if you don't have Asan
$CXX -DCRYPTOPP_ADHOC_MAIN -fsanitize=address adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
if [ "$?" -eq "0" ] && [ "$IS_X86" -ne "0" ]; then
	HAVE_ASAN=1
else
	HAVE_ASAN=0
fi

# Set to 0 if you don't have Intel multiarch
HAVE_INTEL_MULTIARCH=0
if [ "$IS_DARWIN" -ne "0" ] && [ "$IS_X86" -ne "0" ]; then
	$CXX -DCRYPTOPP_ADHOC_MAIN -arch i386 -arch x86_64 adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_INTEL_MULTIARCH=1
	fi
fi

# Set to 0 if you don't have PPC multiarch
HAVE_PPC_MULTIARCH=0
if [ "$IS_DARWIN" -ne "0" ] && [ "$IS_PPC" -ne "0" ]; then
	$CXX -DCRYPTOPP_ADHOC_MAIN -arch ppc -arch ppc64 adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_PPC_MULTIARCH=1
	fi
fi

HAVE_X32=0
if [ "$IS_X64" -ne "0" ]; then
	$CXX -DCRYPTOPP_ADHOC_MAIN -mx32 adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_X32=1
	fi
fi

# Set to 0 if you don't have ARMv8
HAVE_ARM_CRC=0
HAVE_ARM_CRYPTO=0
if [ "$IS_ARM32" -ne "0" ] || [ "$IS_ARM64" -ne "0" ]; then
	$CXX -DCRYPTOPP_ADHOC_MAIN -march=armv8-a+crc adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_ARM_CRC=1
	fi
	$CXX -DCRYPTOPP_ADHOC_MAIN -march=armv8-a+crypto adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_ARM_CRYPTO=1
	fi
fi

HAVE_X86_AES=0
HAVE_X86_RDRAND=0
HAVE_X86_RDSEED=0
HAVE_X86_PCLMUL=0
if [ "$IS_X86" -ne "0" ] || [ "$IS_X64" -ne "0" ]; then
	$CXX -DCRYPTOPP_ADHOC_MAIN -maes adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_X86_AES=1
	fi
	$CXX -DCRYPTOPP_ADHOC_MAIN -mrdrnd adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_X86_RDRAND=1
	fi
	$CXX -DCRYPTOPP_ADHOC_MAIN -mrdseed adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_X86_RDSEED=1
	fi
	$CXX -DCRYPTOPP_ADHOC_MAIN -mpclmul adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		HAVE_X86_PCLMUL=1
	fi
fi

# Set to 0 if you don't have Valgrind. Valgrind tests take a long time...
HAVE_VALGRIND=$(which valgrind 2>&1 | $GREP -v "no valgrind" | $GREP -i -c valgrind)

# Echo back to ensure something is not missed.
echo | tee -a "$TEST_RESULTS"
echo "HAVE_CXX03: $HAVE_CXX03" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX11: $HAVE_CXX11" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX14: $HAVE_CXX14" | tee -a "$TEST_RESULTS"
echo "HAVE_ASAN: $HAVE_ASAN" | tee -a "$TEST_RESULTS"
echo "HAVE_UBSAN: $HAVE_UBSAN" | tee -a "$TEST_RESULTS"

if [ "$HAVE_VALGRIND" -ne "0" ]; then
	echo "HAVE_VALGRIND: $HAVE_VALGRIND" | tee -a "$TEST_RESULTS"
fi
if [ "$HAVE_INTEL_MULTIARCH" -ne "0" ]; then
	echo "HAVE_INTEL_MULTIARCH: $HAVE_INTEL_MULTIARCH" | tee -a "$TEST_RESULTS"
fi
if [ "$HAVE_PPC_MULTIARCH" -ne "0" ]; then
	echo "HAVE_PPC_MULTIARCH: $HAVE_PPC_MULTIARCH" | tee -a "$TEST_RESULTS"
fi
if [ "$IS_DARWIN" -ne "0" ]; then
	echo "IS_DARWIN: $IS_DARWIN" | tee -a "$TEST_RESULTS"
	unset MallocScribble MallocPreScribble MallocGuardEdges
fi
if [ "$IS_LINUX" -ne "0" ]; then
	echo "IS_LINUX: $IS_LINUX" | tee -a "$TEST_RESULTS"
fi
if [ "$IS_CYGWIN" -ne "0" ]; then
	echo "IS_CYGWIN: $IS_CYGWIN" | tee -a "$TEST_RESULTS"
fi
if [ "$IS_MINGW" -ne "0" ]; then
	echo "IS_MINGW: $IS_MINGW" | tee -a "$TEST_RESULTS"
fi
if [ "$IS_ARM64" -ne "0" ]; then
	echo "IS_ARM64: $IS_ARM64" | tee -a "$TEST_RESULTS"
elif [ "$IS_ARM32" -ne "0" ]; then
	echo "IS_ARM32: $IS_ARM32" | tee -a "$TEST_RESULTS"
fi
if [ "$IS_X64" -ne "0" ]; then
	echo "IS_X64: $IS_X64" | tee -a "$TEST_RESULTS"
elif [ "$IS_X86" -ne "0" ]; then
	echo "IS_X86: $IS_X86" | tee -a "$TEST_RESULTS"
fi

############################################

# CPU is logical count, memory is in MB. Low resource boards have
#   fewer than 4 cores and 1GB or less memory. We use this to
#   determine if we can build in parallel without an OOM kill.
CPU_COUNT=1
MEM_SIZE=1024

if [ "$IS_LINUX" -ne "0" ] && [ -e "/proc/cpuinfo" ]; then
	CPU_COUNT=$(cat /proc/cpuinfo | $GREP -c '^processor')
	MEM_SIZE=$(cat /proc/meminfo | $GREP "MemTotal" | awk '{print $2}')
	MEM_SIZE=$(($MEM_SIZE/1024))
elif [ "$IS_DARWIN" -ne "0" ]; then
	CPU_COUNT=$(sysctl -a 2>/dev/null | $GREP 'hw.availcpu' | head -1 | awk '{print $3}')
	MEM_SIZE=$(sysctl -a 2>/dev/null | $GREP 'hw.memsize' | head -1 | awk '{print $3}')
	MEM_SIZE=$(($MEM_SIZE/1024/1024))
elif [ "$IS_SOLARIS" -ne "0" ]; then
	CPU_COUNT=$(psrinfo 2>/dev/null | wc -l | nawk '{print $1}')
	MEM_SIZE=$(prtconf 2>/dev/null | $GREP Memory | nawk '{print $3}')
fi

# Benchmarks expect frequency in GHz.
CPU_FREQ=2.0
if [ "$IS_LINUX" -ne "0" ] && [ -e "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq" ]; then
	CPU_FREQ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)
	CPU_FREQ=$(awk "BEGIN {print $CPU_FREQ/1024/1024}")
elif [ "$IS_DARWIN" -ne "0" ]; then
	CPU_FREQ=$(sysctl -a 2>/dev/null | $GREP 'hw.cpufrequency' | head -1 | awk '{print $3}')
	CPU_FREQ=$(awk "BEGIN {print $CPU_FREQ/1024/1024/1024}")
elif [ "$IS_SOLARIS" -ne "0" ]; then
    CPU_FREQ=$(psrinfo -v 2>/dev/null | $GREP 'MHz' | head -1 | nawk '{print $6}')
    CPU_FREQ=$(nawk "BEGIN {print $CPU_FREQ/1024}")
fi

# Some ARM devboards cannot use 'make -j N', even with multiple cores and RAM
#  An 8-core Cubietruck Plus with 2GB RAM experiences OOM kills with '-j 2'.
HAVE_SWAP=1
if [ "$IS_LINUX" -ne "0" ]; then
	if [ -e "/proc/meminfo" ]; then
		SWAP_SIZE=$(cat /proc/meminfo | $GREP "SwapTotal" | awk '{print $2}')
		if [ "$SWAP_SIZE" -eq "0" ]; then
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

if [ "$CPU_COUNT" -ge "2" ] && [ "$MEM_SIZE" -ge "1280" ] && [ "$HAVE_SWAP" -ne "0" ]; then
	MAKEARGS=(-j "$CPU_COUNT")
	echo "Using $MAKE -j $CPU_COUNT"
fi

############################################

GIT_REPO=$(git branch 2>&1 | $GREP -v "fatal" | wc -l)
if [ "$GIT_REPO" -ne "0" ]; then
	GIT_BRANCH=$(git branch 2>/dev/null | grep '*' | cut -c 3-)
	GIT_HASH=$(git rev-parse HEAD 2>/dev/null | cut -c 1-16)
fi

############################################

echo | tee -a "$TEST_RESULTS"
echo "User CXXFLAGS: $CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "Retained CXXFLAGS: ${RETAINED_CXXFLAGS[@]}" | tee -a "$TEST_RESULTS"

echo | tee -a "$TEST_RESULTS"
if [ ! -z "$GIT_BRANCH" ]; then
	echo "Git branch: $GIT_BRANCH (commit $GIT_HASH)" | tee -a "$TEST_RESULTS"
fi

if [ "$SUN_COMPILER" -ne "0" ]; then
	echo $($CXX -V | head -1) | tee -a "$TEST_RESULTS"
else
	echo "Compiler:" $($CXX --version | head -1) | tee -a "$TEST_RESULTS"
fi

############################################
############################################

TEST_BEGIN=$(date)
echo | tee -a "$TEST_RESULTS"
echo "Start time: $TEST_BEGIN" | tee -a "$TEST_RESULTS"

############################################
# Basic debug build
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DDEBUG -g3 -xO0"
else
	export CXXFLAGS="-DDEBUG -g2 -O0"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Basic release build
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO2"
else
	export CXXFLAGS="-DNDEBUG -g2 -O2"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Basic debug build, DISABLE_ASM
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, default CXXFLAGS, DISABLE_ASM" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DDEBUG -g3 -xO0 -DCRYPTOPP_DISABLE_ASM"
else
	export CXXFLAGS="-DDEBUG -g2 -O0 -DCRYPTOPP_DISABLE_ASM"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Basic release build, DISABLE_ASM
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, default CXXFLAGS, DISABLE_ASM" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO2 -DCRYPTOPP_DISABLE_ASM"
else
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_DISABLE_ASM"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# c++03 debug build
if [ "$HAVE_CXX03" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++03" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DDEBUG -g3 -xO2 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DDEBUG -g3 -O2 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++03 release build
if [ "$HAVE_CXX03" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++03" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DNDEBUG -g3 -xO2 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++11 debug build
if [ "$HAVE_CXX11" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++11" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DDEBUG -g3 -xO0 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DDEBUG -g2 -O0 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++11 release build
if [ "$HAVE_CXX11" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++11" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DNDEBUG -g3 -xO2 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++14 debug build
if [ "$HAVE_CXX14" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++14" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DDEBUG -g3 -xO0 -std=c++14 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DDEBUG -g3 -O0 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# c++14 release build
if [ "$HAVE_CXX14" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++14" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DNDEBUG -g3 -xO2 -std=c++14 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DNDEBUG -g3 -O2 -std=c++14 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# X32 debug build
if [ "$HAVE_X32" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, X32" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DDEBUG -g2 -O2 -mx32 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# X32 release build
if [ "$HAVE_X32" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, X32" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -mx32 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
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

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DDEBUG -g3 -xO0 -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DDEBUG -g3 -O0 -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Release build, all backwards compatibility.
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, MAINTAIN_BACKWARDS_COMPATIBILITY" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO2 -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DNDEBUG -g3 -O2 -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
fi

./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
fi
./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
fi

############################################
# Debug build, init_priority
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, INIT_PRIORITY" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DDEBUG -g3 -xO1 -DCRYPTOPP_INIT_PRIORITY=250 ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DDEBUG -g3 -O1 -DCRYPTOPP_INIT_PRIORITY=250 ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Release build, init_priority
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, INIT_PRIORITY" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO2 -DCRYPTOPP_INIT_PRIORITY=250 ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_INIT_PRIORITY=250 ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
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

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO2 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
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

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO2 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Debug build, OS Independence
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, NO_OS_DEPENDENCE" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DDEBUG -g3 -xO1 -DNO_OS_DEPENDENCE ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DDEBUG -g3 -O1 -DNO_OS_DEPENDENCE ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Release build, OS Independence
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, NO_OS_DEPENDENCE" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO2 -DNO_OS_DEPENDENCE ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DNO_OS_DEPENDENCE ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Basic debug build, using SHA3/FIPS 202
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, default CXXFLAGS, CRYPTOPP_USE_FIPS_202_SHA3" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DDEBUG -g3 -xO1 -DCRYPTOPP_USE_FIPS_202_SHA3 ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DDEBUG -g2 -O1 -DCRYPTOPP_USE_FIPS_202_SHA3 ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Basic release build, using SHA3/FIPS 202
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, default CXXFLAGS, CRYPTOPP_USE_FIPS_202_SHA3" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO2 -DCRYPTOPP_USE_FIPS_202_SHA3 ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_USE_FIPS_202_SHA3 ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Debug build at -O3
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, -O3 optimizations" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DDEBUG -g3 -xO3 ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DDEBUG -g2 -O3 ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Release build at -O3
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, -O3 optimizations" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

if [ "$SUN_COMPILER" -ne "0" ]; then
	export CXXFLAGS="-DNDEBUG -g3 -xO3 ${RETAINED_CXXFLAGS[@]}"
else
	export CXXFLAGS="-DNDEBUG -g2 -O3 ${RETAINED_CXXFLAGS[@]}"
fi

"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

if [ "${PIPESTATUS[0]}" -ne "0" ]; then
	echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
else
	./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
	fi
	./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Debug build at -Os
if [ "$SUN_COMPILER" -eq "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, -Os optimizations" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DDEBUG -g2 -Os ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build at -Os
if [ "$SUN_COMPILER" -eq "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, -Os optimizations" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -Os ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Debug build, dead code strip
if [ "$SUN_COMPILER" -eq "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, dead code strip" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1

	export CXXFLAGS="-DDEBUG -g2 -O2 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" lean 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, dead code strip
if [ "$SUN_COMPILER" -eq "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, dead code strip" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" lean 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Debug build, UBSan, c++03
if [ "$HAVE_CXX03" -ne "0" ] && [ "$HAVE_UBSAN" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++03, UBsan" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DDEBUG -g2 -O1 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" ubsan | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, UBSan, c++03
if [ "$HAVE_CXX03" -ne "0" ] && [ "$HAVE_UBSAN" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++03, UBsan" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" ubsan | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Debug build, Asan, c++03
if [ "$HAVE_CXX03" -ne "0" ] && [ "$HAVE_ASAN" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++03, Asan" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DDEBUG -g2 -O1 -std=c++03 ${RETAINED_CXXFLAGS[@]}"

	if [ "$CXX" == "clang++" ]; then
		"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" asan | asan_symbolize | tee -a "$TEST_RESULTS"
	else
		"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" asan | tee -a "$TEST_RESULTS"
	fi

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Asan, c++03
if [ "$HAVE_CXX03" -ne "0" ] && [ "$HAVE_ASAN" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: release, c++03, Asan" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 ${RETAINED_CXXFLAGS[@]}"

	if [ "$CXX" == "clang++" ]; then
		"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" asan | asan_symbolize | tee -a "$TEST_RESULTS"
	else
		"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" asan | tee -a "$TEST_RESULTS"
	fi

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, UBSan, c++11
if [ "$HAVE_CXX11" -ne "0" ] && [ "$HAVE_UBSAN" -ne "0" ]; then
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: c++11, UBsan" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" ubsan | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Release build, Asan, c++11
if [ "$HAVE_CXX11" -ne "0" ] && [ "$HAVE_ASAN" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: c++11, Asan" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 ${RETAINED_CXXFLAGS[@]}"

	if [ "$CXX" == "clang++" ]; then
		"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" asan | asan_symbolize | tee -a "$TEST_RESULTS"
	else
		"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" asan | tee -a "$TEST_RESULTS"
	fi

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

# For Solaris, we test under Sun Studio 12.4 because it offers both -std=c++03 and -std=c++11.
#   We also want to test a couple of builds under Sun Studio 12.3
if [ "$IS_SOLARIS" -ne "0" ] && [ "$CXX" != "/opt/solarisstudio12.3/bin/CC" ] && [ -e "/opt/solarisstudio12.3/bin/CC" ]; then
	CXX=/opt/solarisstudio12.3/bin/CC

	############################################
	# Basic debug build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Sun Studio 12.3, debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DDEBUG -g3 -xO0"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi

	############################################
	# Basic release build
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Sun Studio 12.3, release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g3 -xO2"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

# For Darwin, we need to test both -stdlib=libstdc++ (GNU) and
#  -stdlib=libc++ (LLVM) crossed with -std=c++03 and -std=c++11.

############################################
# Darwin, c++03, libc++
if [ "$HAVE_CXX03" -ne "0" ] && [ "$IS_DARWIN" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++03, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -stdlib=libc++ ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++03, libstdc++
if [ "$HAVE_CXX03" -ne "0" ] && [ "$IS_DARWIN" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++03, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -stdlib=libstdc++ ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++11, libc++
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_CXX11" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++11, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -stdlib=libc++ ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++11, libstdc++
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_CXX11" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++11, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -stdlib=libstdc++ ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++14, libc++
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_CXX14" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++14, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++14 -stdlib=libc++ ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++14, libstdc++
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_CXX14" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++14, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++14 -stdlib=libstdc++ ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, Intel multiarch, c++03
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_INTEL_MULTIARCH" -ne "0" ] && [ "$HAVE_CXX03" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, Intel multiarch, c++03" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch i386 -arch x86_64 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "Running i386 version..."
		arch -i386 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
		fi
		arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
		fi

		echo "Running x86_64 version..."
		arch -x86_64 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
		fi
		arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, Intel multiarch, c++11
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_INTEL_MULTIARCH" -ne "0" ] && [ "$HAVE_CXX11" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, Intel multiarch, c++11" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch i386 -arch x86_64 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "Running i386 version..."
		arch -i386 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
		fi
		arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
		fi

		echo "Running x86_64 version..."
		arch -x86_64 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
		fi
		arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, PowerPC multiarch
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_PPC_MULTIARCH" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, PowerPC multiarch" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch ppc -arch ppc64 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "Running PPC version..."
		arch -ppc ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite (PPC)" | tee -a "$TEST_RESULTS"
		fi
		arch -ppc ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors (PPC)" | tee -a "$TEST_RESULTS"
		fi

		echo "Running PPC64 version..."
		arch -ppc64 ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite (PPC64)" | tee -a "$TEST_RESULTS"
		fi
		arch -ppc64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors (PPC64)" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Darwin, c++03, Malloc Guards
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_CXX03" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++03, Malloc Guards" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		export MallocScribble=1
		export MallocPreScribble=1
		export MallocGuardEdges=1

		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi

		unset MallocScribble MallocPreScribble MallocGuardEdges
	fi
fi

############################################
# Darwin, c++11, Malloc Guards
if [ "$IS_DARWIN" -ne "0" ] && [ "$HAVE_CXX11" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Darwin, c++11, Malloc Guards" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		export MallocScribble=1
		export MallocPreScribble=1
		export MallocGuardEdges=1

		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi

		unset MallocScribble MallocPreScribble MallocGuardEdges
	fi
fi

############################################
# Xcode compiler
if [ "$IS_DARWIN" -ne "0" ]; then
  XCODE_COMPILER=$(find /Applications/Xcode*.app/Contents/Developer -name clang++ 2>/dev/null | head -1)
  if [ -z "$XCODE_COMPILER" ]; then
	  XCODE_COMPILER=$(find /Developer/Applications/Xcode.app -name clang++ 2>/dev/null | head -1)
  fi

  if [ ! -z "$XCODE_COMPILER" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Xcode Clang compiler" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$XCODE_COMPILER" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
  fi
fi

############################################
# Modern compiler and old hardware, like PII, PIII or Core2
if [ "$HAVE_X86_AES" -ne "0" ] || [ "$HAVE_X86_RDRAND" -ne "0" ] || [ "$HAVE_X86_RDSEED" -ne "0" ]; then

	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: AES, RDRAND and RDSEED" | tee -a "$TEST_RESULTS"
	echo

	OPTS=("-march=native")
	if [ "$HAVE_X86_AES" -ne "0" ]; then
		OPTS+=("-maes")
	fi
	if [ "$HAVE_X86_RDRAND" -ne "0" ]; then
		OPTS+=("-mrdrnd")
	fi
	if [ "$HAVE_X86_RDSEED" -ne "0" ]; then
		OPTS+=("-mrdseed")
	fi
	if [ "$HAVE_X86_PCLMUL" -ne "0" ]; then
		OPTS+=("-mpclmul")
	fi

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 ${OPTS[@]} ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# ARM CRC32
if [ "$HAVE_ARM_CRC" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: ARM CRC32" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -march=armv8-a+crc ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# ARM Crypto
if [ "$HAVE_ARM_CRYPTO" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: ARM Crypto" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -march=armv8-a+crypto ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Benchmarks, c++03
if [ "$HAVE_CXX03" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Benchmarks, c++03" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DNDEBUG -xO3 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DNDEBUG -O3 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "**************************************" >> "$BENCHMARK_RESULTS"
		./cryptest.exe b 3 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute benchmarks" | tee -a "$BENCHMARK_RESULTS"
		fi
	fi
fi

############################################
# Benchmarks, c++11
if [ "$HAVE_CXX11" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Benchmarks, c++11" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DNDEBUG -xO3 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DNDEBUG -O3 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		echo "**************************************" >> "$BENCHMARK_RESULTS"
		./cryptest.exe b 3 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute benchmarks" | tee -a "$BENCHMARK_RESULTS"
		fi
	fi
fi

# For Cygwin, we need to test both PREFER_BERKELEY_STYLE_SOCKETS
#   and PREFER_WINDOWS_STYLE_SOCKETS

############################################
# MinGW and PREFER_BERKELEY_STYLE_SOCKETS
if [ "$IS_MINGW" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: MinGW, PREFER_BERKELEY_STYLE_SOCKETS" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -DPREFER_BERKELEY_STYLE_SOCKETS -DNO_WINDOWS_STYLE_SOCKETS ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# MinGW and PREFER_WINDOWS_STYLE_SOCKETS
if [ "$IS_MINGW" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: MinGW, PREFER_WINDOWS_STYLE_SOCKETS" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -DPREFER_WINDOWS_STYLE_SOCKETS -DNO_BERKELEY_STYLE_SOCKETS ${RETAINED_CXXFLAGS[@]}"
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
		fi
		./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
		fi
	fi
fi

############################################
# Valgrind, c++03. Requires -O1 for accurate results
if [ "$HAVE_CXX03" -ne "0" ] && [ "$HAVE_VALGRIND" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++03" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DNDEBUG -g3 -xO1 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DNDEBUG -g3 -O1 -std=c++03 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Valgrind, c++11. Requires -O1 for accurate results
if [ "$HAVE_VALGRIND" -ne "0" ] && [ "$HAVE_CXX11" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Valgrind, c++11" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DNDEBUG -g3 -xO1 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DNDEBUG -g3 -O1 -std=c++11 ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Build with elevated warnings
if [ "$HAVE_CXX03" -ne "0" ] && [ "$SUN_COMPILER" -eq "0" ]; then

	############################################
	# C++03 debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: debug, c++03, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$CXX" == "g++" ]; then
		CXXFLAGS="-DDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines "
		if [ "$GCC_51_OR_ABOVE" -ne "0" ]; then
			CXXFLAGS+="-Wabi -Wodr"
		fi
	else
		CXXFLAGS="-DDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security "
	fi

	export CXXFLAGS
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# C++03 release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: release, c++03, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$CXX" == "g++" ]; then
		CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines "
		if [ "$GCC_51_OR_ABOVE" -ne "0" ]; then
			CXXFLAGS+="-Wabi -Wodr"
		fi
	else
		CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security "
	fi

	export CXXFLAGS
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [ "$?" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# Build with elevated warnings
if [ "$HAVE_CXX11" -ne "0" ] && [ "$SUN_COMPILER" -eq "0" ]; then

	############################################
	# C++11 debug build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: debug, c++11, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$CXX" == "g++" ]; then
		CXXFLAGS="-DDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines "
		if [ "$GCC_51_OR_ABOVE" -ne "0" ]; then
			CXXFLAGS+="-Wabi -Wodr"
		fi
	else
		CXXFLAGS="-DDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security "
	fi

	export CXXFLAGS
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi

	############################################
	# C++11 release build
	echo
	echo "************************************" | tee -a "$WARN_RESULTS"
	echo "Testing: release, c++11, elevated warnings" | tee -a "$WARN_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	if [ "$CXX" == "g++" ]; then
		CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines "
		if [ "$GCC_51_OR_ABOVE" -ne "0" ]; then
			CXXFLAGS+="-Wabi -Wodr"
		fi
	else
		CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security "
	fi

	export CXXFLAGS
	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [ "$?" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# If using GCC (likely Linux), then perform a quick check with Clang.
# This check was added after testing on Ubuntu 14.04 with Clang 3.4.
if [ "$CXX" == "g++" ] && [ "$SUN_COMPILER" -eq "0" ]; then

	CLANG_COMPILER=$(which clang++ 2>/dev/null)
	"$CLANG_COMPILER" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp -o $TMP/adhoc.exe > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then

		############################################
		# Basic Clang build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Clang" | tee -a "$TEST_RESULTS"
		echo

		unset CXXFLAGS
		"$MAKE" clean > /dev/null 2>&1
		rm -f adhoc.cpp > /dev/null 2>&1

		"$MAKE" "${MAKEARGS[@]}" CXX="$CLANG_COMPILER" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
		else
			./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
			if [ "${PIPESTATUS[0]}" -ne "0" ]; then
				echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
			fi
			./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
			if [ "${PIPESTATUS[0]}" -ne "0" ]; then
				echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
			fi
		fi
	fi
fi

############################################
# Test an install with CRYPTOPP_DATA_DIR
if [ "$IS_CYGWIN" -eq "0" ] && [ "$IS_MINGW" -eq "0" ]; then

	echo
	echo "************************************" | tee -a "$INSTALL_RESULTS"
	echo "Testing: Test install with data directory" | tee -a "$INSTALL_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	INSTALL_DIR="/tmp/cryptopp_test"
	rm -rf "$INSTALL_DIR" > /dev/null 2>&1

	if [ "$SUN_COMPILER" -ne "0" ]; then
		export CXXFLAGS="-DNDEBUG -g3 -xO2 -DCRYPTOPP_DATA_DIR='\"$INSTALL_DIR/share/cryptopp/\"' ${RETAINED_CXXFLAGS[@]}"
	else
		export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_DATA_DIR='\"$INSTALL_DIR/share/cryptopp/\"' ${RETAINED_CXXFLAGS[@]}"
	fi

	"$MAKE" "${MAKEARGS[@]}" CXX="$CXX" static dynamic cryptest.exe 2>&1 | tee -a "$INSTALL_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
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
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute validation suite" | tee -a "$INSTALL_RESULTS"
		fi

		echo
		echo "************************************" | tee -a "$INSTALL_RESULTS"
		echo "Testing: Install (test vectors)" | tee -a "$INSTALL_RESULTS"
		echo
		./cryptest.exe tv all 2>&1 | tee -a "$INSTALL_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute test vectors" | tee -a "$INSTALL_RESULTS"
		fi

		echo
		echo "************************************" | tee -a "$INSTALL_RESULTS"
		echo "Testing: Install (benchmarks)" | tee -a "$INSTALL_RESULTS"
		echo
		./cryptest.exe b 1 2.4+1e9 2>&1 | tee -a "$INSTALL_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "0" ]; then
			echo "ERROR: failed to execute benchmarks" | tee -a "$INSTALL_RESULTS"
		fi

		echo
		echo "************************************" | tee -a "$INSTALL_RESULTS"
		echo "Testing: Install (help file)" | tee -a "$INSTALL_RESULTS"
		echo
		./cryptest.exe h 2>&1 | tee -a "$INSTALL_RESULTS"
		if [ "${PIPESTATUS[0]}" -ne "1" ]; then
			echo "ERROR: failed to provide help" | tee -a "$INSTALL_RESULTS"
		fi

		# Restore original PWD
		cd "$OLD_DIR"
	fi
fi

############################################
# Test a remove with CRYPTOPP_DATA_DIR
if [ "$IS_CYGWIN" -eq "0" ] && [ "$IS_MINGW" -eq "0" ]; then

	echo
	echo "************************************" | tee -a "$INSTALL_RESULTS"
	echo "Testing: Test remove with data directory" | tee -a "$INSTALL_RESULTS"
	echo

	"$MAKE" "${MAKEARGS[@]}" remove PREFIX="$INSTALL_DIR" 2>&1 | tee -a "$INSTALL_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make remove" | tee -a "$INSTALL_RESULTS"
	else
		# Test for complete removal
		if [ -d "$INSTALL_DIR/include/cryptopp" ]; then
			echo "ERROR: failed to remove cryptopp include directory" | tee -a "$INSTALL_RESULTS"
		fi
		if [ -d "$INSTALL_DIR/share/cryptopp" ]; then
			echo "ERROR: failed to remove cryptopp share directory" | tee -a "$INSTALL_RESULTS"
		fi
		if [ -d "$INSTALL_DIR/share/cryptopp/TestData" ]; then
			echo "ERROR: failed to remove cryptopp test data directory" | tee -a "$INSTALL_RESULTS"
		fi
		if [ -d "$INSTALL_DIR/share/cryptopp/TestVector" ]; then
			echo "ERROR: failed to remove cryptopp test vector directory" | tee -a "$INSTALL_RESULTS"
		fi
		if [ -e "$INSTALL_DIR/bin/cryptest.exe" ]; then
			echo "ERROR: failed to remove cryptest.exe program" | tee -a "$INSTALL_RESULTS"
		fi
		if [ -e "$INSTALL_DIR/lib/libcryptopp.a" ]; then
			echo "ERROR: failed to remove libcryptopp.a static library" | tee -a "$INSTALL_RESULTS"
		fi
		if [ "$IS_DARWIN" -ne "0" ] && [ -e "$INSTALL_DIR/lib/libcryptopp.dylib" ]; then
			echo "ERROR: failed to remove libcryptopp.dylib dynamic library" | tee -a "$INSTALL_RESULTS"
		elif [ -e "$INSTALL_DIR/lib/libcryptopp.so" ]; then
			echo "ERROR: failed to remove libcryptopp.so dynamic library" | tee -a "$INSTALL_RESULTS"
		fi
	fi
fi

############################################
# Cleanup
unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

############################################
############################################

TEST_END=$(date)

echo
echo "************************************************" | tee -a "$TEST_RESULTS"
echo "************************************************" | tee -a "$TEST_RESULTS"
echo | tee -a "$TEST_RESULTS"

echo "Testing started: $TEST_BEGIN" | tee -a "$TEST_RESULTS"
echo "Testing finished: $TEST_END" | tee -a "$TEST_RESULTS"
echo | tee -a "$TEST_RESULTS"

COUNT=$($GREP -a 'Testing:' "$TEST_RESULTS" | wc -l)
if [ "$COUNT" -eq "0" ]; then
	echo "No configurations tested" | tee -a "$TEST_RESULTS"
else
	echo "$COUNT configurations tested" | tee -a "$TEST_RESULTS"
fi
echo | tee -a "$TEST_RESULTS"

# "FAILED" is from Crypto++
# "ERROR" is from this script
# "Error" is from the GNU assembler
# "error" is from the sanitizers
# "Illegal", "0 errors" and "suppressed errors" are from Valgrind.
ECOUNT=$($EGREP -a '(Error|ERROR|error|FAILED|Illegal)' $TEST_RESULTS | $EGREP -v '( 0 errors|suppressed errors|error detector)' | wc -l)
if [ "$ECOUNT" -eq "0" ]; then
	echo "No failures detected" | tee -a "$TEST_RESULTS"
else
	echo "$ECOUNT errors detected. See $TEST_RESULTS for details" | tee -a "$TEST_RESULTS"
	echo
	$EGREP -an '(Error|ERROR|error|FAILED|Illegal)' "$TEST_RESULTS" | $EGREP -v '( 0 errors|suppressed errors|error detector)'
fi
echo | tee -a "$TEST_RESULTS"

# Write warnings to $TEST_RESULTS
WCOUNT=$($EGREP -a '(warning:)' $WARN_RESULTS | $GREP -v 'deprecated-declarations' | wc -l)
if [ "$WCOUNT" -eq "0" ]; then
	echo "No warnings detected" | tee -a "$TEST_RESULTS"
else
	echo "$WCOUNT warnings detected. See $WARN_RESULTS for details" | tee -a "$TEST_RESULTS"
	echo
#	$EGREP -an '(warning:)' $WARN_RESULTS | $GREP -v 'deprecated-declarations'
fi
echo | tee -a "$TEST_RESULTS"

echo "************************************************" | tee -a "$TEST_RESULTS"
echo "************************************************" | tee -a "$TEST_RESULTS"

# http://tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
if [ "$ECOUNT" -eq "0" ]; then
	[ "$0" = "$BASH_SOURCE" ] && exit 0 || return 0
else
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi
