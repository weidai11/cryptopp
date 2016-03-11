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
#if [ ! -z "CXXFLAGS" ]; then
#	ADD_CXXFLAGS=$(echo "$CXXFLAGS" | sed 's/\(-DDEBUG\|-DNDEBUG\|-O[0-9]\|-Os\|-Og\|-fsanitize=address\|-fsanitize=undefined\|-DDCRYPTOPP_NO_UNALIGNED_DATA_ACCESS\|-DDCRYPTOPP_NO_UNALIGNED_DATA_ACCESS\|-DDCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562\)//g')
#else\
#	ADD_CXXFLAGS=""
#fi

# Avoid CRYPTOPP_DATA_DIR in this shell
unset CRYPTOPP_DATA_DIR

# I can't seem to get the expression to work in sed on Apple. It returns the original CXXFLAGS.
#   If you want to test with additional flags, then put them in ADD_CXXFLAGS below.
# ADD_CXXFLAGS="-mrdrnd -mrdseed"
ADD_CXXFLAGS=""

IS_DARWIN=$(uname -s | grep -i -c darwin)
IS_LINUX=$(uname -s | grep -i -c linux)
IS_CYGWIN=$(uname -s | grep -i -c cygwin)
IS_MINGW=$(uname -s | grep -i -c mingw)
IS_OPENBSD=$(uname -s | grep -i -c openbsd)
IS_NETBSD=$(uname -s | grep -i -c netbsd)
IS_X86=$(uname -m | egrep -i -c "(i386|i586|i686|amd64|x86_64)")
IS_X64=$(uname -m | egrep -i -c "(amd64|x86_64)")
IS_PPC=$(uname -m | egrep -i -c "(Power|PPC)")
IS_ARM=$(uname -m | egrep -i -c "arm")

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
if [ "$IS_OPENBSD" -ne "0" ] || [ "$IS_NETBSD" -ne "0" ]; then
	MAKE=gmake
else
	MAKE=make
fi

if [ -z "$TMP" ]; then
	TMP=/tmp
fi

$CXX -x c++ -DCRYPTOPP_ADHOC_MAIN -Wno-deprecated-declarations adhoc.cpp.proto -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	ADD_CXXFLAGS="$ADD_CXXFLAGS -Wno-deprecated-declarations"
fi

# Use the compiler driver, and not cpp, to tell us if the flag is consumed.
$CXX -x c++ -dM -E -std=c++11 - < /dev/null > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_CXX11=1
else
	HAVE_CXX11=0
fi

# OpenBSD 5.7 and OS X 10.5 cannot consume -std=c++03
$CXX -x c++ -dM -E -std=c++03 - < /dev/null > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_CXX03=1
else
	HAVE_CXX03=0
fi

# Set to 0 if you don't have UBsan
$CXX -x c++ -DCRYPTOPP_ADHOC_MAIN -fsanitize=undefined adhoc.cpp.proto -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ] && [ "$IS_X86" -ne "0" ]; then
	HAVE_UBSAN=1
else
	HAVE_UBSAN=0
fi

# Set to 0 if you don't have Asan
$CXX -x c++ -DCRYPTOPP_ADHOC_MAIN -fsanitize=address adhoc.cpp.proto -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ] && [ "$IS_X86" -ne "0" ]; then
	HAVE_ASAN=1
else
	HAVE_ASAN=0
fi

# Set to 0 if you don't have Intel multiarch
HAVE_INTEL_MULTIARCH=0
if [ "$IS_DARWIN" -ne "0" ] && [ "$IS_X86" -ne "0" ]; then
$CXX -x c++ -DCRYPTOPP_ADHOC_MAIN -arch i386 -arch x86_64 adhoc.cpp.proto -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_INTEL_MULTIARCH=1
fi
fi

# Set to 0 if you don't have PPC multiarch
HAVE_PPC_MULTIARCH=0
if [ "$IS_DARWIN" -ne "0" ] && [ "$IS_PPC" -ne "0" ]; then
$CXX -x -DCRYPTOPP_ADHOC_MAIN c++ -arch ppc -arch ppc64 adhoc.cpp.proto -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_PPC_MULTIARCH=1
fi
fi

HAVE_X32=0
if [ "$IS_X64" -ne "0" ]; then
$CXX -x -DCRYPTOPP_ADHOC_MAIN c++ -mx32 adhoc.cpp.proto -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_X32=1
fi
fi

# Set to 0 if you don't have Valgrind. Valgrind tests take a long time...
HAVE_VALGRIND=$(which valgrind 2>&1 | grep -v "no valgrind" | grep -i -c valgrind)

# Echo back to ensure something is not missed.
echo | tee -a "$TEST_RESULTS"
echo "HAVE_CXX03: $HAVE_CXX03" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX11: $HAVE_CXX11" | tee -a "$TEST_RESULTS"
echo "HAVE_ASAN: $HAVE_ASAN" | tee -a "$TEST_RESULTS"
echo "HAVE_UBSAN: $HAVE_UBSAN" | tee -a "$TEST_RESULTS"

if [ "$HAVE_VALGRIND" -ne "0" ]; then
	echo "HAVE_VALGRIND: $HAVE_VALGRIND" | tee -a "$TEST_RESULTS"
fi
if [ "$IS_DARWIN" -ne "0" ]; then
	echo "IS_DARWIN: $IS_DARWIN" | tee -a "$TEST_RESULTS"
	unset MallocScribble MallocPreScribble MallocGuardEdges
fi
if [ "$HAVE_INTEL_MULTIARCH" -ne "0" ]; then
	echo "HAVE_INTEL_MULTIARCH: $HAVE_INTEL_MULTIARCH" | tee -a "$TEST_RESULTS"
fi
if [ "$HAVE_PPC_MULTIARCH" -ne "0" ]; then
	echo "HAVE_PPC_MULTIARCH: $HAVE_PPC_MULTIARCH" | tee -a "$TEST_RESULTS"
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

############################################

# CPU is logical count, memory is in MB. Low resource boards have
#   fewer than 4 cores and 1GB or less memory. We use this to
#   determine if we can build in parallel without an OOM kill.
CPU_COUNT=1
MEM_SIZE=1024

if [ "$IS_LINUX" -ne "0" ] && [ -e "/proc/cpuinfo" ]; then
	CPU_COUNT=$(cat /proc/cpuinfo | grep -c '^processor')
	MEM_SIZE=$(cat /proc/meminfo | grep "MemTotal" | awk '{print $2}')
	MEM_SIZE=$(($MEM_SIZE/1024))
elif [ "$IS_DARWIN" -ne "0" ]; then
	CPU_COUNT=$(sysctl -a 2>/dev/null | grep 'hw.availcpu' | head -1 | awk '{print $3}')
	MEM_SIZE=$(sysctl -a 2>/dev/null | grep 'hw.memsize' | head -1 | awk '{print $3}')
	MEM_SIZE=$(($MEM_SIZE/1024/1024))
fi

# Benchmarks expect frequency in GHz.
CPU_FREQ=2.0
if [ "$IS_LINUX" -ne "0" ] && [ -e "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq" ]; then
	CPU_FREQ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)
	CPU_FREQ=$(awk "BEGIN {print $CPU_FREQ/1024/1024}")
elif [ "$IS_DARWIN" -ne "0" ]; then
	CPU_FREQ=$(sysctl -a 2>/dev/null | grep 'hw.cpufrequency' | head -1 | awk '{print $3}')
	CPU_FREQ=$(awk "BEGIN {print $CPU_FREQ/1024/1024/1024}")
fi

# Some ARM devboards cannot use 'make -j N', even with multiple cores and RAM
#  An 8-core Cubietruck Plus with 2GB RAM experiences OOM kills with '-j 2'.
HAVE_SWAP=1
if [ "$IS_LINUX" -ne "0" ]; then
	if [ -e "/proc/meminfo" ]; then
		SWAP_SIZE=$(cat /proc/meminfo | grep "SwapTotal" | awk '{print $2}')
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

echo | tee -a "$TEST_RESULTS"
echo "User CXXFLAGS: $CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "Retained CXXFLAGS: $ADD_CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "Compiler:" $($CXX --version | head -1) | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DDEBUG -g2 -O2"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DNDEBUG -g2 -O2"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DDEBUG -g2 -O2 -DCRYPTOPP_DISABLE_ASM"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_DISABLE_ASM"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DDEBUG -g2 -O2 -mx32 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -mx32 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DDEBUG -g2 -O2 -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DDEBUG -g2 -O1 -DCRYPTOPP_INIT_PRIORITY=250 $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_INIT_PRIORITY=250 $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DDEBUG -g2 -O1 -DNO_OS_DEPENDENCE $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DNDEBUG -g2 -O2 -DNO_OS_DEPENDENCE $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DDEBUG -g2 -O3 $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

export CXXFLAGS="-DNDEBUG -g2 -O3 $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, -Os optimizations" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

export CXXFLAGS="-DDEBUG -g2 -Os $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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
# Release build at -Os
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, -Os optimizations" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

export CXXFLAGS="-DNDEBUG -g2 -Os $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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
# Debug build, dead code strip
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, dead code strip" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1

export CXXFLAGS="-DDEBUG -g2 -O2 $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" lean 2>&1 | tee -a "$TEST_RESULTS"

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
# Release build, dead code strip
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: release, dead code strip" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
rm -f adhoc.cpp > /dev/null 2>&1

export CXXFLAGS="-DNDEBUG -g2 -O2 $ADD_CXXFLAGS"
"$MAKE" "${MAKEARGS[@]}" lean 2>&1 | tee -a "$TEST_RESULTS"

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
# Debug build, UBSan, c++03
if [ "$HAVE_CXX03" -ne "0" ] && [ "$HAVE_UBSAN" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: debug, c++03, UBsan" | tee -a "$TEST_RESULTS"
	echo
	
	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	rm -f adhoc.cpp > /dev/null 2>&1

	export CXXFLAGS="-DDEBUG -g2 -O1 -std=c++03 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DDEBUG -g2 -O1 -std=c++03 $ADD_CXXFLAGS"

	if [ "$CXX" == "clang++" ]; then
		"$MAKE" "${MAKEARGS[@]}" asan | asan_symbolize | tee -a "$TEST_RESULTS"
	else
		"$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"
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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"

	if [ "$CXX" == "clang++" ]; then
		"$MAKE" "${MAKEARGS[@]}" asan | asan_symbolize | tee -a "$TEST_RESULTS"
	else
		"$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"
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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"

	if [ "$CXX" == "clang++" ]; then
		"$MAKE" "${MAKEARGS[@]}" asan | asan_symbolize | tee -a "$TEST_RESULTS"
	else
		"$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"
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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -stdlib=libc++ $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -stdlib=libstdc++ $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -stdlib=libc++ $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -stdlib=libstdc++ $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch i386 -arch x86_64 -std=c++03 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch i386 -arch x86_64 -std=c++11 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch ppc -arch ppc64 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -g2 -O2 $ADD_CXXFLAGS"
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
# Benchmarks, c++03
if [ "$HAVE_CXX03" -ne "0" ]; then
	echo
	echo "************************************" | tee -a "$TEST_RESULTS"
	echo "Testing: Benchmarks, c++03" | tee -a "$TEST_RESULTS"
	echo

	unset CXXFLAGS
	"$MAKE" clean > /dev/null 2>&1
	export CXXFLAGS="-DNDEBUG -O3 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe b 1 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
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

	export CXXFLAGS="-DNDEBUG -O3 -std=c++11 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe b 1 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -DPREFER_BERKELEY_STYLE_SOCKETS -DNO_WINDOWS_STYLE_SOCKETS $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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
	
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DPREFER_WINDOWS_STYLE_SOCKETS -DNO_BERKELEY_STYLE_SOCKETS $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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
	
	export CXXFLAGS="-DNDEBUG -std=c++03 -g3 -O1 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

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

	export CXXFLAGS="-DNDEBUG -std=c++11 -g3 -O1 $ADD_CXXFLAGS"
	"$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		valgrind --track-origins=yes ./cryptest.exe v 2>&1 | tee -a "$TEST_RESULTS"
		valgrind --track-origins=yes ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
	fi
fi

############################################
# Build with elevated warnings
if [ "$HAVE_CXX03" -ne "0" ]; then

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
		export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines"
	else
		export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security"
	fi

	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
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
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines"
	else
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security"
	fi

	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [ "$?" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# Build with elevated warnings
if [ "$HAVE_CXX11" -ne "0" ]; then

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
		export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines"
	else
		export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security"
	fi

	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
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
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines"
	else
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security"
	fi

	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [ "$?" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# If using GCC (likely Linux), then perform a quick check with Clang.
# This check was added after testing on Ubuntu 14.04 with Clang 3.4.
if [ "$CXX" == "g++" ]; then

	CLANG_COMPILER=$(which clang++ 2>/dev/null)
	"$CLANG_COMPILER" -x c++ -DCRYPTOPP_ADHOC_MAIN adhoc.cpp.proto -o $TMP/adhoc > /dev/null 2>&1
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

	export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_DATA_DIR='\"$INSTALL_DIR/share/cryptopp/\"'"
	"$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$INSTALL_RESULTS"
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

COUNT=$(grep -a 'Testing:' "$TEST_RESULTS" | wc -l)
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
ECOUNT=$(egrep -a '(Error|ERROR|error|FAILED|Illegal)' $TEST_RESULTS | egrep -v '( 0 errors|suppressed errors|error detector)' | wc -l)
if [ "$ECOUNT" -eq "0" ]; then
	echo "No failures detected" | tee -a "$TEST_RESULTS"
else
	echo "$ECOUNT errors detected. See $TEST_RESULTS for details" | tee -a "$TEST_RESULTS"
	echo
	egrep -an '(Error|ERROR|error|FAILED|Illegal)' "$TEST_RESULTS" | egrep -v '( 0 errors|suppressed errors|error detector)'
fi
echo | tee -a "$TEST_RESULTS"

# Write warnings to $TEST_RESULTS
WCOUNT=$(egrep -a '(warning:)' $WARN_RESULTS | grep -v 'deprecated-declarations' | wc -l)
if [ "$WCOUNT" -eq "0" ]; then
	echo "No warnings detected" | tee -a "$TEST_RESULTS"
else
	echo "$WCOUNT warnings detected. See $WARN_RESULTS for details" | tee -a "$TEST_RESULTS"
	echo
#	egrep -an '(warning:)' $WARN_RESULTS | grep -v 'deprecated-declarations'
fi
echo | tee -a "$TEST_RESULTS"

echo "************************************************" | tee -a "$TEST_RESULTS"
echo "************************************************" | tee -a "$TEST_RESULTS"

# http://tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
if [ "$ECOUNT" -eq "0" ]; then
	exit 0
else
	exit 1
fi
