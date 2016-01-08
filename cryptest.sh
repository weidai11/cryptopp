#!/bin/bash

# cryptest.sh - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
#               Copyright assigned to Crypto++ project.

# This is a test script that can be used on some Linux/Unix/Apple machines
# to automate building the library and running the self test with various
# combinations of flags, options, and conditions.

# Everything is tee'd into cryptest-result.txt. Change it to suite your taste. You
# should be able to use `egrep -a "(Error|error|FAILED|Illegal)" cryptest-result.txt`
# to quickly find errors and failures.

# Set to suite your taste
TEST_RESULTS=cryptest-result.txt
BENCHMARK_RESULTS=cryptest-bench.txt
WARN_RESULTS=cryptest-warn.txt
INSTALL_RESULTS=cryptest-install.txt

# Respect user's preferred flags, but filter the stuff we expliclty test
#if [ ! -z "CXXFLAGS" ]; then
#	ADD_CXXFLAGS=$(echo "$CXXFLAGS" | sed 's/\(-DDEBUG\|-DNDEBUG\|-O[0-9]\|-Os\|-Og\|-fsanitize=address\|-fsanitize=undefined\|-DDCRYPTOPP_NO_UNALIGNED_DATA_ACCESS\|-DDCRYPTOPP_NO_UNALIGNED_DATA_ACCESS\|-DDCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562\)//g')
#else\
#	ADD_CXXFLAGS=""
#fi

# Avoid CRYPTOPP_DATA_DIR
OLD_CRYPTOPP_DATA_DIR="$CRYPTOPP_DATA_DIR"
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
IS_X86=$(uname -m | egrep -i -c "(i386|i586|i686|amd64|x86_64)")
IS_X64=$(uname -m | egrep -i -c "(amd64|x86_64)")
IS_PPC=$(uname -m | egrep -i -c "(Power|PPC)")

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
if [ "$IS_OPENBSD" -ne "0" ]; then
	MAKE=gmake
else
	MAKE=make
fi

if [ -z "$TMP" ]; then
	TMP=/tmp
fi

$CXX -x c++ -Wno-deprecated-declarations adhoc.cpp.proto -c -o $TMP/adhoc > /dev/null 2>&1
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
$CXX -x c++ -fsanitize=undefined adhoc.cpp.proto -c -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ] && [ "$IS_X86" -ne "0" ]; then
	HAVE_UBSAN=1
else
	HAVE_UBSAN=0
fi

# Set to 0 if you don't have Asan
$CXX -x c++ -fsanitize=undefined adhoc.cpp.proto -c -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ] && [ "$IS_X86" -ne "0" ]; then
	HAVE_ASAN=1
else
	HAVE_ASAN=0
fi

# Fixup...
if [ "$IS_CYGWIN" -ne "0" ] || [ "$IS_MINGW" -ne "0" ]; then
	HAVE_UBAN=0
	HAVE_ASAN=0
fi

# Final fixups for compilers like GCC on ARM64
if [ "$HAVE_UBSAN" -eq "0" ] || [ "$HAVE_ASAN" -eq "0" ]; then
	HAVE_UBAN=0
	HAVE_ASAN=0
fi

# Set to 0 if you don't have Intel multiarch
HAVE_INTEL_MULTIARCH=0
if [ "$IS_DARWIN" -ne "0" ] && [ "$IS_X86" -ne "0" ]; then
$CXX -x c++ -arch i386 -arch x86_64 -c adhoc.cpp.proto -c -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_INTEL_MULTIARCH=1
fi
fi

# Set to 0 if you don't have PPC multiarch
HAVE_PPC_MULTIARCH=0
if [ "$IS_DARWIN" -ne "0" ] && [ "$IS_PPC" -ne "0" ]; then
$CXX -x c++ -arch ppc -arch ppc64 -c adhoc.cpp.proto -c -o $TMP/adhoc > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
	HAVE_PPC_MULTIARCH=1
fi
fi

# Set to 0 if you don't have Valgrind. Valgrind tests take a long time...
HAVE_VALGRIND=$(which valgrind 2>&1 | grep -v "no valgrind" | grep -i -c valgrind)

# Echo back to ensure something is not missed.
echo
echo "HAVE_CXX03: $HAVE_CXX03"
echo "HAVE_CXX11: $HAVE_CXX11"
echo "HAVE_ASAN: $HAVE_ASAN"
echo "HAVE_UBSAN: $HAVE_UBSAN"

if [ "$HAVE_VALGRIND" -ne "0" ]; then
	echo "HAVE_VALGRIND: $HAVE_VALGRIND"
fi
if [ "$IS_DARWIN" -ne "0" ]; then
	echo "IS_DARWIN: $IS_DARWIN"
	unset MallocScribble MallocPreScribble MallocGuardEdges
fi
if [ "$HAVE_INTEL_MULTIARCH" -ne "0" ]; then
	echo "HAVE_INTEL_MULTIARCH: $HAVE_INTEL_MULTIARCH"
fi
if [ "$HAVE_PPC_MULTIARCH" -ne "0" ]; then
	echo "HAVE_PPC_MULTIARCH: $HAVE_PPC_MULTIARCH"
fi
if [ "$IS_LINUX" -ne "0" ]; then
	echo "IS_LINUX: $IS_LINUX"
fi
if [ "$IS_CYGWIN" -ne "0" ]; then
	echo "IS_CYGWIN: $IS_CYGWIN"
fi
if [ "$IS_MINGW" -ne "0" ]; then
	echo "IS_MINGW: $IS_MINGW"
fi

echo "User CXXFLAGS: $CXXFLAGS"
echo "Retained CXXFLAGS: $ADD_CXXFLAGS"
echo "Compiler:" $($CXX --version | head -1)

############################################

# Remove previous test results
rm -f "$TEST_RESULTS" > /dev/null 2>&1
touch "$TEST_RESULTS"

rm -f "$BENCHMARK_RESULTS" > /dev/null 2>&1
touch "$BENCHMARK_RESULTS"

rm -f "$WARN_RESULTS" > /dev/null 2>&1
touch "$WARN_RESULTS"

############################################
############################################

TEST_BEGIN=$(date)
echo
echo "Start time: $TEST_BEGIN"

############################################
# Basic debug build
echo
echo "************************************" | tee -a "$TEST_RESULTS"
echo "Testing: debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
echo

unset CXXFLAGS
"$MAKE" clean > /dev/null 2>&1
export CXXFLAGS="-DDEBUG -g2 -O2"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O2"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DDEBUG -g2 -O2 -DCRYPTOPP_DISABLE_ASM"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_DISABLE_ASM"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"

	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"

	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DDEBUG -g2 -O2 -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DDEBUG -g2 -O1 -DCRYPTOPP_INIT_PRIORITY=250 $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_INIT_PRIORITY=250 $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DDEBUG -g2 -O1 -DNO_OS_DEPENDENCE $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O2 -DNO_OS_DEPENDENCE $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DDEBUG -g2 -O3 $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O3 $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DDEBUG -g2 -Os $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -Os $ADD_CXXFLAGS"

"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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

"$MAKE" lean 2>&1 | tee -a "$TEST_RESULTS"
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
export CXXFLAGS="-DNDEBUG -g2 -O2 $ADD_CXXFLAGS"

"$MAKE" lean 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DDEBUG -g2 -O1 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" ubsan | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" ubsan | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DDEBUG -g2 -O1 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" asan | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" asan | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"

	"$MAKE" ubsan | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"

	"$MAKE" asan | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -stdlib=libc++ $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -stdlib=libstdc++ $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -stdlib=libc++ $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -stdlib=libstdc++ $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch i386 -arch x86_64 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch i386 -arch x86_64 -std=c++11 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -arch ppc -arch ppc64 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXX="$XCODE_COMPILER"
	export CXXFLAGS="-DNDEBUG -g2 -O2 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe b 1 2.4+1e9 2>&1 | tee -a "$BENCHMARK_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -O3 -std=c++11 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
	else
		./cryptest.exe b 1 2.4+1e9 2>&1 | tee -a "$BENCHMARK_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DPREFER_BERKELEY_STYLE_SOCKETS -DNO_WINDOWS_STYLE_SOCKETS $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -g2 -O2 -DPREFER_WINDOWS_STYLE_SOCKETS -DNO_BERKELEY_STYLE_SOCKETS $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -std=c++03 -g3 -O1 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	export CXXFLAGS="-DNDEBUG -std=c++11 -g3 -O1 $ADD_CXXFLAGS"

	"$MAKE" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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

	if [ "$CXX" == "g++" ]; then
		export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines"
	else
		export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security"
	fi

	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
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

	if [ "$CXX" == "g++" ]; then
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines"
	else
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++03 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security"
	fi

	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
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

	if [ "$CXX" == "g++" ]; then
		export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines"
	else
		export CXXFLAGS="-DDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security"
	fi

	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
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

	if [ "$CXX" == "g++" ]; then
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-aliasing=3 -Wstrict-overflow -Waggressive-loop-optimizations -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security -Wtrampolines"
	else
		export CXXFLAGS="-DNDEBUG -g2 -O2 -std=c++11 -DCRYPTOPP_NO_BACKWARDS_COMPATIBILITY_562 -Wall -Wextra -Wno-unknown-pragmas -Wstrict-overflow -Wcast-align -Wwrite-strings -Wformat=2 -Wformat-security"
	fi

	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
	if [ "$?" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
	fi
fi

############################################
# If using GCC (likely Linux), then perform a quick check with Clang.
# This check was added after testing on Ubuntu 14.04 with Clang 3.4.
if [ "$CXX" == "g++" ]; then

	CLANG_COMPILER=$(which clang++)
	"$CLANG_COMPILER" -x c++ -c adhoc.cpp.proto -c -o $TMP/adhoc > /dev/null 2>&1
	if [ "$?" -eq "0" ]; then

		############################################
		# Basic Clang build
		echo
		echo "************************************" | tee -a "$TEST_RESULTS"
		echo "Testing: Clang" | tee -a "$TEST_RESULTS"
		echo

		unset CXXFLAGS
		"$MAKE" clean > /dev/null 2>&1

		"$MAKE" CXX="$CLANG_COMPILER" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
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
	
	INSTALL_DIR="/tmp/cryptopp_test"
	rm -rf "$INSTALL_DIR" > /dev/null 2>&1

	export CXXFLAGS="-DNDEBUG -g2 -O2 -DCRYPTOPP_DATA_DIR='\"$INSTALL_DIR/share/cryptopp/\"'"
	"$MAKE" static dynamic cryptest.exe 2>&1 | tee -a "$INSTALL_RESULTS"
	if [ "${PIPESTATUS[0]}" -ne "0" ]; then
		echo "ERROR: failed to make cryptest.exe" | tee -a "$INSTALL_RESULTS"
	else
		# Still need to manulally place TestData and TestVectors
		OLD_DIR=$(pwd)
		"$MAKE" install PREFIX="$INSTALL_DIR" 2>&1 | tee -a "$INSTALL_RESULTS"
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

		cd "$OLD_DIR"
	fi
fi

############################################
############################################

TEST_END=$(date)

echo "************************************************" | tee -a "$TEST_RESULTS"
echo "************************************************" | tee -a "$TEST_RESULTS"
echo | tee -a "$TEST_RESULTS"

echo "Testing started: $TEST_BEGIN" | tee -a "$TEST_RESULTS"
echo "Testing finished: $TEST_END" | tee -a "$TEST_RESULTS"
echo | tee -a "$TEST_RESULTS"

COUNT=$(grep -a "Testing: " cryptest-result.txt | wc -l)
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
ECOUNT=$(egrep -a '(Error|ERROR|error|FAILED|Illegal)' cryptest-result.txt | egrep -v '( 0 errors|suppressed errors|memory error detector)' | wc -l)
if [ "$ECOUNT" -eq "0" ]; then
	echo "No failures detected" | tee -a "$TEST_RESULTS"
else
	echo "$ECOUNT errors detected" | tee -a "$TEST_RESULTS"
	echo
	egrep -an '(Error|ERROR|error|FAILED|Illegal)' cryptest-result.txt | egrep -v '( 0 errors|suppressed errors|memory error detector)'
fi
echo | tee -a "$TEST_RESULTS"

# Write warnings to $TEST_RESULTS
WCOUNT=$(egrep -a '(warning:)' cryptest-warn.txt | grep -v 'deprecated-declarations' | wc -l)
if [ "$WCOUNT" -eq "0" ]; then
	echo "No warnings detected" | tee -a "$TEST_RESULTS"
else
	echo "$WCOUNT warnings detected" | tee -a "$TEST_RESULTS"
	echo
	egrep -an '(warning:)' cryptest-warn.txt | grep -v 'deprecated-declarations'
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

# Restore
CRYPTOPP_DATA_DIR="$OLD_CRYPTOPP_DATA_DIR"
