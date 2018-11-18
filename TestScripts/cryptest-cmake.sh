#!/usr/bin/env bash

PWD_DIR=$(pwd)
function cleanup {
    cd "$PWD_DIR"
}
trap cleanup EXIT

# Fixup ancient Bash
# https://unix.stackexchange.com/q/468579/56041
if [[ -z "$BASH_SOURCE" ]]; then
	BASH_SOURCE="$0"
fi

# Fixup for Solaris and BSDs
if [[ ! -z $(command -v gmake) ]]; then
	MAKE=gmake
else
	MAKE=make
fi

# Fixup for AIX
if [[ -z "$CMAKE" ]]; then
	CMAKE=cmake
fi

# Feth the three required files
if ! wget --no-check-certificate https://raw.githubusercontent.com/noloader/cryptopp-cmake/master/CMakeLists.txt -O CMakeLists.txt; then
	echo "CMakeLists.txt download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! wget --no-check-certificate https://github.com/noloader/cryptopp-cmake/blob/master/cryptopp-config.cmake -O cryptopp-config.cmake; then
	echo "cryptopp-config.cmake download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

rm -rf "$PWD_DIR/cmake_build"
mkdir -p "$PWD_DIR/cmake_build"
cd "$PWD_DIR/cmake_build"

if [[ ! -z "$CXX" ]];
then
	if ! CXX="$CXX" "$CMAKE" -DCMAKE_CXX_COMPILER="$CXX" ../; then
		echo "cmake failed"
		[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
	fi
else
	if ! "$CMAKE" ../; then
		echo "cmake failed"
		[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
	fi
fi

"$MAKE" clean 2>/dev/null

if ! "$MAKE" -j2 -f Makefile VERBOSE=1; then
	echo "make failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./cryptest.exe v; then
	echo "cryptest.exe v failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./cryptest.exe tv all; then
	echo "cryptest.exe v failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Return success
[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0
