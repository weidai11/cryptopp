#!/usr/bin/env bash

PWD_DIR=$(pwd)
function cleanup {
    cd "$PWD_DIR"
}
trap cleanup EXIT

# Feth the three required files
if ! wget --no-check-certificate https://raw.githubusercontent.com/noloader/cryptopp-cmake/master/CMakeLists.txt -O CMakeLists.txt; then
	echo "CMakeLists.txt download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! wget --no-check-certificate https://github.com/noloader/cryptopp-cmake/blob/master/cryptopp-config.cmake -O cryptopp-config.cmake; then
	echo "cryptopp-config.cmake download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# TODO: Remove this. It is for debugging changes before check-in
# cp ~/cryptopp-cmake/CMakeLists.txt $(pwd)

PWD_DIR=$(pwd)

rm -rf "$PWD_DIR/build"
mkdir -p "$PWD_DIR/build"
cd "$PWD_DIR/build"

if ! cmake ../; then
	echo "cmake failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! make -j2 -f Makefile VERBOSE=1; then
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


