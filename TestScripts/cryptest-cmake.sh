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

#############################################################################

if [[ -z $(command -v "$CMAKE") ]]; then
	echo "Cannot find $CMAKE. Things may fail."
fi

if [[ -z $(command -v curl) ]]; then
	echo "Cannot find cURL. Things may fail."
fi

#############################################################################

files=(CMakeLists.txt cryptopp-config.cmake)

for file in "${files[@]}"; do
	echo "Downloading $file"
	if ! curl -o "$file" --silent --insecure "https://raw.githubusercontent.com/noloader/cryptopp-cmake/master/$file"; then
		echo "$file download failed"
		exit 1
	fi
done

rm -rf "$PWD_DIR/cmake_build"
mkdir -p "$PWD_DIR/cmake_build"
cd "$PWD_DIR/cmake_build"

#############################################################################

echo ""
echo "Building test artifacts"
echo ""

if [[ ! -z "$CXX" ]];
then
	if ! CXX="$CXX" "$CMAKE" -DCMAKE_CXX_COMPILER="$CXX" ../; then
		echo "cmake failed"
		exit 1
	fi
else
	if ! "$CMAKE" ../; then
		echo "cmake failed"
		exit 1
	fi
fi

"$MAKE" clean &>/dev/null

if ! "$MAKE" -j2 -f Makefile VERBOSE=1; then
	echo "make failed"
	exit 1
fi

if ! ./cryptest.exe v; then
	echo "cryptest.exe v failed"
	exit 1
fi

if ! ./cryptest.exe tv all; then
	echo "cryptest.exe v failed"
	exit 1
fi

# Return success
exit 0
