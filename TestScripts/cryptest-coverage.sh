#!/usr/bin/env bash

if ! command -v lcov > /dev/null; then
	echo "Please install gconv or lcov"
	exit 1
fi

# Default make jobs
MAKE_JOBS=${MAKE_JOBS:-4}

DEBUG_CXXFLAGS="-DDEBUG -DCRYPTOPP_COVERAGE -g3 -O1 -coverage"
NOASM_CXXFLAGS="-DNDEBUG -DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_COVERAGE -g3 -O1 -coverage"
RELEASE_CXXFLAGS="-DNDEBUG -DCRYPTOPP_COVERAGE -g3 -O1 -coverage"

# Clean old artifacts
rm -rf TestCoverage/ >/dev/null
make distclean >/dev/null

lcov --base-directory . --directory . --zerocounters -q

make clean > /dev/null
CXXFLAGS="${DEBUG_CXXFLAGS}" make -j "${MAKE_JOBS}"
./cryptest.exe v
./cryptest.exe tv all
lcov --base-directory . --directory . -c -o cryptest.info

make clean > /dev/null
CXXFLAGS="${NOASM_CXXFLAGS}" make -j "${MAKE_JOBS}"
./cryptest.exe v
./cryptest.exe tv all
lcov --base-directory . --directory . -c -o cryptest.info

make clean > /dev/null
CXXFLAGS="${RELEASE_CXXFLAGS}" make -j "${MAKE_JOBS}"
./cryptest.exe v
./cryptest.exe tv all
./cryptest.exe b 0.5 2.0
lcov --base-directory . --directory . -c -o cryptest.info

lcov --remove cryptest.info "adhoc.*" -o cryptest.info
lcov --remove cryptest.info "fips140.*" -o cryptest.info
lcov --remove cryptest.info "*test.*" -o cryptest.info
lcov --remove cryptest.info "/usr/*" -o cryptest.info

genhtml -o TestCoverage/ -t "Crypto++ test coverage" --num-spaces 4 cryptest.info