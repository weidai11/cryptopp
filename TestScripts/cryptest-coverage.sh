#!/usr/bin/env bash

if ! command -v lcov > /dev/null; then
	echo "Please install gconv or lcov"
	exit 1
fi

# Default make jobs
MAKE_JOBS=${MAKE_JOBS:-4}

# Default temp directory
if [ -z "${TMPDIR}" ];
then
	if [ -d "${HOME}/tmp" ]; then
		TMPDIR="${HOME}/tmp"
	else
		TMPDIR="/tmp"
	fi
fi

DEBUG_CXXFLAGS="-DDEBUG -DCRYPTOPP_COVERAGE -g3 -O1 -coverage"
NOASM_CXXFLAGS="-DNDEBUG -DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_COVERAGE -g3 -O1 -coverage"
RELEASE_CXXFLAGS="-DNDEBUG -DCRYPTOPP_COVERAGE -g3 -O1 -coverage"

# Clean old artifacts
rm -rf TestCoverage/ >/dev/null
make distclean >/dev/null

lcov --base-directory . --directory . --zerocounters -q

echo "**************************************************"
echo "*****               Debug build              *****"
echo "**************************************************"

make clean > /dev/null
if ! CXXFLAGS="${DEBUG_CXXFLAGS}" make -j "${MAKE_JOBS}";
then
	echo "Debug build failed"
	exit 1
fi

./cryptest.exe v
./cryptest.exe tv all

lcov --base-directory . --directory . -c -o cryptest_debug.info

echo "**************************************************"
echo "*****              No ASM build              *****"
echo "**************************************************"

make clean > /dev/null
if ! CXXFLAGS="${NOASM_CXXFLAGS}" make -j "${MAKE_JOBS}";
then
	echo "No ASM build failed"
	exit 1
fi

./cryptest.exe v
./cryptest.exe tv all

lcov --base-directory . --directory . -c -o cryptest_noasm.info

echo "**************************************************"
echo "*****              Release build             *****"
echo "**************************************************"

make clean > /dev/null
if ! CXXFLAGS="${RELEASE_CXXFLAGS}" make -j "${MAKE_JOBS}";
then
	echo "Release build failed"
	exit 1
fi

./cryptest.exe v
./cryptest.exe tv all
./cryptest.exe b 0.5

lcov --base-directory . --directory . -c -o cryptest_release.info

echo "**************************************************"
echo "*****             HTML processing            *****"
echo "**************************************************"

lcov --add-tracefile cryptest_debug.info --add-tracefile cryptest_noasm.info --add-tracefile cryptest_release.info -o cryptest.info

lcov --remove cryptest.info "*/adhoc.*" -o cryptest.info
lcov --remove cryptest.info "*/fips140.*" -o cryptest.info
lcov --remove cryptest.info "*/*test.*" -o cryptest.info
lcov --remove cryptest.info "/usr/*" -o cryptest.info

genhtml -o TestCoverage/ -t "Crypto++ test coverage" --num-spaces 4 cryptest.info

exit 0
