#!/usr/bin/env bash

if ! command -v gcov > /dev/null; then
    echo "Please install gcov"
    exit 1
fi

if ! command -v lcov > /dev/null; then
    echo "Please install lcov"
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

DEBUG_CXXFLAGS="-DDEBUG -DCRYPTOPP_COVERAGE=1 -g3 -O1 -coverage"
NOASM_CXXFLAGS="-DNDEBUG -DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_COVERAGE=1 -g3 -O1 -coverage"
RELEASE_CXXFLAGS="-DNDEBUG -DCRYPTOPP_COVERAGE=1 -g3 -O1 -coverage"

# Clean old artifacts
rm -rf TestCoverage/ >/dev/null
make distclean >/dev/null

echo "**************************************************"
echo "*****             Baseline build             *****"
echo "**************************************************"

# The man page says to run a baseline, but the cryptest_base recipe
# breaks things. Zeroing the counters seems to be the best we can do.
if lcov --base-directory . --directory . --zerocounters;
then
	echo
	echo "Baseline zero counters ok"
	echo
else
	echo
	echo "Baseline zero counters failed"
	echo
fi

#make clean > /dev/null
#if ! make -j "${MAKE_JOBS}";
#then
#    echo "Baseline build failed"
#    exit 1
#fi

# Run test programs
#./cryptest.exe v
#./cryptest.exe tv all

# Create a baseline
#lcov --base-directory . --directory . -i -c -o cryptest_base.info

echo "**************************************************"
echo "*****               Debug build              *****"
echo "**************************************************"

make clean > /dev/null
if ! CXXFLAGS="${DEBUG_CXXFLAGS}" make -j "${MAKE_JOBS}";
then
    echo "Debug build failed"
    exit 1
fi

# Run test programs
./cryptest.exe v
./cryptest.exe tv all

# Gather data
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

# Run test programs
./cryptest.exe v
./cryptest.exe tv all

# Gather data
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

# Run test programs
./cryptest.exe v
./cryptest.exe tv all
./cryptest.exe b 0.5

# Gather data
lcov --base-directory . --directory . -c -o cryptest_release.info

echo "**************************************************"
echo "*****             HTML processing            *****"
echo "**************************************************"

if [ ! -e cryptest_debug.info ]; then
    echo "WARN: cryptest_debug.info does not exist"
fi
if [ ! -e cryptest_noasm.info ]; then
    echo "WARN: cryptest_noasm.info does not exist"
fi
if [ ! -e cryptest_release.info ]; then
    echo "WARN: cryptest_release.info does not exist"
fi

# The man page says to run a baseline, but the cryptest_base recipe
# breaks things. Zeroing the counters seems to be the best we can do.
# --add-tracefile cryptest_base.info

lcov --add-tracefile cryptest_debug.info \
    --add-tracefile cryptest_noasm.info \
    --add-tracefile cryptest_release.info \
    --output-file cryptest_all.info

lcov --remove cryptest_all.info \
    '/usr/*' '*/adhoc*.*' '*/dlltest*.*' '*/fipstest*.*' '*/fips140*.*' '*/test*.*' \
    --output-file cryptest.info

genhtml -o TestCoverage/ -t "Crypto++ test coverage" --num-spaces 4 cryptest.info

exit 0
