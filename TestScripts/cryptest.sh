#!/usr/bin/env bash

# cryptest.sh - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.

# This is a test script that can be used on some Linux/Unix/Apple machines to automate building the
# library and running the self test with various combinations of flags, options, and conditions.
# For more details, see http://cryptopp.com/wiki/cryptest.sh.

# To run the script, simply perform the following:
#     ./cryptest.sh

# If you want to test a particular compiler, like clang++ or icpc, issue:
#     CXX=clang++ ./cryptest.sh
#     CXX=/opt/intel/bin/icpc ./cryptest.sh
#     CXX=/opt/solstudio12.2/bin/CC ./cryptest.sh

# The script ignores CXXFLAGS. You can add CXXFLAGS, like -mcpu or -mtune, through USER_CXXFLAGS:
#     USER_CXXFLAGS=-Wall ./cryptest.sh
#     USER_CXXFLAGS="-Wall -Wextra" ./cryptest.sh

# The fastest results (in running time) will most likely omit Valgrind and Benchmarks because
# significantly increase execution time:
#     HAVE_VALGRIND=0 WANT_BENCHMARKS=0 ./cryptest.sh

# Using 'fast' is shorthand for HAVE_VALGRIND=0 WANT_BENCHMARKS=0:
#     ./cryptest.sh fast

# You can reduce CPU load with the following. It will use half the number of CPU cores
# rather than all of them. Its useful at places like the GCC Compile Farm, where being nice is policy.
#     ./cryptest.sh nice

# Keep the noise down
# shellcheck disable=SC2181
# shellcheck disable=SC2016
# shellcheck disable=SC2034

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

if [[ -z "${test_prog}" ]]; then
    test_prog="TestPrograms/test_cxx.cpp"
fi

# Remove previous test results
rm -f "$TEST_RESULTS" &>/dev/null
touch "$TEST_RESULTS"

rm -f "$BENCHMARK_RESULTS" &>/dev/null
touch "$BENCHMARK_RESULTS"

rm -f "$WARN_RESULTS" &>/dev/null
touch "$WARN_RESULTS"

rm -f "$INSTALL_RESULTS" &>/dev/null
touch "$INSTALL_RESULTS"

# Avoid CRYPTOPP_DATA_DIR in this shell (it is tested below)
unset CRYPTOPP_DATA_DIR

# Avoid Malloc and Scribble guards on OS X (they are tested below)
unset MallocScribble MallocPreScribble MallocGuardEdges

# List of tests performed
TEST_LIST=()

# List of failed tests
FAILED_LIST=()

############################################
# Setup tools and platforms

GREP="grep"
SED="sed"
AWK="awk"
MAKE="make"

DISASS="objdump"
DISASSARGS=("--disassemble")

# Fixup, Solaris and friends
if [[ (-d /usr/xpg4/bin) ]]; then
    SED=/usr/xpg4/bin/sed
    AWK=/usr/xpg4/bin/awk
    GREP=/usr/xpg4/bin/grep
elif [[ (-d /usr/bin/posix) ]]; then
    SED=/usr/bin/posix/sed
    AWK=/usr/bin/posix/awk
    GREP=/usr/bin/posix/grep
fi

# Fixup, Solaris and BSDs
if [[ $(command -v gmake 2>/dev/null) ]]; then
    MAKE="gmake"
else
    MAKE="make"
fi

THIS_SYSTEM=$(uname -s 2>&1)
IS_AIX=$("${GREP}" -i -c aix <<< "$THIS_SYSTEM")
IS_DARWIN=$("${GREP}" -i -c darwin <<< "$THIS_SYSTEM")
IS_HURD=$("${GREP}" -i -c gnu <<< "$THIS_SYSTEM")
IS_LINUX=$("${GREP}" -i -c linux <<< "$THIS_SYSTEM")
IS_CYGWIN=$("${GREP}" -i -c cygwin <<< "$THIS_SYSTEM")
IS_MINGW=$("${GREP}" -i -c mingw <<< "$THIS_SYSTEM")
IS_OPENBSD=$("${GREP}" -i -c openbsd <<< "$THIS_SYSTEM")
IS_DRAGONFLY=$("${GREP}" -i -c dragonfly <<< "$THIS_SYSTEM")
IS_FREEBSD=$("${GREP}" -i -c freebsd <<< "$THIS_SYSTEM")
IS_NETBSD=$("${GREP}" -i -c netbsd <<< "$THIS_SYSTEM")
IS_SOLARIS=$("${GREP}" -i -c sunos <<< "$THIS_SYSTEM")
IS_BSD=$("${GREP}" -i -c bsd <<< "$THIS_SYSTEM")

THIS_RELEASE=$(lsb_release -a 2>&1)
IS_DEBIAN=$("${GREP}" -i -c debian <<< "$THIS_RELEASE")
IS_FEDORA=$("${GREP}" -i -c fedora <<< "$THIS_RELEASE")
IS_UBUNTU=$("${GREP}" -i -c ubuntu <<< "$THIS_RELEASE")
IS_SUSE=$("${GREP}" -i -c opensuse <<< "$THIS_RELEASE")

THIS_MACHINE=$(uname -m 2>&1)
IS_X86=$("${GREP}" -i -c -E "(i386|i486|i686|i686)" <<< "$THIS_MACHINE")
IS_X64=$("${GREP}" -i -c -E "(amd64|x86_64)" <<< "$THIS_MACHINE")
IS_PPC32=$("${GREP}" -i -c -E "(Power|PPC)" <<< "$THIS_MACHINE")
IS_PPC64=$("${GREP}" -i -c -E "(Power64|PPC64)" <<< "$THIS_MACHINE")
IS_ARM32=$("${GREP}" -i -c -E "(arm|aarch32)" <<< "$THIS_MACHINE")
IS_ARM64=$("${GREP}" -i -c -E  "(arm64|aarch64)" <<< "$THIS_MACHINE")
IS_S390=$("${GREP}" -i -c "s390" <<< "$THIS_MACHINE")
IS_SPARC=$("${GREP}" -i -c "sparc" <<< "$THIS_MACHINE")
IS_X32=0

# Fixup
if [[ "$IS_AIX" -ne 0 ]]; then
    THIS_MACHINE="$(prtconf | "${GREP}" -i "Processor Type" | head -n 1 | cut -f 2 -d ':')"
    IS_PPC32=$("${GREP}" -i -c -E "(Power|PPC)" <<< "$THIS_MACHINE")
    IS_PPC64=$("${GREP}" -i -c -E "(Power64|PPC64)" <<< "$THIS_MACHINE")
fi

# Fixup
if [[ "$IS_PPC64" -ne 0 ]]; then
    IS_PPC32=0
fi

# Fixup
if [[ "$IS_ARM64" -ne 0 ]]; then
    IS_ARM32=0
fi

# Fixup
if [[ "$IS_SOLARIS" -ne 0 ]]; then
    DISASS=dis
    DISASSARGS=()
fi

# Fixup
if [[ "$IS_DARWIN" -ne 0 ]]; then
    DISASS=otool
    DISASSARGS=("-tV")
fi

# Fixup
if [[ "$IS_AIX" -ne 0 ]]; then
    DISASS=dis
    DISASSARGS=()
fi

# CPU features and flags
if [[ ("$IS_X86" -ne 0 || "$IS_X64" -ne 0) ]]; then
    if [[ ("$IS_DARWIN" -ne 0) ]]; then
        X86_CPU_FLAGS=$(sysctl machdep.cpu.features 2>&1 | cut -f 2 -d ':')
    elif [[ ("$IS_SOLARIS" -ne 0) ]]; then
        X86_CPU_FLAGS=$(isainfo -v 2>/dev/null)
    elif [[ ("$IS_FREEBSD" -ne 0) ]]; then
        X86_CPU_FLAGS=$("${GREP}" Features /var/run/dmesg.boot)
    elif [[ ("$IS_DRAGONFLY" -ne 0) ]]; then
        X86_CPU_FLAGS=$(dmesg | "${GREP}" Features)
    elif [[ ("$IS_HURD" -ne 0) ]]; then
        : # Do nothing... cpuid is not helpful at the moment
    else
        X86_CPU_FLAGS="$(${AWK} '{IGNORECASE=1}{if ($1 == "flags"){print;exit}}' < /proc/cpuinfo 2>/dev/null | cut -f 2 -d ':')"
    fi
elif [[ ("$IS_ARM32" -ne 0 || "$IS_ARM64" -ne 0) ]]; then
    if [[ ("$IS_DARWIN" -ne 0) ]]; then
        ARM_CPU_FLAGS="$(sysctl machdep.cpu.features 2>&1 | cut -f 2 -d ':')"
        # Apple M1 hardware
        if [[ $(sysctl hw.optional.arm64 2>&1 | "${GREP}" -i 'hw.optional.arm64: 1') ]]; then
            ARM_CPU_FLAGS="asimd crc32 aes pmull sha1 sha2"
        fi
        if [[ $(sysctl hw.optional.armv8_2_sha3 2>&1 | "${GREP}" -i 'hw.optional.armv8_2_sha3: 1') ]]; then
            ARM_CPU_FLAGS+=" sha3"
        fi
        if [[ $(sysctl hw.optional.armv8_2_sha512 2>&1 | "${GREP}" -i 'hw.optional.armv8_2_sha512: 1') ]]; then
            ARM_CPU_FLAGS+=" sha512"
        fi
    else
        ARM_CPU_FLAGS="$(${AWK} '{IGNORECASE=1}{if ($1 == "Features"){print;exit}}' < /proc/cpuinfo | cut -f 2 -d ':')"
    fi
elif [[ ("$IS_PPC32" -ne 0 || "$IS_PPC64" -ne 0) ]]; then
    if [[ ("$IS_DARWIN" -ne 0) ]]; then
        PPC_CPU_FLAGS="$(sysctl -a 2>&1 | "${GREP}" machdep.cpu.features | cut -f 2 -d ':')"
        # PowerMac
        if [[ $(sysctl hw.optional.altivec 2>&1 | "${GREP}" -i 'hw.optional.altivec: 1') ]]; then
            PPC_CPU_FLAGS+=" altivec"
        fi
    elif [[ ("$IS_AIX" -ne 0) ]]; then
        CPUINFO="$(prtconf | "${GREP}" -i "Processor Type" | head -n 1 | cut -f 2 -d ':')"
        if echo -n "$CPUINFO" | "${GREP}" -q -i -c "power9"; then
            PPC_CPU_FLAGS="power9 power8 power7 altivec"
        elif echo -n "$CPUINFO" | "${GREP}" -q -i -c "power8"; then
            PPC_CPU_FLAGS="power8 power7 altivec"
        elif echo -n "$CPUINFO" | "${GREP}" -q -i -c "power7"; then
            PPC_CPU_FLAGS="power7 altivec"
        elif echo -n "$CPUINFO" | "${GREP}" -q -i -c "altivec"; then
            PPC_CPU_FLAGS="altivec"
        fi
    else
        CPUINFO="$("${GREP}" "cpu" /proc/cpuinfo | head -n 1 | cut -f 2 -d ':')"
        if echo -n "$CPUINFO" | "${GREP}" -q -i -c "power9"; then
            PPC_CPU_FLAGS="power9 power8 power7 altivec"
        elif echo -n "$CPUINFO" | "${GREP}" -q -i -c "power8"; then
            PPC_CPU_FLAGS="power8 power7 altivec"
        elif echo -n "$CPUINFO" | "${GREP}" -q -i -c "power7"; then
            PPC_CPU_FLAGS="power7 altivec"
        elif echo -n "$CPUINFO" | "${GREP}" -q -i -c "altivec"; then
            PPC_CPU_FLAGS="altivec"
        fi
    fi
fi

for ARG in "$@"
do
    # Recognize "fast" and "quick", which does not perform tests that take more time to execute
    if [[ ($("${GREP}" -ix "fast" <<< "$ARG") || $("${GREP}" -ix "quick" <<< "$ARG")) ]]; then
        HAVE_VALGRIND=0
        WANT_BENCHMARKS=0
    # Recognize "farm" and "nice", which uses 1/2 the CPU cores in accordance with GCC Compile Farm policy
    elif [[ ($("${GREP}" -ix "farm" <<< "$ARG") || $("${GREP}" -ix "nice" <<< "$ARG")) ]]; then
        WANT_NICE=1
    elif [[ ($("${GREP}" -ix "orig" <<< "$ARG") || $("${GREP}" -ix "original" <<< "$ARG") || $("${GREP}" -ix "config.h" <<< "$ARG")) ]]; then
        git checkout config.h &>/dev/null
    else
        echo "Unknown option $ARG"
    fi
done

# We need to use the C++ compiler to determine feature availablility. Otherwise
#   mis-detections occur on a number of platforms.
if [[ ((-z "${CXX}") || ("${CXX}" == "gcc")) ]]; then
    if [[ ("${CXX}" == "gcc") ]]; then
        CXX="g++"
    elif [[ "$IS_DARWIN" -ne 0 ]]; then
        CXX="c++"
    elif [[ "$IS_SOLARIS" -ne 0 ]]; then
        if [[ (-e "/opt/developerstudio12.7/bin/CC") ]]; then
            CXX="/opt/developerstudio12.7/bin/CC"
        elif [[ (-e "/opt/developerstudio12.6/bin/CC") ]]; then
            CXX="/opt/developerstudio12.6/bin/CC"
        elif [[ (-e "/opt/developerstudio12.5/bin/CC") ]]; then
            CXX="/opt/developerstudio12.5/bin/CC"
        elif [[ (-e "/opt/solarisstudio12.4/bin/CC") ]]; then
            CXX="/opt/solarisstudio12.4/bin/CC"
        elif [[ (-e "/opt/solarisstudio12.3/bin/CC") ]]; then
            CXX="/opt/solarisstudio12.3/bin/CC"
        elif [[ (-e "/opt/solstudio12.2/bin/CC") ]]; then
            CXX="/opt/solstudio12.2/bin/CC"
        elif [[ (-e "/opt/solstudio12.1/bin/CC") ]]; then
            CXX="/opt/solstudio12.1/bin/CC"
        elif [[ (-e "/opt/solstudio12.0/bin/CC") ]]; then
            CXX="/opt/solstudio12.0/bin/CC"
        elif [[ $(command -v CC 2>/dev/null) ]]; then
            CXX="CC"
        elif [[ $(command -v g++ 2>/dev/null) ]]; then
            CXX="g++"
        else
            CXX=CC
        fi
    elif [[ $(command -v g++ 2>/dev/null) ]]; then
        CXX="g++"
    else
        CXX="c++"
    fi
fi

SUN_COMPILER=$("${CXX}" -V 2>&1 | "${GREP}" -i -c -E "CC: (Sun|Studio)")
GCC_COMPILER=$("${CXX}" --version 2>&1 | "${GREP}" -i -v "clang" | "${GREP}" -i -c -E "(gcc|g\+\+)")
XLC_COMPILER=$("${CXX}" -qversion 2>&1 | "${GREP}" -i -c "IBM XL")
INTEL_COMPILER=$("${CXX}" --version 2>&1 | "${GREP}" -i -c "\(icc\)")
MACPORTS_COMPILER=$("${CXX}" --version 2>&1 | "${GREP}" -i -c "MacPorts")
CLANG_COMPILER=$("${CXX}" --version 2>&1 | "${GREP}" -i -c "clang")
GNU_LINKER=$(ld --version 2>&1 | "${GREP}" -i -c "GNU ld")

if [[ ("$SUN_COMPILER" -eq 0) ]]; then
    AMD64=$("${CXX}" -dM -E - </dev/null 2>/dev/null | "${GREP}" -i -c -E "(__x64_64__|__amd64__)")
    ILP32=$("${CXX}" -dM -E - </dev/null 2>/dev/null | "${GREP}" -i -c -E "(__ILP32__|__ILP32)")
    if [[ ("$AMD64" -ne 0) && ("$ILP32" -ne 0) ]]; then
        IS_X32=1
    fi
fi

# Now that the compiler is fixed, determine the compiler version for fixups
CXX_VERSION=$("${CXX}" -v 2>&1)
CXX_GCC_VERSION=$("${CXX}" --version 2>&1 | head -n 1 | ${GREP} -i -E '^(gcc|g++)' | ${AWK} '{print $(NF)}')
GCC_4_8=$(echo "${CXX_GCC_VERSION}" | "${GREP}" -i -c -E '^4\.8')
GCC_4_8_OR_ABOVE=$(echo "${CXX_GCC_VERSION}" | "${GREP}" -i -c -E '^(4\.[8-9]|[5-9]\.|[1-9][0-9]\.)')
GCC_10_0_OR_ABOVE=$(echo "${CXX_GCC_VERSION}" | "${GREP}" -i -c -E '^(1[0-9]\.|[2-9][0-9]\.)')
GCC_11_0_OR_ABOVE=$(echo "${CXX_GCC_VERSION}" | "${GREP}" -i -c -E '^(1[1-9]\.|[2-9][0-9]\.)')
GCC_12_0_OR_ABOVE=$(echo "${CXX_GCC_VERSION}" | "${GREP}" -i -c -E '^(1[2-9]\.|[2-9][0-9]\.)')
GCC_12_0_OR_BELOW=$(echo "${CXX_GCC_VERSION}" | "${GREP}" -i -c -E '^([0-9]\.|1[0-2]\.)')

CXX_SUNCC_VERSION=$("${CXX}" -V 2>&1 | head -n 1 | ${GREP} -i -E '^CC: (Sun|Studio)' | ${AWK} '{print $(NF)}')
SUNCC_5_10_OR_ABOVE=$(echo "${CXX_SUNCC_VERSION}" | "${GREP}" -c -E "^(5\.1[0-9]|5\.[2-9]|[6-9]\.)")

# Fixup, bad code generation
if [[ ("$SUNCC_5_10_OR_ABOVE" -ne 0) ]]; then
    HAVE_OFAST=0
fi

# Fixup, Analyzer available in GCC 10.0, but C++ is not planned until GCC 11.
# GCC 12.0 is still missing analyzer support for C++.
if [[ ("$GCC_COMPILER" -ne 0) && ("$GCC_12_0_OR_BELOW" -ne 0) ]]; then
    HAVE_ANALYZER=0
fi

# GCC compile farm is mounted RO
if [[ (-z "${TMPDIR}") ]]; then
    if [[ (-d "/tmp") ]] && [[ $(touch "/tmp/ok-to-delete" &>/dev/null) ]]; then
        TMPDIR=/tmp
        rm -f "/tmp/ok-to-delete"
    elif [[ (-d "/temp") ]] && [[ $(touch "/temp/ok-to-delete" &>/dev/null) ]]; then
        TMPDIR=/temp
        rm -f "/temp/ok-to-delete"
    elif [[ (-d "$HOME/tmp") ]] && [[ $(touch "$HOME/tmp/ok-to-delete" &>/dev/null) ]]; then
        TMPDIR="$HOME/tmp"
        rm -f "$HOME/tmp/ok-to-delete"
    else
        echo "Please set TMPDIR to a valid directory"
        exit 1
    fi
fi

# Make temp if it does not exist
mkdir -p "${TMPDIR}" &>/dev/null

rm -f "${TMPDIR}/test.exe" &>/dev/null

if [[ (-z "$HAVE_CXX23") ]]; then
    HAVE_CXX23=0
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -std=c++23 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_CXX23=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_GNU23") ]]; then
    HAVE_GNU23=0
    "${CXX}" -std=gnu++23 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_GNU23=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_CXX20") ]]; then
    HAVE_CXX20=0
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -std=c++20 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_CXX20=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_GNU20") ]]; then
    HAVE_GNU20=0
    "${CXX}" -std=gnu++20 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_GNU20=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_CXX17") ]]; then
    HAVE_CXX17=0
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -std=c++17 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_CXX17=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_GNU17") ]]; then
    HAVE_GNU17=0
    "${CXX}" -std=gnu++17 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_GNU17=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_CXX14") ]]; then
    HAVE_CXX14=0
    "${CXX}" -std=c++14 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_CXX14=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_GNU14") ]]; then
    HAVE_GNU14=0
    "${CXX}" -std=gnu++14 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_GNU14=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_CXX11") ]]; then
    HAVE_CXX11=0
    "${CXX}" -std=c++11 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_CXX11=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_GNU11") ]]; then
    HAVE_GNU11=0
    "${CXX}" -std=gnu++11 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_GNU11=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_CXX03") ]]; then
    HAVE_CXX03=0
    "${CXX}" -std=c++03 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_CXX03=1
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_GNU03") ]]; then
    HAVE_GNU03=0
    "${CXX}" -std=gnu++03 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_GNU03=1
    fi
fi

# Apple M1's do not do the -stdlib=libstdc++ thing
rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_LIBSTDCXX") ]]; then
    HAVE_LIBSTDCXX=0
    "${CXX}" -stdlib=libstdc++ "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        HAVE_LIBSTDCXX=1
    fi
fi

# Use a fallback strategy so OPT_O0 can be used with DEBUG_CXXFLAGS
OPT_O0=
rm -f "${TMPDIR}/test.exe" &>/dev/null
"${CXX}" -O0 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
if [[ ("$?" -eq 0) ]]; then
    OPT_O0=-O0
else
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -xO0 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        OPT_O0=-xO0
    fi
fi

# Use a fallback strategy so OPT_O1 can be used with VALGRIND_CXXFLAGS
OPT_O1=
rm -f "${TMPDIR}/test.exe" &>/dev/null
"${CXX}" -O1 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
if [[ ("$?" -eq 0) ]]; then
    HAVE_O1=1
    OPT_O1=-O1
else
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -xO1 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        HAVE_O1=1
        OPT_O1=-xO1
    fi
fi

# https://github.com/weidai11/cryptopp/issues/588
OPT_O2=
rm -f "${TMPDIR}/test.exe" &>/dev/null
"${CXX}" -O2 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
if [[ ("$?" -eq 0) ]]; then
    HAVE_O2=1
    OPT_O2=-O2
else
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -xO2 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        HAVE_O2=1
        OPT_O2=-xO2
    fi
fi

# Use a fallback strategy so OPT_O3 can be used with RELEASE_CXXFLAGS
OPT_O3=
rm -f "${TMPDIR}/test.exe" &>/dev/null
"${CXX}" -O3 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
if [[ ("$?" -eq 0) ]]; then
    HAVE_O3=1
    OPT_O3=-O3
else
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -xO3 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        HAVE_O3=1
        OPT_O3=-xO3
    fi
fi

# Hit or miss, mostly hit
if [[ (-z "$HAVE_OS") ]]; then
    HAVE_OS=0
    OPT_OS=
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -Os "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        HAVE_OS=1
        OPT_OS=-Os
    fi
fi

# Hit or miss, mostly hit
if [[ (-z "$HAVE_OZ") ]]; then
    HAVE_OZ=0
    OPT_OZ=
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -Oz "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        HAVE_OZ=1
        OPT_OZ=-Oz
    fi
fi

# Hit or miss, mostly hit
if [[ (-z "$HAVE_OFAST") ]]; then
    HAVE_OFAST=0
    OPT_OFAST=
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -Ofast "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        HAVE_OFAST=1
        OPT_OFAST=-Ofast
    fi
fi

# Use a fallback strategy so OPT_G2 can be used with RELEASE_CXXFLAGS
OPT_G2=
rm -f "${TMPDIR}/test.exe" &>/dev/null
"${CXX}" -g2 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
if [[ ("$?" -eq 0) ]]; then
    OPT_G2=-g2
else
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -g "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        OPT_G2=-g
    fi
fi

# Use a fallback strategy so OPT_G3 can be used with DEBUG_CXXFLAGS
OPT_G3=
rm -f "${TMPDIR}/test.exe" &>/dev/null
"${CXX}" -g3 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
if [[ ("$?" -eq 0) ]]; then
    OPT_G3=-g3
else
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -g "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        OPT_G3=-g
    fi
fi

# Cygwin and noisy compiles
OPT_PIC=
rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_PIC") ]]; then
    HAVE_PIC=0
    PIC_PROBLEMS=$("${CXX}" -fPIC "${test_prog}" -o "${TMPDIR}/test.exe" 2>&1 | "${GREP}" -i -c -E  '(warning|error)')
    if [[ "$PIC_PROBLEMS" -eq 0 ]]; then
        HAVE_PIC=1
        OPT_PIC=-fPIC
        if [[ ("$XLC_COMPILER" -eq 1) ]]; then
            OPT_PIC=-qpic
        fi
    fi
fi

# GCC 4.8; Clang 3.4
rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_UBSAN") ]]; then
    HAVE_UBSAN=0
    "${CXX}" -fsanitize=undefined "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        "${TMPDIR}/test.exe" &>/dev/null
        if [[ ("$?" -eq 0) ]]; then
            HAVE_UBSAN=1
        fi
    fi
fi

# GCC 4.8; Clang 3.4
rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_ASAN") ]]; then
    HAVE_ASAN=0
    "${CXX}" -fsanitize=address "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        "${TMPDIR}/test.exe" &>/dev/null
        if [[ ("$?" -eq 0) ]]; then
            HAVE_ASAN=1
        fi
    fi
fi

# GCC 6.0; maybe Clang
rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_BSAN") ]]; then
    HAVE_BSAN=0
    "${CXX}" -fsanitize=bounds-strict "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        "${TMPDIR}/test.exe" &>/dev/null
        if [[ ("$?" -eq 0) ]]; then
            HAVE_BSAN=1
        fi
    fi
fi

# Analyzer available in GCC 10.0, but C++ is not planned until GCC 11.
# GCC 11 is not working for C++. It is disabled earlier via HAVE_ANALYZER.
# https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10/
# and https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95031#c2.
rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_ANALYZER") ]]; then
    HAVE_ANALYZER=0
    "${CXX}" -fanalyzer "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        "${TMPDIR}/test.exe" &>/dev/null
        if [[ ("$?" -eq 0) ]]; then
            HAVE_ANALYZER=1
        fi
    fi
fi

# GCC 8.0; maybe Clang?
rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_CET") ]]; then
    HAVE_CET=0
    "${CXX}" -fcf-protection=full -mcet "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        "${TMPDIR}/test.exe" &>/dev/null
        if [[ ("$?" -eq 0) ]]; then
            HAVE_CET=1
        fi
    fi
fi

# Meltdown and Specter. This is the Reptoline fix
rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_REPTOLINE") ]]; then
    HAVE_REPTOLINE=0
    "${CXX}" -mfunction-return=thunk -mindirect-branch=thunk "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        "${TMPDIR}/test.exe" &>/dev/null
        if [[ ("$?" -eq 0) ]]; then
            HAVE_REPTOLINE=1
        fi
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_OMP") ]]; then
    HAVE_OMP=0
    if [[ "$GCC_COMPILER" -ne 0 ]]; then
        "${CXX}" -fopenmp -O3 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            HAVE_OMP=1
            OMP_FLAGS=("-fopenmp" "-O3")
        fi
    elif [[ "$INTEL_COMPILER" -ne 0 ]]; then
        "${CXX}" -openmp -O3 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            HAVE_OMP=1
            OMP_FLAGS=("-openmp" "-O3")
        fi
    elif [[ "$CLANG_COMPILER" -ne 0 ]]; then
        "${CXX}" -fopenmp=libomp -O3 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            HAVE_OMP=1
            OMP_FLAGS=("-fopenmp=libomp" "-O3")
        fi
    elif [[ "$SUN_COMPILER" -ne 0 ]]; then
        "${CXX}" -xopenmp=parallel -xO3 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            HAVE_OMP=1
            OMP_FLAGS=("-xopenmp=parallel" "-xO3")
        fi
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_INTEL_MULTIARCH") ]]; then
    HAVE_INTEL_MULTIARCH=0
    if [[ ("$IS_DARWIN" -ne 0) && ("$IS_X86" -ne 0 || "$IS_X64" -ne 0) ]]; then
        "${CXX}" -arch i386 -arch x86_64 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            HAVE_INTEL_MULTIARCH=1
        fi
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_PPC_MULTIARCH") ]]; then
    HAVE_PPC_MULTIARCH=0
    if [[ ("$IS_DARWIN" -ne 0) && ("$IS_PPC32" -ne 0 || "$IS_PPC64" -ne 0) ]]; then
        "${CXX}" -arch ppc -arch ppc64 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            HAVE_PPC_MULTIARCH=1
        fi
    fi
fi

rm -f "${TMPDIR}/test.exe" &>/dev/null
if [[ (-z "$HAVE_X32") ]]; then
    HAVE_X32=0
    if [[ "$IS_X32" -ne 0 ]]; then
        "${CXX}" -mx32 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            HAVE_X32=1
        fi
    fi
fi

# Hit or miss, mostly hit
if [[ (-z "$HAVE_NATIVE_ARCH") ]]; then
    HAVE_NATIVE_ARCH=0
    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -march=native "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ ("$?" -eq 0) ]]; then
        HAVE_NATIVE_ARCH=1
    fi
fi

# ld-gold linker testing
if [[ (-z "$HAVE_LDGOLD") ]]; then
    HAVE_LDGOLD=0
    LD_GOLD=$(command -v ld.gold 2>/dev/null)
    ELF_FILE=$(command -v file 2>/dev/null)
    if [[ (-n "$LD_GOLD") && (-n "$ELF_FILE") ]]; then
        LD_GOLD=$(file "$LD_GOLD" | cut -d":" -f 2 | "${GREP}" -i -c "elf")
        if [[ ("$LD_GOLD" -ne 0) ]]; then
            "${CXX}" -fuse-ld=gold "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
            if [[ "$?" -eq 0 ]]; then
                HAVE_LDGOLD=1
            fi
        fi
    fi
fi

# ARMv7 and ARMv8, including NEON, CRC32 and Crypto extensions
if [[ ("$IS_ARM32" -ne 0 || "$IS_ARM64" -ne 0) ]]; then

    if [[ (-z "$HAVE_ARMV7A" && "$IS_ARM32" -ne 0) ]]; then
        HAVE_ARMV7A=$("${GREP}" -i -c 'neon' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARMV7A" -gt 0) ]]; then HAVE_ARMV7A=1; fi
    fi

    if [[ (-z "$HAVE_ARMV8" && ("$IS_ARM32" -ne 0 || "$IS_ARM64" -ne 0)) ]]; then
        HAVE_ARMV8=$("${GREP}" -i -c -E '(asimd|crc|crypto)' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARMV8" -gt 0) ]]; then HAVE_ARMV8=1; fi
    fi

    if [[ (-z "$HAVE_ARM_VFPV3") ]]; then
        HAVE_ARM_VFPV3=$("${GREP}" -i -c 'vfpv3' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_VFPV3" -gt 0) ]]; then HAVE_ARM_VFPV3=1; fi
    fi

    if [[ (-z "$HAVE_ARM_VFPV4") ]]; then
        HAVE_ARM_VFPV4=$("${GREP}" -i -c 'vfpv4' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_VFPV4" -gt 0) ]]; then HAVE_ARM_VFPV4=1; fi
    fi

    if [[ (-z "$HAVE_ARM_VFPV5") ]]; then
        HAVE_ARM_VFPV5=$("${GREP}" -i -c 'fpv5' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_VFPV5" -gt 0) ]]; then HAVE_ARM_VFPV5=1; fi
    fi

    if [[ (-z "$HAVE_ARM_VFPD32") ]]; then
        HAVE_ARM_VFPD32=$("${GREP}" -i -c 'vfpd32' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_VFPD32" -gt 0) ]]; then HAVE_ARM_VFPD32=1; fi
    fi

    if [[ (-z "$HAVE_ARM_NEON") ]]; then
        HAVE_ARM_NEON=$("${GREP}" -i -c 'neon' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_NEON" -gt 0) ]]; then HAVE_ARM_NEON=1; fi
    fi

    if [[ (-z "$HAVE_ARM_CRC") ]]; then
        HAVE_ARM_CRC=$("${GREP}" -i -c 'crc32' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_CRC" -gt 0) ]]; then HAVE_ARM_CRC=1; fi
    fi

    if [[ (-z "$HAVE_ARM_CRYPTO") ]]; then
        HAVE_ARM_CRYPTO=$("${GREP}" -i -c -E '(aes|pmull|sha1|sha2)' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_CRYPTO" -gt 0) ]]; then HAVE_ARM_CRYPTO=1; fi
    fi

    if [[ (-z "$HAVE_ARM_SHA3") ]]; then
        HAVE_ARM_SHA3=$("${GREP}" -i -c 'sha3' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_SHA3" -gt 0) ]]; then HAVE_ARM_SHA3=1; fi
    fi

    if [[ (-z "$HAVE_ARM_SHA512") ]]; then
        HAVE_ARM_SHA512=$("${GREP}" -i -c 'sha512' <<< "$ARM_CPU_FLAGS")
        if [[ ("$HAVE_ARM_SHA512" -gt 0) ]]; then HAVE_ARM_SHA512=1; fi
    fi
fi

if [[ ("$IS_PPC32" -ne 0 || "$IS_PPC64" -ne 0) ]]; then
    if [[ (-z "$HAVE_PPC_ALTIVEC") ]]; then
        HAVE_PPC_ALTIVEC=$("${GREP}" -i -c 'altivec' <<< "$PPC_CPU_FLAGS")
        if [[ ("$HAVE_PPC_ALTIVEC" -gt 0) ]]; then HAVE_PPC_ALTIVEC=1; fi
    fi
    if [[ (-z "$HAVE_PPC_POWER7") ]]; then
        HAVE_PPC_POWER7=$("${GREP}" -i -c -E 'pwr7|power7' <<< "$PPC_CPU_FLAGS")
        if [[ ("$HAVE_PPC_POWER7" -gt 0) ]]; then HAVE_PPC_POWER7=1; fi
    fi
    if [[ (-z "$HAVE_PPC_POWER8") ]]; then
        HAVE_PPC_POWER8=$("${GREP}" -i -c -E 'pwr8|power8' <<< "$PPC_CPU_FLAGS")
        if [[ ("$HAVE_PPC_POWER8" -gt 0) ]]; then HAVE_PPC_POWER8=1; fi
    fi
    if [[ (-z "$HAVE_PPC_POWER9") ]]; then
        HAVE_PPC_POWER9=$("${GREP}" -i -c -E 'pwr9|power9' <<< "$PPC_CPU_FLAGS")
        if [[ ("$HAVE_PPC_POWER9" -gt 0) ]]; then HAVE_PPC_POWER9=1; fi
    fi
fi

# Valgrind testing of C++03, C++11, C++14 and C++17 binaries. Valgrind tests take a long time...
if [[ (-z "$HAVE_VALGRIND") ]]; then
    if [[ $(command -v valgrind 2>/dev/null) ]]; then
        HAVE_VALGRIND=1
    fi
fi

# Try to find a symbolizer for Asan
if [[ (-z "$HAVE_SYMBOLIZE") && (-n "$ASAN_SYMBOLIZER_PATH") ]]; then
    # Sets default value
    if [[ $(command -v asan_symbolize 2>/dev/null) ]]; then
        HAVE_SYMBOLIZE=1
    fi
    if [[ (("$HAVE_SYMBOLIZE" -ne 0) && (-z "$ASAN_SYMBOLIZE")) ]]; then
        ASAN_SYMBOLIZE=asan_symbolize
    fi

    # Clang implicitly uses ASAN_SYMBOLIZER_PATH; set it if its not set.
    if [[ (-z "$ASAN_SYMBOLIZER_PATH") ]]; then
        if [[ $(command -v llvm-symbolizer 2>/dev/null) ]]; then
            LLVM_SYMBOLIZER_FOUND=1;
        fi
        if [[ ("$LLVM_SYMBOLIZER_FOUND" -ne 0) ]]; then
            ASAN_SYMBOLIZER_PATH=$(command -v llvm-symbolizer)
            export ASAN_SYMBOLIZER_PATH
        fi
    fi
fi

# Used to disassemble object modules so we can verify some aspects of code generation
if [[ (-z "$HAVE_DISASS") ]]; then
    echo "int main(int argc, char* argv[]) {return 0;}" > "${TMPDIR}/test.cc"
    "${CXX}" "${TMPDIR}/test.cc" -o "${TMPDIR}/testest.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        "$DISASS" "${DISASSARGS[@]}" "${TMPDIR}/testest.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            HAVE_DISASS=1
        else
            HAVE_DISASS=0
        fi
    fi
fi

# LD_LIBRARY_PATH and DYLD_LIBRARY_PATH
if [[ "$IS_LINUX" -ne 0 || "$IS_SOLARIS" -ne 0 || "$IS_BSD" -ne 0 ]]; then
    HAVE_LD_LIBRARY_PATH=1
fi
if [[ "$IS_DARWIN" -ne 0 ]]; then
    HAVE_DYLD_LIBRARY_PATH=1
fi

# Fixup... GCC 4.8 ASAN produces false positives under ARM
if [[ ( ("$IS_ARM32" -ne 0 || "$IS_ARM64" -ne 0) && "$GCC_4_8" -ne 0) ]]; then
    HAVE_ASAN=0
fi

# Benchmarks take a long time...
if [[ (-z "$WANT_BENCHMARKS") ]]; then
    WANT_BENCHMARKS=1
fi

############################################
# System information

echo "" | tee -a "$TEST_RESULTS"
if [[ "$IS_LINUX" -ne 0 ]]; then
    echo "IS_LINUX: $IS_LINUX" | tee -a "$TEST_RESULTS"
elif [[ "$IS_CYGWIN" -ne 0 ]]; then
    echo "IS_CYGWIN: $IS_CYGWIN" | tee -a "$TEST_RESULTS"
elif [[ "$IS_MINGW" -ne 0 ]]; then
    echo "IS_MINGW: $IS_MINGW" | tee -a "$TEST_RESULTS"
elif [[ "$IS_SOLARIS" -ne 0 ]]; then
    echo "IS_SOLARIS: $IS_SOLARIS" | tee -a "$TEST_RESULTS"
elif [[ "$IS_DARWIN" -ne 0 ]]; then
    echo "IS_DARWIN: $IS_DARWIN" | tee -a "$TEST_RESULTS"
elif [[ "$IS_AIX" -ne 0 ]]; then
    echo "IS_AIX: $IS_AIX" | tee -a "$TEST_RESULTS"
fi

if [[ "$IS_PPC64" -ne 0 ]]; then
    echo "IS_PPC64: $IS_PPC64" | tee -a "$TEST_RESULTS"
elif [[ "$IS_PPC32" -ne 0 ]]; then
    echo "IS_PPC32: $IS_PPC32" | tee -a "$TEST_RESULTS"
fi
if [[ "$IS_ARM64" -ne 0 ]]; then
    echo "IS_ARM64: $IS_ARM64" | tee -a "$TEST_RESULTS"
elif [[ "$IS_ARM32" -ne 0 ]]; then
    echo "IS_ARM32: $IS_ARM32" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARMV7A" -ne 0 ]]; then
    echo "HAVE_ARMV7A: $HAVE_ARMV7A" | tee -a "$TEST_RESULTS"
elif [[ "$HAVE_ARMV8" -ne 0 ]]; then
    echo "HAVE_ARMV8: $HAVE_ARMV8" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_NEON" -ne 0 ]]; then
    echo "HAVE_ARM_NEON: $HAVE_ARM_NEON" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_VFPD32" -ne 0 ]]; then
    echo "HAVE_ARM_VFPD32: $HAVE_ARM_VFPD32" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_VFPV3" -ne 0 ]]; then
    echo "HAVE_ARM_VFPV3: $HAVE_ARM_VFPV3" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_VFPV4" -ne 0 ]]; then
    echo "HAVE_ARM_VFPV4: $HAVE_ARM_VFPV4" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_CRC" -ne 0 ]]; then
    echo "HAVE_ARM_CRC: $HAVE_ARM_CRC" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_CRYPTO" -ne 0 ]]; then
    echo "HAVE_ARM_CRYPTO: $HAVE_ARM_CRYPTO" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_SHA3" -ne 0 ]]; then
    echo "HAVE_ARM_SHA3: $HAVE_ARM_SHA3" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_ARM_SHA512" -ne 0 ]]; then
    echo "HAVE_ARM_SHA512: $HAVE_ARM_SHA512" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_PPC_ALTIVEC" -ne 0 ]]; then
    echo "HAVE_PPC_ALTIVEC: $HAVE_PPC_ALTIVEC" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_PPC_POWER7" -ne 0 ]]; then
    echo "HAVE_PPC_POWER7: $HAVE_PPC_POWER7" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_PPC_POWER8" -ne 0 ]]; then
    echo "HAVE_PPC_POWER8: $HAVE_PPC_POWER8" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_PPC_POWER9" -ne 0 ]]; then
    echo "HAVE_PPC_POWER9: $HAVE_PPC_POWER9" | tee -a "$TEST_RESULTS"
fi

if [[ "$IS_X32" -ne 0 ]]; then
    echo "IS_X32: $IS_X32" | tee -a "$TEST_RESULTS"
elif [[ "$IS_X64" -ne 0 ]]; then
    echo "IS_X64: $IS_X64" | tee -a "$TEST_RESULTS"
elif [[ "$IS_X86" -ne 0 ]]; then
    echo "IS_X86: $IS_X86" | tee -a "$TEST_RESULTS"
fi

if [[ "$IS_S390" -ne 0 ]]; then
    echo "IS_S390: $IS_S390" | tee -a "$TEST_RESULTS"
fi

# C++03, C++11, C++14 and C++17
echo "" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX03: $HAVE_CXX03" | tee -a "$TEST_RESULTS"
echo "HAVE_GNU03: $HAVE_GNU03" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX11: $HAVE_CXX11" | tee -a "$TEST_RESULTS"
echo "HAVE_GNU11: $HAVE_GNU11" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX14: $HAVE_CXX14" | tee -a "$TEST_RESULTS"
echo "HAVE_GNU14: $HAVE_GNU14" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX17: $HAVE_CXX17" | tee -a "$TEST_RESULTS"
echo "HAVE_GNU17: $HAVE_GNU17" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX20: $HAVE_CXX20" | tee -a "$TEST_RESULTS"
echo "HAVE_GNU20: $HAVE_GNU20" | tee -a "$TEST_RESULTS"
echo "HAVE_CXX23: $HAVE_CXX20" | tee -a "$TEST_RESULTS"
echo "HAVE_GNU23: $HAVE_GNU20" | tee -a "$TEST_RESULTS"

if [[ "$HAVE_LDGOLD" -ne 0 ]]; then
    echo "HAVE_LDGOLD: $HAVE_LDGOLD" | tee -a "$TEST_RESULTS"
fi

# -O2, -O3, -Os and -Ofast
echo "" | tee -a "$TEST_RESULTS"
echo "OPT_O2: $OPT_O2" | tee -a "$TEST_RESULTS"
echo "OPT_O3: $OPT_O3" | tee -a "$TEST_RESULTS"
if [[ ("$HAVE_OS" -eq 1) ]]; then
    echo "OPT_OS: $OPT_OS" | tee -a "$TEST_RESULTS"
fi
if [[ ("$HAVE_OZ" -eq 1) ]]; then
    echo "OPT_OZ: $OPT_OZ" | tee -a "$TEST_RESULTS"
fi
if [[ ("$HAVE_OFAST" -eq 1) ]]; then
    echo "OPT_OFAST: $OPT_OFAST" | tee -a "$TEST_RESULTS"
fi

# Tools available for testing
echo "" | tee -a "$TEST_RESULTS"
if [[ ((-n "$HAVE_OMP") && ("$HAVE_OMP" -ne 0)) ]]; then echo "HAVE_OMP: $HAVE_OMP" | tee -a "$TEST_RESULTS"; fi
echo "HAVE_ASAN: $HAVE_ASAN" | tee -a "$TEST_RESULTS"
if [[ ("$HAVE_ASAN" -ne 0) && (-n "$ASAN_SYMBOLIZE") ]]; then echo "ASAN_SYMBOLIZE: $ASAN_SYMBOLIZE" | tee -a "$TEST_RESULTS"; fi
echo "HAVE_UBSAN: $HAVE_UBSAN" | tee -a "$TEST_RESULTS"
echo "HAVE_BSAN: $HAVE_BSAN" | tee -a "$TEST_RESULTS"
echo "HAVE_CET: $HAVE_CET" | tee -a "$TEST_RESULTS"
echo "HAVE_ANALYZER: $HAVE_ANALYZER" | tee -a "$TEST_RESULTS"
echo "HAVE_REPTOLINE: $HAVE_REPTOLINE" | tee -a "$TEST_RESULTS"
echo "HAVE_VALGRIND: $HAVE_VALGRIND" | tee -a "$TEST_RESULTS"
# HAVE_REPTOLINE is for Meltdown and Spectre option testing, called Reptoline (play on trampoline)

if [[ "$HAVE_INTEL_MULTIARCH" -ne 0 ]]; then
    echo "HAVE_INTEL_MULTIARCH: $HAVE_INTEL_MULTIARCH" | tee -a "$TEST_RESULTS"
fi
if [[ "$HAVE_PPC_MULTIARCH" -ne 0 ]]; then
    echo "HAVE_PPC_MULTIARCH: $HAVE_PPC_MULTIARCH" | tee -a "$TEST_RESULTS"
fi

############################################

# CPU is logical count, memory is in MiB. Low resource boards have
#   fewer than 4 cores and 1GB or less memory. We use this to
#   determine if we can build in parallel without an OOM kill.
CPU_COUNT=1
MEM_SIZE=512

if [[ ("$IS_SPARC" -ne 0) && ("$IS_LINUX" -ne 0) ]]; then
    CPU_COUNT="$(${GREP} -E 'CPU.*' /proc/cpuinfo | cut -f 1 -d ':' | ${SED} 's|CPU||g' | sort -n | tail -1)"
    MEM_SIZE="$(${GREP} "MemTotal" < /proc/meminfo | ${AWK} '{print int($2/1024)}')"
elif [[ (-e "/proc/cpuinfo") && (-e "/proc/meminfo") ]]; then
    CPU_COUNT="$(${GREP} -c -E "^processor" < /proc/cpuinfo)"
    MEM_SIZE="$(${GREP} "MemTotal" < /proc/meminfo | ${AWK} '{print int($2/1024)}')"
elif [[ "$IS_DARWIN" -ne 0 ]]; then
    CPU_COUNT="$(sysctl -a 2>&1 | ${GREP} "hw.availcpu" | ${AWK} '{print $3; exit}')"
    MEM_SIZE="$(sysctl -a 2>&1 | ${GREP} "hw.memsize" | ${AWK} '{print int($3/1024/1024); exit;}')"
elif [[ "$IS_SOLARIS" -ne 0 ]]; then
    CPU_COUNT="$(psrinfo 2>/dev/null | wc -l | ${AWK} '{print $1}')"
    MEM_SIZE="$(prtconf 2>/dev/null | ${GREP} "Memory" | ${AWK} '{print int($3)}')"
elif [[ "$IS_AIX" -ne 0 ]]; then
    CPU_COUNT="$(bindprocessor -q 2>/dev/null | cut -f 2 -d ":" | wc -w | ${AWK} '{print $1}')"
    MEM_SIZE="$(prtconf -m 2>/dev/null | ${GREP} "MB" | ${AWK} '{print int($3); exit;}')"
fi

# Benchmarks expect frequency in GiHz.
CPU_FREQ=0.5
if [[ (-e "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq") ]]; then
    CPU_FREQ="$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)"
    CPU_FREQ="$(echo "$CPU_FREQ" | ${AWK} '{print $0/1024/1024; exit}')"
elif [[ (-e "/proc/cpuinfo") ]]; then
    CPU_FREQ="$(${GREP} 'MHz' < /proc/cpuinfo | ${AWK} '{print $4; exit}')"
    if [[ -z "$CPU_FREQ" ]]; then CPU_FREQ=512; fi
    CPU_FREQ="$(echo "$CPU_FREQ" | ${AWK} '{print $0/1024}')"
elif [[ "$IS_DARWIN" -ne 0 ]]; then
    CPU_FREQ="$(sysctl -a 2>&1 | ${GREP} "hw.cpufrequency" | ${AWK} '{print int($3); exit;}')"
    CPU_FREQ="$(echo "$CPU_FREQ" | ${AWK} '{print int($0/1024/1024/1024)}')"
elif [[ "$IS_SOLARIS" -ne 0 ]]; then
    CPU_FREQ="$(psrinfo -v 2>/dev/null | ${GREP} "MHz" | ${AWK} '{print $6; exit;}')"
    CPU_FREQ="$(echo "$CPU_FREQ" | ${AWK} '{print $0/1024}')"
elif [[ "$IS_AIX" -ne 0 ]]; then
    CPU_FREQ="$(prtconf -s 2>/dev/null | ${GREP} "MHz" | ${AWK} '{print $4; exit;}')"
    CPU_FREQ="$(echo "$CPU_FREQ" | ${AWK} '{print $0/1024}')"
fi

# Fixups for later versions of OS X
if [[ "$IS_DARWIN" -ne 0 ]]; then
    if [[ (-z "$CPU_COUNT") || ("$CPU_COUNT" -eq 0) ]]; then
        CPU_COUNT="$(sysctl -a 2>&1 | ${GREP} "hw.activecpu" | ${AWK} '{print $2; exit}')"
    fi
    if [[ (-z "$MEM_SIZE") || ("$MEM_SIZE" -eq 0) ]]; then
        MEM_SIZE="$(sysctl -a 2>&1 | ${GREP} "hw.memsize" | ${AWK} '{print int($2/1024/1024); exit;}')"
    fi
    if [[ (-z "$CPU_FREQ") || ("$CPU_FREQ" -eq 0) ]]; then
        CPU_FREQ="$(sysctl -a 2>&1 | ${GREP} "hw.cpufrequency" | ${AWK} '{print int($2); exit;}')"
        CPU_FREQ="$(echo "$CPU_FREQ" | ${AWK} '{print int($0/1024/1024/1024)}')"
    fi
    if [[ (-z "$CPU_FREQ") || ("$CPU_FREQ" -eq 0) ]]; then
        CPU_FREQ="$(sysctl -a 2>&1 | ${GREP} "hw.tbfrequency" | ${AWK} '{print int($2); exit;}')"
        CPU_FREQ="$(echo "$CPU_FREQ" | ${AWK} '{print int($0/10/1024/1024)}')"
    fi
fi

# Some ARM devboards cannot use 'make -j N', even with multiple cores and RAM
#  An 8-core Cubietruck Plus with 2GB RAM experiences OOM kills with '-j 2'.
HAVE_SWAP=1
if [[ "$IS_LINUX" -ne 0 ]]; then
    # If memory is small, then ensure swap space exists
    if [[ "$MEM_SIZE" -lt 4096 ]]; then
        if [[ (-e "/proc/meminfo") ]]; then
            SWAP_SIZE="$(${GREP} 'SwapTotal' < /proc/meminfo | "${AWK}" '{print $2}')"
            if [[ "$SWAP_SIZE" -eq 0 ]]; then
                HAVE_SWAP=0
            fi
        else
            HAVE_SWAP=0
        fi
    fi
fi

echo "" | tee -a "$TEST_RESULTS"
echo "CPU: $CPU_COUNT logical" | tee -a "$TEST_RESULTS"
echo "FREQ: $CPU_FREQ GHz" | tee -a "$TEST_RESULTS"
echo "MEM: $MEM_SIZE MB" | tee -a "$TEST_RESULTS"

if [[ -n "$MAKE_JOBS" ]]; then
    MAKEARGS=(-j "$MAKE_JOBS")
    echo "Using $MAKE -j $MAKE_JOBS"
elif [[ ("$CPU_COUNT" -ge 2 && "$MEM_SIZE" -ge 1280 && "$HAVE_SWAP" -ne 0) ]]; then
    if [[ ("$WANT_NICE" -eq 1) ]]; then
        CPU_COUNT=$(echo -n "$CPU_COUNT 2" | "${AWK}" '{print int($1/$2)}')
    fi
    MAKEARGS=(-j "$CPU_COUNT")
    echo "Using $MAKE -j $CPU_COUNT"
fi

############################################

GIT_REPO=$(git branch 2>&1 | "${GREP}" -v "fatal" | wc -l | "${AWK}" '{print $1; exit;}')
if [[ "$GIT_REPO" -ne 0 ]]; then
    GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
    GIT_HASH=$(git rev-parse HEAD 2>/dev/null | cut -c 1-16)
fi

echo "" | tee -a "$TEST_RESULTS"
if [[ -n "$GIT_BRANCH" ]]; then
    echo "Git branch: $GIT_BRANCH (commit $GIT_HASH)" | tee -a "$TEST_RESULTS"
fi

if [[ ("$SUN_COMPILER" -ne 0) ]]; then
    "${CXX}" -V 2>&1 | "${SED}" 's|CC:|Compiler:|g' | head -1 | tee -a "$TEST_RESULTS"
elif [[ ("$XLC_COMPILER" -ne 0) ]]; then
    echo "Compiler: $(${CXX} -qversion | head -1)" | tee -a "$TEST_RESULTS"
else
    echo "Compiler: $(${CXX} --version | head -1)" | tee -a "$TEST_RESULTS"
fi

CXX_PATH=$(command -v "${CXX}" 2>/dev/null)
CXX_SYMLINK=$(ls -l "${CXX_PATH}" 2>/dev/null | "${GREP}" -c '^l' | "${AWK}" '{print $1}')
if [[ ("${CXX_SYMLINK}" -ne 0) ]]; then CXX_PATH="${CXX_PATH} (symlinked)"; fi
echo "Pathname: ${CXX_PATH}" | tee -a "$TEST_RESULTS"

############################################

# Calculate these once. They handle Clang, GCC, ICC, etc
DEBUG_CXXFLAGS="-DDEBUG $OPT_G3 $OPT_O0"
RELEASE_CXXFLAGS="-DNDEBUG $OPT_G2 $OPT_O3"
VALGRIND_CXXFLAGS="-DNDEBUG $OPT_G3 $OPT_O1"
WARNING_CXXFLAGS=()

if [[ ("$GCC_COMPILER" -ne 0 || "$CLANG_COMPILER" -ne 0) ]]; then
    WARNING_CXXFLAGS+=("-Wall" "-Wextra" "-Wno-unknown-pragmas" "-Wstrict-overflow")
    WARNING_CXXFLAGS+=("-Wcast-align" "-Wwrite-strings" "-Wformat=2" "-Wformat-security")
fi

# On PowerPC we test the original Altivec load and store with unaligned data.
# Modern compilers generate a warning and recommend the new loads and stores.
if [[ ("$GCC_COMPILER" -ne 0 && ("$IS_PPC32" -ne 0 || "$IS_PPC64" -ne 0) ) ]]; then
    WARNING_CXXFLAGS+=("-Wno-deprecated")
fi

echo "" | tee -a "$TEST_RESULTS"
echo "DEBUG_CXXFLAGS: $DEBUG_CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "RELEASE_CXXFLAGS: $RELEASE_CXXFLAGS" | tee -a "$TEST_RESULTS"
echo "VALGRIND_CXXFLAGS: $VALGRIND_CXXFLAGS" | tee -a "$TEST_RESULTS"
if [[ (-n "$USER_CXXFLAGS") ]]; then
    echo "USER_CXXFLAGS: $USER_CXXFLAGS" | tee -a "$TEST_RESULTS"
fi

#############################################
#############################################
############### BEGIN TESTING ###############
#############################################
#############################################

TEST_BEGIN=$(date)
echo "" | tee -a "$TEST_RESULTS"
echo "Start time: $TEST_BEGIN" | tee -a "$TEST_RESULTS"

############################################
# Posix NDEBUG and assert
if true; then

    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: No Posix NDEBUG or assert" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("No Posix NDEBUG or assert")
    FAILED=0

    # Search for headers. Filter out C++ abd Doxygen comments.
    COUNT=$(cat ./*.h ./*.cpp | "${GREP}" -v '//' | "${GREP}" -c -E '(assert.h|cassert)')
    if [[ "$COUNT" -ne 0 ]]; then
        FAILED=1
        echo "FAILED: found Posix assert headers" | tee -a "$TEST_RESULTS"
    fi

    # Search for asserts. Filter out C++, Doxygen comments and static_assert.
    COUNT=$(cat ./*.h ./*.cpp | "${GREP}" -v -E '//|_assert' | "${GREP}" -c -E 'assert[[:space:]]*\(')
    if [[ "$COUNT" -ne 0 ]]; then
        FAILED=1
        echo "FAILED: found use of Posix assert" | tee -a "$TEST_RESULTS"
    fi

    # Filter out C++ and Doxygen comments.
    COUNT=$(cat ./*.h ./*.cpp | "${GREP}" -v '//' | "${GREP}" -c 'NDEBUG')
    if [[ "$COUNT" -ne 0 ]]; then
        FAILED=1
        echo "FAILED: found use of Posix NDEBUG" | tee -a "$TEST_RESULTS"
    fi

    if [[ ("$FAILED" -eq 0) ]]; then
        echo "Verified no Posix NDEBUG or assert" | tee -a "$TEST_RESULTS"
    else
        FAILED_LIST+=("No Posix NDEBUG or assert")
    fi
fi

############################################
# C++ std::min and std::max
# This is due to Windows.h and NOMINMAX. Linux test fine, while Windows breaks.
# http://support.microsoft.com/en-us/kb/143208
if true; then

    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: C++ std::min and std::max" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("C++ std::min and std::max")
    FAILED=0

    # If this fires, then use STDMIN(a,b) or (std::min)(a, b);
    COUNT=$(cat ./*.h ./*.cpp | "${GREP}" -v '//' | "${GREP}" -c -E 'std::min[[:space:]]*\(')
    if [[ "$COUNT" -ne 0 ]]; then
        FAILED=1
        echo "FAILED: found std::min" | tee -a "$TEST_RESULTS"
    fi

    # If this fires, then use STDMAX(a,b) or (std::max)(a, b);
    COUNT=$(cat ./*.h ./*.cpp | "${GREP}" -v '//' | "${GREP}" -c -E 'std::max[[:space:]]*\(')
    if [[ "$COUNT" -ne 0 ]]; then
        FAILED=1
        echo "FAILED: found std::max" | tee -a "$TEST_RESULTS"
    fi

    # If this fires, then use STDMIN(a,b) or (std::min)(a, b);
    COUNT=$(cat ./*.h ./*.cpp | "${GREP}" -v '//' | "${GREP}" -c -E 'std::numeric_limits<.*>::min[[:space:]]*\(')
    if [[ "$COUNT" -ne 0 ]]; then
        FAILED=1
        echo "FAILED: found std::numeric_limits<T>::min" | tee -a "$TEST_RESULTS"
    fi

    # If this fires, then use STDMAX(a,b) or (std::max)(a, b);
    COUNT=$(cat ./*.h ./*.cpp | "${GREP}" -v '//' | "${GREP}" -c -E 'std::numeric_limits<.*>::max[[:space:]]*\(')
    if [[ "$COUNT" -ne 0 ]]; then
        FAILED=1
        echo "FAILED: found std::numeric_limits<T>::max" | tee -a "$TEST_RESULTS"
    fi

    if [[ ("$FAILED" -eq 0) ]]; then
        echo "Verified std::min and std::max" | tee -a "$TEST_RESULTS"
    else
        FAILED_LIST+=("C++ std::min and std::max")
    fi
fi

############################################
# X86 code generation tests
if [[ ("$HAVE_DISASS" -ne 0 && ("$IS_X86" -ne 0 || "$IS_X64" -ne 0)) ]]; then

    ############################################
    # X86 rotate immediate code generation

    X86_ROTATE_IMM=1
    if [[ ("$X86_ROTATE_IMM" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: X86 rotate immediate code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("X86 rotate immediate code generation")

        OBJFILE=sha.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        X86_SSE2=$(echo -n "$X86_CPU_FLAGS" | "${GREP}" -i -c sse2)
        X86_SHA256_HASH_BLOCKS=$(echo -n "$DISASS_TEXT" | "${GREP}" -c 'SHA256_HashMultipleBlocks_SSE2')
        if [[ ("$X86_SHA256_HASH_BLOCKS" -ne 0) ]]; then
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E '(rol.*0x|ror.*0x)')
            if [[ ("$COUNT" -le 250) ]]; then
                FAILED=1
                echo "ERROR: failed to generate rotate immediate instruction (SHA256_HashMultipleBlocks_SSE2)" | tee -a "$TEST_RESULTS"
            fi
        else
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E '(rol.*0x|ror.*0x)')
            if [[ ("$COUNT" -le 500) ]]; then
                FAILED=1
                echo "ERROR: failed to generate rotate immediate instruction" | tee -a "$TEST_RESULTS"
            fi
        fi

        if [[ ("$X86_SSE2" -ne 0 && "$X86_SHA256_HASH_BLOCKS" -eq 0) ]]; then
            echo "ERROR: failed to use SHA256_HashMultipleBlocks_SSE2" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0 && "$X86_SHA256_HASH_BLOCKS" -ne 0) ]]; then
            echo "Verified rotate immediate machine instructions (SHA256_HashMultipleBlocks_SSE2)" | tee -a "$TEST_RESULTS"
        elif [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified rotate immediate machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("X86 rotate immediate code generation")
        fi
    fi

    ############################################
    # Test CRC-32C code generation

    "${CXX}" -msse4.2 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        X86_CRC32=1
    fi

    if [[ ("$X86_CRC32" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: X86 CRC32 code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("X86 CRC32 code generation")

        OBJFILE=crc_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c crc32b)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate crc32b instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c crc32l)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate crc32l instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified crc32b and crc32l machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("X86 CRC32 code generation")
        fi
    fi

    ############################################
    # Test AES-NI code generation

    "${CXX}" -maes "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        X86_AESNI=1
    fi

    if [[ ("$X86_AESNI" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: X86 AES-NI code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("X86 AES-NI code generation")

        OBJFILE=rijndael_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aesenc)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aesenc instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aesenclast)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aesenclast instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aesdec)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aesdec instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aesdeclast)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aesdeclast instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aesimc)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aesimc instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aeskeygenassist)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aeskeygenassist instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified aesenc, aesenclast, aesdec, aesdeclast, aesimc, aeskeygenassist machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("X86 AES-NI code generation")
        fi
    fi

    ############################################
    # X86 carryless multiply code generation

    "${CXX}" -mpclmul "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        X86_PCLMUL=1
    fi

    if [[ ("$X86_PCLMUL" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: X86 carryless multiply code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("X86 carryless multiply code generation")

        OBJFILE=gcm_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E '(pclmulqdq|pclmullqhq|vpclmulqdq)')
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate pclmullqhq instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E '(pclmulqdq|pclmullqlq|vpclmulqdq)')
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate pclmullqlq instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified pclmullqhq and pclmullqlq machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("X86 carryless multiply code generation")
        fi
    fi

    ############################################
    # Test RDRAND and RDSEED code generation

    "${CXX}" -mrdrnd "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        X86_RDRAND=1
    fi
    "${CXX}" -mrdseed "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        X86_RDSEED=1
    fi

    if [[ ("$X86_RDRAND" -ne 0 || "$X86_RDSEED" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: X86 RDRAND and RDSEED code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("X86 RDRAND and RDSEED code generation")

        OBJFILE=rdrand.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        if [[ "$X86_RDRAND" -ne 0 ]]; then
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c rdrand)
            if [[ ("$COUNT" -eq 0) ]]; then
                FAILED=1
                echo "ERROR: failed to generate rdrand instruction" | tee -a "$TEST_RESULTS"
            fi
        fi

        if [[ "$X86_RDSEED" -ne 0 ]]; then
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c rdseed)
            if [[ ("$COUNT" -eq 0) ]]; then
                FAILED=1
                echo "ERROR: failed to generate rdseed instruction" | tee -a "$TEST_RESULTS"
            fi
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified rdrand and rdseed machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("X86 RDRAND and RDSEED code generation")
        fi
    fi

    ############################################
    # X86 SHA code generation

    "${CXX}" -msha "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        X86_SHA=1
    fi

    if [[ ("$X86_SHA" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: X86 SHA code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("X86 SHA code generation")

        OBJFILE=sha_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1rnds4)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1rnds4 instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1nexte)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1nexte instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1msg1)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1msg1 instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1msg2)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1msg2 instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha256rnds2)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha256rnds2 instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha256msg1)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha256msg1 instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha256msg2)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha256msg2 instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified sha1rnds4, sha1nexte, sha1msg1, sha1msg2, sha256rnds2, sha256msg1 and sha256msg2 machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("X86 SHA code generation")
        fi
    fi
fi

############################################
# ARM code generation tests
if [[ ("$HAVE_DISASS" -ne 0 && ("$IS_ARM32" -ne 0 || "$IS_ARM64" -ne 0)) ]]; then

    ############################################
    # ARM NEON code generation

    ARM_NEON=$(echo -n "$ARM_CPU_FLAGS" | "${GREP}" -i -c -E '(neon|asimd)')
    if [[ ("$ARM_NEON" -ne 0 || "$HAVE_ARM_NEON" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: ARM NEON code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("ARM NEON code generation")

        OBJFILE=chacha_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        if [[ ("$HAVE_ARMV8" -ne 0) ]]; then
            # ARIA::UncheckedKeySet: 4 ldr q{N}
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'ldr[[:space:]]*q|ldp[[:space:]]*q')
            if [[ ("$COUNT" -lt 4) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON load instructions" | tee -a "$TEST_RESULTS"
            fi
        else  # ARMv7
            # ARIA::UncheckedKeySet: 4 vld {d1,d2}
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'vld[[:space:]]*')
            if [[ ("$COUNT" -lt 4) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON load instructions" | tee -a "$TEST_RESULTS"
            fi
        fi

        if [[ ("$HAVE_ARMV8" -ne 0) ]]; then
            # ARIA::UncheckedKeySet: 17 str q{N}
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'str[[:space:]]*q|stp[[:space:]]*q')
            if [[ ("$COUNT" -lt 8) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON store instructions" | tee -a "$TEST_RESULTS"
            fi
        else
            # ARIA::UncheckedKeySet: 17 vstr {d1,d2}
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'vst[[:space:]]*')
            if [[ ("$COUNT" -lt 16) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON store instructions" | tee -a "$TEST_RESULTS"
            fi
        fi

        if [[ ("$HAVE_ARMV8" -ne 0) ]]; then
            # ARIA::UncheckedKeySet: 17 shl v{N}
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'shl[[:space:]]*v|shl.4s')
            if [[ ("$COUNT" -lt 16) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON shift left instructions" | tee -a "$TEST_RESULTS"
            fi
        else
            # ARIA::UncheckedKeySet: 17 vshl
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'vshl')
            if [[ ("$COUNT" -lt 16) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON shift left instructions" | tee -a "$TEST_RESULTS"
            fi
        fi

        if [[ ("$HAVE_ARMV8" -ne 0) ]]; then
            # ARIA::UncheckedKeySet: 17 shr v{N}
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'shr[[:space:]]*v|shr.4s')
            if [[ ("$COUNT" -lt 16) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON shift right instructions" | tee -a "$TEST_RESULTS"
            fi
        else
            # ARIA::UncheckedKeySet: 17 vshr
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'vshr')
            if [[ ("$COUNT" -lt 16) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON shift right instructions" | tee -a "$TEST_RESULTS"
            fi
        fi

        if [[ ("$HAVE_ARMV8" -ne 0) ]]; then
            # ARIA::UncheckedKeySet: 12 ext v{N}
            COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'ext[[:space:]]*v|ext.*v')
            if [[ ("$COUNT" -lt 12) ]]; then
                FAILED=1
                echo "ERROR: failed to generate NEON extract instructions" | tee -a "$TEST_RESULTS"
            fi
        fi

        # ARIA::UncheckedKeySet: 17 veor
        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c -E 'eor.*v|veor')
        if [[ ("$COUNT" -lt 16) ]]; then
            FAILED=1
            echo "ERROR: failed to generate NEON xor instructions" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified NEON load, store, shfit left, shift right, xor machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("ARM NEON code generation")
        fi
    fi

    ############################################
    # ARM CRC32 code generation

    "${CXX}" -march=armv8-a+crc "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        ARM_CRC32=1
    fi

    if [[ ("$HAVE_ARMV8" -ne 0 && "$ARM_CRC32" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: ARM CRC32 code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("ARM CRC32 code generation")

        OBJFILE=crc_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c crc32cb)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate crc32cb instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c crc32cw)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate crc32cw instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c crc32b)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate crc32b instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c crc32w)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate crc32w instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified crc32cb, crc32cw, crc32b and crc32w machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("ARM CRC32 code generation")
        fi
    fi

    ############################################
    # ARM carryless multiply code generation

    "${CXX}" -march=armv8-a+crypto "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        ARM_PMULL=1
    fi

    if [[ ("$HAVE_ARMV8" -ne 0 && "$ARM_PMULL" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: ARM carryless multiply code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("ARM carryless multiply code generation")

        OBJFILE=gcm_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -v pmull2 | "${GREP}" -i -c pmull)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate pmull instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c pmull2)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate pmull2 instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified pmull and pmull2 machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("ARM carryless multiply code generation")
        fi
    fi

    ############################################
    # ARM AES code generation

    "${CXX}" -march=armv8-a+crypto "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        ARM_AES=1
    fi

    if [[ ("$HAVE_ARMV8" -ne 0 && "$ARM_AES" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: ARM AES code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("ARM AES code generation")

        OBJFILE=rijndael_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aese)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aese instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aesmc)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aesmc instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aesd)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aesd instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c aesimc)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate aesimc instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified aese, aesd, aesmc, aesimc machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("ARM AES code generation")
        fi
    fi

    ############################################
    # ARM SHA code generation

    "${CXX}" -march=armv8-a+crypto "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        ARM_SHA1=1
        ARM_SHA2=1
    fi

    if [[ ("$HAVE_ARMV8" -ne 0 && "$ARM_SHA1" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: ARM SHA1 code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("ARM SHA1 code generation")

        OBJFILE=sha_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1c)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1c instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1m)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1m instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1p)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1p instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1h)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1h instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1su0)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1su0 instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha1su1)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha1su1 instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified sha1c, sha1m, sha1p, sha1su0, sha1su1 machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("ARM SHA1 code generation")
        fi
    fi


    if [[ ("$HAVE_ARMV8" -ne 0 && "$ARM_SHA2" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: ARM SHA2 code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("ARM SHA2 code generation")

        OBJFILE=sha_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -v sha256h2 | "${GREP}" -i -c sha256h)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha256h instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha256h2)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha256h2 instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha256su0)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha256su0 instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c sha256su1)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate sha256su1 instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified sha256h, sha256h2, sha256su0, sha256su1 machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("ARM SHA2 code generation")
        fi
    fi
fi

############################################
# Altivec generation tests
if [[ ("$HAVE_DISASS" -ne 0 && ("$IS_PPC32" -ne 0 || "$IS_PPC64" -ne 0)) ]]; then

    ############################################
    # Altivec

    PPC_ALTIVEC=0
    if [[ ("$PPC_ALTIVEC" -eq 0) ]]; then
        "${CXX}" -maltivec "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            PPC_ALTIVEC=1
        fi
    fi
    if [[ ("$PPC_ALTIVEC" -eq 0) ]]; then
        "${CXX}" -qarch=altivec "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            PPC_ALTIVEC=1
        fi
    fi

    if [[ ("$PPC_ALTIVEC" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Altivec code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Altivec code generation")

        OBJFILE=speck128_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c lvx)
        if [[ ("$COUNT" -lt 8) ]]; then
            FAILED=1
            echo "ERROR: failed to generate lvx instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c stvx)
        if [[ ("$COUNT" -lt 8) ]]; then
            FAILED=1
            echo "ERROR: failed to generate stvx instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c vsldoi)
        if [[ ("$COUNT" -lt 8) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vsldoi instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c vxor)
        if [[ ("$COUNT" -lt 8) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vxor instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c vperm)
        if [[ ("$COUNT" -lt 8) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vperm instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified vxl, stvx, vsldoi, vxor, vperm instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("Altivec code generation")
        fi
    fi
fi

############################################
# Power8 code generation tests
if [[ ("$HAVE_DISASS" -ne 0 && "$GCC_4_8_OR_ABOVE" -ne 0 && ("$IS_PPC32" -ne 0 || "$IS_PPC64" -ne 0)) ]]; then

    ############################################
    # Power8 AES

    PPC_AES=0
    if [[ ("$PPC_AES" -eq 0) ]]; then
        "${CXX}" -mcpu=power8 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            PPC_AES=1
        fi
    fi
    if [[ ("$PPC_AES" -eq 0) ]]; then
        "${CXX}" -qarch=pwr8 -qaltivec "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            PPC_AES=1
        fi
    fi

    if [[ ("$PPC_AES" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Power8 AES code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Power8 AES code generation")

        OBJFILE=rijndael_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -v vcipherlast | "${GREP}" -i -c vcipher)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vcipher instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c vcipherlast)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vcipherlast instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -v vncipherlast | "${GREP}" -i -c vncipher)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vncipher instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c vncipherlast)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vncipherlast instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified vcipher, vcipherlast, vncipher, vncipherlast machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("Power8 AES code generation")
        fi
    fi

    ############################################
    # Power8 SHA

    PPC_SHA=0
    if [[ ("$PPC_SHA" -eq 0) ]]; then
        "${CXX}" -mcpu=power8 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            PPC_SHA=1
        fi
    fi
    if [[ ("$PPC_SHA" -eq 0) ]]; then
        "${CXX}" -qarch=pwr8 -qaltivec "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            PPC_SHA=1
        fi
    fi

    if [[ ("$PPC_SHA" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Power8 SHA code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Power8 SHA code generation")

        OBJFILE=sha_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c vshasigmaw)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vshasigmaw instruction" | tee -a "$TEST_RESULTS"
        fi

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c vshasigmad)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vshasigmad instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified vshasigmaw and vshasigmad machine instructions" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("Power8 SHA code generation")
        fi
    fi

    ############################################
    # Power8 VMULL

    PPC_VMULL=0
    if [[ ("$PPC_VMULL" -eq 0) ]]; then
        "${CXX}" -mcpu=power8 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            PPC_VMULL=1
        fi
    fi
    if [[ ("$PPC_VMULL" -eq 0) ]]; then
        "${CXX}" -qarch=pwr8 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then
            PPC_VMULL=1
        fi
    fi

    if [[ ("$PPC_VMULL" -ne 0) ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Power8 carryless multiply code generation" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Power8 carryless multiply code generation")

        OBJFILE=gcm_simd.o; rm -f "$OBJFILE" 2>/dev/null
        CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" "$MAKE" "${MAKEARGS[@]}" $OBJFILE 2>&1 | tee -a "$TEST_RESULTS"

        COUNT=0
        FAILED=0
        DISASS_TEXT=$("$DISASS" "${DISASSARGS[@]}" "$OBJFILE" 2>/dev/null)

        COUNT=$(echo -n "$DISASS_TEXT" | "${GREP}" -i -c vpmsum)
        if [[ ("$COUNT" -eq 0) ]]; then
            FAILED=1
            echo "ERROR: failed to generate vpmsum instruction" | tee -a "$TEST_RESULTS"
        fi

        if [[ ("$FAILED" -eq 0) ]]; then
            echo "Verified vpmsum machine instruction" | tee -a "$TEST_RESULTS"
        else
            FAILED_LIST+=("Power8 carryless multiply code generation")
        fi
    fi
fi

############################################
# Default CXXFLAGS
if true; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, default CXXFLAGS" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, default CXXFLAGS")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        # Stop now if things are broke
        exit 1
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            # Stop now if things are broke
            exit 1
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            # Stop now if things are broke
            exit 1
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, default CXXFLAGS")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        # Stop now if things are broke
        exit 1
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            # Stop now if things are broke
            exit 1
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            # Stop now if things are broke
            exit 1
        fi
        echo
    fi
fi

############################################
# Shared Objects
if [[ "$HAVE_LD_LIBRARY_PATH" -ne 0 ]]; then
    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, shared object" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, shared object")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXX="${CXX}" CXXFLAGS="$DEBUG_CXXFLAGS" LINK_LIBRARY=libcryptopp.so \
        "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
    else
        LD_LIBRARY_PATH="." ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
        fi
        LD_LIBRARY_PATH="." ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, shared object" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, shared object")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" LINK_LIBRARY=libcryptopp.so \
        "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, shared object")
    else
        LD_LIBRARY_PATH="." ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, shared object")

        fi
        LD_LIBRARY_PATH="." ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, shared object")
        fi
        echo
    fi
fi

############################################
# Dynamic Objects on Darwin
if [[ "$HAVE_DYLD_LIBRARY_PATH" -ne 0 ]]; then
    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, dynamic library" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, dynamic library")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXX="${CXX}" CXXFLAGS="$DEBUG_CXXFLAGS" LINK_LIBRARY=libcryptopp.dylib \
        "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, dynamic library")
    else
        DYLD_LIBRARY_PATH="." ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, dynamic library")
        fi
        DYLD_LIBRARY_PATH="." ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, dynamic library")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, dynamic library" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, dynamic library")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXX="${CXX}" CXXFLAGS="$RELEASE_CXXFLAGS" LINK_LIBRARY=libcryptopp.dylib \
        "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, dynamic library")
    else
        DYLD_LIBRARY_PATH="." ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, dynamic library")
        fi
        DYLD_LIBRARY_PATH="." ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, dynamic library")
        fi
        echo
    fi
fi

############################################
# Debian specific.
if [[ ("$IS_DEBIAN" -ne 0 || "$IS_UBUNTU" -ne 0) ]]; then

    # Flags taken from Debian's build logs
    # https://buildd.debian.org/status/fetch.php?pkg=libcrypto%2b%2b&arch=i386&ver=5.6.4-6
    # https://buildd.debian.org/status/fetch.php?pkg=libcrypto%2b%2b&arch=kfreebsd-amd64&ver=5.6.4-6&stamp=1482663138

    DEBIAN_FLAGS=("-DHAVE_CONFIG_H" "-I." "-Wdate-time" "-D_FORTIFY_SOURCE=2"
    "-g" "-O2" "-fstack-protector-strong" "-Wformat -Werror=format-security"
    "-DNDEBUG" "-fPIC" "-DPIC")

    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debian standard build" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debian standard build")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXX="g++" "$MAKE" "${MAKEARGS[@]}" CXXFLAGS="${DEBIAN_FLAGS[*]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debian standard build")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debian standard build")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debian standard build")
        fi
    fi
fi

############################################
# Fedora specific.
if [[ ("$IS_FEDORA" -ne 0) ]]; then

    # Flags taken from Fedora's build logs
    # https://kojipkgs.fedoraproject.org//packages/cryptopp/5.6.3/8.fc27/data/logs/i686/build.log
    # https://kojipkgs.fedoraproject.org//packages/cryptopp/5.6.3/8.fc27/data/logs/x86_64/build.log
    if [[ ("$IS_X86" -ne 0) ]]; then
        MARCH_OPT=("-m32" "-march=i686")
    elif [[ ("$IS_X64" -ne 0) ]]; then
        MARCH_OPT=("-m64" "-mtune=generic")
    fi

    FEDORA_FLAGS=("-DHAVE_CONFIG_H" "-I." "-O2" "-g" "-pipe" "-Wall" "-Werror=format-security" "-fPIC" "-DPIC"
        "-Wp,-D_FORTIFY_SOURCE=2" "-fexceptions" "-fstack-protector-strong" "--param=ssp-buffer-size=4"
        "-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1" "${MARCH_OPT[@]}" "-fasynchronous-unwind-tables")

    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Fedora standard build" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Fedora standard build")

    if [[ ! -f /usr/lib/rpm/redhat/redhat-hardened-cc1 ]]; then
        echo "ERROR: please install redhat-rpm-config package"
        FAILED_LIST+=("Fedora standard build")
    else
        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXX="g++" "$MAKE" "${MAKEARGS[@]}" CXXFLAGS="${FEDORA_FLAGS[*]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Fedora standard build")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Fedora standard build")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Fedora standard build")
            fi
        fi
    fi
fi

############################################
# openSUSE specific.
if [[ ("$IS_SUSE" -ne 0) ]]; then

    # Flags taken from openSUSE's build logs
    # http://susepaste.org/view//9613298

    SUSE_FLAGS=("-DNDEBUG" "-g" "-O2"
        "-D_FORTIFY_SOURCE=2"
        "-funwind-tables"
        "-fpic" "-fPIC"
        "-pthread" "-fopenmp")

    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -fstack-protector-strong "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        SUSE_FLAGS+=("-fstack-protector-strong")
    fi

    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -fasynchronous-unwind-tables "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        SUSE_FLAGS+=("-fasynchronous-unwind-tables")
    fi

    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -fstack-clash-protection "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        SUSE_FLAGS+=("-fstack-clash-protection")
    fi

    rm -f "${TMPDIR}/test.exe" &>/dev/null
    "${CXX}" -flto=6 "${test_prog}" -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then
        SUSE_FLAGS+=("-flto=6")
    fi

    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: openSUSE standard build" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("openSUSE standard build")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXX="g++" "$MAKE" "${MAKEARGS[@]}" CXXFLAGS="${SUSE_FLAGS[*]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("openSUSE standard build")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("openSUSE standard build")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("openSUSE standard build")
        fi
    fi
fi

############################################
# Minimum platform
if [[ ("$GCC_COMPILER" -ne 0 || "$CLANG_COMPILER" -ne 0 || "$INTEL_COMPILER" -ne 0) ]]; then

    # i686 (lacks MMX, SSE and SSE2)
    if [[ "$IS_X86" -ne 0 ]]; then
        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Debug, i686 minimum arch CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Debug, i686 minimum arch CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$DEBUG_CXXFLAGS -march=i686 $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, i686 minimum arch CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, i686 minimum arch CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, i686 minimum arch CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Release, i686 minimum arch CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Release, i686 minimum arch CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$RELEASE_CXXFLAGS -march=i686 $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, i686 minimum arch CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, i686 minimum arch CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, i686 minimum arch CXXFLAGS")
            fi
        fi
    fi

    # x86_64
    if [[ "$IS_X64" -ne 0 ]]; then
        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Debug, x86_64 minimum arch CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Debug, x86_64 minimum arch CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$DEBUG_CXXFLAGS -march=x86-64 $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, x86_64 minimum arch CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, x86_64 minimum arch CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, x86_64 minimum arch CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Release, x86_64 minimum arch CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Release, x86_64 minimum arch CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$RELEASE_CXXFLAGS -march=x86-64 $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, x86_64 minimum arch CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, x86_64 minimum arch CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, x86_64 minimum arch CXXFLAGS")
            fi
        fi
    fi
fi

############################################
# Mismatched arch capabilities
if [[ ( ("$IS_X86" -ne 0 || "$IS_X32" -ne 0 || "$IS_X64" -ne 0) && "$HAVE_NATIVE_ARCH" -ne 0) ]]; then

    # i686 (lacks MMX, SSE and SSE2)
    if [[ "$IS_X86" -ne 0 ]]; then
        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Debug, mismatched arch capabilities" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Debug, mismatched arch capabilities")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$DEBUG_CXXFLAGS -march=i686 $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static 2>&1 | tee -a "$TEST_RESULTS"

        # The makefile may add -DCRYPTOPP_DISABLE_XXX, so we can't add -march=native
        CXXFLAGS="$DEBUG_CXXFLAGS $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, mismatched arch capabilities")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, mismatched arch capabilities")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, mismatched arch capabilities")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Release, mismatched arch capabilities" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Release, mismatched arch capabilities")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$RELEASE_CXXFLAGS -march=i686 $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static 2>&1 | tee -a "$TEST_RESULTS"

        # The makefile may add -DCRYPTOPP_DISABLE_XXX, so we can't add -march=native
        CXXFLAGS="$RELEASE_CXXFLAGS $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, mismatched arch capabilities")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, mismatched arch capabilities")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, mismatched arch capabilities")
            fi
        fi
    fi

    # x86-64
    if [[ "$IS_X64" -ne 0 ]]; then
        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Debug, mismatched arch capabilities" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Debug, mismatched arch capabilities")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$DEBUG_CXXFLAGS -march=x86-64 $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static 2>&1 | tee -a "$TEST_RESULTS"

        # The makefile may add -DCRYPTOPP_DISABLE_XXX, so we can't add -march=native
        CXXFLAGS="$DEBUG_CXXFLAGS $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, mismatched arch capabilities")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, mismatched arch capabilities")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, mismatched arch capabilities")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Release, mismatched arch capabilities" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Release, mismatched arch capabilities")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$RELEASE_CXXFLAGS -march=x86-64 $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static 2>&1 | tee -a "$TEST_RESULTS"

        # The makefile may add -DCRYPTOPP_DISABLE_XXX, so we can't add -march=native
        CXXFLAGS="$RELEASE_CXXFLAGS $OPT_PIC"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, mismatched arch capabilities")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, mismatched arch capabilities")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, mismatched arch capabilities")
            fi
        fi
    fi
fi

############################################
# Debug build, DISABLE_ASM
if true; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, DISABLE_ASM" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, DISABLE_ASM")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_DISABLE_ASM"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, DISABLE_ASM")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, DISABLE_ASM")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, DISABLE_ASM")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, DISABLE_ASM" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, DISABLE_ASM")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_DISABLE_ASM"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, DISABLE_ASM")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, DISABLE_ASM")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, DISABLE_ASM")
        fi
    fi
fi

############################################
# Debug build, NO_CPU_FEATURE_PROBES
if true; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, NO_CPU_FEATURE_PROBES" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, NO_CPU_FEATURE_PROBES")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_NO_CPU_FEATURE_PROBES=1"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, NO_CPU_FEATURE_PROBES")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, NO_CPU_FEATURE_PROBES")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, NO_CPU_FEATURE_PROBES")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, NO_CPU_FEATURE_PROBES" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, NO_CPU_FEATURE_PROBES")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_NO_CPU_FEATURE_PROBES=1"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, NO_CPU_FEATURE_PROBES")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, NO_CPU_FEATURE_PROBES")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, NO_CPU_FEATURE_PROBES")
        fi
    fi
fi

############################################
# c++03 debug and release build
if [[ "$HAVE_CXX03" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++03" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++03")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++03")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++03")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++03")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++03" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++03")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++03")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++03")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++03")
        fi
    fi
fi

############################################
# gnu++03 debug and release build
if [[ "$HAVE_GNU03" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, gnu++03" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, gnu++03")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, gnu++03")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++03")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++03")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, gnu++03" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, gnu++03")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, gnu++03")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++03")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++03")
        fi
    fi
fi

############################################
# c++11 debug and release build
if [[ "$HAVE_CXX11" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++11" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++11")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++11")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++11")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++11")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++11" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++11")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++11")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++11")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++11")
        fi
    fi
fi

############################################
# gnu++11 debug and release build
if [[ "$HAVE_GNU11" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, gnu++11" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, gnu++11")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, gnu++11")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++11")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++11")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, gnu++11" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, gnu++11")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, gnu++11")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++11")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++11")
        fi
    fi
fi

############################################
# c++14 debug and release build
if [[ "$HAVE_CXX14" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++14" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++14")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++14")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++14")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++14")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++14" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++14")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++14")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14")
        fi
    fi
fi

############################################
# gnu++14 debug and release build
if [[ "$HAVE_GNU14" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, gnu++14" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, gnu++14")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, gnu++14")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++14")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++14")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, gnu++14" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, gnu++14")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, gnu++14")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++14")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++14")
        fi
    fi
fi

############################################
# c++17 debug and release build
if [[ "$HAVE_CXX17" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++17" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++17")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++17")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++17")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++17")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++17" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++17")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++17")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17")
        fi
    fi
fi

############################################
# gnu++17 debug and release build
if [[ "$HAVE_GNU17" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, gnu++17" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, gnu++17")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, gnu++17")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++17")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++17")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, gnu++17" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, gnu++17")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, gnu++17")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++17")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++17")
        fi
    fi
fi

############################################
# c++20 debug and release build
if [[ "$HAVE_CXX20" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++20" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++20")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++20")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++20")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++20")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++20" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++20")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++20")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20")
        fi
    fi
fi

############################################
# gnu++20 debug and release build
if [[ "$HAVE_GNU20" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, gnu++20" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, gnu++20")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++20 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, gnu++20")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++20")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++20")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, gnu++20" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, gnu++20")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++20 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, gnu++20")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++20")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++20")
        fi
    fi
fi

############################################
# gnu++23 debug and release build
if [[ "$HAVE_GNU23" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, gnu++23" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, gnu++23")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=gnu++23 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, gnu++23")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++23")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, gnu++23")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, gnu++23" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, gnu++23")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=gnu++23 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, gnu++23")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++23")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, gnu++23")
        fi
    fi
fi

############################################
# X32 debug and release build
if [[ "$HAVE_X32" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, X32" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, X32")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -mx32 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, X32")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, X32")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, X32")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, X32" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, X32")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -mx32 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, X32")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, X32")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, X32")
        fi
    fi
fi

############################################
# init_priority
if true; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, INIT_PRIORITY (0)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, INIT_PRIORITY (0)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -DCRYPTOPP_INIT_PRIORITY=0 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, INIT_PRIORITY (0)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, INIT_PRIORITY (0)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, INIT_PRIORITY (0)")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, INIT_PRIORITY (0)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, INIT_PRIORITY (0)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_INIT_PRIORITY=0 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, INIT_PRIORITY (0)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, INIT_PRIORITY (0)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, INIT_PRIORITY (0)")
        fi
    fi
fi

############################################
# OS Independence
if true; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, NO_OS_DEPENDENCE" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, NO_OS_DEPENDENCE")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -DNO_OS_DEPENDENCE $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, NO_OS_DEPENDENCE")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, NO_OS_DEPENDENCE")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, NO_OS_DEPENDENCE")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, NO_OS_DEPENDENCE" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, NO_OS_DEPENDENCE")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -DNO_OS_DEPENDENCE $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, NO_OS_DEPENDENCE")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, NO_OS_DEPENDENCE")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, NO_OS_DEPENDENCE")
        fi
    fi
fi

############################################
# Build with LD-Gold
if [[ "$HAVE_LDGOLD" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, ld-gold linker" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, ld-gold linker")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" LD="ld.gold" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, ld-gold linker")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, ld-gold linker")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, ld-gold linker")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, ld-gold linker" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, ld-gold linker")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" LD="ld.gold" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, ld-gold linker")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, ld-gold linker")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, ld-gold linker")
        fi
    fi
fi

############################################
# Build at -O2
if [[ "$HAVE_O2" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, -O2 optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, -O2 optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DDEBUG $OPT_O2 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, -O2 optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -O2 optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -O2 optimizations")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, -O2 optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, -O2 optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DNDEBUG $OPT_O2 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, -O2 optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -O2 optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -O2 optimizations")
        fi
    fi
fi

############################################
# Build at -O3
if [[ "$HAVE_O3" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, -O3 optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, -O3 optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DDEBUG $OPT_O3 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, -O3 optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -O3 optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -O3 optimizations")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, -O3 optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, -O3 optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DNDEBUG $OPT_O3 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, -O3 optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -O3 optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -O3 optimizations")
        fi
    fi
fi

############################################
# Build at -Os
if [[ "$HAVE_OS" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, -Os optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, -Os optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DDEBUG $OPT_OS $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, -Os optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -Os optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -Os optimizations")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, -Os optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, -Os optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DNDEBUG $OPT_OS $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, -Os optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -Os optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -Os optimizations")
        fi
    fi
fi

############################################
# Build at -Oz
if [[ "$HAVE_OZ" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, -Oz optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, -Oz optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DDEBUG $OPT_OZ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, -Oz optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -Oz optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -Oz optimizations")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, -Oz optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, -Oz optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DNDEBUG $OPT_OZ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, -Oz optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -Oz optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -Oz optimizations")
        fi
    fi
fi

############################################
# Build at -Ofast
if [[ "$HAVE_OFAST" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, -Ofast optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, -Ofast optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DDEBUG $OPT_OFAST $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, -Ofast optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -Ofast optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, -Ofast optimizations")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, -Ofast optimizations" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, -Ofast optimizations")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DNDEBUG $OPT_OFAST $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, -Ofast optimizations")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -Ofast optimizations")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, -Ofast optimizations")
        fi
    fi
fi

############################################
# Dead code stripping
if [[ ("$GNU_LINKER" -eq 1) ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, dead code strip" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, dead code strip")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" lean 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, dead code strip")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, dead code strip")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, dead code strip")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, dead code strip" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, dead code strip")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" lean 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, dead code strip")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, dead code strip")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, dead code strip")
        fi
    fi
fi

############################################
# OpenMP
if [[ ("$HAVE_OMP" -ne 0) ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, OpenMP" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, OpenMP")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DDEBUG ${OMP_FLAGS[*]} $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, OpenMP")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, OpenMP")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, OpenMP")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, OpenMP" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, OpenMP")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="-DNDEBUG ${OMP_FLAGS[*]} $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, OpenMP")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, OpenMP")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, OpenMP")
        fi
    fi
fi

############################################
# UBSan, c++03
if [[ ("$HAVE_CXX03" -ne 0 && "$HAVE_UBSAN" -ne 0) ]]; then

    ############################################
    # Debug build, UBSan, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++03, UBsan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++03, UBsan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++03, UBsan")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++03, UBsan")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++03, UBsan")
        fi
    fi

    ############################################
    # Release build, UBSan, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++03, UBsan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++03, UBsan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++03, UBsan")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++03, UBsan")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++03, UBsan")
        fi
    fi
fi

############################################
# Asan, c++03
if [[ ("$HAVE_CXX03" -ne 0 && "$HAVE_ASAN" -ne 0) ]]; then

    ############################################
    # Debug build, Asan, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++03, Asan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++03, Asan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++03, Asan")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++03, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++03, Asan")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++03, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++03, Asan")
            fi
        fi

    fi

    ############################################
    # Release build, Asan, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++03, Asan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++03, Asan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++03, Asan")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++03, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++03, Asan")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++03, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++03, Asan")
            fi
        fi
    fi
fi

############################################
# Bounds Sanitizer, c++03
if [[ ("$HAVE_CXX03" -ne 0 && "$HAVE_BSAN" -ne 0) ]]; then

    ############################################
    # Debug build, Bounds Sanitizer, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++03, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++03, Bounds Sanitizer")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 -fsanitize=bounds-strict $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++03, Bounds Sanitizer")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++03, Bounds Sanitizer")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++03, Bounds Sanitizer")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++03, Bounds Sanitizer")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++03, Bounds Sanitizer")
            fi
        fi

    fi

    ############################################
    # Release build, Bounds Sanitizer, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++03, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++03, Bounds Sanitizer")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -fsanitize=bounds-strict $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++03, Bounds Sanitizer")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++03, Bounds Sanitizer")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++03, Bounds Sanitizer")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++03, Bounds Sanitizer")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++03, Bounds Sanitizer")
            fi
        fi
    fi
fi

############################################
# Control-flow Enforcement Technology (CET), c++03
if [[ ("$HAVE_CXX03" -ne 0 && "$HAVE_CET" -ne 0) ]]; then

    ############################################
    # Debug build, CET, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++03, CET" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++03, CET")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 -fcf-protection=full -mcet $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++03, CET")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++03, CET")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++03, CET")
        fi
    fi

    ############################################
    # Release build, CET, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++03, CET" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++03, CET")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -fcf-protection=full -mcet $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++03, CET")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++03, CET")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++03, CET")
        fi
    fi
fi

############################################
# Specter, c++03
if [[ ("$HAVE_CXX03" -ne 0 && "$HAVE_REPTOLINE" -ne 0) ]]; then

    ############################################
    # Debug build, Specter, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++03, Specter" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++03, Specter")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++03, Specter")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++03, Specter")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++03, Specter")
        fi
    fi

    ############################################
    # Release build, Specter, c++03
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++03, Specter" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++03, Specter")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++03, Specter")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++03, Specter")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++03, Specter")
        fi
    fi
fi

############################################
# UBSan, c++11
if [[ ("$HAVE_CXX11" -ne 0 && "$HAVE_UBSAN" -ne 0) ]]; then

    ############################################
    # Debug build, UBSan, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++11, UBsan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++11, UBsan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++11, UBsan")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++11, UBsan")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++11, UBsan")
        fi
    fi

    ############################################
    # Release build, UBSan, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++11, UBsan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++11, UBsan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++11, UBsan")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++11, UBsan")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++11, UBsan")
        fi
    fi
fi

############################################
# Asan, c++11
if [[ ("$HAVE_CXX11" -ne 0 && "$HAVE_ASAN" -ne 0) ]]; then

    ############################################
    # Debug build, Asan, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++11, Asan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++11, Asan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++11, Asan")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++11, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++11, Asan")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++11, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++11, Asan")
            fi
        fi

    fi

    ############################################
    # Release build, Asan, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++11, Asan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++11, Asan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++11, Asan")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++11, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++11, Asan")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++11, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++11, Asan")
            fi
        fi
    fi
fi

############################################
# Bounds Sanitizer, c++11
if [[ ("$HAVE_CXX11" -ne 0 && "$HAVE_BSAN" -ne 0) ]]; then

    ############################################
    # Debug build, Bounds Sanitizer, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++11, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++11, Bounds Sanitizer")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 -fsanitize=bounds-strict $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++11, Bounds Sanitizer")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++11, Bounds Sanitizer")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++11, Bounds Sanitizer")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++11, Bounds Sanitizer")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Debug, c++11, Bounds Sanitizer")
            fi
        fi

    fi

    ############################################
    # Release build, Bounds Sanitizer, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++11, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++11, Bounds Sanitizer")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -fsanitize=bounds-strict $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++11, Bounds Sanitizer")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++11, Bounds Sanitizer")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++11, Bounds Sanitizer")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++11, Bounds Sanitizer")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++11, Bounds Sanitizer")
            fi
        fi
    fi
fi

############################################
# Control-flow Enforcement Technology (CET), c++11
if [[ ("$HAVE_CXX11" -ne 0 && "$HAVE_CET" -ne 0) ]]; then

    ############################################
    # Debug build, CET, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++11, CET" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++11, CET")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 -fcf-protection=full -mcet $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++11, CET")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++11, CET")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++11, CET")
        fi
    fi

    ############################################
    # Release build, CET, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++11, CET" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++11, CET")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -fcf-protection=full -mcet $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++11, CET")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++11, CET")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++11, CET")
        fi
    fi
fi

############################################
# Specter, c++11
if [[ ("$HAVE_CXX11" -ne 0 && "$HAVE_REPTOLINE" -ne 0) ]]; then

    ############################################
    # Debug build, Specter, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, c++11, Specter" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, c++11, Specter")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, c++11, Specter")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++11, Specter")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, c++11, Specter")
        fi
    fi

    ############################################
    # Release build, Specter, c++11
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++11, Specter" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++11, Specter")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++11, Specter")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++11, Specter")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++11, Specter")
        fi
    fi
fi

############################################
# Release build, UBSan, c++14
if [[ ("$HAVE_CXX14" -ne 0 && "$HAVE_UBSAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++14, UBsan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++14, UBsan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++14, UBsan")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14, UBsan")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14, UBsan")
        fi
    fi
fi

############################################
# Release build, Asan, c++14
if [[ ("$HAVE_CXX14" -ne 0 && "$HAVE_ASAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++14, Asan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++14, Asan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++14, Asan")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++14, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++14, Asan")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++14, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++14, Asan")
            fi
        fi
    fi
fi

############################################
# Release build, Bounds Sanitizer, c++14
if [[ ("$HAVE_CXX14" -ne 0 && "$HAVE_BSAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++14, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++14, Bounds Sanitizer")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -fsanitize=bounds-strict $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++14, Bounds Sanitizer")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14, Bounds Sanitizer")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14, Bounds Sanitizer")
        fi
    fi
fi

############################################
# Release build, Control-flow Enforcement Technology (CET), c++14
if [[ ("$HAVE_CXX14" -ne 0 && "$HAVE_CET" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++14, CET" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++14, CET")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -fcf-protection=full -mcet $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++14, CET")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14, CET")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14, CET")
        fi
    fi
fi

############################################
# Release build, Specter, c++14
if [[ ("$HAVE_CXX14" -ne 0 && "$HAVE_REPTOLINE" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++14, Specter" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++14, Specter")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++14, Specter")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14, Specter")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++14, Specter")
        fi
    fi
fi

############################################
# Release build, UBSan, c++17
if [[ ("$HAVE_CXX17" -ne 0 && "$HAVE_UBSAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++17, UBsan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++17, UBsan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++17, UBsan")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17, UBsan")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17, UBsan")
        fi
    fi
fi

############################################
# Release build, Asan, c++17
if [[ ("$HAVE_CXX17" -ne 0 && "$HAVE_ASAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++17, Asan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++17, Asan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++17, Asan")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++17, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++17, Asan")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++17, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++17, Asan")
            fi
        fi
    fi
fi

############################################
# Release build, Bounds Sanitizer, c++17
if [[ ("$HAVE_CXX17" -ne 0 && "$HAVE_BSAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++17, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++17, Bounds Sanitizer")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -fsanitize=bounds-strict $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++17, Bounds Sanitizer")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17, Bounds Sanitizer")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17, Bounds Sanitizer")
        fi
    fi
fi

############################################
# Release build, Control-flow Enforcement Technology (CET), c++17
if [[ ("$HAVE_CXX17" -ne 0 && "$HAVE_CET" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++17, CET" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++17, CET")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -fcf-protection=full -mcet $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++17, CET")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17, CET")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17, CET")
        fi
    fi
fi

############################################
# Release build, Specter, c++17
if [[ ("$HAVE_CXX17" -ne 0 && "$HAVE_REPTOLINE" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++17, Specter" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++17, Specter")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++17, Specter")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17, Specter")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++17, Specter")
        fi
    fi
fi

############################################
# Release build, UBSan, c++20
if [[ ("$HAVE_CXX20" -ne 0 && "$HAVE_UBSAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++20, UBsan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++20, UBsan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" ubsan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++20, UBsan")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20, UBsan")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20, UBsan")
        fi
    fi
fi

############################################
# Release build, Asan, c++20
if [[ ("$HAVE_CXX20" -ne 0 && "$HAVE_ASAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++20, Asan" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++20, Asan")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" asan | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++20, Asan")
    else
        if [[ ("$HAVE_SYMBOLIZE" -ne 0) ]]; then
            ./cryptest.exe vv 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++20, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | "$ASAN_SYMBOLIZE" 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++20, Asan")
            fi
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++20, Asan")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Release, c++20, Asan")
            fi
        fi
    fi
fi

############################################
# Release build, Bounds Sanitizer, c++20
if [[ ("$HAVE_CXX20" -ne 0 && "$HAVE_BSAN" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++20, Bounds Sanitizer" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++20, Bounds Sanitizer")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 -fsanitize=bounds-strict $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++20, Bounds Sanitizer")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20, Bounds Sanitizer")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20, Bounds Sanitizer")
        fi
    fi
fi

############################################
# Release build, Control-flow Enforcement Technology (CET), c++20
if [[ ("$HAVE_CXX20" -ne 0 && "$HAVE_CET" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++20, CET" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++20, CET")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 -fcf-protection=full -mcet $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++20, CET")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20, CET")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20, CET")
        fi
    fi
fi

############################################
# Release build, Specter, c++20
if [[ ("$HAVE_CXX20" -ne 0 && "$HAVE_REPTOLINE" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, c++20, Specter" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, c++20, Specter")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 -mfunction-return=thunk -mindirect-branch=thunk $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, c++20, Specter")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20, Specter")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, c++20, Specter")
        fi
    fi
fi

############################################
# Analyze debug and release build
if [[ "$HAVE_ANALYZER" -ne 0 ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Debug, Analyze" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Debug, Analyze")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -fanalyzer $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Debug, Analyze")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, Analyze")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Debug, Analyze")
        fi
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Release, Analyze" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Release, Analyze")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -fanalyzer $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Release, Analyze")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, Analyze")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Release, Analyze")
        fi
    fi
fi

############################################
# For Solaris, test under Sun Studio 12.2 - 12.5
if [[ "$IS_SOLARIS" -ne 0 ]]; then

    ############################################
    # Sun Studio 12.2/SunCC 5.11
    if [[ (-e "/opt/solstudio12.2/bin/CC") ]]; then

        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.2, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.2, debug, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DDEBUG -g -xO0"
        CXX="/opt/solstudio12.2/bin/CC" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.2, debug, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.2, debug, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.2, debug, platform CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.2, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.2, release, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g -xO2"
        CXX="/opt/solstudio12.2/bin/CC" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.2, release, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.2, release, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.2, release, platform CXXFLAGS")
            fi
        fi
    fi

    ############################################
    # Sun Studio 12.3/SunCC 5.12
    if [[ (-e "/opt/solarisstudio12.3/bin/CC") ]]; then

        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.3, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.3, debug, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DDEBUG -g3 -xO0"
        CXX=/opt/solarisstudio12.3/bin/CC CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.3, debug, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.3, debug, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.3, debug, platform CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.3, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.3, release, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g3 -xO2"
        CXX=/opt/solarisstudio12.3/bin/CC CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.3, release, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.3, release, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.3, release, platform CXXFLAGS")
            fi
        fi
    fi

    ############################################
    # Sun Studio 12.4/SunCC 5.13
    if [[ (-e "/opt/solarisstudio12.4/bin/CC") ]]; then

        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.4, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.4, debug, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DDEBUG -g3 -xO0"
        CXX=/opt/solarisstudio12.4/bin/CC CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.4, debug, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.4, debug, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.4, debug, platform CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.4, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.4, release, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g2 -xO2"
        CXX=/opt/solarisstudio12.4/bin/CC CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.4, release, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.4, release, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.4, release, platform CXXFLAGS")
            fi
        fi
    fi

    ############################################
    # Sun Studio 12.5/SunCC 5.14
    if [[ (-e "/opt/developerstudio12.5/bin/CC") ]]; then

        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.5, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.5, debug, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DDEBUG -g3 -xO1"
        CXX=/opt/developerstudio12.5/bin/CC CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.5, debug, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.5, debug, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.5, debug, platform CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.5, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.5, release, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g2 -xO2"
        CXX=/opt/developerstudio12.5/bin/CC CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.5, release, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.5, release, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.5, release, platform CXXFLAGS")
            fi
        fi
    fi

    ############################################
    # Sun Studio 12.6/SunCC 5.15
    if [[ (-e "/opt/developerstudio12.6/bin/CC") ]]; then

        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.6, debug, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.6, debug, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DDEBUG -g3 -xO1"
        CXX=/opt/developerstudio12.6/bin/CC CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.6, debug, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.6, debug, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.6, debug, platform CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Sun Studio 12.6, release, platform CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Sun Studio 12.6, release, platform CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g2 -xO2"
        CXX=/opt/developerstudio12.6/bin/CC CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Sun Studio 12.6, release, platform CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.6, release, platform CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Sun Studio 12.6, release, platform CXXFLAGS")
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

        TEST_LIST+=("Solaris GCC, debug, default CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DDEBUG -g3 -O0"
        CXX="/bin/g++" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Solaris GCC, debug, default CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Solaris GCC, debug, default CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Solaris GCC, debug, default CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Solaris GCC, release, default CXXFLAGS" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Solaris GCC, release, default CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g2 -O3"
        CXX="/bin/g++" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Solaris GCC, release, default CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Solaris GCC, release, default CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Solaris GCC, release, default CXXFLAGS")
            fi
        fi
    fi
fi

# For Darwin, we need to test both -stdlib=libstdc++ (GNU) and
#  -stdlib=libc++ (LLVM) crossed with -std=c++03, -std=c++11, and -std=c++17

############################################
# Darwin, c++03, libc++
if [[ ("$IS_DARWIN" -ne 0) && ("$HAVE_CXX03" -ne 0 && "$CLANG_COMPILER" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++03, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++03, libc++ (LLVM)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -stdlib=libc++ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++03, libc++ (LLVM)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++03, libc++ (LLVM)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++03, libc++ (LLVM)")
        fi
    fi
fi

############################################
# Darwin, c++03, libstdc++
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX03" -ne 0) && ("$HAVE_LIBSTDCXX" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++03, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++03, libstdc++ (GNU)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 -stdlib=libstdc++ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++03, libstdc++ (GNU)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++03, libstdc++ (GNU)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++03, libstdc++ (GNU)")
        fi
    fi
fi

############################################
# Darwin, c++11, libc++
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX11" -ne 0 && "$CLANG_COMPILER" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++11, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++11, libc++ (LLVM)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -stdlib=libc++ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++11, libc++ (LLVM)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++11, libc++ (LLVM)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++11, libc++ (LLVM)")
        fi
    fi
fi

############################################
# Darwin, c++11, libstdc++
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX11" -ne 0) && ("$HAVE_LIBSTDCXX" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++11, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++11, libstdc++ (GNU)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 -stdlib=libstdc++ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++11, libstdc++ (GNU)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++11, libstdc++ (GNU)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++11, libstdc++ (GNU)")
        fi
    fi
fi

############################################
# Darwin, c++14, libc++
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX14" -ne 0 && "$CLANG_COMPILER" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++14, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++14, libc++ (LLVM)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -stdlib=libc++ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++14, libc++ (LLVM)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++14, libc++ (LLVM)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++14, libc++ (LLVM)")
        fi
    fi
fi

############################################
# Darwin, c++14, libstdc++
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX14" -ne 0) && ("$HAVE_LIBSTDCXX" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++14, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++14, libstdc++ (GNU)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 -stdlib=libstdc++ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++14, libstdc++ (GNU)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++14, libstdc++ (GNU)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++14, libstdc++ (GNU)")
        fi
    fi
fi

############################################
# Darwin, c++17, libc++
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX17" -ne 0 && "$CLANG_COMPILER" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++17, libc++ (LLVM)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++17, libc++ (LLVM)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -stdlib=libc++ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++17, libc++ (LLVM)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++17, libc++ (LLVM)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++17, libc++ (LLVM)")
        fi
    fi
fi

############################################
# Darwin, c++17, libstdc++
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX17" -ne 0) && ("$HAVE_LIBSTDCXX" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++17, libstdc++ (GNU)" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++17, libstdc++ (GNU)")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 -stdlib=libstdc++ $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++17, libstdc++ (GNU)")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++17, libstdc++ (GNU)")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++17, libstdc++ (GNU)")
        fi
    fi
fi

############################################
# Darwin, Intel multiarch, c++03
if [[ "$IS_DARWIN" -ne 0 && "$HAVE_INTEL_MULTIARCH" -ne 0 && "$HAVE_CXX03" -ne 0 ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, Intel multiarch, c++03" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, Intel multiarch, c++03")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, Intel multiarch, c++03")
    else
        echo "Running i386 version..."
        arch -i386 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (i386), c++03")
        fi
        arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (i386), c++03")
        fi

        echo "Running x86_64 version..."
        arch -x86_64 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (x86_64), c++03")
        fi
        arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (x86_64), c++03")
        fi
    fi
fi

############################################
# Darwin, Intel multiarch, c++11
if [[ "$IS_DARWIN" -ne 0 && "$HAVE_INTEL_MULTIARCH" -ne 0 && "$HAVE_CXX11" -ne 0 ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, Intel multiarch, c++11" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, Intel multiarch, c++11")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, Intel multiarch, c++11")
    else
        echo "Running i386 version..."
        arch -i386 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (i386), c++11")
        fi
        arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (i386), c++11")
        fi

        echo "Running x86_64 version..."
        arch -x86_64 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (x86_64), c++11")
        fi
        arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (x86_64), c++11")
        fi
    fi
fi

############################################
# Darwin, Intel multiarch, c++14
if [[ "$IS_DARWIN" -ne 0 && "$HAVE_INTEL_MULTIARCH" -ne 0 && "$HAVE_CXX14" -ne 0 ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, Intel multiarch, c++14" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, Intel multiarch, c++14")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, Intel multiarch, c++14")
    else
        echo "Running i386 version..."
        arch -i386 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (i386), c++14")
        fi
        arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (i386), c++14")
        fi

        echo "Running x86_64 version..."
        arch -x86_64 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (x86_64), c++14")
        fi
        arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (x86_64), c++14")
        fi
    fi
fi

############################################
# Darwin, Intel multiarch, c++17
if [[ "$IS_DARWIN" -ne 0 && "$HAVE_INTEL_MULTIARCH" -ne 0 && "$HAVE_CXX17" -ne 0 ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, Intel multiarch, c++17" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, Intel multiarch, c++17")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -arch i386 -arch x86_64 -std=c++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, Intel multiarch, c++17")
    else
        echo "Running i386 version..."
        arch -i386 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (i386)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (i386), c++17")
        fi
        arch -i386 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (i386)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (i386), c++17")
        fi

        echo "Running x86_64 version..."
        arch -x86_64 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (x86_64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (x86_64), c++17")
        fi
        arch -x86_64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (x86_64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, Intel multiarch (x86_64), c++17")
        fi
    fi
fi

############################################
# Darwin, PowerPC multiarch
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_PPC_MULTIARCH" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, PowerPC multiarch" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, PowerPC multiarch")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -arch ppc -arch ppc64 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, PowerPC multiarch")
    else
        echo "Running PPC version..."
        arch -ppc ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (PPC)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, PowerPC multiarch (PPC)")
        fi
        arch -ppc ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (PPC)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, PowerPC multiarch (PPC)")
        fi

        echo "Running PPC64 version..."
        arch -ppc64 ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite (PPC64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, PowerPC multiarch (PPC64)")
        fi
        arch -ppc64 ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors (PPC64)" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, PowerPC multiarch (PPC64)")
        fi
    fi
fi

############################################
# Darwin, c++03, Malloc Guards
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX03" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++03, Malloc Guards" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++03, Malloc Guards")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++03, Malloc Guards")
    else
        export MallocScribble=1
        export MallocPreScribble=1
        export MallocGuardEdges=1

        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++03, Malloc Guards")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++03, Malloc Guards")
        fi

        unset MallocScribble MallocPreScribble MallocGuardEdges
    fi
fi

############################################
# Darwin, c++11, Malloc Guards
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX11" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++11, Malloc Guards" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++11, Malloc Guards")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++11, Malloc Guards")
    else
        export MallocScribble=1
        export MallocPreScribble=1
        export MallocGuardEdges=1

        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++11, Malloc Guards")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++11, Malloc Guards")
        fi

        unset MallocScribble MallocPreScribble MallocGuardEdges
    fi
fi

############################################
# Darwin, c++14, Malloc Guards
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX14" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++14, Malloc Guards" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++14, Malloc Guards")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++14, Malloc Guards")
    else
        export MallocScribble=1
        export MallocPreScribble=1
        export MallocGuardEdges=1

        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++14, Malloc Guards")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++14, Malloc Guards")
        fi

        unset MallocScribble MallocPreScribble MallocGuardEdges
    fi
fi

############################################
# Darwin, c++17, Malloc Guards
if [[ ("$IS_DARWIN" -ne 0 && "$HAVE_CXX17" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Darwin, c++17, Malloc Guards" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Darwin, c++17, Malloc Guards")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Darwin, c++17, Malloc Guards")
    else
        export MallocScribble=1
        export MallocPreScribble=1
        export MallocGuardEdges=1

        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++17, Malloc Guards")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Darwin, c++17, Malloc Guards")
        fi

        unset MallocScribble MallocPreScribble MallocGuardEdges
    fi
fi

############################################
# Benchmarks
if [[ "$WANT_BENCHMARKS" -ne 0 ]]; then

    ############################################
    # Benchmarks, c++03
    if [[ "$HAVE_CXX03" -ne 0 ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Benchmarks, c++03" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Benchmarks, c++03")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Benchmarks, c++03")
        else
            echo "**************************************" >> "$BENCHMARK_RESULTS"
            ./cryptest.exe b 3 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute benchmarks" | tee -a "$BENCHMARK_RESULTS"
                FAILED_LIST+=("Benchmarks, c++03")
            fi
        fi
    fi

    ############################################
    # Benchmarks, c++11
    if [[ "$HAVE_CXX11" -ne 0 ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Benchmarks, c++11" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Benchmarks, c++11")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Benchmarks, c++11")
        else
            echo "**************************************" >> "$BENCHMARK_RESULTS"
            ./cryptest.exe b 3 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute benchmarks" | tee -a "$BENCHMARK_RESULTS"
                FAILED_LIST+=("Benchmarks, c++11")
            fi
        fi
    fi

    ############################################
    # Benchmarks, c++14
    if [[ "$HAVE_CXX14" -ne 0 ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Benchmarks, c++14" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Benchmarks, c++14")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Benchmarks, c++14")
        else
            echo "**************************************" >> "$BENCHMARK_RESULTS"
            ./cryptest.exe b 3 "$CPU_FREQ" 2>&1 | tee -a "$BENCHMARK_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute benchmarks" | tee -a "$BENCHMARK_RESULTS"
                FAILED_LIST+=("Benchmarks, c++14")
            fi
        fi
    fi
fi

############################################
# MinGW
if [[ "$IS_MINGW" -ne 0 ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: MinGW" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("MinGW")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("MinGW")
    else
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("MinGW")
        fi
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("MinGW")
        fi
    fi
fi

############################################
# Valgrind, c++03. Requires -O1 for accurate results
if [[ "$HAVE_CXX03" -ne 0 && "$HAVE_VALGRIND" -ne 0 ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Valgrind, c++03" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Valgrind, c++03")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++03 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Valgrind, c++03")
    else
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
    fi
fi

############################################
# Valgrind, c++11. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne 0 && "$HAVE_CXX11" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Valgrind, c++11" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Valgrind, c++11")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++11 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Valgrind, c++11")
    else
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
    fi
fi

############################################
# Valgrind, c++14. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne 0 && "$HAVE_CXX14" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Valgrind, c++14" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Valgrind, c++14")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++14 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Valgrind, c++14")
    else
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
    fi
fi

############################################
# Valgrind, c++17. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne 0 && "$HAVE_CXX17" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Valgrind, c++17" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Valgrind, c++17")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++17 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Valgrind, c++17")
    else
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
    fi
fi

############################################
# Valgrind, c++20. Requires -O1 for accurate results
if [[ ("$HAVE_VALGRIND" -ne 0 && "$HAVE_CXX20" -ne 0) ]]; then
    echo
    echo "************************************" | tee -a "$TEST_RESULTS"
    echo "Testing: Valgrind, c++20" | tee -a "$TEST_RESULTS"
    echo

    TEST_LIST+=("Valgrind, c++20")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$VALGRIND_CXXFLAGS -std=c++20 $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
        FAILED_LIST+=("Valgrind, c++20")
    else
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
        valgrind --track-origins=yes --suppressions=cryptopp.supp ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
    fi
fi

############################################
# C++03 with elevated warnings
if [[ ("$HAVE_CXX03" -ne 0 && ("$GCC_COMPILER" -ne 0 || "$CLANG_COMPILER" -ne 0)) ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Debug, c++03, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Debug, c++03, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++03 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Debug, c++03, elevated warnings")
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Release, c++03, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Release, c++03, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++03 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
    if [[ "$?" -ne 0 ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Debug, c++03, elevated warnings")
    fi
fi

############################################
# C++11 with elevated warnings
if [[ ("$HAVE_CXX11" -ne 0 && ("$GCC_COMPILER" -ne 0 || "$CLANG_COMPILER" -ne 0)) ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Debug, c++11, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Debug, c++11, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++11 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Debug, c++11, elevated warnings")
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Release, c++11, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Release, c++11, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++11 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
    if [[ "$?" -ne 0 ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Release, c++11, elevated warnings")
    fi
fi

############################################
# C++14 with elevated warnings
if [[ ("$HAVE_CXX14" -ne 0 && ("$GCC_COMPILER" -ne 0 || "$CLANG_COMPILER" -ne 0)) ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Debug, c++14, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Debug, c++14, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++14 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Debug, c++14, elevated warnings")
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Release, c++14, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Release, c++14, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++14 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"
    if [[ "$?" -ne 0 ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Release, c++14, elevated warnings")
    fi
fi

############################################
# C++17 with elevated warnings
if [[ ("$HAVE_CXX17" -ne 0 && ("$GCC_COMPILER" -ne 0 || "$CLANG_COMPILER" -ne 0)) ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Debug, c++17, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Debug, c++17, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++17 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Debug, c++17, elevated warnings")
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Release, c++17, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Release, c++17, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++17 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

    if [[ "$?" -ne 0 ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Release, c++17, elevated warnings")
    fi
fi

############################################
# C++20 with elevated warnings
if [[ ("$HAVE_CXX20" -ne 0 && ("$GCC_COMPILER" -ne 0 || "$CLANG_COMPILER" -ne 0)) ]]; then

    ############################################
    # Debug build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Debug, c++20, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Debug, c++20, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$DEBUG_CXXFLAGS -std=c++20 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Debug, c++20, elevated warnings")
    fi

    ############################################
    # Release build
    echo
    echo "************************************" | tee -a "$WARN_RESULTS"
    echo "Testing: Release, c++20, elevated warnings" | tee -a "$WARN_RESULTS"
    echo

    TEST_LIST+=("Release, c++20, elevated warnings")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -std=c++20 ${WARNING_CXXFLAGS[*]}"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$WARN_RESULTS"

    if [[ "$?" -ne 0 ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$WARN_RESULTS"
        FAILED_LIST+=("Release, c++20, elevated warnings")
    fi
fi

############################################
# Perform a quick check with Clang, if available.
#   This check was added after testing on Ubuntu 14.04 with Clang 3.4.
if [[ ("$CLANG_COMPILER" -eq 0) ]]; then

    CLANG_CXX=$(command -v clang++ 2>/dev/null)
    "$CLANG_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then

        ############################################
        # Clang build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Clang compiler" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Clang compiler")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g2 -O3"
        CXX="$CLANG_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Clang compiler")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Clang compiler")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Clang compiler")
            fi
        fi
    fi
fi

############################################
# Perform a quick check with GCC, if available.
if [[ ("$GCC_COMPILER" -eq 0) ]]; then

    GCC_CXX=$(command -v g++ 2>/dev/null)
    "$GCC_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then

        ############################################
        # GCC build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: GCC compiler" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("GCC compiler")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g2 -O3"
        CXX="$GCC_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("GCC compiler")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("GCC compiler")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("GCC compiler")
            fi
        fi
    fi
fi

############################################
# Perform a quick check with Intel ICPC, if available.
if [[ ("$INTEL_COMPILER" -eq 0) ]]; then

    INTEL_CXX=$(command -v icpc 2>/dev/null)
    if [[ (-z "$INTEL_CXX") ]]; then
        INTEL_CXX=$(find /opt/intel -name icpc 2>/dev/null | "${GREP}" -iv composer | head -1)
    fi
    "$INTEL_CXX" -x c++ -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
    if [[ "$?" -eq 0 ]]; then

        ############################################
        # Intel build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Intel compiler" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Intel compiler")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g2 -O3"
        CXX="$INTEL_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Intel compiler")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Intel compiler")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Intel compiler")
            fi
        fi
    fi
fi

############################################
# Perform a quick check with MacPorts compilers, if available.
if [[ ("$IS_DARWIN" -ne 0 && "$MACPORTS_COMPILER" -eq 0) ]]; then

    MACPORTS_CXX=$(find /opt/local/bin -name 'g++-mp-4*' 2>/dev/null | head -1)
    if [[ (-n "$MACPORTS_CXX") ]]; then
        "$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then

            ############################################
            # MacPorts GCC 4.x build
            echo
            echo "************************************" | tee -a "$TEST_RESULTS"
            echo "Testing: MacPorts 4.x GCC compiler" | tee -a "$TEST_RESULTS"
            echo

            TEST_LIST+=("MacPorts 4.x GCC compiler")

            "$MAKE" clean &>/dev/null
            rm -f "${TMPDIR}/test.exe" &>/dev/null

            # We want to use -stdlib=libstdc++ below, but it causes a compile error. Maybe MacPorts hardwired libc++.
            CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"
            CXX="$MACPORTS_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("MacPorts 4.x GCC compiler")
            else
                ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 4.x GCC compiler")
                fi
                ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 4.x GCC compiler")
                fi
            fi
        fi
    fi

    MACPORTS_CXX=$(find /opt/local/bin -name 'g++-mp-5*' 2>/dev/null | head -1)
    if [[ (-n "$MACPORTS_CXX") ]]; then
        "$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then

            ############################################
            # MacPorts GCC 5.x build
            echo
            echo "************************************" | tee -a "$TEST_RESULTS"
            echo "Testing: MacPorts 5.x GCC compiler" | tee -a "$TEST_RESULTS"
            echo

            TEST_LIST+=("MacPorts 5.x GCC compiler")

            "$MAKE" clean &>/dev/null
            rm -f "${TMPDIR}/test.exe" &>/dev/null

            # We want to use -stdlib=libstdc++ below, but it causes a compile error. Maybe MacPorts hardwired libc++.
            CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"
            CXX="$MACPORTS_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("MacPorts 5.x GCC compiler")
            else
                ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 5.x GCC compiler")
                fi
                ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 5.x GCC compiler")
                fi
            fi
        fi
    fi

    MACPORTS_CXX=$(find /opt/local/bin -name 'g++-mp-6*' 2>/dev/null | head -1)
    if [[ (-n "$MACPORTS_CXX") ]]; then
        "$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then

            ############################################
            # MacPorts GCC 6.x build
            echo
            echo "************************************" | tee -a "$TEST_RESULTS"
            echo "Testing: MacPorts 6.x GCC compiler" | tee -a "$TEST_RESULTS"
            echo

            TEST_LIST+=("MacPorts 6.x GCC compiler")

            "$MAKE" clean &>/dev/null
            rm -f "${TMPDIR}/test.exe" &>/dev/null

            # We want to use -stdlib=libstdc++ below, but it causes a compile error. Maybe MacPorts hardwired libc++.
            CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"
            CXX="$MACPORTS_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("MacPorts 6.x GCC compiler")
            else
                ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 6.x GCC compiler")
                fi
                ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 6.x GCC compiler")
                fi
            fi
        fi
    fi

    MACPORTS_CXX=$(find /opt/local/bin -name 'g++-mp-7*' 2>/dev/null | head -1)
    if [[ (-n "$MACPORTS_CXX") ]]; then
        "$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then

            ############################################
            # MacPorts GCC 7.x build
            echo
            echo "************************************" | tee -a "$TEST_RESULTS"
            echo "Testing: MacPorts 7.x GCC compiler" | tee -a "$TEST_RESULTS"
            echo

            TEST_LIST+=("MacPorts 7.x GCC compiler")

            "$MAKE" clean &>/dev/null
            rm -f "${TMPDIR}/test.exe" &>/dev/null

            # We want to use -stdlib=libstdc++ below, but it causes a compile error. Maybe MacPorts hardwired libc++.
            CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"
            CXX="$MACPORTS_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("MacPorts 7.x GCC compiler")
            else
                ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 7.x GCC compiler")
                fi
                ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 7.x GCC compiler")
                fi
            fi
        fi
    fi

    MACPORTS_CXX=$(find /opt/local/bin -name 'clang++-mp-3.9*' 2>/dev/null | head -1)
    if [[ (-n "$MACPORTS_CXX") ]]; then
        "$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then

            ############################################
            # MacPorts 3.9 Clang build
            echo
            echo "************************************" | tee -a "$TEST_RESULTS"
            echo "Testing: MacPorts 3.9 Clang compiler" | tee -a "$TEST_RESULTS"
            echo

            TEST_LIST+=("MacPorts 3.9 Clang compiler")

            "$MAKE" clean &>/dev/null
            rm -f "${TMPDIR}/test.exe" &>/dev/null

            CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11 -stdlib=libc++"
            CXX="$MACPORTS_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("MacPorts 3.9 Clang compiler")
            else
                ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 3.9 Clang compiler")
                fi
                ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 3.9 Clang compiler")
                fi
            fi
        fi
    fi

    MACPORTS_CXX=$(find /opt/local/bin -name 'clang++-mp-4*' 2>/dev/null | head -1)
    if [[ (-n "$MACPORTS_CXX") ]]; then
        "$MACPORTS_CXX" -x c++ -std=c++11 -DCRYPTOPP_ADHOC_MAIN "${test_prog}".proto -o "${TMPDIR}/test.exe" &>/dev/null
        if [[ "$?" -eq 0 ]]; then

            ############################################
            # MacPorts 4.x Clang build
            echo
            echo "************************************" | tee -a "$TEST_RESULTS"
            echo "Testing: MacPorts 4.x Clang compiler" | tee -a "$TEST_RESULTS"
            echo

            TEST_LIST+=("MacPorts 4.x Clang compiler")

            "$MAKE" clean &>/dev/null
            rm -f "${TMPDIR}/test.exe" &>/dev/null

            CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11 -stdlib=libc++"
            CXX="$MACPORTS_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("MacPorts 4.x Clang compiler")
            else
                ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 4.x Clang compiler")
                fi
                ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
                if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                    echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                    FAILED_LIST+=("MacPorts 4.x Clang compiler")
                fi
            fi
        fi
    fi
fi

############################################
# Perform a quick check with Xcode compiler, if available.
if [[ "$IS_DARWIN" -ne 0 ]]; then
    XCODE_CXX=$(find /Applications/Xcode*.app/Contents/Developer -name clang++ 2>/dev/null | head -1)
    if [[ (-z "$XCODE_CXX") ]]; then
        XCODE_CXX=$(find /Developer/Applications/Xcode.app -name clang++ 2>/dev/null | head -1)
    fi

    if [[ ! (-z "$XCODE_CXX") ]]; then
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Xcode Clang compiler" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Xcode Clang compiler")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="-DNDEBUG -g2 -O3"
        CXX="$XCODE_CXX" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Xcode Clang compiler")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Xcode Clang compiler")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Xcode Clang compiler")
            fi
        fi
    fi
fi

############################################
# Test an install with CRYPTOPP_DATA_DIR
if [[ ("$IS_CYGWIN" -eq 0) && ("$IS_MINGW" -eq 0) ]]; then

    echo
    echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
    echo "Testing: Install with data directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
    echo

    TEST_LIST+=("Install with data directory")

    "$MAKE" clean &>/dev/null
    rm -f "${TMPDIR}/test.exe" &>/dev/null

    INSTALL_DIR="${TMPDIR}/cryptopp_test"
    rm -rf "$INSTALL_DIR" &>/dev/null

    CXXFLAGS="$RELEASE_CXXFLAGS -DCRYPTOPP_DATA_DIR='\"$INSTALL_DIR/share/cryptopp/\"' $USER_CXXFLAGS"
    CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"

    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        FAILED_LIST+=("Install with data directory")
    else
        OLD_DIR=$(pwd)
        "$MAKE" "${MAKEARGS[@]}" install PREFIX="$INSTALL_DIR" 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        cd "$INSTALL_DIR/bin" || exit

        echo
        echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        echo "Testing: Install (validation suite)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        echo
        ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Install with data directory")
        fi

        echo
        echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        echo "Testing: Install (test vectors)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        echo
        ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Install with data directory")
        fi

        if [[ "$WANT_BENCHMARKS" -ne 0 ]]; then
            echo
            echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            echo "Testing: Install (benchmarks)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            echo
            ./cryptest.exe b 1 "$CPU_FREQ" 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute benchmarks" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
                FAILED_LIST+=("Install with data directory")
            fi
        fi

        echo
        echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        echo "Testing: Install (help file)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        echo
        ./cryptest.exe h 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to provide help" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Install with data directory")
        fi

        echo
        echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        echo "Testing: Install (no command)" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        echo
        ./cryptest.exe h 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        if [[ ("${PIPESTATUS[0]}" -ne 1) ]]; then
            echo "ERROR: failed to provide help" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Install with data directory")
        fi

        # Restore original PWD
        cd "$OLD_DIR" || exit
    fi
fi

############################################
# Test a remove with CRYPTOPP_DATA_DIR
if [[ ("$IS_CYGWIN" -eq 0 && "$IS_MINGW" -eq 0) ]]; then

    echo
    echo "************************************" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
    echo "Testing: Remove with data directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
    echo

    TEST_LIST+=("Remove with data directory")

    "$MAKE" "${MAKEARGS[@]}" remove PREFIX="$INSTALL_DIR" 2>&1 | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
    if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
        echo "ERROR: failed to make remove" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
        FAILED_LIST+=("Remove with data directory")
    else
        # Test for complete removal
        if [[ (-d "$INSTALL_DIR/include/cryptopp") ]]; then
            echo "ERROR: failed to remove cryptopp include directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Remove with data directory")
        fi
        if [[ (-d "$INSTALL_DIR/share/cryptopp") ]]; then
            echo "ERROR: failed to remove cryptopp share directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Remove with data directory")
        fi
        if [[ (-d "$INSTALL_DIR/share/cryptopp/TestData") ]]; then
            echo "ERROR: failed to remove cryptopp test data directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Remove with data directory")
        fi
        if [[ (-d "$INSTALL_DIR/share/cryptopp/TestVector") ]]; then
            echo "ERROR: failed to remove cryptopp test vector directory" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Remove with data directory")
        fi
        if [[ (-e "$INSTALL_DIR/bin/cryptest.exe") ]]; then
            echo "ERROR: failed to remove cryptest.exe program" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Remove with data directory")
        fi
        if [[ (-e "$INSTALL_DIR/lib/libcryptopp.a") ]]; then
            echo "ERROR: failed to remove libcryptopp.a static library" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Remove with data directory")
        fi
        if [[ "$IS_DARWIN" -ne 0 && (-e "$INSTALL_DIR/lib/libcryptopp.dylib") ]]; then
            echo "ERROR: failed to remove libcryptopp.dylib dynamic library" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Remove with data directory")
        elif [[ (-e "$INSTALL_DIR/lib/libcryptopp.so") ]]; then
            echo "ERROR: failed to remove libcryptopp.so dynamic library" | tee -a "$TEST_RESULTS" "$INSTALL_RESULTS"
            FAILED_LIST+=("Remove with data directory")
        fi
    fi
fi

############################################
# Test latest zip with unzip -a
if command -v zip &>/dev/null && command -v unzip &>/dev/null; then

    if command -v wget &>/dev/null; then
        FETCH_CMD="wget -q -O"
    elif command -v curl &>/dev/null; then
        FETCH_CMD="curl -s -o"
    else
        FETCH_CMD="wget-and-curl-not-found"
    fi

    major=8; minor=9; rev=0
    filebase="cryptopp${major}${minor}${rev}"
    filename="${filebase}.zip"
    url="https://cryptopp.com/${filename}"

    rm -rf "${filebase}" 2>/dev/null
    if ${FETCH_CMD} ${filename} "${url}";
    then
        unzip -aoq "${filename}" -d "${filebase}"
        cd "${filebase}" || exit 1

        ############################################
        # Debug build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Latest zip, unzip -a, Debug" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Latest zip, unzip -a, Debug CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$DEBUG_CXXFLAGS"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Latest zip, unzip -a, Debug CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Latest zip, unzip -a, Debug CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Latest zip, unzip -a, Debug CXXFLAGS")
            fi
        fi

        ############################################
        # Release build
        echo
        echo "************************************" | tee -a "$TEST_RESULTS"
        echo "Testing: Latest zip, unzip -a, Release" | tee -a "$TEST_RESULTS"
        echo

        TEST_LIST+=("Latest zip, unzip -a, Release CXXFLAGS")

        "$MAKE" clean &>/dev/null
        rm -f "${TMPDIR}/test.exe" &>/dev/null

        CXXFLAGS="$RELEASE_CXXFLAGS"
        CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" "$MAKE" "${MAKEARGS[@]}" static dynamic cryptest.exe 2>&1 | tee -a "$TEST_RESULTS"

        if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
            echo "ERROR: failed to make cryptest.exe" | tee -a "$TEST_RESULTS"
            FAILED_LIST+=("Latest zip, unzip -a, Release CXXFLAGS")
        else
            ./cryptest.exe vv 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute validation suite" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Latest zip, unzip -a, Release CXXFLAGS")
            fi
            ./cryptest.exe tv all 2>&1 | tee -a "$TEST_RESULTS"
            if [[ ("${PIPESTATUS[0]}" -ne 0) ]]; then
                echo "ERROR: failed to execute test vectors" | tee -a "$TEST_RESULTS"
                FAILED_LIST+=("Latest zip, unzip -a, Release CXXFLAGS")
            fi
            echo
        fi

        cd ../ || exit 1
        rm -rf "${filebase}"
    else
        FAILED_LIST+=("Latest zip, unzip -a")
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
"$MAKE" clean &>/dev/null
rm -f "${TMPDIR}/test.exe" &>/dev/null

############################################
# Report tests performed

echo
echo "************************************************" | tee -a "$TEST_RESULTS"
echo "************************************************" | tee -a "$TEST_RESULTS"
echo "" | tee -a "$TEST_RESULTS"

COUNT="${#TEST_LIST[@]}"
if (( "$COUNT" == "0" )); then
    echo "No configurations tested" | tee -a "$TEST_RESULTS"
else
    echo "$COUNT configurations tested" | tee -a "$TEST_RESULTS"
    for TEST in "${TEST_LIST[@]}"
    do
      echo "  - $TEST" | tee -a "$TEST_RESULTS"
    done
fi
echo "" | tee -a "$TEST_RESULTS"

############################################
# Report failed tests

echo "************************************************" | tee -a "$TEST_RESULTS"
echo "" | tee -a "$TEST_RESULTS"

FCOUNT="${#FAILED_LIST[@]}"
if (( "$FCOUNT" == "0" )); then
    echo "No failed tests" | tee -a "$TEST_RESULTS"
else
    echo "$FCOUNT failed tests" | tee -a "$TEST_RESULTS"
    for TEST in "${FAILED_LIST[@]}"
    do
      echo "  - $TEST" | tee -a "$TEST_RESULTS"
    done
fi
echo "" | tee -a "$TEST_RESULTS"

############################################
# Report warnings

echo "************************************************" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo "" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"

WCOUNT=$("${GREP}" -E '(warning:)' $WARN_RESULTS | wc -l | "${AWK}" '{print $1}')
if (( "$WCOUNT" == "0" )); then
    echo "No warnings detected" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
else
    echo "$WCOUNT warnings detected. See $WARN_RESULTS for details" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
    # "${GREP}" -n -E '(warning:)' $WARN_RESULTS | "${GREP}" -v 'deprecated-declarations'
fi
echo "" | tee -a "$TEST_RESULTS"

############################################
# Report execution time

echo "************************************************" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo "" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"

echo "Testing started: $TEST_BEGIN" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo "Testing finished: $TEST_END" | tee -a "$TEST_RESULTS" "$WARN_RESULTS"
echo

############################################
# http://tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
if (( "$FCOUNT" == "0" )); then
    exit 0
else
    exit 1
fi
