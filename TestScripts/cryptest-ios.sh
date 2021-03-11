#!/usr/bin/env bash

#############################################################################
#
# This script tests the cryptopp-ios gear.
#
# Written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/iOS_(Command_Line) for more details
#############################################################################

if [ -z "$(command -v ./setenv-ios.sh)" ]; then
    echo "Failed to locate setenv-ios.sh"
    exit 1
fi

# Temp directory
if [[ -z "${TMPDIR}" ]]; then
    TMPDIR="$HOME/tmp"
    mkdir "${TMPDIR}"
fi

# Sane default
if [[ -z "${MAKE_JOBS}" ]]; then
    MAKE_JOBS=4
fi

# Cleanup old artifacts
rm -rf "${TMPDIR}/build.failed" 2>/dev/null
rm -rf "${TMPDIR}/build.log" 2>/dev/null

#############################################################################

# Prepare the environment
unset CXX CPPFLAGS CXXFLAGS LDFLAGS
unset IOS_CPPFLAGS IOS_CXXFLAGS IOS_LDFLAGS IOS_SYSROOT

if [[ -e TestScripts/setenv-ios.sh ]]; then
    cp TestScripts/setenv-ios.sh .
    chmod u+x setenv-ios.sh
fi

#############################################################################

# Hack a Bash data structure...
PLATFORMS=()
PLATFORMS+=("iPhoneOS:armv7")
PLATFORMS+=("iPhoneOS:arm64")
PLATFORMS+=("AppleTVOS:armv7")
PLATFORMS+=("AppleTVOS:arm64")
PLATFORMS+=("WatchOS:armv7")
PLATFORMS+=("WatchOS:arm64")
PLATFORMS+=("WatchOS:arm64_32")
PLATFORMS+=("iPhoneSimulator:i386")
PLATFORMS+=("iPhoneSimulator:x86_64")
PLATFORMS+=("AppleTVSimulator:i386")
PLATFORMS+=("AppleTVSimulator:x86_64")
PLATFORMS+=("WatchSimulator:i386")
PLATFORMS+=("WatchSimulator:x86_64")

for platform in "${PLATFORMS[@]}"
do

    sdk=$(echo "${platform[@]}" | awk -F':' '{print $1}')
    cpu=$(echo "${platform[@]}" | awk -F':' '{print $2}')

    # setenv-ios.sh reads these two variables for configuration info.
    export IOS_SDK="$sdk"
    export IOS_CPU="$cpu"

    make -f GNUmakefile-cross distclean > /dev/null 2>&1

    echo
    echo "====================================================="
    echo "Testing for iOS support of ${platform}"

    # Test if we can set the environment for the platform
    if ! ./setenv-ios.sh > /dev/null 2>&1;
    then
        echo
        echo "${platform} not supported by Xcode"
        echo "${platform} ==> SKIPPED" >> "${TMPDIR}/build.log"

        continue
    fi

    echo
    echo "====================================================="
    echo "Building for ${platform}..."

    # run in subshell to not keep any envars
    (
        source ./setenv-ios.sh

        if make -k -j "${MAKE_JOBS}" -f GNUmakefile-cross static dynamic cryptest.exe;
        then
            echo "${platform} ==> SUCCESS" >> "${TMPDIR}/build.log"
        else
            echo "${platform} ==> FAILURE" >> "${TMPDIR}/build.log"
            touch "${TMPDIR}/build.failed"
        fi

        # Test code generation
        if [[ "${cpu}" == "armv7" ]]
        then

            # Test NEON code generation
            count=$(otool -tV aria_simd.o 2>&1 | grep -c -E 'vld|vst|vshl|vshr|veor')
            if [[ "${count}" -gt 64 ]]
            then
                echo "${platform} : NEON ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : NEON ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

        elif [[ "${cpu}" == "arm64" ]]
        then

            # Test ASIMD code generation
            count=$(otool -tV aria_simd.o 2>&1 | grep -c -E 'ldr[[:space:]]*q|str[[:space:]]*q|shl.4|shr.4|eor.16')
            if [[ "${count}" -gt 64 ]]
            then
                echo "${platform} : ASIMD ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : ASIMD ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test AES code generation
            count=$(otool -tV rijndael_simd.o 2>&1 | grep -c -E 'aese|aesd|aesmc|aesimc')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : AES ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : AES ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test PMULL code generation
            count=$(otool -tV gcm_simd.o 2>&1 | grep -c -E 'pmull|pmull2')
            if [[ "${count}" -gt 16 ]]
            then
                echo "${platform} : PMULL ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : PMULL ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test SHA1 code generation
            count=$(otool -tV sha_simd.o 2>&1 | grep -c -E 'sha1c|sha1m|sha1p|sha1h|sha1su0|sha1su1')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : SHA1 ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : SHA1 ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test SHA2 code generation
            count=$(otool -tV sha_simd.o | grep -c -E 'sha256h|sha256su0|sha256su1')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : SHA2 ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : SHA2 ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi
        fi
    )
done

echo
echo "====================================================="
cat "${TMPDIR}/build.log"

# let the script fail if any of the builds failed
if [ -f "${TMPDIR}/build.failed" ]; then
    exit 1
fi

exit 0
