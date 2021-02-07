#!/usr/bin/env bash

#############################################################################
#
# This script tests the cryptopp-ios gear.
#
# Written and placed in public domain by Jeffrey Walton.
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

# Hack a Bash data structure...
PLATFORMS=()
PLATFORMS+=("iPhoneOS:armv7")
PLATFORMS+=("iPhoneOS:arm64")
PLATFORMS+=("AppleTVOS:armv7")
PLATFORMS+=("AppleTVOS:arm64")
PLATFORMS+=("WatchOS:armv7")
PLATFORMS+=("WatchOS:arm64")
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
