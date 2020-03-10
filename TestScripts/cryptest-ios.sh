#!/usr/bin/env bash

# ====================================================================
# Tests iOS cross-compiles
#
# See http://www.cryptopp.com/wiki/iOS_(Command_Line) for more details
# ====================================================================

if [ -z "$(command -v ./setenv-ios.sh)" ]; then
    echo "Failed to locate setenv-ios.sh"
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Temp directory
if [[ -z "$TMPDIR" ]]; then
    TMPDIR="$HOME/tmp"
    mkdir "$TMPDIR"
fi

MAKE_JOBS=2

# Cleanup old artifacts
rm -rf "$TMPDIR/build.failed" 2>/dev/null
rm -rf "$TMPDIR/build.log" 2>/dev/null

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
    echo "Testing for iOS support of $platform"

    # Test if we can set the environment for the platform
    if ! ./setenv-ios.sh > /dev/null 2>&1;
    then
        echo
        echo "$platform not supported by Xcode"
        echo "$platform ==> SKIPPED" >> "$TMPDIR/build.log"

        continue
    fi

    echo
    echo "Building for $platform..."
    echo

    # run in subshell to not keep any envars
    (
        source ./setenv-ios.sh
        if make -k -j "$MAKE_JOBS" -f GNUmakefile-cross static dynamic cryptest.exe;
        then
            echo "$platform ==> SUCCESS" >> "$TMPDIR/build.log"
        else
            echo "$platform ==> FAILURE" >> "$TMPDIR/build.log"
            touch "$TMPDIR/build.failed"
        fi
    )
done

echo ""
echo "====================================================="
cat "$TMPDIR/build.log"

# let the script fail if any of the builds failed
if [ -f "$TMPDIR/build.failed" ]; then
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0
