#!/usr/bin/env bash

# ====================================================================
# Tests Android cross-compiles
#
# See http://www.cryptopp.com/wiki/Android_(Command_Line) for more details
# ====================================================================

if [ -z "$(command -v ./setenv-android.sh)" ]; then
    echo "Failed to locate setenv-android.sh"
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Temp directory
if [[ -z "$TMPDIR" ]]; then
    TMPDIR="$HOME/tmp"
    mkdir -p "$TMPDIR"
fi

MAKE_JOBS=2

# Cleanup old artifacts
rm -rf "$TMPDIR/build.failed" 2>/dev/null
rm -rf "$TMPDIR/build.log" 2>/dev/null

PLATFORMS=(armv7a aarch64 x86 x86_64)

for platform in "${PLATFORMS[@]}"
do
    # setenv-android.sh reads these two variables for configuration info.
    export ANDROID_API="23"
    export ANDROID_CPU="$platform"

    make -f GNUmakefile-cross distclean > /dev/null 2>&1

    echo
    echo "===================================================================="
    echo "Testing for Android support of $platform"

    # Test if we can set the environment for the platform
    if ! ./setenv-android.sh > /dev/null 2>&1;
    then
        echo
        echo "There were problems testing $platform"
        echo "$platform ==> SKIPPED" >> "$TMPDIR/build.log"

        continue
    fi

    echo
    echo "Building for $platform..."
    echo

    # run in subshell to not keep any envars
    (
        source ./setenv-android.sh
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
