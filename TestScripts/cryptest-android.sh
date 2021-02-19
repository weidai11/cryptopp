#!/usr/bin/env bash

#############################################################################
#
# This script tests Android cross-compiles using setenv-android.sh script.
#
# Written and placed in public domain by Jeffrey Walton.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/Android_(Command_Line) for more details
#
#############################################################################

# Error checking
if [ -z "$(command -v ./setenv-android.sh 2>/dev/null)" ]; then
    echo "Failed to locate setenv-android.sh."
    exit 1
fi

# Error checking
if [ ! -d "${ANDROID_NDK_ROOT}" ]; then
    echo "ERROR: ANDROID_NDK_ROOT is not a valid path for ${USER}. Please set it."
    echo "ANDROID_NDK_ROOT is '${ANDROID_NDK_ROOT}'"
    exit 1
fi

# Error checking
if [ ! -d "${ANDROID_SDK_ROOT}" ]; then
    echo "ERROR: ANDROID_SDK_ROOT is not a valid path for ${USER}. Please set it."
    echo "ANDROID_SDK_ROOT is '${ANDROID_SDK_ROOT}'"
    exit 1
fi

# Error checking
if [ -z "$(command -v ndk-build 2>/dev/null)"  ]; then
    echo "ERROR: ndk-build is not on-path for ${USER}. Please set it."
    echo "PATH is '${PATH}'"
    exit 1
fi

# Temp directory
if [[ -z "${TMPDIR}" ]]; then
    TMPDIR="$HOME/tmp"
    mkdir -p "${TMPDIR}"
    if [ -n "${SUDO_USER}" ]; then
        chown -R "${SUDO_USER}" "${TMPDIR}"
    fi
fi

# Sane default
if [[ -z "${MAKE_JOBS}" ]]; then
    MAKE_JOBS=4
fi

# Cleanup old artifacts
rm -rf "${TMPDIR}/build.failed" 2>/dev/null
rm -rf "${TMPDIR}/build.log" 2>/dev/null

#############################################################################

PLATFORMS=(armv7a aarch64 x86 x86_64)

for platform in "${PLATFORMS[@]}"
do
    # setenv-android.sh reads these two variables for configuration info.
    # Android 5.0 is 21. Android 6.0 is 23.
    export ANDROID_API="21"
    export ANDROID_CPU="${platform}"

    make -f GNUmakefile-cross distclean > /dev/null 2>&1

    echo
    echo "===================================================================="
    echo "Testing for Android support of ${platform}"

    # Test if we can set the environment for the platform
    if ! ./setenv-android.sh > /dev/null 2>&1;
    then
        echo
        echo "There were problems testing ${platform}"
        echo "${platform} ==> SKIPPED" >> "${TMPDIR}/build.log"

        continue
    fi

    echo
    echo "===================================================================="
    echo "Building for ${platform}..."

    # run in subshell to not keep any envars
    (
        source ./setenv-android.sh
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
