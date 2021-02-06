#!/usr/bin/env bash

#############################################################################
#
# This script tests the cryptopp-android gear using ndk-build.
#
# Written and placed in public domain by Jeffrey Walton.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/Android.mk_(Command_Line) for more details
#
#############################################################################

# Error checking
if [ ! -d "${ANDROID_NDK_ROOT}" ]; then
    echo "ERROR: ANDROID_NDK_ROOT is not set. Please set it."
    exit 1
fi

# Error checking
if [ ! -d "${ANDROID_SDK_ROOT}" ]; then
    echo "ERROR: ANDROID_SDK_ROOT is not set. Please set it."
    exit 1
fi

# Temp directory
if [[ -z "$TMPDIR" ]]; then
    TMPDIR="$HOME/tmp"
    mkdir -p "$TMPDIR"
fi

# Sane default
if [[ -z "${MAKE_JOBS}" ]]; then
    MAKE_JOBS=4
fi

# Fixup for sed and "illegal byte sequence"
IS_DARWIN=$(uname -s 2>/dev/null | grep -i -c darwin)
if [[ "${IS_DARWIN}" -ne 0 ]] && [[ -z "${LC_ALL}" ]]; then
    export LC_ALL=C
fi

#############################################################################

files=(Android.mk Application.mk make_neon.sh test_shared.hxx test_shared.cxx)

for file in "${files[@]}"; do
    echo "Downloading $file"
    if ! curl -o "${file}" --silent "https://raw.githubusercontent.com/noloader/cryptopp-android/master/${file}"; then
        echo "${file} download failed"
        exit 1
    fi
done

# Fix permissions
chmod +x make_neon.sh

# Fix Apple quarantine
if [[ "${IS_DARWIN}" -ne 0 ]] && [[ $(command -v xattr 2>/dev/null) ]]; then
    echo "Removing make_neon.sh quarantine"
    xattr -d "com.apple.quarantine" make_neon.sh &>/dev/null
fi

# Fix missing *neon files
echo "Adding NEON files for armeabi-v7a"
bash make_neon.sh

#############################################################################

# Paydirt
NDK_PROJECT_PATH="$PWD"
NDK_APPLICATION_MK="$PWD/Application.mk"
PLATFORMS=(armeabi-v7a arm64-v8a x86 x86_64)

# Clean all past artifacts
ndk-build APP_ABI=all NDK_PROJECT_PATH="${NDK_PROJECT_PATH}" NDK_APPLICATION_MK="${NDK_APPLICATION_MK}" distclean &>/dev/null

for platform in "${PLATFORMS[@]}"
do
    echo ""
    echo "===================================================================="
    echo "Building for ${platform}..."
    echo "===================================================================="

    if ! ndk-build -j "${MAKE_JOBS}" APP_ABI="${platform}" NDK_PROJECT_PATH="${NDK_PROJECT_PATH}" NDK_APPLICATION_MK="${NDK_APPLICATION_MK}" V=1;
    then
        echo ""
        echo "Failed to build for ${platform}..."
        exit 1
    fi

done

echo ""
echo "===================================================================="
echo "Builds for ${PLATFORMS[@]} successful"
echo "===================================================================="

exit 0
