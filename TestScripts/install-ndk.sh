#!/usr/bin/env bash

#############################################################################
# Tests Android cross-compiles
#
# This script installs a SDK and NDK to test Android cross-compiles.
#
# Written and placed in public domain by Jeffrey Walton
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/Android_(Command_Line) for more details
#############################################################################

# NDK-r19: https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip
# SDK for r19: https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip
# SDK for Mac: https://dl.google.com/android/repository/sdk-tools-mac-4333796.zip

# NDK-r20: https://dl.google.com/android/repository/android-ndk-r20b-linux-x86_64.zip
# SDK for r20: https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip
# SDK for Mac: https://dl.google.com/android/repository/commandlinetools-mac-6200805_latest.zip

# NDK-r21: https://dl.google.com/android/repository/android-ndk-r21-linux-x86_64.zip
# SDK for r21: https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip
# SDK for Mac: https://dl.google.com/android/repository/commandlinetools-mac-6200805_latest.zip

# NDK-r22: https://dl.google.com/android/repository/android-ndk-r22-linux-x86_64.zip
# SDK for r22: https://dl.google.com/android/repository/commandlinetools-linux-6858069_latest.zip
# SDK for Mac: https://dl.google.com/android/repository/commandlinetools-mac-6858069_latest.zip

# Platform tools
# Linux: https://dl.google.com/android/repository/platform-tools-latest-linux.zip
# Mac: https://dl.google.com/android/repository/platform-tools-latest-darwin.zip
# Windows: https://dl.google.com/android/repository/platform-tools-latest-windows.zip

if [ -z "${ANDROID_SDK_ROOT}" ]; then
    echo "ERROR: ANDROID_SDK_ROOT is not set. Please set it."
    echo "SDK root is ${ANDROID_SDK_ROOT}"
    exit 1
fi

if [ -z "${ANDROID_NDK_ROOT}" ]; then
    echo "ERROR: ANDROID_NDK_ROOT is not set. Please set it."
    echo "NDK root is ${ANDROID_NDK_ROOT}"
    exit 1
fi

IS_DARWIN=$(uname -s 2>/dev/null | grep -i -c darwin)
IS_LINUX=$(uname -s 2>/dev/null | grep -i -c linux)

# Change NDK_NAME as required
NDK_NAME=android-ndk-r20b
NDK_TOP=$(dirname "${ANDROID_NDK_ROOT}")

# Keep this in sync with the move at the end.
if [ "$IS_LINUX" -eq 1 ]; then
    NDK_URL=https://dl.google.com/android/repository/${NDK_NAME}-linux-x86_64.zip
    SDK_URL=https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip
    TOOLS_URL=https://dl.google.com/android/repository/platform-tools-latest-linux.zip
elif [ "$IS_DARWIN" -eq 1 ]; then
    NDK_URL=https://dl.google.com/android/repository/${NDK_NAME}-darwin-x86_64.zip
    SDK_URL=https://dl.google.com/android/repository/commandlinetools-mac-6200805_latest.zip
    TOOLS_URL=https://dl.google.com/android/repository/platform-tools-latest-darwin.zip
else
    echo "Unknown platform: \"$(uname -s 2>/dev/null)\". Please fix this script."
fi

# install android deps
if [ -n "$(command -v apt-get)" ]; then
    apt-get -qq update 2>/dev/null
    apt-get -qq install --no-install-recommends openjdk-8-jdk unzip curl 2>/dev/null
fi

echo "Downloading SDK"
if ! curl -L -s -o android-sdk.zip "${SDK_URL}";
then
    echo "Failed to download SDK"
    exit 1
fi

echo "Downloading NDK"
if ! curl -L -s -o android-ndk.zip "${NDK_URL}";
then
    echo "Failed to download NDK"
    exit 1
fi

echo "Downloading Platform Tools"
if ! curl -L -s -o platform-tools.zip "${TOOLS_URL}";
then
    echo "Failed to download Platform Tools"
    exit 1
fi

echo "Unpacking SDK to ${ANDROID_SDK_ROOT}"
if ! unzip -u -qq android-sdk.zip -d "${ANDROID_SDK_ROOT}";
then
    echo "Failed to unpack SDK"
    exit 1
fi

echo "Unpacking NDK to ${ANDROID_NDK_ROOT}"
if ! unzip -u -qq android-ndk.zip -d "$HOME";
then
    echo "Failed to unpack NDK"
    exit 1
fi

echo "Unpacking Platform Tools to ${ANDROID_SDK_ROOT}"
if ! unzip -u -qq platform-tools.zip -d "${ANDROID_SDK_ROOT}";
then
    echo "Failed to unpack Platform Tools"
    exit 1
fi

# Unlink as needed
if [[ -d "${ANDROID_NDK_ROOT}" ]]; then
    ls_output=$(ls -l "${ANDROID_NDK_ROOT}" 2>/dev/null | head -n 1)
    if [[ ${ls_output:0:1} == "l" ]]; then
        unlink "${ANDROID_NDK_ROOT}"
    fi
fi

# Remove an old directory
rm -rf "${NDK_TOP}/${NDK_NAME}"

# Place the new directory. mv should be faster on the same partition.
if ! mv "$HOME/${NDK_NAME}" ${NDK_TOP};
then
    echo "Failed to move $HOME/${NDK_NAME} to ${NDK_TOP}"
    exit 1
fi

# Run in a subshell
(
    cd ${NDK_TOP} || exit 1
    ln -s ${NDK_NAME} android-ndk
)

rm -f android-sdk.zip
rm -f android-ndk.zip
rm -f platform-tools.zip

# We don't set ANDROID_HOME to ANDROID_SDK_ROOT.
# https://stackoverflow.com/a/47028911/608639
touch "${ANDROID_SDK_ROOT}/repositories.cfg"

# And https://stackoverflow.com/q/43433542
mkdir -p "${HOME}/.android"
touch "${HOME}/.android/repositories.cfg"

echo "Finished preparing SDK and NDK"

exit 0
