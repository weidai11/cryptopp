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

function cleanup {
    # Cleanup downloads
    rm -f android-sdk.zip android-ndk.zip platform-tools.zip
}
trap cleanup EXIT

if [ -z "${ANDROID_SDK_ROOT}" ]; then
    echo "ERROR: ANDROID_SDK_ROOT is not set for ${USER}. Please set it."
    exit 1
fi

if [ -z "${ANDROID_NDK_ROOT}" ]; then
    echo "ERROR: ANDROID_NDK_ROOT is not set for ${USER}. Please set it."
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

# Install Android deps
if [[ -z "$(command -v java 2>/dev/null)" && -n "$(command -v apt-get 2>/dev/null)" ]]; then
    apt-get -qq update 2>/dev/null || true
    apt-get -qq install --no-install-recommends unzip curl wget 2>/dev/null || true

    if [[ -n "$(apt-cache search openjdk-13-jdk 2>/dev/null | head -n 1)" ]]; then
        apt-get -qq install --no-install-recommends openjdk-13-jdk 2>/dev/null || true
    elif [[ -n "$(apt-cache search openjdk-8-jdk 2>/dev/null | head -n 1)" ]]; then
        apt-get -qq install --no-install-recommends openjdk-8-jdk 2>/dev/null || true
    fi
elif [[ -z "$(command -v java 2>/dev/null)" && -n "$(command -v dnf 2>/dev/null)" ]]; then
    dnf update 2>/dev/null || true
    dnf install unzip curl wget 2>/dev/null || true

    if [[ -n "$(dnf search java-latest-openjdk-devel 2>/dev/null | head -n 1)" ]]; then
        dnf install java-latest-openjdk-devel 2>/dev/null || true
    elif [[ -n "$(dnf search java-11-openjdk-devel 2>/dev/null | head -n 1)" ]]; then
        dnf install java-11-openjdk-devel 2>/dev/null || true
    fi
elif [[ -z "$(command -v java 2>/dev/null)" && -n "$(command -v yum 2>/dev/null)" ]]; then
    yum update 2>/dev/null || true
    yum install unzip curl wget 2>/dev/null || true

    if [[ -n "$(yum search java-latest-openjdk-devel 2>/dev/null | head -n 1)" ]]; then
        yum install java-latest-openjdk-devel 2>/dev/null || true
    elif [[ -n "$(yum search java-11-openjdk-devel 2>/dev/null | head -n 1)" ]]; then
        yum install java-11-openjdk-devel 2>/dev/null || true
    fi
fi

# User feedback
#echo "ANDROID_NDK_ROOT is '${ANDROID_NDK_ROOT}'"
#echo "ANDROID_SDK_ROOT is '${ANDROID_SDK_ROOT}'"

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

# Android SDK does not include a top level directory
echo "Unpacking SDK to ${ANDROID_SDK_ROOT}"
if ! unzip -u -qq android-sdk.zip -d "${ANDROID_SDK_ROOT}";
then
    echo "Failed to unpack SDK"
    exit 1
fi

# Android NDK includes top level NDK_NAME directory
echo "Unpacking NDK to ${NDK_TOP}/${NDK_NAME}"
if ! unzip -u -qq android-ndk.zip -d "${NDK_TOP}";
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
if [[ -e "${ANDROID_NDK_ROOT}" ]]; then
    ls_output=$(ls -l "${ANDROID_NDK_ROOT}" 2>/dev/null | head -n 1)
    # Only remove soft links
    if [[ ${ls_output:0:1} == "l" ]]; then
        unlink "${ANDROID_NDK_ROOT}"
    fi
fi

# Create softlink
(
    echo "Symlinking ${NDK_NAME} to android-ndk"
    cd ${NDK_TOP} || exit 1
    if ! ln -s "${NDK_NAME}" android-ndk; then
        echo "Failed to link ${NDK_NAME} to android-ndk"
    fi
)

# We don't set ANDROID_HOME to ANDROID_SDK_ROOT.
# https://stackoverflow.com/a/47028911/608639
touch "${ANDROID_SDK_ROOT}/repositories.cfg"

# And https://stackoverflow.com/q/43433542
mkdir -p "${HOME}/.android"
touch "${HOME}/.android/repositories.cfg"

if [[ -n "${SUDO_USER}" ]]; then
    chown -R "${SUDO_USER}" "${HOME}/.android"
fi

count=$(ls -1 "${ANDROID_SDK_ROOT}" 2>/dev/null | wc -l)
if [[ "${count}" -lt 2 ]]; then
    echo "ANDROID_SDK_ROOT appears empty. The contents are listed."
    echo "$(ls "${ANDROID_SDK_ROOT}")"
    exit 1
fi

count=$(ls -1 "${ANDROID_NDK_ROOT}" 2>/dev/null | wc -l)
if [[ "${count}" -lt 2 ]]; then
    echo "ANDROID_NDK_ROOT appears empty. The contents are listed."
    echo "$(ls "${ANDROID_NDK_ROOT}")"
    exit 1
fi

echo "Finished installing SDK and NDK"

exit 0
