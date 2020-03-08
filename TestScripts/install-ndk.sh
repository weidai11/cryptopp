#!/usr/bin/env bash

# ====================================================================
# Tests Android cross-compiles
#
# This script installs a SDK and NDK to test Android cross-compiles.
#
# See http://www.cryptopp.com/wiki/Android_(Command_Line) for more details
# ====================================================================

# NDK-r19: https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip
# SDK for r19: https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip

# NDK-r20: https://dl.google.com/android/repository/android-ndk-r20b-linux-x86_64.zip
# SDK for r20: https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip

# NDK-r21: https://dl.google.com/android/repository/android-ndk-r21-linux-x86_64.zip
# SDK for r21: https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip

if [ -z "$ANDROID_SDK_ROOT" ]; then
    echo "ERROR: ANDROID_SDK_ROOT is not set. Please set it."
    echo "SDK root is $ANDROID_SDK_ROOT"
    exit 1
fi

if [ -z "$ANDROID_NDK_ROOT" ]; then
    echo "ERROR: ANDROID_NDK_ROOT is not set. Please set it."
    echo "NDK root is $ANDROID_NDK_ROOT"
    exit 1
fi

echo "Using ANDROID_SDK_ROOT: $ANDROID_SDK_ROOT"
echo "Using ANDROID_NDK_ROOT: $ANDROID_NDK_ROOT"

# install android deps
if [ -n "$(command -v apt-get)" ]; then
    apt-get -qq update
    apt-get -qq install --no-install-recommends openjdk-8-jdk unzip
fi

echo "Downloading SDK"
if ! curl -k -s -o android-sdk.zip https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip;
then
    echo "Failed to download SDK"
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Downloading NDK"
if ! curl -k -s -o android-ndk.zip https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip;
then
    echo "Failed to download NDK"
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Unpacking SDK to $ANDROID_SDK_ROOT"
if ! unzip -qq android-sdk.zip -d "$ANDROID_SDK_ROOT";
then
    echo "Failed to unpack SDK"
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Unpacking NDK to $ANDROID_NDK_ROOT"
if ! unzip -qq android-ndk.zip -d "$HOME";
then
    echo "Failed to unpack NDK"
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! mv "$HOME/android-ndk-r19c" "$ANDROID_NDK_ROOT";
then
    echo "Failed to move $HOME/android-ndk-r19c to $ANDROID_NDK_ROOT"
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

rm -f android-sdk.zip
rm -f android-ndk.zip

# We don't set ANDROID_HOME to ANDROID_SDK_ROOT.
# https://stackoverflow.com/a/47028911/608639
touch "$ANDROID_SDK_ROOT/repositories.cfg"

echo "Finished preparing SDK and NDK"

[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0
