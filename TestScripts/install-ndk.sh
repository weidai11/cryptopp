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
# SDK for Mac: https://dl.google.com/android/repository/sdk-tools-mac-4333796.zip

# NDK-r20: https://dl.google.com/android/repository/android-ndk-r20b-linux-x86_64.zip
# SDK for r20: https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip
# SDK for Mac: https://dl.google.com/android/repository/commandlinetools-mac-6200805_latest.zip

# NDK-r21: https://dl.google.com/android/repository/android-ndk-r21-linux-x86_64.zip
# SDK for r21: https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip
# SDK for Mac: https://dl.google.com/android/repository/commandlinetools-mac-6200805_latest.zip

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

IS_DARWIN=$(uname -s 2>/dev/null | grep -i -c darwin)
IS_LINUX=$(uname -s 2>/dev/null | grep -i -c linux)

# Keep this in sync with the move at the end.
if [ "$IS_LINUX" -eq 1 ]; then
    SDK_URL=https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip
    NDK_URL=https://dl.google.com/android/repository/android-ndk-r20b-linux-x86_64.zip
elif [ "$IS_DARWIN" -eq 1 ]; then
    SDK_URL=https://dl.google.com/android/repository/commandlinetools-mac-6200805_latest.zip
    NDK_URL=https://dl.google.com/android/repository/android-ndk-r20b-darwin-x86_64.zip
else
    echo "Unknown platform: \"$(uname -s 2>/dev/null)\". Please fix this script."
fi

# install android deps
if [ -n "$(command -v apt-get)" ]; then
    apt-get -qq update 2>/dev/null
    apt-get -qq install --no-install-recommends openjdk-8-jdk unzip curl 2>/dev/null
fi

echo "Downloading SDK"
if ! curl -k -s -o android-sdk.zip "$SDK_URL";
then
    echo "Failed to download SDK"
    exit 1
fi

echo "Downloading NDK"
if ! curl -k -s -o android-ndk.zip "$NDK_URL";
then
    echo "Failed to download NDK"
    exit 1
fi

echo "Unpacking SDK to $ANDROID_SDK_ROOT"
if ! unzip -qq android-sdk.zip -d "$ANDROID_SDK_ROOT";
then
    echo "Failed to unpack SDK"
    exit 1
fi

echo "Unpacking NDK to $ANDROID_NDK_ROOT"
if ! unzip -qq android-ndk.zip -d "$HOME";
then
    echo "Failed to unpack NDK"
    exit 1
fi

if ! mv "$HOME/android-ndk-r20b" "$ANDROID_NDK_ROOT";
then
    echo "Failed to move $HOME/android-ndk-r20b to $ANDROID_NDK_ROOT"
    exit 1
fi

rm -f android-sdk.zip
rm -f android-ndk.zip

# We don't set ANDROID_HOME to ANDROID_SDK_ROOT.
# https://stackoverflow.com/a/47028911/608639
touch "$ANDROID_SDK_ROOT/repositories.cfg"

echo "Finished preparing SDK and NDK"

exit 0
