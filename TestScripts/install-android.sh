#!/usr/bin/env bash

# install android deps
sudo apt-get -qq update
sudo apt-get -qq install --no-install-recommends openjdk-8-jdk unzip

echo "Downloading SDK"
if ! curl -L -k -s -o /tmp/android-sdk.zip https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip;
then
	echo "Failed to download SDK"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Downloading NDK"
if ! curl -L -k -s -o /tmp/android-ndk.zip https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip;
then
	echo "Failed to download NDK"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Unpacking SDK to $ANDROID_SDK"
mkdir -p "$ANDROID_SDK"
if ! unzip -qq /tmp/android-sdk.zip -d "$ANDROID_SDK";
then
	echo "Failed to unpack SDK"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Unpacking NDK to $ANDROID_NDK"
rm -rf "$ANDROID_NDK"
if ! unzip -v /tmp/android-ndk.zip -d "$HOME";
then
	echo "Failed to unpack NDK"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

mv -r "$HOME/android-ndk-r19c" "$ANDROID_NDK"

rm -f /tmp/android-sdk.zip
rm -f /tmp/android-ndk.zip

echo "Finished preparing SDK and NDK"

echo "Dumping toolchain locations"

find -L "$ANDROID_NDK" -name 'clang++'


[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0
