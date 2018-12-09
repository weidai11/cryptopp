#!/usr/bin/env bash
set -e

# install android deps
sudo apt-get -qq update
sudo apt-get -qq install --no-install-recommends openjdk-8-jdk unzip

# android skd/ndk
curl -Lo /tmp/android-sdk.zip https://dl.google.com/android/repository/sdk-tools-linux-3859397.zip
unzip -qq /tmp/android-sdk.zip -d "$ANDROID_SDK"
rm -f /tmp/android-sdk.zip
echo y | "$ANDROID_SDK/tools/bin/sdkmanager" --update > /dev/null
for package in "ndk-bundle"; do
	echo install android $package
	echo y | "$ANDROID_SDK/tools/bin/sdkmanager" "$package" > /dev/null
done
