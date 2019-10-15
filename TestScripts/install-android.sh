#!/usr/bin/env bash
set -e

# install android deps
sudo apt-get -qq update
sudo apt-get -qq install --no-install-recommends openjdk-8-jdk unzip

# android skd/ndk
curl -L -k -o /tmp/android-sdk.zip https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip
unzip -qq /tmp/android-sdk.zip -d "$ANDROID_SDK"
rm -f /tmp/android-sdk.zip

curl -L -k -o /tmp/android-ndk.zip https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip
unzip -qq /tmp/android-sdk.zip -d "$ANDROID_NDK"
rm -f /tmp/android-ndk.zip
