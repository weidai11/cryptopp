#/usr/bin/env bash

# This file should be source'd when required.

export ANDROID_HOME="$HOME/.android"
export ANDROID_SDK="$HOME/android/sdk/"
export ANDROID_NDK="$HOME/android/sdk/ndk-bundle"
export ANDROID_SDK_ROOT="$ANDROID_SDK"
export ANDROID_NDK_ROOT="$ANDROID_NDK"

mkdir -p "$ANDROID_HOME"
mkdir -p "$ANDROID_SDK_ROOT"
mkdir -p "$ANDROID_NDK_ROOT"

# https://stackoverflow.com/a/47028911/608639
touch "$ANDROID_HOME/repositories.cfg"

[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0
