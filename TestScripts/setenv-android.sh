#!/usr/bin/env bash

# ====================================================================
# Sets the cross compile environment for Android
# Based upon OpenSSL's setenv-android.sh (by TH, JW, and SM).
# Updated by Skycoder42 to the latest NDK.
# These changes are based on the current recommendations for Android
# for their "Unified Headers". Details can be found at:
# https://android.googlesource.com/platform/ndk.git/+/HEAD/docs/UnifiedHeaders.md
# https://android.googlesource.com/platform/ndk/+/master/docs/PlatformApis.md
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/Android_(Command_Line) for more details
# ====================================================================

# cryptest-android.sh may run this script without sourcing.
if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    echo "setenv-android.sh is usually sourced, but not this time."
fi

unset IS_CROSS_COMPILE

unset IS_IOS
unset IS_ANDROID
unset IS_ARM_EMBEDDED

# Variables used in GNUmakefile-cross
unset AOSP_FLAGS
unset AOSP_SYSROOT
unset AOSP_RUNTIME

# Tools set by this script
unset CPP CC CXX LD AS AR RANLIB STRIP

# Similar to a "make clean"
if [ x"${1-}" = "xunset" ]; then
    echo "Unsetting script variables. PATH may remain tainted"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 0 || return 0
fi

# Set AOSP_API to the API you want to use. Most are listed for
# historical reference. Use API 23 or above.
# https://source.android.com/setup/start/build-numbers
# AOSP_API="3"     # Android 1.5 and above
# AOSP_API="4"     # Android 1.6 and above
# AOSP_API="5"     # Android 2.0 and above
# AOSP_API="8"     # Android 2.2 and above
# AOSP_API="9"     # Android 2.3 and above
# AOSP_API="14"    # Android 4.0 and above
# AOSP_API="18"    # Android 4.3 and above
# AOSP_API="19"    # Android 4.4 and above
# AOSP_API="21"    # Android 5.0 and above
# AOSP_API="23"    # Android 6.0 and above
# AOSP_API="24"    # Android 7.0 and above
# AOSP_API="25"    # Android 7.1 and above
# AOSP_API="26"    # Android 8.0 and above
# AOSP_API="27"    # Android 8.1 and above
# AOSP_API="28"    # Android 9.0 and above
# AOSP_API="29"    # Android 10.0 and above
if [ -z "${AOSP_API-}" ]; then
    AOSP_API="23"
fi

#####################################################################

# ANDROID_NDK_ROOT should always be set by the user (even when not running this script)
# http://groups.google.com/group/android-ndk/browse_thread/thread/a998e139aca71d77.
# If the user did not specify the NDK location, try and pick it up. Something like
# ANDROID_NDK_ROOT=/opt/android-ndk-r19c or ANDROID_NDK_ROOT=/usr/local/android-ndk-r20.

if [ -n "${ANDROID_NDK_ROOT}" ]; then
    echo "ANDROID_NDK_ROOT is $ANDROID_NDK_ROOT"
else
    echo "ANDROID_NDK_ROOT is empty. Searching for the NDK"
    ANDROID_NDK_ROOT=$(find /opt -maxdepth 1 -type d -name "android-ndk*" 2>/dev/null | tail -n -1)

    if [ -z "$ANDROID_NDK_ROOT" ]; then
        ANDROID_NDK_ROOT=$(find /usr/local -maxdepth 1 -type d -name "android-ndk*" 2>/dev/null | tail -n -1)
    fi
    if [ -z "$ANDROID_NDK_ROOT" ]; then
        ANDROID_NDK_ROOT=$(find "$HOME" -maxdepth 1 -type d -name "android-ndk*" 2>/dev/null | tail -n -1)
    fi
    if [ -d "$HOME/Library/Android/sdk/ndk-bundle" ]; then
        ANDROID_NDK_ROOT="$HOME/Library/Android/sdk/ndk-bundle"
    fi
fi

# Error checking
if [ ! -d "$ANDROID_NDK_ROOT" ]; then
    echo "ERROR: ANDROID_NDK_ROOT is not a valid path. Please set it."
    echo "Root is $ANDROID_NDK_ROOT"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#####################################################################

# Need to set HOST_TAG to darwin-x86_64, linux-x86_64,
# windows, or windows-x86_64

IS_DARWIN=$(uname -s | grep -i -c darwin)
IS_LINUX=$(uname -s | grep -i -c linux)

if [[ "$IS_DARWIN" -ne 0 ]]; then
    HOST_TAG=darwin-x86_64
elif [[ "$IS_LINUX" -ne 0 ]]; then
    HOST_TAG=linux-x86_64
else
    echo "ERROR: Unknown host"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

AOSP_TOOLCHAIN_ROOT="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG/"
AOSP_TOOLCHAIN_PATH="$AOSP_TOOLCHAIN_ROOT/bin/"
AOSP_SYSROOT="$AOSP_TOOLCHAIN_ROOT/sysroot"

# Error checking
if [ ! -d "$AOSP_TOOLCHAIN_ROOT" ]; then
    echo "ERROR: AOSP_TOOLCHAIN_ROOT is not a valid path. Please set it."
    echo "Root is $AOSP_TOOLCHAIN_ROOT"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -d "$AOSP_TOOLCHAIN_PATH" ]; then
    echo "ERROR: AOSP_TOOLCHAIN_PATH is not a valid path. Please set it."
    echo "Path is $AOSP_TOOLCHAIN_PATH"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -d "$AOSP_SYSROOT" ]; then
    echo "ERROR: AOSP_SYSROOT is not a valid path. Please set it."
    echo "Path is $AOSP_SYSROOT"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#####################################################################

if [ "$#" -lt 1 ]; then
    THE_ARCH=armeabi-v7a
else
    THE_ARCH=$(tr '[:upper:]' '[:upper:]' <<< "$1")
fi

# https://developer.android.com/ndk/guides/abis.html
case "$THE_ARCH" in
  armv7a|armv7-a|armeabi-v7a)
    CC="armv7a-linux-androideabi$AOSP_API-clang"
    CXX="armv7a-linux-androideabi$AOSP_API-clang++"
    LD="arm-linux-androideabi-ld"
    AS="arm-linux-androideabi-as"
    AR="arm-linux-androideabi-ar"
    RANLIB="arm-linux-androideabi-ranlib"
    STRIP="arm-linux-androideabi-strip"

    AOSP_FLAGS="-march=armv7-a -mthumb -mfloat-abi=softfp -funwind-tables -fexceptions -frtti"
    ;;
  armv8|armv8a|aarch64|arm64|arm64-v8a)
    CC="aarch64-linux-android$AOSP_API-clang"
    CXX="aarch64-linux-android$AOSP_API-clang++"
    LD="aarch64-linux-android-ld"
    AS="aarch64-linux-android-as"
    AR="aarch64-linux-android-ar"
    RANLIB="aarch64-linux-android-ranlib"
    STRIP="aarch64-linux-android-strip"

    AOSP_FLAGS="-funwind-tables -fexceptions -frtti"
    ;;
  x86)
    CC="i686-linux-android$AOSP_API-clang"
    CXX="i686-linux-android$AOSP_API-clang++"
    LD="i686-linux-android-ld"
    AS="i686-linux-android-as"
    AR="i686-linux-android-ar"
    RANLIB="i686-linux-android-ranlib"
    STRIP="i686-linux-android-strip"

    AOSP_FLAGS="-mtune=intel -mssse3 -mfpmath=sse -funwind-tables -fexceptions -frtti"
    ;;
  x86_64|x64)
    CPP="x86_64-linux-android-cpp"
    CC="x86_64-linux-android$AOSP_API-clang"
    CXX="x86_64-linux-android$AOSP_API-clang++"
    LD="x86_64-linux-android-ld"
    AS="x86_64-linux-android-as"
    AR="x86_64-linux-android-ar"
    RANLIB="x86_64-linux-android-ranlib"
    STRIP="x86_64-linux-android-strip"

    AOSP_FLAGS="-march=x86-64 -msse4.2 -mpopcnt -mtune=intel -funwind-tables -fexceptions -frtti"
    ;;
  *)
    echo "ERROR: Unknown architecture $1"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
    ;;
esac

#####################################################################

# Android C++ runtime

if [ "$#" -lt 2 ]; then
    AOSP_RUNTIME=libc++
else
    AOSP_RUNTIME=$(tr '[:upper:]' '[:lower:]' <<< "$2")
fi

#####################################################################

# GNUmakefile-cross expects these to be set. They are also used in the tests below.
export IS_ANDROID=1

export AOSP_FLAGS AOSP_API

export CPP CC CXX LD AS AR RANLIB STRIP

export AOSP_RUNTIME AOSP_SYSROOT

# Do NOT use AOSP_SYSROOT_INC or AOSP_SYSROOT_LD
# https://github.com/android/ndk/issues/894#issuecomment-470837964

#####################################################################

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$CC" ]; then
    echo "ERROR: Failed to find Android clang. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$CXX" ]; then
    echo "ERROR: Failed to find Android clang++. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$RANLIB" ]; then
    echo "ERROR: Failed to find Android ranlib. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$AR" ]; then
    echo "ERROR: Failed to find Android ar. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$AS" ]; then
    echo "ERROR: Failed to find Android as. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$LD" ]; then
    echo "ERROR: Failed to find Android ld. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Only modify/export PATH if AOSP_TOOLCHAIN_PATH good
if [ -d "$AOSP_TOOLCHAIN_PATH" ]; then
    # And only modify PATH if AOSP_TOOLCHAIN_PATH is not present
    LEN=${#AOSP_TOOLCHAIN_PATH}
    SUBSTR=${PATH:0:$LEN}
    if [ "$SUBSTR" != "$AOSP_TOOLCHAIN_PATH" ]; then
        export PATH="$AOSP_TOOLCHAIN_PATH:$PATH"
    fi
fi

# Now that we are using cpu-features from Android rather than CPU probing, we
# need to copy cpu-features.h and cpu-features.c from the NDK into our source
# directory and then build it.

if [[ ! -e "$ANDROID_NDK_ROOT/sources/android/cpufeatures/cpu-features.h" ]]; then
    echo "ERROR: Unable to locate cpu-features.h"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi
cp "$ANDROID_NDK_ROOT/sources/android/cpufeatures/cpu-features.h" .

if [[ ! -e "$ANDROID_NDK_ROOT/sources/android/cpufeatures/cpu-features.c" ]]; then
    echo "ERROR: Unable to locate cpu-features.c"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi
cp "$ANDROID_NDK_ROOT/sources/android/cpufeatures/cpu-features.c" .

#####################################################################

VERBOSE=1
if [ ! -z "$VERBOSE" ] && [ "$VERBOSE" != "0" ]; then
  echo "ANDROID_NDK_ROOT: $ANDROID_NDK_ROOT"
  echo "AOSP_TOOLCHAIN_PATH: $AOSP_TOOLCHAIN_PATH"
  echo "AOSP_API: $AOSP_API"
  echo "AOSP_RUNTIME: $AOSP_RUNTIME"
  echo "AOSP_SYSROOT: $AOSP_SYSROOT"
  echo "AOSP_FLAGS: $AOSP_FLAGS"
  if [ -e "cpu-features.h" ] && [ -e "cpu-features.c" ]; then
    echo "CPU FEATURES: cpu-features.h and cpu-features.c are present"
  fi
fi

#####################################################################

echo
echo "*******************************************************************************"
echo "It looks the the environment is set correctly. Your next step is build"
echo "the library with 'make -f GNUmakefile-cross'. You can create a versioned"
echo "shared object using 'HAS_SOLIB_VERSION=1 make -f GNUmakefile-cross'"
echo "*******************************************************************************"
echo

[ "$0" = "${BASH_SOURCE[0]}" ] && exit 0 || return 0
