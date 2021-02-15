#!/usr/bin/env bash

#############################################################################
#
# This script sets the cross-compile environment for Android.
#
# Based upon OpenSSL's setenv-android.sh by TH, JW, and SM.
# Heavily modified by JWW for Crypto++.
# Modified by Skycoder42 Android NDK-r19 and above.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# Also see:
#   https://android.googlesource.com/platform/ndk.git/+/HEAD/docs/UnifiedHeaders.md
#   https://android.googlesource.com/platform/ndk/+/master/docs/PlatformApis.md
#   https://developer.android.com/ndk/guides/abis.html and
#   https://developer.android.com/ndk/guides/cpp-support.
#
# See http://www.cryptopp.com/wiki/Android_(Command_Line) for more details
#############################################################################

#########################################
#####        Some validation        #####
#########################################

# cryptest-android.sh may run this script without sourcing.
if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    echo "setenv-android.sh is usually sourced, but not this time."
fi

# This supports both 'source setenv-android.sh 21 arm64' and
# 'source setenv-android.sh ANDROID_API=21 ANDROID_CPU=arm64'
if [[ -n "$1" ]]
then
    arg1=$(echo "$1" | cut -f 1 -d '=')
    arg2=$(echo "$1" | cut -f 2 -d '=')
    if [[ -n "${arg2}" ]]; then
        ANDROID_API="${arg2}"
    else
        ANDROID_API="${arg1}"
    fi
    printf "Using positional arg, ANDROID_API=%s\n" "${ANDROID_API}"
fi

# This supports both 'source setenv-android.sh 21 arm64' and
# 'source setenv-android.sh ANDROID_API=21 ANDROID_CPU=arm64'
if [[ -n "$2" ]]
then
    arg1=$(echo "$2" | cut -f 1 -d '=')
    arg2=$(echo "$2" | cut -f 2 -d '=')
    if [[ -n "${arg2}" ]]; then
        ANDROID_CPU="${arg2}"
    else
        ANDROID_CPU="${arg1}"
    fi
    printf "Using positional arg, ANDROID_CPU=%s\n" "${ANDROID_CPU}"
fi

if [ -z "${ANDROID_API}" ]; then
    echo "ANDROID_API is not set. Please set it"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ -z "${ANDROID_CPU}" ]; then
    echo "ANDROID_CPU is not set. Please set it"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#########################################
#####       Clear old options       #####
#########################################

unset IS_IOS
unset IS_ANDROID
unset IS_ARM_EMBEDDED

unset ANDROID_CPPFLAGS
unset ANDROID_CXXFLAGS
unset ANDROID_LDFLAGS
unset ANDROID_SYSROOT

#####################################################################

# ANDROID_NDK_ROOT should always be set by the user (even when not running this script)
# http://groups.google.com/group/android-ndk/browse_thread/thread/a998e139aca71d77.
# If the user did not specify the NDK location, try and pick it up. Something like
# ANDROID_NDK_ROOT=/opt/android-ndk-r19c or ANDROID_NDK_ROOT=/usr/local/android-ndk-r20.

if [ -n "${ANDROID_NDK_ROOT}" ]; then
    echo "ANDROID_NDK_ROOT is ${ANDROID_NDK_ROOT}"
else
    echo "ANDROID_NDK_ROOT is empty. Searching for the NDK"
    ANDROID_NDK_ROOT=$(find /opt -maxdepth 1 -type d -name "android-ndk*" 2>/dev/null | tail -n -1)

    if [ -z "${ANDROID_NDK_ROOT}" ]; then
        ANDROID_NDK_ROOT=$(find /usr/local -maxdepth 1 -type d -name "android-ndk*" 2>/dev/null | tail -n -1)
    fi
    if [ -z "${ANDROID_NDK_ROOT}" ]; then
        ANDROID_NDK_ROOT=$(find "$HOME" -maxdepth 1 -type d -name "android-ndk*" 2>/dev/null | tail -n -1)
    fi
    if [ -d "$HOME/Library/Android/sdk/ndk-bundle" ]; then
        ANDROID_NDK_ROOT="$HOME/Library/Android/sdk/ndk-bundle"
    fi
fi

# Error checking
if [ ! -d "${ANDROID_NDK_ROOT}" ]; then
    echo "ERROR: ANDROID_NDK_ROOT is not a valid path for ${USER}. Please set it."
    echo "ANDROID_NDK_ROOT is '${ANDROID_NDK_ROOT}'"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -d "${ANDROID_SDK_ROOT}" ]; then
    echo "ERROR: ANDROID_SDK_ROOT is not a valid path for ${USER}. Please set it."
    echo "ANDROID_SDK_ROOT is '${ANDROID_SDK_ROOT}'"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# User feedback
#echo "ANDROID_NDK_ROOT is '${ANDROID_NDK_ROOT}'"
#echo "ANDROID_SDK_ROOT is '${ANDROID_SDK_ROOT}'"

#####################################################################

# Need to set HOST_TAG to darwin-x86_64, linux-x86_64,
# windows, or windows-x86_64

if [[ "$(uname -s | grep -i -c darwin)" -ne 0 ]]; then
    HOST_TAG=darwin-x86_64
elif [[ "$(uname -s | grep -i -c linux)" -ne 0 ]]; then
    HOST_TAG=linux-x86_64
else
    echo "ERROR: Unknown host"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

ANDROID_TOOLCHAIN="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${HOST_TAG}/bin"
ANDROID_SYSROOT="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${HOST_TAG}/sysroot"

# Error checking
if [ ! -d "${ANDROID_TOOLCHAIN}" ]; then
    echo "ERROR: ANDROID_TOOLCHAIN is not a valid path. Please set it."
    echo "ANDROID_TOOLCHAIN is '${ANDROID_TOOLCHAIN}'"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -d "${ANDROID_SYSROOT}" ]; then
    echo "ERROR: ANDROID_SYSROOT is not a valid path. Please set it."
    echo "ANDROID_SYSROOT is '${ANDROID_SYSROOT}'"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#####################################################################

THE_ARCH=$(tr '[:upper:]' '[:lower:]' <<< "${ANDROID_CPU}")

# https://developer.android.com/ndk/guides/abis.html and
# https://developer.android.com/ndk/guides/cpp-support.
# Since NDK r16 the only STL available is libc++, so we
# add -std=c++11 -stdlib=libc++ to CXXFLAGS. This is
# consistent with Android.mk and 'APP_STL := c++_shared'.
case "$THE_ARCH" in
  armv7*|armeabi*)
    CC="armv7a-linux-androideabi${ANDROID_API}-clang"
    CXX="armv7a-linux-androideabi${ANDROID_API}-clang++"
    LD="arm-linux-androideabi-ld"
    AS="arm-linux-androideabi-as"
    AR="arm-linux-androideabi-ar"
    RANLIB="arm-linux-androideabi-ranlib"
    STRIP="arm-linux-androideabi-strip"

    # You may need this on older NDKs
    # ANDROID_CPPFLAGS="-D__ANDROID__=${ANDROID_API}"

    # Android NDK r19 and r20 no longer use -mfloat-abi=softfp. Add it as required.
    ANDROID_CXXFLAGS="-target armv7-none-linux-androideabi${ANDROID_API} -std=c++11 -stdlib=libc++"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -march=armv7-a -mthumb"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fno-addrsig -fno-experimental-isel"
    ;;
  armv8*|aarch64|arm64*)
    CC="aarch64-linux-android${ANDROID_API}-clang"
    CXX="aarch64-linux-android${ANDROID_API}-clang++"
    LD="aarch64-linux-android-ld"
    AS="aarch64-linux-android-as"
    AR="aarch64-linux-android-ar"
    RANLIB="aarch64-linux-android-ranlib"
    STRIP="aarch64-linux-android-strip"

    # You may need this on older NDKs
    # ANDROID_CPPFLAGS="-D__ANDROID__=${ANDROID_API}"

    ANDROID_CXXFLAGS="-target aarch64-none-linux-android${ANDROID_API}"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -std=c++11 -stdlib=libc++"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fno-addrsig -fno-experimental-isel"
    ;;
  i686|x86)
    CC="i686-linux-android${ANDROID_API}-clang"
    CXX="i686-linux-android${ANDROID_API}-clang++"
    LD="i686-linux-android-ld"
    AS="i686-linux-android-as"
    AR="i686-linux-android-ar"
    RANLIB="i686-linux-android-ranlib"
    STRIP="i686-linux-android-strip"

    # You may need this on older NDKs
    # ANDROID_CPPFLAGS="-D__ANDROID__=${ANDROID_API}"

    ANDROID_CXXFLAGS="-target i686-none-linux-android${ANDROID_API}"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -std=c++11 -stdlib=libc++"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -mtune=intel -mssse3 -mfpmath=sse"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fno-addrsig -fno-experimental-isel"
    ;;
  x86_64|x64)
    CC="x86_64-linux-android${ANDROID_API}-clang"
    CXX="x86_64-linux-android${ANDROID_API}-clang++"
    LD="x86_64-linux-android-ld"
    AS="x86_64-linux-android-as"
    AR="x86_64-linux-android-ar"
    RANLIB="x86_64-linux-android-ranlib"
    STRIP="x86_64-linux-android-strip"

    # You may need this on older NDKs
    # ANDROID_CPPFLAGS="-D__ANDROID__=${ANDROID_API}"

    ANDROID_CXXFLAGS="-target x86_64-none-linux-android${ANDROID_API}"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -std=c++11 -stdlib=libc++"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -march=x86-64 -msse4.2 -mpopcnt -mtune=intel"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fno-addrsig -fno-experimental-isel"
    ;;
  *)
    echo "ERROR: Unknown architecture ${ANDROID_CPU}"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
    ;;
esac

#####################################################################

# GNUmakefile-cross and Autotools expect these to be set.
# They are also used in the tests below.
export IS_ANDROID=1

export CPP CC CXX LD AS AR RANLIB STRIP
export ANDROID_CPPFLAGS ANDROID_CXXFLAGS ANDROID_LDFLAGS
export ANDROID_API ANDROID_CPU ANDROID_SYSROOT

# Do NOT use ANDROID_SYSROOT_INC or ANDROID_SYSROOT_LD
# https://github.com/android/ndk/issues/894#issuecomment-470837964

#####################################################################

# Error checking
if [ ! -e "${ANDROID_TOOLCHAIN}/$CC" ]; then
    echo "ERROR: Failed to find Android clang. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${ANDROID_TOOLCHAIN}/$CXX" ]; then
    echo "ERROR: Failed to find Android clang++. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${ANDROID_TOOLCHAIN}/$RANLIB" ]; then
    echo "ERROR: Failed to find Android ranlib. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${ANDROID_TOOLCHAIN}/$AR" ]; then
    echo "ERROR: Failed to find Android ar. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${ANDROID_TOOLCHAIN}/$AS" ]; then
    echo "ERROR: Failed to find Android as. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${ANDROID_TOOLCHAIN}/$LD" ]; then
    echo "ERROR: Failed to find Android ld. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#####################################################################

# Add tools to head of path, if not present already
LENGTH=${#ANDROID_TOOLCHAIN}
SUBSTR=${PATH:0:$LENGTH}
if [ "$SUBSTR" != "${ANDROID_TOOLCHAIN}" ]; then
    export PATH="${ANDROID_TOOLCHAIN}:$PATH"
fi

#####################################################################

# Now that we are using cpu-features from Android rather than
# CPU probing, we need to copy cpu-features.h and cpu-features.c
# from the NDK into our source directory and then build it.

if [[ ! -e "${ANDROID_NDK_ROOT}/sources/android/cpufeatures/cpu-features.h" ]]; then
    echo "ERROR: Unable to locate cpu-features.h"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [[ ! -e "${ANDROID_NDK_ROOT}/sources/android/cpufeatures/cpu-features.c" ]]; then
    echo "ERROR: Unable to locate cpu-features.c"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

cp "${ANDROID_NDK_ROOT}/sources/android/cpufeatures/cpu-features.h" .
cp "${ANDROID_NDK_ROOT}/sources/android/cpufeatures/cpu-features.c" .

# Cleanup the sources for the C++ compiler
# https://github.com/weidai11/cryptopp/issues/926

sed -e 's/= memmem/= (const char*)memmem/g' \
    -e 's/= memchr/= (const char*)memchr/g' \
    -e 's/= malloc/= (char*)malloc/g' \
    cpu-features.c > cpu-features.c.fixed
mv cpu-features.c.fixed cpu-features.c

# Fix permissions. For some reason cpu-features.h is +x.
chmod u=rw,go=r cpu-features.h cpu-features.c

#####################################################################

VERBOSE=${VERBOSE:-1}
if [ "$VERBOSE" -gt 0 ]; then
  echo "ANDROID_TOOLCHAIN: ${ANDROID_TOOLCHAIN}"
  echo "ANDROID_API: ${ANDROID_API}"
  echo "ANDROID_CPU: ${ANDROID_CPU}"
  echo "ANDROID_SYSROOT: ${ANDROID_SYSROOT}"
  if [ -n "${ANDROID_CPPFLAGS}" ]; then
    echo "ANDROID_CPPFLAGS: ${ANDROID_CPPFLAGS}"
  fi
  echo "ANDROID_CXXFLAGS: ${ANDROID_CXXFLAGS}"
  if [ -n "${ANDROID_LDFLAGS}" ]; then
    echo "ANDROID_LDFLAGS: ${ANDROID_LDFLAGS}"
  fi
  if [ -e "cpu-features.h" ] && [ -e "cpu-features.c" ]; then
    echo "CPU FEATURES: cpu-features.h and cpu-features.c are present"
  fi
fi

#####################################################################

echo
echo "*******************************************************************************"
echo "It looks the the environment is set correctly. Your next step is build"
echo "the library with 'make -f GNUmakefile-cross'."
echo "*******************************************************************************"
echo

[ "$0" = "${BASH_SOURCE[0]}" ] && exit 0 || return 0
