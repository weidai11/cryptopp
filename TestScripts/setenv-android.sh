#!/usr/bin/env bash

#############################################################################
#
# This script sets the cross-compile environment for Android.
#
# Based upon OpenSSL's setenv-android.sh by TH, JW, and SM.
# Heavily modified by JWW for Crypto++.
# Modified by Skycoder42 Android NDK-r19 and above.
# Modified some more by JW and UB.
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

DEF_CPPFLAGS="-DNDEBUG"
DEF_CFLAGS="-Wall -g2 -O3 -fPIC"
DEF_CXXFLAGS="-Wall -g2 -O3 -fPIC"
DEF_ASFLAGS=
DEF_LDFLAGS=""

#########################################
#####       Clear old options       #####
#########################################

unset IS_IOS
unset IS_MACOS
unset IS_ANDROID
unset IS_ARM_EMBEDDED

unset ANDROID_CPPFLAGS
unset ANDROID_CFLAGS
unset ANDROID_CXXFLAGS
unset ANDROID_ASFLAGS
unset ANDROID_LDFLAGS
unset ANDROID_SYSROOT

#########################################
#####    Small Fixups, if needed    #####
#########################################

ANDROID_CPU=$(tr '[:upper:]' '[:lower:]' <<< "${ANDROID_CPU}")

if [[ "${ANDROID_CPU}" == "amd64" || "${ANDROID_CPU}" == "x86_64" ]] ; then
    ANDROID_CPU=x86_64
fi

if [[ "${ANDROID_CPU}" == "i386" || "${ANDROID_CPU}" == "i686" ]] ; then
    ANDROID_CPU=i686
fi

if [[ "${ANDROID_CPU}" == "armv7"* || "${ANDROID_CPU}" == "armeabi"* ]] ; then
    ANDROID_CPU=armeabi-v7a
fi

if [[ "${ANDROID_CPU}" == "aarch64" || "${ANDROID_CPU}" == "arm64"* || "${ANDROID_CPU}" == "armv8"* ]] ; then
    ANDROID_CPU=arm64-v8a
fi

# Debug
# echo "Configuring for ${ANDROID_API} (${ANDROID_CPU})"

########################################
#####         Environment          #####
########################################

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

# https://developer.android.com/ndk/guides/abis.html and
# https://developer.android.com/ndk/guides/cpp-support.
# Since NDK r16 the only STL available is libc++, so we
# add -std=c++11 -stdlib=libc++ to CXXFLAGS. This is
# consistent with Android.mk and 'APP_STL := c++_shared'.

case "${ANDROID_CPU}" in
  armv7*|armeabi*)
    CC="armv7a-linux-androideabi${ANDROID_API}-clang"
    CXX="armv7a-linux-androideabi${ANDROID_API}-clang++"
    LD="arm-linux-androideabi-ld"
    AS="arm-linux-androideabi-as"
    AR="arm-linux-androideabi-ar"
    NM="arm-linux-androideabi-nm"
    RANLIB="arm-linux-androideabi-ranlib"
    STRIP="arm-linux-androideabi-strip"
    OBJDUMP="arm-linux-androideabi-objdump"

    # https://github.com/weidai11/cryptopp/pull/1119
    if [ -n "${ANDROID_LD}" ]; then
        if [ "$LD" != "ld.lld" ]; then
            LD="arm-linux-androideabi-${ANDROID_LD}"
        fi
    elif [ "${ANDROID_API}" -ge 22 ]; then
        # New default linker
        # https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r22/docs/BuildSystemMaintainers.md#Linkers
        LD="ld.lld"
    elif [ "${ANDROID_API}" -ge 19 ]; then
        # New default linker. BFD used on all excpet aarch64; Gold used on aarch64
        # https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r19/docs/BuildSystemMaintainers.md#Linkers
        LD="arm-linux-androideabi-ld.bfd"
    fi

    # As of NDK r22, there are new names for some tools.
    # https://developer.android.com/ndk/guides/other_build_systems
    if [ "${ANDROID_API}" -ge 22 ]; then
        AR="llvm-ar"
        AS="llvm-as"
        NM="llvm-nm"
        OBJDUMP="llvm-objdump"
        RANLIB="llvm-ranlib"
        STRIP="llvm-strip"
    fi

    # You may need this on older NDKs
    # ANDROID_CPPFLAGS="-D__ANDROID__=${ANDROID_API}"

    # Android NDK r19 and r20 no longer use -mfloat-abi=softfp. Add it as required.
    ANDROID_CFLAGS="-target armv7-none-linux-androideabi${ANDROID_API}"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -march=armv7-a -mthumb"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -fno-addrsig -fno-experimental-isel"

    ANDROID_CXXFLAGS="-target armv7-none-linux-androideabi${ANDROID_API}"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -march=armv7-a -mthumb"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -std=c++11 -stdlib=libc++"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fno-addrsig -fno-experimental-isel"
    ;;

  armv8*|aarch64|arm64*)
    CC="aarch64-linux-android${ANDROID_API}-clang"
    CXX="aarch64-linux-android${ANDROID_API}-clang++"
    LD="aarch64-linux-android-ld"
    AS="aarch64-linux-android-as"
    AR="aarch64-linux-android-ar"
    NM="aarch64-linux-android-nm"
    RANLIB="aarch64-linux-android-ranlib"
    STRIP="aarch64-linux-android-strip"
    OBJDUMP="aarch64-linux-android-objdump"

    # https://github.com/weidai11/cryptopp/pull/1119
    if [ -n "${ANDROID_LD}" ]; then
        if [ "$LD" != "ld.lld" ]; then
            LD="aarch64-linux-android-${ANDROID_LD}"
        fi
    elif [ "${ANDROID_API}" -ge 22 ]; then
        # New default linker
        # https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r22/docs/BuildSystemMaintainers.md#Linkers
        LD="ld.lld"
    elif [ "${ANDROID_API}" -ge 19 ]; then
        # New default linker. BFD used on all excpet aarch64; Gold used on aarch64
        # https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r19/docs/BuildSystemMaintainers.md#Linkers
        LD="aarch64-linux-android-ld.gold"
    fi

    # As of NDK r22, there are new names for some tools.
    # https://developer.android.com/ndk/guides/other_build_systems
    if [ "${ANDROID_API}" -ge 22 ]; then
        AR="llvm-ar"
        AS="llvm-as"
        NM="llvm-nm"
        OBJDUMP="llvm-objdump"
        RANLIB="llvm-ranlib"
        STRIP="llvm-strip"
    fi

    # You may need this on older NDKs
    # ANDROID_CPPFLAGS="-D__ANDROID__=${ANDROID_API}"

    ANDROID_CFLAGS="-target aarch64-none-linux-android${ANDROID_API}"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -fno-addrsig -fno-experimental-isel"

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
    NM="i686-linux-android-nm"
    RANLIB="i686-linux-android-ranlib"
    STRIP="i686-linux-android-strip"
    OBJDUMP="i686-linux-android-objdump"

    # https://github.com/weidai11/cryptopp/pull/1119
    if [ -n "${ANDROID_LD}" ]; then
        if [ "$LD" != "ld.lld" ]; then
            LD="i686-linux-android-${ANDROID_LD}"
        fi
    elif [ "${ANDROID_API}" -ge 22 ]; then
        # New default linker
        # https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r22/docs/BuildSystemMaintainers.md#Linkers
        LD="ld.lld"
    elif [ "${ANDROID_API}" -ge 19 ]; then
        # New default linker. BFD used on all excpet aarch64; Gold used on aarch64
        # https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r19/docs/BuildSystemMaintainers.md#Linkers
        LD="i686-linux-android-ld.bfd"
    fi

    # As of NDK r22, there are new names for some tools.
    # https://developer.android.com/ndk/guides/other_build_systems
    if [ "${ANDROID_API}" -ge 22 ]; then
        AR="llvm-ar"
        AS="llvm-as"
        NM="llvm-nm"
        OBJDUMP="llvm-objdump"
        RANLIB="llvm-ranlib"
        STRIP="llvm-strip"
    fi

    # You may need this on older NDKs
    # ANDROID_CPPFLAGS="-D__ANDROID__=${ANDROID_API}"
    # Newer NDK's choke on -mtune=intel, so omit it

    ANDROID_CFLAGS="-target i686-none-linux-android${ANDROID_API}"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -mssse3 -mfpmath=sse"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -fno-addrsig -fno-experimental-isel"

    ANDROID_CXXFLAGS="-target i686-none-linux-android${ANDROID_API}"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -mssse3 -mfpmath=sse"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -std=c++11 -stdlib=libc++"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fno-addrsig -fno-experimental-isel"
    ;;

  x86_64|x64)
    CC="x86_64-linux-android${ANDROID_API}-clang"
    CXX="x86_64-linux-android${ANDROID_API}-clang++"
    LD="x86_64-linux-android-ld"
    AS="x86_64-linux-android-as"
    AR="x86_64-linux-android-ar"
    NM="x86_64-linux-android-nm"
    RANLIB="x86_64-linux-android-ranlib"
    STRIP="x86_64-linux-android-strip"
    OBJDUMP="x86_64-linux-android-objdump"

    # https://github.com/weidai11/cryptopp/pull/1119
    if [ -n "${ANDROID_LD}" ]; then
        if [ "$LD" != "ld.lld" ]; then
            LD="x86_64-linux-android-${ANDROID_LD}"
        fi
    elif [ "${ANDROID_API}" -ge 22 ]; then
        # New default linker
        # https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r22/docs/BuildSystemMaintainers.md#Linkers
        LD="ld.lld"
    elif [ "${ANDROID_API}" -ge 19 ]; then
        # New default linker. BFD used on all excpet aarch64; Gold used on aarch64
        # https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r19/docs/BuildSystemMaintainers.md#Linkers
        LD="x86_64-linux-android-ld.bfd"
    fi

    # As of NDK r22, there are new names for some tools.
    # https://developer.android.com/ndk/guides/other_build_systems
    if [ "${ANDROID_API}" -ge 22 ]; then
        AR="llvm-ar"
        AS="llvm-as"
        NM="llvm-nm"
        OBJDUMP="llvm-objdump"
        RANLIB="llvm-ranlib"
        STRIP="llvm-strip"
    fi

    # You may need this on older NDKs
    # ANDROID_CPPFLAGS="-D__ANDROID__=${ANDROID_API}"
    # Newer NDK's choke on -mtune=intel, so omit it

    ANDROID_CFLAGS="-target x86_64-none-linux-android${ANDROID_API}"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -march=x86-64 -msse4.2 -mpopcnt"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CFLAGS="${ANDROID_CFLAGS} -fno-addrsig -fno-experimental-isel"

    ANDROID_CXXFLAGS="-target x86_64-none-linux-android${ANDROID_API}"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -march=x86-64 -msse4.2 -mpopcnt"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -std=c++11 -stdlib=libc++"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fstack-protector-strong -funwind-tables -fexceptions -frtti"
    ANDROID_CXXFLAGS="${ANDROID_CXXFLAGS} -fno-addrsig -fno-experimental-isel"
    ;;
  *)
    echo "ERROR: Unknown architecture ${ANDROID_CPU}"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
    ;;
esac

echo "Configuring for Android API ${ANDROID_API} on ${ANDROID_CPU}"

#####################################################################

# Common to all builds

ANDROID_CPPFLAGS="${DEF_CPPFLAGS} ${ANDROID_CPPFLAGS} -DANDROID"
ANDROID_ASFLAGS="${DEF_ASFLAGS} -Wa,--noexecstack"
ANDROID_CFLAGS="${DEF_CFLAGS} ${ANDROID_CFLAGS}"
ANDROID_CXXFLAGS="${DEF_CXXFLAGS} ${ANDROID_CXXFLAGS} -Wa,--noexecstack"
ANDROID_LDFLAGS="${DEF_LDFLAGS}"

# Aarch64 ld does not understand --warn-execstack
ANDROID_LDFLAGS="${ANDROID_LDFLAGS} -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now"
ANDROID_LDFLAGS="${ANDROID_LDFLAGS} -Wl,--warn-shared-textrel -Wl,--warn-common"
ANDROID_LDFLAGS="${ANDROID_LDFLAGS} -Wl,--warn-unresolved-symbols"
ANDROID_LDFLAGS="${ANDROID_LDFLAGS} -Wl,--gc-sections -Wl,--fatal-warnings"

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

# Error checking. lld location is <NDK>/toolchains/llvm/prebuilt/<host-tag>/bin/ld.lld
# https://android.googlesource.com/platform/ndk/+/refs/heads/ndk-release-r21/docs/BuildSystemMaintainers.md#Linkers
if [ "$LD" != "ld.lld" ] && [ ! -e "${ANDROID_TOOLCHAIN}/$LD" ]; then
    echo "ERROR: Failed to find Android ld. Please edit this script. When using NDK 22 or higher make sure to set ANDROID_LD! (bfd, gold)"
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
  if [ -n "${ANDROID_CPPFLAGS}" ]; then
    echo "ANDROID_CPPFLAGS: ${ANDROID_CPPFLAGS}"
  fi
  echo "ANDROID_CFLAGS: ${ANDROID_CFLAGS}"
  echo "ANDROID_CXXFLAGS: ${ANDROID_CXXFLAGS}"
  if [ -n "${ANDROID_ASFLAGS}" ]; then
    echo "ANDROID_ASFLAGS: ${ANDROID_ASFLAGS}"
  fi
    if [ -n "${ANDROID_LDFLAGS}" ]; then
    echo "ANDROID_LDFLAGS: ${ANDROID_LDFLAGS}"
  fi
  echo "ANDROID_SYSROOT: ${ANDROID_SYSROOT}"
  if [ -e "cpu-features.h" ] && [ -e "cpu-features.c" ]; then
    echo "CPU FEATURES: cpu-features.h and cpu-features.c are present"
  fi
fi

#####################################################################

# GNUmakefile-cross and Autotools expect these to be set.
# Note: prior to Crypto++ 8.6, CPPFLAGS, CXXFLAGS and LDFLAGS were not
# exported. At Crypto++ 8.6 CPPFLAGS, CXXFLAGS and LDFLAGS were exported.

export IS_ANDROID=1
export CPP CC CXX LD AS AR NM OBJDUMP RANLIB STRIP

# Do NOT use ANDROID_SYSROOT_INC or ANDROID_SYSROOT_LD
# https://github.com/android/ndk/issues/894#issuecomment-470837964

CPPFLAGS="${ANDROID_CPPFLAGS} -isysroot ${ANDROID_SYSROOT}"
CFLAGS="${ANDROID_CFLAGS}"
CXXFLAGS="${ANDROID_CXXFLAGS}"
ASFLAGS="${ANDROID_ASFLAGS}"
LDFLAGS="${ANDROID_LDFLAGS} --sysroot ${ANDROID_SYSROOT}"

# Trim whitespace as needed
CPPFLAGS=$(echo "${CPPFLAGS}" | awk '{$1=$1;print}')
CFLAGS=$(echo "${CFLAGS}" | awk '{$1=$1;print}')
CXXFLAGS=$(echo "${CXXFLAGS}" | awk '{$1=$1;print}')
ASFLAGS=$(echo "${ASFLAGS}" | awk '{$1=$1;print}')
LDFLAGS=$(echo "${LDFLAGS}" | awk '{$1=$1;print}')

export CPPFLAGS CFLAGS CXXFLAGS ASFLAGS LDFLAGS

#####################################################################

echo
echo "*******************************************************************************"
echo "It looks the the environment is set correctly. Your next step is build"
echo "the library with 'make -f GNUmakefile-cross'."
echo "*******************************************************************************"
echo

[ "$0" = "${BASH_SOURCE[0]}" ] && exit 0 || return 0
