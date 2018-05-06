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

# set -eu

unset IS_CROSS_COMPILE

unset IS_IOS
unset IS_ANDROID
unset IS_ARM_EMBEDDED

# Variables used in GNUmakefile-cross
unset AOSP_FLAGS
unset AOSP_SYSROOT
unset AOSP_LD_SYSROOT
unset AOSP_SYS_ARCH_INC
unset AOSP_STL_INC
unset AOSP_STL_LIB
unset AOSP_BITS_INC

# Tools set by this script
unset CPP CC CXX LD AS AR RANLIB STRIP

# Similar to a "make clean"
if [ x"${1-}" = "xunset" ]; then
	echo "Unsetting script variables. PATH may remain tainted"
	[ "$0" = "$BASH_SOURCE" ] && exit 0 || return 0
fi

# Set AOSP_TOOLCHAIN_SUFFIX to your preference of tools and STL library.
#   Note: 4.9 is required for the latest architectures, like ARM64/AARCH64.
# AOSP_TOOLCHAIN_SUFFIX=4.8
# AOSP_TOOLCHAIN_SUFFIX=4.9
if [ -z "${AOSP_TOOLCHAIN_SUFFIX-}" ]; then
	AOSP_TOOLCHAIN_SUFFIX=4.9
fi

# Set AOSP_API_VERSION to the API you want to use. 'armeabi' and 'armeabi-v7a' need
#   API 3 (or above), 'mips' and 'x86' need API 9 (or above), etc.
# AOSP_API_VERSION="3"     # Android 1.5 and above
# AOSP_API_VERSION="4"     # Android 1.6 and above
# AOSP_API_VERSION="5"     # Android 2.0 and above
# AOSP_API_VERSION="8"     # Android 2.2 and above
# AOSP_API_VERSION="9"     # Android 2.3 and above
# AOSP_API_VERSION="14"    # Android 4.0 and above
# AOSP_API_VERSION="18"    # Android 4.3 and above
# AOSP_API_VERSION="19"    # Android 4.4 and above
# AOSP_API_VERSION="21"    # Android 5.0 and above
# AOSP_API_VERSION="23"    # Android 6.0 and above
if [ -z "${AOSP_API_VERSION-}" ]; then
	AOSP_API_VERSION="21"
fi

if [ -z "${AOSP_API-}" ]; then
	AOSP_API="android-${AOSP_API_VERSION}"
else
	echo "WARNING: Using AOSP_API has been deprecated. Please use AOSP_API_VERSION instead."
	echo "If you set for example AOSP_API=android-23 then now instead set AOSP_API_VERSION=23"
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

#####################################################################

# ANDROID_NDK_ROOT should always be set by the user (even when not running this script)
#   http://groups.google.com/group/android-ndk/browse_thread/thread/a998e139aca71d77.
# If the user did not specify the NDK location, try and pick it up. We expect something
#   like ANDROID_NDK_ROOT=/opt/android-ndk-r10e or ANDROID_NDK_ROOT=/usr/local/android-ndk-r10e.

if [ -z "${ANDROID_NDK_ROOT-}" ]; then
	ANDROID_NDK_ROOT=$(find /opt -maxdepth 1 -type d -name android-ndk* 2>/dev/null | tail -1)

	if [ -z "$ANDROID_NDK_ROOT" ]; then
		ANDROID_NDK_ROOT=$(find /usr/local -maxdepth 1 -type d -name android-ndk* 2>/dev/null | tail -1)
	fi
	if [ -z "$ANDROID_NDK_ROOT" ]; then
		ANDROID_NDK_ROOT=$(find $HOME -maxdepth 1 -type d -name android-ndk* 2>/dev/null | tail -1)
	fi
	if [ -d "$HOME/Library/Android/sdk/ndk-bundle" ]; then
		ANDROID_NDK_ROOT="$HOME/Library/Android/sdk/ndk-bundle"
	fi
fi

# Error checking
if [ ! -d "$ANDROID_NDK_ROOT/toolchains" ]; then
	echo "ERROR: ANDROID_NDK_ROOT is not a valid path. Please set it."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

#####################################################################

if [ "$#" -lt 1 ]; then
	THE_ARCH=armv7a-neon
else
	THE_ARCH=$(tr [A-Z] [a-z] <<< "$1")
fi

# https://developer.android.com/ndk/guides/abis.html
case "$THE_ARCH" in
  arm|armv5|armv6|armv7|armeabi)
	TOOLCHAIN_ARCH="arm-linux-androideabi"
	TOOLCHAIN_NAME="arm-linux-androideabi"
	AOSP_ABI="armeabi"
	AOSP_ARCH="arch-arm"
	AOSP_FLAGS="-march=armv5te -mtune=xscale -mthumb -msoft-float -DCRYPTOPP_DISABLE_ASM -funwind-tables -fexceptions -frtti"
	;;
  armv7a|armv7-a|armeabi-v7a)
	TOOLCHAIN_ARCH="arm-linux-androideabi"
	TOOLCHAIN_NAME="arm-linux-androideabi"
	AOSP_ABI="armeabi-v7a"
	AOSP_ARCH="arch-arm"
	AOSP_FLAGS="-march=armv7-a -mthumb -mfpu=vfpv3-d16 -mfloat-abi=softfp -DCRYPTOPP_DISABLE_ASM -Wl,--fix-cortex-a8 -funwind-tables -fexceptions -frtti"
	;;
  hard|armv7a-hard|armeabi-v7a-hard)
	echo hard, armv7a-hard and armeabi-v7a-hard are not supported, as android uses softfloats
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
	#TOOLCHAIN_ARCH="arm-linux-androideabi"
	#TOOLCHAIN_NAME="arm-linux-androideabi"
	#AOSP_ABI="armeabi-v7a"
	#AOSP_ARCH="arch-arm"
	#AOSP_FLAGS="-mhard-float -D_NDK_MATH_NO_SOFTFP=1 -march=armv7-a -mfpu=vfpv3-d16 -DCRYPTOPP_DISABLE_ASM -mfloat-abi=softfp -Wl,--fix-cortex-a8 -funwind-tables -fexceptions -frtti -Wl,--no-warn-mismatch -Wl,-lm_hard"
	;;
  neon|armv7a-neon)
	TOOLCHAIN_ARCH="arm-linux-androideabi"
	TOOLCHAIN_NAME="arm-linux-androideabi"
	AOSP_ABI="armeabi-v7a"
	AOSP_ARCH="arch-arm"
	AOSP_FLAGS="-march=armv7-a -mfpu=neon -mfloat-abi=softfp -Wl,--fix-cortex-a8 -funwind-tables -fexceptions -frtti"
	;;
  armv8|armv8a|aarch64|arm64|arm64-v8a)
	TOOLCHAIN_ARCH="aarch64-linux-android"
	TOOLCHAIN_NAME="aarch64-linux-android"
	AOSP_ABI="arm64-v8a"
	AOSP_ARCH="arch-arm64"
	AOSP_FLAGS="-funwind-tables -fexceptions -frtti"
	;;
  mips|mipsel)
	TOOLCHAIN_ARCH="mipsel-linux-android"
	TOOLCHAIN_NAME="mipsel-linux-android"
	AOSP_ABI="mips"
	AOSP_ARCH="arch-mips"
	AOSP_FLAGS="-funwind-tables -fexceptions -frtti"
	;;
  mips64|mipsel64|mips64el)
	TOOLCHAIN_ARCH="mips64el-linux-android"
	TOOLCHAIN_NAME="mips64el-linux-android"
	AOSP_ABI="mips64"
	AOSP_ARCH="arch-mips64"
	AOSP_FLAGS="-funwind-tables -fexceptions -frtti"
	;;
  x86)
	TOOLCHAIN_ARCH="x86"
	TOOLCHAIN_NAME="i686-linux-android"
	AOSP_ABI="x86"
	AOSP_ARCH="arch-x86"
	AOSP_FLAGS="-mtune=intel -mssse3 -mfpmath=sse -DCRYPTOPP_DISABLE_SSE4 -funwind-tables -fexceptions -frtti"
	;;
  x86_64|x64)
	TOOLCHAIN_ARCH="x86_64"
	TOOLCHAIN_NAME="x86_64-linux-android"
	AOSP_ABI="x86_64"
	AOSP_ARCH="arch-x86_64"
	AOSP_FLAGS="-march=x86-64 -msse4.2 -mpopcnt -mtune=intel -DCRYPTOPP_DISABLE_CLMUL -DCRYPTOPP_DISABLE_AESNI -DCRYPTOPP_DISABLE_SHANI -funwind-tables -fexceptions -frtti"
	;;
  *)
	echo "ERROR: Unknown architecture $1"
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
	;;
esac

#####################################################################

# add missing android API version flag as of https://android.googlesource.com/platform/ndk.git/+/HEAD/docs/UnifiedHeaders.md
AOSP_FLAGS="-D__ANDROID_API__=$AOSP_API_VERSION $AOSP_FLAGS"

# GNUmakefile-cross expects these to be set. They are also used in the tests below.
export IS_ANDROID=1
export AOSP_FLAGS

export CPP="$TOOLCHAIN_NAME-cpp"
export CC="$TOOLCHAIN_NAME-gcc"
export CXX="$TOOLCHAIN_NAME-g++"
export LD="$TOOLCHAIN_NAME-ld"
export AS="$TOOLCHAIN_NAME-as"
export AR="$TOOLCHAIN_NAME-ar"
export RANLIB="$TOOLCHAIN_NAME-ranlib"
export STRIP="$TOOLCHAIN_NAME-strip"
export AOSP_SYS_ARCH_INC="$ANDROID_NDK_ROOT/sysroot/usr/include/$TOOLCHAIN_NAME"

#####################################################################

# Based on ANDROID_NDK_ROOT, try and pick up the path for the tools. We expect something
# like /opt/android-ndk-r10e/toolchains/arm-linux-androideabi-4.7/prebuilt/linux-x86_64/bin
# Once we locate the tools, we add it to the PATH.
AOSP_TOOLCHAIN_PATH=""
for host in "linux-x86_64" "darwin-x86_64" "linux-x86" "darwin-x86"
do
	if [ -d "$ANDROID_NDK_ROOT/toolchains/$TOOLCHAIN_ARCH-$AOSP_TOOLCHAIN_SUFFIX/prebuilt/$host/bin" ]; then
		AOSP_TOOLCHAIN_PATH="$ANDROID_NDK_ROOT/toolchains/$TOOLCHAIN_ARCH-$AOSP_TOOLCHAIN_SUFFIX/prebuilt/$host/bin"
		break
	fi
done

# Error checking
if [ -z "$AOSP_TOOLCHAIN_PATH" ] || [ ! -d "$AOSP_TOOLCHAIN_PATH" ]; then
	echo "ERROR: AOSP_TOOLCHAIN_PATH is not valid. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$CPP" ]; then
	echo "ERROR: Failed to find Android cpp. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$CC" ]; then
	echo "ERROR: Failed to find Android gcc. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

if [ ! -e "$AOSP_TOOLCHAIN_PATH/$CXX" ]; then
	echo "ERROR: Failed to find Android g++. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$RANLIB" ]; then
	echo "ERROR: Failed to find Android ranlib. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$AR" ]; then
	echo "ERROR: Failed to find Android ar. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$AS" ]; then
	echo "ERROR: Failed to find Android as. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_TOOLCHAIN_PATH/$LD" ]; then
	echo "ERROR: Failed to find Android ld. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Only modify/export PATH if AOSP_TOOLCHAIN_PATH good
if [ -d "$AOSP_TOOLCHAIN_PATH" ]; then

	# And only modify PATH if AOSP_TOOLCHAIN_PATH is not present
	LEN=${#AOSP_TOOLCHAIN_PATH}
	SUBSTR=${PATH:0:$LEN}
	if [ "$SUBSTR" != "$AOSP_TOOLCHAIN_PATH" ]; then
		export PATH="$AOSP_TOOLCHAIN_PATH":"$PATH"
	fi
fi

#####################################################################

# Error checking
if [ ! -d "$ANDROID_NDK_ROOT/platforms/$AOSP_API" ]; then
	echo "ERROR: AOSP_API is not valid. Does the NDK support the API? Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
elif [ ! -d "$ANDROID_NDK_ROOT/platforms/$AOSP_API/$AOSP_ARCH" ]; then
	echo "ERROR: AOSP_ARCH is not valid. Does the NDK support the architecture? Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Android SYSROOT. It will be used on the command line with --sysroot
#   http://android.googlesource.com/platform/ndk/+/ics-mr0/docs/STANDALONE-TOOLCHAIN.html
export AOSP_SYSROOT="$ANDROID_NDK_ROOT/sysroot"
export AOSP_LD_SYSROOT="$ANDROID_NDK_ROOT/platforms/$AOSP_API/$AOSP_ARCH"

#####################################################################

# Android STL. We support GNU, LLVM and STLport out of the box.

if [ "$#" -lt 2 ]; then
	THE_STL=gnu-shared
else
	THE_STL=$(tr [A-Z] [a-z] <<< "$2")
fi

# LLVM include directory may be different depending on NDK version. Default to new location (latest NDK checked: r16beta1).
LLVM_INCLUDE_DIR="$ANDROID_NDK_ROOT/sources/cxx-stl/llvm-libc++/include"
if [ ! -d "$LLVM_INCLUDE_DIR" ]; then
	LLVM_INCLUDE_DIR="$ANDROID_NDK_ROOT/sources/cxx-stl/llvm-libc++/libcxx/include"
fi

case "$THE_STL" in
  stlport-static)
	AOSP_STL_INC="$ANDROID_NDK_ROOT/sources/cxx-stl/stlport/stlport/"
	AOSP_STL_LIB="$ANDROID_NDK_ROOT/sources/cxx-stl/stlport/libs/$AOSP_ABI/libstlport_static.a"
	;;
  stlport|stlport-shared)
	AOSP_STL_INC="$ANDROID_NDK_ROOT/sources/cxx-stl/stlport/stlport/"
	AOSP_STL_LIB="$ANDROID_NDK_ROOT/sources/cxx-stl/stlport/libs/$AOSP_ABI/libstlport_shared.so"
	;;
  gabi++-static|gnu-static)
	AOSP_STL_INC="$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/$AOSP_TOOLCHAIN_SUFFIX/include"
	AOSP_BITS_INC="$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/$AOSP_TOOLCHAIN_SUFFIX/libs/$AOSP_ABI/include"
	AOSP_STL_LIB="$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/$AOSP_TOOLCHAIN_SUFFIX/libs/$AOSP_ABI/libgnustl_static.a"
	;;
  gnu|gabi++|gnu-shared|gabi++-shared)
	AOSP_STL_INC="$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/$AOSP_TOOLCHAIN_SUFFIX/include"
	AOSP_BITS_INC="$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/$AOSP_TOOLCHAIN_SUFFIX/libs/$AOSP_ABI/include"
	AOSP_STL_LIB="$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/$AOSP_TOOLCHAIN_SUFFIX/libs/$AOSP_ABI/libgnustl_shared.so"
	;;
  llvm-static)
	echo WARNING: llvm is still in experimental state and migth not work as expected
	if [ ! -d "$LLVM_INCLUDE_DIR" ]; then
		echo "ERROR: Unable to locate include LLVM directory at $LLVM_INCLUDE_DIR -- has it moved since NDK r16beta1?"
		[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
	fi
	AOSP_STL_INC="$LLVM_INCLUDE_DIR"
	AOSP_STL_LIB="$ANDROID_NDK_ROOT/sources/cxx-stl/llvm-libc++/libs/$AOSP_ABI/libc++_static.a"
	;;
  llvm|llvm-shared)
	echo WARNING: llvm is still in experimental state and migth not work as expected
	if [ ! -d "$LLVM_INCLUDE_DIR" ]; then
		echo "ERROR: Unable to locate LLVM include directory at $LLVM_INCLUDE_DIR -- has it moved since NDK r16beta1?"
		[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
	fi
	AOSP_STL_INC="$LLVM_INCLUDE_DIR"
	AOSP_STL_LIB="$ANDROID_NDK_ROOT/sources/cxx-stl/llvm-libc++/libs/$AOSP_ABI/libc++_shared.so"
	;;
  *)
	echo "ERROR: Unknown STL library $2"
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
esac

# Error checking
if [ ! -d "$AOSP_STL_INC" ] || [ ! -e "$AOSP_STL_INC/memory" ]; then
	echo "ERROR: AOSP_STL_INC is not valid. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "$AOSP_STL_LIB" ]; then
	echo "ERROR: AOSP_STL_LIB is not valid. Please edit this script."
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

export AOSP_STL_INC
export AOSP_STL_LIB

if [ ! -z "$AOSP_BITS_INC" ]; then
	export AOSP_BITS_INC
fi

# Now that we are using cpu-features from Android rather than CPU probing, we
# need to copy cpu-features.h and cpu-features.c from the NDK into our source
# directory and then build it.

if [[ ! -e "$ANDROID_NDK_ROOT/sources/android/cpufeatures/cpu-features.h" ]]; then
	echo "ERROR: Unable to locate cpu-features.h"
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi
cp "$ANDROID_NDK_ROOT/sources/android/cpufeatures/cpu-features.h" .

if [[ ! -e "$ANDROID_NDK_ROOT/sources/android/cpufeatures/cpu-features.c" ]]; then
	echo "ERROR: Unable to locate cpu-features.c"
	[ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi
cp "$ANDROID_NDK_ROOT/sources/android/cpufeatures/cpu-features.c" .

#####################################################################

VERBOSE=1
if [ ! -z "$VERBOSE" ] && [ "$VERBOSE" != "0" ]; then
  echo "ANDROID_NDK_ROOT: $ANDROID_NDK_ROOT"
  echo "AOSP_TOOLCHAIN_PATH: $AOSP_TOOLCHAIN_PATH"
  echo "AOSP_ABI: $AOSP_ABI"
  echo "AOSP_API: $AOSP_API"
  echo "AOSP_SYSROOT: $AOSP_SYSROOT"
  echo "AOSP_LD_SYSROOT: $AOSP_LD_SYSROOT"
  echo "AOSP_FLAGS: $AOSP_FLAGS"
  echo "AOSP_SYS_ARCH_INC: $AOSP_SYS_ARCH_INC"
  echo "AOSP_STL_INC: $AOSP_STL_INC"
  echo "AOSP_STL_LIB: $AOSP_STL_LIB"
  if [ ! -z "$AOSP_BITS_INC" ]; then
    echo "AOSP_BITS_INC: $AOSP_BITS_INC"
  fi

  if [ -e "cpu-features.h" ] && [ -e "cpu-features.c" ]; then
    echo "CPU FEATURES: cpu-features.h and cpu-features.c are present"
  fi
fi

#####################################################################

COUNT=$(echo -n "$AOSP_STL_LIB" | egrep -i -c 'libstdc\+\+')
if [[ ("$COUNT" -ne "0") ]]; then
	echo
	echo "*******************************************************************************"
	echo "You are using GNU's runtime and STL library. Please ensure the resulting"
	echo "binary meets licensing requirements. If you can't use GNU's runtime"
	echo "and STL library, then reconfigure with stlport or llvm. Also see"
	echo "http://code.google.com/p/android/issues/detail?id=216331"
	echo "*******************************************************************************"
fi

COUNT=$(echo -n "$AOSP_STL_LIB" | grep -i -c 'libstlport')
if [[ ("$COUNT" -ne "0") ]]; then
	echo
	echo "*******************************************************************************"
	echo "You are using STLport's runtime and STL library. STLport could cause problems"
	echo "if the resulting binary is used in other environments, like a QT project."
	echo "Also see http://code.google.com/p/android/issues/detail?id=216331"
	echo "*******************************************************************************"
fi

COUNT=$(echo -n "$AOSP_STL_LIB" | egrep -i -c 'libc\+\+')
if [[ ("$COUNT" -ne "0") ]]; then
	echo
	echo "*******************************************************************************"
	echo "You are using LLVM's runtime and STL library. LLVM could cause problems"
	echo "if the resulting binary is used in other environments, like a QT project."
	echo "Also see http://code.google.com/p/android/issues/detail?id=216331"
	echo "*******************************************************************************"
fi

echo
echo "*******************************************************************************"
echo "It looks the the environment is set correctly. Your next step is build"
echo "the library with 'make -f GNUmakefile-cross'. You can create a versioned"
echo "shared object using 'HAS_SOLIB_VERSION=1 make -f GNUmakefile-cross'"
echo "*******************************************************************************"
echo

[ "$0" = "$BASH_SOURCE" ] && exit 0 || return 0
