#!/usr/bin/env bash

#############################################################################
#
# This script sets the cross-compile environment for Xcode/iOS.
#
# Based upon OpenSSL's setenv-android.sh by TH, JW, and SM.
# Heavily modified by JWW for Crypto++.
# Modified some more by JW and UB.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# cpp is set to Apple's cpp. Actually, cpp is merely on-path so Apple's cpp
# is used. But Apple's cpp is sufficiently different from GNU's cpp and causes
# Autotools a lot of trouble because Autotools tests are predicated on GNU cpp.
# If your Autotools project results in "configure:6560: error: C preprocessor
# cpp fails sanity check", then file a bug report with Autotools.
#
# See http://www.cryptopp.com/wiki/iOS_(Command_Line) for more details
#############################################################################

#########################################
#####        Some validation        #####
#########################################

# In the past we could mostly infer arch or cpu from the SDK (and mostly
# vice-versa). Nowadays we need the user to set it for us because Apple
# platforms have both 32-bit or 64-bit variations.

# cryptest-ios.sh may run this script without sourcing.
if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    echo "setenv-ios.sh is usually sourced, but not this time."
fi

# This supports 'source setenv-ios.sh iPhone arm64' and
# 'source setenv-ios.sh IOS_SDK=iPhone IOS_CPU=arm64'
if [[ -n "$1" ]]
then
    arg1=$(echo "$1" | cut -f 1 -d '=')
    arg2=$(echo "$1" | cut -f 2 -d '=')
    if [[ -n "${arg2}" ]]; then
        IOS_SDK="${arg2}"
    else
        IOS_SDK="${arg1}"
    fi
    printf "Using positional arg, IOS_SDK=%s\n" "${IOS_SDK}"
fi

# This supports 'source setenv-ios.sh iPhone arm64' and
# 'source setenv-ios.sh IOS_SDK=iPhone IOS_CPU=arm64'
if [[ -n "$2" ]]
then
    arg1=$(echo "$2" | cut -f 1 -d '=')
    arg2=$(echo "$2" | cut -f 2 -d '=')
    if [[ -n "${arg2}" ]]; then
        IOS_CPU="${arg2}"
    else
        IOS_CPU="${arg1}"
    fi
    printf "Using positional arg, IOS_CPU=%s\n" "${IOS_CPU}"
fi

if [ -z "${IOS_SDK}" ]; then
    echo "IOS_SDK is not set. Please set it"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ -z "${IOS_CPU}" ]; then
    echo "IOS_CPU is not set. Please set it"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

DEF_CPPFLAGS="-DNDEBUG"
DEF_CFLAGS="-Wall -g2 -O3 -fPIC"
DEF_CXXFLAGS="-Wall -g2 -O3 -fPIC"
DEF_LDFLAGS=""

#########################################
#####       Clear old options       #####
#########################################

unset IS_IOS
unset IS_MACOS
unset IS_ANDROID
unset IS_ARM_EMBEDDED

unset IOS_CPPFLAGS
unset IOS_CFLAGS
unset IOS_CXXFLAGS
unset IOS_LDFLAGS
unset IOS_SYSROOT

#########################################
#####    Small Fixups, if needed    #####
#########################################

IOS_CPU=$(tr '[:upper:]' '[:lower:]' <<< "${IOS_CPU}")
ALT_SDK=$(tr '[:upper:]' '[:lower:]' <<< "${IOS_SDK}")

if [[ "${IOS_SDK}" == "iPhone" ]]; then
    IOS_SDK=iPhoneOS
elif [[ "$ALT_SDK" == "iphone" || "$ALT_SDK" == "iphoneos" ]]; then
    IOS_SDK=iPhoneOS
fi

if [[ "${IOS_SDK}" == "iPhoneSimulator" || "${IOS_SDK}" == "iPhoneOSSimulator" ]]; then
    IOS_SDK=iPhoneSimulator
elif [[ "$ALT_SDK" == "iphonesimulator" || "$ALT_SDK" == "iphoneossimulator" ]]; then
    IOS_SDK=iPhoneSimulator
fi

if [[ "${IOS_SDK}" == "TV" || "${IOS_SDK}" == "AppleTV" ]]; then
    IOS_SDK=AppleTVOS
elif [[ "$ALT_SDK" == "tv" || "$ALT_SDK" == "appletv" || "$ALT_SDK" == "appletvos" ]]; then
    IOS_SDK=AppleTVOS
fi

if [[ "${IOS_SDK}" == "Watch" || "${IOS_SDK}" == "AppleWatch" ]]; then
    IOS_SDK=WatchOS
elif [[ "$ALT_SDK" == "watch" || "$ALT_SDK" == "applewatch" || "$ALT_SDK" == "applewatchos" ]]; then
    IOS_SDK=WatchOS
fi

if [[ "${IOS_CPU}" == "amd64" || "${IOS_CPU}" == "x86_64" ]] ; then
    IOS_CPU=x86_64
fi

if [[ "${IOS_CPU}" == "i386" || "${IOS_CPU}" == "i586" || "${IOS_CPU}" == "i686" ]] ; then
    IOS_CPU=i386
fi

if [[ "${IOS_CPU}" == "aarch64" || "${IOS_CPU}" == "arm64"* || "${IOS_CPU}" == "armv8"* ]] ; then
    IOS_CPU=arm64
fi

echo "Configuring for ${IOS_SDK} (${IOS_CPU})"

########################################
#####         Environment          #####
########################################

# The flags below were tested with Xcode 8 on Travis. If
# you use downlevel versions of Xcode, then you can push
# xxx-version-min=n lower. For example, Xcode 7 can use
# -miphoneos-version-min=5. However, Xcode 7 lacks
# AppleTVOS and WatchOS support.

# Also see https://github.com/rust-lang/rust/issues/48862
# and https://developer.apple.com/documentation/bundleresources/information_property_list/minimumosversion

# iPhones can be either 32-bit or 64-bit
if [[ "${IOS_SDK}" == "iPhoneOS" && "${IOS_CPU}" == "armv7"* ]]; then
    MIN_VER=-miphoneos-version-min=6
elif [[ "${IOS_SDK}" == "iPhoneOS" && "${IOS_CPU}" == "arm64" ]]; then
    MIN_VER=-miphoneos-version-min=6

# Fixups for convenience
elif [[ "${IOS_SDK}" == "iPhoneOS" && "${IOS_CPU}" == "i386" ]]; then
    IOS_SDK=iPhoneSimulator
    # MIN_VER=-miphoneos-version-min=6
    MIN_VER=-miphonesimulator-version-min=6
elif [[ "${IOS_SDK}" == "iPhoneOS" && "${IOS_CPU}" == "x86_64" ]]; then
    IOS_SDK=iPhoneSimulator
    # MIN_VER=-miphoneos-version-min=6
    MIN_VER=-miphonesimulator-version-min=6

# Simulator builds
elif [[ "${IOS_SDK}" == "iPhoneSimulator" && "${IOS_CPU}" == "i386" ]]; then
    MIN_VER=-miphonesimulator-version-min=6
elif [[ "${IOS_SDK}" == "iPhoneSimulator" && "${IOS_CPU}" == "x86_64" ]]; then
    MIN_VER=-miphonesimulator-version-min=6
elif [[ "${IOS_SDK}" == "iPhoneSimulator" && "${IOS_CPU}" == "arm64" ]]; then
    MIN_VER=-miphonesimulator-version-min=6

# Apple TV can be 32-bit Intel (1st gen), 32-bit ARM (2nd, 3rd gen) or 64-bit ARM (4th gen)
elif [[ "${IOS_SDK}" == "AppleTVOS" && "${IOS_CPU}" == "i386" ]]; then
    MIN_VER=-mappletvos-version-min=6
elif [[ "${IOS_SDK}" == "AppleTVOS" && "${IOS_CPU}" == "armv7"* ]]; then
    MIN_VER=-mappletvos-version-min=6
elif [[ "${IOS_SDK}" == "AppleTVOS" && "${IOS_CPU}" == "arm64" ]]; then
    MIN_VER=-mappletvos-version-min=6

# Simulator builds
elif [[ "${IOS_SDK}" == "AppleTVSimulator" && "${IOS_CPU}" == "i386" ]]; then
    MIN_VER=-mappletvsimulator-version-min=6
elif [[ "${IOS_SDK}" == "AppleTVSimulator" && "${IOS_CPU}" == "x86_64" ]]; then
    MIN_VER=-mappletvsimulator-version-min=6

# Watch can be either 32-bit or 64-bit ARM. TODO: figure out which
# -mwatchos-version-min=n is needed for arm64. 9 is not enough.
elif [[ "${IOS_SDK}" == "WatchOS" && "${IOS_CPU}" == "armv7"* ]]; then
    MIN_VER=-mwatchos-version-min=6
elif [[ "${IOS_SDK}" == "WatchOS" && "${IOS_CPU}" == "arm64" ]]; then
    MIN_VER=-mwatchos-version-min=6

# Simulator builds. TODO: figure out which -watchos-version-min=n
# is needed for arm64. 6 compiles and links, but is it correct?
elif [[ "${IOS_SDK}" == "WatchSimulator" && "${IOS_CPU}" == "i386" ]]; then
    MIN_VER=-mwatchsimulator-version-min=6
elif [[ "${IOS_SDK}" == "WatchSimulator" && "${IOS_CPU}" == "x86_64" ]]; then
    MIN_VER=-mwatchsimulator-version-min=6

# And the final catch-all
else
    echo "IOS_SDK and IOS_CPU are not valid. Please fix them"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#####################################################################

# Xcode 6 and below cannot handle -miphonesimulator-version-min
# Fix it so the simulator will compile as expected. This trick
# may work on other platforms, but it was not tested.

if [ -n "$(command -v xcodebuild 2>/dev/null)" ]; then
    # Output of xcodebuild is similar to "Xcode 6.2". The first cut gets
    # the dotted decimal value. The second cut gets the major version.
    XCODE_VERSION=$(xcodebuild -version 2>/dev/null | head -n 1 | cut -f 2 -d ' ' | cut -f 1 -d '.')
    if [ -z "${XCODE_VERSION}" ]; then XCODE_VERSION=100; fi

    if [ "${XCODE_VERSION}" -le 6 ]; then
        MIN_VER="${MIN_VER//iphonesimulator/iphoneos}"
    fi
fi

#####################################################################

# Allow a user override? I think we should be doing this. The use case is:
# move /Applications/Xcode somewhere else for a side-by-side installation.
if [ -z "${XCODE_DEVELOPER-}" ]; then
  XCODE_DEVELOPER=$(xcode-select -print-path 2>/dev/null)
fi

if [ ! -d "${XCODE_DEVELOPER}" ]; then
  echo "ERROR: unable to find XCODE_DEVELOPER directory."
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# XCODE_DEVELOPER_SDK is the SDK location.
XCODE_DEVELOPER_SDK="${XCODE_DEVELOPER}/Platforms/$IOS_SDK.platform/Developer/SDKs"

if [ ! -d "${XCODE_DEVELOPER_SDK}" ]; then
  echo "ERROR: unable to find XCODE_DEVELOPER_SDK directory."
  echo "       Is the SDK supported by Xcode and installed?"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# XCODE_TOOLCHAIN is the location of the actual compiler tools.
if [ -d "${XCODE_DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin/" ]; then
  XCODE_TOOLCHAIN="${XCODE_DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin/"
elif [ -d "${XCODE_DEVELOPER_SDK}/Developer/usr/bin/" ]; then
  XCODE_TOOLCHAIN="${XCODE_DEVELOPER_SDK}/Developer/usr/bin/"
fi

if [ ! -d "${XCODE_TOOLCHAIN}" ]; then
  echo "ERROR: unable to find Xcode cross-compiler tools."
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# XCODE_SDK is the SDK name/version being used - adjust the list as appropriate.
# For example, remove 4.3, 6.2, and 6.1 if they are not installed. We go back to
# the 1.0 SDKs because Apple WatchOS uses low numbers, like 2.0 and 2.1.
XCODE_SDK=""
for i in $(seq 30 -1 5)  # SDK major
do
    for j in $(seq 20 -1 0)  # SDK minor
    do
        SDK_VER="$i.$j"
        if [ -d "${XCODE_DEVELOPER_SDK}/${IOS_SDK}${SDK_VER}.sdk" ]; then
            XCODE_SDK="${IOS_SDK}${SDK_VER}.sdk"
            break 2
        fi
    done
done

# Error checking
if [ -z "${XCODE_SDK}" ]; then
    echo "ERROR: unable to find a SDK."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

IOS_CFLAGS="-arch ${IOS_CPU} ${MIN_VER} -fno-common"
IOS_CXXFLAGS="-arch ${IOS_CPU} ${MIN_VER} -stdlib=libc++ -fno-common"
IOS_SYSROOT="${XCODE_DEVELOPER_SDK}/${XCODE_SDK}"

if [ ! -d "${IOS_SYSROOT}" ]; then
  echo "ERROR: unable to find Xcode sysroot."
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# The simulators need to disable ASM. They don't receive arch flags.
# https://github.com/weidai11/cryptopp/issues/635
if [[ "${IOS_SDK}" == *"Simulator" ]]; then
    IOS_CPPFLAGS="$IOS_CPPFLAGS -DCRYPTOPP_DISABLE_ASM"
fi

#####################################################################

CPP="cpp"; CC="clang"; CXX="clang++"; LD="ld"
AS="as"; AR="libtool"; RANLIB="ranlib"
STRIP="strip"; OBJDUMP="objdump"

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$CC" ]; then
    echo "ERROR: Failed to find iOS clang. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$CXX" ]; then
    echo "ERROR: Failed to find iOS clang++. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$RANLIB" ]; then
    echo "ERROR: Failed to find iOS ranlib. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$AR" ]; then
    echo "ERROR: Failed to find iOS ar. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$AS" ]; then
    echo "ERROR: Failed to find iOS as. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$LD" ]; then
    echo "ERROR: Failed to find iOS ld. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#####################################################################

# Add tools to head of path, if not present already
LENGTH=${#XCODE_TOOLCHAIN}
SUBSTR=${PATH:0:$LENGTH}
if [ "${SUBSTR}" != "${XCODE_TOOLCHAIN}" ]; then
    export PATH="${XCODE_TOOLCHAIN}:${PATH}"
fi

#####################################################################

VERBOSE=${VERBOSE:-1}
if [ "$VERBOSE" -gt 0 ]; then
  echo "XCODE_TOOLCHAIN: ${XCODE_TOOLCHAIN}"
  echo "IOS_SDK: ${IOS_SDK}"
  echo "IOS_CPU: ${IOS_CPU}"
  if [ -n "${IOS_CPPFLAGS}" ]; then
    echo "IOS_CPPFLAGS: ${IOS_CPPFLAGS}"
  fi
  echo "IOS_CFLAGS: ${IOS_CFLAGS}"
  echo "IOS_CXXFLAGS: ${IOS_CXXFLAGS}"
  if [ -n "${IOS_LDFLAGS}" ]; then
    echo "IOS_LDFLAGS: ${IOS_LDFLAGS}"
  fi
  echo "IOS_SYSROOT: ${IOS_SYSROOT}"
fi

#####################################################################

# GNUmakefile-cross and Autotools expect these to be set.
# Note: prior to Crypto++ 8.6, CPPFLAGS, CXXFLAGS and LDFLAGS were not
# exported. At Crypto++ 8.6 CPPFLAGS, CXXFLAGS and LDFLAGS were exported.

export IS_IOS=1
export CPP CC CXX LD AS AR RANLIB STRIP OBJDUMP

CPPFLAGS="${DEF_CPPFLAGS} ${IOS_CPPFLAGS} -isysroot ${IOS_SYSROOT}"
CFLAGS="${DEF_CFLAGS} ${IOS_CFLAGS}"
CXXFLAGS="${DEF_CXXFLAGS} ${IOS_CXXFLAGS}"
LDFLAGS="${DEF_LDFLAGS} ${IOS_LDFLAGS} --sysroot ${IOS_SYSROOT}"

# Trim whitespace as needed
CPPFLAGS=$(echo "${CPPFLAGS}" | awk '{$1=$1;print}')
CFLAGS=$(echo "${CFLAGS}" | awk '{$1=$1;print}')
CXXFLAGS=$(echo "${CXXFLAGS}" | awk '{$1=$1;print}')
LDFLAGS=$(echo "${LDFLAGS}" | awk '{$1=$1;print}')

export CPPFLAGS CFLAGS CXXFLAGS LDFLAGS

#####################################################################

echo
echo "*******************************************************************************"
echo "It looks the the environment is set correctly. Your next step is build"
echo "the library with 'make -f GNUmakefile-cross'."
echo "*******************************************************************************"
echo

[ "$0" = "${BASH_SOURCE[0]}" ] && exit 0 || return 0
