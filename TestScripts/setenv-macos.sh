#!/usr/bin/env bash

#############################################################################
#
# This script sets the cross-compile environment for Xcode/MacOS.
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
# See http://www.cryptopp.com/wiki/MacOS_(Command_Line) for more details
#############################################################################

#########################################
#####        Some validation        #####
#########################################

# In the past we could mostly infer arch or cpu from the SDK (and mostly
# vice-versa). Nowadays we need the user to set it for us because Apple
# platforms have both 32-bit or 64-bit variations.

# cryptest-macos.sh may run this script without sourcing.
if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    echo "setenv-macos.sh is usually sourced, but not this time."
fi

# This is fixed since we are building for MacOS
MACOS_SDK=MacOSX

# This supports 'source setenv-macos.sh x86_64' and
# 'source setenv-macos.sh MACOS_CPU=arm64'
if [[ -n "$1" ]]
then
    arg1=$(echo "$1" | cut -f 1 -d '=')
    arg2=$(echo "$1" | cut -f 2 -d '=')
    if [[ -n "${arg2}" ]]; then
        MACOS_CPU="${arg2}"
    else
        MACOS_CPU="${arg1}"
    fi
    printf "Using positional arg, MACOS_CPU=%s\n" "${MACOS_CPU}"
fi

# Sane default. Use current machine.
if [ -z "$MACOS_CPU" ]; then
    MACOS_CPU="$(uname -m 2>/dev/null)"
    if [[ "$MACOS_CPU" == "Power"* ]] ; then
        if sysctl -a 2>/dev/null | grep -q 'hw.cpu64bit_capable: 1'; then
            MACOS_CPU="ppc64"
        else
            MACOS_CPU="ppc"
        fi
    fi
fi

if [ -z "$MACOS_CPU" ]; then
    echo "MACOS_CPU is not set. Please set it"
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

unset MACOS_CPPFLAGS
unset MACOS_CFLAGS
unset MACOS_CXXFLAGS
unset MACOS_LDFLAGS
unset MACOS_SYSROOT

#########################################
#####    Small Fixups, if needed    #####
#########################################

MACOS_CPU=$(tr '[:upper:]' '[:lower:]' <<< "${MACOS_CPU}")

# Old world Macs
if [[ "$MACOS_CPU" == "power macintosh" || "$MACOS_CPU" == "powerpc" ]] ; then
    MACOS_CPU=ppc
fi

if [[ "$MACOS_CPU" == "ppc64" || "$MACOS_CPU" == "powerpc64" ]] ; then
    MACOS_CPU=ppc64
fi

if [[ "$MACOS_CPU" == "386" || "$MACOS_CPU" == "i686" || "$MACOS_CPU" == "686" ]] ; then
    MACOS_CPU=i386
fi

if [[ "$MACOS_CPU" == "amd64" || "$MACOS_CPU" == "x86_64" ]] ; then
    MACOS_CPU=x86_64
fi

if [[ "$MACOS_CPU" == "aarch64" || "$MACOS_CPU" == "arm64"* || "$MACOS_CPU" == "armv8"* ]] ; then
    MACOS_CPU=arm64
fi

echo "Configuring for $MACOS_SDK ($MACOS_CPU)"

########################################
#####         Environment          #####
########################################

# The flags below were tested with Xcode 8 on Travis. If
# you use downlevel versions of Xcode, then you can push
# xxx-version-min=n lower. For example, Xcode 7 can use
# -mmacosx-version-min=5. However, you cannot link
# against LLVM's libc++.

# Also see https://github.com/rust-lang/rust/issues/48862
# and https://developer.apple.com/documentation/bundleresources/information_property_list/minimumosversion

# PowerMacs and Intels can be either 32-bit or 64-bit
if [[ "$MACOS_CPU" == "ppc" ]]; then
    MIN_VER="-mmacosx-version-min=10.4"

elif [[ "$MACOS_CPU" == "ppc64" ]]; then
    MIN_VER="-mmacosx-version-min=10.4"

elif [[ "$MACOS_CPU" == "i386" ]]; then
    MIN_VER="-mmacosx-version-min=10.7"

elif [[ "$MACOS_CPU" == "x86_64" ]]; then
    MIN_VER="-mmacosx-version-min=10.7"

elif [[ "$MACOS_CPU" == "arm64" ]]; then
    MIN_VER="-mmacosx-version-min=11.0"

# And the final catch-all
else
    echo "MACOS_CPU is not valid. Please fix it"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# The first cut if MIN_VER gets the full version, like 10.7. The
# second cut gets the major or minor version
if echo "${MIN_VER}" | grep -q '.'; then
    MAJOR_VER=$(echo "${MIN_VER}" | head -n 1 | cut -f 2 -d '=' | cut -f 1 -d '.')
    MINOR_VER=$(echo "${MIN_VER}" | head -n 1 | cut -f 2 -d '=' | cut -f 2 -d '.')
else
    MAJOR_VER=$(echo "${MIN_VER}" | head -n 1 | cut -f 2 -d '=' | cut -f 1 -d '.')
    MINOR_VER=0
fi

# OS X 10.7 minimum required for LLVM and -stdlib=libc++
if [[ "${MAJOR_VER}" -eq 10 && "${MINOR_VER}" -ge 7 ]]; then
     MACOS_STDLIB="-stdlib=libc++"
elif [[ "${MAJOR_VER}" -ge 11 ]]; then
     MACOS_STDLIB="-stdlib=libc++"
fi

# Allow a user override? I think we should be doing this. The use case is:
# move /Applications/Xcode somewhere else for a side-by-side installation.
if [ -z "${XCODE_DEVELOPER-}" ]; then
  XCODE_DEVELOPER=$(xcode-select -print-path 2>/dev/null)
fi

if [ ! -d "${XCODE_DEVELOPER}" ]; then
  echo "ERROR: unable to find XCODE_DEVELOPER directory."
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [[ "${XCODE_DEVELOPER}" == "/Developer"* ]]; then
   ANTIQUE_XCODE=1
   DEF_CFLAGS=$(echo "$DEF_CFLAGS" | sed 's/-Wall //g')
   DEF_CXXFLAGS=$(echo "$DEF_CXXFLAGS" | sed 's/-Wall //g')
fi

# Command Line Tools show up here on a Mac-mini M1
if [[ "${XCODE_DEVELOPER}" == "/Library"* ]]; then
   CLT_XCODE=1
fi

# XCODE_DEVELOPER_SDK is the SDK location.
if [[ "${ANTIQUE_XCODE}" == "1" ]]
then
    if [[ -d "${XCODE_DEVELOPER}/SDKs" ]]; then
        XCODE_DEVELOPER_SDK="${XCODE_DEVELOPER}/SDKs"
    fi

    if [ ! -d "${XCODE_DEVELOPER_SDK}" ]; then
      echo "ERROR: unable to find XCODE_DEVELOPER_SDK directory."
      echo "       Is the SDK supported by Xcode and installed?"
      [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
    fi

elif [[ "${CLT_XCODE}" == "1" ]]
then
    if [[ -d "${XCODE_DEVELOPER}/SDKs" ]]; then
        XCODE_DEVELOPER_SDK="${XCODE_DEVELOPER}/SDKs"
    fi

    if [ ! -d "${XCODE_DEVELOPER_SDK}" ]; then
      echo "ERROR: unable to find XCODE_DEVELOPER_SDK directory."
      echo "       Is the SDK supported by Xcode and installed?"
      [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
    fi

else
    if [[ -d "${XCODE_DEVELOPER}/Platforms/${MACOS_SDK}.platform" ]]; then
        XCODE_DEVELOPER_SDK="${XCODE_DEVELOPER}/Platforms/${MACOS_SDK}.platform/Developer/SDKs"
    fi
fi

# XCODE_SDK is the SDK name/version being used - adjust the list as appropriate.
# For example, remove 4.3, 6.2, and 6.1 if they are not installed. We go back to
# the 1.0 SDKs because Apple WatchOS uses low numbers, like 2.0 and 2.1.
XCODE_SDK=""
if [[ "${ANTIQUE_XCODE}" == "1" ]]
then
    for i in 10.7 10.6 10.5 10.4 10.3 10.2 10.0
    do
        if [ -d "${XCODE_DEVELOPER_SDK}/${MACOS_SDK}$i.sdk" ]; then
            XCODE_SDK="${MACOS_SDK}$i.sdk"
            break
        fi
    done
else
    for i in $(seq 30 -1 5)  # SDK major
    do
        for j in $(seq 20 -1 0)  # SDK minor
        do
            SDK_VER="$i.$j"
            if [ -d "${XCODE_DEVELOPER_SDK}/${MACOS_SDK}${SDK_VER}.sdk" ]; then
                XCODE_SDK="${MACOS_SDK}${SDK_VER}.sdk"
                break 2
            fi
        done
    done
fi

# Error checking
if [ -z "${XCODE_SDK}" ]; then
    echo "ERROR: unable to find a SDK."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# XCODE_DEVELOPER_SDK is the SDK location.
if [[ "${ANTIQUE_XCODE}" == "1" ]]
then
    # XCODE_DEVELOPER_SDK for old Xcode is above
    :
else
    if [ ! -d "${XCODE_DEVELOPER_SDK}" ]; then
      echo "ERROR: unable to find XCODE_DEVELOPER_SDK directory."
      echo "       Is the SDK supported by Xcode and installed?"
      [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
    fi
fi

# XCODE_TOOLCHAIN is the location of the actual compiler tools.
if [[ "${ANTIQUE_XCODE}" == "1" ]]
then
    if [ -d "${XCODE_DEVELOPER}/usr/bin" ]; then
      XCODE_TOOLCHAIN="${XCODE_DEVELOPER}/usr/bin"
    fi

elif [[ "${CLT_XCODE}" == "1" ]]
then
    if [ -d "${XCODE_DEVELOPER}/usr/bin" ]; then
      XCODE_TOOLCHAIN="${XCODE_DEVELOPER}/usr/bin"
    fi

else
    if [ -d "${XCODE_DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin/" ]; then
      XCODE_TOOLCHAIN="${XCODE_DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin/"
    elif [ -d "${XCODE_DEVELOPER_SDK}/Developer/usr/bin/" ]; then
      XCODE_TOOLCHAIN="${XCODE_DEVELOPER_SDK}/Developer/usr/bin/"
    elif [ -d "${XCODE_DEVELOPER_SDK}/usr/bin/" ]; then
      XCODE_TOOLCHAIN="${XCODE_DEVELOPER_SDK}/usr/bin/"
    fi
fi

if [ ! -d "${XCODE_TOOLCHAIN}" ]; then
  echo "ERROR: unable to find Xcode cross-compiler tools."
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

MACOS_CFLAGS="-arch $MACOS_CPU $MIN_VER -fno-common"
MACOS_CXXFLAGS="-arch $MACOS_CPU $MIN_VER ${MACOS_STDLIB} -fno-common"
MACOS_SYSROOT="${XCODE_DEVELOPER_SDK}/${XCODE_SDK}"

if [ ! -d "${MACOS_SYSROOT}" ]; then
  echo "ERROR: unable to find Xcode sysroot."
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#####################################################################

CPP="cpp"; CC="clang"; CXX="clang++"; LD="ld"
AS="as"; AR="libtool"; RANLIB="ranlib"
STRIP="strip"; OBJDUMP="objdump"

if [[ "${ANTIQUE_XCODE}" == "1" ]]
then
    CC="gcc"; CXX="g++";
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$CC" ]; then
    echo "ERROR: Failed to find MacOS clang. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$CXX" ]; then
    echo "ERROR: Failed to find MacOS clang++. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$RANLIB" ]; then
    echo "ERROR: Failed to find MacOS ranlib. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$AR" ]; then
    echo "ERROR: Failed to find MacOS ar. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$AS" ]; then
    echo "ERROR: Failed to find MacOS as. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Error checking
if [ ! -e "${XCODE_TOOLCHAIN}/$LD" ]; then
    echo "ERROR: Failed to find MacOS ld. Please edit this script."
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

#####################################################################

# Add tools to head of path, if not present already
LENGTH=${#XCODE_TOOLCHAIN}
SUBSTR=${PATH:0:$LENGTH}
if [ "${SUBSTR}" != "${XCODE_TOOLCHAIN}" ]; then
    PATH="${XCODE_TOOLCHAIN}:$PATH"
    export PATH
fi

#####################################################################

VERBOSE=${VERBOSE:-1}
if [ "$VERBOSE" -gt 0 ]; then
  echo "XCODE_TOOLCHAIN: ${XCODE_TOOLCHAIN}"
  echo "MACOS_SDK: ${MACOS_SDK}"
  echo "MACOS_CPU: ${MACOS_CPU}"
  if [ -n "${MACOS_CPPFLAGS}" ]; then
    echo "MACOS_CPPFLAGS: ${MACOS_CPPFLAGS}"
  fi
  echo "MACOS_CFLAGS: ${MACOS_CFLAGS}"
  echo "MACOS_CXXFLAGS: ${MACOS_CXXFLAGS}"
  if [ -n "${MACOS_LDFLAGS}" ]; then
    echo "MACOS_LDFLAGS: ${MACOS_LDFLAGS}"
  fi
  echo "MACOS_SYSROOT: ${MACOS_SYSROOT}"
fi

#####################################################################

# GNUmakefile-cross and Autotools expect these to be set.
# Note: prior to Crypto++ 8.6, CPPFLAGS, CXXFLAGS and LDFLAGS were not
# exported. At Crypto++ 8.6 CPPFLAGS, CXXFLAGS and LDFLAGS were exported.

export IS_MACOS=1
export CPP CC CXX LD AS AR RANLIB STRIP OBJDUMP

if [[ "${ANTIQUE_XCODE}" == "1" ]]
then
    CPPFLAGS="${DEF_CPPFLAGS} ${MACOS_CPPFLAGS} -isysroot ${MACOS_SYSROOT}"
    CFLAGS="${DEF_CFLAGS} ${MACOS_CFLAGS}"
    CXXFLAGS="${DEF_CXXFLAGS} ${MACOS_CXXFLAGS}"
    LDFLAGS="${DEF_LDFLAGS} ${MACOS_LDFLAGS} -sysroot=${MACOS_SYSROOT}"
else
    CPPFLAGS="${DEF_CPPFLAGS} ${MACOS_CPPFLAGS} -isysroot ${MACOS_SYSROOT}"
    CFLAGS="${DEF_CFLAGS} ${MACOS_CFLAGS}"
    CXXFLAGS="${DEF_CXXFLAGS} ${MACOS_CXXFLAGS}"
    LDFLAGS="${DEF_LDFLAGS} ${MACOS_LDFLAGS} --sysroot ${MACOS_SYSROOT}"
fi

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
