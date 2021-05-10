#!/usr/bin/env bash

#############################################################################
#
# This script sets the cross-compile environment for ARM embedded.
#
# Based upon OpenSSL's setenv-android.sh by TH, JW, and SM.
# Heavily modified by JWW for Crypto++.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/ARM_Embedded_(Command_Line) for details.
#############################################################################

# cryptest-embedded.sh may run this script without sourcing.
if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    echo "setenv-embedded.sh is usually sourced, but not this time."
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

unset ARM_EMBEDDED_CPPFLAGS
unset ARM_EMBEDDED_CFLAGS
unset ARM_EMBEDDED_HEADERS
unset ARM_EMBEDDED_CXX_HEADERS
unset ARM_EMBEDDED_CXXFLAGS
unset ARM_EMBEDDED_LDFLAGS
unset ARM_EMBEDDED_SYSROOT

########################################
#####         Environment          #####
########################################

if [ -z "${ARM_EMBEDDED_TOOLCHAIN-}" ]; then
    ARM_EMBEDDED_TOOLCHAIN="/usr/bin"
fi

if [ ! -d "${ARM_EMBEDDED_TOOLCHAIN}" ]; then
    echo "ARM_EMBEDDED_TOOLCHAIN is not valid"
    [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Fedora
# TOOL_PREFIX="arm-linux-gnu"

# Ubuntu
TOOL_PREFIX="arm-linux-gnueabi"

CPP="${ARM_EMBEDDED_TOOLCHAIN}/${TOOL_PREFIX}-cpp"
CC="${ARM_EMBEDDED_TOOLCHAIN}/${TOOL_PREFIX}-gcc"
CXX="${ARM_EMBEDDED_TOOLCHAIN}/${TOOL_PREFIX}-g++"
LD="${ARM_EMBEDDED_TOOLCHAIN}/${TOOL_PREFIX}-ld"
AR="${ARM_EMBEDDED_TOOLCHAIN}/${TOOL_PREFIX}-ar"
AS="${ARM_EMBEDDED_TOOLCHAIN}/${TOOL_PREFIX}-as"
RANLIB="${ARM_EMBEDDED_TOOLCHAIN}/${TOOL_PREFIX}-ranlib"
OBJDUMP="${ARM_EMBEDDED_TOOLCHAIN}/${TOOL_PREFIX}-objdump"

# Test a few of the tools
if [ ! -e "$CPP" ]; then
  echo "ERROR: CPP is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ ! -e "$CC" ]; then
  echo "ERROR: CC is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ ! -e "$CXX" ]; then
  echo "ERROR: CXX is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ ! -e "$AR" ]; then
  echo "ERROR: AR is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ ! -e "$AS" ]; then
  echo "ERROR: AS is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ ! -e "$RANLIB" ]; then
  echo "ERROR: RANLIB is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ ! -e "$LD" ]; then
  echo "ERROR: LD is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ -z "${ARM_EMBEDDED_SYSROOT}" ]; then
  ARM_EMBEDDED_SYSROOT="/usr/arm-linux-gnueabi"
fi

if [ ! -d "${ARM_EMBEDDED_SYSROOT}" ]; then
  echo "ERROR: ARM_EMBEDDED_SYSROOT is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Fix C++ header paths for Ubuntu
# ARM_EMBEDDED_TOOLCHAIN_VERSION="4.7.3"
ARM_EMBEDDED_TOOLCHAIN_VERSION="5.4.0"
ARM_EMBEDDED_CXX_HEADERS="${ARM_EMBEDDED_SYSROOT}/include/c++/${ARM_EMBEDDED_TOOLCHAIN_VERSION}"

if [ ! -d "${ARM_EMBEDDED_CXX_HEADERS}" ]; then
  echo "ERROR: ARM_EMBEDDED_CXX_HEADERS is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

if [ ! -d "${ARM_EMBEDDED_CXX_HEADERS}/arm-linux-gnueabi" ]; then
  echo "ERROR: ARM_EMBEDDED_CXX_HEADERS is not valid"
  [ "$0" = "${BASH_SOURCE[0]}" ] && exit 1 || return 1
fi

# Add additional flags below, like -mcpu=cortex-m3.
if [ -z "${ARM_EMBEDDED_HEADERS}" ]; then
  ARM_EMBEDDED_HEADERS="-I\"${ARM_EMBEDDED_CXX_HEADERS}\" -I\"${ARM_EMBEDDED_CXX_HEADERS}/arm-linux-gnueabi\""
fi

#####################################################################

VERBOSE=${VERBOSE:-1}
if [ "$VERBOSE" -gt 0 ]; then
  echo "ARM_EMBEDDED_TOOLCHAIN: ${ARM_EMBEDDED_TOOLCHAIN}"
  if [[ -n "${ARM_EMBEDDED_CPPFLAGS}" ]]; then
    echo "ARM_EMBEDDED_CPPFLAGS: ${ARM_EMBEDDED_CPPFLAGS}"
  fi
  echo "ARM_EMBEDDED_CFLAGS: ${ARM_EMBEDDED_CFLAGS}"
  echo "ARM_EMBEDDED_CXXFLAGS: ${ARM_EMBEDDED_CXXFLAGS}"
  if [[ -n "${ARM_EMBEDDED_LDFLAGS}" ]]; then
    echo "ARM_EMBEDDED_LDFLAGS: ${ARM_EMBEDDED_LDFLAGS}"
  fi
  echo "ARM_EMBEDDED_SYSROOT: ${ARM_EMBEDDED_SYSROOT}"
fi

#####################################################################

# GNUmakefile-cross and Autotools expect these to be set.
# Note: prior to Crypto++ 8.6, CPPFLAGS, CXXFLAGS and LDFLAGS were not
# exported. At Crypto++ 8.6 CPPFLAGS, CXXFLAGS and LDFLAGS were exported.

export IS_ARM_EMBEDDED=1
export CPP CC CXX LD AS AR RANLIB STRIP OBJDUMP

CPPFLAGS="${DEF_CPPFLAGS} ${ARM_EMBEDDED_CPPFLAGS} ${ARM_EMBEDDED_HEADERS} -isysroot ${ARM_EMBEDDED_SYSROOT}"
CFLAGS="${DEF_CFLAGS} ${ARM_EMBEDDED_CFLAGS}"
CXXFLAGS="${DEF_CXXFLAGS} ${ARM_EMBEDDED_CXXFLAGS}"
LDFLAGS="${DEF_LDFLAGS} ${ARM_EMBEDDED_LDFLAGS} --sysroot ${ARM_EMBEDDED_SYSROOT}"

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
