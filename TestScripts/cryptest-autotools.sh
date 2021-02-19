#!/usr/bin/env bash

#############################################################################
#
# This script tests the Autotools gear.
#
# Written and placed in public domain by Jeffrey Walton.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See https://www.cryptopp.com/wiki/Autotools for more details
#
#############################################################################

# Default tools
GREP=grep
SED=sed
AWK=awk
MAKE=make

#############################################################################

# Fixup, Solaris and friends
if [[ -d /usr/xpg4/bin ]]; then
	SED=/usr/xpg4/bin/sed
	AWK=/usr/xpg4/bin/awk
	GREP=/usr/xpg4/bin/grep
elif [[ -d /usr/bin/posix ]]; then
	SED=/usr/bin/posix/sed
	AWK=/usr/bin/posix/awk
	GREP=/usr/bin/posix/grep
fi

# Fixup for sed and "illegal byte sequence"
IS_DARWIN=$(uname -s 2>/dev/null | "$GREP" -i -c darwin)
if [[ "$IS_DARWIN" -ne 0 ]]; then
	export LC_ALL=C
fi

# Fixup for Solaris and BSDs
if [[ -n "$(command -v gmake 2>/dev/null)" ]]; then
	MAKE=gmake
else
	MAKE=make
fi

# Fixup for missing libtool
if [[ ! -z $(command -v glibtoolize 2>/dev/null) ]]; then
	export LIBTOOLIZE=$(command -v glibtoolize)
elif [[ ! -z $(command -v libtoolize 2>/dev/null) ]]; then
	export LIBTOOLIZE=$(command -v libtoolize)
elif [[ ! -z $(command -v glibtool 2>/dev/null) ]]; then
	export LIBTOOLIZE=$(command -v glibtool)
elif [[ ! -z $(command -v libtool 2>/dev/null) ]]; then
	export LIBTOOLIZE=$(command -v libtool)
fi

# In case libtool is located in /opt, like under MacPorts or Compile Farm
if [[ -z $(command -v glibtoolize 2>/dev/null) ]]; then
	export LIBTOOLIZE=$(find /opt -name libtool 2>/dev/null | head -n 1)
fi

#############################################################################

if [[ -z $(command -v aclocal 2>/dev/null) ]]; then
	echo "Cannot find aclocal. Things may fail."
fi

if [[ -z $(command -v autoupdate 2>/dev/null) ]]; then
	echo "Cannot find autoupdate. Things may fail."
fi

if [[ -z "$LIBTOOLIZE" ]]; then
	echo "Cannot find libtoolize. Things may fail."
fi

if [[ -z $(command -v automake 2>/dev/null) ]]; then
	echo "Cannot find automake. Things may fail."
fi

if [[ -z $(command -v autoreconf 2>/dev/null) ]]; then
	echo "Cannot find autoreconf. Things may fail."
fi

if [[ -z $(command -v curl 2>/dev/null) ]]; then
	echo "Cannot find cURL. Things may fail."
fi

#############################################################################

files=(configure.ac Makefile.am libcryptopp.pc.in)

for file in "${files[@]}"; do
	echo "Downloading $file"
	if ! curl -L -s -o "$file" "https://raw.githubusercontent.com/noloader/cryptopp-autotools/master/$file"; then
		echo "$file download failed"
		exit 1
	fi
    # Throttle
    sleep 1
done

mkdir -p m4/

#############################################################################

echo "Running aclocal"
if ! aclocal &>/dev/null; then
	echo "aclocal failed."
	exit 1
fi

echo "Running autoupdate"
if ! autoupdate &>/dev/null; then
	echo "autoupdate failed."
	exit 1
fi

# Run autoreconf twice on failure. Also see
# https://github.com/tracebox/tracebox/issues/57
echo "Running autoreconf"
if ! autoreconf --force --install &>/dev/null; then
	echo "autoreconf failed, running again."
	if ! autoreconf --force --install; then
		echo "autoreconf failed, again."
		exit 1
	fi
fi

#############################################################################

# Update config.sub config.guess. GNU recommends using the latest for all projects.
echo "Updating config.sub"
curl -L -s -o config.sub.new 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub'

# Solaris removes +w, can't overwrite
chmod +w build-aux/config.sub
mv config.sub.new build-aux/config.sub
chmod +x build-aux/config.sub

if [[ "$IS_DARWIN" -ne 0 ]] && [[ -n $(command -v xattr 2>/dev/null) ]]; then
	echo "Removing config.sub quarantine"
	xattr -d "com.apple.quarantine" build-aux/config.sub &>/dev/null
fi

echo "Updating config.guess"
curl -L -s -o config.guess.new 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess'

# Solaris removes +w, can't overwrite
chmod +w build-aux/config.guess
mv config.guess.new build-aux/config.guess
chmod +x build-aux/config.guess

if [[ "$IS_DARWIN" -ne 0 ]] && [[ -n $(command -v xattr 2>/dev/null) ]]; then
	echo "Removing config.guess quarantine"
	xattr -d "com.apple.quarantine" build-aux/config.guess &>/dev/null
fi

#############################################################################

echo "Running configure"
echo ""

if ! ./configure; then
	echo "configure failed."
	exit 1
fi

#############################################################################

echo ""
echo "Building test artifacts"
echo ""

"$MAKE" clean &>/dev/null

if ! "$MAKE" -j2 -f Makefile; then
	echo "make failed."
	exit 1
fi

#############################################################################

echo ""
echo "Testing library"
echo ""

if ! ./cryptest v; then
	echo "cryptest v failed."
	exit 1
fi

if ! ./cryptest tv all; then
	echo "cryptest tv all failed."
	exit 1
fi

#############################################################################

echo ""
echo "Building tarball"
echo ""

if ! make dist; then
	echo "make dist failed."
	exit 1
fi

# Return success
exit 0
