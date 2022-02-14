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

if ! command -v wget >/dev/null 2>&1; then
    if ! command -v curl >/dev/null 2>&1; then
        echo "wget and curl not found. Things will fail"
        exit 1
    fi
fi

#############################################################################

# Default tools
GREP=grep
SED=sed
AWK=awk
MAKE=make

# Fixup, Solaris and friends
if [ -d /usr/xpg4/bin ]; then
	SED=/usr/xpg4/bin/sed
	AWK=/usr/xpg4/bin/awk
	GREP=/usr/xpg4/bin/grep
elif [ -d /usr/bin/posix ]; then
	SED=/usr/bin/posix/sed
	AWK=/usr/bin/posix/awk
	GREP=/usr/bin/posix/grep
fi

if command -v wget >/dev/null 2>&1; then
    FETCH_CMD="wget -q -O"
elif command -v curl >/dev/null 2>&1; then
    FETCH_CMD="curl -L -s -o"
else
    FETCH_CMD="curl-and-wget-not-found"
fi

# Fixup for sed and "illegal byte sequence"
IS_DARWIN=`uname -s 2>&1 | "$GREP" -i -c darwin`
if [ "$IS_DARWIN" -ne 0 ]; then
	LC_ALL=C; export LC_ALL
fi

# Fixup for Solaris and BSDs
if [ command -v gmake >/dev/null 2>&1 ]; then
	MAKE=gmake
fi

#############################################################################

files=(bootstrap.sh configure.ac Makefile.am libcryptopp.pc.in)

for file in "${files[@]}"; do
	echo "Downloading $file"
	if ! ${FETCH_CMD} "$file" "https://raw.githubusercontent.com/noloader/cryptopp-autotools/master/$file"; then
		echo "$file download failed"
		exit 1
	fi

	if file "$file" | $GREP -q 'executable'; then
	    chmod +x "$file"
	fi

    # Throttle
    sleep 1
done

if [ "$IS_DARWIN" -ne 0 ] && [ command -v xattr >/dev/null 2>&1 ]; then
	echo "Removing bootstrap.sh quarantine"
	xattr -d "com.apple.quarantine" bootstrap.sh >/dev/null 2>&1
fi

#############################################################################

echo "Running bootstrap"
echo ""

if ! ./bootstrap.sh; then
	echo "bootstrap failed."
	exit 1
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

${MAKE} clean >/dev/null 2>&1

if ! ${MAKE} -j2 -f Makefile; then
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
