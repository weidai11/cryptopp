#!/usr/bin/env bash

#############################################################################
#
# This script tests the cryptopp-pem gear.
#
# Written and placed in public domain by Jeffrey Walton.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
#############################################################################

GREP=grep
SED=sed
AWK=awk
MAKE=make

# Fixup, Solaris and friends
if [[ (-d /usr/xpg4/bin) ]]; then
	SED=/usr/xpg4/bin/sed
	AWK=/usr/xpg4/bin/awk
	GREP=/usr/xpg4/bin/grep
elif [[ (-d /usr/bin/posix) ]]; then
	SED=/usr/bin/posix/sed
	AWK=/usr/bin/posix/awk
	GREP=/usr/bin/posix/grep
fi

# Fixup for sed and "illegal byte sequence"
IS_DARWIN=$(uname -s | "$GREP" -i -c darwin)
if [[ "$IS_DARWIN" -ne 0 ]]; then
	export LC_ALL=C
fi

# Fixup for Solaris and BSDs
if command -v gmake 2>/dev/null; then
	MAKE=gmake
else
	MAKE=make
fi

#############################################################################

if ! command -v "${MAKE}" 2>/dev/null; then
	echo "Cannot find $MAKE. Things may fail."
fi

if ! command -v curl 2>/dev/null; then
	echo "Cannot find cURL. Things may fail."
fi

if ! command -v openssl 2>/dev/null; then
	echo "Cannot find openssl. Things may fail."
fi

#############################################################################

files=(pem_create.sh pem_verify.sh pem_test.cxx pem_eol.cxx
       pem.h pem_common.cpp pem_common.h pem_read.cpp pem_write.cpp
       x509cert.h x509cert.cpp)

for file in "${files[@]}"; do
	echo "Downloading $file"
	if ! curl -L -s -o "$file" "https://raw.githubusercontent.com/noloader/cryptopp-pem/master/$file"; then
		echo "$file download failed"
		exit 1
	fi
    # Throttle
    sleep 1
done

# Add execute to scripts
chmod +x *.sh

if [[ "$IS_DARWIN" -ne 0 ]] && [[ -n $(command -v xattr) ]]; then
	echo "Removing pem_create.sh pem_verify.sh quarantine"
	xattr -d "com.apple.quarantine" pem_create.sh pem_verify.sh &>/dev/null
fi

#############################################################################

echo ""
echo "Building test artifacts"
echo ""

"$MAKE" clean &>/dev/null

if ! "$MAKE" -j 2; then
	echo "make failed."
	exit 1
fi

if ! ./cryptest.exe v; then
	echo "cryptest v failed."
	exit 1
fi

if ! ./pem_create.sh; then
	echo "pem_create.sh failed."
	exit 1
fi

if ! ./pem_verify.sh; then
	echo "pem_verify.sh failed."
	exit 1
fi

# Return success
exit 0
